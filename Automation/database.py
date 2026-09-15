import json
import sqlite3
import re
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime, timezone

from risk_engine import load_events, calculate_risk


DB_FILE = Path.home() / "cowrie" / "honeypot.db"


def create_database():
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS risk_assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT NOT NULL,
            risk_score INTEGER,
            severity TEXT,
            event_count INTEGER,
            failed_login_attempts INTEGER,
            command_count INTEGER,
            factors TEXT,
            reasons TEXT,
            created_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_intelligence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT NOT NULL,
            status TEXT,
            abuse_confidence_score INTEGER,
            country_code TEXT,
            usage_type TEXT,
            isp TEXT,
            domain TEXT,
            total_reports INTEGER,
            last_reported_at TEXT,
            raw_result TEXT,
            created_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            session_id TEXT,
            source_ip TEXT,
            username TEXT,
            command TEXT,
            message TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE,
            source_ip TEXT,
            username TEXT,
            start_time TEXT,
            end_time TEXT,
            command_count INTEGER,
            behaviors TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            session_id TEXT,
            ioc_type TEXT,
            ioc_value TEXT,
            created_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT UNIQUE NOT NULL,
            source_ip TEXT NOT NULL,
            title TEXT,
            severity TEXT,
            risk_score INTEGER,
            event_count INTEGER,
            session_count INTEGER,
            command_count INTEGER,
            status TEXT DEFAULT 'OPEN',
            first_seen TEXT,
            last_seen TEXT,
            created_at TEXT
        )
    """)

    connection.commit()
    connection.close()

    print(f"Database ready: {DB_FILE}")


def insert_events(events):
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    for event in events:

        cursor.execute("""
            INSERT INTO events (
                timestamp,
                event_type,
                session_id,
                source_ip,
                username,
                command,
                message
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            event.get("timestamp"),
            event.get("eventid"),
            event.get("session"),
            event.get("src_ip"),
            event.get("username"),
            event.get("input"),
            event.get("message")
        ))

    connection.commit()
    connection.close()

    print(f"Events stored: {len(events)}")


def insert_risk_assessment(result):
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO risk_assessments (
            source_ip,
            risk_score,
            severity,
            event_count,
            failed_login_attempts,
            command_count,
            factors,
            reasons,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        result.get("source_ip"),
        result.get("risk_score"),
        result.get("severity"),
        result.get("event_count"),
        result.get("failed_login_attempts"),
        result.get("command_count"),
        json.dumps(result.get("factors", {})),
        json.dumps(result.get("reasons", [])),
        datetime.now(timezone.utc).isoformat()
    ))

    connection.commit()
    connection.close()


def insert_threat_intelligence(result, source_ip):
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO threat_intelligence (
            source_ip,
            status,
            abuse_confidence_score,
            country_code,
            usage_type,
            isp,
            domain,
            total_reports,
            last_reported_at,
            raw_result,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        result.get("ip") or result.get("source_ip") or source_ip,
        result.get("status"),
        result.get("abuse_confidence_score"),
        result.get("country_code"),
        result.get("usage_type"),
        result.get("isp"),
        result.get("domain"),
        result.get("total_reports"),
        result.get("last_reported_at"),
        json.dumps(result),
        datetime.now(timezone.utc).isoformat()
    ))

    connection.commit()
    connection.close()


def build_sessions(events):
    sessions = {}

    for event in events:

        session_id = event.get("session")

        if not session_id:
            continue

        if session_id not in sessions:
            sessions[session_id] = {
                "session_id": session_id,
                "source_ip": event.get("src_ip"),
                "username": event.get("username"),
                "start_time": event.get("timestamp"),
                "end_time": event.get("timestamp"),
                "commands": [],
                "behaviors": []
            }

        session = sessions[session_id]

        timestamp = event.get("timestamp")

        if timestamp:
            session["end_time"] = timestamp

        if event.get("username"):
            session["username"] = event.get("username")

        if event.get("eventid") == "cowrie.command.input":
            command = event.get("input")

            if command:
                session["commands"].append(command)

    return sessions


def insert_sessions(sessions):
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    for session in sessions.values():

        cursor.execute("""
            INSERT OR REPLACE INTO sessions (
                session_id,
                source_ip,
                username,
                start_time,
                end_time,
                command_count,
                behaviors
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            session["session_id"],
            session["source_ip"],
            session["username"],
            session["start_time"],
            session["end_time"],
            len(session["commands"]),
            json.dumps(session["behaviors"])
        ))

    connection.commit()
    connection.close()

    print(f"Sessions stored: {len(sessions)}")

def extract_and_store_iocs(events):
    """
    Extract IPs, URLs, domains and SHA-256 hashes from Cowrie events
    and store them in the iocs table.
    """

    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    url_pattern = r"https?://[^\s\"'<>]+"

    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

    stored = 0

    for event in events:

        session_id = event.get("session")

        source_ip = (
            event.get("src_ip")
            or event.get("source_ip")
        )

        timestamp = (
            event.get("timestamp")
            or datetime.now(timezone.utc).isoformat()
        )

        text = " ".join(
            str(event.get(field, ""))
            for field in [
                "input",
                "message",
                "url",
                "outfile",
                "shasum"
            ]
        )

        # -------------------------
        # IP ADDRESS EXTRACTION
        # -------------------------

        ips = re.findall(ip_pattern, text)

        for ip in ips:

            # Ignore local/private addresses
            parts = ip.split(".")

            if len(parts) != 4:
                continue

            try:
                first = int(parts[0])
                second = int(parts[1])
            except ValueError:
                continue

            private_ip = (
                first == 10
                or (first == 172 and 16 <= second <= 31)
                or (first == 192 and second == 168)
                or first == 127
            )

            if private_ip:
                continue

            cursor.execute(
                """
                SELECT 1
                FROM iocs
                WHERE session_id = ?
                AND ioc_type = ?
                AND ioc_value = ?
                """,
                (
                    session_id,
                    "IP",
                    ip
                )
            )

            if cursor.fetchone():
                continue

            cursor.execute(
                """
                INSERT INTO iocs (
                    source_ip,
                    session_id,
                    ioc_type,
                    ioc_value,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    source_ip,
                    session_id,
                    "IP",
                    ip,
                    timestamp
                )
            )

            stored += 1

        # -------------------------
        # URL EXTRACTION
        # -------------------------

        urls = re.findall(url_pattern, text)

        for url in urls:

            url = url.rstrip(".,);]")

            cursor.execute(
                """
                SELECT 1
                FROM iocs
                WHERE session_id = ?
                AND ioc_type = ?
                AND ioc_value = ?
                """,
                (
                    session_id,
                    "URL",
                    url
                )
            )

            if cursor.fetchone():
                continue

            cursor.execute(
                """
                INSERT INTO iocs (
                    source_ip,
                    session_id,
                    ioc_type,
                    ioc_value,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    source_ip,
                    session_id,
                    "URL",
                    url,
                    timestamp
                )
            )

            stored += 1

            # Extract domain from URL
            try:
                domain = urlparse(url).hostname

                if domain:

                    cursor.execute(
                        """
                        SELECT 1
                        FROM iocs
                        WHERE session_id = ?
                        AND ioc_type = ?
                        AND ioc_value = ?
                        """,
                        (
                            session_id,
                            "DOMAIN",
                            domain
                        )
                    )

                    if not cursor.fetchone():

                        cursor.execute(
                            """
                            INSERT INTO iocs (
                                source_ip,
                                session_id,
                                ioc_type,
                                ioc_value,
                                created_at
                            )
                            VALUES (?, ?, ?, ?, ?)
                            """,
                            (
                                source_ip,
                                session_id,
                                "DOMAIN",
                                domain,
                                timestamp
                            )
                        )

                        stored += 1

            except Exception:
                pass

        # -------------------------
        # SHA-256 HASH EXTRACTION
        # -------------------------

        hashes = re.findall(sha256_pattern, text)

        for file_hash in hashes:

            cursor.execute(
                """
                SELECT 1
                FROM iocs
                WHERE session_id = ?
                AND ioc_type = ?
                AND ioc_value = ?
                """,
                (
                    session_id,
                    "SHA256",
                    file_hash
                )
            )

            if cursor.fetchone():
                continue

            cursor.execute(
                """
                INSERT INTO iocs (
                    source_ip,
                    session_id,
                    ioc_type,
                    ioc_value,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    source_ip,
                    session_id,
                    "SHA256",
                    file_hash,
                    timestamp
                )
            )

            stored += 1

    connection.commit()
    connection.close()

    print(f"IOCs stored: {stored}")

def create_or_update_incidents():
    """
    Create or update analyst-facing incidents from the latest
    risk assessment for each source IP.
    """

    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    # Get the latest risk assessment for each source IP
    cursor.execute("""
        SELECT r.*
        FROM risk_assessments r
        INNER JOIN (
            SELECT source_ip, MAX(id) AS max_id
            FROM risk_assessments
            GROUP BY source_ip
        ) latest
        ON r.id = latest.max_id
    """)

    risk_rows = cursor.fetchall()

    if not risk_rows:
        print("No risk assessments available for incident creation.")
        connection.close()
        return

    # Get column names so this remains readable even if the table evolves
    columns = [
        description[0]
        for description in cursor.description
    ]

    created_count = 0
    updated_count = 0

    for row in risk_rows:

        risk_data = dict(zip(columns, row))

        source_ip = risk_data.get("source_ip")
        risk_score = risk_data.get("risk_score")
        severity = risk_data.get("severity")
        event_count = risk_data.get("event_count") or 0
        command_count = risk_data.get("command_count") or 0

        if not source_ip:
            continue

        # --------------------------------------------------------
        # Gather supporting telemetry
        # --------------------------------------------------------

        cursor.execute("""
            SELECT COUNT(*)
            FROM sessions
            WHERE source_ip = ?
        """, (source_ip,))

        session_count = cursor.fetchone()[0]

        cursor.execute("""
            SELECT MIN(timestamp), MAX(timestamp)
            FROM events
            WHERE source_ip = ?
        """, (source_ip,))

        first_seen, last_seen = cursor.fetchone()

        # --------------------------------------------------------
        # Generate incident title
        # --------------------------------------------------------

        title = (
            f"{severity} honeypot activity detected from {source_ip}"
        )

        # --------------------------------------------------------
        # Check whether an OPEN incident already exists
        # --------------------------------------------------------

        cursor.execute("""
            SELECT id, incident_id
            FROM incidents
            WHERE source_ip = ?
              AND status = 'OPEN'
            ORDER BY id DESC
            LIMIT 1
        """, (source_ip,))

        existing = cursor.fetchone()

        if existing:

            incident_db_id, incident_id = existing

            cursor.execute("""
                UPDATE incidents
                SET
                    title = ?,
                    severity = ?,
                    risk_score = ?,
                    event_count = ?,
                    session_count = ?,
                    command_count = ?,
                    first_seen = ?,
                    last_seen = ?
                WHERE id = ?
            """, (
                title,
                severity,
                risk_score,
                event_count,
                session_count,
                command_count,
                first_seen,
                last_seen,
                incident_db_id
            ))

            updated_count += 1

        else:

            # ----------------------------------------------------
            # Generate next incident ID
            # ----------------------------------------------------

            year = datetime.now().year

            cursor.execute("""
                SELECT COUNT(*)
                FROM incidents
            """)

            incident_number = cursor.fetchone()[0] + 1

            incident_id = (
                f"INC-{year}-{incident_number:04d}"
            )

            cursor.execute("""
                INSERT INTO incidents (
                    incident_id,
                    source_ip,
                    title,
                    severity,
                    risk_score,
                    event_count,
                    session_count,
                    command_count,
                    status,
                    first_seen,
                    last_seen,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?)
            """, (
                incident_id,
                source_ip,
                title,
                severity,
                risk_score,
                event_count,
                session_count,
                command_count,
                first_seen,
                last_seen,
                datetime.now().isoformat()
            ))

            created_count += 1

            print(
                f"Incident created: {incident_id} "
                f"| {source_ip} "
                f"| {severity} "
                f"| Risk {risk_score}"
            )

    connection.commit()
    connection.close()

    print(
        f"Incident correlation complete: "
        f"{created_count} created, "
        f"{updated_count} updated."
    )

def main():

    print()
    print("====================================")
    print(" HONEYPOT DATABASE ENGINE")
    print("====================================")
    print()

    create_database()

    events = load_events()

    print(f"Events loaded: {len(events)}")

    # Store raw Cowrie events
    insert_events(events)

    # Store IOC data
    extract_and_store_iocs(events)

    # Build and store sessions
    sessions = build_sessions(events)
    insert_sessions(sessions)

    # Identify source IPs
    source_ips = sorted(
        set(
            event.get("src_ip")
            for event in events
            if event.get("src_ip")
        )
    )

    print(f"Source IPs found: {len(source_ips)}")

    # Calculate and store risk + TI
    for source_ip in source_ips:

        result = calculate_risk(
            events,
            source_ip
        )

        insert_risk_assessment(result)

        ti_result = result.get(
            "threat_intelligence"
        )

        if ti_result:
            insert_threat_intelligence(ti_result, source_ip)
    print()
    print("Creating / updating incidents...")
    create_or_update_incidents()

    print()
    print("====================================")
    print(" DATABASE PROCESSING COMPLETE")
    print("====================================")


if __name__ == "__main__":
    main()
