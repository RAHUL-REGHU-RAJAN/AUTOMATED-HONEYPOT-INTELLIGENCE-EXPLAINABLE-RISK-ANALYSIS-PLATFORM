import sqlite3
import json
from pathlib import Path
from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path.home() / "cowrie"
DB_FILE = BASE_DIR / "honeypot.db"
REPORT_DIR = BASE_DIR / "reports"


# ============================================================
# DATABASE
# ============================================================

def get_connection():
    return sqlite3.connect(DB_FILE)


def fetch_one(cursor, query, params=()):
    cursor.execute(query, params)
    row = cursor.fetchone()

    if not row:
        return None

    columns = [
        description[0]
        for description in cursor.description
    ]

    return dict(zip(columns, row))


def fetch_all(cursor, query, params=()):
    cursor.execute(query, params)
    rows = cursor.fetchall()

    columns = [
        description[0]
        for description in cursor.description
    ]

    return [
        dict(zip(columns, row))
        for row in rows
    ]


# ============================================================
# INCIDENT DATA
# ============================================================

def get_incident(cursor, incident_id):

    return fetch_one(
        cursor,
        """
        SELECT *
        FROM incidents
        WHERE incident_id = ?
        """,
        (incident_id,)
    )


def get_events(cursor, source_ip):

    return fetch_all(
        cursor,
        """
        SELECT *
        FROM events
        WHERE source_ip = ?
        ORDER BY timestamp ASC
        """,
        (source_ip,)
    )


def get_sessions(cursor, source_ip):

    return fetch_all(
        cursor,
        """
        SELECT *
        FROM sessions
        WHERE source_ip = ?
        ORDER BY id ASC
        """,
        (source_ip,)
    )


def get_iocs(cursor, source_ip):

    return fetch_all(
        cursor,
        """
        SELECT *
        FROM iocs
        WHERE source_ip = ?
        ORDER BY id ASC
        """,
        (source_ip,)
    )


def get_threat_intelligence(cursor, source_ip):

    return fetch_all(
        cursor,
        """
        SELECT *
        FROM threat_intelligence
        WHERE source_ip = ?
        ORDER BY id DESC
        """,
        (source_ip,)
    )


def get_risk_assessment(cursor, source_ip):

    return fetch_one(
        cursor,
        """
        SELECT *
        FROM risk_assessments
        WHERE source_ip = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (source_ip,)
    )


# ============================================================
# HELPERS
# ============================================================

def safe_json(value, default=None):

    if value is None:
        return default

    try:
        return json.loads(value)

    except (json.JSONDecodeError, TypeError):
        return default


def markdown_table(rows, columns):

    if not rows:
        return "_No data available._\n"

    header = "| " + " | ".join(columns) + " |"
    separator = "| " + " | ".join("---" for _ in columns) + " |"

    lines = [
        header,
        separator
    ]

    for row in rows:

        values = []

        for column in columns:

            value = row.get(column, "")

            if value is None:
                value = ""

            value = str(value).replace("|", "\\|")
            value = value.replace("\n", " ")

            values.append(value)

        lines.append(
            "| " + " | ".join(values) + " |"
        )

    return "\n".join(lines) + "\n"


# ============================================================
# REPORT GENERATION
# ============================================================

def generate_report(incident_id):

    connection = get_connection()
    cursor = connection.cursor()

    incident = get_incident(
        cursor,
        incident_id
    )

    if not incident:

        print(
            f"Incident not found: {incident_id}"
        )

        connection.close()
        return

    source_ip = incident["source_ip"]

    events = get_events(
        cursor,
        source_ip
    )

    sessions = get_sessions(
        cursor,
        source_ip
    )

    iocs = get_iocs(
        cursor,
        source_ip
    )

    threat_intelligence = get_threat_intelligence(
        cursor,
        source_ip
    )

    risk = get_risk_assessment(
        cursor,
        source_ip
    )

    connection.close()

    # --------------------------------------------------------
    # Risk data
    # --------------------------------------------------------

    factors = {}

    reasons = []

    if risk:

        factors = safe_json(
            risk.get("factors"),
            {}
        )

        reasons = safe_json(
            risk.get("reasons"),
            []
        )

    # --------------------------------------------------------
    # Build report
    # --------------------------------------------------------

    report = []

    report.append(
        "# Honeypot Security Incident Report"
    )

    report.append("")

    report.append(
        f"## {incident['incident_id']}"
    )

    report.append("")

    report.append(
        f"**Generated:** "
        f"{datetime.now().isoformat()}"
    )

    report.append("")

    report.append("---")

    report.append("")

    # --------------------------------------------------------
    # Executive summary
    # --------------------------------------------------------

    report.append("## Executive Summary")

    report.append("")

    report.append(
        f"Source IP **{source_ip}** generated "
        f"honeypot activity classified as "
        f"**{incident['severity']}** with a risk score "
        f"of **{incident['risk_score']}/100**."
    )

    report.append("")

    report.append(
        f"Incident status: **{incident['status']}**"
    )

    report.append("")

    # --------------------------------------------------------
    # Incident details
    # --------------------------------------------------------

    report.append("## Incident Details")

    report.append("")

    report.append(
        markdown_table(
            [
                {
                    "Field": "Incident ID",
                    "Value": incident["incident_id"]
                },
                {
                    "Field": "Source IP",
                    "Value": source_ip
                },
                {
                    "Field": "Severity",
                    "Value": incident["severity"]
                },
                {
                    "Field": "Risk Score",
                    "Value": incident["risk_score"]
                },
                {
                    "Field": "Status",
                    "Value": incident["status"]
                },
                {
                    "Field": "First Seen",
                    "Value": incident["first_seen"]
                },
                {
                    "Field": "Last Seen",
                    "Value": incident["last_seen"]
                }
            ],
            ["Field", "Value"]
        )
    )

    # --------------------------------------------------------
    # Activity summary
    # --------------------------------------------------------

    report.append("## Activity Summary")

    report.append("")

    report.append(
        markdown_table(
            [
                {
                    "Metric": "Events",
                    "Count": incident["event_count"]
                },
                {
                    "Metric": "Sessions",
                    "Count": incident["session_count"]
                },
                {
                    "Metric": "Commands",
                    "Count": incident["command_count"]
                },
                {
                    "Metric": "IOCs",
                    "Count": len(iocs)
                }
            ],
            ["Metric", "Count"]
        )
    )

    # --------------------------------------------------------
    # Risk analysis
    # --------------------------------------------------------

    report.append("## Risk Analysis")

    report.append("")

    if factors:

        factor_rows = [
            {
                "Factor": key,
                "Score": value
            }
            for key, value in factors.items()
        ]

        report.append(
            markdown_table(
                factor_rows,
                ["Factor", "Score"]
            )
        )

    else:

        report.append(
            "_No risk factors available._"
        )

    report.append("")

    report.append("### Risk Reasons")

    report.append("")

    if reasons:

        for reason in reasons:

            report.append(
                f"- {reason}"
            )

    else:

        report.append(
            "- No risk reasons available."
        )

    # --------------------------------------------------------
    # Sessions
    # --------------------------------------------------------

    report.append("")

    report.append("## Sessions")

    report.append("")

    report.append(
        markdown_table(
            sessions,
            [
                "id",
                "source_ip",
                "session_id"
            ]
        )
    )

    # --------------------------------------------------------
    # IOCs
    # --------------------------------------------------------

    report.append("## Extracted Indicators")

    report.append("")

    report.append(
        markdown_table(
            iocs,
            [
                "id",
                "session_id",
                "ioc_type",
                "ioc_value"
            ]
        )
    )

    # --------------------------------------------------------
    # Threat Intelligence
    # --------------------------------------------------------

    report.append("## Threat Intelligence")

    report.append("")

    if threat_intelligence:

        ti_columns = [
            "id",
            "source_ip",
            "status",
            "abuse_confidence_score",
            "country_code",
            "usage_type",
            "isp",
            "domain",
            "total_reports",
            "last_reported_at"
        ]

        available_columns = [
            column
            for column in ti_columns
            if column in threat_intelligence[0]
        ]

        report.append(
            markdown_table(
                threat_intelligence,
                available_columns
            )
        )

    else:

        report.append(
            "_No threat intelligence records available._"
        )

    # --------------------------------------------------------
    # Recent events
    # --------------------------------------------------------

    report.append("## Honeypot Event Evidence")

    report.append("")

    # Keep the report readable while preserving useful evidence
    recent_events = events[-50:]

    event_columns = [
        "id",
        "timestamp",
        "event_type",
        "session_id",
        "source_ip",
        "username",
        "command",
        "message"
    ]

    if recent_events:

        available_columns = [
            column
            for column in event_columns
            if column in recent_events[0]
        ]

        report.append(
            markdown_table(
                recent_events,
                available_columns
            )
        )

    else:

        report.append(
            "_No event evidence available._"
        )

    # --------------------------------------------------------
    # Analyst recommendations
    # --------------------------------------------------------

    report.append("## Analyst Recommendations")

    report.append("")

    recommendations = [
        "Review the associated honeypot sessions.",
        "Investigate suspicious commands and downloaded content.",
        "Validate extracted IOCs against trusted intelligence sources.",
        "Review threat-intelligence reputation for public indicators.",
        "Preserve relevant session and event evidence.",
        "Monitor for repeated activity from the same source."
    ]

    for recommendation in recommendations:

        report.append(
            f"- {recommendation}"
        )

    # --------------------------------------------------------
    # Footer
    # --------------------------------------------------------

    report.append("")

    report.append("---")

    report.append("")

    report.append(
        "*Generated automatically by the "
        "Automated Honeypot Intelligence & "
        "Explainable Risk Analysis Platform.*"
    )

    report_text = "\n".join(report)

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    report_file = (
        REPORT_DIR /
        f"{incident_id}.md"
    )

    report_file.write_text(
        report_text,
        encoding="utf-8"
    )

    print()
    print("====================================")
    print(" INCIDENT REPORT GENERATED")
    print("====================================")
    print(
        f"Incident : {incident_id}"
    )
    print(
        f"Report   : {report_file}"
    )
    print(
        f"Events   : {len(events)}"
    )
    print(
        f"Sessions : {len(sessions)}"
    )
    print(
        f"IOCs     : {len(iocs)}"
    )
    print(
        f"TI       : {len(threat_intelligence)}"
    )
    print("====================================")


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "HONEYPOT INCIDENT REPORT GENERATOR"
    )

    print(
        "==================================="
    )

    connection = get_connection()
    cursor = connection.cursor()

    latest_incident = fetch_one(
        cursor,
        """
        SELECT incident_id
        FROM incidents
        ORDER BY id DESC
        LIMIT 1
        """
    )

    connection.close()

    if not latest_incident:

        print("No incidents available.")
        return

    generate_report(
        latest_incident["incident_id"]
    )


if __name__ == "__main__":
    main()
