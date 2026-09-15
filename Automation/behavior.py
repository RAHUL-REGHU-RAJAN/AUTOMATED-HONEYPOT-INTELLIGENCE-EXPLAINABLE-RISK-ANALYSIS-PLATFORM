import json
import re
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

LOG_FILE = Path.home() / "cowrie" / "var" / "log" / "cowrie" / "cowrie.json"

BRUTE_FORCE_THRESHOLD = 3


# ============================================================
# 1. EVENT CLASSIFICATION
# ============================================================

EVENT_CATEGORIES = {
    "cowrie.session.connect": "CONNECTION",
    "cowrie.client.version": "CONNECTION",
    "cowrie.client.kex": "CONNECTION",
    "cowrie.client.size": "CONNECTION",
    "cowrie.client.var": "CONNECTION",

    "cowrie.session.params": "SESSION",

    "cowrie.login.failed": "AUTHENTICATION",
    "cowrie.login.success": "AUTHENTICATION",

    "cowrie.command.input": "COMMAND_EXECUTION",
    "cowrie.command.failed": "COMMAND_EXECUTION",

    "cowrie.session.file_download": "PAYLOAD_ACTIVITY",
    "cowrie.session.file_upload": "PAYLOAD_ACTIVITY",

    "cowrie.log.closed": "SESSION_END",
    "cowrie.session.closed": "SESSION_END"
}


def classify_event(event_type):
    return EVENT_CATEGORIES.get(event_type, "OTHER")


# ============================================================
# 2. LOAD EVENTS
# ============================================================

def load_events():
    events = []

    if not LOG_FILE.exists():
        print(f"Log file not found: {LOG_FILE}")
        return events

    for line in LOG_FILE.read_text(encoding="utf-8").splitlines():

        if not line.strip():
            continue

        try:
            events.append(json.loads(line))

        except json.JSONDecodeError:
            continue

    return events


# ============================================================
# 3. NORMALIZE EVENTS
# ============================================================

def normalize_events(events):

    normalized = []

    for event in events:

        normalized.append(
            {
                "timestamp": event.get("timestamp"),
                "event_type": event.get("eventid"),
                "category": classify_event(event.get("eventid")),
                "session_id": event.get("session"),
                "source_ip": event.get("src_ip"),
                "source_port": event.get("src_port"),
                "destination_ip": event.get("dst_ip"),
                "destination_port": event.get("dst_port"),
                "username": event.get("username"),
                "command": event.get("input"),
                "message": event.get("message")
            }
        )

    return normalized


# ============================================================
# 4. AUTHENTICATION ANALYSIS
# ============================================================

def analyze_authentication(events):

    results = []

    for event in events:

        if event["event_type"] == "cowrie.login.success":

            results.append(
                {
                    "timestamp": event["timestamp"],
                    "source_ip": event["source_ip"],
                    "session_id": event["session_id"],
                    "username": event["username"],
                    "behavior": "SUCCESSFUL_AUTHENTICATION"
                }
            )

        elif event["event_type"] == "cowrie.login.failed":

            results.append(
                {
                    "timestamp": event["timestamp"],
                    "source_ip": event["source_ip"],
                    "session_id": event["session_id"],
                    "username": event["username"],
                    "behavior": "AUTHENTICATION_FAILURE"
                }
            )

    return results


# ============================================================
# 5. BRUTE-FORCE DETECTION
# ============================================================

def detect_brute_force(events):

    failed_logins = [
        event
        for event in events
        if event["event_type"] == "cowrie.login.failed"
    ]

    source_ips = sorted(
        set(
            event["source_ip"]
            for event in failed_logins
            if event["source_ip"]
        )
    )

    results = []

    for ip in source_ips:

        attempts = sum(
            1
            for event in failed_logins
            if event["source_ip"] == ip
        )

        if attempts >= BRUTE_FORCE_THRESHOLD:

            results.append(
                {
                    "source_ip": ip,
                    "failed_attempts": attempts,
                    "behavior": "BRUTE_FORCE"
                }
            )

    return results


# ============================================================
# 6. RECONNAISSANCE DETECTION
# ============================================================

RECON_PATTERNS = [

    r"\bwhoami\b",
    r"\bid\b",
    r"\bunmae\b",
    r"\buname\b",
    r"\bhostname\b",
    r"\bpwd\b",
    r"\benv\b",
    r"\bprintenv\b",

    r"\bls\b",
    r"\bls\s+-",
    r"\bfind\b",

    r"\bcat\s+/etc/passwd\b",
    r"\bcat\s+/etc/group\b",
    r"\bcat\s+/etc/os-release\b",

    r"\bcat\s+/etc/hostname\b",
    r"\bcat\s+/etc/issue\b",

    r"\bgetent\s+passwd\b",
    r"\bgetent\s+group\b",

    r"\bps\b",
    r"\btop\b",
    r"\bdf\b",
    r"\bfree\b"
]


def detect_reconnaissance(events):

    results = []

    for event in events:

        command = event.get("command")

        if not command:
            continue

        command_lower = command.lower().strip()

        for pattern in RECON_PATTERNS:

            if re.search(pattern, command_lower):

                results.append(
                    {
                        "timestamp": event["timestamp"],
                        "source_ip": event["source_ip"],
                        "session_id": event["session_id"],
                        "command": command,
                        "behavior": "RECONNAISSANCE"
                    }
                )

                break

    return results


# ============================================================
# 7. NETWORK RECONNAISSANCE
# ============================================================

NETWORK_RECON_PATTERNS = [

    r"\bip\s+addr\b",
    r"\bip\s+route\b",
    r"\bifconfig\b",
    r"\broute\b",

    r"\bnetstat\b",
    r"\bss\s+",
    r"\barp\b",

    r"\bping\b",
    r"\btraceroute\b",
    r"\btraceroute6\b",

    r"\bnmap\b",
    r"\bnc\b",
    r"\bnetcat\b",

    r"\blsof\s+-i\b"
]


def detect_network_reconnaissance(events):

    results = []

    for event in events:

        command = event.get("command")

        if not command:
            continue

        command_lower = command.lower().strip()

        for pattern in NETWORK_RECON_PATTERNS:

            if re.search(pattern, command_lower):

                results.append(
                    {
                        "timestamp": event["timestamp"],
                        "source_ip": event["source_ip"],
                        "session_id": event["session_id"],
                        "command": command,
                        "behavior": "NETWORK_RECONNAISSANCE"
                    }
                )

                break

    return results


# ============================================================
# 8. SUSPICIOUS COMMAND DETECTION
# ============================================================

SUSPICIOUS_COMMAND_PATTERNS = [

    r"\bcurl\b",
    r"\bwget\b",
    r"\btftp\b",

    r"\bbash\s+-c\b",
    r"\bsh\s+-c\b",

    r"\bpython\s+-c\b",
    r"\bpython3\s+-c\b",
    r"\bperl\s+-e\b",
    r"\bruby\s+-e\b",

    r"\bbase64\b",
    r"\beval\b",

    r"/dev/tcp/",

    r"\bchmod\s+\+x\b",

    r"\brm\s+-rf\b",

    r"\bmkfifo\b"
]


def detect_suspicious_commands(events):

    results = []

    for event in events:

        command = event.get("command")

        if not command:
            continue

        command_lower = command.lower()

        for pattern in SUSPICIOUS_COMMAND_PATTERNS:

            if re.search(pattern, command_lower):

                results.append(
                    {
                        "timestamp": event["timestamp"],
                        "source_ip": event["source_ip"],
                        "session_id": event["session_id"],
                        "command": command,
                        "behavior": "SUSPICIOUS_COMMAND"
                    }
                )

                break

    return results


# ============================================================
# 9. PAYLOAD ACTIVITY DETECTION
# ============================================================

PAYLOAD_COMMAND_PATTERNS = [

    r"\bwget\b",
    r"\bcurl\b",

    r"\btftp\b",
    r"\bftp\b",

    r"\bscp\b",

    r"\bfetch\b"
]


def detect_payload_activity(events):

    results = []

    for event in events:

        event_type = event.get("event_type")
        command = event.get("command")

        # Cowrie generated file download/upload event
        if event_type in [
            "cowrie.session.file_download",
            "cowrie.session.file_upload"
        ]:

            results.append(
                {
                    "timestamp": event["timestamp"],
                    "source_ip": event["source_ip"],
                    "session_id": event["session_id"],
                    "command": command,
                    "event_type": event_type,
                    "behavior": "PAYLOAD_ACTIVITY"
                }
            )

            continue

        # Download-related command
        if command:

            command_lower = command.lower()

            for pattern in PAYLOAD_COMMAND_PATTERNS:

                if re.search(pattern, command_lower):

                    results.append(
                        {
                            "timestamp": event["timestamp"],
                            "source_ip": event["source_ip"],
                            "session_id": event["session_id"],
                            "command": command,
                            "event_type": event_type,
                            "behavior": "PAYLOAD_ACTIVITY"
                        }
                    )

                    break

    return results


# ============================================================
# 10. PERSISTENCE DETECTION
# ============================================================

PERSISTENCE_PATTERNS = [

    r"\bcrontab\b",
    r"/etc/crontab",
    r"/etc/cron\.",

    r"\bsystemctl\s+enable\b",
    r"\bsystemctl\s+start\b",

    r"/etc/rc\.local",

    r"\.bashrc",
    r"\.profile",
    r"\.bash_profile",

    r"\.ssh/authorized_keys",

    r"\bssh-keygen\b",

    r"\buseradd\b",
    r"\badduser\b",

    r"\bpasswd\b",

    r"\bchattr\b"
]


def detect_persistence(events):

    results = []

    for event in events:

        command = event.get("command")

        if not command:
            continue

        command_lower = command.lower()

        for pattern in PERSISTENCE_PATTERNS:

            if re.search(pattern, command_lower):

                results.append(
                    {
                        "timestamp": event["timestamp"],
                        "source_ip": event["source_ip"],
                        "session_id": event["session_id"],
                        "command": command,
                        "behavior": "PERSISTENCE_ATTEMPT"
                    }
                )

                break

    return results


# ============================================================
# 11. SESSION CORRELATION
# ============================================================

def correlate_sessions(events):

    sessions = {}

    for event in events:

        session_id = event.get("session_id")

        if not session_id:
            continue

        if session_id not in sessions:

            sessions[session_id] = {
                "session_id": session_id,
                "source_ip": event.get("source_ip"),
                "username": None,
                "commands": [],
                "event_types": [],
                "behaviors": [],
                "start_time": event.get("timestamp"),
                "end_time": event.get("timestamp")
            }

        session = sessions[session_id]

        session["end_time"] = event.get("timestamp")

        if event.get("username"):
            session["username"] = event.get("username")

        if event.get("event_type"):

            if event["event_type"] not in session["event_types"]:

                session["event_types"].append(
                    event["event_type"]
                )

        if event.get("command"):

            session["commands"].append(
                event["command"]
            )

    return list(sessions.values())


# ============================================================
# 12. ADD BEHAVIOR FLAGS TO SESSIONS
# ============================================================

def attach_behaviors(
    sessions,
    auth_results,
    brute_force_results,
    recon_results,
    network_recon_results,
    suspicious_results,
    payload_results,
    persistence_results
):

    behavior_groups = [

        auth_results,
        recon_results,
        network_recon_results,
        suspicious_results,
        payload_results,
        persistence_results
    ]

    for session in sessions:

        session_id = session["session_id"]

        behaviors = set()

        for group in behavior_groups:

            for result in group:

                if result.get("session_id") == session_id:

                    behaviors.add(
                        result["behavior"]
                    )

        for result in brute_force_results:

            if result.get("source_ip") == session["source_ip"]:

                behaviors.add(
                    result["behavior"]
                )

        session["behaviors"] = sorted(behaviors)

    return sessions


# ============================================================
# 13. BEHAVIOR SUMMARY
# ============================================================

def generate_behavior_summary(
    events,
    auth_results,
    brute_force_results,
    recon_results,
    network_recon_results,
    suspicious_results,
    payload_results,
    persistence_results
):

    summary = {

        "total_events": len(events),

        "authentication_events": len(
            auth_results
        ),

        "brute_force_sources": len(
            brute_force_results
        ),

        "reconnaissance_events": len(
            recon_results
        ),

        "network_reconnaissance_events": len(
            network_recon_results
        ),

        "suspicious_command_events": len(
            suspicious_results
        ),

        "payload_activity_events": len(
            payload_results
        ),

        "persistence_attempts": len(
            persistence_results
        )
    }

    return summary


# ============================================================
# 14. MAIN ANALYSIS ENGINE
# ============================================================

def main():

    print()
    print("==========================================")
    print(" COWRIE BEHAVIOR ANALYSIS ENGINE")
    print("==========================================")
    print()

    # Load raw Cowrie events
    raw_events = load_events()

    if not raw_events:

        print("No Cowrie events found.")
        return

    # Normalize/classify events
    events = normalize_events(raw_events)

    # Authentication analysis
    auth_results = analyze_authentication(events)

    # Brute force
    brute_force_results = detect_brute_force(events)

    # Reconnaissance
    recon_results = detect_reconnaissance(events)

    # Network reconnaissance
    network_recon_results = detect_network_reconnaissance(events)

    # Suspicious commands
    suspicious_results = detect_suspicious_commands(events)

    # Payload activity
    payload_results = detect_payload_activity(events)

    # Persistence
    persistence_results = detect_persistence(events)

    # Session correlation
    sessions = correlate_sessions(events)

    # Attach all detected behaviors to sessions
    sessions = attach_behaviors(
        sessions,
        auth_results,
        brute_force_results,
        recon_results,
        network_recon_results,
        suspicious_results,
        payload_results,
        persistence_results
    )

    # Overall summary
    summary = generate_behavior_summary(
        events,
        auth_results,
        brute_force_results,
        recon_results,
        network_recon_results,
        suspicious_results,
        payload_results,
        persistence_results
    )

    # ========================================================
    # FINAL OUTPUT
    # ========================================================

    print("BEHAVIOR SUMMARY")
    print("================")

    print(
        json.dumps(
            summary,
            indent=2
        )
    )

    print()
    print("BRUTE FORCE")
    print("===========")

    if brute_force_results:

        for result in brute_force_results:

            print(
                json.dumps(
                    result,
                    indent=2
                )
            )

    else:

        print("No brute-force activity detected.")

    print()
    print("AUTHENTICATION")
    print("==============")

    for result in auth_results:

        print(
            json.dumps(
                result,
                indent=2
            )
        )

    print()
    print("RECONNAISSANCE")
    print("==============")

    for result in recon_results:

        print(
            json.dumps(
                result,
                indent=2
            )
        )

    print()
    print("NETWORK RECONNAISSANCE")
    print("======================")

    for result in network_recon_results:

        print(
            json.dumps(
                result,
                indent=2
            )
        )

    print()
    print("SUSPICIOUS COMMANDS")
    print("===================")

    for result in suspicious_results:

        print(
            json.dumps(
                result,
                indent=2
            )
        )

    print()
    print("PAYLOAD ACTIVITY")
    print("================")

    for result in payload_results:

        print(
            json.dumps(
                result,
                indent=2
            )
        )

    print()
    print("PERSISTENCE")
    print("===========")

    for result in persistence_results:

        print(
            json.dumps(
                result,
                indent=2
            )
        )

    print()
    print("SESSION CORRELATION")
    print("===================")

    for session in sessions:

        print(
            json.dumps(
                session,
                indent=2
            )
        )

    print()
    print("==========================================")
    print(" BEHAVIOR ANALYSIS COMPLETE")
    print("==========================================")


if __name__ == "__main__":
    main()
