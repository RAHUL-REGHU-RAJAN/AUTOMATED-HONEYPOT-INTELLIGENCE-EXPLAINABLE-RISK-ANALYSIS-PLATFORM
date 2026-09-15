import json
from pathlib import Path

LOG_FILE = Path.home() / "cowrie" / "var" / "log" / "cowrie" / "cowrie.json"

events = [
    json.loads(line)
    for line in LOG_FILE.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

auth_events = [
    {
        "timestamp": event.get("timestamp"),
        "event_type": event.get("eventid"),
        "source_ip": event.get("src_ip"),
        "session_id": event.get("session"),
        "username": event.get("username"),
        "behavior": (
            "SUCCESSFUL_AUTHENTICATION"
            if event.get("eventid") == "cowrie.login.success"
            else "AUTHENTICATION_FAILURE"
        )
    }
    for event in events
    if event.get("eventid") in [
        "cowrie.login.success",
        "cowrie.login.failed"
    ]
]

print("\n".join(json.dumps(event) for event in auth_events))
