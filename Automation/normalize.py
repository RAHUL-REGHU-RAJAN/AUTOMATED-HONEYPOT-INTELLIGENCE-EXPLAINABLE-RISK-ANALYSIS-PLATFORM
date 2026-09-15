import json
from pathlib import Path
LOG_FILE = Path.home() / "cowrie" / "var" / "log" / "cowrie" / "cowrie.json"

def normalize_event(event):
   return {
      "timestamp": event.get("timestamp"),
      "event_type": event.get("eventid"),
      "session_id": event.get("session"),
      "source_ip": event.get("src_ip"),
      "source_port": event.get("src_port"),
      "destination_ip": event.get("dst_ip"),
      "destination_port": event.get("dst_port"),
      "username": event.get("username"),
      "command": event.get("input"),
      "message": event.get("message"),
   }


with LOG_FILE.open("r", encoding="utf-8") as logfile:
    for line in logfile:
        if not line.strip():
            continue

        event = json.loads(line)
        normalized = normalize_event(event)
        print(json.dumps(normalized))
