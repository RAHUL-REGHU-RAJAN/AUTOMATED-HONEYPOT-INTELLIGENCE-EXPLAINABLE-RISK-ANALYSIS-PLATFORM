import json
import re
from pathlib import Path

LOG_FILE = Path.home() / "cowrie" / "var" / "log" / "cowrie" / "cowrie.json"

IP_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
URL_PATTERN = r"https?://[^\s\"']+"
HASH_PATTERN = r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b"
DOMAIN_PATTERN = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"


def extract_iocs(text):
    if not text:
        return {
            "ips": [],
            "urls": [],
            "domains": [],
            "hashes": []
        }

    return {
        "ips": sorted(set(re.findall(IP_PATTERN, text))),
        "urls": sorted(set(re.findall(URL_PATTERN, text))),
        "domains": sorted(set(re.findall(DOMAIN_PATTERN, text))),
        "hashes": sorted(set(re.findall(HASH_PATTERN, text)))
    }


with LOG_FILE.open("r", encoding="utf-8") as logfile:
    for line in logfile:
        if not line.strip():
            continue

        event = json.loads(line)

        text = " ".join(
            str(event.get(field, ""))
            for field in ["input", "message"]
        )

        iocs = extract_iocs(text)

        if any(iocs.values()):
            print(json.dumps({
                "timestamp": event.get("timestamp"),
                "event_type": event.get("eventid"),
                "session_id": event.get("session"),
                "source_ip": event.get("src_ip"),
                "iocs": iocs
            }))
