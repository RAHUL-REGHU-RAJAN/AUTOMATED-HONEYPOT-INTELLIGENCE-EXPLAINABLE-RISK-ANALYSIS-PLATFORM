import json
from pathlib import Path 
LOG_FILE = Path.home() / "cowrie" / "var" / "log" / "cowrie" / "cowrie.json"

events = [
json.loads(line)
for line in LOG_FILE.read_text(encoding="utf-8").splitlines()
if line.strip()
]

print(*events, sep="\n")
