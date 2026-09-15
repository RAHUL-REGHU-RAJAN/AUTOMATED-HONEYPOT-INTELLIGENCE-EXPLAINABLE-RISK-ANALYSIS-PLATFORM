import json
import re
import urllib.request
import urllib.error
from pathlib import Path

LOG_FILE = Path.home() / "cowrie" / "var" / "log" / "cowrie" / "cowrie.json"

IP_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"


def is_private_ip(ip):
    parts = ip.split(".")

    if len(parts) != 4:
        return True

    first = int(parts[0])
    second = int(parts[1])

    if first == 10:
        return True

    if first == 172 and 16 <= second <= 31:
        return True

    if first == 192 and second == 168:
        return True

    if first == 127:
        return True

    return False


def extract_public_ips():
    public_ips = set()

    with LOG_FILE.open("r", encoding="utf-8") as logfile:

        for line in logfile:

            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            text = " ".join(
                str(event.get(field, ""))
                for field in ["input", "message"]
            )

            ips = re.findall(IP_PATTERN, text)

            for ip in ips:

                if not is_private_ip(ip):
                    public_ips.add(ip)

    return sorted(public_ips)


def check_abuseipdb(ip):

    api_key = __import__("os").environ.get("ABUSEIPDB_API_KEY")

    if not api_key:
        return {
            "ip": ip,
            "status": "ERROR",
            "message": "ABUSEIPDB_API_KEY is missing"
        }

    url = (
        "https://api.abuseipdb.com/api/v2/check"
        f"?ipAddress={ip}&maxAgeInDays=90"
    )

    request = urllib.request.Request(
        url,
        headers={
            "Key": api_key,
            "Accept": "application/json"
        }
    )

    try:

        with urllib.request.urlopen(request, timeout=10) as response:

            data = json.loads(response.read().decode("utf-8"))

            abuse_data = data.get("data", {})

            return {
                "ip": ip,
                "status": "SUCCESS",
                "abuse_confidence_score":
                    abuse_data.get("abuseConfidenceScore"),
                "country_code":
                    abuse_data.get("countryCode"),
                "usage_type":
                    abuse_data.get("usageType"),
                "isp":
                    abuse_data.get("isp"),
                "domain":
                    abuse_data.get("domain"),
                "total_reports":
                    abuse_data.get("totalReports"),
                "last_reported_at":
                    abuse_data.get("lastReportedAt")
            }

    except urllib.error.HTTPError as error:

        return {
            "ip": ip,
            "status": "HTTP_ERROR",
            "http_code": error.code
        }

    except urllib.error.URLError as error:

        return {
            "ip": ip,
            "status": "CONNECTION_ERROR",
            "message": str(error.reason)
        }

    except Exception as error:

        return {
            "ip": ip,
            "status": "ERROR",
            "message": str(error)
        }


def main():

    print("IOC → THREAT INTELLIGENCE PIPELINE")
    print("===================================")

    public_ips = extract_public_ips()

    print(f"Public IPs discovered: {len(public_ips)}")

    if not public_ips:

        print("No public IP IOCs found.")
        return

    print("\nTHREAT INTELLIGENCE RESULTS")
    print("============================")

    for ip in public_ips:

        result = check_abuseipdb(ip)

        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
