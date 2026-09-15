import json
import os
import sys
import ipaddress
import urllib.parse
import urllib.request
import urllib.error


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def is_public_ip(ip):
    try:
        address = ipaddress.ip_address(ip)
        return not (
            address.is_private
            or address.is_loopback
            or address.is_reserved
            or address.is_link_local
            or address.is_multicast
        )
    except ValueError:
        return False


def check_abuseipdb(ip):
    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        return {
            "ip": ip,
            "status": "ERROR",
            "message": "ABUSEIPDB_API_KEY environment variable not set"
        }

    if not is_public_ip(ip):
        return {
            "ip": ip,
            "status": "SKIPPED",
            "message": "Private or non-public IP address"
        }

    params = urllib.parse.urlencode({
        "ipAddress": ip,
        "maxAgeInDays": "90"
    })

    request = urllib.request.Request(
        f"{ABUSEIPDB_URL}?{params}",
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
            "abuse_confidence_score": abuse_data.get(
                "abuseConfidenceScore"
            ),
            "country_code": abuse_data.get("countryCode"),
            "usage_type": abuse_data.get("usageType"),
            "isp": abuse_data.get("isp"),
            "domain": abuse_data.get("domain"),
            "total_reports": abuse_data.get("totalReports"),
            "last_reported_at": abuse_data.get("lastReportedAt")
        }

    except urllib.error.HTTPError as error:
        return {
            "ip": ip,
            "status": "HTTP_ERROR",
            "http_code": error.code,
            "message": error.read().decode("utf-8", errors="replace")
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
    if len(sys.argv) != 2:
        print("Usage: python automation/threat_intel.py <IP>")
        sys.exit(1)

    ip = sys.argv[1]

    result = check_abuseipdb(ip)

    print("THREAT INTELLIGENCE RESULT")
    print("==========================")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
