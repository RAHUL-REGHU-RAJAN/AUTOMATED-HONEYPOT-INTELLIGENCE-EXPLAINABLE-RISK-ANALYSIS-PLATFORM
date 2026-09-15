import json
import ipaddress
from pathlib import Path

from threat_intel import check_abuseipdb


LOG_FILE = Path.home() / "cowrie" / "var" / "log" / "cowrie" / "cowrie.json"


def load_events():
    events = []

    for line in LOG_FILE.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue

        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return events


def is_public_ip(ip):
    try:
        address = ipaddress.ip_address(ip)

        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
        )

    except ValueError:
        return False


def get_abuseipdb_intelligence(ip):
    if not ip or not is_public_ip(ip):
        return {
            "status": "SKIPPED",
            "message": "Private or non-public IP address"
        }

    return check_abuseipdb(ip)


def calculate_risk(events, source_ip):
    source_events = [
        event
        for event in events
        if event.get("src_ip") == source_ip
    ]

    commands = [
        event.get("input", "")
        for event in source_events
        if event.get("eventid") == "cowrie.command.input"
        and event.get("input")
    ]

    failed_logins = sum(
        1
        for event in source_events
        if event.get("eventid") == "cowrie.login.failed"
    )

    successful_logins = sum(
        1
        for event in source_events
        if event.get("eventid") == "cowrie.login.success"
    )

    reconnaissance_commands = [
        "whoami",
        "uname",
        "hostname",
        "pwd",
        "ls",
        "id",
        "cat /etc/passwd",
        "cat /etc/os-release",
        "ps",
        "ifconfig",
        "ip addr",
        "ip route",
        "netstat"
    ]

    suspicious_commands = [
        "wget",
        "curl",
        "chmod",
        "bash -c",
        "nc ",
        "ncat",
        "python -c",
        "perl -e",
        "rm -rf",
        "base64",
        "passwd"
    ]

    persistence_commands = [
        ".bashrc",
        ".profile",
        "crontab",
        "/etc/rc.local",
        "systemctl enable",
        "authorized_keys"
    ]

    reconnaissance_count = sum(
        1
        for command in commands
        if any(
            keyword in command.lower()
            for keyword in reconnaissance_commands
        )
    )

    suspicious_command_count = sum(
        1
        for command in commands
        if any(
            keyword in command.lower()
            for keyword in suspicious_commands
        )
    )

    payload_activity_count = sum(
        1
        for event in source_events
        if event.get("eventid") in [
            "cowrie.session.file_download"
        ]
    )

    persistence_count = sum(
        1
        for command in commands
        if any(
            keyword in command.lower()
            for keyword in persistence_commands
        )
    )

    repeated_activity = len(commands)

    # -----------------------------
    # THREAT INTELLIGENCE
    # -----------------------------

    ti_result = get_abuseipdb_intelligence(source_ip)

    abuse_score = 0

    if ti_result.get("status") == "SUCCESS":
        abuse_score = ti_result.get(
            "abuse_confidence_score",
            0
        )

    # -----------------------------
    # RISK SCORING
    # -----------------------------

    factors = {
        "successful_authentication": 20 if successful_logins > 0 else 0,
        "brute_force": 15 if failed_logins >= 3 else 0,
        "reconnaissance": min(reconnaissance_count, 10),
        "suspicious_command": min(
            suspicious_command_count * 5,
            15
        ),
        "payload_activity": 15 if payload_activity_count > 0 else 0,
        "persistence_attempt": min(
            persistence_count * 10,
            15
        ),
        "repeated_activity": 10 if repeated_activity >= 10 else 0,
        "threat_intelligence": 0
    }

    # Convert AbuseIPDB score into a risk contribution.
    if abuse_score >= 80:
        factors["threat_intelligence"] = 20
    elif abuse_score >= 50:
        factors["threat_intelligence"] = 15
    elif abuse_score >= 20:
        factors["threat_intelligence"] = 8

    risk_score = min(sum(factors.values()), 100)

    if risk_score >= 80:
        severity = "CRITICAL"
    elif risk_score >= 60:
        severity = "HIGH"
    elif risk_score >= 40:
        severity = "MEDIUM"
    elif risk_score >= 20:
        severity = "LOW"
    else:
        severity = "INFO"

    reasons = []

    if successful_logins > 0:
        reasons.append(
            "Successful authentication was observed"
        )

    if failed_logins >= 3:
        reasons.append(
            f"Brute-force activity detected ({failed_logins} failed logins)"
        )

    if reconnaissance_count > 0:
        reasons.append(
            f"Reconnaissance activity detected ({reconnaissance_count} commands)"
        )

    if suspicious_command_count > 0:
        reasons.append(
            f"Suspicious command execution detected ({suspicious_command_count} commands)"
        )

    if payload_activity_count > 0:
        reasons.append(
            "Payload/download activity detected"
        )

    if persistence_count > 0:
        reasons.append(
            f"Persistence attempt detected ({persistence_count} commands)"
        )

    if repeated_activity >= 10:
        reasons.append(
            f"Repeated command activity detected ({repeated_activity} commands)"
        )

    if abuse_score >= 80:
        reasons.append(
            f"AbuseIPDB reports a very high abuse confidence score ({abuse_score}/100)"
        )
    elif abuse_score >= 50:
        reasons.append(
            f"AbuseIPDB reports elevated abuse confidence ({abuse_score}/100)"
        )
    elif abuse_score > 0:
        reasons.append(
            f"AbuseIPDB reports abuse confidence of {abuse_score}/100"
        )

    if ti_result.get("status") == "SKIPPED":
        reasons.append(
            "Threat intelligence lookup skipped because source IP is private/non-public"
        )

    return {
        "source_ip": source_ip,
        "risk_score": risk_score,
        "severity": severity,
        "factors": factors,
        "reasons": reasons,
        "threat_intelligence": ti_result,
        "event_count": len(source_events),
        "failed_login_attempts": failed_logins,
        "command_count": len(commands)
    }


def main():

    print()
    print("====================================")
    print(" EXPLAINABLE RISK ANALYSIS ENGINE")
    print("====================================")
    print()

    events = load_events()

    source_ips = sorted(
        set(
            event.get("src_ip")
            for event in events
            if event.get("src_ip")
        )
    )

    print(f"Events loaded: {len(events)}")
    print(f"Source IPs found: {len(source_ips)}")

    for source_ip in source_ips:

        result = calculate_risk(
            events,
            source_ip
        )

        print()
        print("------------------------------------")
        print("RISK ASSESSMENT")
        print("------------------------------------")

        print(
            json.dumps(
                result,
                indent=2
            )
        )

    print()
    print("====================================")
    print(" RISK ANALYSIS COMPLETE")
    print("====================================")


if __name__ == "__main__":
    main()
