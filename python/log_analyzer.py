import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime


FAILED_PATTERN = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
ACCEPTED_PATTERN = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+)"
)
TIMESTAMP_PATTERN = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


def parse_log(filepath):
    failed_events = []
    accepted_events = []

    with open(filepath, "r", errors="ignore") as file:
        for line_num, line in enumerate(file, start=1):
            match = TIMESTAMP_PATTERN.match(line)
            timestamp = match.group(1) if match else None

            match = FAILED_PATTERN.search(line)
            if match:
                failed_events.append({
                    "line": line_num,
                    "timestamp": timestamp,
                    "user": match.group("user"),
                    "ip": match.group("ip")
                })
                continue

            match = ACCEPTED_PATTERN.search(line)
            if match:
                accepted_events.append({
                    "line": line_num,
                    "timestamp": timestamp,
                    "user": match.group("user"),
                    "ip": match.group("ip")
                })

    return failed_events, accepted_events


def analyze(failed_events, accepted_events, threshold=5):
    findings = []
    failures_by_ip = defaultdict(list)

    for event in failed_events:
        failures_by_ip[event["ip"]].append(event)

    for ip, events in failures_by_ip.items():
        if len(events) >= threshold:
            findings.append({
                "type": "brute_force_suspected",
                "ip": ip,
                "failed_attempts": len(events),
                "users_tried": sorted(set(e["user"] for e in events)),
                "detail": f"{len(events)} failed login attempts from {ip} "
                          f"(threshold: {threshold})"
            })

    accepted_by_ip = defaultdict(list)

    for event in accepted_events:
        accepted_by_ip[event["ip"]].append(event)

    for ip, events in accepted_by_ip.items():
        if ip in failures_by_ip and len(failures_by_ip[ip]) >= 3:
            findings.append({
                "type": "possible_successful_brute_force",
                "ip": ip,
                "failed_attempts_before_success": len(failures_by_ip[ip]),
                "detail": f"{ip} had {len(failures_by_ip[ip])} failed attempts "
                          f"before a successful login"
            })

    root_attempts = [
        event for event in failed_events + accepted_events
        if event["user"] == "root"
    ]

    if root_attempts:
        findings.append({
            "type": "root_login_attempts",
            "count": len(root_attempts),
            "ips": sorted(set(event["ip"] for event in root_attempts)),
            "detail": f"{len(root_attempts)} login attempts targeting root"
        })

    if len(failures_by_ip) >= 10:
        findings.append({
            "type": "distributed_scanning_suspected",
            "distinct_ips": len(failures_by_ip),
            "detail": f"Failed logins from {len(failures_by_ip)} different IPs"
        })

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Analyze login logs for suspicious activity"
    )
    parser.add_argument("logfile", help="Path to the log file")
    parser.add_argument(
        "--threshold", "-t", type=int, default=5,
        help="Number of failed logins needed to flag an IP"
    )
    parser.add_argument(
        "--output", "-o", default="log_report.json",
        help="Path for the JSON report"
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("threshold must be at least 1")

    print(f"Reading {args.logfile}...")

    try:
        failed_events, accepted_events = parse_log(args.logfile)
    except OSError as error:
        print(f"Error reading log file: {error}", file=sys.stderr)
        sys.exit(1)

    print(f"Failed logins: {len(failed_events)}")
    print(f"Successful logins: {len(accepted_events)}")

    findings = analyze(
        failed_events,
        accepted_events,
        threshold=args.threshold
    )

    report = {
        "generated_at": datetime.now().isoformat(),
        "source_log": args.logfile,
        "total_failed_events": len(failed_events),
        "total_accepted_events": len(accepted_events),
        "threshold_used": args.threshold,
        "findings": findings
    }

    try:
        with open(args.output, "w") as file:
            json.dump(report, file, indent=2)
    except OSError as error:
        print(f"Error writing report: {error}", file=sys.stderr)
        sys.exit(1)

    print(f"\nFound {len(findings)} suspicious pattern(s).")
    print(f"Report saved to {args.output}")

    for finding in findings:
        print(f"[{finding['type']}] {finding['detail']}")


if __name__ == "__main__":
    main()
