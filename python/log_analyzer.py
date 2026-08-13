"""
log_analyzer.py - Log analysis for digital forensics toolkit

Parses system authentication logs (Linux auth.log / secure style) and
flags patterns commonly associated with intrusion attempts:
  - Repeated failed login attempts (possible brute force)
  - Successful login immediately following a burst of failures
    (possible successful brute force / credential stuffing)
  - Logins from an unusually high number of distinct source IPs
  - Root login attempts

This is a static, offline analyzer meant for learning log-analysis
techniques and for after-the-fact review of logs you already have
legitimate access to (your own machine, a lab VM, a CTF, etc.).

Usage:
    python3 log_analyzer.py <logfile> [--threshold 5] [--output report.json]

Example log line formats supported (OpenSSH style):
    Aug 12 03:14:15 myhost sshd[1234]: Failed password for root from 203.0.113.5 port 51515 ssh2
    Aug 12 03:14:20 myhost sshd[1234]: Accepted password for mike from 198.51.100.7 port 51516 ssh2
"""

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
    """Reads a log file and extracts failed/accepted login events."""
    failed_events = []
    accepted_events = []

    with open(filepath, "r", errors="ignore") as f:
        for line_num, line in enumerate(f, start=1):
            ts_match = TIMESTAMP_PATTERN.match(line)
            timestamp = ts_match.group(1) if ts_match else None

            failed_match = FAILED_PATTERN.search(line)
            if failed_match:
                failed_events.append({
                    "line": line_num,
                    "timestamp": timestamp,
                    "user": failed_match.group("user"),
                    "ip": failed_match.group("ip"),
                })
                continue

            accepted_match = ACCEPTED_PATTERN.search(line)
            if accepted_match:
                accepted_events.append({
                    "line": line_num,
                    "timestamp": timestamp,
                    "user": accepted_match.group("user"),
                    "ip": accepted_match.group("ip"),
                })

    return failed_events, accepted_events


def analyze(failed_events, accepted_events, threshold=5):
    """Applies simple heuristics to flag suspicious patterns."""
    findings = []

    # 1. Repeated failures per source IP (possible brute force)
    failures_by_ip = defaultdict(list)
    for ev in failed_events:
        failures_by_ip[ev["ip"]].append(ev)

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

    # 2. Successful login from an IP that also had failures (possible
    #    successful brute force / credential stuffing)
    accepted_by_ip = defaultdict(list)
    for ev in accepted_events:
        accepted_by_ip[ev["ip"]].append(ev)

    for ip in accepted_by_ip:
        if ip in failures_by_ip and len(failures_by_ip[ip]) >= 3:
            findings.append({
                "type": "possible_successful_brute_force",
                "ip": ip,
                "failed_attempts_before_success": len(failures_by_ip[ip]),
                "detail": f"{ip} had {len(failures_by_ip[ip])} failed attempts "
                          f"before a successful login - review this session"
            })

    # 3. Root login attempts (failed or accepted)
    root_attempts = [e for e in failed_events + accepted_events if e["user"] == "root"]
    if root_attempts:
        findings.append({
            "type": "root_login_attempts",
            "count": len(root_attempts),
            "ips": sorted(set(e["ip"] for e in root_attempts)),
            "detail": f"{len(root_attempts)} login attempt(s) targeting the root account"
        })

    # 4. Wide-net scanning: many distinct IPs each trying a small number of times
    if len(failures_by_ip) >= 10:
        findings.append({
            "type": "distributed_scanning_suspected",
            "distinct_ips": len(failures_by_ip),
            "detail": f"Failed logins from {len(failures_by_ip)} distinct IPs - "
                      f"may indicate a distributed scan or botnet"
        })

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Analyze auth logs for signs of brute-force or intrusion attempts."
    )
    parser.add_argument("logfile", help="Path to the log file (e.g. auth.log)")
    parser.add_argument(
        "--threshold", "-t", type=int, default=5,
        help="Minimum failed attempts from one IP to flag as suspicious (default: 5)"
    )
    parser.add_argument(
        "--output", "-o", default="log_report.json",
        help="Output JSON report path (default: log_report.json)"
    )
    args = parser.parse_args()

    print(f"Parsing {args.logfile} ...")
    try:
        failed_events, accepted_events = parse_log(args.logfile)
    except FileNotFoundError:
        print(f"Error: file not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(failed_events)} failed login events, "
          f"{len(accepted_events)} accepted login events.")

    findings = analyze(failed_events, accepted_events, threshold=args.threshold)

    report = {
        "generated_at": datetime.now().isoformat(),
        "source_log": args.logfile,
        "total_failed_events": len(failed_events),
        "total_accepted_events": len(accepted_events),
        "threshold_used": args.threshold,
        "findings": findings,
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n{len(findings)} finding(s). Report written to {args.output}")
    for f_ in findings:
        print(f"  [{f_['type']}] {f_['detail']}")


if __name__ == "__main__":
    main()
