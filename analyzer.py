"""
Suspicious Log Analyzer - v0.4
Detects SSH brute-force attempts with:
  - sliding time-window detection
  - IP allowlisting
  - state tracking (no duplicate alerts across runs)
  - CSV export
  - secure file permissions (chmod 600 on state file)
"""
import re
import csv
import json
import os
import stat
import argparse
from collections import Counter
from datetime import datetime, timedelta


LOG_PATTERN = re.compile(
    r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'\S+\s+'
    r'sshd\[\d+\]:\s+'
    r'Failed password for (?:invalid user )?(?P<user>\S+)\s+'
    r'from (?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'port \d+\s+ssh2'
)

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"


def parse_line(line):
    match = LOG_PATTERN.search(line)
    return match.groupdict() if match else None


def parse_log(path):
    events = []
    with open(path, "r") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)
    return events


def parse_timestamp(ts_str, year=2026):
    cleaned = " ".join(ts_str.split())
    return datetime.strptime(f"{year} {cleaned}", "%Y %b %d %H:%M:%S")


def detect_brute_force(events, threshold, window_seconds):
    by_ip = {}
    for event in events:
        ts = parse_timestamp(event["timestamp"])
        by_ip.setdefault(event["ip"], []).append(ts)

    alerts = []
    for ip, timestamps in by_ip.items():
        timestamps.sort()
        for i in range(len(timestamps) - threshold + 1):
            span = timestamps[i + threshold - 1] - timestamps[i]
            if span <= timedelta(seconds=window_seconds):
                alerts.append({
                    "ip": ip,
                    "total_attempts": len(timestamps),
                    "burst_start": timestamps[i],
                    "burst_span_seconds": int(span.total_seconds()),
                })
                break
    return alerts


def load_allowlist(path):
    if not os.path.exists(path):
        return set()
    with open(path) as f:
        return {line.strip() for line in f
                if line.strip() and not line.startswith("#")}


def load_state(path):
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def save_state(path, state):
    with open(path, "w") as f:
        json.dump(state, f, indent=2)
    # Defense in depth: enforce owner-only read/write on every write
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def filter_alerts(alerts, allowlist, previous_state):
    new_alerts = []
    updated_state = dict(previous_state)
    for a in alerts:
        ip = a["ip"]
        if ip in allowlist:
            continue
        burst_iso = a["burst_start"].isoformat()
        last_seen = previous_state.get(ip)
        if last_seen is None or burst_iso > last_seen:
            new_alerts.append(a)
            updated_state[ip] = burst_iso
    return new_alerts, updated_state


def export_csv(alerts, path):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["ip", "total_attempts", "burst_start", "burst_span_seconds"],
        )
        writer.writeheader()
        for a in alerts:
            row = dict(a)
            row["burst_start"] = a["burst_start"].isoformat()
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(description="Suspicious SSH login analyzer")
    parser.add_argument("logfile", help="Path to auth.log")
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window", type=int, default=60)
    parser.add_argument("--allowlist", default="allowlist.txt")
    parser.add_argument("--state", default="alert_state.json")
    parser.add_argument("--csv", help="Optional CSV output path")
    parser.add_argument("--reset-state", action="store_true",
                        help="Clear state file before running")
    args = parser.parse_args()

    if args.reset_state and os.path.exists(args.state):
        os.remove(args.state)

    events = parse_log(args.logfile)
    print(f"Parsed {len(events)} failed login events from {args.logfile}\n")

    ip_counts = Counter(e["ip"] for e in events)
    print("Top source IPs by total failed attempts:")
    for ip, count in ip_counts.most_common(5):
        print(f"  {ip:<20} {count}")
    print()

    allowlist = load_allowlist(args.allowlist)
    previous_state = load_state(args.state)

    raw_alerts = detect_brute_force(events, args.threshold, args.window)
    new_alerts, updated_state = filter_alerts(raw_alerts, allowlist, previous_state)
    new_alerts.sort(key=lambda a: a["total_attempts"], reverse=True)

    print(f"{YELLOW}--- {len(new_alerts)} NEW alert(s) "
          f"(>= {args.threshold} attempts within {args.window}s, "
          f"allowlist: {len(allowlist)} IPs) ---{RESET}")
    for a in new_alerts:
        print(f"{RED}[ALERT]{RESET} {a['total_attempts']} failed logins from "
              f"{a['ip']} (burst: {args.threshold} in {a['burst_span_seconds']}s, "
              f"starting {a['burst_start']})")

    save_state(args.state, updated_state)

    if args.csv and new_alerts:
        export_csv(new_alerts, args.csv)
        print(f"\n{GREEN}Wrote {len(new_alerts)} alerts to {args.csv}{RESET}")


if __name__ == "__main__":
    main()