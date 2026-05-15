# Suspicious Log Analyzer

A defensive Python tool that detects SSH brute-force attacks by analyzing auth logs. Built as a learning project to explore detection engineering trade-offs, defensive security automation, and the basics of secure design.

## What it does

- Parses syslog-format SSH authentication logs using regex
- Aggregates failed login attempts by source IP
- Applies a sliding time-window to flag bursts of activity (configurable threshold and window)
- Supports an allowlist for trusted IPs to suppress false positives
- Tracks alert state across runs so duplicate alerts are suppressed
- Exports alerts to CSV for portable reporting
- Enforces owner-only permissions (chmod 600) on the state file as defense-in-depth

## Quick start

​```bash
git clone https://github.com/FOOGLE-ETH/suspicious-log-analyzer.git
cd suspicious-log-analyzer
python3 analyzer.py auth.log
​```

Requires Python 3.9+. No external dependencies.

## Usage examples

Default detection (5 failed attempts within 60 seconds):

​```bash
python3 analyzer.py auth.log
​```

Catch slower distributed attacks (3 attempts within a 5-minute window):

​```bash
python3 analyzer.py auth.log --threshold 3 --window 300
​```

Export findings to CSV and reset previous alert state:

​```bash
python3 analyzer.py auth.log --reset-state --csv alerts.csv
​```

## Sample output

​```
Parsed 106 failed login events from auth.log

Top source IPs by total failed attempts:
  203.0.113.42         62
  198.51.100.99        11
  198.51.100.7         10
  192.0.2.15           10
  198.51.100.23        7

--- 3 NEW alert(s) (>= 3 attempts within 300s, allowlist: 2 IPs) ---
[ALERT] 62 failed logins from 203.0.113.42 (burst: 3 in 9s, starting 2026-05-09 02:14:20)
[ALERT] 11 failed logins from 198.51.100.99 (burst: 3 in 300s, starting 2026-05-09 03:24:00)
[ALERT] 10 failed logins from 192.0.2.15 (burst: 3 in 240s, starting 2026-05-09 03:20:00)
​```

## How the detection works

The detector groups failed login events by source IP, sorts them chronologically, and slides a window across the events. An IP is flagged when `threshold` consecutive attempts fall within a span of `window` seconds. This catches bursts while letting genuinely sporadic failures (e.g., a real user mistyping their password twice over a day) pass without alerting.

The sliding window is the core defensive trade-off: tighter windows miss low-and-slow attacks; wider windows generate noise. The CLI parameters expose this trade-off explicitly so the operator can tune detection to their e
