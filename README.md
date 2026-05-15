# Suspicious Log Analyzer

A defensive Python tool that detects SSH brute-force attacks by analyzing auth logs. Built as a learning project to explore detection engineering trade-offs, defensive security automation, and the basics of secure design.

## What it does

- Parses syslog-format SSH authentication logs using regex
- Aggregates failed login attempts by source IP
- Applies a sliding time-window to flag bursts of activity (configurable threshold and window)
- Supports an allowlist for trusted IPs to suppress false positives
- Tracks alert state across runs so duplicate alerts are suppressed
- Exports alerts to CSV for portable reporting
- Enforces owner-only permissions (`chmod 600`) on the state file as defense-in-depth

## Quick start

```bash
git clone https://github.com/FOOGLE-ETH/suspicious-log-analyzer.git
cd suspicious-log-analyzer
python3 analyzer.py auth.log
```

Requires Python 3.9+. No external dependencies.

## Usage examples

Default detection (5 failed attempts within 60 seconds):
```bash
python3 analyzer.py auth.log
```

Catch slower distributed attacks (3 attempts within a 5-minute window):
```bash
python3 analyzer.py auth.log --threshold 3 --window 300
```

Export findings to CSV and reset previous alert state:
```bash
python3 analyzer.py auth.log --reset-state --csv alerts.csv
```

## Sample output

```
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
```

## How the detection works

The detector groups failed login events by source IP, sorts them chronologically, and slides a window across the events. An IP is flagged when **`threshold` consecutive attempts** fall within a span of **`window` seconds**. This catches bursts while letting genuinely sporadic failures (e.g., a real user mistyping their password twice over a day) pass without alerting.

The sliding window is the core defensive trade-off: tighter windows miss low-and-slow attacks; wider windows generate noise. The CLI parameters expose this trade-off explicitly so the operator can tune detection to their environment.

## Security design decisions

**State persistence + permission enforcement.** Alert state is written to `alert_state.json`. Every write call enforces `chmod 600` on the file. This protects the state file from being tampered with by other low-privilege processes on the same host — an attacker who modifies the state file (e.g., setting a future timestamp) could silently disable detection for their own IP. Aligned with the principle of least privilege (OWASP A01:2021 / CWE-732).

**Allowlist for false-positive control.** Trusted internal IPs are excluded from detection via `allowlist.txt`. This file is intentionally separate from program state so it can be owned and edited by a different user (e.g., a sysadmin) than the user that runs the analyzer — a form of separation of duties.

**Stateless detection logic.** The detection function is pure (input events + parameters → alerts) and isolated from I/O. This makes it independently testable and means the detection rule can be tuned or replaced without touching the rest of the pipeline.

## Mapping to industry frameworks

- **OWASP Top 10 A09:2021** — Security Logging and Monitoring Failures. This project addresses the detection side: turning raw logs into actionable alerts.
- **CWE-732** — Incorrect Permission Assignment for Critical Resource. Mitigated by enforcing `chmod 600` on the state file.
- **MITRE ATT&CK T1110** — Brute Force. The detector targets `T1110.001` (Password Guessing) and partially `T1110.003` (Password Spraying — limited; see below).

## Limitations (known)

This is a learning project, not production software. The current implementation has deliberate gaps:

- **IPv4 only.** The regex captures only IPv4 source addresses. Attacks over IPv6 are invisible.
- **Only matches `Failed password` events.** Other SSH failure modes (`error: maximum authentication attempts exceeded`, `Invalid user X from Y` without a password attempt) are not detected.
- **Single host.** No centralized aggregation across multiple servers.
- **No password-spray detection.** Aggregation is per-source-IP, not per-target-username. An attacker rotating across 1,000 IPs but hitting the same account would evade detection.
- **State file is JSON, not a transactional database.** Concurrent runs of the script could produce a TOCTOU race.
- **No reputation enrichment.** All non-allowlisted IPs are treated equally.

## Roadmap

- IPv6 support
- Per-username aggregation for password spraying detection
- Multi-pattern parsing for non-password failure modes
- Pluggable enrichment (IP reputation feeds)
- File locking to prevent concurrent-run race conditions
- Optional output to syslog / JSON over network for SIEM ingestion

## License

MIT
