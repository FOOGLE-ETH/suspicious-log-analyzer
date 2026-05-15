# Suspicious Log Analyzer — Cheat Sheet

Quick reference for running, demoing, and maintaining the project.

---

## File layout

```
loganalyzer/
├── .gitignore
├── README.md
├── analyzer.py
├── auth.log              # sample log with seeded attacks
├── allowlist.txt         # trusted IPs (one per line)
└── alert_state.json      # auto-created, NOT in repo
```

---

## Environment check

```bash
python3 --version        # need 3.9+
pwd                      # confirm you're in loganalyzer/
ls -la                   # see all files including dotfiles
```

---

## The four runs to memorize

**Default — 5 attempts in 60 seconds:**
```bash
python3 analyzer.py auth.log
```

**Wider window — 5 attempts in 10 minutes:**
```bash
python3 analyzer.py auth.log --threshold 5 --window 600
```

**Aggressive — catches the low-and-slow distributed attackers:**
```bash
python3 analyzer.py auth.log --threshold 3 --window 300
```

**Reset state + export CSV:**
```bash
python3 analyzer.py auth.log --threshold 3 --window 300 --reset-state --csv alerts.csv
```

---

## All CLI flags

| Flag             | Default              | What it does                                  |
|------------------|----------------------|-----------------------------------------------|
| `logfile`        | (required)           | Path to the auth log                          |
| `--threshold`    | 5                    | Failed attempts needed to trigger an alert    |
| `--window`       | 60                   | Time window in seconds                        |
| `--allowlist`    | allowlist.txt        | File listing trusted IPs                      |
| `--state`        | alert_state.json     | Where alert history is persisted              |
| `--csv`          | (none)               | Optional CSV output path                      |
| `--reset-state`  | off                  | Clear state file before running               |

---

## 3-minute demo sequence (for PyCon)

```bash
# 1. Show the README
head -30 README.md

# 2. Show the sample log
head auth.log

# 3. Default run — show "only catches the obvious one"
python3 analyzer.py auth.log

# 4. Widen the window — show the trade-off
python3 analyzer.py auth.log --threshold 3 --window 300

# 5. Re-run same command — show state tracking suppresses dupes
python3 analyzer.py auth.log --threshold 3 --window 300

# 6. Show the security feature
ls -l alert_state.json    # demonstrates chmod 600 is enforced
```

Talking points for each step are in the README under "Security design decisions."

---

## Edit the allowlist live (demo move)

```bash
# Temporarily trust the big attacker IP
echo "203.0.113.42" >> allowlist.txt

# Re-run — that IP no longer alerts
python3 analyzer.py auth.log --threshold 3 --window 300 --reset-state

# Restore allowlist when done
# (open allowlist.txt and remove the line you added)
nano allowlist.txt
```

---

## Reset between demos

```bash
rm -f alert_state.json alerts.csv
```

---

## Verify security features

```bash
ls -l alert_state.json           # owner-only: -rw-------
ls -l allowlist.txt              # operator-readable: -rw-r--r--
cat allowlist.txt                # see trusted IPs
```

---

## Git workflow

```bash
git status                       # see what's changed
git add .                        # stage everything
git commit -m "describe change"  # commit locally
git push                         # push to GitHub
git pull                         # pull remote changes (e.g., if you edited via the web)
git log --oneline                # see commit history
```

---

## Troubleshooting

| Symptom                                       | Fix                                                                 |
|-----------------------------------------------|---------------------------------------------------------------------|
| `No such file or directory: auth.log`         | `cd` into the `loganalyzer/` folder first                          |
| Script outputs 0 alerts when you expect some  | State file is suppressing duplicates — add `--reset-state`          |
| `JSONDecodeError` on startup                  | Corrupted state — `rm alert_state.json`                            |
| `alert_state.json` permissions look wrong     | `chmod 600 alert_state.json` (script re-enforces on next write)    |
| Colors show as `\033[91m` garbage             | Run in a real terminal, not a non-ANSI environment                  |

---

## Rebuild from scratch on a new machine

```bash
git clone https://github.com/FOOGLE-ETH/suspicious-log-analyzer.git
cd suspicious-log-analyzer
python3 --version    # confirm 3.9+
python3 analyzer.py auth.log
```

That's it — no dependencies, no virtualenv, no install step.

---

## Key concepts mapped to industry frameworks

| Concept                            | Reference                                          |
|------------------------------------|----------------------------------------------------|
| Logging gap → detection            | OWASP A09:2021 — Security Logging and Monitoring Failures |
| File permission enforcement        | CWE-732 — Incorrect Permission Assignment          |
| Least privilege & blast radius     | OWASP A01:2021 — Broken Access Control             |
| Brute force / password guessing    | MITRE ATT&CK T1110.001                             |
| Password spraying (future work)    | MITRE ATT&CK T1110.003                             |
