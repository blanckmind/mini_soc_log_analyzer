# Mini SOC Log Analyzer

A desktop learning project that demonstrates security-log ingestion, transparent rule-based detections, alert triage, and CSV reporting using Python, Tkinter, and SQLite.

> **Scope:** This is an educational prototype. Alerts are indicators for review, not proof of compromise. It is not a production SIEM and does not monitor live systems.

## Features

- Dark SOC-inspired interface with severity-coloured alert rows.
- Import security events from CSV and skip exact duplicate records.
- Local SQLite storage that persists between launches.
- Rule-based detection:
  - Five or more failed login events from one source IP within a 10-minute window.
  - Failed privileged-account login attempts (`root`, `admin`, `administrator`).
  - Successful login following a failed login from the same IP within five minutes.
- Search and filter events/alerts.
- Alert triage states: Open, Investigating, Resolved.
- Export alerts and supporting evidence to CSV.
- Offense summary and severity breakdown.
- Unit tests for core detection behavior.
- Synthetic sample data for safe demonstrations.

## Requirements

- Python 3.10 or newer recommended.
- Tkinter available in your Python installation.
- SQLite is included with Python.

No third-party packages are required for the core app.

## Run on macOS

1. Download or clone this repository.
2. Open the folder in VS Code.
3. In the terminal, check Python and Tkinter:

   ```bash
   python3 --version
   python3 -m tkinter
   ```

4. Launch the application:

   ```bash
   python3 main.py
   ```

The application creates `minisoc.db` locally on first launch and adds synthetic sample events if the log table is empty.

## Import CSV format

Your CSV must include these exact column names (capitalization is ignored):

```csv
timestamp,source_ip,username,event_type,status,details
2026-10-19 09:00:00,192.168.1.15,alice,LOGIN,SUCCESS,Successful user authentication
2026-10-19 09:01:00,203.0.113.25,admin,LOGIN,FAILED,Invalid password
```

Timestamps should be parseable by `datetime.fromisoformat`, for example `YYYY-MM-DD HH:MM:SS`.

## Run tests

From the repository root:

```bash
python3 -m unittest discover -s tests -v
```

## Suggested demonstration

1. Launch the app and review the synthetic events.
2. Import `sample_data/security_logs.csv`.
3. Click **Run Detection**.
4. Open **Alerts & Incidents**, inspect an alert, and change its status.
5. Filter alerts by severity/status.
6. Export alerts to CSV.
7. Restart the app to demonstrate persistent storage.

## Team contribution template

Update this section with the actual work completed by each member. Do not claim work that a member did not implement.

- **Member 1 — UI and interaction:** navigation, dashboard layout, tables, filters, and GUI event handlers.
- **Member 2 — Data layer:** SQLite schema, CSV import, duplicate handling, and data persistence.
- **Member 3 — Detection and validation:** detection rules, alert evidence, test cases, and report export.

All members should review the full codebase and be able to explain how their module works.

## Limitations and next steps

- The detector uses fixed, explainable heuristics; it does not use machine learning.
- The sample events are synthetic and do not represent live telemetry.
- IP addresses and usernames in the demo should not be interpreted as real threat intelligence.
- Future work could add configurable detection thresholds, richer log formats, charts, JSON export, and integration with an authorized lab log source.

## Security and privacy

Do not commit real authentication logs, personal information, API keys, credentials, or production databases. This repository ignores local SQLite database files by default.
