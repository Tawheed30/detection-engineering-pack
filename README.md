# Detection Engineering Pack

Production-style detection repository:
- MITRE ATT&CK mapped detections (Sigma + Splunk SPL + QRadar AQL)
- Curated benign/malicious log samples (JSONL)
- Automated tests to validate detections (fires on malicious, not on benign)
- CI via GitHub Actions

## Repo layout
- detections/  — one folder per technique/pattern
- data/        — curated sample logs (benign + malicious)
- tests/       — test harness
- docs/        — shared docs (log format, tuning notes)
- .github/     — CI workflows

## Included detections

### T1110 Brute Force — Excessive Failed Logons (4625)
- Folder: detections/T1110_bruteforce/
- Logic: >=10 failed logons in 5 minutes per TargetUserName + IpAddress
- Includes: Sigma + Splunk SPL + QRadar AQL + triage + FP tuning + tests

### T1110 Password Spraying — Many Users Failed Logons (4625)
- Folder: detections/T1110_password_spraying/
- Logic: >=6 distinct usernames in 10 minutes per IpAddress
- Includes: Sigma + Splunk SPL + QRadar AQL + triage + FP tuning + tests

## Run tests locally

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    python tests/run_detection_tests.py

## Log format
All sample logs are JSONL. See: docs/log-format.md
