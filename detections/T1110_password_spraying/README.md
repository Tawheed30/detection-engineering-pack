# T1110 Password Spraying — Windows Failed Logons (4625)

## Goal
Detect **password spraying**: one source IP attempting logons across **many distinct usernames** in **10 minutes**.

Logic:
- Group by `IpAddress`
- Count distinct `TargetUserName`
- Trigger when `distinct_users >= 6` within `10m`

MITRE ATT&CK:
- **T1110** (Brute Force)

Files:
- Sigma: `sigma/T1110_password_spraying_windows_4625.yml`
- Splunk SPL: `splunk/T1110_password_spraying_windows_4625.spl`
- QRadar AQL: `qradar/T1110_password_spraying_windows_4625.aql`

Sample data:
- Benign: `data/T1110_password_spraying/benign/windows_security_failed_logons.jsonl`
- Malicious: `data/T1110_password_spraying/malicious/windows_security_failed_logons.jsonl`

Tests:
- `tests/test_cases.yml`
- Run from repo root: `python tests/run_detection_tests.py`

Triage + tuning:
- `docs/triage.md`
- `docs/false_positives.md`
