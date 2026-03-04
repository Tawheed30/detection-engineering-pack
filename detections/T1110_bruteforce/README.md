# T1110 Brute Force — Windows Failed Logons (4625)

## Goal
Detect **brute force attempts** by identifying **>=10 failed logons (EventID 4625)** within **5 minutes**, grouped by:
- `TargetUserName`
- `IpAddress`

MITRE ATT&CK:
- **T1110** (Credential Access → Brute Force)

## Detection logic
- Source: Windows Security logs
- Signal: repeated `4625` for same user + source IP
- Threshold: `count >= 10` in `5m`

Files:
- Sigma: `sigma/T1110_bruteforce_windows_failed_logons.yml`
- Splunk SPL: `splunk/T1110_bruteforce_windows_failed_logons.spl`
- QRadar AQL: `qradar/T1110_bruteforce_windows_failed_logons.aql`

## Sample data (for testing)
- Benign: `data/T1110_bruteforce/benign/windows_security_failed_logons.jsonl` (8 events)
- Malicious: `data/T1110_bruteforce/malicious/windows_security_failed_logons.jsonl` (12 events)

Log schema reference:
- `docs/log-format.md`

## How to run tests (local)
From repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python tests/run_detection_tests.py
```

Expected:
- benign case = no alert
- malicious case = alert

## Triage + tuning
- Analyst playbook: `docs/triage.md`
- False positives + tuning: `docs/false_positives.md`

## Tuning knobs (recommended order)
1) Allowlist known scanner / VPN / management IP ranges
2) Prioritize `LogonType=10` (RDP) or raise severity for it
3) Correlate 4625 → 4624 success for same user+IP
4) Lower threshold / raise severity for privileged accounts
