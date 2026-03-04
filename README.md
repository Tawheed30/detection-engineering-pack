# Detection Engineering Pack

A production-style detection repository:
- MITRE ATT&CK mapped detections (Sigma + Splunk SPL + QRadar AQL)
- Curated benign/malicious log samples
- Automated tests to validate detections
- Dashboards + triage notes + false-positive tuning guidance

## Repo layout
- detections/ – one folder per technique (e.g., T1110_bruteforce/)
- data/ – small curated log samples (benign + malicious)
- tests/ – automated detection validation
- docs/ – triage steps, FP tuning, severity rubric
- dashboards/ – Splunk/QRadar exports (optional)
