# False Positives + Tuning (T1110 / 4625)

## Common false positives
1) Users typing wrong password repeatedly (especially mornings / after password change)
2) Misconfigured services using stale credentials (scheduled tasks, services, backups)
3) Vulnerability scanners / pentest activity from known scanner IP ranges
4) Shared devices / jump hosts where many users authenticate

## Tuning strategy (do in this order)
### 1) Allowlist known-good sources (best ROI)
- scanner subnets
- corporate VPN egress IPs (if expected)
- known management servers / jump boxes

### 2) Focus on higher-risk logon types
- Prioritize LogonType=10 (RDP)
- Keep LogonType=3 but consider higher threshold if too noisy

### 3) Tighten to “bad password” patterns (Status/SubStatus)
Typical bad password: Status=0xC000006D and SubStatus=0xC000006A
If you see lots of unknown-user attempts (often spray): SubStatus=0xC0000064

### 4) Add “privileged account” boost
Lower threshold or raise severity when target_user is:
- administrator
- domain admins
- service accounts with broad privileges

### 5) Reduce noisy internal traffic
- Exclude src_ip in RFC1918 ranges if your environment generates lots of internal auth noise
  (Only do this if you have separate internal detections.)

## What NOT to do
- Don’t blanket ignore EventID 4625 — it’s a core signal.
- Don’t tune only by raising the threshold to something huge (you’ll miss real attacks).
