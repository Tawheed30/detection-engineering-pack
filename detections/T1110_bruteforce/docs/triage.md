# T1110 Brute Force (Windows 4625) — Triage Playbook

## Alert intent
Excessive failed logons (**EventID 4625**) aggregated by **TargetUserName + Src IP** within **5 minutes**.
Goal: catch brute force attempts early and distinguish from user typos / noisy systems.

## What to capture from the alert
- target_user
- src_ip
- time window (start/end)
- fail_count
- affected hosts (Computer/host)
- logon_types (3=Network, 10=RDP are most relevant)
- Status/SubStatus (e.g., 0xC000006D/0xC000006A = bad password)

## Immediate validation (2 minutes)
1) Confirm it meets threshold (>=10 in 5m).
2) Check if src_ip is **external** or **internal**.
3) Check if target_user is **privileged** (administrator/domain admin/service account).
4) Check if logon type indicates interactive access:
   - LogonType=10 (RDP) = higher priority
   - LogonType=3 (Network) = common for SMB/WinRM/etc.

## High-confidence escalation signals
- Failures followed by a **success** for same target_user + src_ip (look for **EventID 4624**).
- Multiple hosts targeted from same src_ip (spray / automated tooling).
- Account lockouts (**EventID 4740**) shortly after.
- Attempts against many usernames from same src_ip (password spraying pattern).

## Splunk pivots (copy/paste templates)
### A) Look for success after failures (same user + IP)
index=wineventlog sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| eval target_user=coalesce(TargetUserName, Account_Name, user)
| eval src_ip=coalesce(IpAddress, src, Source_Network_Address)
| search target_user="<TARGET_USER>" src_ip="<SRC_IP>"
| stats count by EventCode target_user src_ip host

### B) See if src_ip is spraying multiple users
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625
| eval target_user=coalesce(TargetUserName, Account_Name, user)
| eval src_ip=coalesce(IpAddress, src, Source_Network_Address)
| search src_ip="<SRC_IP>"
| stats count dc(target_user) as uniq_users values(target_user) as users by src_ip

### C) Check lockouts
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4740
| search TargetUserName="<TARGET_USER>"

## QRadar pivots (operator workflow)
- Pivot on source IP → “View Events” last 1h
- Search for:
  - 4624 (successful logon)
  - 4740 (account lockout)
  - repeated 4625 against multiple usernames

## Containment actions (choose based on confidence)
- If external IP + high rate:
  - Block src_ip at firewall/WAF/VPN gateway
  - Force password reset for target_user if privileged or success observed
  - Review MFA status / enforce MFA if missing
- If internal IP:
  - Identify the device owner (asset inventory / DHCP / VPN logs)
  - Check for malware / credential stuffing tools on that endpoint
  - Contain endpoint via EDR isolation if needed

## Evidence to attach to ticket
- Timeline of failures (counts per minute)
- Any 4624 success correlation
- Impacted hosts + logon types
- IP enrichment (geo/ASN/reputation if you have it)
- Recommended tuning/exclusions if clearly benign
