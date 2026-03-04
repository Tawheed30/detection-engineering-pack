# T1110 Password Spraying (Windows 4625) — Triage Playbook

## Alert intent
Detect password spraying: **one source IP** failing authentication across **many distinct usernames** within **10 minutes**.

## What to capture from the alert
- src_ip
- distinct_users + list of attempted users
- time window (first_seen/last_seen)
- impacted hosts
- logon_types (3=Network, 10=RDP)

## Fast triage (2–5 minutes)
1) Is src_ip external? If yes, higher confidence.
2) Are targeted usernames real/valid in your directory? (random names = spray attempt)
3) Any success after failures? Look for **4624** for same src_ip.
4) Any account lockouts? Look for **4740** for targeted users.

## Escalation signals
- 4624 success for any sprayed user from same src_ip
- targeting privileged accounts (administrator/domain admins/service accounts)
- multiple hosts involved
- src_ip matches threat intel / TOR / hosting provider ASN

## Containment actions
- Block src_ip at perimeter/VPN/identity provider if external
- Force reset + MFA enforcement for any account that later succeeded
- If internal src_ip: identify host owner and isolate via EDR, investigate for tooling

## Splunk pivots
### A) Users targeted by this src_ip
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625
| eval target_user=coalesce(TargetUserName, Account_Name, user)
| eval src_ip=coalesce(IpAddress, src, Source_Network_Address)
| search src_ip="<SRC_IP>"
| stats count dc(target_user) as uniq_users values(target_user) as users by src_ip

### B) Success after failures
index=wineventlog sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| eval target_user=coalesce(TargetUserName, Account_Name, user)
| eval src_ip=coalesce(IpAddress, src, Source_Network_Address)
| search src_ip="<SRC_IP>"
| stats count by EventCode target_user host
