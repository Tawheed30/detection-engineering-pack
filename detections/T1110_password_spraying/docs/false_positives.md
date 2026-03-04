# False Positives + Tuning (Password Spraying)

## Common false positives
- NAT/VPN egress IP where many users authenticate (shared source IP)
- Jump hosts / Citrix / VDI brokers
- Internal password audit tools
- Vulnerability scanners from known ranges

## Tuning strategy
1) Allowlist corporate VPN/NAT ranges and known management/jump hosts
2) Require external src_ip (if you have internal-only noise)
3) Increase threshold for known shared egress points (e.g., 10+ distinct users)
4) Boost severity for:
   - LogonType=10 (RDP)
   - privileged usernames
   - follow-up 4624 success

## Don’t do this
- Don’t exclude all shared IPs blindly — attackers can come through the same paths (VPN compromise).
