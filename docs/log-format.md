# Log Format (JSONL)

All sample logs in `data/**` are **JSON Lines** (one JSON object per line).

## Required fields (minimum)
- `@timestamp` (ISO-8601 UTC, e.g. 2026-03-04T10:00:00Z)
- `EventID` (integer)
- `Channel` (string) - e.g. "Security"
- `Computer` (string) - hostname
- `TargetUserName` (string)
- `IpAddress` (string)
- `LogonType` (integer)
- `Status` (string hex) - e.g. "0xC000006D"
- `SubStatus` (string hex) - e.g. "0xC000006A"

## Notes
- For Windows failed logons we model **EventID 4625**.
- We keep fields flat to make testing and translations straightforward.
