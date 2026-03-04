#!/usr/bin/env python3
import glob
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml


def parse_ts(ts: str) -> datetime:
    # Supports ISO-8601 like "2026-03-04T10:00:00Z"
    ts = ts.strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


def max_count_in_window(timestamps, window_seconds: int) -> int:
    # Sliding window over sorted timestamps
    if not timestamps:
        return 0
    timestamps.sort()
    best = 0
    left = 0
    for right in range(len(timestamps)):
        while (timestamps[right] - timestamps[left]).total_seconds() > window_seconds:
            left += 1
        best = max(best, right - left + 1)
    return best


def eval_threshold_jsonl(log_path: str, group_by: list[str], timeframe_minutes: int, threshold: int) -> bool:
    groups: dict[tuple, list[datetime]] = {}
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            evt = json.loads(line)

            # require timestamp + all group fields
            if "@timestamp" not in evt:
                continue
            key_vals = []
            missing = False
            for field in group_by:
                if field not in evt or evt[field] in (None, "", "-"):
                    missing = True
                    break
                key_vals.append(str(evt[field]))
            if missing:
                continue

            ts = parse_ts(evt["@timestamp"])
            key = tuple(key_vals)
            groups.setdefault(key, []).append(ts)

    window_seconds = timeframe_minutes * 60
    for key, ts_list in groups.items():
        mx = max_count_in_window(ts_list, window_seconds)
        if mx >= threshold:
            return True
    return False


@dataclass
class CaseResult:
    detection_id: str
    case_name: str
    log_file: str
    expected: bool
    actual: bool


def main() -> int:
    test_files = sorted(glob.glob("detections/**/tests/test_cases.yml", recursive=True))
    if not test_files:
        print("No test_cases.yml found under detections/**/tests/")
        return 2

    results: list[CaseResult] = []
    failed = 0

    for tf in test_files:
        with open(tf, "r", encoding="utf-8") as f:
            spec = yaml.safe_load(f)

        detection_id = spec["detection_id"]
        timeframe_minutes = int(spec["timeframe_minutes"])
        threshold = int(spec["threshold"])
        group_by = list(spec["group_by"])

        for case in spec["cases"]:
            name = case["name"]
            log_file = case["log_file"]
            expected = bool(case["expect_alert"])

            if not Path(log_file).exists():
                print(f"[ERROR] Missing log file: {log_file} (referenced by {tf})")
                failed += 1
                continue

            actual = eval_threshold_jsonl(
                log_path=log_file,
                group_by=group_by,
                timeframe_minutes=timeframe_minutes,
                threshold=threshold,
            )

            results.append(CaseResult(detection_id, name, log_file, expected, actual))
            ok = (expected == actual)
            status = "PASS" if ok else "FAIL"
            print(f"[{status}] {detection_id} :: {name} :: expected={expected} actual={actual} :: {log_file}")
            if not ok:
                failed += 1

    print("\nSummary:")
    print(f"  Total cases: {len(results)}")
    print(f"  Failed:      {failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
