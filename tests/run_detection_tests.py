#!/usr/bin/env python3
import glob
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml


def parse_ts(ts: str) -> datetime:
    ts = ts.strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


def max_count_in_window(timestamps, window_seconds: int) -> int:
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


def max_distinct_in_window(events, window_seconds: int) -> int:
    """
    events: list of (timestamp, value)
    Returns max distinct value count within any sliding window.
    """
    if not events:
        return 0
    events.sort(key=lambda x: x[0])

    left = 0
    counts = {}
    best = 0

    for right in range(len(events)):
        ts_r, val_r = events[right]
        counts[val_r] = counts.get(val_r, 0) + 1

        while (events[right][0] - events[left][0]).total_seconds() > window_seconds:
            _, val_l = events[left]
            counts[val_l] -= 1
            if counts[val_l] <= 0:
                del counts[val_l]
            left += 1

        best = max(best, len(counts))
    return best


def eval_event_count_jsonl(log_path: str, group_by: list[str], timeframe_minutes: int, threshold: int) -> bool:
    groups: dict[tuple, list[datetime]] = {}

    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            evt = json.loads(line)

            if "@timestamp" not in evt:
                continue

            key_vals = []
            for field in group_by:
                if field not in evt or evt[field] in (None, "", "-"):
                    key_vals = None
                    break
                key_vals.append(str(evt[field]))
            if key_vals is None:
                continue

            ts = parse_ts(evt["@timestamp"])
            key = tuple(key_vals)
            groups.setdefault(key, []).append(ts)

    window_seconds = timeframe_minutes * 60
    for _, ts_list in groups.items():
        mx = max_count_in_window(ts_list, window_seconds)
        if mx >= threshold:
            return True
    return False


def eval_value_count_jsonl(
    log_path: str,
    group_by: list[str],
    value_field: str,
    timeframe_minutes: int,
    threshold: int,
) -> bool:
    groups: dict[tuple, list[tuple[datetime, str]]] = {}

    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            evt = json.loads(line)

            if "@timestamp" not in evt:
                continue
            if value_field not in evt or evt[value_field] in (None, "", "-"):
                continue

            key_vals = []
            for field in group_by:
                if field not in evt or evt[field] in (None, "", "-"):
                    key_vals = None
                    break
                key_vals.append(str(evt[field]))
            if key_vals is None:
                continue

            ts = parse_ts(evt["@timestamp"])
            key = tuple(key_vals)
            groups.setdefault(key, []).append((ts, str(evt[value_field])))

    window_seconds = timeframe_minutes * 60
    for _, event_list in groups.items():
        mx = max_distinct_in_window(event_list, window_seconds)
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

    failed = 0
    total = 0

    for tf in test_files:
        with open(tf, "r", encoding="utf-8") as f:
            spec = yaml.safe_load(f) or {}

        detection_id = spec.get("detection_id", Path(tf).as_posix())
        rule_type = spec.get("rule_type", "event_count")  # event_count | value_count
        timeframe_minutes = int(spec.get("timeframe_minutes", 5))
        threshold = int(spec.get("threshold", 1))
        group_by = list(spec.get("group_by", []))
        value_field = spec.get("value_field")

        for case in spec.get("cases", []):
            total += 1
            name = case["name"]
            log_file = case["log_file"]
            expected = bool(case["expect_alert"])

            if not Path(log_file).exists():
                print(f"[ERROR] Missing log file: {log_file} (referenced by {tf})")
                failed += 1
                continue

            if rule_type == "event_count":
                actual = eval_event_count_jsonl(log_file, group_by, timeframe_minutes, threshold)
            elif rule_type == "value_count":
                if not value_field:
                    print(f"[ERROR] value_count requires 'value_field' in {tf}")
                    failed += 1
                    continue
                actual = eval_value_count_jsonl(log_file, group_by, value_field, timeframe_minutes, threshold)
            else:
                print(f"[ERROR] Unknown rule_type '{rule_type}' in {tf}")
                failed += 1
                continue

            ok = (expected == actual)
            status = "PASS" if ok else "FAIL"
            print(f"[{status}] {detection_id} :: {name} :: expected={expected} actual={actual} :: {log_file}")
            if not ok:
                failed += 1

    print("\nSummary:")
    print(f"  Total cases: {total}")
    print(f"  Failed:      {failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
