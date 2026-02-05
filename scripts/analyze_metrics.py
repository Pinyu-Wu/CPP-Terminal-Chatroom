#!/usr/bin/env python3
import argparse
import json
import sys
from datetime import datetime


def parse_ts(ts_value: str):
    try:
        return datetime.strptime(ts_value, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def load_entries(path: str):
    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = parse_ts(obj.get("ts", ""))
            if ts is None:
                continue
            obj["_ts"] = ts
            obj["_raw"] = line
            entries.append(obj)
    return entries


def find_markers(entries, run_id: str):
    start_ts = None
    end_ts = None
    if not run_id:
        return start_ts, end_ts
    start_token = f"TEST_START run_id={run_id}"
    end_token = f"TEST_END run_id={run_id}"
    for entry in entries:
        raw = entry.get("_raw", "")
        if start_token in raw:
            start_ts = entry["_ts"]
        if end_token in raw:
            end_ts = entry["_ts"]
    return start_ts, end_ts


def filter_window(entries, start_ts, end_ts):
    if start_ts is None and end_ts is None:
        return entries
    filtered = []
    for entry in entries:
        ts = entry["_ts"]
        if start_ts and ts < start_ts:
            continue
        if end_ts and ts > end_ts:
            continue
        filtered.append(entry)
    return filtered


def summarize_metrics(metrics_entries, start_ts=None, end_ts=None):
    metrics = [e for e in metrics_entries if e.get("action") == "metrics_dump"]
    if not metrics:
        return None
    metrics.sort(key=lambda e: e["_ts"])
    first = metrics[0]
    last = metrics[-1]

    baseline = None
    if start_ts is not None:
        for m in metrics:
            if m["_ts"] < start_ts:
                baseline = m
            else:
                break
    if baseline is None:
        baseline = first

    qps_values = [m.get("qps", 0.0) for m in metrics if isinstance(m.get("qps"), (int, float))]
    avg_qps = sum(qps_values) / len(qps_values) if qps_values else 0.0
    peak_qps = max(qps_values) if qps_values else 0.0

    first_actions = baseline.get("actions", {}) if isinstance(baseline.get("actions"), dict) else {}
    last_actions = last.get("actions", {}) if isinstance(last.get("actions"), dict) else {}

    action_stats = {}
    for action, stats in last_actions.items():
        if not isinstance(stats, dict):
            continue
        last_count = stats.get("count", 0)
        if len(metrics) <= 1 or baseline is first:
            first_count = 0
        else:
            first_count = 0
            if action in first_actions and isinstance(first_actions[action], dict):
                first_count = first_actions[action].get("count", 0)
        action_stats[action] = {
            "count": max(0, last_count - first_count),
            "p50_ms": stats.get("p50_ms", 0),
            "p95_ms": stats.get("p95_ms", 0),
            "p99_ms": stats.get("p99_ms", 0),
        }

    return {
        "avg_qps": avg_qps,
        "peak_qps": peak_qps,
        "action_stats": action_stats,
    }


def summarize_errors(entries):
    request_logs = [e for e in entries if e.get("action") == "request" and "status" in e]
    if not request_logs:
        return None
    total = len(request_logs)
    fail = sum(1 for e in request_logs if e.get("status") != "success")
    rate = (fail / total) * 100.0 if total else 0.0
    return {"total": total, "fail": fail, "rate": rate}


def main():
    parser = argparse.ArgumentParser(description="Analyze chat server JSON logs")
    parser.add_argument("--log", required=True, help="Path to server JSON log file")
    parser.add_argument("--run-id", default="", help="Run id used in TEST_START/TEST_END markers")
    args = parser.parse_args()

    all_entries = load_entries(args.log)
    if not all_entries:
        print("No valid JSON log entries found.", file=sys.stderr)
        return 1

    start_ts, end_ts = find_markers(all_entries, args.run_id.strip())
    if args.run_id and start_ts is None and end_ts is None:
        print("Warning: no markers found for run_id; analyzing full log.", file=sys.stderr)

    entries = filter_window(all_entries, start_ts, end_ts)
    if not entries:
        print("No log entries in the selected window.", file=sys.stderr)
        return 1

    entries.sort(key=lambda e: e["_ts"])
    duration = (entries[-1]["_ts"] - entries[0]["_ts"]).total_seconds()

    metrics = summarize_metrics(all_entries, start_ts, end_ts)
    errors = summarize_errors(entries)

    print(f"Test duration: {duration:.2f} seconds")
    if metrics:
        print(f"Average QPS: {metrics['avg_qps']:.2f}")
        print(f"Peak QPS: {metrics['peak_qps']:.2f}")
        print("Per-action count / p50 / p95 / p99:")
        for action in sorted(metrics["action_stats"].keys()):
            s = metrics["action_stats"][action]
            print(f"  - {action}: count={s['count']} p50={s['p50_ms']}ms p95={s['p95_ms']}ms p99={s['p99_ms']}ms")
    else:
        print("Average QPS: N/A (no metrics_dump entries)")
        print("Peak QPS: N/A (no metrics_dump entries)")
        print("Per-action count / p50 / p95 / p99: N/A")

    if errors:
        print(f"Error rate: {errors['rate']:.2f}% (fail {errors['fail']} / total {errors['total']})")
    else:
        print("Error rate: N/A (no request entries)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
