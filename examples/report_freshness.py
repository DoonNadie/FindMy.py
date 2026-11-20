"""Compare the timestamps of two successful report queries, without network access."""

import argparse
import json
from datetime import datetime
from pathlib import Path


def summarize(current, previous):
    queried = datetime.fromisoformat(current["queried_at"])
    baseline = {row["name"]: row.get("timestamp") for row in previous.get("results", [])}
    for row in current["results"]:
        name, timestamp = row["name"], row.get("timestamp")
        if not timestamp:
            yield {"name": name, "status": "no_report", "age_seconds": None}
            continue
        reported = datetime.fromisoformat(timestamp)
        if reported > queried:
            yield {"name": name, "status": "future_timestamp", "age_seconds": None}
            continue
        prior = baseline.get(name)
        status = "no_baseline"
        if prior:
            before = datetime.fromisoformat(prior)
            status = "newer" if reported > before else "older" if reported < before else "unchanged"
        yield {"name": name, "status": status,
               "age_seconds": int((queried - reported).total_seconds())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("current", type=Path)
    parser.add_argument("--previous", type=Path)
    args = parser.parse_args()
    current = json.loads(args.current.read_text(encoding="utf-8"))
    previous = json.loads(args.previous.read_text(encoding="utf-8")) if args.previous else {}
    rows = list(summarize(current, previous))
    coverage = {row["name"]: row for row in current.get("diagnostics", {}).get("reports", [])}
    for row in rows:
        if stats := coverage.get(row["name"]):
            for field in ("requested_lookback_days", "report_count", "batches_attempted"):
                row[field] = stats[field]
            row["batches_failed"] = len(stats["batch_errors"])
            if row["batches_failed"]:
                row["status"] = "incomplete"
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
