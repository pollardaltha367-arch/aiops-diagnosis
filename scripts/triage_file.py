"""Batch CLI: turn one local log artifact into a report and review queue."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from diagnosis_engine import diagnose, to_markdown


DEFAULT_MAX_BYTES = 50 * 1024 * 1024


def write_review_queue(path: Path, queue: list[dict]) -> None:
    fields = [
        "review_id", "priority", "anomaly_score", "classification_status", "categories",
        "occurrences", "objects", "services", "first_line", "last_line", "template",
        "score_reasons", "sample_evidence", "required_action",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in queue:
            row = dict(item)
            for field in ("categories", "objects", "services", "score_reasons", "sample_evidence"):
                row[field] = "；".join(str(value) for value in row.get(field, []))
            writer.writerow({field: row.get(field, "") for field in fields})


def triage(input_path: Path, output_dir: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> dict:
    size = input_path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"Input is {size} bytes; limit is {max_bytes}. Split by time window before analysis.")
    text = input_path.read_text(encoding="utf-8", errors="replace")
    report = diagnose(text, input_path.name)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "report.md").write_text(to_markdown(report), encoding="utf-8")
    (output_dir / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    write_review_queue(output_dir / "review_queue.csv", report["review_queue"])
    return {
        "input": str(input_path), "bytes": size, "events": report["summary"]["events"],
        "queue_items": report["review_summary"]["queue_items"],
        "high_priority": report["review_summary"]["high_priority"],
        "medium_priority": report["review_summary"]["medium_priority"],
        "output": str(output_dir),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a read-only AIOps review queue from a local log file.")
    parser.add_argument("input", type=Path, help="LOG/TXT/CSV/JSON/JSONL input")
    parser.add_argument("--output", type=Path, default=Path("triage-output"), help="Output directory")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="Safety size limit")
    args = parser.parse_args()
    print(json.dumps(triage(args.input, args.output, args.max_bytes), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
