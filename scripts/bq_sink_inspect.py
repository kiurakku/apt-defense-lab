#!/usr/bin/env python3
"""
Inspect BigQuery tables created by the Cloud Logging → BigQuery sink (Terraform: logging.tf).

The sink writes rows with the **managed Cloud Logging schema** (not the lab table raw_compressed_logs).
This script:
  1) Lists tables in the dataset (excluding raw_compressed_logs / clean_vulnerabilities).
  2) Prints JSON schema for the first sink table found (via INFORMATION_SCHEMA).
  3) Fetches one sample row (pretty-printed JSON) from that table.
  4) Optionally copies a discovered base64-looking blob into raw_compressed_logs for parse_trivy_bq.py.

Usage:
  python bq_sink_inspect.py --project PROJECT --dataset trivy_logs
  python bq_sink_inspect.py --project PROJECT --dataset trivy_logs --ingest-raw
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from typing import Any

from google.cloud import bigquery

EXCLUDE = frozenset({"raw_compressed_logs", "clean_vulnerabilities"})


def find_sink_tables(client: bigquery.Client, project: str, dataset: str) -> list[str]:
    ds_ref = f"{project}.{dataset}"
    tables = list(client.list_tables(ds_ref))
    return sorted(
        t.table_id for t in tables if t.table_id not in EXCLUDE
    )


def table_row_count(client: bigquery.Client, fq: str) -> int:
    q = f"SELECT COUNT(1) AS c FROM `{fq}`"
    return next(client.query(q).result())["c"]


def fetch_schema_json(client: bigquery.Client, project: str, dataset: str, table: str) -> list[dict[str, Any]]:
    q = f"""
    SELECT column_name, data_type, is_nullable
    FROM `{project}.{dataset}.INFORMATION_SCHEMA.COLUMNS`
    WHERE table_name = @t
    ORDER BY ordinal_position
    """
    job = client.query(
        q,
        job_config=bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("t", "STRING", table),
            ]
        ),
    )
    return [dict(row) for row in job.result()]


def fetch_sample_row(client: bigquery.Client, fq: str) -> dict[str, Any] | None:
    q = f"SELECT * FROM `{fq}` LIMIT 1"
    rows = list(client.query(q).result())
    if not rows:
        return None
    return dict(rows[0].items())


def walk_for_b64_strings(obj: Any, out: list[str]) -> None:
    if isinstance(obj, str):
        if len(obj) > 80 and re.match(r"^[A-Za-z0-9+/=\s]+$", obj):
            out.append(obj.replace("\n", "").strip())
    elif isinstance(obj, dict):
        for v in obj.values():
            walk_for_b64_strings(v, out)
    elif isinstance(obj, list):
        for v in obj:
            walk_for_b64_strings(v, out)


def main() -> int:
    p = argparse.ArgumentParser(description="Inspect Logging sink BQ tables + optional raw ingest.")
    p.add_argument("--project", required=True)
    p.add_argument("--dataset", default="trivy_logs")
    p.add_argument(
        "--ingest-raw",
        action="store_true",
        help="Try to insert first long base64-like string from sample row into raw_compressed_logs",
    )
    args = p.parse_args()

    client = bigquery.Client(project=args.project)
    tables = find_sink_tables(client, args.project, args.dataset)
    if not tables:
        print(
            "No sink tables found (only manual tables?). Run terraform apply (logging.tf) and wait for logs.",
            file=sys.stderr,
        )
        return 1

    # Prefer a table that has rows
    chosen = None
    for t in tables:
        fq = f"{args.project}.{args.dataset}.{t}"
        try:
            if table_row_count(client, fq) > 0:
                chosen = t
                break
        except Exception as exc:
            print(f"Skip {t}: {exc}", file=sys.stderr)

    if not chosen:
        chosen = tables[0]

    fq = f"{args.project}.{args.dataset}.{chosen}"
    print(f"=== Sink table: {chosen} ===\n")

    schema_rows = fetch_schema_json(client, args.project, args.dataset, chosen)
    print("--- INFORMATION_SCHEMA (subset) ---")
    print(json.dumps(schema_rows, indent=2))
    print()

    sample = fetch_sample_row(client, fq)
    if sample is None:
        print("No rows yet in table (wait for trivy-operator logs).")
        return 0

    # Timestamps etc. may not be JSON-serializable by default
    def json_default(o: Any) -> Any:
        if hasattr(o, "isoformat"):
            return o.isoformat()
        return str(o)

    print("--- Sample row (one) ---")
    print(json.dumps(sample, indent=2, default=json_default))
    print()

    if args.ingest_raw:
        blobs: list[str] = []
        walk_for_b64_strings(sample, blobs)
        if not blobs:
            print("No base64-like blob found in sample row; ingest skipped.", file=sys.stderr)
            return 0
        raw = blobs[0]
        insert_time = sample.get("timestamp") or sample.get("receiveTimestamp")
        if hasattr(insert_time, "isoformat"):
            ts = insert_time.isoformat()
        elif isinstance(insert_time, str):
            ts = insert_time
        else:
            ts = datetime.now(timezone.utc).isoformat()
        row = {
            "insert_time": ts,
            "namespace": "sink-ingest",
            "report_name": chosen,
            "log_data": raw,
        }
        table_id = f"{args.project}.{args.dataset}.raw_compressed_logs"
        errors = client.insert_rows_json(table_id, [row])
        if errors:
            print(f"Insert errors: {errors}", file=sys.stderr)
            return 1
        print("--- Inserted one row into raw_compressed_logs (run parse_trivy_bq.py next) ---")
        print(json.dumps(row, indent=2, default=json_default))

    return 0


if __name__ == "__main__":
    sys.exit(main())
