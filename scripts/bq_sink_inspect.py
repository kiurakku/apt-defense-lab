#!/usr/bin/env python3
"""
Inspect BigQuery tables created by the Cloud Logging → BigQuery sink (Terraform: logging.tf).

The sink writes rows with the **managed Cloud Logging schema** (not the lab table raw_compressed_logs).

Why a random LIMIT 1 row often looks "uncompressed":
  Trivy scan jobs log many **plain** stderr lines (INFO, DB download). The vulnerability report is
  **gzip → base64** and appears as **long base64-like spans** in separate log lines. This script
  prefers those rows for [S-BQ-3] evidence.

This script:
  1) Lists sink tables (excluding raw_compressed_logs / clean_vulnerabilities).
  2) Picks a table with rows containing long base64-like text (or falls back to first non-empty).
  3) Prints compact schema by default; use --full-schema for INFORMATION_SCHEMA JSON.
  4) Fetches the best demonstration row (encoded payload), with long fields truncated for terminals.
  5) Optionally copies a discovered base64 blob into raw_compressed_logs for parse_trivy_bq.py.

Usage:
  python scripts/bq_sink_inspect.py --project PROJECT --dataset trivy_logs
  python scripts/bq_sink_inspect.py --project PROJECT --dataset trivy_logs --ingest-raw
  python scripts/bq_sink_inspect.py --project PROJECT --dataset trivy_logs --table stderr_20260409
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
_MIN_B64 = 96
_DISPLAY = 240


def find_sink_tables(client: bigquery.Client, project: str, dataset: str) -> list[str]:
    ds_ref = f"{project}.{dataset}"
    tables = list(client.list_tables(ds_ref))
    return sorted(t.table_id for t in tables if t.table_id not in EXCLUDE)


def table_row_count(client: bigquery.Client, fq: str) -> int:
    q = f"SELECT COUNT(1) AS c FROM `{fq}`"
    return int(next(client.query(q).result())["c"])


def count_b64_candidate_rows(client: bigquery.Client, fq: str) -> int:
    q = f"""
    SELECT COUNT(1) AS c FROM `{fq}`
    WHERE textPayload IS NOT NULL
      AND REGEXP_CONTAINS(textPayload, r'[A-Za-z0-9+/]{{{_MIN_B64},}}')
    """
    try:
        return int(next(client.query(q).result())["c"])
    except Exception:
        return 0


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
            query_parameters=[bigquery.ScalarQueryParameter("t", "STRING", table)],
        ),
    )
    return [dict(row) for row in job.result()]


def fetch_best_row(client: bigquery.Client, fq: str) -> tuple[dict[str, Any] | None, str]:
    """Return (row, note). Prefer log lines that contain gzip+b64 report transport."""

    def one(sql: str) -> dict[str, Any] | None:
        rows = list(client.query(sql).result())
        return dict(rows[0].items()) if rows else None

    q_b64 = f"""
    SELECT * FROM `{fq}`
    WHERE textPayload IS NOT NULL
      AND REGEXP_CONTAINS(textPayload, r'[A-Za-z0-9+/]{{{_MIN_B64},}}')
    ORDER BY LENGTH(textPayload) DESC
    LIMIT 1
    """
    row = one(q_b64)
    if row:
        return row, "row with long base64-like span (typical for gzip+json report transport)"

    q_long = f"""
    SELECT * FROM `{fq}`
    WHERE textPayload IS NOT NULL
    ORDER BY LENGTH(textPayload) DESC
    LIMIT 1
    """
    row = one(q_long)
    if row:
        return (
            row,
            "longest textPayload (may be plain INFO log — wait for scan report lines or check stdout_* )",
        )

    q_any = f"SELECT * FROM `{fq}` LIMIT 1"
    row = one(q_any)
    return (row, "first row (LIMIT 1)") if row else (None, "empty")


def _truncate_sample(obj: Any, max_len: int = _DISPLAY) -> Any:
    if isinstance(obj, str):
        if len(obj) <= max_len:
            return obj
        return f"{obj[:max_len]}… [truncated, {len(obj)} chars total]"
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if k == "textPayload" and isinstance(v, str):
                out[k] = _truncate_sample(v, max_len)
            else:
                out[k] = _truncate_sample(v, max_len) if isinstance(v, (dict, list)) else v
        return out
    if isinstance(obj, list):
        return [_truncate_sample(x, max_len) for x in obj[:30]]
    return obj


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


def pick_table(
    client: bigquery.Client,
    project: str,
    dataset: str,
    explicit: str | None,
) -> str:
    if explicit:
        return explicit
    tables = find_sink_tables(client, project, dataset)
    if not tables:
        raise RuntimeError("No sink tables found.")
    best: tuple[str, int] | None = None
    for t in tables:
        fq = f"{project}.{dataset}.{t}"
        try:
            n = count_b64_candidate_rows(client, fq)
            if n > 0 and (best is None or n > best[1]):
                best = (t, n)
        except Exception as exc:
            print(f"Skip {t}: {exc}", file=sys.stderr)
    if best:
        return best[0]
    for t in tables:
        fq = f"{project}.{dataset}.{t}"
        try:
            if table_row_count(client, fq) > 0:
                return t
        except Exception:
            continue
    return tables[0]


def main() -> int:
    p = argparse.ArgumentParser(description="Inspect Logging sink BQ tables + optional raw ingest.")
    p.add_argument("--project", required=True)
    p.add_argument("--dataset", default="trivy_logs")
    p.add_argument(
        "--table",
        metavar="ID",
        default=None,
        help="Sink table id (default: auto — prefer table with base64-like rows)",
    )
    p.add_argument(
        "--full-schema",
        action="store_true",
        help="Dump INFORMATION_SCHEMA as JSON (verbose)",
    )
    p.add_argument(
        "--ingest-raw",
        action="store_true",
        help="Insert first long base64-like string from sample row into raw_compressed_logs",
    )
    args = p.parse_args()

    client = bigquery.Client(project=args.project)
    tables = find_sink_tables(client, args.project, args.dataset)
    if not tables:
        print(
            "No sink tables found. Run terraform apply (logging.tf) and wait for logs.",
            file=sys.stderr,
        )
        return 1

    try:
        chosen = pick_table(client, args.project, args.dataset, args.table)
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1

    fq = f"{args.project}.{args.dataset}.{chosen}"
    print(f"=== Sink table: {chosen} ===\n")

    schema_rows = fetch_schema_json(client, args.project, args.dataset, chosen)
    if args.full_schema:
        print("--- INFORMATION_SCHEMA ---")
        print(json.dumps(schema_rows, indent=2))
    else:
        cols = ", ".join(f"{r['column_name']}:{r['data_type'][:24]}" for r in schema_rows[:18])
        more = len(schema_rows) - 18
        print("--- Schema (compact) ---")
        print(cols + (f" … (+{more} columns)" if more > 0 else ""))
    print()

    sample, note = fetch_best_row(client, fq)
    print(f"--- Sample row — {note} ---")

    def json_default(o: Any) -> Any:
        if hasattr(o, "isoformat"):
            return o.isoformat()
        return str(o)

    if sample is None:
        print("No rows.")
        return 0

    print(json.dumps(_truncate_sample(sample), indent=2, default=json_default))
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
