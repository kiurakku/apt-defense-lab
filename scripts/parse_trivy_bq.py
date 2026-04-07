#!/usr/bin/env python3
"""
Trivy BQ Log Parser
====================
Trivy operator stores VulnerabilityReport data compressed:
  1. Report JSON is serialized
  2. Compressed with gzip
  3. Encoded as base64
  4. Stored in k8s CR annotation / ConfigMap, then shipped to Cloud Logging

This script:
  1. Reads raw compressed rows from BQ table `raw_compressed_logs`, OR (--from-sink)
     rows from Cloud Logging sink auto-tables (managed schema).
  2. base64-decodes → gunzips → json.loads each blob
  3. Extracts vulnerabilities from Results[].Vulnerabilities[]
  4. Inserts clean rows into `clean_vulnerabilities` table
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import logging
import re
import sys
from datetime import date, datetime, time, timezone
from typing import Any, Iterator

from google.cloud import bigquery

LOGGER = logging.getLogger("parse_trivy_bq")

# Tables managed by this repo (not Logging sink exports)
_EXCLUDE_SINK_SCAN = frozenset({"raw_compressed_logs", "clean_vulnerabilities"})
_B64ISH = re.compile(r"^[A-Za-z0-9+/=\s]+$")


def decode_blob(raw: str) -> dict[str, Any]:
    """Decode base64(gzip(JSON)) to a dict."""
    compressed = base64.b64decode(raw)
    text = gzip.decompress(compressed).decode("utf-8")
    return json.loads(text)


def iter_vulnerabilities(payload: dict[str, Any]) -> Iterator[dict[str, Any]]:
    results = payload.get("Results") or []
    if not isinstance(results, list):
        return
    for res in results:
        if not isinstance(res, dict):
            continue
        vulns = res.get("Vulnerabilities") or []
        if not isinstance(vulns, list):
            continue
        for v in vulns:
            if isinstance(v, dict):
                yield v


def _ts_for_bq(ts: Any) -> str:
    if ts is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(ts, datetime):
        return ts.isoformat()
    if isinstance(ts, date):
        return datetime.combine(ts, time.min, tzinfo=timezone.utc).isoformat()
    return str(ts)


def _walk_strings(obj: Any, out: list[str]) -> None:
    if isinstance(obj, str):
        s = obj.strip()
        if len(s) >= 80 and _B64ISH.match(s):
            out.append(s.replace("\n", "").replace(" ", ""))
    elif isinstance(obj, dict):
        for v in obj.values():
            _walk_strings(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _walk_strings(v, out)


def _row_to_nested_dict(row: Any) -> dict[str, Any]:
    return {k: row[k] for k in row.keys()}


def _report_label_from_sink_row(d: dict[str, Any]) -> str:
    for key in ("insertId", "log_name", "log_id"):
        v = d.get(key)
        if v:
            return str(v)
    res = d.get("resource") or {}
    if isinstance(res, dict):
        labels = res.get("labels") or {}
        if isinstance(labels, dict) and labels.get("pod_name"):
            return str(labels["pod_name"])
    return "sink-row"


def _find_sink_table(client: bigquery.Client, project: str, dataset: str) -> tuple[str, int]:
    """Return (table_id, row_count) for best sink table candidate."""
    ds = f"{project}.{dataset}"
    candidates: list[tuple[str, int]] = []
    for t in client.list_tables(ds):
        if t.table_id in _EXCLUDE_SINK_SCAN:
            continue
        fq = f"{project}.{dataset}.{t.table_id}"
        try:
            q = f"SELECT COUNT(1) AS c FROM `{fq}`"
            c = next(client.query(q).result())["c"]
            if c and int(c) > 0:
                candidates.append((t.table_id, int(c)))
        except Exception as exc:
            LOGGER.debug("Skip table %s: %s", t.table_id, exc)

    if not candidates:
        raise RuntimeError(
            "No non-empty sink tables found. Apply terraform/logging.tf and wait for trivy-operator logs."
        )
    candidates.sort(key=lambda x: -x[1])
    return candidates[0]


def run_from_sink(
    project: str,
    dataset: str,
    clean_table: str,
    limit: int,
) -> int:
    """Read Cloud Logging → BQ export rows, find gzip+base64 blobs, fill clean_vulnerabilities."""
    client = bigquery.Client(project=project)
    table_id, total = _find_sink_table(client, project, dataset)
    LOGGER.info("Using sink table %s (~%s rows)", table_id, total)

    fq = f"`{project}.{dataset}.{table_id}`"
    clean_fq = f"{project}.{dataset}.{clean_table}"

    # Sink tables use Cloud Logging schema (timestamp column is typical; avoid ORDER BY if missing).
    q = f"SELECT * FROM {fq} LIMIT {limit}"
    rows_to_insert: list[dict[str, Any]] = []

    try:
        job = client.query(q)
        for row in job.result():
            d = _row_to_nested_dict(row)
            ins = d.get("timestamp") or d.get("receiveTimestamp") or datetime.now(timezone.utc)
            report_name = _report_label_from_sink_row(d)

            candidates: list[str] = []
            _walk_strings(d, candidates)

            decoded: dict[str, Any] | None = None
            for raw in candidates:
                try:
                    decoded = decode_blob(raw)
                    break
                except (OSError, ValueError, json.JSONDecodeError):
                    continue

            if decoded is None:
                LOGGER.debug("No decodable Trivy blob in row %s", report_name)
                continue

            image = (
                decoded.get("ArtifactName")
                or decoded.get("artifactName")
                or decoded.get("image")
                or ""
            )
            ns_val = decoded.get("Namespace") or decoded.get("namespace") or ""

            for vuln in iter_vulnerabilities(decoded):
                rows_to_insert.append(
                    {
                        "insert_time": _ts_for_bq(ins),
                        "namespace": str(ns_val) if ns_val is not None else None,
                        "report_name": str(report_name) if report_name else None,
                        "image": str(image),
                        "vulnerability_id": vuln.get("VulnerabilityID", ""),
                        "severity": vuln.get("Severity", ""),
                        "pkg_name": vuln.get("PkgName", ""),
                        "installed_version": vuln.get("InstalledVersion", ""),
                        "fixed_version": vuln.get("FixedVersion", ""),
                        "title": vuln.get("Title", ""),
                    }
                )

        if not rows_to_insert:
            LOGGER.info("No vulnerability rows extracted from sink (no valid compressed reports in sample).")
            return 0

        errors = client.insert_rows_json(clean_fq, rows_to_insert)
        if errors:
            LOGGER.error("BigQuery insert errors: %s", errors)
            return 1

        LOGGER.info("Inserted %s rows into %s (from sink %s)", len(rows_to_insert), clean_fq, table_id)
        return 0
    except Exception:
        LOGGER.exception("Sink pipeline failed")
        return 1


def run(
    project: str,
    dataset: str,
    raw_table: str,
    clean_table: str,
    limit: int,
) -> int:
    client = bigquery.Client(project=project)
    raw_fq = f"`{project}.{dataset}.{raw_table}`"
    clean_fq = f"{project}.{dataset}.{clean_table}"

    if limit < 1 or limit > 10_000_000:
        raise ValueError("limit must be between 1 and 10000000")

    query = f"""
        SELECT insert_time, namespace, report_name, log_data
        FROM {raw_fq}
        WHERE log_data IS NOT NULL
        LIMIT {limit}
    """

    rows_to_insert: list[dict[str, Any]] = []

    try:
        job = client.query(query)
        for row in job.result():
            ins = row["insert_time"] or datetime.now(timezone.utc)
            ns = row["namespace"]
            report_name = row["report_name"]
            raw = row["log_data"]
            if raw is None:
                continue
            try:
                data = decode_blob(str(raw))
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                LOGGER.warning("Skip row (report=%s): %s", report_name, exc)
                continue

            image = (
                data.get("ArtifactName")
                or data.get("artifactName")
                or data.get("image")
                or ""
            )
            ns_val = data.get("Namespace") or data.get("namespace") or ns or ""

            for vuln in iter_vulnerabilities(data):
                rows_to_insert.append(
                    {
                        "insert_time": _ts_for_bq(ins),
                        "namespace": str(ns_val) if ns_val is not None else None,
                        "report_name": str(report_name) if report_name else None,
                        "image": str(image),
                        "vulnerability_id": vuln.get("VulnerabilityID", ""),
                        "severity": vuln.get("Severity", ""),
                        "pkg_name": vuln.get("PkgName", ""),
                        "installed_version": vuln.get("InstalledVersion", ""),
                        "fixed_version": vuln.get("FixedVersion", ""),
                        "title": vuln.get("Title", ""),
                    }
                )

        if not rows_to_insert:
            LOGGER.info("No vulnerability rows to insert.")
            return 0

        errors = client.insert_rows_json(clean_fq, rows_to_insert)
        if errors:
            LOGGER.error("BigQuery insert errors: %s", errors)
            return 1

        LOGGER.info("Inserted %s rows into %s", len(rows_to_insert), clean_fq)
        return 0
    except Exception:
        LOGGER.exception("Pipeline failed")
        return 1


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Decode Trivy gzip+b64 logs in BQ → clean table.")
    p.add_argument("--project", required=True, help="GCP project ID")
    p.add_argument("--dataset", default="trivy_logs", help="BigQuery dataset ID")
    p.add_argument(
        "--from-sink",
        action="store_true",
        help="Read Cloud Logging sink auto-tables (skip raw_compressed_logs); E2E from router export",
    )
    p.add_argument("--raw-table", default="raw_compressed_logs", help="Source table (ignored with --from-sink)")
    p.add_argument("--clean-table", default="clean_vulnerabilities", help="Destination table")
    p.add_argument("--limit", type=int, default=1000, help="Max rows to scan from source")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    if args.from_sink:
        return run_from_sink(
            project=args.project,
            dataset=args.dataset,
            clean_table=args.clean_table,
            limit=args.limit,
        )
    return run(
        project=args.project,
        dataset=args.dataset,
        raw_table=args.raw_table,
        clean_table=args.clean_table,
        limit=args.limit,
    )


if __name__ == "__main__":
    sys.exit(main())
