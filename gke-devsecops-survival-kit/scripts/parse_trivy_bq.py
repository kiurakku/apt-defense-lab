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
  1. Reads raw compressed rows from BQ table `raw_compressed_logs`
  2. base64-decodes → gunzips → json.loads each row
  3. Extracts vulnerabilities from Results[].Vulnerabilities[]
  4. Inserts clean rows into `clean_vulnerabilities` table
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import logging
import sys
from datetime import date, datetime, time, timezone
from typing import Any, Iterator

from google.cloud import bigquery

LOGGER = logging.getLogger("parse_trivy_bq")


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
    p.add_argument("--raw-table", default="raw_compressed_logs", help="Source table")
    p.add_argument("--clean-table", default="clean_vulnerabilities", help="Destination table")
    p.add_argument("--limit", type=int, default=1000, help="Max raw rows to process")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
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
