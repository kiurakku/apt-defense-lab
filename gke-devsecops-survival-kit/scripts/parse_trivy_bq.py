#!/usr/bin/env python3
"""
Read compressed Trivy-related rows from BigQuery, decode, and write clean vulnerabilities.

Trivy operator serializes VulnerabilityReport to JSON, gzips it, base64-encodes it,
then stores the blob in the CR's annotation / ConfigMap (see operator source: pkg/compress).

This script expects `raw_compressed_logs.log_data` to hold base64(gzip(JSON)).
The JSON shape follows Trivy scan output: Results[].Vulnerabilities[] with fields such as
VulnerabilityID, Severity, PkgName, InstalledVersion.
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
    """Base64-decode, gunzip, parse JSON."""
    compressed = base64.b64decode(raw)
    text = gzip.decompress(compressed).decode("utf-8")
    return json.loads(text)


def iter_vulnerabilities(payload: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield flattened vulnerability dicts from Trivy JSON."""
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
    """Serialize timestamps for BigQuery JSON insert."""
    if ts is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(ts, datetime):
        return ts.isoformat()
    if isinstance(ts, date):
        return datetime.combine(ts, time.min, tzinfo=timezone.utc).isoformat()
    return str(ts)


def run(project: str, dataset: str, raw_table: str, clean_table: str) -> int:
    client = bigquery.Client(project=project)
    raw_fq = f"`{project}.{dataset}.{raw_table}`"
    clean_fq = f"{project}.{dataset}.{clean_table}"

    query = f"""
        SELECT timestamp, log_data
        FROM {raw_fq}
        WHERE log_data IS NOT NULL
    """

    rows_to_insert: list[dict[str, Any]] = []

    try:
        job = client.query(query)
        for row in job.result():
            ts = row["timestamp"]
            raw = row["log_data"]
            if raw is None:
                continue
            try:
                data = decode_blob(str(raw))
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                LOGGER.warning("Skip row at %s: decode failed: %s", ts, exc)
                continue

            image = (
                data.get("ArtifactName")
                or data.get("artifactName")
                or data.get("image")
                or ""
            )
            namespace = data.get("Namespace") or data.get("namespace") or ""

            for vuln in iter_vulnerabilities(data):
                rows_to_insert.append(
                    {
                        "timestamp": _ts_for_bq(ts),
                        "vulnerability_id": vuln.get("VulnerabilityID", ""),
                        "severity": vuln.get("Severity", ""),
                        "pkg_name": vuln.get("PkgName", ""),
                        "pkg_version": vuln.get("InstalledVersion", ""),
                        "image": str(image),
                        "namespace": str(namespace),
                    }
                )

        if not rows_to_insert:
            LOGGER.info("No vulnerability rows produced; nothing to insert.")
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
    )


if __name__ == "__main__":
    sys.exit(main())
