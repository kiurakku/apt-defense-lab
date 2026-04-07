# Screenshot checklist

Use this list when converting `docs/submission_report.md` into Google Docs.

**For live GCP runs (Cloud Build + parser):** follow **`docs/evidence_gcp_runs.md`** — exact commands, console URLs, and artifact IDs (A–I) to attach to the submission.

## Mandatory evidence

- GKE cluster overview with both node pools visible
- BigQuery dataset `trivy_logs` — **sink auto-table** sample row (or `bq_sink_inspect.py` output)
- BigQuery `raw_compressed_logs` / `clean_vulnerabilities` after parser (if ETL path used)
- Cloud Build: `cloudbuild.yaml` (image) + `deploy-gke-apps.yaml` (Helm + NetworkPolicies) or documented `gcloud builds submit`
- Trivy Operator pods healthy in `trivy-system`
- Falco pods healthy and at least one triggered alert
- NetworkPolicy: egress to 443 OK; blocked path to disallowed port (e.g. 4444) where policy applies
- Container escape PoC result
- API server stress result
- GitHub Actions: vulnerable PR **plan** (lab WIF) vs hardened **push main** (prod WIF)
- Proof of stolen federated token (lab) vs **demo bucket write only** for `hardened-tf-apply` (prod apply SA)

## Recommended terminal captures

- `kubectl get pods -n trivy-system`
- `kubectl get pods -n falco`
- `kubectl get networkpolicy -A`
- `kubectl get cm trivy-operator-config -n trivy-system -o yaml | grep compressLogs`
- `python scripts/bq_sink_inspect.py --project PROJECT_ID --dataset trivy_logs`
- `python scripts/parse_trivy_bq.py --project PROJECT_ID --dataset trivy_logs --from-sink --limit 1000`
- `powershell -File scripts/verify_lab.ps1 -ProjectId PROJECT_ID`
- `gcloud auth list`
- `gsutil ls gs://YOUR_TF_STATE_BUCKET/terraform/state`
- `gsutil cat gs://DEMO_IMPACT_BUCKET/demo-write-proof.txt` (after hardened apply)
