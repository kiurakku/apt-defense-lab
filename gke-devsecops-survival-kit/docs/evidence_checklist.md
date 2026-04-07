# Screenshot checklist

Use this list when converting `docs/submission_report.md` into Google Docs.

## Mandatory evidence

- GKE cluster overview with both node pools visible
- BigQuery dataset `trivy_logs`
- BigQuery preview of raw compressed records
- BigQuery preview of `clean_vulnerabilities`
- Cloud Build successful run for `cloudbuild/deploy-lab.yaml`
- Trivy Operator pods healthy in `trivy-system`
- Falco pods healthy and at least one triggered alert
- Container escape PoC result
- API server stress result
- GitHub Actions vulnerable PR run
- Proof of stolen federated token being usable
- Proof of modified GCP resource or Terraform state

## Recommended terminal captures

- `kubectl get pods -n trivy-system`
- `kubectl get pods -n falco`
- `kubectl get cm trivy-operator-config -n trivy-system -o yaml | grep compressLogs`
- `python scripts/parse_trivy_bq.py --project PROJECT_ID --dataset trivy_logs --limit 1000`
- `gcloud auth list`
- `gsutil ls gs://YOUR_TF_STATE_BUCKET`
