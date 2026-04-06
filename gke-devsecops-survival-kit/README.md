# gke-devsecops-survival-kit

GKE security lab I built for a DevSecOps test task. Covers container escape PoCs, Trivy → BigQuery log pipeline, and a deliberately broken GitHub Actions WIF setup to demonstrate token theft.

```
GitHub (fork PR)
    │  vulnerable WIF subject (no ref restriction)
    ▼
GCP CI service account
    │
    ▼
GKE lab-cluster
    ├── vulnerable-pool   ← legacy image, for escape demos
    ├── hardened-pool     ← Shielded VM, latest image
    ├── trivy-operator    → VulnerabilityReports (gzip+base64)
    ├── Falco             → alerts: /tmp writes, reverse shell port
    └── NetworkPolicy     → deny all egress except 443/53

Log Router sink → BigQuery (raw compressed)
    └── parse_trivy_bq.py → BigQuery (clean vulnerabilities)
```

## Requirements

- gcloud, terraform ≥ 1.5, helm, kubectl
- Python 3.11+
- GCP project with billing enabled

## Setup

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# fill in project_id, region
terraform init && terraform apply

gcloud container clusters get-credentials lab-cluster \
  --region REGION --project PROJECT_ID
```

Deploy Trivy and Falco via Helm — fill in the `# TODO` values in `k8s/*/values.yaml` first, then check chart versions with `helm show chart`.

Set up the log sink:
```bash
# edit PROJECT_ID and DATASET in the script first
bash scripts/log_sink_setup.sh
```

Parse compressed logs from BQ:
```bash
cd scripts
pip install -r requirements.txt
python parse_trivy_bq.py --project YOUR_PROJECT --dataset trivy_logs
```

## Exploits (lab only)

Each has its own README under `exploits/`. Run only against the `vulnerable-pool`.

- `container_escape/` — CVE-2022-0492 cgroup escape + privileged mount
- `master_plane_crash/` — API server resource exhaustion
- `github_action_steal/` — WIF token exfiltration from forked PR

## GitHub Actions

- `vulnerable-tf-plan.yml` — triggers on PRs including forks, no `attribute_condition` on WIF subject → token leaks on `terraform plan`
- `hardened-tf-plan.yml` — restricted to `refs/heads/main`, `attribute_condition` set

## References

- https://cloud.google.com/kubernetes-engine/security-bulletins
- CVE-2022-0492
- https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity