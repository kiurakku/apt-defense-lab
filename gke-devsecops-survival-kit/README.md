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

- gcloud (Google Cloud SDK), terraform ≥ 1.5, helm, kubectl
- Python 3.11+
- GCP project with billing enabled

### Google Cloud SDK (`gcloud`) on Windows

Якщо в PowerShell з’являється `gcloud: The term 'gcloud' is not recognized`:

1. Встановіть [Cloud SDK](https://cloud.google.com/sdk/docs/install-sdk#windows) (інсталятор додасть `gcloud` у PATH).
2. Або додайте вручну PATH до каталогу `bin`, наприклад:
   - `C:\Program Files\Google\Cloud SDK\google-cloud-sdk\bin`
   - або `%LOCALAPPDATA%\Google\Cloud SDK\google-cloud-sdk\bin`
3. Перезапустіть термінал і перевірте: `gcloud --version`
4. Далі: `gcloud auth application-default login` і `gcloud config set project YOUR_PROJECT_ID`

## Setup

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Set project_id, region, github_org, github_repo, and optional bq_dataset_id / SA names
```

Remote state (GCS): створіть bucket (через консоль GCP або `gcloud`), заповніть `bucket` у `backend.hcl` (скопійованому з `backend.hcl.example`, файл у `.gitignore`).

**PowerShell (Windows)** — ініціалізація backend з файлом (обов’язкові лапки навколо аргументу):

```powershell
terraform init "-backend-config=backend.hcl"
```

Без лапок PowerShell інколи дає помилку `Too many command line arguments`.

Bash / cmd:

```bash
terraform init -backend-config=backend.hcl
```

Або без віддаленого state (локальний `terraform.tfstate`, зручно до встановлення `gcloud`):

```bash
terraform init -backend=false
terraform apply
```

If `apply` fails with an API not enabled, enable `compute.googleapis.com` for GKE nodes (in addition to APIs in `terraform/apis.tf`).

```bash
gcloud container clusters get-credentials lab-cluster \
  --region REGION --project PROJECT_ID
```

Deploy Trivy and Falco via Helm — set `iam.gke.io/gcp-service-account` in `k8s/trivy-operator/values.yaml` to the email from `terraform output trivy_sa_email`, then install pinned chart versions from file headers.

Enable compressed Trivy scan logs after install:
```bash
bash scripts/configure_trivy_log_compression.sh
```

Set up the log sink:
```bash
PROJECT_ID=YOUR_PROJECT_ID DATASET=trivy_logs bash scripts/log_sink_setup.sh
```

Parse compressed logs from BQ:
```bash
cd scripts
pip install -r requirements.txt
python parse_trivy_bq.py --project YOUR_PROJECT --dataset trivy_logs
```

## Cloud Build

The GCP-side CI/CD pieces live under `cloudbuild/`:

- `cloudbuild/deploy-lab.yaml` — Terraform apply + GKE deployment pipeline
- `cloudbuild/run-trivy-parser.yaml` — parser pipeline for BigQuery compressed logs
- `terraform/cloudbuild.tf` — Cloud Build deployer service account and IAM

Recommended trigger model:

1. Use a Cloud Build trigger on `push` to `main`.
2. Point it to `cloudbuild/deploy-lab.yaml`.
3. Use `terraform output cloudbuild_sa_email` as the trigger service account.
4. Set substitutions `_GITHUB_ORG`, `_GITHUB_REPO`, `_TF_STATE_BUCKET`, `_TRIVY_GSA_EMAIL`.

I did not hardcode the GitHub-to-Cloud-Build connection in Terraform because that requires tenant-specific GitHub App installation details and secrets which should not live in a public lab repo.

## Exploits (lab only)

Each has its own README under `exploits/`. Run only against the `vulnerable-pool`.

- `container_escape/` — CVE-2022-0492 cgroup escape + privileged mount
- `master_plane_crash/` — API server resource exhaustion
- `github_action_steal/` — WIF token exfiltration from forked PR

## GitHub Actions

Configure repository secrets: `WIF_PROVIDER` (output `wif_provider_name`), `CICD_SA_EMAIL`, `TF_STATE_BUCKET`.

- `vulnerable-tf-plan.yml` — `pull_request` (forks included); WIF in Terraform has **no** `refs/heads/main` check → fork PR can obtain `cicd-sa` token during plan
- `hardened-tf-plan.yml` — `push` to `main` only; use with a **hardened** `google_iam_workload_identity_pool_provider` in Terraform (`attribute_condition` including `refs/heads/main`)

## References

- https://cloud.google.com/kubernetes-engine/security-bulletins
- CVE-2022-0492
- https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity
- https://aquasecurity.github.io/trivy-operator/v0.25.0/getting-started/installation/configuration/

## Report

- `docs/submission_report.md` — Google-Docs-ready report text
- `docs/evidence_checklist.md` — screenshot checklist for final submission
