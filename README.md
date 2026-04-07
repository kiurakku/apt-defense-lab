# gke-devsecops-survival-kit

GKE security lab I built for a DevSecOps test task. Covers container escape PoCs, Trivy → BigQuery log pipeline, and a deliberately broken GitHub Actions WIF setup to demonstrate token theft.

```
GitHub (fork PR)
    │  vulnerable WIF (lab pool: repo only)
    ▼
GCP CI service account (cicd-lab-sa)
    │
    ▼
GKE lab-cluster
    ├── vulnerable-pool   ← legacy image, for escape demos
    ├── hardened-pool     ← Shielded VM, latest image
    ├── trivy-operator    → VulnerabilityReports (gzip+base64)
    ├── Falco             → alerts: /tmp writes, reverse shell port
    └── NetworkPolicy     → deny all egress except 443/53

Log Router sink → BigQuery (managed export tables)
    └── parse_trivy_bq.py --from-sink → BigQuery (clean vulnerabilities)
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
# Required: project_id, region, github_org, github_repo, tf_state_bucket_name,
# github_hardened_plan_workflow / github_hardened_apply_workflow (must match workflow `name:` in YAML)
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

Log Router sink → BigQuery is created by **Terraform** (`terraform/logging.tf`). Do **not** also run `scripts/log_sink_setup.sh` (duplicate sink).

Inspect the **managed** sink tables and a sample row, then optionally bridge into `raw_compressed_logs`:

```bash
pip install -r scripts/requirements.txt
python scripts/bq_sink_inspect.py --project YOUR_PROJECT_ID --dataset trivy_logs
# optional: python scripts/bq_sink_inspect.py --project YOUR_PROJECT_ID --dataset trivy_logs --ingest-raw
```

Parse logs into `clean_vulnerabilities`:

- **From Cloud Logging sink tables** (recommended E2E, matches `terraform/logging.tf`):

```bash
cd scripts
pip install -r requirements.txt
python parse_trivy_bq.py --project YOUR_PROJECT --dataset trivy_logs --from-sink
```

- **From lab table** `raw_compressed_logs` (legacy path):

```bash
python parse_trivy_bq.py --project YOUR_PROJECT --dataset trivy_logs
```

## Cloud Build

Configs under `cloudbuild/` (see `cloudbuild/README.md` for IAM and order of operations):

| File | Role |
|------|------|
| `cloudbuild.yaml` | Build/push `lab-ci/ci-deploy` image (`:SHORT_SHA` + `:latest`) |
| `deploy-gke-apps.yaml` | Helm: Trivy + Falco + `configure_trivy_log_compression.sh` + **`apply_network_policies.sh`** (all namespaces) |
| `run-trivy-parser.yaml` | `parse_trivy_bq.py --from-sink` → BigQuery |

Infra (**Terraform**) is **not** run from Cloud Build in this model; the deploy SA only needs GKE + Artifact Registry + BigQuery (see `terraform/cloudbuild.tf`).

Recommended: trigger on `main` for `deploy-gke-apps.yaml` using `terraform output -raw cloudbuild_sa_email` as the build service account; set `_TRIVY_GSA_EMAIL` to `terraform output -raw trivy_sa_email`.

GitHub App ↔ Cloud Build connection is left to you (tenant-specific); not hardcoded in Terraform.

## Exploits (lab only)

Each has its own README under `exploits/`. Run only against the `vulnerable-pool`.

- `container_escape/` — CVE-2022-0492 cgroup escape + privileged mount
- `master_plane_crash/` — API server resource exhaustion
- `github_action_steal/` — WIF token exfiltration from forked PR

## GitHub Actions

Покроковий чекліст (push, secrets, PR, apply, drift GKE): **`docs/github_actions_runbook.md`**.

Repository secrets:

| Secret | Purpose |
|--------|---------|
| `GCP_PROJECT_ID` | GCP project id (same as `project_id` in `terraform.tfvars`; required for `terraform plan` in Actions) |
| `WIF_PROVIDER_LAB` | `terraform output -raw wif_lab_provider_name` |
| `WIF_PROVIDER_PROD` | `terraform output -raw wif_prod_provider_name` |
| `CICD_LAB_SA_EMAIL` | `cicd_lab_sa_email` |
| `CICD_PLAN_SA_EMAIL` | `cicd_plan_sa_email` |
| `CICD_APPLY_SA_EMAIL` | `cicd_apply_sa_email` |
| `TF_STATE_BUCKET` | GCS bucket for remote state and for `tf_state_bucket_name` in Terraform (no `gs://` prefix) |
| `DEMO_IMPACT_BUCKET` | `terraform output -raw demo_impact_bucket` (for `hardened-tf-apply` only) |

Workflows set `TF_VAR_github_org` / `TF_VAR_github_repo` from the GitHub repository automatically (must match `github_org` / `github_repo` used when you applied Terraform/WIF).

- `vulnerable-tf-plan.yml` — `pull_request` (forks); lab pool WIF → `cicd-lab-sa`
- `hardened-tf-plan.yml` — `push` to `main`; prod pool WIF → `cicd-plan-sa` (strict provider in Terraform: repo + `refs/heads/main` + workflow allowlist)
- `hardened-tf-apply.yml` — `workflow_dispatch`; prod pool → `cicd-apply-sa` writes **only** `gs://DEMO_IMPACT_BUCKET/demo-write-proof.txt` (no full Terraform apply)

Інтеграційний чекліст: `scripts/verify_lab.ps1`

## References

- https://cloud.google.com/kubernetes-engine/security-bulletins
- CVE-2022-0492
- https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity
- https://aquasecurity.github.io/trivy-operator/v0.25.0/getting-started/installation/configuration/

## Report

- `docs/submission_report.md` — Google-Docs-ready report text
- `docs/evidence_checklist.md` — screenshot checklist for final submission
- `docs/evidence_gcp_runs.md` — how to collect **real** Cloud Build + BigQuery parser proof in GCP
