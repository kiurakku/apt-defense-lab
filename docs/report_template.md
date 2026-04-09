# DevSecOps — technical test task report

**Repository:** apt-defense-lab (Terraform in `terraform/`, workflows in `.github/workflows/` at repo root.)

**Author:** [Your Name]  
**Date:** [Date]  
**GCP Project:** [project-id]

---

## 1. Executive Summary

[Three sentences: a Russian APT-style scenario targeting crypto-mining and lateral movement in GCP; what was demonstrated in this test task (escape, control-plane stress, Trivy→BigQuery, vulnerable GitHub Actions WIF); what defensive controls were applied and what risk remains.]

---

## 2. Infrastructure Overview

**GCP Resources deployed:**

- GKE cluster `lab-cluster` — Standard mode, two node pools (`vulnerable-pool` pinned to 1.27.x for demos, `hardened-pool` with Shielded VM)
- BigQuery dataset `trivy_logs` (location **US**) — tables `raw_compressed_logs`, `clean_vulnerabilities`, plus **managed** tables from Cloud Logging sink
- Workload Identity: **two** pools (`github-lab-pool`, `github-prod-pool`) with OIDC providers for GitHub Actions (vulnerable vs hardened conditions in Terraform)
- Log Router sink → BigQuery via **`terraform/logging.tf`** (do not duplicate with manual `log_sink_setup.sh` if Terraform already applied)
- Service accounts: `trivy-sa` (Workload Identity for Trivy operator); `cicd-lab-sa` / `cicd-plan-sa` / `cicd-apply-sa` (GitHub WIF); `cloudbuild-deployer` (Cloud Build)

**ASCII diagram (optional):**

```
GitHub PR ──► Actions ──► WIF (`github-lab-pool`) ──► cicd-lab-sa ──► GCS state + demo bucket (per IAM)
GKE ──► trivy-operator ──► Cloud Logging ──► Sink ──► BQ (managed tables) ──► parse_trivy_bq.py --from-sink ──► BQ clean
```

[Screenshot placeholder: GCP Console → Kubernetes Engine → Clusters]

---

## 3. Task 1: Container Escape & Control Plane Stress

### 3a. Container Escape (CVE-2022-0492 class)

**What:** Demonstrate cgroup v1 `release_agent` style escape from a privileged / CAP_SYS_ADMIN context; alternative path commented for host mount / `chroot`.

**Node pool used:** `vulnerable-pool` (GKE **1.27.16-gke.1800**)

**Command run:**

```bash
bash exploits/container_escape/escape.sh
```

**Result:** [Screenshot of `/tmp/escape_proof.txt` or log output explaining cgroup v2 / hardening blocked the PoC]

**CVE / reference:** [GKE security bulletins](https://cloud.google.com/kubernetes-engine/security-bulletins), [CVE-2022-0492](https://nvd.nist.gov/vuln/detail/CVE-2022-0492)

**Mitigation:** No privileged workloads in production; Pod Security Standards; Shielded VM + hardened pool; seccomp/AppArmor; keep node versions current.

### 3b. Control Plane Stress

**What:** Flood the API server with many `ConfigMap` creates to show latency impact and operator risk.

**Command run:**

```bash
COUNT=500 bash exploits/master_plane_crash/dos_apiserver.sh default
```

**Result:** [Screenshot: `time kubectl get nodes` before vs after, or API latency metrics]

**Mitigation:** Admission webhooks, API priority/fairness, `ResourceQuota` / `LimitRange`, RBAC least privilege, GKE version with appropriate protection.

---

## 4. Task 2: Trivy → BigQuery Pipeline

### 4a. Trivy Operator Deployment

Helm release `trivy-operator` chart **0.32.1**, namespace `trivy-system`, Workload Identity annotation binding `trivy-sa`.

[Screenshot: `kubectl get pods -n trivy-system`]

### 4b. Compression Format

Trivy operator serializes `VulnerabilityReport` to JSON, compresses with **gzip**, then encodes **base64** before storing in CR annotations / related objects; logs may ship the same payload to Cloud Logging.

Source reference: `pkg/compress` in [aquasecurity/trivy-operator](https://github.com/aquasecurity/trivy-operator).

### 4c. Raw Logs in BigQuery

Schema: `insert_time`, `namespace`, `report_name`, `log_data` (base64+gzip blob).

[Screenshot: BigQuery → `raw_compressed_logs` preview]

### 4d. Clean Vulnerabilities Table

Parser expands `Results[].Vulnerabilities[]` into normalized rows.

**Parser command:**

```bash
python scripts/parse_trivy_bq.py --project PROJECT_ID --dataset trivy_logs --from-sink --limit 1000
```

[Screenshot: `clean_vulnerabilities` preview]

---

## 5. Task 3: GitHub Actions WIF Exploit

### 5a. Vulnerable Workflow

**File:** `.github/workflows/vulnerable-tf-plan.yml`

**Issue:** Terraform’s WIF provider uses `attribute_condition` that **does not** require `refs/heads/main`. A fork PR can still satisfy `assertion.repository` for the upstream repo in many OIDC flows used in class demos.

**Attack path (conceptual):**

1. Fork the repository.
2. Modify workflow or add steps (see `exploits/github_action_steal/malicious_pr_payload.sh`).
3. Open a pull request — workflow runs with `id-token: write`.
4. `google-github-actions/auth` exchanges OIDC for a Google access token for **`cicd-lab-sa`** (WIF pool `github-lab-pool`).
5. Token can call APIs allowed to that SA (e.g. state bucket `objectUser`, project `viewer`, demo bucket — see Terraform `workload_identity.tf`).

[Screenshot: GitHub Actions log showing successful `terraform init` / `gcloud auth` on a fork PR — redact secrets]

### 5b. Token Exfiltration Proof

[Screenshot: `gcloud auth list` — active SA]

[Screenshot: first 20 characters of access token only]

[Screenshot: `gcloud storage buckets list`]

### 5c. Fix Applied

**Workflow:** `.github/workflows/hardened-tf-plan.yml` — trigger on `push` to `main` only; `auth` action uses `attribute_condition` for `refs/heads/main`.

**Terraform:** Recreate `google_iam_workload_identity_pool_provider.github_provider` with:

```text
attribute_condition = "assertion.repository == 'ORG/REPO' && assertion.ref == 'refs/heads/main'"
```

Fork PRs no longer receive usable tokens for production applies when correctly enforced end-to-end.

---

## 6. Defensive Controls

| Control | Tool | Status |
|---------|------|--------|
| /tmp write detection | Falco: APT Malware TMP File Drop | ✅ Active |
| Reverse shell / odd ports | Falco: Reverse Shell C2 Connection | ✅ Active |
| Egress to C&C port | NetworkPolicy default deny + allowlist | ✅ Active |
| WIF subject restriction | `attribute_condition` + branch triggers | ✅ Applied (hardened path) |
| Node hardening | Shielded VM on `hardened-pool` | ✅ Active |
| No JSON SA keys for GKE workloads | Workload Identity (`trivy-sa`) | ✅ Applied |

[Screenshot: Falco pod logs showing a triggered rule]

---

## 7. Recommendations

1. **Zero Trust** — Bind least-privilege GSAs at pod level; avoid project-wide Editor for CI.
2. **Immutable infrastructure** — Pin GKE versions; Binary Authorization where appropriate.
3. **Pin GitHub Actions by SHA** — Reduce supply-chain risk from mutable tags.
4. **Restrict WIF subjects** — Always include `assertion.ref == 'refs/heads/main'` (or tighter) for production Terraform.
5. **Runtime detection** — Falco on all clusters; forward alerts to SIEM.
6. **Egress control** — Default-deny `NetworkPolicy`, allowlist only required CIDRs/ports.

---

## 8. Appendix

**Terraform outputs used in CI:**

- `wif_provider_name` → GitHub secret `WIF_PROVIDER`
- `cicd_sa_email` → `CICD_SA_EMAIL`

**GCS backend:** Create a bucket for remote state; set `TF_STATE_BUCKET` and run `terraform init -backend-config=...` as in workflows.

**Share:** Upload this report to Google Docs with view access and submit the link as required by the course.

---

_End of template_
