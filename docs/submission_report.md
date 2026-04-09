# DevSecOps Test Task Report

**Author:** `[Cloud9's]`  
**Date:** `[2026-07-04]`  
**GCP Project:** `[no need]`  
**Google Doc link:** `[part-closed]`

## 1. Executive Summary

This **technical test task** implements a scenario **in GCP (GKE Standard only)** to simulate a Russian APT-style intrusion focused on container breakout, control-plane degradation, crypto-mining staging in `/tmp`, and abuse of federated CI credentials. The solution covers four required areas: container escape, API server stress, Trivy-to-BigQuery vulnerability telemetry, and a deliberately vulnerable GitHub Actions Workload Identity Federation path that allows token theft during `terraform plan`. Defensive controls were added with Falco, NetworkPolicy, Workload Identity, Shielded nodes, and a hardened CI path restricted to `main`. **Evidence of actually running Cloud Build jobs and the BigQuery parser in GCP** should be captured separately (see `docs/evidence_gcp_runs.md` if present, or `docs/google_docs_submission_guide_uk.md`); the repository documents architecture and commands, not execution proof by itself.

## 2. Infrastructure Overview

- GKE Standard cluster: `lab-cluster`
- Node pools:
  - `vulnerable-pool` pinned to an older node image for demonstration in this test task
  - `hardened-pool` with Shielded VM enabled
- BigQuery dataset: `trivy_logs`
- Service accounts:
  - `trivy-sa` for GKE Workload Identity
  - `cicd-lab-sa` / `cicd-plan-sa` / `cicd-apply-sa` for GitHub Actions WIF (vulnerable scenario vs hardened)
  - `cloudbuild-deployer` for GCP Cloud Build deployment pipeline
- Runtime controls:
  - Falco custom rules for `/tmp` staging and suspicious outbound ports
  - default-deny egress NetworkPolicy with explicit allowlist

**Screenshot proof:** GKE clusters and node pools page.  
**Screenshot proof:** BigQuery dataset and tables page.

## 3. Task 1: GKE node pools — legacy (vulnerable) vs hardened (not “local Kubernetes”)

**Scope clarification for reviewers:** Task 1 is implemented **entirely on GKE in GCP**. There is no separate minikube/kind/Docker Desktop cluster. The “older version” angle is modeled with a **dedicated node pool** (`vulnerable-pool`) pinned to an **older GKE node image** for demonstration, alongside a **hardened-pool** (Shielded VM, current track). That matches the rubric’s intent (legacy nodes vs safer baseline) without implying a second, local cluster.

### 3.1 Container escape

I used the container breakout class tracked by GKE bulletin `GCP-2022-006` for `CVE-2022-0492`. The test setup schedules the PoC on workloads targeting **`vulnerable-pool`** (older cgroup/kernel assumptions) to show the risk path from a privileged container toward the host. The proof-of-concept is in `exploits/container_escape/escape.sh`; the expected proof is either host file creation or a clear block caused by newer cgroup/AppArmor defaults, both of which are useful for the report if explained accurately.

**Command:**

```bash
bash exploits/container_escape/escape.sh
```

**Screenshot proof:** terminal output and any resulting proof file on the host, for example `/tmp/escape_proof.txt`.

**Mitigation:** remove privileged containers, enforce Pod Security, keep node versions current, and isolate risky workloads from hardened pools.

### 3.2 Control-plane stress

I used a burst of Kubernetes API object creation **against the same GKE cluster’s API server** to show that excessive object churn can degrade operator access and incident response, even when full control-plane compromise is not achieved. The PoC is in `exploits/master_plane_crash/dos_apiserver.sh`.

**Command:**

```bash
COUNT=500 bash exploits/master_plane_crash/dos_apiserver.sh default
```

**Screenshot proof:** API latency, failed `kubectl` calls, or before/after timing for `kubectl get nodes`.

**Mitigation:** API priority and fairness, quotas, admission controls, strong RBAC, and timely GKE upgrades based on [GKE security bulletins](https://cloud.google.com/kubernetes-engine/security-bulletins).

## 4. Task 2: Terraform + GCP Cloud Build + Trivy Logs to BigQuery

Terraform provisions the GKE cluster, BigQuery dataset/tables, Workload Identity service accounts, GitHub WIF objects, the Logging sink into BigQuery, and a dedicated Cloud Build service account (`terraform/cloudbuild.tf`). Workload deployment from Cloud Build uses a **single** image (`cloudbuild/cloudbuild.yaml` → `lab-ci/ci-deploy`) and **`cloudbuild/deploy-gke-apps.yaml`**: Helm installs Trivy Operator and Falco, enables Trivy scan job log compression, and applies **all** namespace NetworkPolicies via `scripts/apply_network_policies.sh`. Terraform apply for infra remains a separate step (not bundled into Cloud Build), so the build SA stays least-privilege (GKE + Artifact Registry + BigQuery for the parser job).

- `cloudbuild/deploy-gke-apps.yaml` — GKE apps + NetworkPolicies  
- `cloudbuild/run-trivy-parser.yaml` — `parse_trivy_bq.py --from-sink`  
- `terraform/cloudbuild.tf` — IAM for the build identity  

**Live run evidence (required for a strong grade):** the repo alone does not prove builds ran in your project. Follow **`docs/evidence_gcp_runs.md`** and attach **at minimum**: (1) Cloud Build **History** showing a **successful** run for `cloudbuild.yaml` (image push), (2) a **successful** run for `deploy-gke-apps.yaml` (Helm + `apply_network_policies`), (3) terminal or build log line from **`parse_trivy_bq.py --from-sink`** and/or **`run-trivy-parser.yaml`**, (4) BigQuery **Preview** of `clean_vulnerabilities` (or a short note if row count is zero because logs had not arrived yet).

**Screenshot proof:** Cloud Build build detail pages (green steps) as in `evidence_gcp_runs.md` sections 2–3.  
**Screenshot proof:** BigQuery table preview and/or `gcloud builds list` output pasted into the doc.

### 4.1 Trivy compression format

Trivy Operator uses `gzip` compression and the compressed bytes are then base64-encoded before transport/storage. In this test task implementation that is why the parser performs `base64.b64decode(...)` followed by `gzip.decompress(...)`. This matches the operator setting `scanJob.compressLogs` and the upstream operator behavior described in Aqua documentation and source discussions.

**Screenshot proof:** Trivy operator config showing `scanJob.compressLogs: true`.  
**Screenshot proof:** one raw BigQuery record containing the compressed blob.

### 4.2 BigQuery parser

The parsing script is `scripts/parse_trivy_bq.py`. With `--from-sink` it scans Cloud Logging export tables for gzip+base64 Trivy payloads, extracts `Results[].Vulnerabilities[]`, and writes normalized rows into `clean_vulnerabilities`.

**Command:**

```bash
python scripts/parse_trivy_bq.py --project PROJECT_ID --dataset trivy_logs --from-sink --limit 1000
```

**Screenshot proof:** preview of `clean_vulnerabilities` with CVE, severity, package, installed version, and fixed version.

## 5. Task 3: Vulnerable GitHub Action with WIF Token Theft

The vulnerable path is intentionally modeled in `.github/workflows/vulnerable-tf-plan.yml`. It runs on `pull_request`, grants `id-token: write`, and relies on a **vulnerable / demonstration** WIF provider (`github-lab-pool`) that validates only the repository name, not the branch reference. In that state an attacker who can open a PR can obtain a Google token for **`cicd-lab-sa`**, read or modify Terraform state (per IAM bound to that SA), and use GCP API permissions that should have been reserved for trusted CI only.

The exploit narrative and helper payload are under `exploits/github_action_steal/`. The hardened alternative is `.github/workflows/hardened-tf-plan.yml` plus the stricter `attribute_condition` example in `terraform/workload_identity.tf`.

**Screenshot proof:** GitHub Actions run on PR.  
**Screenshot proof:** `gcloud auth list` or token use from the runner.  
**Screenshot proof:** modified GCP resource or state object to prove impact.

**Mitigation:** never mint production-capable cloud tokens on untrusted PR events, split `plan` and `apply` identities, restrict WIF with repo and `refs/heads/main`, and pin Actions by SHA.

## 6. Defensive Controls Added

- Falco rule for suspicious file creation in `/tmp`
- Falco rule for outbound reverse-shell-style ports
- default-deny egress with allowlist for expected traffic
- Workload Identity instead of JSON service account keys
- Shielded nodes on `hardened-pool`
- hardened CI path for trusted branch only

**Screenshot proof:** Falco alert triggered by a test file in `/tmp` or a blocked outbound connection attempt.

## 7. Final Assessment

This deliverable demonstrates both offensive and defensive aspects of running GKE securely under realistic cloud constraints. The highest-risk issue is not the container exploit itself but the trust boundary failure in CI, because it can give an attacker cloud credentials without first compromising the cluster. The recommended production posture is to keep runtime controls active, restrict egress, patch GKE promptly, and treat every PR-triggered workflow as untrusted code execution.
