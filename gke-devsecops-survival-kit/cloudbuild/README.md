# Cloud Build pipeline

This directory contains the missing GCP-side CI/CD pieces for the lab.

## Files

- `deploy-lab.yaml` — end-to-end deploy pipeline: Terraform apply, GKE credentials, Trivy, Falco, NetworkPolicy, and Logging sink.
- `run-trivy-parser.yaml` — manual or scheduled parser run that expands compressed Trivy payloads from BigQuery into `clean_vulnerabilities`.

## Recommended trigger setup

1. Create a Cloud Build trigger on `push` to `main`.
2. Point the trigger to `cloudbuild/deploy-lab.yaml`.
3. Set the trigger service account to `terraform output cloudbuild_sa_email`.
4. Configure substitutions:
   - `_GITHUB_ORG`
   - `_GITHUB_REPO`
   - `_TF_STATE_BUCKET`
   - `_TRIVY_GSA_EMAIL`
   - optionally `_REGION`, `_CLUSTER_NAME`, `_DATASET`

## Why the GitHub trigger itself is not fully codified here

The Cloud Build GitHub connection requires tenant-specific GitHub App installation details and secrets. Those should not be committed into a public lab repository. Terraform in this repo provisions the Cloud Build service account and IAM, and the checked-in build configs are ready to be attached to a trigger in the GCP project.
