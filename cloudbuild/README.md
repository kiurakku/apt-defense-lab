# Cloud Build — pipelines for the technical test task

## Privilege model (Terraform `terraform/cloudbuild.tf`)

The dedicated service account `cloudbuild-deployer` (name overridable via `cloudbuild_sa_name`) receives:

| Role | Purpose |
|------|---------|
| `roles/cloudbuild.builds.builder` | Run builds |
| `roles/artifactregistry.writer` | Push `lab-ci/ci-deploy` image |
| `roles/container.developer` | `kubectl` / `helm` against GKE (`get-credentials`, deploy) |
| `roles/logging.logWriter` | Build logs |
| `roles/bigquery.jobUser` | Query BigQuery in parser job |
| `roles/bigquery.dataEditor` on dataset `trivy_logs` | Insert into `clean_vulnerabilities` / read sink tables |

**Not granted:** Terraform state bucket, project Owner/Editor, broad Storage admin. Infra stays outside this SA — run `terraform apply` with your admin or CI that owns state.

Set the **trigger service account** to `terraform output -raw cloudbuild_sa_email` (or the full id from `cloudbuild_sa_resource_name` per [Cloud Build SA docs](https://cloud.google.com/build/docs/securing-builds/configure-access-to-resources)).

## Pipelines

### 1. `cloudbuild.yaml` — builder image

Builds `docker/ci-deploy/Dockerfile` (gcloud + kubectl + helm + `gke-gcloud-auth-plugin`) and pushes:

- `REGION-docker.pkg.dev/PROJECT/lab-ci/ci-deploy:SHORT_SHA`
- `:latest`

```bash
gcloud builds submit --config=cloudbuild/cloudbuild.yaml .
```

### 2. `deploy-gke-apps.yaml` — GKE workloads + NetworkPolicies

Deploys Trivy Operator, Falco, compression flag, and **all** namespace policies (`default`, `trivy-system`, `falco`) via `scripts/apply_network_policies.sh`.

**Does not** run Terraform or create log sinks (those live in `terraform/`).

Substitutions:

- `_TRIVY_GSA_EMAIL` — `terraform output -raw trivy_sa_email`
- `_REGION`, `_CLUSTER_NAME`, `_IMAGE_TAG` (default `latest` after first image build)

### 3. `run-trivy-parser.yaml` — BigQuery E2E parser

Runs `parse_trivy_bq.py --from-sink` to read **Logging sink export tables** and write `clean_vulnerabilities`.

Requires the same Cloud Build SA and BigQuery IAM from Terraform.

## Order of operations

1. `terraform apply` (GKE, BQ, sink, IAM, Artifact Registry).
2. `gcloud builds submit --config=cloudbuild/cloudbuild.yaml .`
3. Create trigger for `deploy-gke-apps.yaml` (or manual submit with substitutions).
4. After logs land in BigQuery, run `run-trivy-parser.yaml` or `parse_trivy_bq.py --from-sink` locally.
