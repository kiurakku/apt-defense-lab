# -----------------------------------------------------------------------------
# A) GKE → GCP: Trivy operator KSA ↔ GSA (Workload Identity on GKE)
# -----------------------------------------------------------------------------

resource "google_service_account" "trivy" {
  account_id   = var.trivy_sa_name
  display_name = "Trivy operator (BigQuery export)"
  project      = var.project_id

  depends_on = [google_project_service.lab]
}

resource "google_project_iam_member" "trivy_bigquery_data_editor" {
  project = var.project_id
  role    = "roles/bigquery.dataEditor"
  member  = "serviceAccount:${google_service_account.trivy.email}"
}

resource "google_project_iam_member" "trivy_bigquery_job_user" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.trivy.email}"
}

resource "google_service_account_iam_member" "trivy_workload_identity_user" {
  service_account_id = google_service_account.trivy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[trivy-system/trivy-operator]"
}

# -----------------------------------------------------------------------------
# B) GitHub Actions → GCP via Workload Identity Federation (lab: vulnerable)
# -----------------------------------------------------------------------------

resource "google_service_account" "cicd" {
  account_id   = var.cicd_sa_name
  display_name = "GitHub Actions Terraform (CI/CD)"
  project      = var.project_id

  depends_on = [google_project_service.lab]
}

resource "google_project_iam_member" "cicd_storage_admin" {
  project = var.project_id
  role    = "roles/storage.admin"
  member  = "serviceAccount:${google_service_account.cicd.email}"
}

resource "google_project_iam_member" "cicd_compute_viewer" {
  project = var.project_id
  role    = "roles/compute.viewer"
  member  = "serviceAccount:${google_service_account.cicd.email}"
}

resource "google_iam_workload_identity_pool" "github_pool" {
  project                   = var.project_id
  workload_identity_pool_id = "github-pool"
  display_name              = "GitHub Actions pool"
}

resource "google_iam_workload_identity_pool_provider" "github_provider" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider"
  display_name                       = "GitHub OIDC"
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.ref"        = "assertion.ref"
    "attribute.repository" = "assertion.repository"
  }
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  # VULNERABLE: repository only — any ref (including fork PR merge refs) may authenticate.
  # A forked PR can still obtain a token during terraform plan.
  attribute_condition = "assertion.repository == '${var.github_org}/${var.github_repo}'"

  # HARDENED (replace provider resource when switching to secure CI):
  # attribute_condition = "assertion.repository == '${var.github_org}/${var.github_repo}' && assertion.ref == 'refs/heads/main'"
}

resource "google_service_account_iam_member" "cicd_github_wif" {
  service_account_id = google_service_account.cicd.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}/attribute.repository/${var.github_org}/${var.github_repo}"
}
