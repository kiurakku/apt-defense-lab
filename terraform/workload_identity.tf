# -----------------------------------------------------------------------------
# A) GKE → GCP: Trivy operator KSA ↔ GSA
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
# B) GitHub Actions → GCP via WIF (two pools: lab = vulnerable, prod = hardened)
# -----------------------------------------------------------------------------

# --- Lab / vulnerable pool (educational): token if repository matches only ---
resource "google_iam_workload_identity_pool" "github_lab_pool" {
  project                   = var.project_id
  workload_identity_pool_id = "github-lab-pool"
  display_name              = "GitHub Actions lab (vulnerable)"
  description               = "Fork PR / broad subject demos"
}

resource "google_iam_workload_identity_pool_provider" "github_lab_provider" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_lab_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider-lab"
  display_name                       = "GitHub OIDC (lab)"
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.ref"        = "assertion.ref"
    "attribute.repository" = "assertion.repository"
    "attribute.workflow" = "assertion.workflow"
  }
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  # VULNERABLE: no ref/workflow restriction.
  attribute_condition = "assertion.repository == '${var.github_org}/${var.github_repo}'"
}

# --- Production (hardened) pool: strict repository + branch + workflow + trusted event ---
resource "google_iam_workload_identity_pool" "github_prod_pool" {
  project                   = var.project_id
  workload_identity_pool_id = "github-prod-pool"
  display_name              = "GitHub Actions prod"
  description               = "Strict OIDC binding for plan/apply SAs"
}

resource "google_iam_workload_identity_pool_provider" "github_prod_provider" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_prod_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider-prod"
  display_name                       = "GitHub OIDC (prod)"
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.ref"        = "assertion.ref"
    "attribute.repository" = "assertion.repository"
    "attribute.workflow" = "assertion.workflow"
  }
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  # HARDENED: trusted repo + main + allowlisted workflow names (plan vs apply jobs).
  attribute_condition = <<-EOT
    assertion.repository == '${var.github_org}/${var.github_repo}' &&
    assertion.ref == 'refs/heads/main' &&
    (assertion.workflow == '${var.github_hardened_plan_workflow}' || assertion.workflow == '${var.github_hardened_apply_workflow}')
  EOT
}

# --- Service accounts ---
resource "google_service_account" "cicd_lab" {
  account_id   = var.cicd_lab_sa_name
  display_name = "GitHub Actions lab (vulnerable workflow)"
  project      = var.project_id

  depends_on = [google_project_service.lab]
}

resource "google_service_account" "cicd_plan" {
  account_id   = var.cicd_plan_sa_name
  display_name = "GitHub Actions Terraform plan (read/write state)"
  project      = var.project_id

  depends_on = [google_project_service.lab]
}

resource "google_service_account" "cicd_apply" {
  account_id   = var.cicd_apply_sa_name
  display_name = "GitHub Actions Terraform apply (demo impact only)"
  project      = var.project_id

  depends_on = [google_project_service.lab]
}

# Terraform plan needs read access to project resources (provider refresh).
resource "google_project_iam_member" "cicd_plan_viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.cicd_plan.email}"
}

resource "google_project_iam_member" "cicd_lab_viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.cicd_lab.email}"
}

# Apply SA: demo bucket write only (see hardened-tf-apply.yml — no full terraform apply).

# Lab SA: state bucket + demo bucket only (no project storage.admin).
resource "google_storage_bucket_iam_member" "cicd_lab_tf_state" {
  bucket = var.tf_state_bucket_name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.cicd_lab.email}"
}

resource "google_storage_bucket_iam_member" "cicd_lab_demo_impact" {
  bucket = google_storage_bucket.demo_impact.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.cicd_lab.email}"
}

# Plan SA (prod WIF): only Terraform state objects in the bucket.
resource "google_storage_bucket_iam_member" "cicd_plan_tf_state" {
  bucket = var.tf_state_bucket_name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.cicd_plan.email}"
}

# Apply SA (prod WIF): write only to demo impact bucket (controlled blast radius).
resource "google_storage_bucket_iam_member" "cicd_apply_demo_impact" {
  bucket = google_storage_bucket.demo_impact.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.cicd_apply.email}"
}

# WIF impersonation bindings (principalSet on repository within each pool).
resource "google_service_account_iam_member" "cicd_lab_wif" {
  service_account_id = google_service_account.cicd_lab.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_lab_pool.name}/attribute.repository/${var.github_org}/${var.github_repo}"
}

resource "google_service_account_iam_member" "cicd_plan_wif" {
  service_account_id = google_service_account.cicd_plan.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_prod_pool.name}/attribute.repository/${var.github_org}/${var.github_repo}"
}

resource "google_service_account_iam_member" "cicd_apply_wif" {
  service_account_id = google_service_account.cicd_apply.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_prod_pool.name}/attribute.repository/${var.github_org}/${var.github_repo}"
}
