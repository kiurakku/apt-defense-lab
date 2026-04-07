resource "google_service_account" "cloudbuild" {
  account_id   = var.cloudbuild_sa_name
  display_name = "Cloud Build deploy pipeline"
  project      = var.project_id

  depends_on = [google_project_service.lab]
}

# Minimal roles for building + pushing + deploying to GKE (tighten further per org policy).
locals {
  cloudbuild_project_roles = [
    "roles/cloudbuild.builds.builder",
    "roles/artifactregistry.writer",
    "roles/container.developer",
    "roles/logging.logWriter",
    # run-trivy-parser.yaml / parse_trivy_bq.py (sink or raw tables)
    "roles/bigquery.jobUser",
  ]
}

resource "google_project_iam_member" "cloudbuild_roles" {
  for_each = toset(local.cloudbuild_project_roles)

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.cloudbuild.email}"
}

resource "google_bigquery_dataset_iam_member" "cloudbuild_bq_data_editor" {
  dataset_id = google_bigquery_dataset.trivy_logs.dataset_id
  project    = var.project_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.cloudbuild.email}"

  depends_on = [google_bigquery_dataset.trivy_logs]
}
