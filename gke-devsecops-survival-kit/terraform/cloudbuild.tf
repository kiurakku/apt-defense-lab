resource "google_service_account" "cloudbuild" {
  account_id   = var.cloudbuild_sa_name
  display_name = "Cloud Build lab deployer"
  project      = var.project_id

  depends_on = [google_project_service.lab]
}

locals {
  cloudbuild_project_roles = [
    "roles/cloudbuild.builds.builder",
    "roles/container.admin",
    "roles/bigquery.admin",
    "roles/logging.configWriter",
    "roles/storage.admin",
  ]
}

resource "google_project_iam_member" "cloudbuild_roles" {
  for_each = toset(local.cloudbuild_project_roles)

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.cloudbuild.email}"
}
