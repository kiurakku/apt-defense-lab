locals {
  required_project_services = [
    "container.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
    "bigquery.googleapis.com",
    "cloudbuild.googleapis.com",
    "artifactregistry.googleapis.com",
    "logging.googleapis.com",
    "cloudresourcemanager.googleapis.com",
  ]
}

resource "google_project_service" "lab" {
  for_each = toset(local.required_project_services)

  project            = var.project_id
  service            = each.key
  disable_on_destroy = false
}
