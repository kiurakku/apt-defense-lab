# Enable required GCP APIs before GKE, BigQuery, IAM, and log sinks.
# Service identifiers: https://cloud.google.com/service-usage/docs/reference/rest/v1/services

locals {
  required_project_services = [
    "serviceusage.googleapis.com",       # Service Usage API (meta)
    "container.googleapis.com",          # Kubernetes Engine
    "compute.googleapis.com",            # Compute (GKE nodes, networks)
    "iam.googleapis.com",                # IAM
    "iamcredentials.googleapis.com",     # SignBlob (WIF / workload identity)
    "sts.googleapis.com",                # Security Token Service (Workload Identity Federation)
    "bigquery.googleapis.com",           # BigQuery datasets/tables
    "logging.googleapis.com",            # Log Router → BigQuery sinks
    "monitoring.googleapis.com",         # Metrics (GKE node SA)
  ]
}

resource "google_project_service" "lab" {
  for_each = toset(local.required_project_services)

  project = var.project_id
  service = each.key

  disable_on_destroy = false
}
