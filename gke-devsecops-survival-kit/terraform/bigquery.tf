resource "google_bigquery_dataset" "trivy_logs" {
  depends_on = [google_project_service.lab]

  dataset_id                 = "trivy_logs"
  friendly_name              = "Trivy operator compressed logs"
  description                = "Raw gzip+base64 container logs and cleaned vulnerability rows"
  location                   = var.region
  project                    = var.project_id
  delete_contents_on_destroy = true # TODO: set false for production

  labels = {
    env = "lab"
  }
}

resource "google_bigquery_table" "raw_compressed_logs" {
  dataset_id = google_bigquery_dataset.trivy_logs.dataset_id
  table_id   = "raw_compressed_logs"
  project    = var.project_id

  schema = jsonencode([
    { name = "timestamp", type = "TIMESTAMP", mode = "NULLABLE" },
    { name = "log_data", type = "STRING", mode = "NULLABLE", description = "Raw base64+gzip blob from log sink" },
  ])
}

resource "google_bigquery_table" "clean_vulnerabilities" {
  dataset_id = google_bigquery_dataset.trivy_logs.dataset_id
  table_id   = "clean_vulnerabilities"
  project    = var.project_id

  schema = jsonencode([
    { name = "timestamp", type = "TIMESTAMP", mode = "NULLABLE" },
    { name = "vulnerability_id", type = "STRING", mode = "NULLABLE" },
    { name = "severity", type = "STRING", mode = "NULLABLE" },
    { name = "pkg_name", type = "STRING", mode = "NULLABLE" },
    { name = "pkg_version", type = "STRING", mode = "NULLABLE" },
    { name = "image", type = "STRING", mode = "NULLABLE" },
    { name = "namespace", type = "STRING", mode = "NULLABLE" },
  ])
}
