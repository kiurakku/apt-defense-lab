resource "google_bigquery_dataset" "trivy_logs" {
  depends_on = [google_project_service.lab]

  dataset_id                 = var.bq_dataset_id
  friendly_name              = "Trivy logs"
  description                = "Raw compressed logs and parsed vulnerabilities"
  location                   = "US"
  project                    = var.project_id
  delete_contents_on_destroy = true
}

resource "google_bigquery_table" "raw_compressed_logs" {
  dataset_id = google_bigquery_dataset.trivy_logs.dataset_id
  table_id   = "raw_compressed_logs"
  project    = var.project_id

  schema = jsonencode([
    { name = "insert_time", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "namespace", type = "STRING", mode = "NULLABLE" },
    { name = "report_name", type = "STRING", mode = "NULLABLE" },
    { name = "log_data", type = "STRING", mode = "REQUIRED" },
  ])
}

resource "google_bigquery_table" "clean_vulnerabilities" {
  dataset_id = google_bigquery_dataset.trivy_logs.dataset_id
  table_id   = "clean_vulnerabilities"
  project    = var.project_id

  schema = jsonencode([
    { name = "insert_time", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "namespace", type = "STRING", mode = "NULLABLE" },
    { name = "report_name", type = "STRING", mode = "NULLABLE" },
    { name = "image", type = "STRING", mode = "NULLABLE" },
    { name = "vulnerability_id", type = "STRING", mode = "NULLABLE" },
    { name = "severity", type = "STRING", mode = "NULLABLE" },
    { name = "pkg_name", type = "STRING", mode = "NULLABLE" },
    { name = "installed_version", type = "STRING", mode = "NULLABLE" },
    { name = "fixed_version", type = "STRING", mode = "NULLABLE" },
    { name = "title", type = "STRING", mode = "NULLABLE" },
  ])
}
