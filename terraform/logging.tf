# Log Router sink → BigQuery (managed). Creates partition tables under the dataset with Cloud Logging schema.
# Inspect actual columns in Console or: bq show --format=prettyjson PROJECT:DATASET.TABLE

resource "google_logging_project_sink" "trivy_operator" {
  name        = "trivy-operator-bq-sink-tf"
  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.trivy_logs.dataset_id}"

  filter = <<-EOT
    resource.type="k8s_container"
    labels."k8s-pod/app.kubernetes.io/name"="trivy-operator"
  EOT

  unique_writer_identity = true

  depends_on = [
    google_bigquery_dataset.trivy_logs,
    google_project_service.lab,
  ]
}

resource "google_project_iam_member" "log_sink_writer_bigquery" {
  project = var.project_id
  role    = "roles/bigquery.dataEditor"
  member  = google_logging_project_sink.trivy_operator.writer_identity
}
