output "cluster_name" {
  description = "GKE cluster name"
  value       = google_container_cluster.lab_cluster.name
}

output "cluster_endpoint" {
  description = "Kubernetes API server endpoint"
  value       = google_container_cluster.lab_cluster.endpoint
}

output "wif_lab_provider_name" {
  description = "WIF provider resource name for vulnerable/lab GitHub workflows"
  value       = google_iam_workload_identity_pool_provider.github_lab_provider.name
}

output "wif_prod_provider_name" {
  description = "WIF provider resource name for hardened plan/apply workflows"
  value       = google_iam_workload_identity_pool_provider.github_prod_provider.name
}

output "cicd_lab_sa_email" {
  description = "Lab / vulnerable workflow service account"
  value       = google_service_account.cicd_lab.email
}

output "cicd_plan_sa_email" {
  description = "Hardened terraform plan service account"
  value       = google_service_account.cicd_plan.email
}

output "cicd_apply_sa_email" {
  description = "Hardened terraform apply / demo impact service account"
  value       = google_service_account.cicd_apply.email
}

output "demo_impact_bucket" {
  description = "Single demo bucket for controlled write impact (objectAdmin for lab + apply SAs)"
  value       = google_storage_bucket.demo_impact.name
}

output "trivy_sa_email" {
  description = "Trivy operator service account email"
  value       = google_service_account.trivy.email
}

output "cloudbuild_sa_email" {
  description = "Cloud Build service account email"
  value       = google_service_account.cloudbuild.email
}

output "cloudbuild_sa_resource_name" {
  description = "Service account id for Cloud Build trigger `serviceAccount` (projects/.../serviceAccounts/...)"
  value       = google_service_account.cloudbuild.id
}

output "logging_sink_writer" {
  description = "Log sink writer identity (for debugging IAM)"
  value       = google_logging_project_sink.trivy_operator.writer_identity
}

output "logging_sink_name" {
  description = "Log Router sink id (Terraform-managed)"
  value       = google_logging_project_sink.trivy_operator.name
}

output "bigquery_dataset_id" {
  description = "BigQuery dataset for Trivy / logging pipeline"
  value       = google_bigquery_dataset.trivy_logs.dataset_id
}

output "artifact_registry_lab_ci" {
  description = "Artifact Registry repo for Docker (Cloud Build image)"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.lab_ci.repository_id}"
}
