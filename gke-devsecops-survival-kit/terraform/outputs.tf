output "cluster_name" {
  description = "Name of the GKE cluster"
  value       = google_container_cluster.lab_cluster.name
}

output "cluster_endpoint" {
  description = "Kubernetes API endpoint"
  value       = google_container_cluster.lab_cluster.endpoint
}

output "cluster_location" {
  description = "Cluster location (region)"
  value       = google_container_cluster.lab_cluster.location
}

output "workload_identity_pool_id" {
  description = "Full WIF pool ID for GitHub Actions provider"
  value       = google_iam_workload_identity_pool.github_pool.name
}

output "github_wif_provider_name" {
  description = "GitHub OIDC provider resource name"
  value       = google_iam_workload_identity_pool_provider.github_provider.name
}

output "cicd_service_account_email" {
  description = "CI/CD service account email for GitHub WIF"
  value       = google_service_account.cicd.email
}

output "bigquery_dataset_id" {
  description = "BigQuery dataset for Trivy logs"
  value       = google_bigquery_dataset.trivy_logs.dataset_id
}

output "gke_nodes_service_account" {
  description = "GKE node service account email"
  value       = google_service_account.gke_nodes.email
}
