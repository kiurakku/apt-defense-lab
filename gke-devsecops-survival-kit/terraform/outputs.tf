output "cluster_name" {
  description = "GKE cluster name"
  value       = google_container_cluster.lab_cluster.name
}

output "cluster_endpoint" {
  description = "Kubernetes API server endpoint"
  value       = google_container_cluster.lab_cluster.endpoint
}

output "wif_provider_name" {
  description = "Full resource name of the GitHub WIF provider (for GitHub Actions)"
  value       = google_iam_workload_identity_pool_provider.github_provider.name
}

output "cicd_sa_email" {
  description = "CI/CD service account email"
  value       = google_service_account.cicd.email
}

output "trivy_sa_email" {
  description = "Trivy operator service account email"
  value       = google_service_account.trivy.email
}

output "cloudbuild_sa_email" {
  description = "Cloud Build service account email"
  value       = google_service_account.cloudbuild.email
}
