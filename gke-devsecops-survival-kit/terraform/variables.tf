variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for GKE and regional resources"
  type        = string
  default     = "us-central1"
}

variable "cluster_name" {
  description = "GKE cluster name"
  type        = string
  default     = "lab-cluster"
}

variable "github_org" {
  description = "GitHub organization or user (for WIF attribute mapping)"
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name (for WIF attribute mapping)"
  type        = string
}

variable "cicd_sa_name" {
  description = "GCP service account ID (without domain) for GitHub Actions / Terraform CI"
  type        = string
  default     = "cicd-sa"
}

variable "trivy_sa_name" {
  description = "GCP service account ID (without domain) for Trivy operator Workload Identity"
  type        = string
  default     = "trivy-sa"
}

variable "cloudbuild_sa_name" {
  description = "GCP service account ID (without domain) for Cloud Build deployment pipeline"
  type        = string
  default     = "cloudbuild-deployer"
}

variable "bq_dataset_id" {
  description = "BigQuery dataset ID for Trivy logs"
  type        = string
  default     = "trivy_logs"
}
