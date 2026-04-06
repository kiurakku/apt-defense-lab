variable "project_id" {
  description = "GCP project ID for the lab"
  type        = string
}

variable "region" {
  description = "GCP region for GKE and related resources"
  type        = string
}

variable "zone" {
  description = "GCP zone for zonal node pools (if used)"
  type        = string
  default     = null
}

variable "cluster_name" {
  description = "GKE cluster name"
  type        = string
  default     = "lab-cluster"
}

variable "github_org" {
  description = "GitHub org or user for Workload Identity Federation audience"
  type        = string
  default     = "TODO_GITHUB_ORG"
}

variable "github_repo" {
  description = "GitHub repository name for WIF attribute mapping"
  type        = string
  default     = "TODO_REPO"
}

variable "cicd_service_account_id" {
  description = "Service account ID (without domain) for CI/CD and WIF"
  type        = string
  default     = "cicd-sa"
}
