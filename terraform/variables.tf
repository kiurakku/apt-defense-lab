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

variable "github_hardened_plan_workflow" {
  description = "GitHub Actions workflow `name:` for hardened plan (must match OIDC claim `workflow`)"
  type        = string
  default     = "hardened-tf-plan"
}

variable "github_hardened_apply_workflow" {
  description = "GitHub Actions workflow `name:` for hardened apply"
  type        = string
  default     = "hardened-tf-apply"
}

variable "tf_state_bucket_name" {
  description = "Existing GCS bucket used for Terraform remote state (IAM bindings for plan/lab SAs)"
  type        = string
}

variable "cicd_lab_sa_name" {
  description = "GSA for vulnerable / lab GitHub workflows (WIF lab pool)"
  type        = string
  default     = "cicd-lab-sa"
}

variable "cicd_plan_sa_name" {
  description = "GSA for hardened terraform plan (WIF prod pool)"
  type        = string
  default     = "cicd-plan-sa"
}

variable "cicd_apply_sa_name" {
  description = "GSA for hardened terraform apply / demo writes (WIF prod pool)"
  type        = string
  default     = "cicd-apply-sa"
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

variable "magic_tmp_filename" {
  description = "IOC filename under /tmp (keep in sync with k8s/falco/custom-rules.yaml macro apt_magic_filename / values.yaml)"
  type        = string
  default     = "apt-magic-staging.txt"
}
