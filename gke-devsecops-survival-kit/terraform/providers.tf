terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.23"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  alias   = "beta"
  project = var.project_id
  region  = var.region
}

# Kubernetes provider uses GKE cluster endpoint and credentials from the same project.
provider "kubernetes" {
  host = "https://${google_container_cluster.lab_cluster.endpoint}"

  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(google_container_cluster.lab_cluster.master_auth[0].cluster_ca_certificate)
}

data "google_client_config" "default" {}

# NOTE: The kubernetes provider depends on cluster creation. If `terraform plan` errors on
# provider configuration, apply in two phases: first `terraform apply -target=google_container_cluster.lab_cluster`
# (and node pools), then full apply — or comment this provider until the cluster exists.
