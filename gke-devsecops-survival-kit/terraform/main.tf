# GKE Standard cluster with two node pools (vulnerable vs hardened).

resource "google_service_account" "gke_nodes" {
  account_id   = "gke-nodes-sa"
  display_name = "GKE node service account"
  project      = var.project_id
}

resource "google_project_iam_member" "gke_nodes_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

resource "google_container_cluster" "lab_cluster" {
  provider = google-beta
  name     = var.cluster_name
  location = var.region

  remove_default_node_pool = true
  initial_node_count       = 1

  networking_mode = "VPC_NATIVE"

  ip_allocation_policy {}

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  depends_on = [google_project_service.lab]
}

resource "google_container_node_pool" "vulnerable_pool" {
  provider = google-beta
  name     = "vulnerable-pool"
  cluster  = google_container_cluster.lab_cluster.name
  location = var.region

  node_count = 1
  version    = "1.27.16-gke.1800"

  node_config {
    machine_type    = "e2-medium"
    image_type      = "COS_CONTAINERD"
    preemptible     = true
    service_account = google_service_account.gke_nodes.email

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }

  management {
    auto_repair  = true
    auto_upgrade = false
  }
}

resource "google_container_node_pool" "hardened_pool" {
  provider = google-beta
  name     = "hardened-pool"
  cluster  = google_container_cluster.lab_cluster.name
  location = var.region

  node_count = 1

  node_config {
    machine_type    = "e2-medium"
    image_type      = "COS_CONTAINERD"
    preemptible     = true
    service_account = google_service_account.gke_nodes.email

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }
}
