# GKE lab cluster: two node pools (vulnerable vs hardened) for Red/Blue exercises.

resource "google_container_cluster" "lab_cluster" {
  provider = google-beta.beta
  name     = "lab-cluster"
  location = var.region

  # Remove default node pool; manage pools explicitly.
  remove_default_node_pool = true
  initial_node_count       = 1

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # TODO: Pin release channel / version per https://cloud.google.com/kubernetes-engine/security-bulletins
  min_master_version = null # set e.g. "1.28.x-gke.x" after checking bulletins

  binary_authorization {
    evaluation_mode = "DISABLED" # TODO: set PROJECT_SINGLETON_POLICY / etc. for real environments
  }

  network_policy {
    enabled = true
  }

  ip_allocation_policy {
    cluster_ipv4_cidr_block  = null # TODO: customize if needed
    services_ipv4_cidr_block = null
  }

  depends_on = [google_project_service.lab]
}

# Vulnerable pool: older image channel, preemptible, no Shielded VM — lab Red Team target.
resource "google_container_node_pool" "vulnerable_pool" {
  provider = google-beta.beta
  name     = "vulnerable-pool"
  cluster  = google_container_cluster.lab_cluster.name
  location = var.region

  node_count = 1

  node_config {
    # TODO: Replace with an older supported image type from GKE release notes / bulletins
    image_type = "COS_CONTAINERD"

    machine_type = "e2-medium"
    disk_size_gb = 50

    preemptible     = true
    service_account = google_service_account.gke_nodes.email

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    # Intentionally no shielded_instance_config — matches "no Shielded VM" lab scenario
  }

  management {
    auto_repair  = true
    auto_upgrade = false # TODO: pin upgrades manually while reproducing CVEs
  }
}

# Hardened pool: latest/default image preferences, Shielded VM enabled.
resource "google_container_node_pool" "hardened_pool" {
  provider = google-beta.beta
  name     = "hardened-pool"
  cluster  = google_container_cluster.lab_cluster.name
  location = var.region

  node_count = 1

  node_config {
    image_type   = "COS_CONTAINERD"
    machine_type = "e2-standard-2"
    disk_size_gb = 50

    preemptible     = false
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

# Node GSA for pools (minimal pattern; extend IAM as needed).
resource "google_service_account" "gke_nodes" {
  account_id   = "gke-nodes-sa"
  display_name = "GKE node service account (lab)"
  project      = var.project_id
}

resource "google_project_iam_member" "gke_nodes_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

resource "google_project_iam_member" "gke_nodes_monitoring" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}
