resource "google_artifact_registry_repository" "lab_ci" {
  location      = var.region
  repository_id = "lab-ci"
  description   = "CI deploy images (gcloud/kubectl/helm)"
  format        = "DOCKER"
  project       = var.project_id

  depends_on = [google_project_service.lab]
}
