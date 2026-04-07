# Demo impact bucket: only this bucket gets objectAdmin for cicd_apply / lab SA demonstrations.
resource "random_id" "demo_bucket" {
  byte_length = 2
}

resource "google_storage_bucket" "demo_impact" {
  name                        = "${var.project_id}-demo-impact-${random_id.demo_bucket.hex}"
  location                    = var.region
  project                     = var.project_id
  uniform_bucket_level_access = true
  force_destroy               = true

  depends_on = [google_project_service.lab]
}
