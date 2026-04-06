# Workload Identity Federation (GitHub Actions) + GSA for CI/CD.
# -----------------------------------------------------------------------------
# VULNERABLE pattern (conceptual — do NOT use in production):
#   - Workload Identity Pool Provider for GitHub with NO attribute_condition
#     on assertion.ref / repository, OR
#   - IAM "principalSet" bindings that allow any pull_request from any fork
#   - Result: a workflow running in a forked PR context can still obtain a token
#     that maps to a powerful GSA → token exfiltration via malicious workflow.
#
# HARDENED pattern:
#   - Provider attribute_condition: e.g. attribute.repository == 'org/repo'
#     AND attribute.ref == 'refs/heads/main'
#   - GitHub workflow: trigger on push to main, not PR from forks for Terraform
#   - Least-privilege roles on the GSA; separate planning vs applying SAs.
# -----------------------------------------------------------------------------

locals {
  # TODO: Replace with your GitHub org/repo for attribute mapping
  github_audience = "https://token.actions.githubusercontent.com"
}

resource "google_service_account" "cicd" {
  depends_on = [google_project_service.lab]
  account_id   = var.cicd_service_account_id
  display_name = "CI/CD Terraform (WIF lab)"
  project      = var.project_id
}

# Pool for external identities (GitHub OIDC).
resource "google_iam_workload_identity_pool" "github_pool" {
  workload_identity_pool_id = "github-lab-pool"
  display_name                = "GitHub Lab Pool"
  description                 = "WIF pool for GitHub Actions (lab)"
  project                     = var.project_id
}

resource "google_iam_workload_identity_pool_provider" "github_provider" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider"
  display_name                       = "GitHub OIDC"
  project                            = var.project_id

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  # HARDENED: restrict which GitHub repos/refs can mint Google credentials.
  # VULNERABLE: omit attribute_condition entirely → broader principal acceptance.
  attribute_condition = "assertion.repository == '${var.github_org}/${var.github_repo}' && assertion.ref == 'refs/heads/main'"
}

# Allow GitHub WIF identities to impersonate the CI/CD GSA (principalset on repo).
resource "google_service_account_iam_member" "cicd_wif_user" {
  service_account_id = google_service_account.cicd.name
  role                 = "roles/iam.workloadIdentityUser"
  member               = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}/attribute.repository/${var.github_org}/${var.github_repo}"
}

# TODO (lab doc): Duplicate provider as a "vulnerable" thought experiment:
# google_iam_workload_identity_pool_provider.github_provider_vulnerable
#   with NO attribute_condition and member = principalSet://.../attribute.repository/ORG/*
# Never apply the vulnerable variant to a real project.

resource "google_project_iam_member" "cicd_editor" {
  # TODO: Narrow to minimal roles (e.g. custom role for tf state + target resources)
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.cicd.email}"
}
