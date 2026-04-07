#!/usr/bin/env bash
set -euo pipefail
# DEPRECATED for this repo: use Terraform `terraform/logging.tf` (google_logging_project_sink.trivy_operator).
# Running this script after Terraform will create a DUPLICATE sink with the same filter → duplicate BigQuery costs.
# Kept only for emergency manual recreation or labs without Terraform.

# Usage: PROJECT_ID=my-project DATASET=trivy_logs bash log_sink_setup.sh

: "${PROJECT_ID:?Set PROJECT_ID}"
: "${DATASET:?Set DATASET (e.g. trivy_logs)}"

SINK_NAME="${SINK_NAME:-trivy-bq-sink}"

echo "Creating log sink ${SINK_NAME} → BigQuery dataset ${DATASET}"

gcloud logging sinks create "${SINK_NAME}" \
  "bigquery.googleapis.com/projects/${PROJECT_ID}/datasets/${DATASET}" \
  --log-filter='resource.type="k8s_container" AND labels."k8s-pod/app.kubernetes.io/name"="trivy-operator"' \
  --project="${PROJECT_ID}"

SINK_SA="$(gcloud logging sinks describe "${SINK_NAME}" --project="${PROJECT_ID}" --format='value(writerIdentity)')"

echo "Sink writer identity: ${SINK_SA}"

echo "Granting BigQuery Data Editor on dataset ${DATASET}"

gcloud datasets add-iam-policy-binding "${DATASET}" \
  --project="${PROJECT_ID}" \
  --member="${SINK_SA}" \
  --role="roles/bigquery.dataEditor"

echo "Done."
