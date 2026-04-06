#!/usr/bin/env bash
# Create a log router sink from GKE container logs (trivy-operator) to BigQuery.
# Set variables before running. Requires: gcloud, logging.admin, bigquery admin on project.
set -euo pipefail

: "${PROJECT_ID:?Set PROJECT_ID}"
: "${DATASET:?Set DATASET (e.g. trivy_logs)}"
: "${SINK_NAME:=trivy-operator-bq-sink}"
: "${BQ_LOCATION:=EU}" # TODO: match dataset location

# Log filter: k8s container logs for trivy-operator workload
LOG_FILTER='resource.type="k8s_container" AND labels."k8s-pod/app"="trivy-operator"'

echo "Creating sink ${SINK_NAME} in project ${PROJECT_ID}..."

gcloud logging sinks create "${SINK_NAME}" \
  "bigquery.googleapis.com/projects/${PROJECT_ID}/datasets/${DATASET}" \
  --project="${PROJECT_ID}" \
  --log-filter="${LOG_FILTER}"

# Sink service account is printed by create; fetch writer identity
SINK_SA="$(gcloud logging sinks describe "${SINK_NAME}" --project="${PROJECT_ID}" --format='value(writerIdentity)')"

echo "Grant BigQuery Data Editor to sink SA: ${SINK_SA}"

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="${SINK_SA}" \
  --role="roles/bigquery.dataEditor"

echo "Done. TODO: verify dataset ${DATASET} exists and location matches ${BQ_LOCATION}."
