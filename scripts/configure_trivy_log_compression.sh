#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-trivy-system}"
CONFIGMAP="${CONFIGMAP:-trivy-operator-config}"
DEPLOYMENT="${DEPLOYMENT:-trivy-operator}"

echo "Enabling Trivy scan job log compression in ${NAMESPACE}/${CONFIGMAP}"

kubectl patch configmap "${CONFIGMAP}" \
  -n "${NAMESPACE}" \
  --type merge \
  -p '{"data":{"scanJob.compressLogs":"true"}}'

kubectl rollout restart deployment "${DEPLOYMENT}" -n "${NAMESPACE}"
kubectl rollout status deployment "${DEPLOYMENT}" -n "${NAMESPACE}" --timeout=180s

echo "Compression enabled."
