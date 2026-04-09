#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-trivy-system}"
CONFIGMAP="${CONFIGMAP:-trivy-operator-config}"
DEPLOYMENT="${DEPLOYMENT:-trivy-operator}"

echo "Enabling Trivy scan job log compression in ${NAMESPACE}/${CONFIGMAP}"

current_value="$(kubectl get configmap "${CONFIGMAP}" -n "${NAMESPACE}" -o jsonpath='{.data.scanJob\.compressLogs}' 2>/dev/null || true)"
if [[ "${current_value}" == "true" ]]; then
  echo "Compression already enabled; skipping deployment restart."
  exit 0
fi

kubectl patch configmap "${CONFIGMAP}" \
  -n "${NAMESPACE}" \
  --type merge \
  -p '{"data":{"scanJob.compressLogs":"true"}}'

kubectl rollout restart deployment "${DEPLOYMENT}" -n "${NAMESPACE}"
kubectl rollout status deployment "${DEPLOYMENT}" -n "${NAMESPACE}" --timeout=300s

echo "Compression enabled."
