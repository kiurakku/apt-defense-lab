#!/usr/bin/env bash
# Apply all namespace-scoped egress policies (deny-all + allowlist 443/53).
# Order: per namespace, deny then allow (allow unions with deny in Kubernetes NP semantics).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NP="${ROOT}/k8s/network-policy"

echo "Applying NetworkPolicies from ${NP}"

kubectl apply -f "${NP}/deny-egress-default.yaml"
kubectl apply -f "${NP}/allow-known-egress.yaml"
kubectl apply -f "${NP}/deny-egress-trivy-system.yaml"
kubectl apply -f "${NP}/allow-known-egress-trivy-system.yaml"
kubectl apply -f "${NP}/deny-egress-falco.yaml"
kubectl apply -f "${NP}/allow-known-egress-falco.yaml"

echo "Done."
