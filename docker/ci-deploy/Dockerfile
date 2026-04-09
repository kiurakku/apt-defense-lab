# Single image: gcloud + kubectl + helm + GKE auth plugin (for Cloud Build / CI)
FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:slim

# Pin Helm — official install script from GitHub often flakes in CI; direct binary is reliable.
ARG HELM_VERSION=v3.15.4
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" -o /tmp/helm.tgz \
    && tar -xzf /tmp/helm.tgz -C /tmp \
    && install -m 0755 /tmp/linux-amd64/helm /usr/local/bin/helm \
    && rm -rf /tmp/helm.tgz /tmp/linux-amd64 \
    && gcloud components install kubectl gke-gcloud-auth-plugin --quiet \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV USE_GKE_GCLOUD_AUTH_PLUGIN=True
