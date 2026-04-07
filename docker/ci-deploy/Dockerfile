# Single image: gcloud + kubectl + helm + GKE auth plugin (for Cloud Build / CI)
FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:slim

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && bash -c "$(curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3)" \
    && gcloud components install gke-gcloud-auth-plugin kubectl --quiet \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV USE_GKE_GCLOUD_AUTH_PLUGIN=True
