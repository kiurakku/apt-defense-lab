#Requires -Version 5.1
<#
  Доказові перевірки для gke-devsecops-survival-kit (після deploy).
  Заповніть змінні середовища або передайте параметри.
#>
param(
  [string] $ProjectId = $env:GCP_PROJECT,
  [string] $Region = "us-central1",
  [string] $Cluster = "lab-cluster",
  [string] $TfStateBucket = $env:TF_STATE_BUCKET,
  [string] $DemoBucket = $env:DEMO_IMPACT_BUCKET,
  [string] $BqDataset = "trivy_logs"
)

$ErrorActionPreference = "Continue"

function Ok($msg) { Write-Host "[OK] $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "[--] $msg" -ForegroundColor Yellow }
function Fail($msg) { Write-Host "[!!] $msg" -ForegroundColor Red }

if (-not $ProjectId) { throw "Вкажіть -ProjectId або `$env:GCP_PROJECT" }

Write-Host "`n=== 1. Terraform / GCP (локально або CI) ===" 
try {
  $tv = terraform version 2>&1 | Select-Object -First 1
  if ($LASTEXITCODE -eq 0) { Ok "terraform: $tv" } else { Warn "terraform не знайдено в PATH" }
} catch { Warn "terraform: $_" }

Write-Host "`n=== 2. GKE кластер ===" 
try {
  gcloud container clusters describe $Cluster --region $Region --project $ProjectId 2>&1 | Out-Null
  if ($LASTEXITCODE -eq 0) { Ok "кластер $Cluster" } else { Fail "кластер $Cluster недоступний" }
} catch { Fail $_ }

Write-Host "`n=== 3. Terraform state (GCS) ===" 
if ($TfStateBucket) {
  try {
    gsutil ls "gs://$TfStateBucket/terraform/state" 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { Ok "gs://$TfStateBucket/terraform/state" } else { Warn "префікс state не знайдено або немає доступу" }
  } catch { Warn $_ }
} else {
  Warn "не задано TF_STATE_BUCKET / -TfStateBucket"
}

Write-Host "`n=== 4. BigQuery: sink + парсер ===" 
Write-Host "    python scripts/parse_trivy_bq.py --project $ProjectId --dataset $BqDataset --from-sink --limit 50"
Write-Host "    (діагностика) python scripts/bq_sink_inspect.py --project $ProjectId --dataset $BqDataset"

Write-Host "`n=== 5. Falco / NetworkPolicy (kubectl) ===" 
Write-Host "    kubectl get networkpolicy -A"
Write-Host "    kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50"

Write-Host "`n=== 6. Egress (очікування: 443/53 OK, 4444 блок) ===" 
Write-Host "    kubectl run curl-test --rm -it --restart=Never --image=curlimages/curl --command -- curl -v --connect-timeout 3 https://example.com:443"
Write-Host "    (у namespace з deny-all + allowlist — перевірте відповідно до політики)"

Write-Host "`n=== 7. WIF (GitHub) ===" 
Write-Host "    Secrets: WIF_PROVIDER_LAB, WIF_PROVIDER_PROD, CICD_LAB_SA_EMAIL, CICD_PLAN_SA_EMAIL, CICD_APPLY_SA_EMAIL, TF_STATE_BUCKET"
Write-Host "    Для hardened-tf-apply: DEMO_IMPACT_BUCKET = output demo_impact_bucket"
Write-Host "    Вразливий fork PR: план з lab pool; push main: hardened plan з prod pool."

Write-Host "`n=== 8. Cloud Build (образ lab-ci) ===" 
Write-Host "    gcloud builds submit --config=cloudbuild/cloudbuild.yaml (з project/region substitutions за README)"

Write-Host "`nГотово (скрипт лише підказує команди; виконайте їх у середовищі з gcloud/kubectl).`n"
