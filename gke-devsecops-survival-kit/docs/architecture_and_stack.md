# Архітектура та стек — `gke-devsecops-survival-kit`

Цей документ описує загальну архітектуру, ключові потоки (CI→GCP, Pod→GCP, Logs→BQ) та технологічний стек/версії в проєкті.

---

## Архітектура (високий рівень)

```text
                    (A) CI/CD path (GitHub Actions → GCP)
┌───────────────────────────────────────────────────────────────────────────┐
│ GitHub repo                                                               │
│  - vulnerable workflow: pull_request (forks)                              │
│  - hardened workflow: push to main                                        │
└───────────────┬───────────────────────────────────────────────────────────┘
                │ OIDC (id-token: write)
                ▼
        Workload Identity Federation (WIF)
  google_iam_workload_identity_pool + provider (github-provider)
                │ STS exchange
                ▼
        GCP Service Account: cicd-sa
        - roles/storage.admin (tf state bucket)
        - roles/compute.viewer (demo API access)


                     (B) Runtime path (GKE Pod → GCP)
┌───────────────────────────────────────────────────────────────────────────┐
│ GKE Standard cluster: lab-cluster                                         │
│  - nodepool vulnerable-pool (1.27.x pinned)                               │
│  - nodepool hardened-pool (Shielded VM)                                   │
│                                                                           │
│  trivy-operator (KSA: trivy-operator, ns: trivy-system)                   │
│      │ Workload Identity (KSA ↔ GSA)                                      │
│      ▼                                                                    │
│  GCP Service Account: trivy-sa                                            │
│   - roles/bigquery.dataEditor, roles/bigquery.jobUser                     │
└───────────────────────────────────────────────────────────────────────────┘


                  (C) Telemetry path (Cloud Logging → BigQuery)
┌───────────────────────────────────────────────────────────────────────────┐
│ Cloud Logging                                                             │
│  - k8s_container logs for trivy-operator                                   │
│     │ Log Router sink (scripts/log_sink_setup.sh)                          │
│     ▼                                                                      │
│ BigQuery dataset: trivy_logs (US)                                          │
│  - raw_compressed_logs (base64(gzip(JSON)) як log_data)                    │
│  - clean_vulnerabilities (нормалізовані CVE рядки)                         │
│     ▲                                                                      │
│ scripts/parse_trivy_bq.py                                                  │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Компоненти та їх роль

- **Terraform (`terraform/`)**
  - **GKE Standard кластер** з двома node pool:
    - `vulnerable-pool`: старий pinned node version для демонстрації класу escape/DoS.
    - `hardened-pool`: Shielded VM (`secure_boot`, `integrity_monitoring`) як “blue team” ціль.
  - **BigQuery**: dataset + таблиці для сирих/очищених даних.
  - **Workload Identity (GKE)**: прив’язка KSA `trivy-system/trivy-operator` → GSA `trivy-sa`.
  - **WIF (GitHub OIDC)**: пул/провайдер для GitHub Actions → `cicd-sa` (вразливий vs hardened варіант).

- **Helm / Kubernetes (`k8s/`)**
  - **Trivy Operator**: генерує `VulnerabilityReport` та журнальні/репортні payload-и (gzip+base64) для pipeline.
  - **Falco**: runtime-detection для тактик (запис у `/tmp`, C2-порти).
  - **NetworkPolicy**: deny-all egress + allowlist (443/53), блокування C2 через “відсутність дозволу”.

- **Скрипти (`scripts/`)**
  - `log_sink_setup.sh`: створює Log Router sink на BigQuery + видає IAM на dataset.
  - `parse_trivy_bq.py`: читає `raw_compressed_logs`, декодує base64→gzip→JSON, пише в `clean_vulnerabilities`.

- **Експлойти (`exploits/`)**
  - `container_escape/escape.sh`: демонструє **клас** CVE-2022-0492 (cgroup v1 `release_agent`) і показує proof-файл.
  - `master_plane_crash/dos_apiserver.sh`: навантаження API server через flood створень ConfigMap.
  - `github_action_steal/malicious_pr_payload.sh`: симуляція “що додасть атакер у PR workflow” для крадіжки токена.

---

## Потоки безпеки (Threat-model у двох словах)

### 1) Вразливий CI (навмисно)

- **Передумова**: workflow запускається на `pull_request` (включно з fork) + `id-token: write`.
- **Помилка довіри**: WIF provider перевіряє лише `assertion.repository`, але **не** вимагає `assertion.ref == 'refs/heads/main'`.
- **Наслідок**: fork PR може отримати Google access token для `cicd-sa` під час `terraform plan` та виконувати API-виклики в межах ролей SA.

### 2) Hardened CI (цільовий стан)

- Trigger **лише** `push` на `main`.
- WIF provider `attribute_condition` включає **repo + ref** (`refs/heads/main`).
- Додатково: мінімізувати ролі SA, розділити `plan` і `apply` SAs, pin Actions by SHA.

### 3) Runtime + Egress controls

- Falco: виявляє “magic file” у `/tmp` та мережеві патерни reverse shell/C2.
- NetworkPolicy: default-deny egress; allowlist DNS/HTTPS; C2 порт (напр. 4444) не дозволений.

---

## Стек та версії (орієнтир)

- **OS**: Windows 10/11 (локальна машина), bash-скрипти запускаються у Linux контейнері/WSL/Cloud Shell за потреби.
- **Terraform**: `>= 1.5` (локально рекомендовано 1.14.8 windows_amd64).
- **Terraform providers**:
  - `hashicorp/google` `~> 5.0`
  - `hashicorp/google-beta` `~> 5.0`
- **GKE**: Standard (Autopilot вимкнено), Workload Identity увімкнено.
  - `vulnerable-pool`: `1.27.16-gke.1800` (pinned)
  - `hardened-pool`: “latest stable” (без pin)
- **Helm charts**:
  - `aquasecurity/trivy-operator` `0.32.1`
  - `falcosecurity/falco` `8.0.1`
- **Python**: 3.11+; залежності — `scripts/requirements.txt`.
- **Auth**:
  - GitHub OIDC → GCP WIF (pool/provider)
  - GKE Workload Identity (KSA↔GSA) для Trivy→BQ

---

## Рекомендований порядок розгортання (операційно)

1. Встановити `gcloud` і зробити `gcloud auth application-default login`.
2. Створити GCS bucket для Terraform state (або тимчасово `-backend=false`).
3. `terraform init` → `terraform apply` (створить GKE, BQ, SAs, WIF).
4. `kubectl` credentials до кластера.
5. Helm install Trivy operator (з анотацією на `trivy-sa`) та Falco.
6. Налаштувати Log Router sink → BigQuery.
7. Дочекатися даних у `raw_compressed_logs`, запустити `parse_trivy_bq.py`.
8. Провести демонстрації (експлойти) лише в lab-контурі.

