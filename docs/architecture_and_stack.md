# Архітектура та стек — apt-defense-lab

Цей документ описує загальну архітектуру, ключові потоки (CI→GCP, Pod→GCP, Logs→BQ) та технологічний стек/версії. Репозиторій **кореневий** (`terraform/`, `.github/workflows/` у корені проєкту).

**GitHub Actions:** у workflow для `terraform plan` передаються `TF_VAR_*` (у т.ч. `project_id`, `tf_state_bucket_name`, `github_org`/`github_repo` з контексту репозиторію). Деталі — `docs/github_actions_runbook.md` та кореневий `README.md` (таблиця секретів).

---

## Архітектура (високий рівень)

```text
                    (A) CI/CD path (GitHub Actions → GCP)
┌───────────────────────────────────────────────────────────────────────────┐
│ GitHub repo                                                               │
│  - vulnerable: pull_request → WIF pool `github-lab-pool` (лише repository) │
│  - hardened plan: push main → WIF prod pool (repo + ref + workflow)       │
│  - hardened apply: workflow_dispatch → cicd-apply-sa, лише demo GCS bucket  │
└───────────────┬───────────────────────────────────────────────────────────┘
                │ OIDC (id-token: write)
                ▼
        Workload Identity Federation — два pool:
        github-lab-pool / github-prod-pool + окремі providers
                │ STS exchange
                ▼
        GCP SA: cicd-lab-sa | cicd-plan-sa | cicd-apply-sa
        - state bucket: objectUser для cicd-lab + cicd-plan (terraform init/plan)
        - demo bucket: objectAdmin лише для cicd-lab + cicd-apply (контрольований impact)
        - project: roles/viewer для cicd-lab + cicd-plan (terraform refresh)


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
│     │ Log Router sink (terraform/logging.tf → managed BQ tables)           │
│     ▼                                                                      │
│ BigQuery dataset: trivy_logs (US)                                          │
│  - авто-таблиці sink (схема Cloud Logging) + raw_compressed_logs (тестове)│
│  - clean_vulnerabilities (нормалізовані CVE рядки)                         │
│     ▲                                                                      │
│ parse_trivy_bq.py --from-sink (sink tables) або raw_compressed_logs        │
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
  - **WIF (GitHub OIDC)**: два pool (вразливий сценарій `github-lab-pool` vs `github-prod-pool`), три SA (`cicd-lab`, `cicd-plan`, `cicd-apply`), окремий demo GCS bucket для write-демонстрацій у завданні.

- **Helm / Kubernetes (`k8s/`)**
  - **Trivy Operator**: генерує `VulnerabilityReport` та журнальні/репортні payload-и (gzip+base64) для pipeline.
  - **Falco**: runtime-detection для тактик (запис у `/tmp`, C2-порти).
  - **NetworkPolicy**: deny-all egress + allowlist (443/53), блокування C2 через “відсутність дозволу”.

- **Скрипти (`scripts/`)**
  - `bq_sink_inspect.py`: схема + sample row з таблиць sink; опційно рядок у `raw_compressed_logs`.
  - `parse_trivy_bq.py`: з `--from-sink` читає таблиці експорту Logging; інакше — `raw_compressed_logs`; пише в `clean_vulnerabilities`.
  - `log_sink_setup.sh`: застарілий ручний sink (дублює Terraform — не запускати разом).

- **Експлойти (`exploits/`)**
  - `container_escape/escape.sh`: демонструє **клас** CVE-2022-0492 (cgroup v1 `release_agent`) і показує proof-файл.
  - `master_plane_crash/dos_apiserver.sh`: навантаження API server через flood створень ConfigMap.
  - `github_action_steal/malicious_pr_payload.sh`: симуляція “що додасть атакер у PR workflow” для крадіжки токена.

---

## Потоки безпеки (Threat-model у двох словах)

### 1) Вразливий CI (навмисно)

- **Передумова**: workflow запускається на `pull_request` (включно з fork) + `id-token: write`.
- **Помилка довіри**: WIF provider перевіряє лише `assertion.repository`, але **не** вимагає `assertion.ref == 'refs/heads/main'`.
- **Наслідок**: fork PR може отримати Google access token для **`cicd-lab-sa`** під час `terraform plan` та виконувати API-виклики в межах ролей SA.

### 2) Hardened CI (цільовий стан)

- **Plan**: `push` на `main`, prod pool WIF: **repo + ref + allowlist workflow** (`hardened-tf-plan` / `hardened-tf-apply`).
- **Apply**: окремий SA з write лише на **demo bucket**; workflow не виконує повний `terraform apply` (лише `gcloud storage cp` proof-об’єкт).
- Додатково: pin Actions by SHA, branch protection на `main`.

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
6. `terraform apply` уже створює Log Router sink (`logging.tf`); дочекатися рядків у авто-таблицях dataset.
7. `python scripts/parse_trivy_bq.py --project … --dataset trivy_logs --from-sink` (або `bq_sink_inspect.py` для діагностики).
8. Провести демонстрації (експлойти) лише в ізольованому середовищі тестового завдання.

