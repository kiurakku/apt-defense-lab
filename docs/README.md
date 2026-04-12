# Документація — apt-defense-lab (технічне тестове завдання)

Репозиторій з виконанням **технічного тестового завдання**: **GKE + Terraform + GitHub Actions (WIF) + Trivy/BigQuery + Falco + NetworkPolicy**. Код у **корені** (`terraform/`, `k8s/`, `.github/workflows/`, `cloudbuild/`).

---

## Швидка навігація

| Документ | Зміст |
|----------|--------|
| [**README**](../README.md) (корінь) | Встановлення, Terraform, Cloud Build, секрети GitHub, посилання |
| [**architecture_and_stack.md**](architecture_and_stack.md) | Архітектура, потоки CI/runtime/логів, стек і порядок розгортання |
| [**github_actions_runbook.md**](github_actions_runbook.md) | Push, PR, hardened plan/apply, секрети, drift GKE |
| [**logging_pipeline.md**](logging_pipeline.md) | Sink → BigQuery, парсер `--from-sink`, E2E |
| [**google_docs_submission_guide_uk.md**](google_docs_submission_guide_uk.md) | **Звіт у Google Docs:** структура, усі скріншоти, як їх зняти |
| [**Google_Doc_Report_apt-defense-lab_UK.md**](Google_Doc_Report_apt-defense-lab_UK.md) | **Повний текст звіту (UK)** для імпорту в Google Docs; з нього збирається [**Report02-apt-defense-lab.docx**](Report02-apt-defense-lab.docx) (`python scripts/build_report_docx.py`) |
| [**submission_report.md**](submission_report.md) | Чернетка тексту звіту (EN) |
| [**report_template.md**](report_template.md) | Шаблон розділів звіту |

---

## Terraform

- Каталог: **`terraform/`**
- Приклад змінних: **`terraform/terraform.tfvars.example`** → скопіювати в **`terraform.tfvars`** (не комітити).
- Backend: **`terraform/backend.hcl.example`** → **`backend.hcl`** (локально, не комітити).
- Обов’язкові змінні: `project_id`, `github_org`, `github_repo`, `tf_state_bucket_name` та ін. — див. example.

## GitHub Actions

- Файли: **`.github/workflows/`** (`vulnerable-tf-plan`, `hardened-tf-plan`, `hardened-tf-apply`).
- У **Secrets** обов’язково **`GCP_PROJECT_ID`** (те саме, що `project_id` у tfvars) — інакше `terraform plan` у CI впаде.
- `TF_VAR_github_org` / `TF_VAR_github_repo` у workflow беруться з репозиторію автоматично; мають відповідати значенням, з якими робився `terraform apply` для WIF.

Детально: [**github_actions_runbook.md**](github_actions_runbook.md).

## Cloud Build

- Каталог: **`cloudbuild/`** — опис IAM і порядку кроків: [**cloudbuild/README.md**](../cloudbuild/README.md).

## Експлойти (лише в межах тестового завдання / ізольованого стенду)

- **`exploits/container_escape/`**, **`exploits/master_plane_crash/`**, **`exploits/github_action_steal/`** — у кожного свій README.

---

## Типові проблеми

| Симптом | Що перевірити |
|---------|----------------|
| `No value for required variable` у Actions | Секрет **`GCP_PROJECT_ID`**, **`TF_STATE_BUCKET`** |
| WIF / OIDC відмова | `github_org`/`github_repo` у state = реальний org/repo; провайдер у Terraform |
| У кластері лише `default-pool` | Drift: код очікує `vulnerable-pool` + `hardened-pool` після `terraform apply` — див. runbook |
| Дубль log sink | Не запускати **`scripts/log_sink_setup.sh`**, якщо вже є **`terraform/logging.tf`** |
