# Документація — apt-defense-lab

**GKE + Terraform + GitHub Actions (WIF) + Trivy/BigQuery + Falco + NetworkPolicy.** Код: `terraform/`, `k8s/`, `.github/workflows/`, `cloudbuild/`.

## Основні файли

| Файл | Зміст |
|------|--------|
| [**README**](../README.md) | Встановлення, секрети, команди |
| [**Google_Doc_Report_apt-defense-lab_UK.md**](Google_Doc_Report_apt-defense-lab_UK.md) | **Повний текст звіту (UK)** для Google Docs |
| [**google_docs_submission_guide_uk.md**](google_docs_submission_guide_uk.md) | Чекліст скріншотів (S-*) і як їх зняти |
| [**github_actions_runbook.md**](github_actions_runbook.md) | GitHub/GCP, секрети, drift |
| [**logging_pipeline.md**](logging_pipeline.md) | Sink → BigQuery, парсер |
| [**architecture_and_stack.md**](architecture_and_stack.md) | Архітектура, діаграми потоків |
| [**evidence_upstream_kernel_and_k8s_uk.md**](evidence_upstream_kernel_and_k8s_uk.md) | Вимоги рецензента: gzip у BQ, CVE-2022-0492 у linux.git, DoS + CVE з бюлетеню GKE, kubernetes/kubernetes |

Збірка Word зі звіту: `python scripts/build_report_docx.py` → створює `docs/Report02-apt-defense-lab.docx` (не комітиться — див. `.gitignore`).

## Terraform / GitHub / Cloud Build

- `terraform/terraform.tfvars.example`, `terraform/backend.hcl.example` — копії локально (не комітити).
- Секрет **`GCP_PROJECT_ID`** у GitHub = `project_id` у tfvars.
- Деталі: **github_actions_runbook.md**, кореневий **README.md**.

## Експлойти (лише ізольований стенд)

- **`exploits/container_escape/`**, **`exploits/master_plane_crash/`** — PoC; у виводі скриптів є мітки **`[DEMO]`**.
- Клас escape: cgroup/release_agent (узгоджено з бюлетенями GKE); на **cgroup v2** багато PoC не спрацьовують — очікувано.
- DoS API: масове створення `ConfigMap` — навантаження на apiserver.

## Типові проблеми

| Симптом | Перевірити |
|---------|------------|
| Помилка змінних у Actions | `GCP_PROJECT_ID`, `TF_STATE_BUCKET` |
| WIF відмова | `github_org` / `github_repo` у state = реальний репозиторій |
| Немає `vulnerable-pool` | `terraform apply`, runbook |
| Дубль log sink | не запускати `scripts/log_sink_setup.sh`, якщо є `terraform/logging.tf` |
