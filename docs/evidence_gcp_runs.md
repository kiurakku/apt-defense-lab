# Live evidence: Cloud Build + BigQuery parser (GCP)

Цей файл — **операційний чекліст**, щоб зібрати артефакти оцінювача (скріншоти або експорт логів) після **реального** прогону в GCP. Код репозиторію сам по собі не є доказом виконання pipeline.

## 1. Передумови

- Виконано `terraform apply` (кластер, BQ, sink, Artifact Registry, SA для Cloud Build).
- Обліковка з правом дивитися Cloud Build і BigQuery.

## 2. Cloud Build — образ `lab-ci/ci-deploy`

**Команда (локально або Cloud Shell):**

```bash
cd /path/to/gke-devsecops-survival-kit
gcloud builds submit --config=cloudbuild/cloudbuild.yaml .
```

**Що зняти для звіту:**

| # | Артефакт |
|---|----------|
| A | Консоль **Cloud Build → History**: рядок білду зі статусом **Success**, видно **Trigger** або **Submitted manually**. |
| B | Відкрити білд → вкладка **Steps**: кроки `docker build` / `push` зелені; у **Artifacts** або логах видно образ `…/lab-ci/ci-deploy:SHORT_SHA` і `:latest`. |
| C | (Опційно) Текст: `gcloud builds describe BUILD_ID --format='value(status,finishTime)'` |

Пряме посилання на білд має вигляд:  
`https://console.cloud.google.com/cloud-build/builds;region=REGION/BUILD_ID?project=PROJECT_ID`

## 3. Cloud Build — deploy GKE (`deploy-gke-apps.yaml`)

Після наявності образу `latest`:

```bash
gcloud builds submit --config=cloudbuild/deploy-gke-apps.yaml \
  --substitutions=_TRIVY_GSA_EMAIL="$(terraform -chdir=terraform output -raw trivy_sa_email)"
```

(Або тригер у консолі з тими ж substitutions; SA тригера = `terraform output -raw cloudbuild_sa_email`.)

**Що зняти:**

| # | Артефакт |
|---|----------|
| D | **History** — окремий успішний білд з конфігом `deploy-gke-apps.yaml`. |
| E | У логах кроку: рядки `helm upgrade --install trivy-operator`, `falco`, `apply_network_policies.sh` без помилки. |
| F | `kubectl get pods -n trivy-system` і `-n falco` одразу після білду (термінал або скрін). |

## 4. BigQuery parser (`run-trivy-parser.yaml` або локально)

Переконайтеся, що в dataset уже є **sink-таблиці** з логами (після роботи trivy-operator і sink з `terraform/logging.tf`).

**Локально (той самий код, що в Cloud Build):**

```bash
pip install -r scripts/requirements.txt
python scripts/parse_trivy_bq.py --project YOUR_PROJECT_ID --dataset trivy_logs --from-sink --limit 100
```

**Або Cloud Build:**

```bash
gcloud builds submit --config=cloudbuild/run-trivy-parser.yaml .
```

**Що зняти:**

| # | Артефакт |
|---|----------|
| G | Термінал: рядок на кшталт `Inserted N rows into ...clean_vulnerabilities` **або** пояснення, якщо `N=0` (ще немає стислих звітів у логах). |
| H | BigQuery → таблиця `clean_vulnerabilities` → **Preview** з ≥1 рядком (CVE, severity) **або** порожня таблиця з коментарем у звіті. |
| I | (Опційно) `bq query --use_legacy_sql=false 'SELECT COUNT(*) FROM \`PROJECT.trivy_logs.clean_vulnerabilities\`'` |

## 5. Що вставити в Google Doc / PDF

Мінімальний набір для «живого» Task 2: **A + B + D + E + G + H** (або G з поясненням нульових рядків).

У **`docs/submission_report.md`** залиште посилання на цей файл або коротко перелічте номери артефактів у розділі Task 2.
