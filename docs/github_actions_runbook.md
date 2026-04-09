# GitHub Actions + секрети + узгодження з GKE

У репозиторії **обов’язково** мають бути три файли (інакше GitHub Actions їх не побачить):

| Файл | Призначення |
|------|----------------|
| `.github/workflows/vulnerable-tf-plan.yml` | PR / WIF для вразливого сценарію (`github-lab-pool`) |
| `.github/workflows/hardened-tf-plan.yml` | push у `main`, prod WIF |
| `.github/workflows/hardened-tf-apply.yml` | ручний demo-write у GCS |

Якщо зміни лише локальні — **запуш у віддалений репозиторій** (`main` або гілка для PR).

---

## 1. Push у `main`

Після push у **`main`** має автоматично стартувати **`hardened-tf-plan`**.

**Secrets (GitHub → Settings → Secrets and variables → Actions):**

| Secret | Приклад призначення |
|--------|---------------------|
| `GCP_PROJECT_ID` | id GCP-проєкту (як у `terraform.tfvars` → `project_id`) |
| `WIF_PROVIDER_PROD` | `terraform output -raw wif_prod_provider_name` |
| `CICD_PLAN_SA_EMAIL` | `terraform output -raw cicd_plan_sa_email` |
| `TF_STATE_BUCKET` | ім’я bucket без `gs://` (те саме, що `tf_state_bucket_name` у Terraform) |

`github_org` / `github_repo` у CI підставляються з репозиторію автоматично; вони мають збігатися з тим, що було в `terraform apply` при створенні WIF.

**Що перевірити в логах run:** крок **Authenticate to Google Cloud**, потім **`terraform init`**, **`terraform plan`** — успіх.

**Типові помилки:** не той `WIF_PROVIDER_PROD` / `CICD_PLAN_SA_EMAIL`; не той bucket у `TF_STATE_BUCKET`; workflow не на гілці `main` (для `hardened-tf-plan` тригер лише `push` → `main`).

---

## 2. Hardened apply (вручну)

**Actions → `hardened-tf-apply` → Run workflow.**

**Secrets:**

| Secret | |
|--------|--|
| `WIF_PROVIDER_PROD` | як вище |
| `CICD_APPLY_SA_EMAIL` | `terraform output -raw cicd_apply_sa_email` |
| `DEMO_IMPACT_BUCKET` | `terraform output -raw demo_impact_bucket` (без `gs://`) |

**Очікування:** у bucket з’являється об’єкт **`demo-write-proof.txt`**.

Перевірка (підставте свій bucket):

```bash
gcloud storage cat gs://YOUR_DEMO_BUCKET/demo-write-proof.txt
```

---

## 3. Вразливий сценарій (PR + WIF) — демонстрація ризику

1. Створіть **окрему гілку**, відкрийте **PR** у той самий репозиторій.
2. Має запуститися **`vulnerable-tf-plan`** (тригер `pull_request`).

**Secrets:**

| Secret | |
|--------|--|
| `GCP_PROJECT_ID` | той самий project id, що в `terraform.tfvars` |
| `WIF_PROVIDER_LAB` | `terraform output -raw wif_lab_provider_name` |
| `CICD_LAB_SA_EMAIL` | `terraform output -raw cicd_lab_sa_email` |
| `TF_STATE_BUCKET` | той самий remote state bucket |

Це і є сценарій **недостатньо жорсткого WIF** на подіях PR.

---

## 4. Після GitHub — GCP / Cloud Build

1. За потреби **вирівняйте Terraform/GKE** з кодом (див. розділ **Drift** нижче).
2. Збір образу CI:

   ```bash
   gcloud builds submit --config=cloudbuild/cloudbuild.yaml .
   ```

3. Деплой додатків у GKE — **`cloudbuild/deploy-gke-apps.yaml`**, з підстановкою наприклад:

   ```text
   _TRIVY_GSA_EMAIL=trivy-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com
   ```

   (точне значення: `terraform output -raw trivy_sa_email`.)

4. Парсер BigQuery — **`cloudbuild/run-trivy-parser.yaml`** (або локально `parse_trivy_bq.py --from-sink`).

Детальніше: `docs/google_docs_submission_guide_uk.md` (скріншоти та команди).

---

## 5. Докази для звіту (скріни)

- Успішний **`hardened-tf-plan`** (зелений run).
- Успішний **`hardened-tf-apply`** + наявність **`demo-write-proof.txt`** у bucket.
- Run **`vulnerable-tf-plan`** на PR.
- BigQuery dataset / таблиці, Trivy і Falco в кластері (`kubectl get pods`).

Повний список скрінів: `docs/google_docs_submission_guide_uk.md` (розділ чеклісту).

---

## 6. Важливий нюанс: drift GKE node pools

У **`terraform/main.tf`** задано:

- `remove_default_node_pool = true`
- окремі пули **`vulnerable-pool`** та **`hardened-pool`**

Після **повного** успішного `terraform apply` для цього ресурсу **не** повинно лишатися типового **`default-pool`** — його замінюють кастомні пули.

Якщо в **реальному** кластері в консолі видно лише **`default-pool`**, а в коді очікуються **`vulnerable-pool` / `hardened-pool`**, то:

- кластер міг бути створений **не** цим Terraform, або
- `apply` не застосовувався до цього проєкту/state, або
- state розійшовся з реальністю.

**Що робити:** вирівняти інфраструктуру під код (адмінський `terraform plan` / `apply` у той самий проєкт і backend), або свідомо імпортувати/перенести state — інакше кроки **kubectl/Helm/Cloud Build**, що очікують саме цей кластер, можуть падати або націлюватися не туди.

Деталі коду: `terraform/main.tf`.
