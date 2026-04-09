# Гайд: як зібрати звіт у Google Docs (текст + скріншоти)

Цей документ описує **як має виглядати звіт з технічного тестового завдання** (репозиторій **apt-defense-lab**): **де** вставляти скріншоти, **які** саме, і **як їх отримати**. Базовий текст розділів — у **`docs/submission_report.md`** (англійською); нижче — українська інструкція для переносу в Google Docs.

---

## Загальна структура документа в Google Docs

Рекомендований порядок розділів (1 документ):

| № | Розділ | Джерело тексту |
|---|--------|----------------|
| 0 | Титул: автор, дата, GCP project, посилання на репозиторій | Вручну |
| 1 | Executive Summary (коротко: що зроблено, 4 теми, захист) | `submission_report.md` §1 |
| 2 | Infrastructure Overview | §2 |
| 3 | Task 1 — escape + stress на GKE | §3 |
| 4 | Task 2 — Terraform, Cloud Build, Trivy → BigQuery | §4 |
| 5 | Task 3 — вразливий GitHub Actions + WIF | §5 |
| 6 | Defensive Controls | §6 |
| 7 | Final Assessment | §7 |
| Додаток | Команди / посилання на логи (за бажанням) | Репозиторій, консолі |

Під кожним розділом у таблицях нижче — **що заскрінити** і **як отримати**.

---

## Правила для скріншотів

1. **Закрийте секрети:** не показуйте повні OIDC provider URL, повні service account keys, повні access token у відкритому вигляді. Для токена — лише перші/останні символи або факт успішного `gcloud`.
2. **Підписи:** під кожним скріном — 1 речення: що видно і чому це доказ (напр. «Успішний `hardened-tf-plan` після push у main»).
3. **Роздільність:** достатня для читання тексту в консолі (не розмиті мобільні фото екрана, якщо можна — вікно браузера або Win+Shift+S).

---

## Розділ 2 — Infrastructure Overview

### Що вставити текстом

Перепис або копія з **`submission_report.md` §2** (кластер, пули, dataset, SA, Falco/NP).

### Скріншоти

| ID | Що показати | Як отримати |
|----|-------------|-------------|
| **S-GKE-1** | Сторінка GKE: кластер `lab-cluster`, видно **два** node pool (`vulnerable-pool`, `hardened-pool`) | GCP Console → **Kubernetes Engine** → **Clusters** → відкрити кластер → вкладка **NODE POOLS** або список пулів. Якщо видно лише `default-pool` — спочатку вирівняй інфра з `terraform/` (див. `docs/github_actions_runbook.md`). |
| **S-BQ-1** | BigQuery: dataset **`trivy_logs`**, список таблиць | Console → **BigQuery** → **Explorer** → ваш проєкт → dataset `trivy_logs`. |

---

## Розділ 3 — Task 1 (Container escape + Control-plane stress)

### 3.1 Container escape

| ID | Що показати | Як отримати |
|----|-------------|-------------|
| **S-ESC-1** | Термінал: вивід скрипта або повідомлення про блок | Локально/Cloud Shell: `gcloud container clusters get-credentials …`, под на `vulnerable-pool` за README експлойту, `bash exploits/container_escape/escape.sh`. Скрін вікна терміналу з результатом. |
| **S-ESC-2** | (Опційно) Файл-доказ на ноді або в контейнері, як у README експлойту | Якщо скрипт створює файл — `kubectl exec` / SSH до ноди **лише в ізольованому тестовому середовищі** — скрін `cat` або вмісту. |

### 3.2 Control-plane stress

| ID | Що показати | Як отримати |
|----|-------------|-------------|
| **S-DOS-1** | Термінал: запуск `dos_apiserver.sh` + фрагмент виводу | `COUNT=500 bash exploits/master_plane_crash/dos_apiserver.sh default` (або менше для демо). |
| **S-DOS-2** | Затримка або помилка `kubectl` «до/після» | Два скріни або один з таймстампом: `time kubectl get nodes` під час/після навантаження. |

---

## Розділ 4 — Task 2 (Terraform, Cloud Build, Trivy → BigQuery)

### Текст

`submission_report.md` §4, §4.1, §4.2.

### Скріншоти та артефакти

| ID | Що показати | Як отримати |
|----|-------------|-------------|
| **S-CB-1** | Cloud Build: **успішний** білд з конфігом **`cloudbuild/cloudbuild.yaml`** (образ `lab-ci/ci-deploy`) | Console → **Cloud Build** → **History** → відкрити успішний run → скрін списку steps зелених. Або: `gcloud builds list --limit=5` у терміналі → скрін. |
| **S-CB-2** | Успішний білд **`deploy-gke-apps.yaml`** (Helm, `apply_network_policies`) | Після `gcloud builds submit --config=cloudbuild/deploy-gke-apps.yaml …` — скрін History або логу кроку з `helm` / `apply_network_policies.sh`. |
| **S-CB-3** | (Опційно) Білд **`run-trivy-parser.yaml`** або локальний вивід парсера | Submit парсера або термінал: `python scripts/parse_trivy_bq.py --project … --from-sink` — скрін рядка `Inserted N rows…` або пояснення N=0. |
| **S-BQ-2** | BigQuery: **Preview** таблиці **`clean_vulnerabilities`** (колонки CVE, severity тощо) | BigQuery → таблиця → **Preview**. Якщо порожньо — скрін + короткий підпис у тексті, що логи ще не накопичились. |
| **S-BQ-3** | (Опційно) Один рядок **sink**-таблиці (managed Logging) | Або вивід `python scripts/bq_sink_inspect.py --project … --dataset trivy_logs` — скрін терміналу. |
| **S-TRIVY-1** | `scanJob.compressLogs: true` | `kubectl get cm trivy-operator-config -n trivy-system -o yaml` — скрін фрагмента з `compressLogs`. |

---

## Розділ 5 — Task 3 (Vulnerable GitHub Actions + WIF)

### Текст

`submission_report.md` §5.

### Скріншоти

| ID | Що показати | Як отримати |
|----|-------------|-------------|
| **S-GH-1** | **Actions** → workflow **`vulnerable-tf-plan`** — успішний run на **pull request** | Створити гілку, відкрити PR → дочекатися run → скрін списку jobs зелених. |
| **S-GH-2** | **Actions** → **`hardened-tf-plan`** — успішний run на **push** у `main` | Push у main → скрін (автоматичний запуск). |
| **S-GH-3** | **Actions** → **`hardened-tf-apply`** — успішний **workflow_dispatch** | Run workflow вручну → скрін. |
| **S-GH-4** | Фрагмент логу: крок **Authenticate to Google Cloud** успішний | Відкрити job → розгорнути крок auth → скрін (без зайвих секретів). |
| **S-IMP-1** | Доказ impact для `cicd-lab-sa` (опційно): наприклад список bucket / об’єкт у state | Те, що дозволяє IAM для цієї SA — без витоку повних шляхів секретів. |
| **S-DEMO-1** | Файл **`demo-write-proof.txt`** у demo bucket | Після `hardened-tf-apply`: Console **Cloud Storage** → bucket з `terraform output demo_impact_bucket` → об’єкт видно. Або термінал: `gcloud storage cat gs://BUCKET/demo-write-proof.txt` → скрін. |

---

## Розділ 6 — Defensive Controls (Falco, NetworkPolicy)

| ID | Що показати | Як отримати |
|----|-------------|-------------|
| **S-FALCO-1** | Лог Falco зі спрацюванням правила (наприклад `/tmp` або порт) | `kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=100` після тестового події — скрін. |
| **S-NP-1** | Політики в кластері | `kubectl get networkpolicy -A` — скрін терміналу. |
| **S-NP-2** | (Опційно) Перевірка egress: дозволений 443 vs заблокований «поганий» порт | Короткий опис у тексті + скрін `curl`/timeout з пода в namespace з NP (як у README). |

---

## Розділ 7 — Final Assessment

Текст з **`submission_report.md` §7**; скріншоти не обов’язкові.

---

## Чекліст перед експортом у PDF / здачею

- [ ] S-GKE-1, S-BQ-1  
- [ ] Мінімум один з S-ESC / S-DOS  
- [ ] S-CB-1, S-CB-2, S-BQ-2 (або пояснення чому даних немає)  
- [ ] S-GH-1 (vulnerable PR) + S-GH-2 (hardened push) + S-DEMO-1 (apply)  
- [ ] S-FALCO-1 або S-NP-1  
- [ ] Усі скріни підписані одним реченням контексту  

---

## Як перенести в Google Docs

1. Створи документ, застосуй **Заголовок 1 / 2 / 3** як у структурі вище.  
2. Скопіюй текст з **`docs/submission_report.md`** (або переклади українською — як вимагає курс).  
3. Вставляй **Вставка → Зображення → Завантажити з комп’ютера** для кожного скріну під відповідним підрозділом; у **Додати опис** можна вказати ID (наприклад `S-CB-1`).  
4. Для команд використовуй **моноширинний** шрифт (Format → Text → Courier New або Consolas).  
5. Експорт: **Файл → Завантажити → PDF** (якщо здача у PDF).

---

## Зв’язок з іншими файлами репозиторію

| Файл | Призначення |
|------|-------------|
| `docs/submission_report.md` | Чернетка тексту звіту (EN) |
| `docs/github_actions_runbook.md` | Порядок GitHub/GCP, секрети, drift GKE |
| `docs/architecture_and_stack.md` | Детальніша архітектура |
| `docs/logging_pipeline.md` | Логи → BigQuery → парсер |
| `README.md` | Секрети `GCP_PROJECT_ID`, Cloud Build |

Якщо файлів `evidence_gcp_runs.md` / `evidence_checklist.md` у твоїй копії немає — усі потрібні кроки для Cloud Build зібрані **в таблицях вище** (S-CB-* та S-BQ-*).
