# Звіт: apt-defense-lab (технічне тестове завдання DevSecOps)

**Інструкція для Google Docs:** Файл → Імпортувати або вставити вміст; застосуйте стилі «Заголовок 1» до рядків `#`, «Заголовок 2» до `##`.

## Титульні дані

| Поле | Значення |
|------|----------|
| Автор | (вкажіть ім’я) |
| Дата | 10.04.2026 |
| GCP Project ID | devsecopstests |
| Репозиторій | https://github.com/kiurakku/apt-defense-lab |
| Посилання на Google Doc | (вставте посилання з доступом «Anyone with the link») |

---

## 1. Executive Summary

Побудовано ізольоване технічне тестове середовище в GCP (лише **GKE Standard**) для демонстрації сценарію на кшталт APT: вихід за межі контейнера, деградація доступу до API сервера кластера, підготовка активності в `/tmp`, зворотні з’єднання на типові порти C2, а також зловживання **Workload Identity Federation (WIF)** у GitHub Actions.

**Охоплені області:**

1. **Container escape** — PoC для класу CVE-2022-0492 (узгоджено з бюлетенями GKE).
2. **Control-plane stress** — масове створення об’єктів API для демонстрації деградації `kubectl` / планувальника.
3. **Trivy → BigQuery** — оператор Trivy, стислі звіти (gzip→base64 у транспорті), Log Router sink у BigQuery, парсер у таблицю `clean_vulnerabilities`.
4. **Вразливий CI** — `terraform plan` на PR з WIF до `cicd-lab-sa`; поряд захищений шлях (`main` → `cicd-plan-sa`, контрольований apply → `cicd-apply-sa` та demo bucket).

**Захист:** Falco (кастомні правила), NetworkPolicy (default-deny egress + allowlist), WIF замість JSON-ключів сервісних акаунтів, Shielded nodes на `hardened-pool`.

**Стек з ТЗ:** повний ELK не розгортався; телеметрія — **Cloud Logging → BigQuery** та Falco.

**Докази:** скріншоти за розділами нижче; детальні інструкції по кожному ID — `docs/google_docs_submission_guide_uk.md`.

---

## 2. Огляд інфраструктури

- **Кластер:** `lab-cluster` (GKE Standard).
- **Node pools:** `vulnerable-pool` (старіший образ для демо ризиків); `hardened-pool` (Shielded VM).
- **BigQuery:** dataset `trivy_logs` (sink, `clean_vulnerabilities`, `raw_compressed_logs`, керовані таблиці експорту).
- **Сервісні акаунти:** `trivy-sa` (WI); `cicd-lab-sa` / `cicd-plan-sa` / `cicd-apply-sa` (GitHub WIF); `cloudbuild-deployer` (Cloud Build).

### 2.1 Скріншоти інфраструктури

| ID | Що показати | Де взяти |
|----|-------------|----------|
| **S-GKE-1** | Кластер `lab-cluster`, обидва пули | GKE → Clusters → NODE POOLS |
| **S-BQ-1** | Dataset `trivy_logs`, список таблиць | BigQuery → Explorer |

---

## 3. Task 1. Container escape та навантаження на API

Окремий локальний minikube/kind у ТЗ не обов’язковий; «старіша» конфігурація — **окремий node pool** на GKE. Для демонстрації механіки PoC локально можна використати **kind/minikube** (ізольоване середовище).

### 3.1 Container escape (CVE-2022-0492)

- **PoC:** `exploits/container_escape/escape.sh` (у виводі є мітки `[DEMO]`).
- **S-ESC-1:** термінал з результатом скрипта (успіх або блок, наприклад cgroup v2).

### 3.2 Control-plane stress

- **Скрипт:** `exploits/master_plane_crash/dos_apiserver.sh` (`COUNT`, `[DEMO]` у логах).
- **S-DOS-1 / S-DOS-2:** фрагмент виконання та/або `time kubectl get nodes` до/після.

---

## 4. Task 2. Terraform, Cloud Build, Trivy, BigQuery

Terraform: кластер, BQ, sink, WIF, IAM для Cloud Build. Робочі навантаження в кластері — **Cloud Build** (`cloudbuild/cloudbuild.yaml` → образ `lab-ci/ci-deploy`, далі `deploy-gke-apps.yaml`).

### 4.1 Cloud Build

| ID | Опис |
|----|------|
| **S-CB-1** | Успішний білд з `cloudbuild/cloudbuild.yaml` (образ `ci-deploy`) |
| **S-CB-2** | Успішний білд з `deploy-gke-apps.yaml` (Helm Trivy/Falco, NetworkPolicy) |
| **S-CB-3** (опц.) | `run-trivy-parser.yaml` або вивід парсера |

### 4.2 Trivy: компресія та BigQuery

**Формат звіту:** JSON → **gzip** → **base64** у транспорті; у парсері — `decode_blob` (base64 → розпакування → JSON). У ConfigMap оператора: `scanJob.compressLogs: "true"`.

**Чому в BigQuery інколи видно «незжатий» текст у `textPayload`:** у потік **stderr** потрапляють **звичайні** рядки логера Trivy (`INFO`, завантаження Trivy DB) — вони **не** gzip. Це **не** означає, що компресія вимкнена: **звіт CVE** потрапляє в **інші** записи логів, де `textPayload` містить **довгу** послідовність символів base64 (транспорт gzip+json).

**Інструменти в репозиторії (оновлено за зауваженням рецензента):**

- `scripts/bq_sink_inspect.py` — обирає таблицю/рядок із довгим base64-подібним вмістом для скріну **[S-BQ-3]**; компактна схема за замовчуванням (`--full-schema` — повна).
- `scripts/parse_trivy_bq.py --from-sink` — **не зшиває** усі рядки підряд; декодує кандидатів base64(gzip(JSON)) окремо.

**Команди перевірки:**

```bash
python scripts/bq_sink_inspect.py --project devsecopstests --dataset trivy_logs
python scripts/parse_trivy_bq.py --project devsecopstests --dataset trivy_logs --from-sink --limit 20000 -v
```

| ID | Що зняти |
|----|----------|
| **S-TRIVY-1** | `kubectl get cm trivy-operator-config -n trivy-system -o yaml` — `scanJob.compressLogs: "true"` |
| **S-BQ-3** | Рядок sink з довгим base64 у `textPayload` або вивід `bq_sink_inspect.py` |

### 4.3 Парсер BigQuery (`scripts/parse_trivy_bq.py`)

У звіті варто вставити **фрагменти коду** (або посилання на репозиторій): функції **`decode_blob`**, **`run_from_sink`**, **`_extract_encoded_candidates`**.

Очікуваний рядок у логу після успішного прогону: `Inserted N rows into … clean_vulnerabilities`.

| ID | Що зняти |
|----|----------|
| **S-BQ-2** | Preview таблиці `clean_vulnerabilities` (CVE, severity, пакет) |

### 4.4 Відповідь рецензенту: експлойти та «відладчик Kubernetes»

**BigQuery / компресія та експлойти:** див. **Додаток B** нижче (повний текст відповіді рецензента). У скриптах експлойтів — вивід **`[DEMO]`**; опційно **`demos/cgroup_escape_trace_stub.go`**.

**Що свідомо не входить у обсяг лабораторії:** повна перекомпіляція вихідного коду Kubernetes з підключенням **dlv** до `kube-apiserver` — окремий великий проєкт; у звіті достатньо посилань на бюлетені GKE, анотовані скрипти та цей абзац.

---

## 5. Task 3. GitHub Actions і WIF

- **Вразливий шлях:** `vulnerable-tf-plan.yml` на `pull_request` → pool **lab** → `cicd-lab-sa`.
- **Захищений план:** `hardened-tf-plan.yml` на push у `main` → pool **prod** → `cicd-plan-sa`.
- **Контрольований write:** `hardened-tf-apply.yml` (`workflow_dispatch`) → `cicd-apply-sa` → лише об’єкт у demo bucket (`demo-write-proof.txt`).

**Секрети GitHub:** `GCP_PROJECT_ID`, `WIF_PROVIDER_LAB`, `WIF_PROVIDER_PROD`, `CICD_*_SA_EMAIL`, `TF_STATE_BUCKET`, `DEMO_IMPACT_BUCKET` (див. README).

### 5.1 Скріншоти

| ID | Опис |
|----|------|
| S-GH-1 | `vulnerable-tf-plan` на PR |
| S-GH-2 | `hardened-tf-plan` на push у main |
| S-GH-3 | `hardened-tf-apply` (workflow_dispatch) |
| S-GH-4 | Успішний крок Authenticate to Google Cloud |
| S-DEMO-1 | Об’єкт `demo-write-proof.txt` у bucket з `terraform output demo_impact_bucket` |

---

## 6. Захисні засоби: Falco та NetworkPolicy

- **Falco:** правила на запис у `/tmp` (у т.ч. magic filename) та підозрілий egress (C2-порти) — `k8s/falco/values.yaml`.
- **NetworkPolicy:** `scripts/apply_network_policies.sh`.

| ID | Опис |
|----|------|
| S-FALCO-1 | Лог Falco після тестової події |
| S-NP-1 | `kubectl get networkpolicy -A` |

---

## 7. Висновок

Найвищий ризик у сценарії — **порушення довіри CI/CD** (WIF на PR без суворих `attribute_condition`). Falco, NetworkPolicy, оновлення GKE та суворіший WIF знижують ризик у продакшені.

**Посилання:** [GKE Security Bulletins](https://cloud.google.com/kubernetes-engine/security-bulletins).

---

## Додаток A. Чекліст скріншотів

- S-GKE-1, S-BQ-1  
- S-ESC-1 або S-DOS-1  
- S-CB-1, S-CB-2, S-TRIVY-1, S-BQ-2  
- опційно: S-BQ-3, S-CB-3  
- S-GH-1 … S-DEMO-1  
- S-FALCO-1 або S-NP-1  

Не показувати повні OIDC URL, ключі SA, повні access token.

---

## Додаток B. Текст відповіді рецензенту (BigQuery + експлойти)

*(Нижче — текст відповіді рецензента для копіювання в Google Doc.)*

### B.1 Чому в BigQuery у textPayload видно «незжатий» текст

**Коротко:** `scanJob.compressLogs: true` стосується **формату звіту про вразливості** (JSON → gzip → base64) у шляху оператора. У **stderr/stdout** у Cloud Logging одночасно потрапляють **звичайні** рядки логера (`INFO`, завантаження Trivy DB) — вони **не** gzip.

**Рядок на кшталт** `"2026-… INFO [vulndb] Downloading artifact…"` — **очікуваний** шум, а не звіт CVE.

**Де шукати стиснений транспорт:** записи, де `textPayload` містить **довгу** послідовність base64 — це **base64(gzip(JSON))** (див. `decode_blob` у `parse_trivy_bq.py`).

**Зміни в репозиторії:** `parse_trivy_bq.py --from-sink` більше не зшиває всі рядки підряд; `bq_sink_inspect.py` обирає рядок для демонстрації base64.

**Команди:**

```text
python scripts/bq_sink_inspect.py --project PROJECT_ID --dataset trivy_logs
python scripts/parse_trivy_bq.py --project PROJECT_ID --dataset trivy_logs --from-sink -v
```

### B.2 Експлойти, локальний K8s, відладчик

У `escape.sh` та `dos_apiserver.sh` додано етапи **`[DEMO]`**; опційно **`demos/cgroup_escape_trace_stub.go`**.

**Не входить у обсяг типового ТЗ без окремого завдання:** форк **kubernetes/kubernetes**, `klog` у ядрі оркестратора, **dlv** на реальному `kube-apiserver`.

**Код демо:** `exploits/container_escape/escape.sh`, `exploits/master_plane_crash/dos_apiserver.sh`, `exploits/container_escape/escape-pod.yaml`.

---

*Кінець документа.*
