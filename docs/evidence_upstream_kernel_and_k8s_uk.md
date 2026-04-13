# Докази для рецензента: upstream Linux / Kubernetes (без «демо-заглушок»)

Цей файл — **покрокова інструкція**, як виконати вимоги щодо **реальних репозиторіїв** (`torvalds/linux`, `kubernetes/kubernetes`) і що саме заскрінити для Google Doc. Скрипти в `exploits/` лишаються **лабораторними PoC**; для звіту потрібні **фрагменти коду з upstream** і **інструменти відладки** на цих джерелах.

---

## 1. Стислий gzip-транспорт Trivy у BigQuery [S-BQ-3]

**Чому рецензент міг не побачити gzip:** у потік логів потрапляють і звичайні рядки (`INFO`, завантаження БД Trivy), і окремі записи з **довгим base64** — це вже **gzip(JSON)** у транспорті.

**Що зробити в кластері**

1. Увімкнути компресію для scan job (у цьому репозиторії це робить скрипт, який патчить ConfigMap оператора):

   ```bash
   bash scripts/configure_trivy_log_compression.sh
   ```

2. Переконатися:

   ```bash
   kubectl get cm trivy-operator-config -n trivy-system -o yaml | findstr compressLogs
   ```

   Очікується `scanJob.compressLogs: "true"` (скрін **S-TRIVY-1**).

**Що зняти для звіту**

- У **BigQuery** (або вивід `python scripts/bq_sink_inspect.py --project PROJECT --dataset trivy_logs`): рядок, де `textPayload` починається з **`H4sI`** (магія gzip у base64) або довга base64-рядкова послідовність без префікса `INFO`.
- Підпис до скріну: *«Запис sink: сирий транспорт звіту CVE — gzip, закодований у base64 у textPayload (не текстовий лог рівня INFO)»*.

**Неправильна порада з чат-ботів:** вигадані ключі на кшталт `stdoutReport: true` у `values.yaml` для chart 0.32.1 — у **цьому** репозиторії використовується **`scanJob.compressLogs`** у ConfigMap `trivy-operator-config` (див. `scripts/configure_trivy_log_compression.sh` і коментар у `k8s/trivy-operator/values.yaml`).

---

## 2. CVE-2022-0492: анотація коду **ядра Linux** і відладка

**Офіційний опис:** [CVE-2022-0492](https://nvd.nist.gov/vuln/detail/CVE-2022-0492) — обхід ізоляції через механізм cgroup v1 `release_agent` (деталі — у бюлетенях дистрибутивів і ядра).

**Робота з оригінальним деревом ядра**

1. Клонувати **Linux** (достатньо shallow):

   ```bash
   git clone --depth 1 --branch v5.16 https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git linux-stable
   ```

   (Або гілка **до** фіксу 5.17; для читання вразливого коду зручні теги 5.16.x.)

2. Відкрити у редакторі / IDE файл:

   - **`kernel/cgroup/cgroup-v1.c`**

3. Знайти функцію **`cgroup_release_agent_write`** (запис у псевдофайл `release_agent`). Саме ланцюжок перевірок навколо запису шляху до агента релевантний до CVE-2022-0492.

**Що вставити в звіт**

- Скрін **фрагмента з upstream** (GitHub mirror: `https://github.com/torvalds/linux/blob/master/kernel/cgroup/cgroup-v1.c` — оберіть **конкретний tag commit**, щоб рядки не «попливли»).
- Власні **короткі коментарі** у стилі `// [LAB] ...` **лише у копії для звіту** (не комітити у форк ядра без потреби) або виноски в Google Doc поруч зі скріном.

**GDB / kgdb (реальна відладка, не Go-заглушка)**

- Повноцінна зупинка у **`cgroup_release_agent_write`** потребує **збірки ядра з debug symbols** або **remote kgdb** на тестовій VM — це нормальний обсяг для окремого підпункту звіту.
- Мінімально показати рецензенту **наміри**:
  - `break cgroup_release_agent_write`
  - після зупинки: `list`, `info args`, `print` буфера зі шляхом до агента
- Якщо повна збірка ядра недоступна — у тексті звіту чесно вказати: показано **статичну анотацію** upstream-коду; **динамічний** трейс виконано на рівні PoC (`escape.sh`) + `dmesg`/логи ноди **або** повний kgdb у окремому середовищі.

**Зв’язок з репозиторієм лабораторії:** `exploits/container_escape/escape.sh` — лише **скрипт для стенду**; для рецензента головне — **посилання на `cgroup-v1.c` у linux.git** і пояснення, як PoC потрапляє в `release_agent`.

---

## 3. DoS control plane: CVE з бюлетеню Google і код **Kubernetes**

### 3.1 Яку CVE вказати з [GKE Security Bulletins](https://cloud.google.com/kubernetes-engine/security-bulletins)

У бюлетенях прямо згадується **CVE-2019-11254**: відмова в обслуговуванні **kube-apiserver** через обробку запитів (для авторизованих клієнтів). Текст бюлетеню Google посилається на Kubernetes PSC і проблему класу **DoS API server**.

**Чесне уточнення для звіту:** CVE-2019-11254 стосується **шкідливих YAML-навантажень** (парсинг). Ваш лабораторний сценарій `dos_apiserver.sh` реалізує **інший**, але **типовий** для операторів ризик — **масове створення об’єктів** (`ConfigMap`), що навантажує apiserver/etcd і дає деградацію. У звіті варто написати одним реченням: *«Як ілюстрацію класу DoS control plane з бюлетеню обрано CVE-2019-11254; практичний PoC демонструє вичерпання ресурсів через API flood»*.

### 3.2 Де дивитися код у `kubernetes/kubernetes`

1. Клонувати:

   ```bash
   git clone --depth 1 --branch release-1.28 https://github.com/kubernetes/kubernetes.git
   ```

2. Для **реєстрації ConfigMap** (шлях обробки створення):

   - `pkg/registry/core/configmap/storage/storage.go`
   - загальні шари: `staging/src/k8s.io/apiserver/pkg/registry/generic/registry/store.go`

3. Для **контексту CVE-2019-11254** — обговорення та прив’язка до релізів:

   - Issue: [kubernetes/kubernetes#89535](https://github.com/kubernetes/kubernetes/issues/89535)

**Що заскрінити:** 1–2 екрани з IDE з відкритим файлом **з вашого локального клону** (видно шлях на диску + функція `Create` / стратегія ресурсу), плюс підпис, що це **upstream**, а не скрипт з `exploits/`.

**Відладчик:** підключення **dlv** до живого `kube-apiserver` у GKE **недоступне** кандидату (керований control plane). Прийнятна формула для звіту: **анотований код apiserver/registry** з клону `kubernetes/kubernetes` + **лабораторний** вимір деградації (`time kubectl get nodes` під час `dos_apiserver.sh`). Якщо є власний kind/kubeadm з локальним apiserver — тоді можна додати крок `dlv` **локально** (не вимагається текстом ТЗ, але вітається рецензентом).

---

## 4. Що **не** подавати як основний доказ

- `demos/cgroup_escape_trace_stub.go` — **не** заміна аналізу `kernel/cgroup/cgroup-v1.c`; лишається опційною ілюстрацією гілок, не «аналізом великого репо».
- Вигадані YAML-параметри Trivy з інтернет-чатів без перевірки по `helm show values` / ConfigMap оператора.

---

## 5. Чекліст відповіді рецензенту

| Вимога | Артефакт |
|--------|----------|
| Gzip-журнали Trivy | Скрін BigQuery / `bq_sink_inspect.py` — base64 gzip [S-BQ-3] |
| CVE-2022-0492 | Фрагмент `cgroup-v1.c` з linux.git + пояснення; опційно GDB/kgdb |
| Kubernetes / експлуатація | Фрагмент registry/apiserver з kubernetes/kubernetes + PoC навантаження |
| DoS + CVE з бюлетеню | Текстом: **CVE-2019-11254** + посилання на бюлетень; PoC flood як ілюстрація класу ризику |

Після оновлення Markdown перенесіть зміни у свій **`Report02-apt-defense-lab.docx`** (імпорт розділів або копіювання з `docs/Google_Doc_Report_apt-defense-lab_UK.md`).
