# Logging pipeline: BigQuery E2E

## Що є в репозиторії

1. **Terraform** (`terraform/logging.tf`) створює **Log Router sink** `trivy-operator-bq-sink-tf` у BigQuery dataset `trivy_logs` з фільтром по `k8s_container` і label `app.kubernetes.io/name=trivy-operator`.
2. Cloud Logging **автоматично** створює таблиці в dataset’і зі **схемою Cloud Logging** (не ручна `raw_compressed_logs` schema). Таблиці зазвичай мають вигляд на кшталт `cloudaudit_*` або датовані партиції з полем `log_id`, `resource`, `jsonPayload`, `textPayload`, `timestamp`.
3. Таблиця **`raw_compressed_logs`** (ручна схема) усе ще може використовуватися для **лабораторного парсера** з `scripts/parse_trivy_bq.py`, якщо ви **заповнюєте** її з ETL (наприклад, Scheduled Query з `jsonPayload` або окремий Cloud Function).

## Як подивитися реальну схему таблиць після sink

```bash
bq ls --project_id=PROJECT_ID DATASET_ID
bq show --format=prettyjson PROJECT_ID:DATASET_ID.TABLE_ID
```

Або в консолі: **BigQuery → dataset → table → Schema**.

## Приклад: витягнути один рядок логу з авто-таблиці

Після `terraform apply` знайдіть ім’я таблиці, куди пишеться sink (наприклад `*_trivy_*` або `*_k8s_*`), і виконайте:

```sql
SELECT timestamp, log_name, resource, jsonPayload, textPayload
FROM `PROJECT_ID.trivy_logs.<AUTO_TABLE_NAME>`
ORDER BY timestamp DESC
LIMIT 5;
```

## Парсер `parse_trivy_bq.py`

- **`--from-sink`** (рекомендовано): сканує **авто-таблиці** експорту Logging (усі таблиці в dataset, крім `raw_compressed_logs` / `clean_vulnerabilities`), шукає у рядках рядки схожі на base64(gzip(JSON)), декодує та заповнює **`clean_vulnerabilities`** без проміжного ETL.
- Без `--from-sink`: читає **`raw_compressed_logs`.`log_data`** (лабораторний шлях).

## Доказ E2E

- CLI: `python scripts/parse_trivy_bq.py --project PROJECT_ID --dataset trivy_logs --from-sink --limit 50`
- Додатково для діагностики: `python scripts/bq_sink_inspect.py --project PROJECT_ID --dataset trivy_logs` (схема + sample row).
- Скріншот BigQuery: авто-таблиця sink + preview `clean_vulnerabilities` після парсера.
