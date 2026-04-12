# Logging pipeline: BigQuery E2E

Див. також **[README.md](README.md)** (індекс документації) та кореневий **README**.

## Що є в репозиторії

1. **Terraform** (`terraform/logging.tf`) створює **Log Router sink** `trivy-operator-bq-sink-tf` у BigQuery dataset `trivy_logs` з фільтром по `k8s_container` і label `app.kubernetes.io/name=trivy-operator`.
2. Cloud Logging **автоматично** створює таблиці в dataset’і зі **схемою Cloud Logging** (не ручна `raw_compressed_logs` schema). Таблиці зазвичай мають вигляд на кшталт `cloudaudit_*` або датовані партиції з полем `log_id`, `resource`, `jsonPayload`, `textPayload`, `timestamp`.
3. Таблиця **`raw_compressed_logs`** (ручна схема) усе ще може використовуватися для **парсера** з `scripts/parse_trivy_bq.py`, якщо **заповнюєте** її з ETL (наприклад, Scheduled Query з `jsonPayload` або окремий Cloud Function).

## Як подивитися схему таблиць після sink

```bash
bq ls --project_id=PROJECT_ID DATASET_ID
bq show --format=prettyjson PROJECT_ID:DATASET_ID.TABLE_ID
```

Або в консолі: **BigQuery → dataset → table → Schema**.

## Парсер `parse_trivy_bq.py`

- **`--from-sink`** (рекомендовано): обирає sink-таблицю (за можливості ту, де є рядки з **довгим base64-подібним** `textPayload`), декодує кожен кандидат як **base64 → gzip → JSON** і заповнює **`clean_vulnerabilities`**. Раніше зшивались усі рядки логу підряд — через це в BigQuery «виглядало все незжатим» (INFO/Downloading змішувались із звітом).
- Без `--from-sink`: читає **`raw_compressed_logs`.`log_data`** (додатковий шлях у тестовому завданні).

## Чому в Preview часто видно plain `textPayload`

Потік **stderr** Trivy містить багато **читабельних** рядків (завантаження DB тощо). **Gzip+base64** звіту про CVE з’являється в **інших** рядках — шукайте довгі послідовності `[A-Za-z0-9+/]{96+,}` у `textPayload` або використовуйте `scripts/bq_sink_inspect.py` (автовибір такого рядка). Детальніше: **`docs/reviewer_addendum_bq_and_exploits_uk.md`**.

## Доказ E2E

- CLI: `python scripts/parse_trivy_bq.py --project PROJECT_ID --dataset trivy_logs --from-sink --limit 50`
- Додатково для діагностики: `python scripts/bq_sink_inspect.py --project PROJECT_ID --dataset trivy_logs` (схема + sample row).
- Скріншот BigQuery: авто-таблиця sink + preview `clean_vulnerabilities` після парсера.
