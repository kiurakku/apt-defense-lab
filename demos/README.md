# Demos (optional)

- **`cgroup_escape_trace_stub.go`** — мінімальна Go-програма з виводом етапів (не експлойт і не частина Kubernetes). **Не використовуйте як основний доказ для рецензента:** для CVE-2022-0492 потрібен аналіз **`kernel/cgroup/cgroup-v1.c`** у дереві **torvalds/linux** (див. `docs/evidence_upstream_kernel_and_k8s_uk.md`).

Запуск (локально, якщо встановлено Go):

```bash
go run demos/cgroup_escape_trace_stub.go
```

Очікуваний вивід показує гілку **cgroup v2 → abort**, узгоджену з `exploits/container_escape/escape.sh`.
