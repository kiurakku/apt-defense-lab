# Demos (optional)

- **`cgroup_escape_trace_stub.go`** — мінімальна Go-програма з виводом етапів і «змінних» для пояснення логіки (не експлойт і не частина Kubernetes).

Запуск (локально, якщо встановлено Go):

```bash
go run demos/cgroup_escape_trace_stub.go
```

Очікуваний вивід показує гілку **cgroup v2 → abort**, узгоджену з `exploits/container_escape/escape.sh`.
