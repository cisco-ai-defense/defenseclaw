# Local observability fixture

A docker-compose bundle that brings up Collector → Prometheus + Loki + Tempo + Grafana for `skills.observability.otlp.*` and `stories.local-observability.*` cases.

Before running:

1. Edit `grafana-admin-password.txt` and set a strong password. **Do not** commit your edit.
2. `docker compose up -d`
3. Grafana lands on `http://127.0.0.1:3000` (admin / your password).
4. Configure DefenseClaw to ship OTLP to `127.0.0.1:4317` or `:4318`.
5. When done, `docker compose down`.

The Grafana admin password is read from a Docker secret pointing to `grafana-admin-password.txt`. The file is gitignored by `.gitignore.rules` below; if you commit your edit by accident, rotate immediately and update the fixture.

Containers run with `cap_drop: [ALL]`, `read_only: true` (where applicable), and `no-new-privileges`. They do NOT mount the Docker daemon socket.
