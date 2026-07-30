# Local observability bundle

Operator setup, commands, dashboards, retention, and troubleshooting live in
the
[published local-observability guide](https://cisco-ai-defense.github.io/defenseclaw/docs/observability/local-observability/).
The [Grafana catalog](https://cisco-ai-defense.github.io/defenseclaw/docs/observability/grafana-dashboards/)
and [Agent360 guide](https://cisco-ai-defense.github.io/defenseclaw/docs/observability/agent360/)
describe the user-visible dashboard behavior.

This directory is the source bundle copied into an installed DefenseClaw
deployment. It defines one Compose project with five services:

| Service | Role |
| --- | --- |
| `otel-collector` | Receives OTLP gRPC/HTTP and fans out logs, metrics, and traces |
| `prometheus` | Metrics storage, recording rules, and alert evaluation |
| `loki` | Log storage |
| `tempo` | Trace storage |
| `grafana` | Provisioned datasources and dashboards |

All published host ports are loopback-bound by default in
[`docker-compose.yml`](docker-compose.yml). Raw Compose use can override the
bind address, so it is not equivalent to the managed CLI's loopback safety
checks.

## Source ownership

- [`otel-collector/config.yaml`](otel-collector/config.yaml): collector
  receivers, processors, and exporters.
- [`prometheus/prometheus.yml`](prometheus/prometheus.yml): scrape and rule
  loading.
- [`prometheus/rules/recording.yml`](prometheus/rules/recording.yml): dashboard
  recording rules.
- [`prometheus/rules/alerts.yml`](prometheus/rules/alerts.yml): alerts whose
  runbook URLs point to the canonical website.
- [`loki/loki.yaml`](loki/loki.yaml) and [`tempo/tempo.yaml`](tempo/tempo.yaml):
  local storage configuration.
- [`grafana/provisioning/`](grafana/provisioning/): datasource and dashboard
  provisioning.
- [`grafana/dashboards/`](grafana/dashboards/): the fourteen shipped dashboard
  JSON definitions.
- [`bin/openclaw-observability-bridge`](bin/openclaw-observability-bridge):
  low-level bundle controller; [`run.sh`](run.sh) is its compatibility shim.

Installed-stack refresh and rollback are implemented by the release upgrade
code, not by this README. Managed files may be replaced by a target release;
named data volumes and operator-only files are preserved by that transaction.

## Contributor verification

Run the static bundle/dashboard gate from the repository root:

```bash
python scripts/check_grafana_dashboards.py --require-packaged
```

The optional `--live --inventory` mode requires a running local stack and
checks the provisioned services and dashboards. Alert response procedures are
the
[published runbooks](https://cisco-ai-defense.github.io/defenseclaw/docs/observability/#alert-runbooks).
