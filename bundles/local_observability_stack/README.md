# DefenseClaw Local Observability Stack

End-to-end OTLP downstream so you can point a locally-running
DefenseClaw sidecar at a real collector, real metrics store, real log
store, real trace store, and a pre-provisioned Grafana — all on
loopback, all driven by `docker compose`.

```
┌──────────────────┐   OTLP gRPC/HTTP   ┌──────────────────┐
│ defenseclaw      │ ─────────────────► │ otel-collector   │
│ (cmd/defenseclaw)│                    └─┬─────┬─────┬────┘
└──────────────────┘           traces ────┘  metrics└──┐ logs
                              to Tempo  to Prometheus   └─► Loki
                                │           │               │
                                ▼           ▼               ▼
                              ┌────────────────────────────────┐
                              │           Grafana              │
                              │  http://localhost:3000         │
                              └────────────────────────────────┘
```

## Quick start

The recommended path boots the stack, waits for readiness, and writes
the `otel:` block in `~/.defenseclaw/config.yaml` automatically:

```bash
defenseclaw setup local-observability up
defenseclaw gateway                            # reads config.yaml
defenseclaw setup local-observability status   # compose ps + readiness probes
```

Use the existing CLI with `--no-config` when another preset owns the `otel:`
block or a CI job must avoid configuration side effects:

```powershell
defenseclaw setup local-observability up --no-config
defenseclaw setup local-observability env --json
```

The historical `run.sh` and extensionless POSIX entry point remain
compatibility shims into this same Python controller for macOS/Linux users.

Grafana is provisioned with four datasources (Prometheus, Loki, Tempo,
and a `Prometheus-Alerts` Alertmanager-shim that surfaces the rules in
`prometheus/rules/alerts.yml`) and a tagged dashboard pack under
**Dashboards → Browse → `defenseclaw`**:

| Dashboard | Audience | What to watch for |
|---|---|---|
| **Overview** | on-call landing | alerts, SLO gauges, guardrail outcomes, findings, and canonical errors |
| **Agent Activity (Live)** | developers / IR | cross-agent prompts, model usage, tools, destinations, and session correlation |
| **Agent identity** | governance / IR | logical agents, runtime instances, discovery confidence, and Agent360 links |
| **Agent360** | developers / SOC | one agent tree's lifecycle, tools, tokens, decisions, recovery, topology, and traces |
| **AI Agent Usage & Detection** | security / governance | active AI signals, detector health, confidence, vendor/product inventory, and scan traces |
| **Hook Connectors** | platform | connector traffic, latency, evaluation outcomes, silence, and drift |
| **Connector Detail** | connector developers | one connector's hook phases, model activity, findings, and recent events |
| **Guardrail Evaluations** | security / IR | allow/alert/confirm/block funnel, severity, latency, and judge reliability |
| **Policy decisions** | governance | evaluated tools, observe-mode would-blocks, URL destinations, and policy events |
| **HITL** | security / governance | hook confirmations plus chat/execution approval outcomes when those modes are active |
| **Findings** | detection engineers | per-rule incidence, first/last seen, target attribution, and verdict correlation |
| **Scanners (Ops)** | scanner developers / SRE | rolling scan counts and duration, findings, quarantine, and scanner errors |
| **Proxy & LLM Guard** | proxy operators | HTTP/tool/admission/LLM telemetry when proxy/router mode is active |
| **Runtime & Reliability** | SRE | process, SQLite, hook SLOs, exporter health, audit delivery, schema violations, and panics |

All dashboards cross-link via the "Dashboards" dropdown on the Overview,
and the `ALERTS{alertstate="firing"}` annotation overlay is enabled on
the Overview so you can see when a page fired against the data you're
looking at.

### Metric naming convention

The OTel SDK emits metrics like `defenseclaw.scan.duration` (unit `ms`).
Prometheus exposes them as `defenseclaw_scan_duration_milliseconds_*`
(dots → underscores, unit expanded to its long form, `_total` appended
to counters). Recording rules in `prometheus/rules/recording.yml`
pre-aggregate the most-used queries so dashboards remain snappy.

## Alerts

Alert rules live in
[`prometheus/rules/alerts.yml`](prometheus/rules/alerts.yml) and are
mounted read-only into the Prometheus container; recording rules live
next to them in `recording.yml`. Alerts fall into five groups — each
rule has a `summary`, a `description` that tells you which dashboard to
open, and where relevant a `runbook` pointer under
`docs/OBSERVABILITY-CONTRACT.md#runbook-*`.

| Group                       | Example alerts | Severity |
|-----------------------------|----------------|----------|
| `defenseclaw.correctness`   | `DefenseClawSchemaViolations`, `DefenseClawGatewayErrorsSpike`, `DefenseClawPanic` | critical / warning |
| `defenseclaw.slo.alerts`    | `DefenseClawBlockSLOBreach`, `DefenseClawTUIRefreshSLOBreach` | critical / warning |
| `defenseclaw.pipeline`      | `DefenseClawOTLPExporterStalled`, `DefenseClawAuditSinkFailures`, `DefenseClawAuditSinkCircuitOpen` | critical / warning |
| `defenseclaw.security`      | `DefenseClawBlockRateSpike`, `DefenseClawJudgeErrorRate`, `DefenseClawWebhookFailuresSustained` | warning |
| `defenseclaw.traffic`       | `DefenseClawHTTP5xxSpike`, `DefenseClawHTTPAuthFailuresSurge`, `DefenseClawRateLimitSurge` | warning |
| `defenseclaw.runtime`       | `DefenseClawGoroutineLeak`, `DefenseClawSQLiteBusyRetries`, `DefenseClawConfigLoadErrors` | warning |
| `defenseclaw.connectors`    | `DefenseClawConnectorHookErrorRate`, `DefenseClawConnectorAgentIdChurn` | warning |
| `defenseclaw.ai_discovery`  | `DefenseClawAIDiscoveryStalled`, `DefenseClawAIDiscoveryDetectorErrors` | warning |
| `defenseclaw.observability_pipeline` | `DefenseClawLokiIngestOverflow` | warning |

Rules are owned by Prometheus (so they keep firing even if Grafana is
down). Grafana reads them through the `Prometheus-Alerts` Alertmanager
datasource, which makes them visible under **Alerting → Alert rules**
and through the **Firing alerts** table on the Overview dashboard.

To iterate locally:

```bash
# Edit rules
$EDITOR prometheus/rules/alerts.yml
# Reload Prometheus in place (config.reload is enabled)
curl -X POST http://localhost:9090/-/reload
# Check the parser / current evaluation state
curl -s http://localhost:9090/api/v1/rules | jq '.data.groups[].name'
```

To pipe alerts to Slack / PagerDuty / Opsgenie, drop a standard
`alertmanager` service into `docker-compose.yml`, point Prometheus at
it via `alerting.alertmanagers` in `prometheus.yml`, and reuse the
existing labels (`severity`, `surface`, `slo`) for routing.

## Runtime schema validation

In parallel with this stack, `gatewaylog.Writer` runs a **strict JSON
Schema validator** against every event it emits. Violations are dropped
from the sinks, surface as an `EventError(subsystem=gatewaylog,
code=SCHEMA_VIOLATION)`, and increment
`defenseclaw_schema_violations_total`. The panel "Schema violations /
min" on the dashboard is the canary for contract drift.

To disable validation locally (e.g. when iterating on a new event
type), set `DEFENSECLAW_SCHEMA_VALIDATION=off` before starting the
sidecar.

## Services

| Service          | Host port(s)       | Notes                                                       |
|------------------|--------------------|-------------------------------------------------------------|
| `otel-collector` | 4317, 4318, 8888 | OTLP gRPC (4317), OTLP HTTP (4318), self-telemetry (8888) |
| `prometheus`     | 9090             | Scrapes collector self-metrics and receives application metrics by remote write |
| `loki`           | 3100               | Receives logs via OTLP HTTP                                 |
| `tempo`          | 3200, 9095         | HTTP query (3200), gRPC (9095). Traces enter via the collector on 4317 |
| `grafana`        | 3000               | admin / admin; anon Viewer role enabled (loopback only)     |

## Teardown

```bash
defenseclaw setup local-observability down     # stop containers, keep data
defenseclaw setup local-observability reset    # stop + drop all volumes
```

The standard lifecycle commands remain:

```powershell
defenseclaw setup local-observability down
defenseclaw setup local-observability reset --yes
```

## Notes

- All services are unconditionally bound to loopback. The certified bundle has
  no environment variable that can widen exposure. Maintain a separate,
  independently secured Compose override if you need remote access.
- The collector's `debug` exporter is on for every pipeline. Tail
  `./run.sh logs otel-collector` to watch raw OTLP frames while
  iterating on the sidecar contract.
- `reset` requires explicit confirmation and deletes only volumes whose labels
  prove ownership by the named `defenseclaw-observability` Compose project.
