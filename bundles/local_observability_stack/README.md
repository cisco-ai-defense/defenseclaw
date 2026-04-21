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

Raw compose access (identical container outcome, no CLI side-effects on
`config.yaml` — use in CI or when another preset owns the `otel:` block):

```bash
cd bundles/local_observability_stack
./bin/openclaw-observability-bridge up         # or ./run.sh up (compat shim)
eval "$(./bin/openclaw-observability-bridge env)"
go run ./cmd/defenseclaw gateway
```

Grafana is provisioned with four datasources (Prometheus, Loki, Tempo,
and a `Prometheus-Alerts` Alertmanager-shim that surfaces the rules in
`prometheus/rules/alerts.yml`) and a tagged dashboard pack under
**Dashboards → Browse → `defenseclaw`**:

| Dashboard                       | Audience            | What to watch for |
|---------------------------------|---------------------|-------------------|
| **Overview**                    | on-call landing     | `ALERTS` table, SLO gauges, health stats, Loki tail |
| **Security**                    | security eng / IR   | verdict mix, judge latency + errors, redactions, GenAI tokens |
| **Scanners**                    | platform / scanner devs | scan rate + p95 latency per scanner, findings by severity/rule, quarantine, queue |
| **Reliability**                 | SRE / reliability   | gateway errors by code, sink health + circuit state, webhooks, panics, config errors |
| **Runtime & SLO**               | SRE                 | goroutines, heap, GC, SQLite size/WAL/busy, block-<2s + TUI-<5s SLO compliance, exporter freshness |
| **Traffic & Traces**            | perf / integration  | HTTP RPS + 5xx ratio per route, SSE lifecycle, tool calls, LLM bridge / Cisco Inspect latency, Tempo search |

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
| `defenseclaw.slo`           | `DefenseClawBlockSLOBreach`, `DefenseClawTUIRefreshSLOBreach` | critical / warning |
| `defenseclaw.pipeline`      | `DefenseClawOTLPExporterStalled`, `DefenseClawAuditSinkFailures`, `DefenseClawAuditSinkCircuitOpen` | critical / warning |
| `defenseclaw.security`      | `DefenseClawBlockRateSpike`, `DefenseClawJudgeErrorRate`, `DefenseClawWebhookFailuresSustained` | warning |
| `defenseclaw.traffic`       | `DefenseClawHTTP5xxSpike`, `DefenseClawHTTPAuthFailuresSurge`, `DefenseClawRateLimitSurge` | warning |
| `defenseclaw.runtime`       | `DefenseClawGoroutineLeak`, `DefenseClawSQLiteBusyRetries`, `DefenseClawConfigLoadErrors` | warning |

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

| Service          | Port       | Notes                                           |
|------------------|------------|-------------------------------------------------|
| `otel-collector` | 4317/4318  | OTLP gRPC + HTTP receivers                      |
| `prometheus`     | 9090       | Scrapes collector, receives remote-write        |
| `loki`           | 3100       | Receives logs via OTLP HTTP                     |
| `tempo`          | 3200/4317  | Receives traces via OTLP                        |
| `grafana`        | 3000       | admin / admin; anon Viewer role enabled         |

## Teardown

```bash
defenseclaw setup local-observability down     # stop containers, keep data
defenseclaw setup local-observability reset    # stop + drop all volumes
```

Equivalent raw invocations (same container outcome):

```bash
./bin/openclaw-observability-bridge down       # or ./run.sh down
./bin/openclaw-observability-bridge reset      # or ./run.sh reset
```

## Notes

- All services are bound to loopback only — safe on multi-tenant dev
  boxes but won't be reachable from another host. Replace `127.0.0.1`
  with `0.0.0.0` in `docker-compose.yml` if you need remote access.
- The collector's `debug` exporter is on for every pipeline. Tail
  `./run.sh logs otel-collector` to watch raw OTLP frames while
  iterating on the sidecar contract.
- No persistence contract: `./run.sh reset` is non-destructive to the
  rest of your system but wipes every metric / log / trace you've
  captured.
