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

The recommended path boots the stack, waits for readiness, and creates or
updates the named `local-observability` OTLP entry under
`observability.destinations` in `~/.defenseclaw/config.yaml`:

```bash
defenseclaw setup local-observability up
defenseclaw-gateway restart                    # reload the validated config
defenseclaw setup local-observability status   # compose ps + readiness probes
```

Raw compose access (identical container outcome, no CLI side-effects on
`config.yaml` — useful in CI or when configuration is managed out of band):

```bash
cd bundles/local_observability_stack
./bin/openclaw-observability-bridge up         # or ./run.sh up (compat shim)
```

Raw bridge startup only manages the containers. Configure a v8 named OTLP
destination separately, validate it with `defenseclaw config validate`, inspect
the compiled graph with `defenseclaw observability plan`, and then restart the
gateway.

Grafana is provisioned with four datasources (Prometheus, Loki, Tempo,
and a `Prometheus-Alerts` Alertmanager-shim that surfaces the rules in
`prometheus/rules/alerts.yml`) and a tagged dashboard pack under
**Dashboards → Browse → `defenseclaw`**:

| Dashboard | Audience | What to watch for |
|---|---|---|
| **Overview** | on-call landing | alerts, SLO gauges, guardrail outcomes, findings, and canonical errors |
| **Agent Activity (Live)** | developers / IR | cross-agent prompts, model usage, tools, destinations, and session correlation |
| **Agent identity** | governance / IR | logical agents, runtime instances, discovery confidence, and Agent360 links |
| **Agent360** | developers / SOC | one agent tree's prompt-to-outcome DAG, grouped per-agent model/tool work, tokens, decisions, recovery, and traces |
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

Agent360's DAG is built from canonical Loki events and durable relationship
evidence: session creation is a separate
anchor; one per-root **Prompt inputs** node counts distinct depth-zero
`model.request` facts while the ordered/raw views retain the individual initial and
follow-up records; replayed observations deduplicate by turn, model-request,
request, operation, then occurrence ID;
root depth 0 connects through active typed `parent_of` relationships and inverse
`delegated_by` relationships; raw parent fields and trace parentage never create
lineage. Work is grouped by its owning agent. Session and durable lineage anchors
may be recovered from the prior 24 hours, with recovered edges kept only for
children active in the selected range. Repeated model
calls share one summary per owning agent, provider, and model. Repeated tool calls
share one per-agent family node: Bash, MCP, Skills, Collaboration, File edits,
Web/browser, Visual, or Task control; an unrecognized tool keeps its reported
name. Exact `collaboration.send_message` requests are excluded from the generic
Collaboration family so they appear only as message groups; other collaboration
tools remain in that family. Request records remain visible without a terminal counterpart, but their
grouped total is a request count rather than a pending-state assertion. Turn
outcomes and session/subagent terminal records remain separate. Node/edge clicks expose exact
counts, lineage provenance, and stable agent/root/parent detail, with filtered
links to the raw OTEL events behind each group. Optional session fields remain on
lifecycle, session, ordered, and raw surfaces rather than splitting stable agent
nodes.

The correlation row distinguishes durable logical events from immutable raw Loki
observations. Exact hook/proxy/native mirrors can share one logical event without
removing any source record. Relationship-change chronology shows the edge type,
typed source and target node kinds, reported/trace-exact/derived/inferred method,
active or conflict status, stable rule ID and version, confidence, and cumulative
durable evidence count. Lineage never comes from a shared trace or
span parent. Tempo remains the exact synchronous-trace drill-down, while
Prometheus retains only bounded aggregate labels and never semantic, logical,
request, turn, tool, or relationship IDs.

Update nodes are sourced only from actual `collaboration.send_message` tool
records. For each sender, `/root` and `/root/*` collapse into one
**Messages to root** node whose target agent ID resolves to the exported root;
exact task paths and calls remain in ordered/raw drill-downs. Non-root targets
remain exact groups and are not fabricated into an agent edge unless canonical
telemetry supplies the target-agent mapping. Generic compatibility events are not
treated as updates.

The dashboards do not apply an additional redaction, masking, or field-hiding
layer. DefenseClaw redacts the canonical projection before OTEL export; Grafana
displays or links every field actually received by Loki/Tempo, including content
when it is present. Removed or transformed source fields cannot be recovered in
the UI.

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
the [observability alert runbooks](../../docs/OBSERVABILITY.md#alert-runbooks).

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

The v8 telemetry registry is the canonical event, span, and metric contract.
Producers use its generated typed builders, and canonical records are validated
before destination projection and delivery. Rejected records increment
`defenseclaw_schema_violations_total`; the **Schema violations / min** panel on
Runtime & Reliability is the contract-drift canary.

There is no runtime flag that safely turns this gate off. When adding or changing
telemetry, edit `schemas/telemetry/v8/`, regenerate the owned artifacts with
`make telemetry-generate`, and verify drift with `make telemetry-check`. Update
the producer through the generated builder surface rather than bypassing the
contract.

## Services

| Service          | Host port(s)       | Notes                                                       |
|------------------|--------------------|-------------------------------------------------------------|
| `otel-collector` | 4317, 4318, 8888 | OTLP gRPC (4317), OTLP HTTP (4318), self-telemetry (8888) |
| `prometheus`     | 9090             | Scrapes collector self-metrics and receives application metrics by remote write |
| `loki`           | 3100               | Receives logs via OTLP HTTP                                 |
| `tempo`          | 3200, 9095         | HTTP query (3200), gRPC (9095). Traces enter via the collector on 4317 |
| `grafana`        | 3000               | admin / admin; anon Viewer role enabled (loopback only)     |

## DefenseClaw upgrades

`defenseclaw upgrade` refreshes an installed copy of this bundle as part of
the ordinary one-command upgrade. It validates the complete target manifest,
backs up every DefenseClaw-managed file under the upgrade backup's
`local-observability-stack/managed/` directory, and then activates the target
files as an all-or-rollback transaction.

Files that exist only in the installed stack are operator-owned and remain in
place. If an operator changes a path also shipped by DefenseClaw, the target
version replaces that managed path, records the conflict in
`refresh-backup.json`, and retains the exact previous bytes in the backup.
The four Compose named volumes (`prometheus-data`, `loki-data`, `tempo-data`,
and `grafana-data`) are never reset by upgrade. A stack that was running is
stopped with `down` (without `-v`), refreshed, restarted, and checked for
service readiness plus all fourteen dashboard UIDs.

A refresh/rollback safety failure leaves target services stopped and reports
the recovery backup. A later stack restart/readiness failure is reported as
degraded without undoing an otherwise healthy gateway upgrade; recover with
`defenseclaw setup local-observability up`.

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
  boxes but won't be reachable from another host. Override `HOST_BIND`
  in your environment (e.g. `HOST_BIND=0.0.0.0 ./run.sh up`) if you
  need remote access. Before doing so, change Grafana's default
  `admin / admin` password and disable the anonymous Viewer role —
  loopback is the only thing keeping those credentials safe.
- The collector's `debug` exporter is on for every pipeline. Tail
  `./run.sh logs otel-collector` to watch raw OTLP frames while
  iterating on the sidecar contract.
- `./run.sh reset` is explicitly destructive to local observability
  history: it leaves the rest of your system alone but wipes every
  metric, log, and trace in the four named volumes. Ordinary upgrades
  and `down` never invoke this reset path.
