# DefenseClaw Splunk Observability Dashboards

This bundle creates Splunk Observability Cloud dashboards for the native OTel
metrics emitted by DefenseClaw.

## Dashboards

The Terraform bundle creates one dashboard group (`DefenseClaw O11y`) and seven
dashboards:

| Dashboard | Purpose |
|---|---|
| `Executive Agent Watch` | Landing view for verdicts, blocks, guardrails, inspections, connector ingress, GenAI usage, and error signals. |
| `Guardrail and Inspection` | O11y-native equivalent of the exported guardrail dashboard: guardrail evaluations, inspection actions, tool/severity breakdowns, audit events, and latency. |
| `Connector and OTel Ingest` | OTLP ingest health, connector hook telemetry, Codex notify, normalized LLM events, GenAI tokens, and LLM operation duration. |
| `DefenseClaw AI Agents Token Economics` | GenAI token usage, estimated model cost, per-agent token breakdowns, and agent token inventory. |
| `Security and Policy` | Gateway verdicts, policy decisions, findings, egress decisions, alerts, judge latency/errors, cache behavior, and external security integration latency. |
| `Runtime and Reliability` | Gateway errors, schema violations, HTTP traffic, streams, audit sinks, webhooks, runtime gauges, SLO latency, SQLite health, exporter health, and queues. |
| `Scanners and Findings` | Scanner throughput, scanner latency, scan errors, findings by severity/rule/scanner, quarantine actions, and scanner queue depth. |

## Detectors

The Terraform bundle also creates Splunk Observability detectors based on the
local Prometheus alert rules in
`bundles/local_observability_stack/prometheus/rules/alerts.yml`.

Examples:

| Prometheus source | Splunk O11y detector equivalent |
|---|---|
| `service:defenseclaw_gateway_block_ratio:5m` | SignalFlow ratio of `defenseclaw.gateway.verdicts{verdict.action=block}` to all verdicts. |
| `service:defenseclaw_http_requests_5xx_ratio:5m` | SignalFlow ratio of `defenseclaw.http.request.count{http.status_code=5*}` to all HTTP requests. |
| `slo:defenseclaw_block_latency:ratio_5m` | Detector on `defenseclaw.slo.block.latency` p95 crossing the 2s SLO threshold. |
| `connector:defenseclaw_otel_ingest_malformed:ratio_5m` | SignalFlow ratio of malformed OTLP requests to total OTLP requests by source/signal. |
| `connector:defenseclaw_otel_ingest_silence:seconds` | Splunk detector that fires when `defenseclaw.otel.ingest.last_seen_ts` stops reporting. |

The detector set covers:

- correctness: schema violations, gateway error spikes, recovered panics
- SLOs: block latency and TUI refresh latency
- telemetry pipeline: exporter silence/errors, audit sink failures, sink circuit state, sink drop ratio
- security: block-rate spike, judge error rate, webhook failure rate
- traffic: HTTP 5xx ratio, auth failures, rate-limit breaches
- runtime: goroutine leak, SQLite busy retries, config load errors
- connectors: silent connector telemetry and malformed OTLP payload ratio

## Apply

Preferred DefenseClaw CLI flow:

The CLI automatically imports matching existing dashboards, charts, and detectors when they are already present in O11y, and creates fresh resources when they are not.

```bash
defenseclaw setup splunk-o11y-dashboards apply \
  --api-url <api-url-endpoint> \
  --auth-token <api-access-token> \
  --yes
```


### CLI flags

| Flag | Purpose |
|---|---|
| `--api-url <url>` | Splunk Observability Cloud API URL|
| `--auth-token <token>` | Splunk O11y API access token. |
| `--with-detectors` | Create detectors along with dashboards. Omit this flag for dashboards only. |
| `--enable-detectors` | Create detectors enabled instead of disabled. This only matters when `--with-detectors` is set. |
| `--dashboards-only` | Explicitly skip detectors. This is the default when `--with-detectors` is not provided. |
| `--name-prefix <label>` | Prefix dashboard and detector names for smoke tests or disposable orgs. |
| `--detector-notification <target>` | Repeatable detector notification target such as `Email,secops@example.com`. |

```bash
defenseclaw setup splunk-o11y-dashboards apply \
  --api-url <api-url-endpoint> \
  --auth-token <api-access-token> \
  --dashboards-only \
  --yes
```

Create detectors, left disabled:

```bash
defenseclaw setup splunk-o11y-dashboards apply \
  --api-url <api-url-endpoint> \
  --auth-token <api-access-token> \
  --with-detectors \
  --yes
```

Create detectors enabled:

```bash
defenseclaw setup splunk-o11y-dashboards apply \
  --api-url <api-url-endpoint> \
  --auth-token <api-access-token> \
  --with-detectors \
  --enable-detectors \
  --yes
```
