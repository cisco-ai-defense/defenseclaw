# DefenseClaw Observability

DefenseClaw v4 separates **audit sinks** (durable event forwarders) from
**OpenTelemetry** (standard metrics/traces/logs). Both are first-class,
both are vendor-neutral, and both are configured declaratively in
`~/.defenseclaw/config.yaml`.

> **Breaking in v4 (beta):** the old `splunk:` block was replaced by
> `audit_sinks:`. Config load will refuse to start if the legacy block
> is present. Migrate as described below.

---

## 1. Concepts

### 1.1 Audit sinks

Every `Event` the audit logger writes (scan verdicts, guardrail
verdicts, block/allow decisions, webhook fires, lifecycle events) is
persisted to the local SQLite audit store **and** fanned out to every
enabled sink.

Sink kinds:

| Kind          | Use case                                                       |
|---------------|----------------------------------------------------------------|
| `splunk_hec`  | Splunk HTTP Event Collector (SIEM).                            |
| `otlp_logs`   | Any OTLP-compatible log backend (Splunk O11y, Grafana, Honey). |
| `http_jsonl`  | Generic HTTP endpoint that accepts newline-delimited JSON.     |

Sinks are independent: you can run zero, one, or many in parallel.
A failing sink does **not** block a decision — audit remains local-first.

### 1.2 Structured JSONL Event Log (gatewaylog)

In addition to audit sinks, the gateway writes a structured JSONL event
stream via `internal/gatewaylog/`. This is a local rotating log file
(`gateway.jsonl`) managed by lumberjack:

| Setting | Default |
|---------|---------|
| Max file size | 50 MB |
| Max backups | 5 |
| Max age | 30 days |
| Compression | gzip |

The gatewaylog writer uses fanout callbacks — each event is written to the
JSONL file and simultaneously dispatched to registered listeners (audit
store, sinks, webhooks). This is the primary structured event tier for
local debugging and log forwarding pipelines that read files directly.

### 1.3 OpenTelemetry

`internal/telemetry` is a plain OTLP client — gRPC or HTTP, logs +
metrics + traces, configurable via `otel:` in the config file or the
standard `OTEL_*` environment variables. There is **no** Splunk-specific
coupling in the telemetry stack; operators who need a Splunk access
token put it in `otel.headers` or `OTEL_EXPORTER_OTLP_HEADERS`.

---

## 2. Migration from v3 → v4

If you previously had:

```yaml
splunk:
  enabled: true
  hec_endpoint: https://splunk.example.com:8088
  hec_token_env: SPLUNK_HEC_TOKEN
  index: defenseclaw
```

rewrite as:

```yaml
audit_sinks:
  - name: splunk-prod
    kind: splunk_hec
    enabled: true
    splunk_hec:
      endpoint: https://splunk.example.com:8088
      token_env: SPLUNK_HEC_TOKEN
      index: defenseclaw
      source: defenseclaw
      sourcetype: defenseclaw:audit
```

DefenseClaw will **fail fast** on startup if any legacy `splunk.*` key
is still set — this is intentional so you cannot silently lose
forwarding after an upgrade.

### 2.1 Automated migration

Instead of rewriting the YAML by hand, run:

```bash
defenseclaw setup observability migrate-splunk --apply
```

The command is idempotent — re-running it on a config that has already
been migrated is a no-op. Omit `--apply` for a dry-run preview.

---

## 3. Sink reference

### 3.1 Common fields

```yaml
audit_sinks:
  - name: my-sink          # required, unique
    kind: splunk_hec       # required
    enabled: true          # default: false

    # Optional batching / timeout knobs (all sinks):
    batch_size:       200
    flush_interval_s: 5
    timeout_s:        10

    # Optional per-sink filters:
    min_severity: MEDIUM         # INFO | LOW | MEDIUM | HIGH | CRITICAL
    actions:      [guardrail-verdict, tool-block]   # only emit matching actions
```

### 3.2 `splunk_hec`

```yaml
- name: splunk-prod
  kind: splunk_hec
  enabled: true
  splunk_hec:
    endpoint:   https://splunk.example.com:8088
    token_env:  SPLUNK_HEC_TOKEN     # preferred
    # token:    ${SPLUNK_HEC_TOKEN}  # inline (flagged as warning)
    index:      defenseclaw
    source:     defenseclaw
    sourcetype: defenseclaw:audit
    verify_tls: true
    ca_cert:    /etc/ssl/certs/splunk-ca.pem
```

### 3.3 `otlp_logs`

```yaml
- name: grafana-logs
  kind: otlp_logs
  enabled: true
  otlp_logs:
    endpoint:    https://otlp.grafana.net
    protocol:    http           # or grpc (default)
    url_path:    /v1/logs        # http only
    headers:
      Authorization: "Bearer ${GRAFANA_OTLP_TOKEN}"
    insecure:    false
    ca_cert:     ""
```

### 3.4 `http_jsonl` (Generic HTTP JSONL audit sink)

> **Not a notifier webhook.** This sink forwards *every* audit event to
> a single URL as newline-delimited JSON. Chat/incident notifications
> (Slack, PagerDuty, Webex, HMAC-signed) are a separate system —
> `webhooks[]` — configured with `defenseclaw setup webhook`. See §7
> below.

```yaml
- name: events-jsonl
  kind: http_jsonl
  enabled: true
  http_jsonl:
    url:          https://events.example.com/ingest
    bearer_env:   EVENTS_BEARER_TOKEN   # preferred
    # bearer_token: ${EVENTS_BEARER_TOKEN}
    verify_tls:   true
    ca_cert:      ""
```

Each line posted to the endpoint is a JSON object with the full audit
event shape (`id`, `timestamp`, `action`, `target`, `severity`,
`details`, `run_id`, …).

---

## 4. OpenTelemetry

Minimal config:

```yaml
otel:
  enabled: true
  endpoint: https://otlp.example.com:4318
  protocol: http          # or grpc
  headers:
    X-SF-Token: ${SPLUNK_ACCESS_TOKEN}
    # any other vendor-specific auth header

  traces:  { enabled: true }
  metrics: { enabled: true, temporality: delta }
  logs:    { enabled: true }

  tls:
    insecure: false
    ca_cert:  ""
```

You can also drive the telemetry stack entirely through standard
`OTEL_EXPORTER_OTLP_*` env vars — the SDK's defaults apply when the
config is empty.

---

## 5. Event shape (what every sink receives)

```json
{
  "id":        "c5b8a6fe-1e23-4a17-8f0d-6a7a6de8f45d",
  "timestamp": "2026-04-14T17:05:11.123Z",
  "run_id":    "2026-04-14T17-02-00Z",
  "actor":     "defenseclaw",
  "action":    "guardrail-verdict",
  "target":    "amazon-bedrock/anthropic.claude-3-5-sonnet",
  "severity":  "HIGH",
  "details":   "action=block; reason=injection.system_prompt; source=regex_judge"
}
```

Sinks that support a native event envelope (Splunk HEC, OTLP Logs) map
these fields onto the native shape; `http_jsonl` posts the raw JSON.

### PII redaction in the event pipeline

Every audit event is run through `internal/redaction` before it reaches
the SQLite store or any remote sink. The pipeline preserves safe
metadata (rule IDs like `SEC-ANTHROPIC`, severity, target names,
finding titles) while masking literal values:

- Anthropic / OpenAI / Stripe / GitHub / AWS secrets
- Credit cards, SSNs, phone numbers, email addresses
- Matched message bodies and tool arguments

Redaction is **unconditional** for persistent sinks. `DEFENSECLAW_REVEAL_PII=1`
only affects operator-facing stderr logs (for local incident triage); it
has no effect on SQLite, webhooks, Splunk HEC, or OTLP logs — those
always receive the scrubbed copy.

> **Never set `DEFENSECLAW_REVEAL_PII=1` in production.** This flag is
> intended for developer workstations and short-lived incident-triage
> sessions only. When set, the gateway will print matched literals
> (secrets, credentials, PII) to stderr — any shared terminal,
> `tmux`/`screen` buffer, recorded session, support bundle, or shell
> history that captures that output becomes a new exfiltration channel.
> Restrict its use to isolated reproduction environments with
> throwaway data, and unset it before attaching the process to any
> shared transport (journald, syslog, container log drivers, CI logs).

Masked placeholders are deterministic (they include a SHA-256 prefix of
the literal), so SIEM/observability workflows can still correlate on
identifier hash across events without handling the raw secret.

To opt back into raw evidence for a single `/inspect` HTTP response, use
the `X-DefenseClaw-Reveal-PII: 1` header documented in `docs/API.md`.
That path audit-logs the reveal and still writes the redacted copy to
the store.

---

## 6. Health

`defenseclaw-gateway status` reports a `Sinks` subsystem that aggregates
every configured audit sink:

```
Sinks:   running — 2 sinks (splunk_hec, otlp_logs)
```

Per-sink health and failure counters are exposed on the gateway
`/health` endpoint under `sinks.details.sinks[]`.

---

## 7. Notifier webhooks (`webhooks[]`)

Notifier webhooks are **not** audit sinks. They deliver low-volume,
human-facing notifications — Slack messages, PagerDuty incidents,
Webex rooms, or generic HMAC-signed JSON — filtered by severity and
event category.

| Surface                        | Schema key                  | What it does                                    | Example preset          |
|--------------------------------|-----------------------------|-------------------------------------------------|-------------------------|
| `setup observability add`      | `audit_sinks[]`             | High-volume, every-event forwarding             | `webhook` → `http_jsonl`|
| `setup webhook add`            | `webhooks[]`                | Per-event chat / incident notifications         | `slack`, `pagerduty`    |

### 7.1 CLI

```bash
defenseclaw setup webhook add slack \
    --url https://hooks.slack.com/services/T000/B000/XXXX \
    --events scan.failed,block \
    --min-severity high

defenseclaw setup webhook add pagerduty \
    --routing-key-env PAGERDUTY_ROUTING_KEY \
    --min-severity critical

defenseclaw setup webhook add webex \
    --room-id Y2lzY29zcGFyazovL3VzL1JPT00v… \
    --secret-env WEBEX_BOT_TOKEN

defenseclaw setup webhook add generic \
    --url https://ops.example.com/alerts \
    --secret-env OPS_WEBHOOK_HMAC_KEY \
    --min-severity high

defenseclaw setup webhook list
defenseclaw setup webhook show <name>
defenseclaw setup webhook enable  <name>
defenseclaw setup webhook disable <name>
defenseclaw setup webhook remove  <name>
defenseclaw setup webhook test    <name>   # dispatches a synthetic event
```

All secrets are resolved from env vars (never written in `config.yaml`).
URLs are validated against SSRF (private ranges, localhost, cloud
metadata endpoints are rejected by default).

### 7.2 YAML schema

```yaml
webhooks:
  - type:             slack            # slack | pagerduty | webex | generic
    url:              https://hooks.slack.com/services/T000/B000/XXXX
    secret_env:       ""               # unused for slack (URL carries the secret)
    room_id:          ""               # webex only
    min_severity:     high             # info | low | medium | high | critical
    events: [scan.failed, block]
    timeout_seconds:  10
    cooldown_seconds: 60               # optional; omit (null) to disable debounce
    enabled:          true
```

`cooldown_seconds` is a tri-state: *omitted / null* → use the
dispatcher default (`webhookDefaultCooldown`, currently 300s);
`0` → dispatch every matching event; `>0` → explicit minimum seconds
between dispatches per (webhook, event-category) pair.

### 7.3 TUI

The Setup wizard exposes a **Webhooks** step that runs through the
same `setup webhook add` path non-interactively. The Config Editor
surfaces a read-only `Webhooks` section (CRUD lives in the wizard or
CLI because list-of-structs + per-entry secrets aren't safely editable
via single-key form fields).

### 7.4 Doctor

`defenseclaw doctor` runs a `Webhooks` probe per entry:

- SSRF guard (same rules as the gateway dispatcher)
- `secret_env` / room_id presence for types that need it
- reachability (HEAD/OPTIONS) — **never** dispatches live events; use
  `setup webhook test` for an end-to-end synthetic dispatch.

---

## 8. Local OTLP + schema validation stack

`bundles/local_observability_stack/` ships a one-shot docker-compose
stack you can point a local sidecar at to see every span / metric / log
flowing end-to-end in Grafana. It bundles:

- `otel-collector` on `127.0.0.1:4317` (gRPC) + `4318` (HTTP)
- `prometheus` (metrics) on `127.0.0.1:9090`
- `loki` (logs) on `127.0.0.1:3100`
- `tempo` (traces) on `127.0.0.1:3200`
- `grafana` (UI + provisioned DefenseClaw dashboard) on
  `http://127.0.0.1:3000`

Quick start (recommended — preflights Docker, waits for readiness, and
writes the `otel:` block in `~/.defenseclaw/config.yaml` automatically):

```bash
defenseclaw setup local-observability up
defenseclaw gateway                            # start sidecar; it reads config.yaml
defenseclaw setup local-observability status   # compose ps + reachability probes
defenseclaw setup local-observability down     # stop (volumes preserved)
defenseclaw setup local-observability reset    # stop + wipe data volumes
```

Manual compose access (no CLI side-effects on `config.yaml`) still
works for CI / scripted environments:

```bash
cd bundles/local_observability_stack
./bin/openclaw-observability-bridge up         # or ./run.sh up (compat shim)
eval "$(./bin/openclaw-observability-bridge env)"
go run ./cmd/defenseclaw gateway
./bin/openclaw-observability-bridge down
```

The provisioned dashboard pulls straight from the live Prometheus
metric names the sidecar already emits: `defenseclaw_gateway_verdicts`,
`defenseclaw_scanner_errors`, `defenseclaw_guardrail_latency`, plus
the v7 addition `defenseclaw_schema_violations_total` (see below).

### 8.1 Runtime JSON-schema validation

The gateway event writer (`internal/gatewaylog.Writer`) runs a **strict
JSON Schema gate** over every event it emits. The validator compiles
`schemas/gateway-event-envelope.json` and its three `$ref`d sibling
schemas (scan / scan_finding / activity) at boot — these files are
embedded into the binary at build time, so the sidecar has no
filesystem dependency on the repo.

When an event fails validation we:

1. **Drop** the event from JSONL, stderr, OTel fanout, and sinks — it
   never reaches any downstream consumer.
2. **Emit an `EventError`** with
   `subsystem=gatewaylog`, `code=SCHEMA_VIOLATION`, `message=<leaf
   violation>`, `cause=<dropped event_type>` so the violation is
   visible on every tier including SIEM/OTel backends.
3. **Increment `defenseclaw.schema.violations`** (labelled by
   `event_type` and `code`) so operators can alert on contract drift
   from PromQL without having to tail JSONL.
4. Guard against recursion: if the crafted violation event itself
   fails validation (must not happen in practice) we never re-enter
   the validator — the operator gets one error per bad source event,
   guaranteed.

Operational controls:

- `DEFENSECLAW_SCHEMA_VALIDATION=off` (or `false`/`0`/`disabled`)
  disables the gate at sidecar start. Breakglass for when a newer
  binary emits a field the shipped schema doesn't know about yet;
  re-enable as soon as the schema PR merges.
- The **"Schema violations / min"** panel on the Grafana dashboard
  is the canary: any sustained non-zero rate is a contract regression
  and should open a ticket.
- The embedded schema copies under `internal/gatewaylog/schemas/*.json`
  are pinned to `schemas/*.json` by `TestEmbeddedSchemasMatchRepo`.
  If the test fails, re-run:
  ```bash
  cp schemas/*.json internal/gatewaylog/schemas/
  ```
  before shipping.
