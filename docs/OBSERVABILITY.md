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

### 1.2.1 Audit Bridge

The `auditBridge` (`internal/gateway/audit_bridge.go`) connects the SQLite
audit store to the JSONL event stream, ensuring every scan verdict, watcher
transition, and enforcement action appears in `gateway.jsonl` alongside
guardrail verdicts — giving operators a single, correlated log instead of
three partial ones (SQLite, OTel, JSONL).

**Behavior:**

- Registered as a callback on `audit.Logger` — fires on every persisted event.
- Translates audit `Action` fields into `EventLifecycle` entries with
  automatic subsystem inference:

  | Action prefix | Subsystem |
  |---------------|-----------|
  | `scan` | `scanner` |
  | `watcher-`, `watch-start`, `watch-stop` | `watcher` |
  | `sidecar-`, `gateway-ready` | `gateway` |
  | `api-` | `api` |
  | `sink-`, `splunk-` | `sinks` |
  | `otel-`, `telemetry-` | `telemetry` |
  | `skill-`, `mcp-`, `block-`, `allow-`, `quarantine-` | `enforcement` |

- **Deduplication**: skips `guardrail-verdict` and `llm-judge-response`
  actions because those already have dedicated structured emissions
  (`emitVerdict` / `emitJudge`) on the proxy hot path.
- **Stateless**: relies on `audit.sanitizeEvent` for PII redaction — all
  text is forwarded verbatim without re-running detection.
- Details map preserves `target`, `actor`, `details`, `trace_id`,
  `audit_id`, and `action` for pivot queries between JSONL and SQLite.

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

For an existing remote Splunk Enterprise deployment, use the
`splunk-enterprise` preset or the `setup splunk --enterprise` shortcut.
The Splunk administrator must already have enabled HEC, created an active HEC
token, and allowed the index.

```bash
defenseclaw setup splunk --enterprise \
  --hec-endpoint https://splunk.example.com:8088/services/collector/event \
  --hec-token "$SPLUNK_HEC_TOKEN" \
  --index defenseclaw \
  --non-interactive

# Equivalent lower-level preset:
defenseclaw setup observability add splunk-enterprise \
  --endpoint https://splunk.example.com:8088/services/collector/event \
  --token "$SPLUNK_HEC_TOKEN" \
  --index defenseclaw \
  --non-interactive
```

DefenseClaw does not create Splunk indexes, HEC tokens, output groups, or
Splunk apps for this path. Client certificates/mTLS and HEC indexer
acknowledgment tokens are out of scope for this preset.

`setup splunk --enterprise` sends one best-effort live HEC probe after the
config write. The probe creates a small synthetic event in the configured
index and reports `200`, auth failures, or network errors without rolling back
the config. Add `--skip-test` when configuring ahead of firewall or VPN access.

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

### 4.1 Span naming hierarchy

The telemetry runtime (`internal/telemetry/runtime.go`) creates nested spans
for every guardrail evaluation:

| Level | Span name pattern | Purpose |
|-------|------------------|---------|
| Stage | `guardrail/{stage}` | Top-level per-evaluation span. Stage = `regex_only`, `regex_judge`, `judge_first`, etc. |
| Phase | `guardrail.{phase}` | Nested under stage. Phase = `regex`, `cisco_ai_defense`, `judge.pii`, `judge.prompt_injection`, `opa`, `finalize` |
| Tool | `inspect/{tool}` | Tool call inspection span |
| Startup | `defenseclaw/startup` | One-shot span emitted on sidecar start |

Stage spans carry `defenseclaw.guardrail.{stage, direction, model, action,
severity, reason, latency_ms}` attributes. Phase spans carry
`defenseclaw.guardrail.{phase, action, severity, latency_ms}`.

### 4.2 Metric instruments

The gateway emits the following OTel metrics
(`internal/telemetry/metrics.go`):

**Verdict and judge:**

| Metric | Labels |
|--------|--------|
| `defenseclaw.gateway.verdicts` | verdict.stage, verdict.action, verdict.severity, policy_id, destination_app |
| `defenseclaw.gateway.judge.invocations` | judge.kind, judge.action, judge.severity |
| `defenseclaw.gateway.judge.latency` | judge.kind |
| `defenseclaw.gateway.judge.errors` | judge.kind, judge.reason (provider \| parse) |

**Guardrail pipeline:**

| Metric | Labels |
|--------|--------|
| `defenseclaw.guardrail.evaluations` | guardrail.scanner, guardrail.action_taken |
| `defenseclaw.guardrail.latency` | guardrail.scanner |
| `defenseclaw.guardrail.judge.latency` | gen_ai.request.model, judge.kind |
| `defenseclaw.guardrail.cache.hits` | scanner, verdict, ttl_bucket |
| `defenseclaw.guardrail.cache.misses` | scanner, verdict, ttl_bucket |

**Redaction and egress:**

| Metric | Labels |
|--------|--------|
| `defenseclaw.redaction.applied` | detector, field |
| `defenseclaw.egress.events` | branch (known \| shape \| passthrough), decision (allow \| block), source (go \| ts) |

**Sink delivery:**

| Metric | Labels |
|--------|--------|
| `defenseclaw.audit.sink.batches.delivered` | sink, kind, status_code, retry_count |
| `defenseclaw.audit.sink.batches.dropped` | sink, kind, status_code, retry_count |
| `defenseclaw.audit.sink.queue.depth` | sink.kind, sink.name |
| `defenseclaw.audit.sink.circuit.state` | sink.kind, sink.name (0=closed, 1=open, 2=half-open) |
| `defenseclaw.audit.sink.delivery.latency` | sink, kind, status_code, retry_count |

**Stream/SSE:**

| Metric | Labels |
|--------|--------|
| `defenseclaw.stream.lifecycle` | http.route, transition (open \| close), outcome |
| `defenseclaw.stream.bytes_sent` | http.route, outcome |
| `defenseclaw.stream.duration_ms` | http.route, outcome |

**Schema validation:** `defenseclaw.schema.violations` (event_type, code) —
see §8.1 below.

### 4.3 Verdict reason truncation

OTel attribute values for `verdict.reason` are capped at 200 bytes
(`maxReasonAttrBytes`) to avoid oversized span attributes. The full reason
is always included in the OTLP log body.

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

### Redaction function variants

The `internal/redaction` package provides two tiers of redaction functions:

| Tier | Functions | When used |
|------|-----------|-----------|
| **Display** | `String()`, `Entity()`, `Reason()`, `Evidence()` | Stderr logs — respects `DEFENSECLAW_REVEAL_PII` |
| **ForSink** | `ForSinkString()`, `ForSinkEntity()`, `ForSinkReason()`, `ForSinkEvidence()`, `ForSinkMessageContent()` | SQLite, Splunk HEC, OTLP, webhooks — **always** redacts regardless of reveal flag |

ForSink functions are idempotent — already-placeholdered values are not
re-redacted.

**Placeholder format:**
- Values ≥ 10 bytes: `<redacted len=N prefix="X" sha=8hex>`
- Values < 5 bytes: `<redacted len=N>` (no SHA)
- Evidence: `<redacted-evidence len=N match=[start:end] sha=8hex>`

**Reason/evidence redaction** preserves safe metadata tokens (rule IDs like
`SEC-ANTHROPIC`, status codes, severity labels) while masking literal values
within semicolon/comma-delimited fields.

To opt back into raw evidence for a single `/inspect` HTTP response, use
the `X-DefenseClaw-Reveal-PII: 1` header documented in `docs/API.md`.
That path audit-logs the reveal and still writes the redacted copy to
the store.

---

## 6. Health

`defenseclaw-gateway status` reports a `Sinks` subsystem with one
human-readable line per configured sink so operators can tell at a
glance which destinations are wired and which are toggled off.

When at least one sink is enabled:

```
  Sinks:     RUNNING (since 2026-04-28T13:39:10-04:00)
             count: 1
             sink_01: local-otlp-logs (otlp_logs) -> 127.0.0.1:4317 [enabled]
             summary: 1 of 1 enabled
```

When entries are configured but all toggled off:

```
  Sinks:     DISABLED (since 2026-04-28T13:39:10-04:00)
             count: 0
             sink_01: splunk-prod (splunk_hec) -> https://splunk.example.com:8088/services/collector/event [disabled]
             sink_02: local-otlp-logs (otlp_logs) -> 127.0.0.1:4317 [disabled]
             summary: 0 of 2 sink(s) enabled — flip one on with 'defenseclaw setup observability enable <name>'
```

When nothing is configured at all:

```
  Sinks:     DISABLED (since 2026-04-28T13:39:10-04:00)
             hint: run 'defenseclaw setup local-observability' or 'defenseclaw setup observability add <preset>' to enable audit forwarding
             summary: no audit sinks configured
```

The structured per-sink array is still exposed on the gateway
`/health` endpoint under `sinks.details.sinks[]` for dashboards and
the TUI; the terminal renderer skips it because the
`sink_<NN>` scalar lines above already carry the same information in
a one-line-per-sink shape.

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
URLs are validated against SSRF (see §7.5 below).

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

### 7.5 SSRF Protection

`validateWebhookURL` (`internal/gateway/webhook.go`) blocks outbound
webhook delivery to unsafe destinations. Every webhook URL (at config
load and at dispatch time) is checked against:

| Blocked range | CIDR | Reason |
|---------------|------|--------|
| RFC1918 Class A | `10.0.0.0/8` | Private network |
| RFC1918 Class B | `172.16.0.0/12` | Private network |
| RFC1918 Class C | `192.168.0.0/16` | Private network |
| Loopback | `127.0.0.0/8` | Localhost |
| Link-local / cloud metadata | `169.254.0.0/16` | AWS/GCP/Azure metadata endpoint |
| IPv6 loopback | `::1/128` | Localhost |
| IPv6 unique local | `fc00::/7` | Private network |
| IPv6 link-local | `fe80::/10` | Link-local |

Additionally:
- Non-HTTP(S) schemes are rejected.
- Hostnames are DNS-resolved at config time; if any A/AAAA record points
  to a private IP, the endpoint is rejected.
- `localhost` is rejected unless `DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST=1`
  (for local development only).

### 7.6 HMAC Signing

For `generic` webhook type, payloads are signed with HMAC-SHA256 using
the secret from `secret_env`. The signature is sent in the
`X-DefenseClaw-Signature` header as a hex-encoded digest:

```
X-DefenseClaw-Signature: <hex(HMAC-SHA256(payload, secret))>
```

Receivers should compute the same HMAC over the raw request body and
compare using constant-time comparison.

### 7.7 Dispatcher Internals

The `WebhookDispatcher` (`internal/gateway/webhook.go`) manages delivery:

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Max retries | 3 | Per delivery attempt |
| Retry backoff | 2s | Between retries |
| Max concurrency | 20 | Bounded goroutine pool via semaphore |
| Default timeout | 10s | Per HTTP request |
| Default cooldown | 300s (5 min) | Debounce per (webhook, event-category) pair |
| Retryable status codes | 429, 5xx | All others are terminal failures |

Payload formatters per type:
- **Slack**: Block Kit attachments with severity color coding
- **PagerDuty**: Events API v2 format with routing key
- **Webex**: Adaptive card with room ID targeting
- **Generic**: Raw JSON audit event with HMAC signature

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

## 9. Connector observability

DefenseClaw runs Codex, Claude Code, and the hook-first agent connectors in
**observability mode** by default: enforcement is gated off, and connector
telemetry feeds audit events + Prometheus counters + Grafana panels without
modifying the agent traffic plane unless the connector explicitly supports it.

### 9.1 Channels

1. **Hooks** — connector hook scripts post structured JSON to their
   `/api/v1/<connector>/hook` endpoints. The gateway normalizes connector,
   source, session/turn IDs, hook event, tool, workspace, decision,
   `raw_action`, `would_block`, fail mode, and duration into audit, logs,
   spans, and counters.

2. **Native OTel/OTLP** — Codex and Claude Code use header-token OTLP;
   Gemini CLI uses settings.json with a loopback path token because custom
   OTLP headers are not documented; Copilot CLI can be pointed at the gateway
   with documented process environment variables. The gateway's local OTLP
   receiver accepts OTLP/HTTP JSON and protobuf on:
   - `POST /v1/logs`     → `audit.action=otel.ingest.logs`
   - `POST /v1/metrics`  → `audit.action=otel.ingest.metrics`
   - `POST /v1/traces`   → `audit.action=otel.ingest.traces`
   - Malformed body      → `audit.action=otel.ingest.malformed` (WARN)

   The receiver also re-emits one OTel log record per accepted batch via the
   gateway's own OTel pipeline so Loki / Tempo see connector telemetry
   directly — no audit OTLP sink configuration required.

3. **Codex notify** — codex calls `notify-bridge.sh` after every
   agent turn. The bridge POSTs codex's raw JSON arg to
   `/api/v1/codex/notify`; the gateway derives a sanitized action
   key and persists `audit.action=codex.notify.<sanitized-type>`
   (e.g. `codex.notify.agent-turn-complete`). Sanitization is
   `[a-z0-9._-]{1,64}`; the schema treats this as a curated dynamic
   suffix family (see `schemas/audit-event.json`).

4. **Agent discovery** — `defenseclaw agent discover` runs the cached
   local discovery probes on demand, prints the same table used by
   first-run init, and best-effort POSTs a sanitized report to
   `/api/v1/agents/discovery`. The POST body includes booleans,
   basenames, version probe classes, and SHA-256 path hashes only;
   raw local filesystem paths are never sent to the sidecar telemetry
   endpoint.

5. **Continuous AI visibility** — when `ai_discovery.enabled` is on, the
   sidecar runs an enhanced-artifacts scan at startup, on a periodic
   interval, and whenever `defenseclaw agent usage --refresh` calls
   `POST /api/v1/ai-usage/scan`. The detector registry looks for
   supported connectors plus broader AI signals such as AI CLIs,
   active processes, installed desktop apps, editor extensions, MCP
   files, skills, rules, plugins, package dependencies, provider env
   var names, shell-history signature matches, provider-domain
   references, and loopback-only local AI endpoints. Process monitoring
   matches executable names only, not argv. Endpoint probes only target
   cataloged `localhost` / `127.0.0.1` URLs, send no credentials, and
   discard response bodies after a small bounded read. Results are
   available from `GET /api/v1/ai-usage` and emitted as sanitized
   `event_type=ai_discovery` gateway events, OTel logs, metrics, and
   spans. Outbound telemetry includes low-cardinality product/category
   metadata, basenames, and `sha256:` hashes only; raw paths, shell
   commands, process arguments, prompt text, file contents, local
   endpoint URLs, and env var values are not emitted.

### 9.2 SIEM consumer guidance

Audit events emitted from the new ingest paths carry the same envelope
shape as every other audit row but expose three new top-level
attributes worth indexing in your SIEM:

| Field           | Type   | Meaning                                                                 |
|-----------------|--------|-------------------------------------------------------------------------|
| `action`        | enum   | One of `otel.ingest.{logs,metrics,traces,malformed}`, `codex.notify`, `codex.notify.<type>`, or `codex.notify.malformed`. Validators MUST accept the full enum *and* the `^codex\.notify\.[a-z0-9._-]{1,64}$` prefix family. |
| `actor`         | string | Authenticated connector source from the `x-defenseclaw-source` header or the Gemini path token. Examples: `codex`, `claudecode`, `copilot`, `geminicli`, `unknown`. |
| `details`       | string | Structured one-line summary: `signal=logs size=4096 bytes resources=2 logRecords=14 services=[codex=1,claudecode=1]`. |

The matching gateway envelope events (`gateway-event-envelope.json`)
add an `agent_telemetry` payload block (`event_type=agent_telemetry`)
with `channel`, `source`, `result`, `records`, `bytes`, and notify
fields. SIEM rules should join on `agent_telemetry.source` to break
down telemetry rate per connector.

Continuous AI visibility uses the same envelope family with an
`ai_discovery` payload block (`event_type=ai_discovery`). Index
`ai_discovery.category`, `ai_discovery.vendor`, `ai_discovery.product`,
`ai_discovery.state`, and `ai_discovery.evidence_types` for shadow-AI
inventory reporting. Treat `path_hashes`, `basenames`, and
`workspace_hash` as correlation hints, not user-readable local paths.

### 9.3 Connector dashboard + alerts

Provisioned in `bundles/local_observability_stack/`:

- **DefenseClaw — Connectors** dashboard
  (`bundles/local_observability_stack/grafana/dashboards/
  defenseclaw-connectors.json`, uid `defenseclaw-connectors`):
  per-connector OTLP request rate, leaf-record volume, byte rate,
  malformed ratio, hook-vs-OTel drift, GenAI tokens / latency, and
  the live ingest log stream.

- **Recording rules** (`prometheus/rules/recording.yml` →
  `defenseclaw.connectors` group):
  `connector:defenseclaw_otel_ingest_requests:rate5m`,
  `connector:defenseclaw_otel_ingest_records:rate5m`,
  `connector:defenseclaw_otel_ingest_bytes:rate5m`,
  `connector:defenseclaw_otel_ingest_malformed:ratio_5m`,
  `connector:defenseclaw_otel_ingest_silence:seconds`,
  `connector:defenseclaw_codex_notify:rate5m`,
  `connector:defenseclaw_hooks:rate5m`,
  `connector:defenseclaw_otel_logs:rate5m`.

- **Alerts** (`prometheus/rules/alerts.yml` →
  `defenseclaw.connectors` group):
  - `DefenseClawConnectorTelemetrySilent` — fires when a connector
    that has previously emitted telemetry goes silent for >10
    minutes. Gated on `last_seen_ts` existing so a never-used
    connector doesn't page.
  - `DefenseClawConnectorTelemetryMalformed` — fires when >10% of
    inbound OTLP-HTTP bodies fail to parse for 10m, indicating
    schema drift or a misconfigured exporter.

### 9.4 Toggling enforcement

Observability mode keeps connector enforcement code intact but inactive
unless explicitly requested. For Codex and Claude Code, the proxy
simply doesn't bind until the connector-specific enforcement switch is
enabled:

```yaml
# ~/.defenseclaw/config.yaml
guardrail:
  codex_enforcement_enabled: true        # codex
  claude_code_enforcement_enabled: true  # claude code
```

Restart the gateway. The connector setup logic re-patches
`~/.codex/config.toml` / `~/.claude/settings.json` to point traffic
through the proxy and persists snapshots in
`~/.defenseclaw/state/{codex,claudecode}-config.json` so a future
mode flip cleanly reverts both the guardrail wiring AND the OTel /
notify glue. See `internal/gateway/connector/{codex,claudecode}.go`
for the full backup/restore contract.

### 9.5 One-shot setup aliases

For operators who only want telemetry (no enforcement, no proxy
listener), DefenseClaw exposes dedicated setup paths that wrap the
observability-only branch of `setup guardrail` and additionally pin
`claw.mode` so the rest of the CLI/TUI surfaces the matching
connector's source-of-truth files.

```bash
# Codex: hooks + native OTel + notify-bridge.sh
defenseclaw setup codex --yes

# Claude Code: hooks + native OTel exporter
defenseclaw setup claude-code --yes

# Hook-first connectors: hooks, plus native OTel where documented
defenseclaw setup hermes --yes
defenseclaw setup cursor --yes
defenseclaw setup windsurf --yes
defenseclaw setup geminicli --yes
defenseclaw setup copilot --yes

# Optionally bring up the bundled Prom/Loki/Tempo/Grafana stack in
# the same step:
defenseclaw setup copilot --yes --with-local-stack
```

Both aliases persist:

| Field                                         | Value             | Why                                                                    |
|-----------------------------------------------|-------------------|------------------------------------------------------------------------|
| `claw.mode`                                   | selected connector | TUI / scanners read from the connector's documented local surfaces instead of the OpenClaw layout. |
| `guardrail.connector`                         | selected connector | Drives `Config.activeConnector()` (Go) and `Config.active_connector()` (Python). |
| `guardrail.codex_enforcement_enabled`         | `false`           | Keeps the proxy out of the data path even though `guardrail.enabled=true`. |
| `guardrail.claudecode_enforcement_enabled`    | `false`           | Same as above for Claude Code.                                         |
| `guardrail.enabled`                           | `true`            | Required so the gateway's `Connector.Setup()` runs and wires hooks + OTel + notify. |
| `guardrail.mode`                              | `observe`         | Sensible if-flipped-on-later default.                                  |
| `<data_dir>/picked_connector`                 | selected connector | So `defenseclaw setup guardrail`, `init`, and quickstart default to the same connector on subsequent runs. |

After both aliases run, the gateway is restarted (unless `--no-restart`
is passed) so its connector setup hook scripts, OTel block, and
(codex only) notify bridge are reconciled with the running sidecar.
To revert and restore direct LLM access, run
`defenseclaw setup guardrail --disable`.
