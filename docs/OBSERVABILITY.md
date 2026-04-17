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

### 1.2 OpenTelemetry

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

### 3.4 `http_jsonl`

```yaml
- name: webhook-jsonl
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
