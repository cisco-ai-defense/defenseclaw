# DefenseClaw Observability

DefenseClaw v4 separates **audit sinks** (durable event forwarders) from
**OpenTelemetry** (standard metrics/traces/logs). Both are first-class,
both are vendor-neutral, and both are configured declaratively in
`~/.defenseclaw/config.yaml`.

> **Breaking in v4 (beta):** the old `splunk:` block was replaced by
> `audit_sinks:`. Config load will refuse to start if the legacy block
> is present. Migrate as described below.

> **Release note — SQLite write-lock remediation (Phase 1–4):**
> The sidecar now caps SQLite to a single open connection per database
> (`SetMaxOpenConns(1)`), applies all performance pragmas via the DSN
> (so they propagate to every pool connection), retries
> `database is locked` with exponential backoff, persists LLM-judge
> bodies through an async batched queue, and stores judge bodies in
> their own file `~/.defenseclaw/judge_bodies.db` (`audit.judge_bodies_db`
> in config). New OTel metrics
> `defenseclaw.sqlite.busy_retries`,
> `defenseclaw.judge.persist.drops`,
> `defenseclaw.judge.persist.queue_depth`, and
> `defenseclaw.judge.persist.batch_size` surface the new pathways —
> see §4.2 and §5.1. The legacy `judge_responses` table on `audit.db`
> remains readable but receives no new writes; operators may drop it
> at their convenience (see §5.1 for the one-liner).

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
metrics + traces, configured through named `otel.destinations[]` routes.
Transport, credentials, and signals are explicit per destination; the
runtime does not create new outbound routes from `OTEL_EXPORTER_OTLP_*`.
During upgrade, a legacy flat exporter in `otel.*` or the documented
`DEFENSECLAW_OTEL_*`/standard OTLP endpoint variables is persisted as a single
named destination, preserving any destinations already present. The Go loader
also performs the conversion in memory before validation as a write-free
fallback, so an interrupted release migration cannot prevent startup or stop
the legacy route.

### 1.4 Unified finding pipeline

Every runtime detection — whether it originates from a hook-based
connector, an inspect HTTP endpoint, the proxy guardrail, a tool-call
inspection, a mid-stream check, an asset-policy evaluation, or a
rescan drift comparison — goes through the same `scanner.EmitScanResult`
choke point as classic skill/MCP scans. There is exactly one finding
pipeline, regardless of source. Practically, this means every finding
is guaranteed to land on **all** of the following surfaces:

1. `gateway.jsonl` (and every fanned-out audit sink) — one `EventScan`
   row plus one `EventScanFinding` row per finding.
2. `audit.sqlite` — one `scan_results` row plus one `scan_findings`
   row per finding.
3. Prometheus / OTel — `defenseclaw_scan_findings_by_rule_total`
   (per-rule), `defenseclaw_scan_findings_total` (per-severity),
   `defenseclaw_scan_count_total`, and `defenseclaw_scan_duration_*`.
4. Correlator inputs — multi-step attack patterns see every finding,
   not just those from CLI scans.

The runtime origin is encoded on the `scanner` label, so dashboards can
slice findings by source without changing the query shape:

| `scanner=` value     | Origin                                                |
|----------------------|-------------------------------------------------------|
| `skill`              | Classic skill scanner (CLI / install / watcher)       |
| `mcp`                | Classic MCP scanner (CLI / install / watcher)         |
| `hook-rules`         | Hook-based connector rule engine (claudecode, codex, cursor, windsurf, geminicli, copilot, hermes) |
| `inspect-http`       | `/api/v1/inspect/{request,response,tool-response,tool}` |
| `guardrail-llm`      | Proxy guardrail final-stage verdict                   |
| `mid-stream`         | Mid-stream guardrail re-check                         |
| `tool-call-inspect`  | Inline tool-call guardrail check during proxy flow    |
| `asset-policy`       | Runtime asset-policy enforcement (skills/MCP install) |
| `drift`              | Rescan drift detection (new/removed/changed findings) |

#### `evaluation_id` — the runtime join key

For runtime sources (everything except classic `skill`/`mcp`), every
emission carries an `evaluation_id` (UUID) generated at the entry
point and propagated through the entire fan-out. It surfaces as:

- `scan.evaluation_id` on the aggregate `EventScan` row.
- `scan_finding.evaluation_id` on every child `EventScanFinding` row.
- `verdict.evaluation_id` on the corresponding `EventVerdict` (proxy
  guardrail / hook / inspect flows).
- `error.evaluation_id` on schema-violation `EventError` rows when the
  dropped payload was attributable to an evaluation (so a malformed
  finding does not become an anonymous infrastructure error).
- `evaluation_id` column on the `scan_results` and `scan_findings`
  audit DB tables.
- Audit log `details` for hook / HILT / asset-policy decisions, as
  `evaluation_id=<uuid> rule_ids=<id1,id2,...>`.

#### Pivot examples

```text
# All findings that fired during one proxy request:
gateway.jsonl: event_type=scan_finding evaluation_id="eval-…"

# Aggregate scan row + every child finding + the verdict that gated
# the request, joined on evaluation_id:
SELECT * FROM scan_results    WHERE evaluation_id = 'eval-…';
SELECT * FROM scan_findings   WHERE evaluation_id = 'eval-…';
SELECT * FROM judge_responses WHERE evaluation_id = 'eval-…';

# Prometheus: how many findings did rule X fire across all surfaces
# in the last hour, regardless of whether they came from a hook, the
# proxy, or a CLI scan?
sum(increase(defenseclaw_scan_findings_by_rule_total{rule_id="…"}[1h]))
```

#### Connectors that emit findings

All hook-based connectors — Claude Code (`claudecode`), Codex
(`codex`), Cursor (`cursor`), Windsurf (`windsurf`), Gemini CLI
(`geminicli`), Copilot (`copilot`), Hermes (`hermes`) — emit per-rule
findings through this pipeline. The HTTP hook response keeps the
existing `findings: []string` field (backward-compatible) and adds an
opt-in `detailed_findings: []RuleFinding` block plus top-level
`evaluation_id` and `rule_ids` fields. Clients that don't read the
new fields are unaffected.

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

Named multi-destination config:

```yaml
otel:
  enabled: true
  traces: { sampler: always_on, sampler_arg: "1.0" }
  destinations:
    - name: primary
      enabled: true
      endpoint: https://otlp.example.com:4318
      protocol: http
      headers:
        Authorization: ${OTLP_TOKEN}
      traces:  { enabled: true }
      metrics: { enabled: true, temporality: delta }
      logs:    { enabled: true }
      tls: { insecure: false, ca_cert: "" }
```

Every destination gets its own span/log batch processor and metric reader, so
backpressure or a transport failure on one route does not stop the other
routes. Process-wide resource attributes, sampling, and redaction remain on
the parent `otel:` block. Sampling is intentionally global: destination-local
samplers are not supported because the SDK makes its sampling decision before
fan-out processors run.

The flat single-exporter shape (`otel.endpoint`, `otel.protocol`,
`otel.headers`, and top-level signal transport/enable fields) is legacy-only
and is persisted as a named destination by `defenseclaw upgrade`. Preview or
repair the conversion explicitly with:

```bash
defenseclaw setup observability migrate-otel       # preview
defenseclaw setup observability migrate-otel --apply
```

Setup commands also perform this conversion atomically before adding a named
route. Migration preserves the old exporter, writes a backup, and removes the
flat transport fields so subsequent saves cannot recreate them.

Named destination identity is the `name` field. Adding a new name appends an
independent route; applying a preset with an existing name updates only that
route. Use `defenseclaw setup observability list [--json]` for the complete
inventory and `--dry-run` before a write. The text inventory includes target
(`otel` or `audit_sinks`), kind, enabled state, signals, preset, and endpoint.
The TUI Overview mirrors the runtime-loaded inventory in a dedicated
**Observability Destinations · Runtime** panel and shows schema eligibility
separately from OTLP delivery acknowledgement, rejection, and failure.
Process/global/connector scope and explicit connector suppression are shown;
headers and credential values are intentionally omitted.

Migration note: moving from the flat exporter to named destinations
removes the old `defenseclaw.preset` and `defenseclaw.preset_name` resource
attributes. Preset identity now lives on each destination because one
process-wide resource cannot truthfully identify multiple vendors. This is a
wire-visible metadata change for queries that used those two resource keys.

Galileo is available as a traces-only destination:

```bash
export GALILEO_API_KEY='...'
defenseclaw setup local-observability up
defenseclaw setup galileo --project defenseclaw --logstream production
defenseclaw setup galileo test
```

Cloud defaults to `https://api.galileo.ai/otel/traces`; self-hosted setup uses
`--console-url` derivation or an exact `--trace-endpoint`. The API key is
referenced as `${GALILEO_API_KEY}` and never stored in `config.yaml`.
Real-time export is the setup default: each completed model invocation, agent
invocation, or tool execution is queued immediately with a one-second maximum
batch delay. `setup galileo test` uses the running gateway/filter/exporter path;
`setup galileo test --direct` is only for isolating remote connectivity.

For Galileo, DefenseClaw projects LLM spans onto the standard
`gen_ai.operation.name`, `gen_ai.provider.name`, request/response model,
usage, conversation, and input/output message attributes. The existing
`defenseclaw.*` attributes remain the authoritative security overlay. GenAI
message values use persistent-sink redaction by default, and the Galileo
destination's generic `span_filter` filters non-GenAI policy/scanner/runtime
spans that Galileo would otherwise reject; other OTLP destinations still
receive the complete trace set. Preset names do not control filtering, so
renaming a destination cannot accidentally disable the projection. The filter
has schema-pinned branches for `chat`, `invoke_agent`, and `execute_tool`;
each branch requires the exact attributes declared by its runtime span schema.

At runtime, credential-bearing OTLP routes must use TLS unless their endpoint
is loopback. This guard also applies to hand-edited YAML and rejects URL
userinfo before any exporter is created.

Hook connectors deliver prompt, model-completion, and tool lifecycle events
separately. Each hook delivery gets a short canonical `invoke_agent` anchor;
the delivery's completed `chat`, `execute_tool`, or lifecycle span is parented
to that anchor and exported as one independently indexable trace. Reusing one
trace ID for an hours-long session is deliberately avoided because a backend
may finalize a trace after its first batch and ignore late child spans.
`gen_ai.conversation.id` and the stable DefenseClaw agent, root-session,
lifecycle, and execution attributes correlate the short traces into the same
Galileo session and Agent360 identity. Connectors with a post-model hook export
at that event; Codex and Claude Code use Stop as their model-completion
fallback. Start and completed-operation traces export during long-running
turns, so an agent does not need to stop before Galileo receives activity.
Correlation caches are bounded, duplicate completions are suppressed, and all
content continues to follow persistent-sink redaction.

Hook correlation has three explicit identity layers. `gen_ai.conversation.id`
is the upstream resumable session; `defenseclaw.agent.lifecycle.id` is stable
for the same root agent or subagent across gateway restarts; and
`defenseclaw.agent.execution.id` identifies one start/resume attempt even when
the gateway process remains running. Child agents carry
`defenseclaw.agent.parent.id`, `defenseclaw.session.parent.id`, and
`defenseclaw.agent.depth`. Session source (`startup`, `resume`, `clear`, or
`compact`) is inherited by later spans and logs in that execution. Every hook
also emits an explicit correlated `lifecycle` log. Session/subagent terminal
and compaction hooks emit short transition spans, so terminal state remains
visible even when the upstream hook reports no assistant text.

Every normalized hook event also carries a canonical execution phase, the
previous phase, a monotonically increasing per-execution sequence, and a stable
operation ID. The native `defenseclaw.agent.phase.current` gauge gives Agent360
a continuous state timeline between scrapes, while
`defenseclaw.agent.phase.transitions` supplies real directed `from → to` edges.
The Loki sequence keeps every sub-scrape transition in order. Every hook also
emits a first-class `hook_decision` event after connector enforcement and
capability mapping. This separates an enforced `block` from a raw guardrail
block that became an observe-mode `would_block`, and carries the same
agent/root/lifecycle/execution/trace/evaluation identifiers as nearby model and
tool events. Agent360's recovery-path timeline renders those records in
timestamp order so the next tool call, model retry, decision, or terminal
lifecycle event is visible without inferring a missing retry.

Agent360's trace table lists completed operation traces (`tool_end`,
`turn_end`, terminal session/subagent events) **and** enforcement attempts
whose hook span records `defenseclaw.raw_action` or `defenseclaw.decision` as
block/confirm/alert. The Trace ID link preserves the selected scope and replaces
the trace variable directly, so the adjacent Tempo waterfall opens the exact
operation rather than retaining an empty previous trace value.

Connector-native child IDs are authoritative. Codex, Claude Code, Cursor,
Copilot, and Hermes expose subagent lifecycle hooks; OpenCode exposes child
sessions through `parentID`. For connectors that expose delegation only as a
tool call, DefenseClaw creates a deterministic inferred child lifecycle for
known agent-spawner tools. Inference is labeled through the normal lifecycle
fields and never replaces a later native child identity.

Prometheus lifecycle series deliberately aggregate by connector and normalized
event rather than user, session, or agent ID. Those unbounded identities live
in logs and traces; token metrics retain agent and conversation dimensions for
per-agent usage drilldown.

Missing telemetry is never converted to agent content or a synthetic zero.
The `defenseclaw.telemetry.{input,output,tokens}.reported` attributes state
whether the connector supplied each field. Galileo may render an omitted
token metric as zero in its built-in table; the reported flag distinguishes
that UI default from a genuine provider-reported zero.

The durable contracts are `schemas/otel/runtime-{llm,agent,tool,approval}-span.schema.json`,
`schemas/otel/agent-lifecycle-event.schema.json`, and
`schemas/otel/galileo-export-profile.schema.json`. CI emits each runtime
span shape and fails when its name, kind, required fields, or declared
attributes drift from those files. Galileo routing volume remains available as
`defenseclaw.telemetry.destination.spans{destination,outcome,reason}`. `/health`
also exposes eligibility separately from attempted, delivered, rejected, and
failed export counts. These counters are batch-level outcomes. The runtime
canary isolates its trace in a single-use export request and verifies the exact
trace ID, so concurrent traffic cannot create a false acknowledgement.

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
| `defenseclaw.gateway.forwarded_headers` | path (chat-completions \| passthrough), result (ok \| rejected_invalid \| rejected_overflow) |

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

**SQLite storage (Phase 1–3 write-lock remediation):**

| Metric | Labels | Notes |
|--------|--------|-------|
| `defenseclaw.sqlite.busy_retries` | operation | Increments when `database is locked` is observed before a retry succeeds. With Phase 1 (pool cap + DSN pragmas) and Phase 2 (exponential-backoff retry) deployed, this counter should hover near zero in steady state. A non-zero rate is a leading indicator that some new write path bypasses the `audit.Store`/`inventory.Store` helpers. |
| `defenseclaw.judge.persist.drops` | reason (`queue_full` \| `shutdown` \| `worker_error`) | Phase 3 async judge-persistence queue overflow counter. Any non-zero value means judge bodies were silently discarded — either because the proxy was generating judges faster than the worker could fsync them (raise `guardrail.judge_persist_queue_depth` or `DEFENSECLAW_JUDGE_PERSIST_QUEUE_SIZE`) or because Shutdown ran out of time before draining (raise the sidecar shutdown grace period). |
| `defenseclaw.judge.persist.queue_depth` | — | Current size of the async judge queue. Used together with `judge.persist.drops` to size queue depth empirically — a sustained queue depth at the cap is the precondition for drops. |
| `defenseclaw.judge.persist.batch_size` | — | Histogram of rows committed per worker transaction (target up to 32 rows or every 100 ms). Higher means more rows are sharing a single fsync, which is the entire point of the async queue. |

> **Alerting threshold suggestion:** alert when `rate(defenseclaw_sqlite_busy_retries_total[5m]) > 0` for more than 10 minutes, and page when any non-zero `defenseclaw_judge_persist_drops_total` sample is observed.

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

## 5.1 SQLite storage layout (Phase 4 split)

DefenseClaw's local SQLite footprint is split across two files, each
hardened with the same connection pool and pragma defaults (WAL,
`busy_timeout=5000`, `synchronous=NORMAL`, `cache_size=-20000`,
`temp_store=MEMORY`, `mmap_size=268435456`, `foreign_keys=ON`,
`SetMaxOpenConns(1)`):

| File | Default path | Tables (selected) | Config key |
|------|--------------|-------------------|------------|
| `audit.db` | `~/.defenseclaw/audit.db` | `audit_events`, `activity_events`, `scan_results`, `findings`, `network_egress`, `sink_health` | `audit_db` |
| `judge_bodies.db` | `~/.defenseclaw/judge_bodies.db` | `judge_responses` | `judge_bodies_db` |

The split exists because retained LLM-judge bodies are the largest and
highest-frequency rows in the system (each capped at `MaxJudgeRawBytes
= 64 KiB`). Keeping them in their own DB means audit/activity writers
on `audit.db` never share a fsync window with judge body INSERTs,
which is what made the pre-Phase-4 layout vulnerable to
`SQLITE_BUSY` under burst load.

The legacy `judge_responses` table on `audit.db` is preserved by the
upgrade (so historical rows remain readable) but never receives new
writes. Operators who want to reclaim that disk space can drop the
legacy table at their convenience:

```bash
sqlite3 ~/.defenseclaw/audit.db "DROP TABLE IF EXISTS judge_responses; VACUUM;"
```

This is safe at any point after the upgraded sidecar has started; new
judge bodies always land in `judge_bodies.db`.

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
defenseclaw-gateway start                      # start sidecar; it reads config.yaml
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
go run ./cmd/defenseclaw
./bin/openclaw-observability-bridge down
```

The provisioned dashboards pull straight from the live Prometheus
metric names the sidecar already emits: `defenseclaw_gateway_verdicts`,
`defenseclaw_scanner_errors`, `defenseclaw_guardrail_latency`, plus
the v7 addition `defenseclaw_schema_violations_total` (see below).

### 8.0 Dashboard catalog

Every JSON file under
`bundles/local_observability_stack/grafana/dashboards/` is auto-loaded
by Grafana via the file provisioner
(`grafana/provisioning/dashboards/dashboards.yml`). The catalog is:

| Dashboard | UID | Purpose |
| --- | --- | --- |
| **Overview** | `defenseclaw-overview` | KPI strip (verdicts, blocks, confirm-rate, HITL pending, top blocked rule, exporter freshness, panics), firing alerts, SLO gauges. Top-of-funnel landing — every other board is one click away. |
| **Agent Activity (Live)** | `defenseclaw-activity` | Cross-agent prompts, model usage, tools, internet destinations, and session correlation. |
| **Connectors (Overview)** | `defenseclaw-connectors` | Cross-connector compare board: per-connector traffic, blocks, redactions, errors, hooks-vs-OTel drift, identity assignment rate. The connector table cell drills into Connector Detail. |
| **Connector Detail** | `defenseclaw-connector-detail` | Single-connector deep dive driven by `$connector`: identity, ingest, hooks, verdicts, judge, findings, HITL, SSE, tools, scoped Loki streams. |
| **Security (Verdicts)** | `defenseclaw-security` | Verdict funnel by stage × action, action mix over time, prompt/completion/tool_call split, confirm-rate handoff to HITL, judge + cache + redactions, top blocked categories and rules. |
| **HITL (Human-in-the-Loop)** | `defenseclaw-hitl` | Two stacked sections: chat HILT (`openclaw:hilt` status mix, approval / denial / timeout rates, pending gauge, mean-time-to-decision) and exec approvals (`RecordApproval` result mix, auto-approval ratio, dangerous share, latency, top denied commands). |
| **Findings (Rule detail)** | `defenseclaw-findings` | Top rules with sparklines, rule_id × time heatmap, last-seen / first-seen tables, top targets, finding-to-verdict correlation, scoped Loki `scan_finding` stream. |
| **Policy decisions** | `defenseclaw-policy-decisions` | OPA verdicts by `policy_domain` × `policy_verdict`, egress branch / decision split, block-list hits, multi-turn injection trips, schema violation panel. |
| **Agent identity** | `defenseclaw-agent-identity` | v7 correlation: agent.id × agent.instance_id × sidecar.instance_id counts, identity churn, on-demand discovery latency / errors, continuous AI confidence histograms, per-connector header presence. |
| **Agent360** | `defenseclaw-agent-360` | Automatic runtime Agent Directory and one-click agent/tree drill-down: durable lifecycle/execution identity, continuous execution-phase timeline, ordered hook sequence, clickable completed-operation Tempo waterfall, directed phase flow, aggregate agent/subagent/model/tool topology, inputs/outputs, reported tokens/cost, websites, and security decisions. |
| **Scanners (Ops)** | `defenseclaw-scanners` | Scanner ops focus: sparse-safe rolling throughput and duration, errors by `error_type`, quarantine actions, and top rules with drill into Findings. Queue depth is omitted because scanner execution is currently synchronous and does not emit a durable queue series. |
| **AI Agent Usage & Detection** | `defenseclaw-ai-discovery` | Continuous AI inventory loop: active signals, scan completions, new / gone signals, detector errors, per-vendor / per-product tables, two-axis Bayesian confidence, scoped traces and logs. |
| **Runtime & Reliability** | `defenseclaw-runtime` | Process, SQLite, exporter, audit-sink, and canonical gateway-error health. The former Reliability board is consolidated here. |
| **Traffic & Traces** | `defenseclaw-traffic` | HTTP surface latency / status, OTel ingest rates, trace samples. |

### 8.0.1 Shared template-variable contract

To keep URL-state reusable across boards, every dashboard exposes the
relevant subset of these template variables. The dashboard navbar then
propagates the active selections via `${var:queryparam}` so a click on
`Connector detail` from anywhere preserves the chosen connector,
severity, action, etc.

| Variable | Source | Used on |
| --- | --- | --- |
| `connector` | `label_values(defenseclaw_connector_hook_invocations_total, connector)` — hook invocations only, **not** unioned with `defenseclaw_otel_ingest_records_total{source}` (that metric carries only connectors pushing native OTLP and would silently exclude every hook-only connector). | Connectors + Connector Detail (single-connector deep dive) are connector-scoped; Security (Guardrail Evaluations), HITL, and Agent identity are connector-filterable (multi-select `connector` template var). |
| `surface` | `defenseclaw_direction` (`prompt` / `completion` / `tool_call`) | Connector Detail, Security. |
| `stage` | `defenseclaw_gateway_verdicts_total{verdict_stage}` | Security, Connector Detail. |
| `action` | `defenseclaw_gateway_verdicts_total{verdict_action}` | Security, Connector Detail. |
| `severity` | `defenseclaw_scan_findings_total{severity}` | Security, Findings, Scanners. |
| `scanner` | `defenseclaw_scan_findings_total{scanner}` | Findings, Scanners. |
| `rule_id` | `defenseclaw_scan_findings_by_rule_total{rule_id}` | Findings. |
| `policy_id` | `defenseclaw_gateway_verdicts_total{policy_id}` | Security. |
| `policy_domain` / `egress_branch` | `defenseclaw_opa_evaluations_total{policy_domain}`, `defenseclaw_egress_decisions_total{branch}` | Policy decisions. |

Panel-level data links carry the same convention: a click on a
`connector` cell opens Connector Detail with `var-connector=...`, a
click on a `rule_id` cell opens Findings with `var-rule_id=...`, a
click on a `verdict_action=confirm` series opens HITL, etc.

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

### 9.0 Multi-connector telemetry

A single gateway can enforce guardrail policy for several hook connectors at
once (Codex, Claude Code, Antigravity, …), each with an independent policy
block under `guardrail.connectors.<name>` in `~/.defenseclaw/config.yaml`
(per-connector `mode`, `hook_fail_mode`, `hilt`, `block_message`,
`rule_pack_dir`). Proxy connectors (OpenClaw, ZeptoClaw) cannot be peers —
multi-connector is hook-only. When more than one connector is active,
`claw.mode` is set to `multi`, and that sentinel is mirrored onto the OTel
**resource** attribute `defenseclaw.claw.mode=multi` so a fan-out gateway is
distinguishable from a single-connector one at the resource level.

Every per-event rail carries a connector dimension, so telemetry can be sliced
per connector:

| Rail | Connector dimension |
|------|---------------------|
| OTel metrics | `connector` label (e.g. `defenseclaw_connector_hook_invocations_total{connector="codex"}`) |
| OTel spans / logs | `defenseclaw.connector.source` attribute |
| Audit rows + OTLP-ingest audit rows | top-level `connector` field, plus `structured.connector` on hook rows |
| Splunk HEC | top-level `connector`, and `structured.connector` on hook events |

Grafana's **Connectors (Overview)** and **Connector Detail** boards are built
on the `connector` metric label; the **Guardrail Evaluations** (Security) board
is connector-filterable via the multi-select `connector` template variable
(see §8.0.1). The egress firewall is **not** part of this per-connector
surface — it is one host-wide ruleset (see `docs/ARCHITECTURE.md` → Firewall
scope); per-connector guardrail policy is enforced inside the gateway above it.

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

   The AI signature catalog is extensible. DefenseClaw always loads the
   built-in catalog first, then merges operator-managed packs from
   `<data-dir>/signature-packs/*.json`, explicit files/directories/globs
   listed in `ai_discovery.signature_packs`, and workspace-local
   `.defenseclaw/ai-signatures.json` files only when
   `ai_discovery.allow_workspace_signatures=true`. Duplicate signature
   IDs fail closed at catalog load time, and
   `ai_discovery.disabled_signature_ids` suppresses individual built-in or
   custom signatures without editing the pack. Operators can manage packs
   with `defenseclaw agent signatures list|validate|install|disable|enable`.
   Pack JSON uses the same schema as `internal/inventory/ai_signatures.json`:
   `version: 1` plus a `signatures` array with `id`, `name`, `vendor`,
   `category`, `confidence`, and optional evidence fields such as
   `binary_names`, `process_names`, `application_names`, `config_paths`,
   `extension_ids`, `mcp_paths`, `package_names`, `env_var_names`,
   `domain_patterns`, `history_patterns`, and loopback-only
   `local_endpoints`.

### 9.2 SIEM consumer guidance

Audit events emitted from connector ingest paths carry the same v7
envelope shape as every other audit row and sink event. The most useful
fields to index are:

| Field | Type | Meaning |
|--------|------|---------|
| `schema_version` | integer | Required audit contract version. v7 events include provenance and three-tier agent identity. |
| `action` | enum | One of `connector-hook`, `connector-hook-synthetic`, `asset-policy`, `otel.ingest.{logs,metrics,traces,malformed}`, `codex.notify`, `codex.notify.<type>`, or `codex.notify.malformed`. Validators MUST accept the full enum and the `^codex\.notify\.[a-z0-9._-]{1,64}$` prefix family. |
| `actor` | string | Authenticated connector source from the `x-defenseclaw-source` header or the Gemini path token. Examples: `codex`, `claudecode`, `copilot`, `geminicli`, `unknown`. |
| `structured` | object | Machine-readable payload when the row has one. Connector hook rows use `schema="defenseclaw.hook.v1"` from `schemas/hook-audit-envelope.json`. |
| `details` | string | Legacy redacted summary. Connector-hook rows keep a quoted `details_json=` mirror during migration; new consumers should prefer `structured`. |
| `content_hash`, `generation`, `binary_version` | string/integer | Provenance for deterministic replay and dashboard bucketing. |

The matching OTel connector log contract
(`schemas/otel/connector-telemetry-event.schema.json`) carries
`event.name=defenseclaw.otel.ingest`, `defenseclaw.hook.invocation`,
or `defenseclaw.codex.notify` with connector `source`, `signal`,
and `result` fields; ingest and hook records also carry record count
and bytes, while notify records carry notify-specific fields. SIEM rules should
join on `defenseclaw.connector.source` to break down telemetry rate
per connector.

Continuous AI visibility uses the same envelope family with an
`ai_discovery` payload block (`event_type=ai_discovery`). Index
`ai_discovery.category`, `ai_discovery.vendor`, `ai_discovery.product`,
`ai_discovery.state`, and `ai_discovery.evidence_types` for shadow-AI
inventory reporting. Treat `path_hashes`, `basenames`, and
`workspace_hash` as correlation hints, not user-readable local paths.

### 9.3 Connector dashboard + alerts

Provisioned in `bundles/local_observability_stack/`:

- **DefenseClaw — Connectors (Overview)** dashboard
  (`bundles/local_observability_stack/grafana/dashboards/
  defenseclaw-connectors.json`, uid `defenseclaw-connectors`):
  cross-connector compare board — per-connector OTLP request rate,
  leaf-record volume, byte rate, malformed ratio, hook-vs-OTel drift,
  GenAI tokens / latency, identity assignment rate, and the live
  ingest log stream. The connector table cell deep-links into
  Connector Detail with `var-connector=...` preserved.

- **DefenseClaw — Connector Detail** dashboard
  (`defenseclaw-connector-detail.json`, uid
  `defenseclaw-connector-detail`): driven by the `$connector`
  template variable. Drills into one connector's identity (agent.id /
  agent.instance_id stability), OTLP ingest, hook results, verdicts,
  judge invocations, findings, HITL, SSE lifecycle, top tools, and
  Loki streams scoped to `defenseclaw_destination_app="$connector"`
  and `gen_ai_agent_name="$connector"`.

- **Recording rules** (`prometheus/rules/recording.yml` →
  `defenseclaw.connectors` group):
  `connector:defenseclaw_otel_ingest_requests:rate5m`,
  `connector:defenseclaw_otel_ingest_records:rate5m`,
  `connector:defenseclaw_otel_ingest_bytes:rate5m`,
  `connector:defenseclaw_otel_ingest_malformed:ratio_5m`,
  `connector:defenseclaw_otel_ingest_silence:seconds`,
  `connector:defenseclaw_codex_notify:rate5m`,
  `connector:defenseclaw_hooks:rate5m`,
  `connector:defenseclaw_hook_invocations:rate5m`,
  `connector:defenseclaw_hook_latency:p95_5m`,
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

### 9.4 Hook-only enforcement

The Codex, Claude Code, Hermes, Cursor, Windsurf, Gemini CLI, Copilot
CLI, and OpenHands connectors are hook-only. There is no LLM-proxy
data path — those agents talk directly to their native upstreams and
DefenseClaw observes / enforces via each connector's documented hook
bus. There is no proxy listener to enable for hook connectors; in
`guardrail.mode=action`, tool-call decisions are surfaced through the
hook's deny verdict.

For connectors that still bind the proxy (OpenClaw, ZeptoClaw), set
`guardrail.mode=action` and restart the gateway.

### 9.5 One-shot setup aliases

For operators who only want telemetry (no enforcement, no proxy
listener), DefenseClaw exposes dedicated setup paths that default to
`guardrail.mode=observe` and additionally pin `claw.mode` so the rest
of the CLI/TUI surfaces the matching connector's source-of-truth
files. The same aliases also accept `--mode action` for hook-native
blocking without inserting a proxy.

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
defenseclaw setup openhands --yes

# Hook-native blocking, still no proxy:
defenseclaw setup openhands --yes --mode action

# Optionally bring up the bundled Prom/Loki/Tempo/Grafana stack in
# the same step:
defenseclaw setup copilot --yes --with-local-stack
```

Both aliases persist:

| Field                                         | Value             | Why                                                                    |
|-----------------------------------------------|-------------------|------------------------------------------------------------------------|
| `claw.mode`                                   | selected connector | TUI / scanners read from the connector's documented local surfaces instead of the OpenClaw layout. |
| `guardrail.connector`                         | selected connector | Drives `Config.activeConnector()` (Go) and `Config.active_connector()` (Python). |
| `guardrail.enabled`                           | `true`            | Required so the gateway's `Connector.Setup()` runs and wires hooks + OTel + notify. |
| `guardrail.mode`                              | `observe` by default, `action` with `--mode action` | Default mode for hook-only connectors is observability-only; action mode blocks through the hook. |
| `<data_dir>/picked_connector`                 | selected connector | So `defenseclaw setup guardrail`, `init`, and quickstart default to the same connector on subsequent runs. |

After both aliases run, the gateway is restarted (unless `--no-restart`
is passed) so its connector setup hook scripts, OTel block, and
(codex only) notify bridge are reconciled with the running sidecar.
To revert and restore direct LLM access, run
`defenseclaw setup guardrail --disable`.
