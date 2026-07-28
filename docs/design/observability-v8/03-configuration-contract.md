# Configuration Contract

## 1. Version and Ownership

This contract applies when `config_version: 8` is present.

If the top-level `observability` block is absent, the full-fidelity defaults still
apply: every defined log, trace, and metric signal is collected, logs are retained
locally without content redaction, and no optional destination is initialized. An
empty `observability: {}` is equivalent. Operators who require minimization or
redaction configure it explicitly.

The top-level `observability` block becomes the single owner of:

- Collection policy.
- Bucket defaults.
- Redaction profile definitions.
- Optional-destination registry and routing.
- Process-wide trace sampling and metric export policy.
- Resource attributes.
- Built-in SQLite event/evidence retention.

### 1.1 Canonical machine schema

The machine-readable source of truth is
`schemas/config/v8/defenseclaw-config.schema.json`, with the observability contract
under `$defs.observability`. Its stable `$id` is
`https://schemas.defenseclaw.dev/config/v8/defenseclaw-config.schema.json`.
The `internal/config` maintainers own this schema; Go config types, the Python loader,
setup/TUI writers, examples, and generated Markdown/YAML references are consumers
and are checked against it. Generated references are never edited as an independent
truth. The schema carries `x-defenseclaw-owner: internal/config` so ownership is
machine visible.

Queue and batch fields are part of that same canonical schema rather than an
adapter-private configuration language. The P3 implementation change that adds
`batch.max_queue_bytes` and `batch.max_export_batch_bytes`, and permits the common
queue subset on JSONL and console destinations, MUST update the canonical schema,
Go/Python types and validators, generated references, and effective-plan rendering
atomically. A runtime adapter MUST NOT accept a hidden environment variable or an
unmodeled field as an alternative queue limit.

The legacy top-level `otel`, `audit_sinks`, and
`privacy.disable_redaction` blocks MUST be rejected. The existing
`observability.connectors[*].audit_sinks` child is legacy too and MUST be migrated
and rejected under v8. Existing `observability.connectors[*].webhooks` remain a
typed notification-only compatibility child: they are not destinations, do not
receive records through this router, and are outside collection/redaction routing.
A later notification redesign may move them under a separately versioned contract.
For the preserved webhook dimension, an absent connector key inherits the existing
top-level `webhooks` list, a present empty `webhooks: []` suppresses it for that
connector, and a present nonempty list overrides it. Its item schema remains the
existing `WebhookConfig` contract. None of those values creates a log route.
It still compiles into the notification subsystem rather than the signal router.

## 2. Complete Example

The following example is illustrative but syntactically normative:

```yaml
config_version: 8

observability:
  resource:
    attributes:
      service.name: defenseclaw-gateway
      deployment.environment.name: production
      organization.unit: security
      deployment.region: us-east-1

  trace_policy:
    sampler: parentbased_traceidratio
    sampler_arg: "0.10"
    semantic_profile: defenseclaw-genai-rich-v1
    compatibility_aliases: true
    limits:
      max_attributes_per_span: 128
      max_events_per_span: 64
      max_links_per_span: 32
      max_attributes_per_event: 32
      max_attribute_value_bytes: 16384
      max_projected_span_bytes: 262144
      max_stacktrace_bytes: 32768
      max_message_items: 128

  metric_policy:
    export_interval_seconds: 60
    temporality: delta

  # Explicit narrowing example. Omit defaults/buckets for full collection and
  # unredacted local storage.
  defaults:
    collect:
      logs: true
      traces: false
      metrics: false

  buckets:
    compliance.activity:
      collect: {logs: true, traces: false, metrics: true}
      redaction_profile: strict

    security.finding:
      collect: {logs: true, traces: false, metrics: true}
      redaction_profile: sensitive

    guardrail.evaluation:
      collect: {logs: true, traces: true, metrics: true}
      redaction_profile: sensitive

    model.io:
      collect: {logs: false, traces: true, metrics: true}
      redaction_profile: content

    tool.activity:
      collect: {logs: true, traces: true, metrics: true}
      redaction_profile: content

    diagnostic:
      collect: {logs: false, traces: false, metrics: false}
      redaction_profile: strict

  redaction_profiles:
    soc:
      extends: sensitive
      detectors: [pii, credentials, secrets]
      field_classes:
        credential: remove
        content: detect
        evidence: detect
        reason: detect
        path: hash
        error: detect

  # Optional overrides for the always-on built-in SQLite event-history store
  # and its separate judge-body forensic database.
  local:
    path: ~/.defenseclaw/audit.db
    judge_bodies_path: ~/.defenseclaw/judge_bodies.db
    retention_days: 90

  destinations:
    - name: operator-console
      kind: console
      routes:
        - name: hide-model-and-tool-content
          signals: [logs]
          selector:
            buckets: [model.io, tool.activity]
          action: drop
        - name: show-operational-events
          signals: [logs]
          selector:
            buckets: ["*"]
          action: send
          redaction_profile: strict

    - name: local-jsonl
      kind: jsonl
      path: ~/.defenseclaw/gateway.jsonl
      rotation:
        max_size_mb: 50
        max_backups: 5
        max_age_days: 30
        compress: true
      # Optional advanced override. Omitting batch keeps the same bounded queue
      # with the reviewed defaults shown by config show --effective.
      batch:
        max_queue_size: 2048
        max_queue_bytes: 67108864
      send:
        signals: [logs]
        buckets: ["*"]
        redaction_profile: sensitive

    - name: prometheus
      kind: prometheus
      listen: 127.0.0.1:9464
      path: /metrics
      send:
        signals: [metrics]
        buckets:
          - compliance.activity
          - security.finding
          - guardrail.evaluation
          - enforcement.action
          - model.io
          - tool.activity
          - asset.scan
          - platform.health
          - telemetry.ingest

    - name: splunk-production
      kind: splunk_hec
      endpoint: https://splunk.example.test:8088/services/collector/event
      token_env: SPLUNK_HEC_TOKEN
      batch:
        max_queue_size: 2048
        max_queue_bytes: 67108864
        max_export_batch_size: 256
        max_export_batch_bytes: 8388608
        scheduled_delay_ms: 1000
      routes:
        - name: security-and-enforcement
          signals: [logs]
          selector:
            buckets:
              - security.finding
              - guardrail.evaluation
              - enforcement.action
              - network.egress
            min_severity: HIGH
          action: send
          redaction_profile: soc
        - name: compliance
          signals: [logs]
          selector:
            buckets: [compliance.activity]
          action: send
          redaction_profile: strict

    - name: general-otel
      kind: otlp
      protocol: http/protobuf
      endpoint: https://otel.example.test
      headers:
        Authorization:
          env: OTEL_AUTHORIZATION
      tls:
        insecure: false
        ca_cert: /etc/defenseclaw/otel-ca.pem
      signal_overrides:
        logs: {path: /v1/logs}
        traces: {path: /v1/traces}
        metrics: {path: /v1/metrics}
      batch:
        max_queue_size: 4096
        max_queue_bytes: 134217728
        max_export_batch_size: 512
        max_export_batch_bytes: 16777216
        scheduled_delay_ms: 5000
      routes:
        - name: operational-logs-and-metrics
          signals: [logs, metrics]
          selector:
            buckets: [platform.health, telemetry.ingest]
          action: send
          redaction_profile: strict
        - name: runtime-traces-and-metrics
          signals: [traces, metrics]
          selector:
            buckets: [guardrail.evaluation, tool.activity, model.io]
          action: send
          redaction_profile: sensitive

    - name: galileo
      kind: otlp
      preset: galileo
      endpoint: https://api.galileo.ai/otel/traces
      headers:
        Galileo-API-Key:
          env: GALILEO_API_KEY
        project: defenseclaw
        logstream: production
      batch:
        scheduled_delay_ms: 1000
      send:
        signals: [traces]
        buckets:
          - agent.lifecycle
          - model.io
          - tool.activity
          - guardrail.evaluation
        redaction_profile: sensitive
```

### 2.1 Source-to-effective compilation

The source form above is not the runtime representation. Before runtime resources
are initialized, the configuration compiler deterministically:

1. Resolves the config-version catalog default.
2. Adds the non-disableable generated local SQLite destination and unredacted
   catch-all log projection.
3. Resolves omitted optional-destination `enabled` to `true`.
4. Expands every concise `send` block into one generated route; when an enabled
   optional destination omits both `send` and `routes`, generates a capability-wide
   unredacted send for every catalog bucket.
5. Derives OTLP enabled signals from the union of generated/advanced route signals.
6. Resolves destination presets, redaction inheritance, transport defaults,
   queue/batch count and byte limits, and route indexes.

The masked effective view displays those generated objects with provenance. Keys
such as `generated` and the generated local destination are diagnostic output, not
accepted source YAML. Concise and advanced source forms therefore share one runtime
router and one test contract rather than creating parallel pipelines.

## 3. Collection Policy

For `config_version: 8`, omitted `observability.bucket_catalog_version` resolves to
catalog version 1, which contains the fourteen buckets in
`02-taxonomy-and-data-model.md`. The field is written only when an operator advances
to a later catalog. Catalog evolution and wildcard behavior are defined in
`09-configuration-ux-and-bucket-evolution.md`.

### 3.1 Effective collection

For a bucket and signal, effective collection is resolved in this order:

1. `observability.buckets.<bucket>.collect.<signal>` when present.
2. `observability.defaults.collect.<signal>` when present.
3. The bucket's versioned catalog default.

Catalog v1 defaults logs, traces, and metrics to `true` for all fourteen buckets.
A producer records only signal families/instruments the bucket actually defines;
this default does not manufacture empty telemetry.

Catalog v1 defaults every bucket's redaction profile to `none`, including
`model.io`, `tool.activity`, and `diagnostic`. This intentionally preserves complete
prompt, response, argument, result, evidence, reason, path, and error fields when
the producer reports them and schema/size limits allow them.

There is no separate default-off content-capture switch. Enabling a log or trace
family authorizes capture of its registered content fields; `none` preserves them
and an explicit redacting profile transforms/removes them at projection. A producer
that never received or cannot report a field marks it unreported rather than
inventing a value.

Bucket keys not present under `buckets` remain valid catalog buckets and inherit the
full-fidelity defaults. Unknown bucket keys are invalid.

### 3.2 Meaning of disabled collection

- `logs: false`: normal log objects for the bucket are not created. Mandatory-floor
  logic may create a minimal SQLite-only record.
- `traces: false`: instrumentation for that bucket returns a no-op span or avoids
  constructing span events and attributes.
- `metrics: false`: instruments for that bucket do not record a measurement.

A destination route cannot override collection.

### 3.3 Effective default redaction

For a delivered log or trace, the effective redaction profile is resolved in this
order:

1. Concise `send.redaction_profile` or advanced `route.redaction_profile`.
2. `observability.buckets.<bucket>.redaction_profile`.
3. `observability.defaults.redaction_profile`.
4. The bucket's versioned catalog redaction default.

The implicit catalog profile is `none`. It is valid at every resolution level,
including defaults, bucket policy, optional destinations, and the built-in local
store. The complete built-in name set is `none`, `sensitive`, `content`, `strict`,
and the immutable migration-compatibility profile `legacy-v7`. `legacy-v7` is a
valid explicit reference but cannot be extended or aliased; its exact projection
contract is defined in `04-redaction-contract.md`. An explicitly named unknown
profile is invalid.

Custom-profile source grammar is closed: `extends`, `detectors`, and
`field_classes` are the only permitted members. Detector scan bytes, candidate and
match limits, correlation-token/report lengths, custom excerpts, key material, and
correlation-key paths are fixed by 04 §§6-7 and MUST be rejected if supplied as
configuration. The sole key path is derived from `data_dir`; there is no v8
environment-variable equivalent.

## 4. Destination Registry

### 4.1 Built-in local store

SQLite is not an operator-authored destination. Exactly one built-in event-history
store, `audit.db`, always exists, receives every collected log plus floor-only
records, and cannot be disabled or filtered. Its default projection is unredacted.
The separate `judge_bodies.db` forensic database is not a destination, does not
receive ordinary logs or compliance-floor records, and is not counted as a second
built-in event-history store. The optional `observability.local` object exposes
only:

- `path`: defaults to `<data_dir>/audit.db`.
- `judge_bodies_path`: defaults to `<data_dir>/judge_bodies.db`.
- `retention_days`: defaults to `90`; `0` retains forever and MUST produce a
  persistent lint/doctor capacity warning explaining that event, evidence, and
  retained judge-body history are unbounded by age.

Both database paths are restart-required and must differ from each other and every
other configured file after lexical normalization and canonical/real-path
resolution (including existing symlink targets). Validation rejects `..`, symlink,
hard-link/inode, or other aliases that make the two database roles or another
configured file collide. `audit.db` always initializes and any initialization or
write-capability failure is a mandatory local-durability startup failure.
`judge_bodies.db` is initialized when `guardrail.retain_judge_bodies` is effective
true or an upgrade/cutover has legacy judge bodies to process; failure in either
case fails startup or the required upgrade before serving. When capture is disabled
and no cutover work exists, the path is still validated but the gateway need not
open the database. The guardrail Boolean controls whether new raw bodies are
captured; the one shared `observability.local.retention_days` value controls the age
of retained event, evidence, and judge-body history. Local log redaction resolves
from bucket policy, configured global policy, and the catalog default and may
resolve to `none`.

The effective view exposes a generated `local-sqlite` destination and catch-all log
projection for debugging, clearly marked `generated: true`; these are not accepted
as source keys.

### 4.2 Optional destination common fields

Every optional destination has:

- `name`: required, unique, nonempty stable identifier.
- `kind`: required supported kind.
- `enabled`: optional; defaults to `true`. Explicit `false` retains policy without
  initializing the transport.
- At most one of `send` or `routes`. When an enabled destination supplies neither,
  the compiler generates its capability-default send.

Disabled destinations are still structurally validated, but secret resolution and
network initialization MAY be deferred until enabled.

The name `local-sqlite` is reserved for the generated effective destination and is
invalid on an operator-authored optional destination.

### 4.2.1 Capability-default send

An enabled destination with neither `send` nor `routes` receives every catalog
bucket, uses `redaction_profile: none`, and selects every signal supported by its
kind:

| Kind | Generated default signals |
|---|---|
| `jsonl`, `console`, `splunk_hec`, `http_jsonl` | `[logs]` |
| `prometheus` | `[metrics]` |
| `otlp` | `[logs, traces, metrics]` |

A preset may narrow the adapter's declared capability only when the backend truly
does not support a signal; for example, a traces-only vendor preset generates
`[traces]`. The effective view shows the declared capability and generated send.
Explicit `send` or `routes` fully replaces this generated policy and is how an
operator narrows buckets/signals or applies redaction.

For a mixed OTLP default, `none` applies to log bodies and trace attributes/events.
Metrics are exported in full but remain subject to the metric schema's prohibition
on content-bearing or unbounded labels; “unredacted metrics” does not authorize
turning prompts, responses, arguments, paths, or evidence into metric attributes.

### 4.3 Destination capabilities

| Kind | Logs | Traces | Metrics | Notes |
|---|---:|---:|---:|---|
| `jsonl` | Yes | No | No | File output with rotation behavior preserved from current implementation |
| `console` | Yes | No | No | Human-readable stderr/stdout projection |
| `splunk_hec` | Yes | No | No | Structured HEC events |
| `http_jsonl` | Yes | No | No | Batched or individual JSONL over HTTP |
| `prometheus` | No | No | Yes | Pull endpoint; routes filter exposed instruments/series |
| `otlp` | Yes | Yes | Yes | Enabled signal transports are derived from policy |

`preset: galileo` is valid only with `kind: otlp`. A preset supplies documented
defaults and validation but does not override explicitly provided values. It does
not create a separate routing model. It expands a versioned Galileo compatibility
profile for agent, LLM, tool, retriever, and workflow spans; the profile validates
an already-routed, already-redacted projection and does not hide bucket routes.
Effective config shows the exact profile version and eligible span shapes.

Every general `otlp` destination that selects traces also exposes the generated
`openinference-v1` compatibility capability in its effective plan. For an eligible
family, its destination-private trace projection derives OpenInference kind and
input/output aliases only from the already route-redacted canonical values. A
nonmember family remains a canonical OTel span without OpenInference aliases;
malformed eligible input, an alias collision, or generated-capability drift fails
that destination projection closed. Galileo and `local-observability-v1` retain
their separate mutually exclusive projectors and never pass through this generic
OTLP compatibility arm.

### 4.4 Common transport fields

Every queue-backed optional destination uses one concise `batch` object. JSONL and
console use its queue subset; Splunk HEC, HTTP JSONL, and OTLP additionally use its
push-batch subset. The object is optional in source YAML, so a normal destination
does not require queue boilerplate. Prometheus is pull-based, owns no delivery
queue, and rejects `batch`.

The common vocabulary is:

| Field | Meaning |
|---|---|
| `endpoint` | Destination URL or OTLP authority/base URL |
| `headers` | Static non-secret values or `{env: NAME}` secret/value references |
| `timeout_ms` | Per-attempt transport timeout; positive bounded integer |
| `tls.insecure_skip_verify` | Explicit unsafe HTTPS certificate bypass for HTTP adapters; default false and warning required when true |
| `tls.insecure` | OTLP plaintext/insecure transport selector; default false and warning required when true |
| `tls.ca_cert` | Optional trusted CA file subject to config-path trust checks |
| `batch.max_queue_size` | Maximum queued projected records; default 2,048, valid range 1 through 65,536 |
| `batch.max_queue_bytes` | Maximum sum of immutable projected payload bytes retained by the queue; default 67,108,864 (64 MiB), valid range 4,198,400 through 268,435,456 (256 MiB) |
| `batch.max_export_batch_size` | Push-only maximum records per request; default 512, valid range 1 through 8,192, and cannot exceed `max_queue_size` |
| `batch.max_export_batch_bytes` | Push-only hard ceiling for one encoded request; default 8,388,608 (8 MiB), valid range 4,263,936 through 67,108,864 (64 MiB) |
| `batch.scheduled_delay_ms` | Push-only maximum normal batching delay; default 5,000, valid range 1 through 600,000 |
| `network_safety.allow_private_networks` | Reviewed opt-in for loopback, RFC1918, and IPv6 ULA collector endpoints; default false |
| `network_safety.allow_cgnat` | Reviewed opt-in for RFC 6598 CGNAT/overlay endpoints; default false |

The compiler makes all omitted adapter defaults visible in the effective plan:

- JSONL rotation defaults to 50 MiB, five backups, 30 days, and compression on;
  explicit zero backups/age and `compress: false` remain distinguishable.
- HTTP JSONL method defaults to `POST`.
- Every queue-backed destination defaults to a 2,048-record, 67,108,864-byte
  queue. JSONL and console perform ordered single-record writes from that queue;
  their source `batch` object therefore accepts only `max_queue_size` and
  `max_queue_bytes`.
- Push timeout defaults to 10,000 ms. Push batching additionally defaults to a
  512-record, 8,388,608-byte maximum request and 5,000 ms scheduled delay.
  Export batch count may not exceed queue count. Queue bytes count immutable
  projected payloads, while batch bytes count the fully encoded request, so those
  two independently bounded byte fields have no invalid cross-field ordering. A
  destination wrapper added after redaction is bounded to 65,536 bytes per record,
  which is why the minimum push-batch byte ceiling is the maximum 4,198,400-byte
  projection plus that wrapper allowance.
- General OTLP protocol defaults to `grpc`. `preset: galileo` instead expands to
  `galileo-rich-v2`, requires `http/protobuf`, and overrides only the omitted
  scheduled delay to 1,000 ms as locked by P-043. General OTLP trace capability
  expands the generated `openinference-v1` projection without changing its logs,
  metrics, protocol, queue, or route defaults.
- TLS unsafe modes and both network-safety opt-ins default false. Omitted values
  never inherit exporter behavior from ambient OTel environment variables.

Static inline authorization secrets are discouraged and must be masked if retained
for compatibility. New generated configurations use environment or key-store
references.

Header maps contain at most 128 entries. Names use the HTTP token grammar, are
unique ignoring case, and cannot override transport-owned fields (`Host`,
`Content-Length`, `Content-Type`, connection/hop-by-hop headers, trailers, or
transfer framing). gRPC OTLP additionally rejects `grpc-*`, binary `*-bin`, and
names outside the supported gRPC metadata grammar. These checks occur during
source validation; a configuration that the selected adapter cannot prepare is
not reported as valid.

An explicit `http://` endpoint remains valid for intentional local or legacy
collectors. When Splunk authentication, a bearer token, an authentication-like
static header, or any secret-provider-backed header is present, preparation MUST
emit a bounded `plaintext_credentials` startup/reload warning and mandatory
`compliance.activity` event naming only the destination. It never includes the
endpoint, header name/value, reference name, or resolved secret. Unauthenticated
HTTP emits no credential warning. HTTPS and OTLP TLS policy remain unchanged.

#### 4.4.1 Push-destination network safety

Every enabled `splunk_hec`, `http_jsonl`, and `otlp` destination MUST use the shared
outbound network guard at endpoint validation and at every connection/reconnection.
This is a transport invariant, including destinations created by presets:

- Only the selected transport's documented HTTP(S) or gRPC scheme is accepted.
  Inline URL user information is invalid.
- By default, every DNS answer and literal address is rejected when it is loopback,
  RFC1918 private space, IPv6 ULA, RFC 6598 CGNAT, link-local, unspecified,
  multicast/reserved, or a known cloud/container metadata or task-credential
  endpoint. Mixed public/private DNS answers are rejected.
- Resolution is repeated and enforced by the guarded dial path so validation cannot
  be bypassed by DNS rebinding. Exporter redirects are disabled; an adapter that
  cannot disable them is invalid for v8 rather than following an unvalidated hop.
- A syntactically invalid or currently resolved prohibited endpoint makes the new
  config graph invalid and leaves the old graph active on reload. A temporary DNS or
  network failure sends no request, marks only that optional destination degraded,
  and retries through the same guard. It never falls back to an unguarded client or
  another endpoint.
- `network_safety.allow_private_networks: true` is the only push-destination opt-in
  for an intentional local/private collector; it permits loopback, RFC1918, and IPv6
  ULA only. `network_safety.allow_cgnat: true` separately permits RFC 6598. Either
  option emits a startup/reload warning, persistent doctor/TUI warning, and mandatory
  `compliance.activity` record naming the destination but no credentials.
- Link-local space, cloud/container metadata and task-credential endpoints,
  unspecified/multicast/reserved addresses, and inline credentials remain blocked
  even with either opt-in. There is no environment-only or global push-exporter SSRF
  bypass in v8.
- Explicit plaintext HTTP with resolved authentication or secret-backed headers
  remains supported for compatibility but always emits the content-free
  `plaintext_credentials` warning/audit. This warning is independent of the
  private-network opt-ins and cannot be suppressed through environment state.

Unsafe-endpoint health records use `platform.health`, contain a bounded reason code,
and MUST NOT echo credentials, headers, URL user information, or sensitive query
values.

The offline `config validate` command checks URL syntax, literal addresses, and
policy but performs no DNS/network I/O. Enabled-destination activation and the
explicit destination-test command perform the guarded resolution; the effective
validation output states whether network checks were not run.

Kind-specific fields are:

| Kind | Fields |
|---|---|
| `jsonl` | `path`, `rotation.max_size_mb`, `rotation.max_backups`, `rotation.max_age_days`, `rotation.compress`, queue-only `batch.{max_queue_size,max_queue_bytes}`, plus existing file permission/reopen behavior |
| `console` | No required transport fields; optional queue-only `batch.{max_queue_size,max_queue_bytes}`; output stream/format behavior remains adapter-defined and schema-documented |
| `prometheus` | `listen`, `path` |
| `splunk_hec` | `endpoint`, `token_env`, optional `index`, `source`, `sourcetype`, `sourcetype_overrides`, TLS/timeout/full batch |
| `http_jsonl` | `endpoint`, optional `method`, `headers`, `bearer_env`, TLS/timeout/full batch |
| `otlp` | `protocol`, `endpoint`, `headers`, optional `logger_name`, TLS/timeout/full batch, optional `signal_overrides.<signal>.{endpoint,path}` |

`sourcetype_overrides` is a bounded map from registered audit action to Splunk
sourcetype. It changes only the adapter envelope; it does not reclassify the
canonical record or replace route selectors. `logger_name` is the bounded OTel log
instrumentation-scope name used by a log-capable OTLP destination. It likewise has
no routing or schema-selection effect. Both fields are retained because they are
operator-visible v7 adapter behavior, not implementation-only constants.

Any flattened or legacy-compatible fields in the Splunk HEC event wrapper MUST be
derived only from the already-redacted, schema-validated projected bytes selected
for that Splunk destination. The adapter may parse those immutable bytes to copy a
projected action, identifier, correlation value, or body field into a documented
alias, but it MUST NOT receive or recover the canonical `Record`, a producer event,
a pre-redaction body, or another destination's projection. If the selected profile
removed a value, the alias is omitted; there is no raw fallback. The embedded
projected record remains byte-identical, wrapper aliases equal their projected
source values, and opaque producer-supplied extra HEC events are invalid.

Every configurable adapter field must be present in the canonical schema and the
generated all-knobs reference. Internal constants that are intentionally not
operator tunable must not be presented as YAML knobs.

### 4.5 OTLP-specific validation

- Protocol values are `grpc`, `grpc/protobuf`, `http`, or `http/protobuf`.
  `http/json` is rejected because the current Go OTLP exporters encode protobuf;
  accepting it would mislabel the wire format.
- Enabled signal transports are the union of signals in the destination's generated
  capability-default send, explicit `send` block, or advanced routes. There is no
  second transport enablement switch.
- `signal_overrides` may contain only selected signals and may change endpoint/path
  details, not enable an otherwise unselected signal. A `path` override is valid
  only for `http`/`http/protobuf`; gRPC OTLP service method paths are fixed by the
  protocol, so `grpc`/`grpc/protobuf` destinations with a nonempty path fail
  validation instead of silently ignoring it.
- OTLP endpoint URLs cannot contain query or fragment data. gRPC endpoint URLs
  cannot contain a non-root path. For URL-form endpoints, `http://` requires
  `tls.insecure: true` and `https://` requires it to remain false. These rules
  apply after resolving each signal override as well as to the destination base.
- A v8 OTLP destination has one protocol. Automatic migration of a v7 destination
  whose selected signals use different effective protocols creates deterministic
  signal-specific destinations instead of adding a hidden per-signal protocol
  exception or guessing one protocol.
- Each selected signal resolves an endpoint from its override or the destination
  endpoint.
- Trace sampling is process-wide under `trace_policy`; a destination cannot request
  spans already removed by sampling.
- Metric export interval and temporality are process-wide unless the SDK can provide
  an independent reader without semantic conflict. Destination configuration may
  supply transport batching but not redefine instrument meaning.

### 4.6 Secret-bearing fields

Tokens, authorization headers, and credentials MUST support environment or key-store
references. New v8 source does not require an inline secret compatibility form.
During automatic migration, a v7 inline token, bearer token, or interpolated header
such as `Basic ${TOKEN}` is converted to one deterministic environment reference
whose value is the complete effective secret/header value. That value is written
only through the ancillary locked, backed-up, rollback-capable `.env` update;
it never enters v8 YAML, a candidate/diff object, migration output, doctor/TUI
display, an error, or a compliance record. The generated environment-variable name
is stable for the source destination and field so retry cannot create duplicate
`.env` entries.

Explicit v8 observability policy is not implicitly overridden by legacy DefenseClaw
or standard OTel environment variables. Only documented bootstrap variables and
source-declared secret references participate, as defined in
`09-configuration-ux-and-bucket-evolution.md`.

## 5. Routes

### 5.1 Concise `send` form

The normal authoring form is one `send` object:

```yaml
send:
  signals: [traces]
  buckets: [model.io, tool.activity, guardrail.evaluation]
  redaction_profile: sensitive
```

- `signals` is required and nonempty.
- `buckets` is required and contains exact bucket IDs or the sole value `"*"`.
- `redaction_profile` is optional; logs/traces fall back to bucket/global policy.
  It is rejected on metric-only sends because metrics contain no content fields.
- No source, connector, action, event-name, severity, exclusion, or ordering logic
  is accepted in this form; those requirements use advanced routes.

The compiler expands `send` into one route named `send` with `generated: true` in
the effective graph. It is deterministic and never written back to source YAML.

### 5.2 Advanced route shape

A route has:

- `name`: required and unique within the destination.
- `signals`: required nonempty list.
- `selector`: required object.
- `action`: optional; defaults to `send`; values are `send` or `drop`.
- `redaction_profile`: valid for send routes on log or trace destinations; ignored
  fields are rejected rather than silently accepted.

Metrics never contain content fields, so metric-only send routes do not require a
redaction profile. If a route includes logs or traces, profile resolution is
required. `send` and `routes` are mutually exclusive.

### 5.3 Selector fields

Supported selector fields are:

- `buckets`
- `sources`
- `connectors`
- `actions`
- `event_names`
- `min_severity`

No other selector field is accepted in v8.

### 5.4 Selector logic

- Different fields are ANDed.
- Multiple values within a field are ORed.
- Values are exact, case-sensitive canonical values after producer normalization.
- For traces, `event_names` matches the stable registered trace family ID (for
  example `span.model.chat`), not the rendered OTel span name containing a model,
  tool, route, or other operation value.
- The literal `"*"` is the only wildcard and must be the sole value in that field.
- Regex, glob, prefix, negation, and arbitrary expression syntax are not supported.
- An absent selector field places no constraint on that dimension.
- An empty selector value list is invalid.
- If the record lacks a field selected by the route, the route does not match.
- `min_severity` is a single canonical severity and matches equal or greater values.
  A record with absent severity does not match it.
- For optional destinations, bucket wildcard matches all buckets in the effective
  reviewed catalog version and does not silently include future runtime buckets.

### 5.5 Compilation and evaluation

For every collected canonical record:

1. Iterate enabled destinations independently.
2. Skip destinations that cannot accept the record’s signal.
3. Use the generated route for concise `send`, or iterate advanced routes in YAML
   order.
4. A route is eligible only if its `signals` contains the record signal.
5. Evaluate its selector.
6. On the first match, perform `send` or `drop` and stop evaluating routes for that
   destination and signal.
7. If no route matches, do not deliver to that destination.

First-match-wins is not global. A record matching Splunk and two OTLP destinations
is delivered to all three, each with its own projection, in addition to mandatory
local persistence.

### 5.6 Why `drop` exists

`drop` supports exclusions before a broad catch-all. Example: drop diagnostics,
then send `"*"`. Without an explicit drop action, exclusion behavior would depend on
fragile route omissions.

### 5.7 Unredacted delivery

`redaction_profile: none` is the catalog and capability-default behavior. It needs no
break-glass flag and does not by itself generate a startup warning or mandatory
event. Source, effective, plan, doctor, and TUI views MUST display the effective
profile as `none`/`unredacted` rather than hiding it behind “default.” Any
configuration change to collection, routing, or redaction remains ordinary
`compliance.activity` regardless of whether it strengthens or weakens redaction.

Unredacted delivery does not let a destination read producer objects directly: it
still receives a cloned, schema-validated, bounded projection through the central
redaction boundary with the `none` transform.

## 6. Resource, Sampling, and Metrics Policy

- `observability.resource.attributes` contains the configurable registered core
  keys (`service.name`, `deployment.environment.name`, `tenant.id`, and
  `workspace.id`) plus custom process-stable attributes. The legacy
  `deployment.environment` spelling canonicalizes to
  `deployment.environment.name`; equal dual spellings collapse and conflicting
  values fail. The block accepts at most 64 entries; names are 1-128 ASCII bytes matching
  `^[A-Za-z][A-Za-z0-9_.-]{0,127}$`; values are nonblank, control-free strings of
  1-1,024 UTF-8 bytes; and the aggregate encoded key-plus-value budget is 16 KiB.
  The compiler stores registered core values separately from a bytewise-key-sorted
  generated immutable custom-resource value and rejects invalid input without
  rendering the value in diagnostics. The value owns at most 64 detached string
  entries, exposes only copy-returning accessors, and is the sole runtime form of
  custom resource data; providers, builders, and destinations do not re-parse the
  YAML map or accept an unvalidated map/slice substitute. Custom entries are
  classified `metadata`/`internal`, remain process-stable, and cannot collide with
  fixed core, process-owned, or compatibility-alias keys.
- Other registered identity, process-owned keys, preset markers, and
  compatibility-alias spellings are invalid in source. DefenseClaw derives those
  canonical values and documented legacy aliases from trusted runtime identity;
  custom configuration cannot override or collide with them. Custom attributes
  otherwise apply to all OTLP destinations through the same immutable generation
  plan.
- Secret-bearing resource attributes are invalid.
- When `trace_policy.sampler` is omitted, collected traces use
  `parentbased_always_on`; bucket trace collection is true by catalog default. Ratio
  samplers require a valid `sampler_arg`.
- Trace sampler and argument are validated before providers are built.
- `trace_policy.semantic_profile` selects a shipped immutable telemetry-registry
  profile. v8 supports `defenseclaw-genai-rich-v1`; arbitrary operator-defined
  attribute schemas are invalid. That profile resolves through
  `schemas/telemetry/v8/registry.yaml` to one exact trace-schema, locked GenAI
  semantic-convention, OpenInference, and Galileo compatibility-profile tuple.
  Operators cannot override tuple members independently, and a lock mismatch is a
  build/startup validation error.
- `trace_policy.compatibility_aliases` controls only documented legacy aliases. It
  never bypasses redaction. Migrated v7 configurations default it to true for the
  declared compatibility window; new configurations use the release default shown
  by the effective view. When true, exactly these aliases are derived from the same
  canonical value: `deployment.environment <- deployment.environment.name`,
  `deployment.mode <- defenseclaw.deployment.mode`, and
  `defenseclaw.device.id <- defenseclaw.device.public_key_fingerprint`. When false,
  all three are absent. An alias is never independently configurable or allowed to
  disagree with its canonical source. Legacy `discovery.source` is not a v8 process
  resource; discovery provenance belongs on its registered operation/log family.
- One generation-owned resource snapshot supplies SDK traces and metrics,
  generated canonical trace records, OTLP logs, general OTLP projection, and
  Galileo projection. Every enabled OTLP signal therefore carries the same
  registered core, custom entries, and enabled aliases. Exact canonical/physical
  trace handoff compares the complete schema URL, key set, string types, and
  values; no physical-only extra is accepted. Native Prometheus remains governed
  by its generated label catalog and does not automatically expose arbitrary
  resource labels.
- `trace_policy.limits` accepts positive bounded values for attributes, events,
  links, event attributes, attribute bytes, total projected span bytes, stack-trace
  bytes, and message/document items. Values above hard safety ceilings are invalid;
  values below a family’s required shape are invalid.
- Bucket collection and sampling both apply: collection decides whether a span may
  exist; sampling decides whether an otherwise enabled trace is recorded/exported.
- The rich span-family, event, link, status, content-state, Galileo, and overflow
  rules in `11-trace-and-span-contract.md` are normative.
- The telemetry registry and generated-schema rules in
  `12-telemetry-schema-architecture.md` are normative.
- The PR #403 agent-lifecycle and PR #412 local-dashboard compatibility rules in
  `14-agent-lifecycle-and-dashboard-compatibility.md` are normative. The
  `local-observability-v1` consumer profile is bundle/registry metadata rather than
  another per-destination routing switch: setup/plan validates whether the local
  OTLP destination's ordinary bucket/signal policy satisfies it and reports partial
  dashboard coverage when an operator narrows that policy.
- Metric temporality and interval must be compatible with all enabled metric
  destinations.
- Omitted metric policy defaults to a 60-second delta export policy; bucket metric
  collection is true by catalog default. The bundled local collector converts delta
  sums to cumulative monotonic Prometheus series, and its Grafana datasource
  advertises a minimum 60-second interval so `$__rate_interval` has sufficient
  samples.

## 7. Atomic Reload

### 7.1 Reloadable fields

The following are live reloadable:

- Bucket collection policy.
- Concise send policies; advanced route order, selectors, actions, and profiles.
- Redaction profile composition.
- Optional destination enablement and transport settings.
- Retention age.
- Resource attributes where the SDK supports provider rebuild.
- Sampling, trace semantic profile/limits/compatibility aliases, and metric export
  policy through provider rebuild.
- Reviewed bucket catalog version.

### 7.2 Restart-required fields

- SQLite database path.
- Judge-body database path.
- `guardrail.retain_judge_bodies`, because it changes the authoritative raw-body
  database and async-writer lifecycle. Reload reports this exact field path and
  does not publish the new value while the old capture state remains active.
- Any listener binding that cannot be atomically replaced on the current platform.

A reload that changes a restart-required field is rejected with an actionable
message; the old graph remains active.

### 7.3 Reload transaction

1. Parse and strictly validate the complete new configuration off-path.
2. Resolve profiles, compile route indexes, and validate catalog completeness.
3. Initialize new optional exporters and processors without publishing them.
4. Confirm required local resources remain valid.
5. Atomically swap one immutable policy/runtime graph pointer.
6. Stop intake to removed exporters and drain them within the shutdown deadline.
7. Record a compliance activity outcome.

If any operation before the step 5 swap fails, nothing is swapped and the existing
graph remains active. Before returning the reload failure, the implementation MUST
shut down every exporter and processor that initialization entered for the
unpublished graph: successfully initialized components, the component whose
initialization failed, and any child queue worker, connection, listener, timer, or
other resource that either acquired before returning its error. Cleanup unwinds in
reverse initialization order within the shutdown deadline. Teardown failure is
reported through the still-active graph as destination/platform health and in the
mandatory reload-failure compliance record; an initialized or partially initialized
off-path component MUST NOT remain live after a rejected reload.

## 8. Legacy Rejection and Migration

The gateway MUST return actionable validation errors such as:

- `otel is a v7 field; run defenseclaw upgrade (optional preview: defenseclaw setup observability migrate-v8 --dry-run)`
- `audit_sinks is replaced by observability.destinations`
- `privacy.disable_redaction is a v7 field; run defenseclaw upgrade; v8 redaction is configured with observability defaults, bucket policies, and destination send/routes`

It MUST NOT silently reinterpret, merge, or prioritize old and new blocks.
