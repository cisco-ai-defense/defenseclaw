# DefenseClaw Observability v8

DefenseClaw v8 has one observability pipeline and one configuration surface:

```text
producer -> bucket -> collection -> canonical record
                                      |
                                      +-> mandatory local SQLite projection
                                      |      (bucket/global redaction profile)
                                      +-> destination A: select -> redact -> deliver
                                      +-> destination B: select -> redact -> deliver
                                      +-> destination N: select -> redact -> deliver
```

Logs, traces, and metrics are classified in a versioned bucket catalog. Collection,
routing, redaction, retention, resource attributes, sampling, and transport settings
all live under `observability:` in `~/.defenseclaw/config.yaml`.

The defaults favor simple, full-fidelity operation:

- every registered log, trace, and metric is collected;
- local SQLite stores every collected log unredacted;
- an enabled destination with no `send` or `routes` exports every signal that kind
  supports, from every bucket, unredacted; the Galileo preset further restricts
  its generated trace route to available compatibility-profile families;
- multiple destinations receive independent copies; one destination's failure or
  filter does not alter another destination;
- local SQLite is always present and cannot be disabled or filtered.

These defaults can contain prompts, model outputs, tool arguments, evidence, paths,
and identifiers. Apply a redaction profile before exporting to a destination whose
trust boundary does not permit that content.

## Minimal configuration

Fresh v8 configuration needs no observability boilerplate:

```yaml
config_version: 8
observability: {}
```

The effective plan expands the versioned defaults without writing hundreds of
derived lines into the source file:

```bash
defenseclaw config validate
defenseclaw config show --effective --section observability
defenseclaw config reference observability
defenseclaw observability plan
```

Use `config reference observability` to discover every knob, then copy only deliberate
overrides into the source file. The complete generated source example is
[`schemas/config/v8/reference/observability.yaml`](../schemas/config/v8/reference/observability.yaml).
Do not edit that generated reference or paste it over the source file.

## Buckets

Buckets describe why a record exists, not where it is sent:

| Bucket | Contains |
|---|---|
| `compliance.activity` | Operator, service, and system control-plane actions, including administrative authentication failures |
| `security.finding` | Durable security observations with evidence, status, and remediation |
| `guardrail.evaluation` | One runtime inspection and its decision, including clean evaluations |
| `enforcement.action` | Applied or attempted block, quarantine, disable, allow, and approval actions |
| `model.io` | Model request/response operations, usage, latency, and permitted content |
| `tool.activity` | Tool invocation, arguments/results, status, and latency |
| `asset.scan` | Skill, MCP, plugin, and source scan execution details |
| `asset.lifecycle` | Asset discovery, install, enable, disable, quarantine, restore, and removal transitions |
| `network.egress` | Network requests and egress policy decisions |
| `agent.lifecycle` | Root agent, subagent, turn, execution, phase, delegation, and workflow lifecycle |
| `ai.discovery` | AI runtime/component discovery observations and inventory |
| `telemetry.ingest` | Inbound OTLP acceptance, rejection, normalization, and re-export accounting |
| `platform.health` | Gateway, storage, exporter, guardrail, sidecar, and queue health |
| `diagnostic` | Explicit diagnostic/debug records that do not belong to another product bucket |

`guardrail.evaluation` is the inspection process and decision. A
`security.finding` is a durable security fact discovered by that evaluation or by
another source such as an admission scan. A clean evaluation can therefore exist
without a finding. `asset.scan` describes scan execution; findings emitted by that
scan remain `security.finding`. Lifecycle transitions can also produce an
`enforcement.action` when DefenseClaw actually attempts or applies a policy action.

### Operator overrides versus catalog changes

Operators do not edit the bucket catalog. They select one of the fourteen catalog
v1 names under `observability.buckets`, `send.buckets`, or
`routes[].selector.buckets`; an unknown name or a mismatched
`bucket_catalog_version` fails configuration validation. Use `'*'` only where the
generated route schema permits the one-item wildcard list.

A product developer adding, renaming, or removing a bucket is making a versioned
wire-contract change, not a documentation-only edit. The change begins in the
canonical telemetry authoring set under `schemas/telemetry/v8/`, including the
envelope bucket enum and every affected family assignment, and in the hand-authored
config-v8 schema's closed bucket names. The current compiler also has closed Go/API
bindings in `internal/observability/taxonomy.go` and
`scripts/telemetry_go_api_plan.py`; update those in the same change and bump the
catalog/version contracts when compatibility requires it. Then run:

```bash
make telemetry-generate
make telemetry-check
make check-schemas
make check-observability-v8-spec
```

Review every generated runtime/catalog/compatibility diff, destination projection,
example, producer, route fixture, and dashboard query. Do not hand-edit generated
gzip members, generated Go APIs, or `schemas/config/v8/reference/`.

### Local model discovery

The `ai.discovery` bucket includes installed and loaded local-model inventory.
Continuous scans collect it through two metadata-only paths. Endpoint presence
checks prefer `HEAD`; inventory uses bounded `GET` requests only for explicitly
allow-listed loopback metadata routes. The detector never calls completion,
embedding, audio, pull, load, delete, or other inference or control endpoints.

Lemonade Server discovery recognizes its binaries, desktop app, documented
configuration locations, relevant environment-variable names, and default port
`13305`. Its `/v1/models` route reports downloaded models and `/v1/health`
reports loaded models; the `/api/v1/...` compatibility routes are also accepted.
Ollama uses `/api/tags` and `/api/ps`, while LM Studio, LocalAI, and vLLM use
their read-only `/v1/models` metadata. Generic model-list integrations report
`status=installed`; `status=loaded` is reserved for a runtime status route that
explicitly reports an in-memory model.

Each decoded response is capped at 1 MiB after decompression. One pass emits at
most 256 model items, considers at most 24 endpoints, gives each request a 650 ms
timeout, and has a 3 s overall budget. Per-source cursors and rotating origins give
later models and providers a bounded turn on subsequent passes. Authenticated
Lemonade discovery uses only the least-privileged `LEMONADE_API_KEY`, never
`LEMONADE_ADMIN_API_KEY`. The key is sent only when the loopback origin came from
explicit Lemonade host/port settings or Lemonade configuration and a
credential-free `/live` check succeeds; its value is never persisted or emitted.

Filesystem discovery recognizes GGUF/GGML, safetensors, ONNX/ORT, Core ML, TFLite,
Q4NX, MLX, Hugging Face cache layouts, and Ollama manifests/blob stores. It enforces
`ai_discovery.max_files_per_scan` plus separate global and per-root traversal
budgets, groups shards and cache entries into model rows, and never opens model
binaries. Small Ollama manifest JSON is the only model-store content read, and that
read is regular-file checked and bounded by `ai_discovery.max_file_bytes`.

Every `local_model` signal keeps dynamic identity in a dedicated `model` block
(`id`, `status`, and optional format, provider, recipe, modality, device, size,
and pinned fields), rather than in low-cardinality product labels. The local usage
API and `inventory.db` history retain that block for operator inventory. Exported
records still flow through the selected destination's v8 routes and redaction
profile. Normal discovery sanitization omits extended model metadata, model
basenames, and path hashes while retaining lifecycle correlation through an
installation-scoped HMAC pseudonym. Raw paths additionally require
`ai_discovery.store_raw_local_paths=true` and a v8 profile that preserves path
fields. Shell commands, process arguments, prompts, model-binary contents, endpoint
URLs, and environment-variable values are never emitted.

## Add destinations

Destination capability determines the signals selected by an omitted policy:

| Kind | Capability-default signals |
|---|---|
| `jsonl`, `console`, `splunk_hec`, `http_jsonl` | logs |
| `prometheus` | metrics |
| `otlp` | logs, traces, metrics |
| Galileo preset | traces |

For `preset: galileo`, the omitted policy's generated traces-only route also has
an `event_names` selector equal to the currently available generated
`galileo-rich-v2` family membership. This compiler-owned selector is more precise
than an operator-authored `send: {signals: [traces]}`.

For example, this sends every bucket and all three signals, unredacted, to one OTLP
collector while retaining every collected log in local SQLite:

```yaml
config_version: 8
observability:
  destinations:
    - name: production
      kind: otlp
      protocol: grpc
      endpoint: otel.example.com:4317
      headers:
        Authorization: {env: OTEL_AUTHORIZATION}
```

This logs-only destination receives every bucket's logs because `splunk_hec` cannot
accept traces or metrics:

```yaml
observability:
  destinations:
    - name: soc
      kind: splunk_hec
      endpoint: https://splunk.example.com:8088/services/collector/event
      token_env: SPLUNK_HEC_TOKEN
      index: defenseclaw
```

Adding both destinations fans matching records to both. Delivery is not a choice of
one backend:

```text
model.io trace ----------> production OTLP
security.finding log ----> production OTLP + Splunk HEC + local SQLite
security.finding metric --> production OTLP
```

Each destination has its own selector, redaction transform, queue, transport, health,
and accounting. A record is projected independently for every matching destination.

## Narrow collection or delivery

Collection controls whether a normal signal is constructed at all. A route cannot
resurrect a signal disabled here:

```yaml
observability:
  buckets:
    diagnostic:
      collect: {logs: false, traces: false, metrics: false}
    model.io:
      collect: {logs: false, traces: true, metrics: true}
```

The concise `send` form is the normal way to narrow one destination:

```yaml
observability:
  destinations:
    - name: soc
      kind: splunk_hec
      endpoint: https://splunk.example.com:8088/services/collector/event
      token_env: SPLUNK_HEC_TOKEN
      send:
        signals: [logs]
        buckets: [compliance.activity, security.finding, enforcement.action]
        redaction_profile: strict
```

For ordered inclusion/exclusion, use `routes` instead of `send`:

```yaml
observability:
  destinations:
    - name: archive
      kind: otlp
      protocol: http/protobuf
      endpoint: https://otel.example.com
      routes:
        - name: drop-diagnostics
          signals: [logs, traces, metrics]
          selector: {buckets: [diagnostic]}
          action: drop
        - name: everything-else
          signals: [logs, traces, metrics]
          selector: {buckets: ['*']}
          action: send
          redaction_profile: sensitive
```

Routes are evaluated in YAML order independently for each destination and signal;
the first match wins. Different selector fields are ANDed, while values in one
field are ORed. Selectors support `buckets`, `sources`, `connectors`, `actions`,
`event_names`, and `min_severity`. An unmatched record is not delivered to that
destination. `send` and `routes` are mutually exclusive.

## Destination policies and bounded delivery

Signal and bucket policy is resolved separately for every destination. Omitted
policy expands to all signals supported by that kind and all buckets; `send`
provides one inclusive policy, while ordered `routes` can send or drop by bucket,
source, connector, action, event name, and severity. There can be at most 64 named
destinations, and advanced route lists contain at most 256 entries. Destination
names are unique after canonical normalization.

Transport and queue ownership is also per destination:

| Kind | Policy capability | Delivery controls |
|---|---|---|
| `jsonl`, `console` | logs and log buckets only | Queue count/bytes only; JSONL also has bounded rotation controls |
| `prometheus` | metrics and metric buckets only | Pull listener/path; no DefenseClaw push queue or `batch` block |
| `splunk_hec`, `http_jsonl` | logs and log buckets only | HTTP/TLS, timeout, network safety, queue, and push-batch controls |
| `otlp` | logs, traces, metrics and their buckets; Galileo preset is traces-only by default | gRPC or HTTP/protobuf, TLS, timeout, per-signal endpoint/path overrides, network safety, queue, and push-batch controls |

Normal queue/push defaults and schema bounds are:

| Field | Default | Valid range / rule |
|---|---:|---|
| `batch.max_queue_size` | `2048` records | `1..65536` |
| `batch.max_queue_bytes` | `67108864` (64 MiB) | `4198400..268435456` bytes |
| `batch.max_export_batch_size` | `512` records | `1..8192`, and no greater than queue size |
| `batch.max_export_batch_bytes` | `8388608` (8 MiB) | `4263936..67108864` bytes for the fully encoded request |
| `batch.scheduled_delay_ms` | `5000` | `1..600000`; an omitted Galileo preset delay resolves to `1000` |
| `timeout_ms` | `10000` | `1..2147483647` per attempt |

JSONL and console accept only the first two queue fields. Push destinations accept
all five batch fields. The compiler makes adapter/preset-specific resolved values
visible in `config show --effective` and `observability plan`; source YAML should
contain only intentional overrides.

Optional delivery never blocks required local persistence. Each queue accounts for
immutable, already-projected payload bytes. If either queue limit would be exceeded,
the newest attempted enqueue is dropped without evicting older FIFO work; local
SQLite and sibling destinations continue, and bounded platform-health telemetry
records the drop. Transient and ambiguous-acknowledgement failures use bounded
retry of the exact immutable bytes and record ID. Permanent authentication or
malformed-payload failures are not put into a hot retry loop. Remote delivery is
not exactly once: a lost acknowledgement can produce a duplicate, so downstream
consumers should deduplicate by record ID.

## Safely edit bucket and redaction policy

Bucket names are a closed catalog. Operators may override collection and
redaction for the fourteen registered buckets, but cannot invent a bucket in
`config.yaml`. Unknown names fail validation. Disabling collection prevents a
normal signal from being constructed; no destination route can restore it, though
the bounded mandatory compliance floor can still create a minimal SQLite record.

Use this workflow for a manual edit:

```bash
umask 077
cp "$HOME/.defenseclaw/config.yaml" \
  "$HOME/.defenseclaw/config.yaml.before-observability-edit"
${EDITOR:-vi} "$HOME/.defenseclaw/config.yaml"

# Offline and non-mutating: stop here if validation fails.
defenseclaw config validate

# Review generated defaults, effective local-sqlite, narrowed routes,
# unredacted legs, and local-dashboard coverage before activation.
defenseclaw config show --effective --section observability
defenseclaw observability plan

# Activate only the validated source.
defenseclaw-gateway restart
defenseclaw doctor
```

There is no separate observability apply step. If validation fails, do not restart;
restore the private backup or correct the source and repeat all three inspection
commands. Keep secret values outside YAML and reference their environment names.

The scope of a redaction edit matters:

| Location | Affected projections |
|---|---|
| `observability.defaults.redaction_profile` | Every delivered log/trace without a more-specific override, including generated local SQLite |
| `observability.buckets.<bucket>.redaction_profile` | That bucket for local SQLite and optional destinations unless a route/send override wins |
| `destinations[].send.redaction_profile` | Only that destination's concise send policy |
| `destinations[].routes[].redaction_profile` | Only records matched by that route on that destination |

To preserve full-fidelity local history while redacting a remote destination, keep
the global and bucket profiles at `none` and put `sensitive`, `content`, `strict`,
or a custom profile on the remote destination's `send` or route. Conversely, a
global or bucket profile is the correct choice when local SQLite must also redact
that material. Never author a `local-sqlite` destination; it exists only in the
effective plan.

## Central redaction

Redaction is a projection stage after routing and before delivery. Every destination,
including local SQLite, receives a detached, bounded, schema-validated projection;
even the `none` profile does not expose mutable producer objects.

Operational pretty logs are a separate, content-free diagnostic surface. The
daemon persists stderr to `gateway.log`, and deployments may forward that file,
so request bodies, prompt/history/tool message bodies, and response bodies are
omitted unconditionally—even when a destination uses `none` or
`DEFENSECLAW_REVEAL_PII=1` is set. Pretty logs retain only bounded metadata such
as role, content length, model, timing, token usage, and verdict. Canonical
SQLite and remote destination projections continue to follow their configured
v8 redaction profiles.

Built-in profiles are:

| Profile | Intent |
|---|---|
| `none` | Preserve registered fields and content; this is the fresh-v8 default |
| `sensitive` | Redact detected PII, credentials, and secrets while retaining useful structure |
| `content` | Redact whole content/evidence bodies while preserving metadata and identifiers |
| `strict` | Minimize content, sensitive metadata, paths, credentials, and errors |
| `legacy-v7` | Immutable migration profile that preserves the effective v7 projection |

Profiles can apply globally, to one bucket, or to one route. The most specific route
profile wins, followed by bucket, global, and catalog defaults:

```yaml
observability:
  defaults:
    redaction_profile: sensitive
  buckets:
    model.io:
      redaction_profile: content
  redaction_profiles:
    soc:
      extends: sensitive
      detectors: [pii, credentials, secrets]
      field_classes:
        content: detect
        evidence: detect
        reason: detect
        path: hash
        credential: remove
```

`detect` replaces only sensitive substrings. `whole` replaces an entire field,
`hash` emits a keyed correlation token for normalized values, `remove` omits the
field, and `preserve` retains it. Metrics contain no content fields and do not take
a redaction profile.

Redaction failures never fall back to raw content. After a valid field map is
established, a detector/key/field-limit failure replaces the complete affected
field with a bounded `failed_closed` token, records value-free health metadata, and
continues the rest of the projection. A missing/ambiguous classification map,
unsafe traversal, projection-context mismatch, or complete-record serialization/
size failure rejects that destination's entire projection. Other destinations
still receive their independently projected copies. Mandatory SQLite writes a
minimal content-safe failure record if its normal projection cannot be serialized.
The `none` profile intentionally preserves registered values, but it still enforces
schema, type, size, and serialization limits.

Use the effective plan to review unredacted routes before deployment:

```bash
defenseclaw observability plan
defenseclaw doctor
```

See the [redaction reference](../docs-site/content/docs/reference/redaction.mdx) for
the field classes, detector groups, and examples.

## Local history and retention

Exactly one generated `local-sqlite` destination stores every collected log plus a
small mandatory compliance floor. It is not written in `destinations`, cannot be
disabled, and cannot be filtered. Its fresh-v8 default projection is unredacted;
global and bucket redaction overrides change the matching local projection too.

```yaml
observability:
  local:
    path: ~/.defenseclaw/audit.db
    judge_bodies_path: ~/.defenseclaw/judge_bodies.db
    retention_days: 90
```

`retention_days: 0` retains history indefinitely and produces a capacity warning.
Judge-body capture is controlled separately by `guardrail.retain_judge_bodies`;
the database path alone does not enable capture.

## Rich agent traces and dashboards

The `defenseclaw-genai-rich-v1` semantic profile combines OpenTelemetry GenAI
conventions with DefenseClaw security and lifecycle fields. It preserves root agents,
subagents, turns, workflow runs, executions, phases, model calls, tool calls,
retrieval, approvals, guardrail/judge operations, links, events, and stable
conversation/lifecycle correlation.

The bundled `local-observability-v1` projection keeps the Agent360 and other local
Grafana dashboards compatible. A local OTLP destination should therefore retain
logs, traces, and metrics and all required buckets unless partial dashboard coverage
is intentional. Setup and plan output report a narrowed local route as partial
coverage rather than pretending every panel will work.

### Agent360 lifecycle DAG and correlation

Agent360's node graph is a directed acyclic graph of canonical Loki facts backed by
the durable correlation ledger. Agent lineage comes only from active, typed
agent-to-agent `parent_of` relationship-change records, with `delegated_by` accepted
as the contract-defined inverse fallback. Raw subagent parent fields, a shared OTLP
trace, or a parent span never create an agent edge. It keeps
session creation as its own anchor, groups canonical depth-zero prompt submissions
into one root **Prompt inputs** node, connects each parent agent to its child,
and connects the owning agent to grouped model/tool work, real message
updates, approvals, turn outcomes, and terminal outcomes. The root is depth `0`;
direct and recursive children are depth `1`, `2`, and so on through the accepted
maximum depth `64`. A four-level validation tree therefore means root depth 0 plus
subagents at depths 1, 2, and 3—not four subagent generations. Node and edge detail
state the durable relationship method. Session and lineage anchors use a bounded
24-hour recovery lookup so a selected-range boundary does not leave an edge
endpoint missing; a recovered relationship is retained only when that child has
graph-eligible activity in the selected range.

Some Codex versions complete a spawn tool call without emitting `SubagentStart`.
DefenseClaw correlates the first event from a previously unseen child only when one
completed spawn in the same connector/session scope is the unique owner, then emits
an inferred canonical start with lineage provenance. Concurrent ambiguous spawns
remain unresolved, so the DAG never invents a parent-child edge.

`session_start` is labeled Session start; it is never presented as prompt content.
For Codex, the prompt node comes from canonical connector-source
`UserPromptSubmit` facts and includes the initial request plus later follow-ups;
native OTLP `model.request` mirrors remain in the ordered and raw views. Other
connectors use recognized prompt hooks with `model.request` as a fallback. Prompt
families group exact mirrors by `defenseclaw.logical_event.id`; an observation
without that ID falls back to its semantic-event ID and then record ID so unresolved
evidence remains separate instead of disappearing. Each retained raw record keeps
its own `defenseclaw.semantic_event.id`. Typed turn, model-request,
request, and operation identifiers remain evidence and never become interchangeable
fallbacks. When a
connector supplies prompt content or any other field in canonical OTEL, Agent360
shows it directly or links to the exact raw record; the dashboard does not remove,
truncate, or mask it.

Model request records are grouped per owning agent, provider, and model. Logical
counts use the durable logical-event ID, then semantic-event ID and record ID as
separate-observation fallbacks, avoiding connector/native mirror double-counting
without dropping unresolved source observations from Loki. Tool
request records are grouped per owning agent into Bash, MCP, Skills, Collaboration,
File edits, Web/browser, Visual, or Task control; an unrecognized tool retains its
reported name. Exact `collaboration.send_message` requests are excluded from the
generic Collaboration family so they appear once as message groups; other
collaboration tools remain grouped in that family. Request records remain visible
without waiting for a completion that may never arrive. A summary node's exact
total is its request count, not a pending gauge or terminal-status breakdown;
clicks expose canonical detail and filtered links to the raw
requested/completed/failed/blocked records so operation, request/response,
tool-call, status, outcome, trace, and payload fields remain available. Stable
agent-node identity uses agent/root/parent IDs, name, type, depth, and connector.
Optional current/root/parent session fields stay on lifecycle, session, ordered,
and raw surfaces instead of splitting one agent node when metadata is absent or
arrives late. A root agent's summaries appear under the root when it emitted those
records.

Message updates are derived only from real `collaboration.send_message` tool
records. For each emitting agent, `/root` and `/root/*` collapse into one
**Messages to root** node whose target agent ID resolves to the exported root.
Exact root task paths, calls, and terminal results remain in the ordered and raw
drill-downs. A non-root task path remains an exact explicit group until telemetry
reports a canonical target-agent mapping. No generic lifecycle event is
reinterpreted as an update, and only durable `parent_of`/`delegated_by` relationship
evidence proves lineage rather than message delivery. Approvals remain
agent/execution-scoped when no exact work ID is
reported. The dashboard exposes these limits instead of inventing edges.

Cross-backend correlation uses the strongest facts each signal carries:

| Scope | Join fields and meaning |
|---|---|
| One accepted occurrence | semantic-event ID; every log/span/metric derived from that accepted occurrence shares it |
| One exact logical event | logical-event ID; exact hook/proxy/native mirrors group without rewriting or hiding raw records |
| Agent tree | active typed agent `parent_of` edges or inverse `delegated_by` edges; event-carried root/parent/depth/session fields remain display and matching evidence |
| Resumed lifetime | lifecycle ID plus session source/resumed state |
| One attempt | execution ID and sequence; sequence is monotonic within that execution, not across the whole tree |
| One unit of work | operation, tool-call, model request/response, approval, turn, and run IDs when reported |
| Synchronous trace | W3C trace/span IDs and explicit links; absent IDs remain absent |

Loki supplies durable cross-request lifecycle chronology and the DAG. Tempo supplies
request-bounded synchronous spans and waterfalls; DefenseClaw does not fabricate one
trace parent across an asynchronous lifetime. Prometheus supplies aggregates with
bounded lineage/execution labels rather than event-level trace IDs. Node clicks show
all available lineage/work IDs and preserve time ranges in links to Agent360,
ordered logs, and exact Tempo traces.

The **Correlation identity and relationship evidence** row compares distinct logical
events with immutable raw observations and renders the chronological
`correlation.relationship.changed` stream, including relationship type, method,
typed source and target node kinds, status, stable rule ID and version, confidence,
and cumulative durable evidence count. `reported`, `trace_exact`,
`derived`, and `inferred` describe how an edge was established; `unresolved`,
`conflicted`, `superseded`, and `rejected` remain visible rather than being folded
into the graph. The authenticated read-only endpoints provide the durable query view
for automation and exact investigation:

```text
GET /api/v1/correlation/graph
GET /api/v1/correlation/explain
GET /api/v1/correlation/timeline
GET /api/v1/correlation/conflicts
```

Each endpoint accepts exactly one correlation anchor. The Grafana row consumes the
corresponding content-free relationship-change logs so local and remote Loki users
can reconstruct the same evidence without giving Grafana direct database access.
Prometheus receives only bounded aggregate dimensions; semantic, logical, request,
turn, tool, and relationship IDs are never metric labels.

Token range panels include a first-publication fallback: Prometheus `increase()`
cannot see a counter's initial nonzero sample, so a series first published inside
the range contributes its reported cumulative value once; established series use
their normal counter increase.

The local dashboards perform no second redaction pass, masking, or field hiding.
DefenseClaw centrally applies the selected v8 profile before exporting the
canonical OTEL projection. Grafana displays or links every field actually present
in that projection, including prompt, completion, tool, or evidence content when a
producer supplies it. Content removed or transformed before OTEL cannot be
recovered by Loki, Tempo, or a dashboard query.

Start or refresh the local bundle with:

```bash
defenseclaw setup local-observability up
defenseclaw setup local-observability status
```

### Interpret empty panels before troubleshooting

DefenseClaw does not fabricate absent telemetry:

| Display | Meaning |
|---|---|
| **0** | The signal is instrumented and the selected range contains zero matching events. |
| **No data** | No matching series, log, or trace exists for the panel's current time range, variables, and operation type. |
| **Not reported** | A matching operation exists, but the connector/provider omitted an optional value such as token usage or cost. |

**No data** is expected for conditional surfaces: HITL before an approval occurs,
error panels on a healthy system, proxy panels for hook-only traffic, or the Tempo
waterfall before a Trace ID is selected. It is also expected after intentionally
narrowing collection or the local destination's signals/buckets. Historical data
is not backfilled when a new family or field is added.

An explicit destination test is not a dashboard canary:

```bash
defenseclaw observability destination test local-observability
# Optional adapter write; still bypasses ordinary routing and dashboard counts:
defenseclaw observability destination test local-observability --write-probe
```

The default performs a non-mutating protocol handshake. A `--write-probe`, when
supported, sends one marked content-free probe directly to that adapter. Neither
path enters normal collection, routing, local event history, other destinations,
or dashboard counts. The command persists only a separate bounded, local-only
`compliance.activity` attempt/outcome record. To validate panels, restart the
gateway after a config edit, generate a fresh real agent turn/tool
call/scan/approval, select a matching recent time range, and reset dashboard
variables to `All`. Then inspect:

```bash
defenseclaw observability plan
defenseclaw setup local-observability status
defenseclaw setup local-observability logs --service otel-collector --follow
```

From a source checkout, the static/live audit distinguishes genuine zero, empty,
interactive, and not-reported panels:

```bash
uv run python scripts/check_grafana_dashboards.py \
  --require-packaged --live --inventory
```

The upgrade refresh preserves Prometheus, Loki, Tempo, and Grafana volumes and
operator-created files. See the [local stack guide](../docs-site/content/docs/observability/local-observability.mdx)
and [Agent360 guide](../docs-site/content/docs/observability/agent360.mdx).

## Galileo

The Galileo preset is an OTLP trace destination with a generated rich projection.
It receives eligible agent, workflow, model, tool, retrieval, and guardrail/judge
span families without replacing a local OTLP destination. Structured prompts,
outputs, tool arguments, and results follow that destination's redaction profile;
the fresh-v8 default is unredacted.

```bash
export GALILEO_API_KEY='...'
defenseclaw setup galileo --project defenseclaw --logstream production
defenseclaw setup galileo test
```

`setup galileo` deliberately omits both `send` and `routes`. The compiler then owns
the `capability-default` trace route and restricts its event names to the generated
available Galileo family membership.

Adding explicit `send` or advanced `routes` replaces that generated route. This is
operator intent: DefenseClaw does not silently intersect an explicit selector with
the compatibility profile. Use explicit policy to narrow buckets or apply a
Galileo-only redaction profile, and enumerate reviewed compatible `event_names` in
advanced routes when exact family control is required. If explicit policy admits a
nonmember, the compatibility projector rejects it as `unsupported_shape` and
destination failure accounting and health report it; it is not a silent policy
drop. Review the generated membership and route decisions before activation:

```bash
defenseclaw config show --effective --section observability
defenseclaw observability plan --signal traces --event-name span.model.chat
```

See the [Galileo guide](../docs-site/content/docs/observability/galileo.mdx).

## Automatic v7 upgrade

Do not hand-convert a supported installation. Every supported POSIX source,
including an installed `0.8.4` bridge, crosses the `0.8.5` hard cut with the
authenticated target-release resolver. Before backup or service stop, it
authenticates and privately acquires the exact published `0.8.4` rollback
artifacts:

```bash
bash defenseclaw-upgrade.sh --yes
```

For `0.8.3` or older, authenticate the current target release's resolver asset
as documented in [CLI Reference — upgrade](CLI.md#upgrade), then run that
verified asset in latest mode without a version override:

```bash
bash defenseclaw-upgrade.sh --yes
```

The immutable `0.8.4` built-in parser cannot accept the truthful target
manifest because `platform_tested_source_versions.windows` is empty; this is
independent of whether Cosign is installed. Do not execute any obsolete
raw-network hint printed by a frozen built-in controller and do not stream a
resolver directly into a shell. The authenticated resolver performs `source →
0.8.4 bridge → fresh 0.8.4 controller → 0.8.5 hard cut` as one transaction.

During the `0.8.5` hard cut, the upgrader backs up the
exact source, establishes and validates the v7 bridge state, creates and
validates the whole v8 candidate, promotes inline observability credentials
into locked environment references, writes atomically, refreshes owned local
dashboard assets, restarts, and checks health.
It preserves narrower v7 collection/export behavior and redaction posture
instead of silently broadening an upgraded installation to the fresh-v8
defaults. It also preserves local dashboard and Agent360 compatibility.

The v8 gateway does not rewrite legacy configuration during startup and does not run
v7 and v8 observability pipelines side by side. A required migration failure restores
the original files and does not start the v8 gateway against v7 config.

The same converter may be exposed by release/support tooling as a read-only,
secret-free preview. Such a preview is never required before the authenticated
target-release resolver and does not introduce a second apply protocol.

### Install and environment ownership

Release `0.8.4` remains on `config_version: 7` and does not create the v8
destination model. A fresh `0.8.5` install writes
strict `config_version: 8`; its setup commands will add or update named entries
under `observability.destinations`. Use the release installer only for a new
host. On every supported existing POSIX installation, use the authenticated
target-release resolver in latest mode so bridge selection, configuration,
owned dashboard assets, restart, and health checks remain one transaction.

Live observability policy is YAML, not ambient process state. V8 ignores
`DEFENSECLAW_OTEL_*`, standard `OTEL_EXPORTER_OTLP_*`, and
`DEFENSECLAW_DISABLE_REDACTION` as runtime collection/routing/redaction controls.
Those legacy values are upgrade inputs only. Destinations reference secret values
explicitly with `token_env`, `bearer_env`, or `{env: NAME}`; the environment holds
the secret, while the YAML field names which destination may use it. Inspect the
generated [environment-variable reference](ENV-VARS.md) before relying on any
process setting.

## Network and secret safety

- Secret values use environment/key-store references; do not place resolved tokens
  in YAML.
- Push destinations reject inline URL credentials and unsafe network targets.
- Loopback, RFC1918, and IPv6 ULA targets require the per-destination
  `network_safety.allow_private_networks: true` opt-in; RFC 6598 CGNAT has a separate
  opt-in. Metadata, link-local, unspecified, multicast, and reserved targets remain
  blocked.
- DNS is checked again when connecting so a validation-time answer cannot be swapped
  through DNS rebinding.
- Remote plaintext credentials generate a persistent warning and compliance event.

## Alert runbooks

These headings are stable targets for the bundled Prometheus alert annotations.

### Runbook: schema violations

1. Open **Runtime & Reliability → Schema violations by event type / code** and
   identify the first failing family/code and deployment time.
2. Run `defenseclaw doctor` and `defenseclaw observability plan`; verify the source
   config validates and the destination graph is the expected generation.
3. Inspect the correlated gateway/collector logs without copying content fields
   into a ticket. A sustained non-zero rate is a producer/registry compatibility
   failure, not a reason to disable validation.
4. For a source build, run `make telemetry-check`, `make check-schemas`, and the
   owning producer tests. Roll back the incompatible producer or generated
   registry set if the alert began with a deployment.

### Runbook: block SLO

1. Confirm real admission-block traffic exists in the alert window; an idle
   histogram must not be treated as an SLO breach.
2. Open **Runtime & Reliability → Admission block SLO compliance**, then pivot to
   **Guardrail Evaluations** or **Connector Detail** for the affected connector.
3. Compare regex, AI Defense, judge, policy, and finalize phase latency. Check
   upstream inspection/judge health before changing enforcement policy.
4. Preserve action mode unless the incident commander explicitly chooses a
   documented fail-open mitigation; capture the affected connector and trace IDs.

### Runbook: exporter stalled

1. Run `defenseclaw observability plan` and confirm the named destination is
   enabled and still selects the expected signals/buckets.
2. Check `defenseclaw setup local-observability status` and Collector logs for a
   local destination; for remote OTLP, verify DNS/TLS/network policy and adapter
   health.
3. Use `defenseclaw observability destination test NAME` for a non-mutating
   handshake. Use `--write-probe` only when an isolated adapter write is acceptable;
   it does not populate dashboards.
4. Inspect destination queue/drop/retry health in **Runtime & Reliability**. One
   stalled destination does not stop its siblings or mandatory local SQLite.

### Runbook: audit sink

The alert/metric retains `audit.sink` as a compatibility name. In config v8 this
runbook applies to one named observability destination; there is no separate live
`audit_sinks` runtime.

1. Read `sink_kind` and `sink_name` from the alert and inspect that destination's
   delivered/dropped batches and circuit state in **Runtime & Reliability**.
2. Confirm its secret reference resolves, endpoint/network safety is intentional,
   and its `send`/`routes` policy still matches the expected logs.
3. Test only that destination with `defenseclaw observability destination test
   NAME`; an optional `--write-probe` remains isolated from normal telemetry.
4. Verify mandatory local SQLite is healthy. Repair or disable the failing remote
   destination explicitly; do not remove local history or broaden another route to
   compensate without reviewing its trust boundary.

## Developer contracts

The canonical family and field registry is
[`schemas/telemetry/v8/registry.yaml`](../schemas/telemetry/v8/registry.yaml). Generated
runtime schema/catalog/compatibility assets are deterministic gzip members under
[`schemas/telemetry/runtime/`](../schemas/telemetry/runtime/); generated Go IDs,
catalogs, builders, producer mappings, and fixtures are the
`internal/observability/zz_generated_telemetry_*.go` files. These are outputs, not
parallel authoring surfaces. Add or change a family in the v8 registry/domain YAML,
run `make telemetry-generate`, review the generated diff, and run
`make telemetry-check`. Do not edit the compressed runtime assets or generated Go
files directly.

Normative design and acceptance requirements are indexed from
[`docs/design/observability-v8/README.md`](design/observability-v8/README.md).
