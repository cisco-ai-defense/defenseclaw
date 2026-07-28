# Migration and Implementation Plan

## 1. Current-State Baseline

The implementation begins from these v7 realities:

- `gatewaylog.Writer` emits a structured gateway JSONL envelope, pretty console
  output, and fan-out callbacks.
- `audit.Logger` writes SQLite audit data, metrics, audit sinks, and a gateway-log
  bridge.
- Native OTel named destinations have independent processors/readers for logs,
  traces, and metrics.
- Galileo currently exports schema-filtered `chat`, `invoke_agent`, and
  `execute_tool` spans with GenAI/OpenInference attributes, rich agent/session
  correlation, redacted content, delivery-funnel health, and an exact-trace canary.
  The v7 global/default scheduled delay is 5,000 ms; the 1,000 ms value is a v8
  Galileo preset default, not a v7 baseline claim.
- Merged PR #403 (`9e417889c4c456bc3c7e6c160ee98c1add1094ee`) adds the
  full Agent360 compatibility baseline: root/subagent lineage; stable
  lifecycle/execution identity; bounded turn/model/tool/approval traces; phase,
  sequence, and operation correlation; final connector-facing `hook_decision`;
  real-time completed-operation export without waiting for `Stop`; truthful
  missing token/cost/content state; and local Collector/Loki/Prometheus/Tempo
  wiring.
- Merged PR #412 (`94dd46c689fefbcf85b8f478249e74f3925eca49`) corrects
  dashboard metric names, label selectors, histogram buckets, datasource cadence,
  and source/packaged validation. Those corrections are migration inputs, not
  disposable presentation changes.
- The real gateway metric baseline is a 60-second delta export interval. The
  bundled Collector converts delta sums to cumulative Prometheus series, sends
  application metrics through one remote-write path, and provisions Grafana with
  a Prometheus interval of at least 60 seconds.
- The bundled local-observability baseline has fourteen stable dashboard UIDs and
  stable Prometheus/Loki/Tempo datasource UIDs. Agent360 uses Loki for durable
  chronology/counts, Prometheus for aggregate/phase/topology data, and Tempo for
  bounded trace search/waterfalls.
- OTel contracts are spread across resource, metrics, four runtime span, lifecycle,
  scan/finding/event, connector, and Galileo profile JSON files with repeated common
  attribute definitions.
- Related gateway/audit/scan transport schemas repeat parts of the same domain
  concepts and must compose generated canonical bodies rather than become a second
  independently authored truth.
- `audit_sinks` support Splunk HEC, HTTP JSONL, and OTLP logs; SQLite is instead
  configured by the top-level `audit_db`, and gateway JSONL/console are separate
  `gatewaylog.Writer` outputs.
- The top-level `judge_bodies_db` configures the separate judge-response database.
- Existing gateway JSONL is disabled by `DEFENSECLAW_JSONL_DISABLE` and uses the
  current 50 MiB/5-backup/30-day/compressed rotation behavior.
- v7 gateway metrics use OTel/OTLP and the operator-side observability bundle; a
  gateway-native `kind: prometheus` destination is new in v8.
- The existing `observability.connectors[*]` contains connector `audit_sinks` and
  notification `webhooks`, not the v8 unified pipeline.
- Inbound OTLP normalization can emit audit rows, metrics, and connector OTel logs.
- Redaction helpers are called at multiple producer and sink boundaries rather than
  one universal projection boundary.
- `privacy.disable_redaction` and `DEFENSECLAW_DISABLE_REDACTION` can globally
  bypass redaction through Go and Python CLI/setup/TUI surfaces.
- `DEFENSECLAW_REVEAL_PII` currently participates in local reveal/retention paths;
  v8 constrains it to authorized display-time reveal only.
- Scanner findings already expose description and optional remediation in several
  CLI/API/TUI/event paths.
- Runtime guardrail findings may carry redacted evidence, but there is no canonical
  `evidence_summary` field across all producers.
- Finding observations do not have `status: open` or a managed lifecycle.
- No age-based event reaper exists for all audit/evidence tables.
- The current upgrader verifies release artifacts, downloads before shutdown, keeps
  a migration cursor, backs up selected files and the previous gateway binary, and
  polls health. Individual migration errors can currently continue, and the
  unconditional restart path can attempt to start the target afterward; the v8
  required migration must close that narrow incompatible-start case.

## 2. Migration Principle

Build one canonical pipeline and move producers to it. Do not put another fan-out
layer around the existing duplicate pipelines.

During development, compatibility adapters MAY translate old internal types into
canonical records as temporary scaffolding. Before v8 is released, all live v7
producer branches, fallbacks, direct OTel/provider calls, sink fan-outs, gateway
JSONL bridges, runtime configuration switches, and dual-format startup/reload paths
MUST be deleted—not merely left behind an `if config_version` branch or proven
inactive by a normal-path test.

The final target binary may retain v7 knowledge only in these closed boundaries:

1. the pure `defenseclaw upgrade` converter and read-only migration preview;
2. historical conformance fixtures and generated converter-selection artifacts;
3. exact source/ancillary backups, rollback metadata, and previous-binary recovery;
4. additive v8 consumer projections that intentionally preserve Galileo, local
   dashboard, OpenInference, or legacy-shaped SQLite read compatibility.

Item 4 never permits a legacy producer, provider, router, sink, or fallback. A
target-v8 ordinary command presented with active v7 source refuses it and directs
the operator to `defenseclaw upgrade`; only the migration boundary parses or writes
that source.

## 3. Automatic Upgrade Migration

### 3.1 Command contract

`defenseclaw upgrade` runs one registered, required version migration that converts
supported v7 observability configuration to v8. It uses the existing upgrade
confirmation, backup, migration cursor, manifest failure policy, service restart,
and health check. There is no required preflight command or separate write step.

The conversion function MAY also back a read-only support preview:

```text
defenseclaw setup observability migrate-v8 --dry-run
```

Preview parses without mutation, prints a redacted diff and warnings, and validates
the same candidate. It is optional and never writes the active source.

The automatic writer MUST preserve unrelated sections, comments, ASCII guidance,
key order, safe scalar/list style, modes, and ownership; acquire the configuration
lock; back up every changed source; and activate only a complete validated candidate
using temporary files, fsync, and atomic rename. Resolved secrets never enter the
candidate or output.

Normative upgrade sequencing and required-failure behavior are defined in
`10-automatic-upgrade-and-migration.md`.

“Supported v7” includes a missing or numeric-zero `config_version` when the
complete document validates as the currently supported v7 shape and contains no
v8-only observability key. Existing Go/Python writers commonly leave the stamp
absent, so absence alone is not an unsupported-version error. A missing/zero stamp
combined with v8-only keys or a shape ambiguous between versions is rejected with
an actionable path; the migrator never guesses from one key while ignoring the
rest.

### 3.2 Legacy mapping

| v7 source | v8 target |
|---|---|
| Effective `otel.resource.attributes.service.name`, including `OTEL_SERVICE_NAME` precedence | `observability.resource.attributes.service.name`; record a content-free preservation summary code |
| `deployment.environment` and `deployment.environment.name` | Canonical `observability.resource.attributes.deployment.environment.name`; equal dual spellings coalesce and conflicting values fail before write |
| `defenseclaw.preset` / `defenseclaw.preset_name` resource markers | Consume them into destination identity/display handling, omit them from the process resource, and record content-free migration summary codes |
| Other eligible stable `otel.resource.attributes` | Preserve under `observability.resource.attributes`; unsupported registered/process-owned keys fail value-free rather than becoming custom attributes |
| `otel.traces` sampler | `observability.trace_policy` |
| `otel.metrics` interval/temporality | `observability.metric_policy`; preserve explicit values, while the inherited current default remains `export_interval_s: 60` and `temporality: delta` |
| `otel.logs.emit_individual_findings: true` | Add an OTLP log route for the generated canonical individual-finding event family; `false`/absent does not automatically route those individual finding logs and does not drop unrelated `security.finding` facts |
| `otel.destinations[]` | `observability.destinations[]` with `kind: otlp`; selected signals come from generated `send`/advanced routes and per-signal endpoint/path details become `signal_overrides` |
| Different effective v7 per-signal protocols in one OTel destination | Split into deterministic signal-specific v8 destinations with stable suffixes; never select one protocol or add a hidden override |
| Conflicting effective v7 metric interval/temporality policies | Fail candidate generation before any write and identify the conflicting destination names/fields plus the exact remediation: align the policies or keep only one metric-export destination |
| Effective non-secret legacy OTel environment inputs | Materialize the effective master enablement, endpoint, signal endpoint, protocol, signal protocol, TLS-insecure, and resource-attribute values into destination-scoped v8 source; later environment changes do not override the committed graph |
| Named `local-observability` OTLP destination | Preserve its name, endpoint/protocol/TLS and local-network intent; include logs/traces/metrics and every `local-observability-v1` family unless explicit v7 policy was narrower, in which case preserve it and report partial dashboard capability |
| Explicit v7 loopback/RFC1918/IPv6-ULA literal endpoint | Materialize `network_safety.allow_private_networks: true` only on each translated destination that needs it, with the required warning/audit; metadata/link-local/unspecified/multicast/reserved targets remain invalid and no process-wide bypass is created |
| Galileo batch delay | Preserve an explicit operator delay. If the source merely inherited the v7 5,000 ms default, materialize the v8 `galileo-rich-v2` preset value of 1,000 ms and disclose the preset-default change in the upgrade summary |
| OTel span filters and current exporter eligibility | Use generated v7 family-compatibility selection from the telemetry registry to produce exact bucket/source/event routes; never maintain a hand-authored converter list or broaden on an unknown mapping |
| Top-level `audit_db` | `observability.local.path` |
| Top-level `judge_bodies_db` | `observability.local.judge_bodies_path` (deliberate relocation; field name simplified) |
| `guardrail.retain_judge_bodies: true/false` | Preserve the explicit Boolean at the same `guardrail.retain_judge_bodies` key; the path moves, but feature enablement does not |
| `DEFENSECLAW_PERSIST_JUDGE` set to `0`, `false`, `no`, or `off` (case-insensitive) | Materialize `guardrail.retain_judge_bodies: false`; after migration the runtime no longer consults the variable |
| `DEFENSECLAW_PERSIST_JUDGE` unset or any other value, with no explicit YAML value | Leave the key absent so v8 resolves the same default `true`; the variable has never forced `true` over an explicit false |
| Current gateway JSONL writer | One `kind: jsonl` destination using the current path, avoiding duplicate output |
| `DEFENSECLAW_JSONL_DISABLE` truthy | Migrated JSONL destination has `enabled: false`; otherwise it is enabled to preserve current output |
| Current gateway JSONL rotation defaults | `rotation: {max_size_mb: 50, max_backups: 5, max_age_days: 30, compress: true}` unless a supported current override supplies another value |
| Current gateway pretty console output | One `kind: console` destination preserving current stderr/pretty behavior and audience as closely as the taxonomy permits |
| Splunk HEC audit sink | `kind: splunk_hec`, including the adapter-owned `sourcetype_overrides` action map |
| HTTP JSONL audit sink | `kind: http_jsonl` |
| OTLP log audit sink | Merge into a matching `kind: otlp` destination or create a separate uniquely named OTLP destination; preserve adapter-owned `logger_name` |
| `observability.connectors[*].audit_sinks` | Destination selectors using `connectors`; preserve explicit suppress/inherit intent, then remove the legacy child |
| `observability.connectors[*].webhooks` | Preserve in place as a typed notification-only compatibility child; do not translate it into a destination route |
| `ai_discovery.emit_otel: false` | Keep local `ai.discovery` logs enabled, but omit `ai.discovery` from translated OTLP log/trace/metric policies; do not incorrectly turn this destination-specific legacy intent into `collect.logs: false` |
| `ai_discovery.emit_otel: true` or absent (v7 default true) | Enable `ai.discovery` trace/metric collection and include the bucket in each translated OTLP signal policy that previously received that provider signal; ordinary local discovery logs remain enabled |
| `privacy.disable_redaction: true` | Preserve unredacted local and destination behavior with effective `none`; omit redundant profile keys where the new default is exact |
| `DEFENSECLAW_DISABLE_REDACTION` truthy | Same unredacted preservation as the privacy field; migration reports that the legacy environment gate is now represented by v8 policy/defaults |
| `privacy.disable_redaction: false/absent` | Materialize immutable built-in `legacy-v7` on the applicable local, bucket, and destination routes so the upgrade retains the exact old projection instead of becoming unredacted or approximating it with another v8 profile |
| `DEFENSECLAW_REVEAL_PII` | Retain only as an authorized local display control; it does not influence persisted/exported projections or judge-body retention |
| Inline v7 tokens/bearer tokens and interpolated secret headers | Replace with deterministic environment references; write the complete effective values only through ancillary locked/backed-up/rollback-capable `.env` edits and never place them in YAML or output |
| Prometheus/operator-side scrape integration | Preserve bundle intent/documentation; create no native destination implicitly. `kind: prometheus` is a new opt-in v8 destination |
| Seeded local-observability bundle | Back up and refresh DefenseClaw-owned Collector/datasource/dashboard/rule/config files to the mutually compatible target bundle; preserve custom files and all history volumes; restart/verify an already-running stack through the existing lifecycle |

The inspected v7 configuration model has no separate connector-level
`emit_otel` YAML field: the only persisted field with that name is
`ai_discovery.emit_otel`; `agent discover --emit-otel/--no-emit-otel` is a
per-invocation CLI override of that behavior. Migration inventory tests MUST keep
this assertion explicit so a newly discovered connector toggle cannot be silently
ignored. The CLI override is retired in favor of the compiled bucket/destination
policy; `--require-otel` may remain only as a delivery-test command option and may
not mutate collection policy.

For judge-body retention, precedence is the existing v7 precedence: an explicit
YAML `false` remains false; an off-like `DEFENSECLAW_PERSIST_JUDGE` forces false;
otherwise an explicit YAML value is preserved and absence resolves to true. The
migration summary reports the effective choice without inspecting or displaying
judge content.

The migrator MUST NOT merge destinations merely because their endpoints match when
credentials, TLS, batching, signal settings, or route intent differ.

The v8 converter consumes a generated v7 compatibility-selection artifact owned by
the telemetry registry. For every current log, trace, metric, action, and exporter
family, that artifact declares its v7 eligibility and canonical v8
bucket/source/event identity. Phase 5 generates and drift-checks it from the same
registry as the public schemas; the converter never embeds a second manually
maintained family list. A missing or ambiguous mapping is a pre-write migration
error with the affected source family, not permission to use `*` and broaden
delivery.

The complete legacy OTel environment inventory is mechanical, not illustrative:
`DEFENSECLAW_OTEL_ENABLED`; the DefenseClaw, OpenClaw, and standard OTel global
endpoint/protocol names; their `LOGS`, `TRACES`, and `METRICS` endpoint/protocol
forms; the DefenseClaw/OpenClaw TLS-insecure names; and `OTEL_SERVICE_NAME`. The
converter applies the existing v7 precedence,
materializes all effective non-secret values, and records only the input names in
its masked summary. Header values are secret-bearing: exact environment references
remain references, while complete inline or interpolated values use the ancillary
`.env` promotion contract below. Inventory tests enumerate the concrete names and
fail when runtime support adds one without a migration disposition.

`OTEL_RESOURCE_ATTRIBUTES` and `OTEL_EXPORTER_OTLP_HEADERS` are not v7 inputs:
DefenseClaw constructs its resource and supplies destination header options
explicitly, so the pinned v7 runtime does not apply those SDK environment values.
The converter MUST ignore them rather than invent new telemetry or credentials.
Any future runtime support for either name requires an inventory, migration, and
compatibility-baseline change together.

V7 secret-bearing inputs are normalized before the v8 candidate is constructed.
Exact `${NAME}` or `$NAME` references remain references when the explicit upgrade
environment resolves them to a nonblank value. V7 uses Go `os.Expand`; therefore
missing references materialize the same empty/static effective header instead of
becoming an unresolved required v8 secret. Inline values and interpolated values
such as `Basic ${TOKEN}` or `Bearer $TOKEN` become stable,
destination-and-field-derived environment references whose complete effective
values are stored only in the ancillary `.env` edit. The active config and `.env`
are locked and backed up as
one required migration unit; failure restores both, and retry reuses the same names
without duplicate assignments. Preview reports only reference names and the fact
that an ancillary edit would occur.

When a v7 destination selects signals with different effective protocols, the
converter creates one destination per protocol/signal group and preserves the
source name on the group using the destination's effective base protocol. If no
selected signal uses that protocol, the first canonical group keeps the name. The
remaining groups use `-<signal[-signal...]>` suffixes, with signals and otherwise
tied groups ordered by the canonical `logs`, `traces`, `metrics` order.
Endpoint, credentials, TLS, batching, routes, enabled state, and redaction are
copied to each resulting destination before signal-specific overrides are applied.
Metric export remains process-policy scoped in v8: two effective v7 metric
interval/temporality policies that disagree are not representable, so conversion
fails before write and instructs the operator to align those named policies or
retain only one metric-export destination.

The migrator emits the concise `send` form whenever one bucket/signal selection and
one redaction choice preserve intent. It MUST NOT omit both `send` and `routes` on a
migrated destination unless the v7 destination already received every supported
signal, every catalog bucket, unredacted; omission has broad v8 meaning. It emits
advanced `routes` only for legacy exclusions, multiple precedence rules,
source/connector/action/event/severity
selectors, or differing redaction within one destination. It never writes the
generated local destination/catch-all or a second OTLP signal-enable map. It omits
`enabled` for active optional destinations and writes `enabled: false` only to
preserve a disabled legacy destination.

After a successful migration, the gateway/CLI no longer consult
`DEFENSECLAW_JSONL_DISABLE`, `DEFENSECLAW_DISABLE_REDACTION`, or
`DEFENSECLAW_PERSIST_JUDGE`, nor the legacy DefenseClaw/OpenClaw/standard OTel
enablement, endpoint, protocol, or TLS inputs for observability policy; their
effective intent is represented in v8 YAML and source-declared secret references.
Migration preview must name an environment-derived decision without printing any
secret values.

## 4. Producer Classification Registry

### 4.1 Registry requirement

Create one reviewed registry that maps every existing producer event, audit action,
span family, and metric instrument to:

- Bucket.
- Stable event/span/instrument name.
- Signal.
- Default severity rules.
- Mandatory-floor qualification.
- Body schema.
- Field classes.
- Correlation extraction.
- Normalized projection writers.

Build/test generation must fail when a known action/event/instrument lacks a
classification.

### 4.2 Initial event mapping

| Current event family | Primary v8 bucket |
|---|---|
| Activity/operator mutations | `compliance.activity` |
| Scan finding fan-out | `security.finding` |
| Verdict/judge/final connector-facing `hook_decision` | `guardrail.evaluation`; an actually imposed control additionally creates a separate linked `enforcement.action` record |
| Scan summaries | `asset.scan` |
| Skill/MCP/plugin state transitions | `asset.lifecycle` |
| Block/deny/quarantine/release/redact effects | `enforcement.action` |
| LLM prompt/response | `model.io` |
| Tool invocation/result | `tool.activity` |
| Network egress records | `network.egress` |
| Sidecar/agent/session/run lifecycle | `agent.lifecycle` or `platform.health` according to subject |
| AI discovery delta | `ai.discovery` |
| OTLP receive/normalization | `telemetry.ingest` |
| Sink/exporter/schema/DB health | `platform.health` |
| Existing diagnostic | `diagnostic` unless reclassified into a stable bucket |

The detailed registry must resolve individual actions that are ambiguous at the
family level. For example, a config reload attempt is compliance activity; the
runtime becoming degraded because reload failed is platform health. Both may be
linked records.

## 5. Implementation Phases

### Phase 1: Contracts and strict configuration

Deliver:

- Bucket, signal, event-name, severity, source, field-class, and selector types.
- Producer classification registry and exhaustive completeness tests.
- v8 config parser, defaults, strict unknown-field validation, capabilities, route
  compilation, profile resolution, and legacy rejection.
- Omitted-policy capability-send compilation, concise `send` narrowing, mutually
  exclusive advanced routes, implicit local storage defaults, route-derived OTLP
  signal activation, bucket catalog default/versioning, and
  duplicate-key/alias/merge rejection.
- Canonical machine-readable config schema plus generated YAML/Markdown reference,
  compact example, Go/Python parity checks, and comment-preserving mutation path.
- A strict Python v8 parser/validator with the same observability unknown-field,
  legacy-field, detector-group, capability, and route checks as Go. Today the
  Python loader preserves many unmodeled keys; changing that behavior for the v8
  observability contract is intentional and breaking. Unrelated valid extension
  sections remain preserved according to their own schemas.
- One deterministic, side-effect-free v7-to-v8 candidate conversion library with
  secret-free diagnostics. Registration, ancillary writes, service restart, and
  rollback remain Phase 7 integration work; Phase 1 tests only pure conversion and
  validation seams.
- Documentation examples and config reference.

Do not switch runtime producers yet. Phase 1 must produce a validated immutable
runtime plan from YAML.

Primary areas:

- `internal/config/`
- `cli/defenseclaw/config.py`
- `cli/defenseclaw/commands/cmd_config.py`
- `cli/defenseclaw/observability/`
- schema and documentation directories

### Phase 2: Canonical router, redaction, and SQLite

Deliver:

- Canonical immutable generic-record, deterministic-serialization, and current
  classified-log builder APIs. Phase 2 validates registered identity and generic
  envelope/payload bounds but does not hand-author the generated family builders
  owned by Phase 5.
- Collection gate and mandatory-floor catalog.
- Ordered per-destination route engine.
- Central redaction engine and built-in/custom profiles.
- Immutable built-in `legacy-v7` route projection with exact compatibility vectors;
  it is not extendable and does not preserve a parallel producer/fan-out path.
- Built-in SQLite store adapter and event-history schema migration.
- Transactional normalized projections.
- Global reaper across audit and judge-body databases.
- Health and mandatory failure behavior.

At the end of Phase 2, a representative subset of producers must write through the
new router, but old and new outputs must not duplicate records.

Primary areas:

- `internal/gatewaylog/`
- `internal/redaction/`
- `internal/audit/`
- new internal observability routing package if separation is needed

### Phase 3: Optional destinations and OTel signals

Deliver:

- JSONL, console, Splunk HEC, HTTP JSONL, OTLP, and the new opt-in native
  Prometheus adapter behind the destination registry.
- Splunk `sourcetype_overrides` and OTLP-log `logger_name` as typed adapter-owned
  fields in the destination registry and canonical schema.
- Independent destination queues, retry, draining, and health.
- Destination-local log/trace/metric route filtering.
- Trace span creation gates and cloned redacted export projections.
- Metric instrument catalog, recording gates, bounded attributes, and export
  filters.
- Initial Galileo OTLP preset preserving current agent/LLM/tool shapes and delivery
  behavior through the same router.
- Inbound OTLP normalization through the same router.
- The `local-observability-v1` destination/query profile, preserving the existing
  three-signal local destination, datasource UIDs, Collector pipeline, metric
  temporality conversion, and one application-metric path.

Primary areas:

- `internal/telemetry/`
- `internal/audit/sinks/`
- gateway OTLP receiver/normalization code
- local observability bundle configuration and dashboards

### Phase 4: Producer migration and duplicate-path removal

Migrate all producers, including:

- Gateway lifecycle/errors/diagnostics.
- Operator activity and config/policy changes.
- Scan summaries and individual findings.
- Guardrail stages, judge calls, hook decisions, and runtime findings.
- Model I/O and tool calls/results.
- Enforcement and asset state transitions.
- Network egress.
- AI discovery.
- Inbound telemetry.
- Destination and SQLite health.

Remove or retire:

- Audit-to-gateway bridge once all audit events originate as canonical records.
- Separate audit OTLP log provider.
- Direct writer fan-outs around the router.
- Destination-specific producer redaction.
- Global disable-redaction behavior in Go and Python, including
  `internal/redaction/`, `internal/config/config.go`, the environment-variable
  registry, `cli/defenseclaw/commands/redaction_status.py`,
  `cli/defenseclaw/commands/cmd_setup.py`,
  `cli/defenseclaw/commands/cmd_doctor.py`,
  `cli/defenseclaw/commands/cmd_init.py`,
  `cli/defenseclaw/tui/panels/logs.py`, Python `PrivacyConfig` handling, and their
  documentation/tests.
- The `setup redaction off` global bypass workflow; replace it with ordinary
  observability default/bucket/destination profile authoring and status.
- `DEFENSECLAW_REVEAL_PII` influence on persistence or judge-body retention while
  preserving, if still required, its authorized display-only semantics. Audit all
  current redaction, gateway judge/proxy, telemetry-scan, and environment-registry
  call sites so no persistence/export path inherits the display choice.
- Runtime consultation of `DEFENSECLAW_JSONL_DISABLE` after its state is migrated
  to the JSONL destination's `enabled` key, including the kill-switch parser,
  sidecar wiring, environment registry, documentation, and tests.
- Runtime consultation of `DEFENSECLAW_PERSIST_JUDGE` after the effective retention
  choice is materialized, including `internal/gateway/sidecar.go`, the environment
  registry, CLI setup/status/TUI surfaces, documentation, and tests.
- The `ai_discovery.emit_otel` persisted/CLI toggle after its intent is translated
  to `ai.discovery` collection and destination policy. Setup, TUI, status, and
  per-invocation CLI output must explain the compiled policy instead of maintaining
  a second emission gate.
- Opaque inbound raw event preservation.
- Every `config_version != 8`, unbound-runtime, missing-capability, build-error,
  sampling-drop, reload-detach, or destination-error branch that invokes a live v7
  producer, SDK provider, gateway writer, structured bridge, audit sink, or direct
  OTel call. These branches are release-blocking even when a production v8 startup
  normally makes them unreachable.
- Runtime v7 interfaces, fields, constructors, and tests after their last live
  caller is removed. Converter DTOs, historical fixtures, rollback artifacts, and
  generated compatibility projections remain explicitly allowlisted at the
  migration/consumer boundary instead of sharing runtime names or ownership.

Duplicate-removal tests must assert one semantic action produces exactly the
expected records and projections.

Phase 4 also switches ordinary Python config/setup/TUI writers and runtime config
entrypoints to v8-only operation. A v8 source is validated and mutated through the
v8 source/writer path; it is never loaded and re-saved through the connector-only
v7 `ObservabilityConfig` dataclass. In the target release, an ordinary command that
finds v7 source refuses mutation and points to `defenseclaw upgrade`; only the
registered Phase 7 converter or read-only preview may parse it. Tests must prove
that an unrelated Python write cannot erase v8 defaults, buckets, profiles,
destinations, routes, or local settings and cannot silently enter a v7 writer.

Python CLI/setup/TUI tests must additionally prove that legacy redaction and JSONL
environment variables cannot silently override a committed v8 graph and that
redaction status reports capability-default, explicit concise-send, and
advanced-route profiles instead of a global off/on state.

### Phase 5: Rich telemetry and schema consolidation

This workstream builds on the already functioning unified router and does not block
the concise configuration compiler or basic destination migration.

Deliver:

- One logical OTel/GenAI-compatible telemetry registry with a small focused
  authoring set, pinned upstream semantic-convention lock, generated JSON Schema
  bundle, compact catalog, documentation, constants/builders, field-class maps,
  fixtures, and Galileo/OpenInference projections.
- Generated log/trace/metric family builders and detailed family payload schemas;
  every generated builder terminates at the Phase 2 generic canonical-record
  constructor rather than creating a parallel record representation.
- A generation-owned ended-span handoff that synchronizes the generated canonical
  trace record with the SDK `OnEnd` callback without exposing the provider-owned
  SDK span object to canonical destination workers. Each named destination owns
  exactly one canonical consumer or one legacy SDK processor, never both; callback
  fanout is exact-once, panic-contained, generation-bound, and bounded by the
  common trace queue count/byte limits in P-062, while canonical enqueue is
  nonblocking.
- A single checked-in compiler entry point,
  `scripts/generate_telemetry_registry.py`, with `--write` and `--check` modes.
  `scripts/check_schemas.py` invokes its `--check` mode so the existing
  `make check-schemas` target remains the repository-wide schema gate; no parallel
  hand-maintained generator or undocumented Make target is introduced.
- Rich bounded trace topology for agent, model, tool, retriever, workflow,
  guardrail/judge/phase, finding enrichment, enforcement/approval, scan, lifecycle,
  network, ingest, config reload, export, and diagnostic families.
- Standard OTel/GenAI portable attributes plus the focused DefenseClaw overlay,
  events, links, status/outcome semantics, missing-data states, retries/timing, and
  compatibility aliases.
- Galileo rich compatibility projection adding retriever/workflow, safe security
  enrichment, and judge-chat eligibility without a second pipeline.
- Import of every PR #403 lifecycle identity/event/state/phase, runtime
  agent/model/tool/approval field, operation boundary, `hook_decision`, missing-data
  flag, metric, and Agent360 spanmetrics dimension with an explicit
  preserved/aliased/corrected disposition.
- Generated `local-observability-v1` compatibility inventory connecting registry
  families to the exact Prometheus names/labels/buckets, Loki fields, Tempo fields,
  and dashboard consumers fixed by PR #412.
- Generated versioned v7 exporter/family compatibility selection consumed by the
  pure converter, covering current logs, traces, metrics, audit actions,
  JSONL/console eligibility, OTel filters, and destination-specific behavior.

Canonical destination consumers MUST remain inactive until all of the following
are generated and verified together: record-authoritative W3C `trace_state` and
full OTLP flags; a typed bounded representation for configured safe custom
resource attributes; the generated two-span root-agent/model canary; runtime-graph
lease/reload E2E coverage from span start through canonical end; PR #403 producer
and Galileo projection migration; and PR #412 local-observability projection
validation through the branch-specific filter that retains diagnostic canaries in
Tempo while excluding only exact Boolean-marked canaries from Agent360 spanmetrics.
The handoff substrate may coexist with named legacy processors before this gate,
but a canonical destination has no legacy fallback when registration or parity
fails.

Primary areas:

- `schemas/` migration into the generated registry architecture
- `internal/telemetry/` instrumentation and builders
- generated schema/docs/constants/fixture/projection outputs
- `bundles/local_observability_stack/` Collector, datasource, dashboards, rules,
  alerts, and source/packaged parity checks

### Phase 6: Focused operator experience and release hardening

Deliver:

- Setup commands for adding/removing/testing unified destinations; generated source
  uses concise `send` unless the requested policy requires advanced routes.
- TUI and doctor views for buckets, destination policies, clearly visible effective
  unredacted/redacted profiles, retention, and destination health.
- Source/effective/reference config views, observability plan, explicit destination
  connectivity test, authoring presets, and bucket-catalog upgrade preview.
- Keep config-path explain, advanced lint, event explanation, and schema browsing as
  follow-up commands; they are not v8 release gates.
- Config migration documentation and upgrade diagnostics.
- Coordinated dashboard/query updates to use bucket/event/source fields while
  preserving `local-observability-v1` answers, root/subagent scope, lifecycle and
  execution variables, datasource/dashboard UIDs, and historical aliases.
- Static and live dashboard inventory validation, including classification of
  expected-idle versus unexpectedly empty queries so `No data` and plausible
  false zeroes cannot pass as compatibility.
- Release notes and breaking-change documentation.
- End-to-end upgrade, reload, fan-out, privacy, and retention verification.

### Phase 7: Automatic upgrade integration

Deliver before the v8 release:

- A non-executing target-wheel capability preflight, after artifact verification
  and before confirmation or mutation, that enforces the release stamp,
  `run_migrations` call contract, literal migration registry, manifest-required
  reachable rows, and config-v8 capability defined in
  `10-automatic-upgrade-and-migration.md` section 2.1.
- Automatic v7 detection and target-library candidate generation in the existing
  `defenseclaw upgrade` command.
- A concise redacted summary in the ordinary upgrade confirmation and complete
  candidate validation before the source file is replaced.
- Exact config backup and comment/permission preservation.
- Atomic v8 config activation as part of target installation.
- Exact v7 source restoration and prevention of an incompatible v8 gateway start
  when the required conversion fails.
- Version-dispatched Python migration activation plus ancillary `.env`
  locking, backup, and rollback. The active v8 writer/runtime dispatch delivered in
  Phase 4 is a prerequisite; Phase 7 must not route the new source through a v7 save
  path.
- A narrow required-migration restart gate: candidate, ancillary-write, manifest,
  or cursor failure restores the backed-up unit, leaves the migration unapplied,
  skips the target gateway start, and exits nonzero with the backup path. This is
  Phase 7 work, not part of the Phase 1 pure converter.
- Retry/idempotence, backup status, and read-only config permission preflight.
- Historical baseline upgrade, failure injection, rollback, and compatibility tests.
- Automatic backup/refresh of an installed local-observability bundle, preservation
  of custom files and Prometheus/Loki/Tempo/Grafana volumes, restart of a previously
  running stack, and bounded readiness/live-query verification. Optional stack
  failure is reported as degraded and does not roll back a healthy gateway/SQLite
  migration.

Normative behavior is defined in `10-automatic-upgrade-and-migration.md`. The release
must not rely on the current warning-and-continuing migration behavior.

Phase 7 preserves the old source and previous executable for rollback; it does not
ship a v7 observability runtime inside the target executable. Successful migration
is the sole forward transition. Rollback restores the v7 source and restarts the
preserved previous binary, while the target binary continues to reject v7 startup.

## 6. Atomic Runtime Graph

The runtime graph should contain immutable:

- Collection matrix.
- Bucket metadata.
- Compiled route lists per destination and signal.
- Resolved redaction profiles.
- Destination capability and adapter handles.
- Trace/metric policy.
- Configuration generation.

Producer calls load one active graph pointer. Reload builds a second graph, verifies
it, swaps atomically, and drains the first graph. SQLite store handles are retained
when paths do not change.

## 7. Compatibility Behavior

### 7.1 Event readers

- Existing TUI/API/CLI readers continue to query normalized projections.
- New v8 event readers use bucket/event/payload fields.
- Legacy rows remain readable and are labeled with derived legacy bucket metadata
  only at query time where derivation is unambiguous.
- Migration does not rewrite all historical event payloads.

### 7.2 Metrics and dashboards

- Existing metric names and labels MUST remain stable where semantics are unchanged.
  Renames use generated aliases/dual emission until every bundled/documented query
  and historical fixture migrates at the declared removal version.
- Gateway metric defaults remain 60-second delta. The local Collector converts
  delta sums to cumulative Prometheus series, uses one application-metric path, and
  Grafana advertises a Prometheus interval of at least 60 seconds.
- New bucket labels and Agent360 spanmetrics dimensions must be bounded. Content,
  request/turn/trace/span IDs, arbitrary errors, users, and URLs are not metric
  labels.
- `local-observability-v1` is a generated registry consumer profile covering the
  fourteen dashboard UIDs, three datasource UIDs, metric/label/bucket inventory,
  Loki/Tempo fields, Agent360 variables, links, and source/packaged parity.
- Dashboards, rules, alerts, compatibility profile, and producers are updated in
  one change before an old field/provider/alias is removed.
- Queries must tolerate historical rows without v8 bucket fields and retain current
  PR #403 lifecycle/execution identity. A syntactically valid query that addresses
  a nonexistent field/label or produces a cadence-induced false zero fails tests.
- Backend ownership remains: Loki for durable chronology/counts, Prometheus for
  aggregates/latency/phase/topology, and Tempo for bounded trace waterfall.

The complete compatibility contract is
`14-agent-lifecycle-and-dashboard-compatibility.md`.

### 7.3 APIs

- Avoid breaking existing scan/finding response shapes solely for this refactor.
- Add bucket/event fields additively where possible.
- Do not add finding workflow status.
- Existing remediation remains optional and producer-supplied; central catalog
  enrichment is additive.

## 8. Security Review Points

Security review is required before merging changes that affect:

- Mandatory-floor membership.
- Changes to the `none` full-fidelity default, its visibility, or the scope of
  schema-defined content it preserves.
- Field classification or detector behavior.
- Judge-body retention.
- Destination credential resolution.
- Inbound telemetry raw payload handling.
- HMAC/signature order.
- SQLite failure behavior.
- Migration of global redaction-disable configurations.

## 9. Documentation and PR Expectations

Implementation PR descriptions must follow the repository-required structure:

- Stack/base note when applicable.
- `## Problem`
- `## Current Situation`
- `## Solution`
- Focused subsections and architecture diagram where useful.
- `## What Changed (Where & How)` with path table.
- `## Breaking Changes`.
- `## Open Issues / Follow-ups`; only linked GitHub issues may be listed, otherwise
  `None`.
- `## Test Plan` with exact commands and observed results.

Each phase should be reviewable and independently testable, but no phase may ship a
configuration that appears authoritative while significant producers still bypass
it without an explicit compatibility notice.
