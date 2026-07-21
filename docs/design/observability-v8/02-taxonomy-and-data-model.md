# Taxonomy and Canonical Data Model

## 1. Classification Principle

Buckets describe the semantic fact being recorded, not the vendor that produced it,
the destination receiving it, or the subsystem that happened to emit it.

- Cisco AI Defense is represented as `source: ai_defense`, not as a bucket.
- Galileo is represented as an OTLP destination preset, not as a bucket.
- “Audit” is a durability and governance property. Operator control-plane actions
  use `compliance.activity`; other buckets can also be mandatory audit records.
- A record MUST have one primary bucket. It MAY have source, connector, action,
  event-name, severity, phase, outcome, and correlation dimensions.

## 2. Bucket Catalog

The following fourteen IDs are bucket catalog version 1. IDs are stable public
contracts; future additions and deprecations follow the process in
`09-configuration-ux-and-bucket-evolution.md`.

### 2.1 `compliance.activity`

Purpose: durable control-plane audit trail for user, service, and system actions.

Example event names:

- `config.change.attempted`
- `config.change.applied`
- `config.reload.rejected`
- `policy.updated`
- `policy.reload.rejected`
- `redaction.profile.updated`
- `destination.updated`
- `observability.profile.changed`
- `approval.resolved`
- `alert.acknowledgement.requested`
- `alert.dismissal.requested`
- `authentication.failed`
- `authorization.denied`

Example data: actor, actor type, authentication mechanism, origin, action, target,
sanitized before/after summary, outcome, reason, revision, and correlation IDs.

`authentication.failed` and `authorization.denied` belong here when the attempted
access is to an administrative/operator control-plane boundary. Actor identity may
be unknown; the record stores only safe origin/mechanism/result metadata and never
the submitted credential.

Default sensitivity: high. Default signal recommendation: logs. Traces and metrics
are normally unnecessary except aggregate mutation/error metrics.

### 2.2 `security.finding`

Purpose: one concrete security-risk observation produced by a scanner, detector,
correlator, admission control, runtime inspection, network control, or external
security system.

Example event names:

- `finding.observed`
- `finding.correlated`

Example data: occurrence ID, stable rule ID, category, title, severity, confidence,
source, target reference, safe location, evidence summary, evidence fingerprint,
optional redacted excerpt, optional remediation guidance, scan/evaluation ID, and
correlation IDs.

A finding is not the automatic final state of every guardrail evaluation. One
evaluation or scan can produce zero, one, or many findings.

Default sensitivity: high. Default signal recommendation: logs and bounded count
metrics. Finding details MUST NOT be metric attributes.

### 2.3 `guardrail.evaluation`

Purpose: one execution of a policy, detector, classifier, judge, or inspection
control and the resulting decision.

Example event names:

- `guardrail.evaluation.started`
- `guardrail.evaluation.completed`
- `guardrail.evaluation.failed`
- `hook_decision` (preserved compatibility event name for the final
  connector-facing result)

Example data: evaluation ID, stage, policy and rule-set versions, detector sources,
scores, matched rule IDs, decision, would-block, enforced, duration, input reference
or hash, finding IDs, and enforcement-action IDs.

OPA admission, firewall, audit-retention, and skill-action policy APIs use these
same guardrail identities rather than a parallel policy-log taxonomy. Their
source-observed target reference is optional and centrally redacted per route;
security severity remains absent when the policy input did not report one.

This bucket MUST NOT contain a duplicate full prompt, response, tool argument set,
or tool result. It references `model.io` or `tool.activity` records and may contain
minimal redacted evidence.

`hook_decision` belongs primarily to `guardrail.evaluation`: it records the raw
guardrail action and the effective action returned after mode/capability mapping.
When `enforced: true` means an actual control was imposed, a separate linked
`enforcement.action` record owns that enforced attempt/outcome and qualifies for
the mandatory floor. The two records share evaluation/action/agent correlation but
do not duplicate model/tool content.

Default sensitivity: medium/high. Default signal recommendation: verdict logs,
evaluation traces, and aggregate metrics.

### 2.4 `enforcement.action`

Purpose: an actual attempt to impose or remove a control.

Example event names:

- `enforcement.block.requested`
- `enforcement.block.applied`
- `enforcement.block.failed`
- `enforcement.quarantine.applied`
- `enforcement.release.applied`
- `enforcement.redaction.applied`
- `enforcement.access.revoked`

Example data: action ID, action, target, requested/effective mode, initiator,
evaluation or finding references, outcome, reason, failure class, previous state,
and resulting state.

An action can fail without causing a lifecycle transition. Enforced outcomes are
part of the mandatory floor.

Default sensitivity: medium. Default signal recommendation: logs and aggregate
metrics; traces when action latency matters.

### 2.5 `model.io`

Purpose: interaction with a model provider.

Example event names:

- `model.request`
- `model.response`
- `model.stream.completed`
- `model.call.failed`

Example data: request/response ID, provider, model, operation, role structure,
prompt or response content when reported by the producer, content hashes, token counts, finish reason,
streaming state, latency, retry, and error class.

This is the canonical home of model content. Other buckets MUST reference these
records rather than copy their content.

Default sensitivity: critical. Default signal recommendation: traces and aggregate
metrics; content logs only through explicit policy.

### 2.6 `tool.activity`

Purpose: requested and completed agent tool interactions.

Example event names:

- `tool.invocation.requested`
- `tool.invocation.started`
- `tool.invocation.completed`
- `tool.invocation.blocked`
- `tool.invocation.failed`

Example data: invocation ID, tool name and class, caller, target, argument metadata
or reported content, result metadata or reported content, status, duration,
exit code, and error class.

Guardrail evaluation of a tool is a separate linked record. The evaluation is not a
superset of the tool record.

Default sensitivity: critical. Default signal recommendation: traces and aggregate
metrics; detailed logs by explicit policy.

### 2.7 `asset.scan`

Purpose: execution state and roll-up result of scanning an asset or content target.

Example event names:

- `scan.started`
- `scan.phase.completed`
- `scan.completed`
- `scan.failed`
- `scan.cancelled`

Example data: scan ID, scanner and rule-set version, target and revision, phases,
coverage, skipped checks, duration, exit state, maximum severity, and finding counts.

This is the scan process and summary. Individual issues are `security.finding`
records. A clean scan still produces `asset.scan` records and no findings.

Default sensitivity: medium. Default signal recommendation: summary logs, phase
traces, and duration/count metrics.

### 2.8 `asset.lifecycle`

Purpose: observed changes to the state of governed assets such as skills, MCP
servers, plugins, models, agent packages, policies, and other admitted components.

Example event names:

- `asset.discovered`
- `asset.registered`
- `asset.updated`
- `asset.admitted`
- `asset.activated`
- `asset.quarantined`
- `asset.released`
- `asset.disabled`
- `asset.removed`

Example data: asset ID, type, source, previous and new state, revision, provenance,
reason, and related scan or enforcement IDs.

If quarantine succeeds, emit one `enforcement.action` record for the attempted
control and one `asset.lifecycle` record for the resulting state transition. If
quarantine fails, emit the failed enforcement record but no false lifecycle change.

Default sensitivity: medium. Default signal recommendation: logs and inventory
metrics.

### 2.9 `network.egress`

Purpose: outbound network activity and its policy disposition.

Example event names:

- `egress.requested`
- `egress.allowed`
- `egress.blocked`
- `egress.completed`
- `egress.failed`

Example data: destination classification, redacted or normalized host, port,
protocol, method class, byte counts, policy rule, disposition, duration, and related
agent/tool/model identifiers.

Credentials, query secrets, full request bodies, and full response bodies MUST NOT
be included by default.

Default sensitivity: high. Default signal recommendation: metadata logs, traces,
and aggregate metrics.

### 2.10 `agent.lifecycle`

Purpose: lifecycle of an agent, session, run, or connector runtime.

Example event names:

- `session_start`
- `session_end`
- `subagent_start`
- `subagent_stop`
- `turn_start`
- `turn_end`
- `tool_start`
- `tool_end`
- `compact_start`
- `compact_end`
- `event`

Example data: conversation/current/root/parent agent, root/parent session, stable
lifecycle, execution attempt, operation, run, connector, depth, state, phase,
previous phase, immutable phase code, monotonically increasing per-execution
sequence, session source/resume state, transition, reason, and available user
correlation.

The required lifecycle vocabulary, identity semantics, phase-code mapping, and
root/subagent compatibility floor are defined in
`14-agent-lifecycle-and-dashboard-compatibility.md`. Delegation lineage is not the
same as OTel trace parentage. Completed turn/model/tool work remains visible before
a later `session_end`/`Stop` event.

Default sensitivity: low/medium. Default signal recommendation: logs, traces, and
availability metrics.

### 2.11 `ai.discovery`

Purpose: discovery of AI-related components and evidence supporting that discovery.

Example event names:

- `ai_component.discovered`
- `ai_component.changed`
- `ai_component.removed`
- `ai_component.confidence.changed`

Example data: component ID and type, detector, confidence, evidence types, scrubbed
basenames, hashes, match kind, and observed time.

Raw paths and arbitrary source contents MUST NOT be exported as discovery evidence.

Default sensitivity: medium. Default signal recommendation: change logs and bounded
inventory metrics.

### 2.12 `telemetry.ingest`

Purpose: inbound telemetry receiver behavior, normalization, and admission.

Example event names:

- `telemetry.batch.accepted`
- `telemetry.batch.rejected`
- `telemetry.batch.normalized`
- `telemetry.records.dropped`
- `telemetry.authentication.failed`
- `telemetry.authorization.denied`

Example data: protocol, signal, source connector, record count, byte count, schema
version, normalization result, rejection reason class, and latency.

Receiver authentication/authorization failures belong here because the protected
boundary is inbound telemetry admission. They are mandatory-floor logs even if
ordinary `telemetry.ingest` logs are disabled.

Opaque raw transport bodies MUST NOT bypass canonical routing. In particular,
special decoded HEC bodies must be normalized or safely summarized.

Default sensitivity: low/medium. Default signal recommendation: health logs and
metrics; diagnostic traces when troubleshooting ingestion.

### 2.13 `platform.health`

Purpose: operational state of DefenseClaw subsystems and observability components.

Example event names:

- `subsystem.ready`
- `subsystem.degraded`
- `subsystem.restored`
- `destination.queue_full`
- `destination.export_failed`
- `sqlite.write_failed`
- `schema.validation_failed`
- `redaction.failed_closed`
- `destination.authentication.failed`
- `destination.authorization.denied`

Example data: subsystem or destination, state transition, stable error code, retry
state, dropped count, queue utilization, and sanitized cause class.

Outbound exporter/destination credential rejection belongs here as component
health, not as operator authentication. These failure events are mandatory-floor
logs and MUST NOT include a token, authorization header, or credential value.

Default sensitivity: low. Default signal recommendation: logs and metrics. Health
records MUST avoid embedding the failed content.

### 2.14 `diagnostic`

Purpose: temporary developer troubleshooting that does not fit a stable production
event contract.

Example event names:

- `diagnostic.message`
- `diagnostic.snapshot`

Example data: component, bounded message, and classified fields.

Diagnostics MUST NOT be used as a shortcut around stable buckets. They are disabled
by recommended production profiles and must still pass central redaction.

Default sensitivity: high and unpredictable. Default signal recommendation:
disabled unless temporarily enabled.

### 2.15 Catalog v1 source defaults

These are the normative effective values when neither `observability.defaults` nor
a bucket override is present. Catalog v1 is intentionally full-fidelity: every
bucket collects every supported signal and uses `none` redaction. Operators narrow
collection or add redaction explicitly.

| Bucket | Logs | Traces | Metrics | Redaction |
|---|---:|---:|---:|---|
| `compliance.activity` | true | true | true | `none` |
| `security.finding` | true | true | true | `none` |
| `guardrail.evaluation` | true | true | true | `none` |
| `enforcement.action` | true | true | true | `none` |
| `model.io` | true | true | true | `none` |
| `tool.activity` | true | true | true | `none` |
| `asset.scan` | true | true | true | `none` |
| `asset.lifecycle` | true | true | true | `none` |
| `network.egress` | true | true | true | `none` |
| `agent.lifecycle` | true | true | true | `none` |
| `ai.discovery` | true | true | true | `none` |
| `telemetry.ingest` | true | true | true | `none` |
| `platform.health` | true | true | true | `none` |
| `diagnostic` | true | true | true | `none` |

“True” means that a producer records the signal when that bucket defines the
corresponding log family, span family, or metric instrument. It does not require
inventing a meaningless metric or span merely to fill the matrix.

For a collected log or trace, full-fidelity defaults also enable capture of the
family's schema-defined prompt, response, message, tool argument/result, evidence,
reason, error, and path fields when the producer has them. Missing producer data
remains honestly unreported; it is never fabricated.

## 3. Canonical Record Envelope

Every canonical record MUST carry:

| Field | Requirement |
|---|---|
| `schema_version` | Required; integer `1`, the canonical record envelope version |
| `bucket_catalog_version` | Required; integer `1`, the catalog version under which the bucket assignment was emitted |
| `timestamp` | Required UTC event time |
| `observed_at` | Optional UTC receive/observe time when different |
| `record_id` | Required unique occurrence ID |
| `bucket` | Required catalog value |
| `signal` | Required: logs, traces, or metrics |
| `event_name` | Required stable registry ID: normally a dotted log event, trace family ID, or metric instrument ID, with registry-declared canonical snake_case lifecycle/compatibility names such as `session_start` and `hook_decision` also valid; route selectors never depend on a rendered high-cardinality span name |
| `span_name` | Trace-only OTel display/operation name derived from the registered family pattern, such as `chat {model}` |
| `severity` | Optional for records without severity semantics |
| `log_level` | Optional operational logging level; separate from security severity |
| `source` | Required stable producer identity such as `ai_defense`, `codeguard`, `gateway`, or `operator_api` |
| `connector` | Optional connector identity |
| `action` | Optional stable action vocabulary |
| `phase` | Optional lifecycle/evaluation phase |
| `outcome` | Optional stable outcome vocabulary |
| `mandatory` | Required Boolean for log records; true only for floor-qualified semantics |
| `correlation` | Required exact object, possibly empty, containing only the optional string join keys in §3.1 |
| `provenance` | Required exact object with the fields and types in §3.4 |
| `body` | Required immutable canonical JSON object for logs and traces; forbidden for metrics |
| `instrument_data` | Required immutable canonical JSON object for metrics; forbidden for logs and traces |
| `field_classes` | Required JSON-Pointer-to-field-class object under the derivation rule in §3.5 |

Exactly one payload arm is present: `body` for `signal: logs` or `signal: traces`,
and `instrument_data` for `signal: metrics`. A record with neither arm or both arms
is invalid. The envelope `schema_version` is the version of the complete canonical
record shape. It is distinct from the telemetry registry version and from a span
family's `family_schema_version`.

### 3.1 Correlation fields

`correlation` is an exact object with `additionalProperties: false`. Every property
below is optional; when present, its value MUST be a nonempty string. The builder
preserves known values and never invents one:

| Property | Join identity |
|---|---|
| `run_id` | Run |
| `request_id` | Request |
| `session_id` | Session |
| `turn_id` | Turn |
| `trace_id` | Trace |
| `span_id` | Span |
| `agent_id` | Agent |
| `agent_instance_id` | Agent instance |
| `policy_id` | Policy |
| `policy_version` | Policy version |
| `evaluation_id` | Evaluation |
| `scan_id` | Scan |
| `finding_occurrence_id` | Finding occurrence |
| `enforcement_action_id` | Enforcement action |
| `model_request_id` | Model request |
| `model_response_id` | Model response |
| `tool_invocation_id` | Tool invocation |
| `destination_id` | Destination when the record concerns a destination |
| `connector_id` | Connector |
| `sidecar_instance_id` | Sidecar instance |

### 3.2 Action, phase, decision, and outcome

These fields have different jobs and MUST NOT be used interchangeably:

- `action` names the requested operation, such as `config.change`, `block`,
  `quarantine`, or `release`.
- `phase` names bounded progress inside an operation, such as `attempt`, `validate`,
  `apply`, or `finalize`.
- A typed body `decision` records a domain verdict such as `allow`, `block`, `deny`,
  `review`, or `redact` when that family defines decision semantics.
- `outcome` records the observed result of the record's subject.

The canonical v8 outcome vocabulary is:

`attempted`, `validated`, `applied`, `completed`, `allowed`, `blocked`, `denied`,
`approved`, `quarantined`, `redacted`, `revoked`, `released`, `terminated`,
`rejected`, `failed`, `timed_out`, `cancelled`, `partial`, `skipped`, and
`no_change`.

Each family schema declares the applicable subset. Producers MUST NOT introduce an
unregistered family-specific synonym. For example, a successfully executed
guardrail that decides to block uses `decision: block` and `outcome: blocked`; its
OTel status can still be OK because the control itself succeeded. A configuration
mutation record uses the existing control-plane subset `attempted`, `validated`,
`applied`, `rejected`, or `failed`.

### 3.3 Immutable bounded payloads and deterministic JSON

At the P2 generic-record boundary, `body` and `instrument_data` are JSON objects,
not pre-serialized strings or opaque byte buffers. Their recursive values are
limited to JSON object, array, string, Boolean, null, and finite number values.
Object keys and strings MUST be valid UTF-8. NaN, positive or negative infinity,
invalid UTF-8, cyclic values, non-string map keys, and implementation-specific
objects are rejected.

Construction deep-copies and freezes the selected payload arm and all other nested
record objects. No constructor input, accessor, route projection, redaction pass,
destination adapter, or serialization call can mutate the canonical record or
retain a mutable alias into it. A failed build returns no partially usable record.

The generic P2 ceiling for either payload arm is:

- at most 32 container levels below the payload root;
- at most 8,192 total object members plus array elements; and
- at most 1,048,576 bytes (1 MiB) in the deterministic encoding defined below.

The complete deterministic record encoding, including the envelope, payload arm,
and explicit field-class map, is limited to 4,194,304 bytes (4 MiB). Envelope text
is additionally bounded as follows: `record_id`, each correlation identifier, and
`span_name` are at most 512 UTF-8 bytes; `binary_version` is at most 256 UTF-8
bytes; and each optional provenance hexadecimal value is at most 128 ASCII bytes.
There is no smaller arbitrary JSON-Pointer length limit: the payload and complete
record ceilings bound pointer storage, and a valid pointer to a legal payload key
must remain representable.

Per-family schemas and destination projections MAY impose lower limits. The generic
builder rejects a payload above a P2 ceiling; it does not truncate or partially
accept canonical input. Later projection-specific truncation follows the registered
family contract and never mutates the canonical record.

DefenseClaw deterministic JSON is UTF-8 JSON with object keys ordered by their UTF-8
byte sequence, array order preserved, no insignificant whitespace, and the minimal
JSON escapes required for a valid string. Numbers inside the `body` or `metric`
canonical `Value` payload are emitted in their shortest exact plain or scientific
base-10 form, with negative zero emitted as `0`. Equivalent integer, decimal,
exponent, and native numeric payload inputs therefore converge on the same bytes.
Schema-defined integral envelope fields such as `schema_version`,
`bucket_catalog_version`, `config_generation`, and provenance
`registry_schema_version` are emitted as ordinary unsigned or signed plain base-10
integers; they are not dynamically typed payload numbers. The same immutable value
always produces the same bytes. Record integrity and equality tests use this
encoding; map iteration order, locale, process, and destination do not affect it.

Canonical `Value` number normalization is lossless over the accepted JSON decimal
value. An
implementation MUST NOT round a parsed decimal through binary floating point or
silently change precision merely to obtain a shorter spelling. It removes
insignificant decimal zeroes, normalizes the exponent, and chooses a shortest exact
plain or scientific representation; native binary floating-point inputs use their
shortest exact round-trippable decimal representation before this normalization.

### 3.4 Provenance

`provenance` is an exact object with `additionalProperties: false` and these fields:

| Property | Requirement |
|---|---|
| `producer` | Required stable token matching `[a-z][a-z0-9_.-]{0,63}` |
| `binary_version` | Required nonempty string, at most 256 UTF-8 bytes |
| `registry_schema_version` | Required positive integer |
| `config_generation` | Required nonnegative integer |
| `build_commit` | Optional nonempty lowercase hexadecimal string, at most 128 ASCII bytes |
| `config_digest` | Optional nonempty lowercase hexadecimal string, at most 128 ASCII bytes |

The optional hexadecimal fields match `[0-9a-f]+`; uppercase, prefixes such as
`0x`, separators, and mutable display labels are invalid. `producer` identifies the
record-building component and is distinct from the envelope `source`, which
identifies the semantic source used for routing.

### 3.5 Field-class map and builder ownership

`field_classes` is an immutable object whose keys are RFC 6901 JSON Pointers rooted
at the selected payload object and whose values are exactly one of the eight field
classes: `metadata`, `identifier`, `content`, `reason`, `evidence`, `error`, `path`,
or `credential`. An entry classifies the value at that exact pointer. Invalid
pointers, pointers that do not resolve, unknown classes, and conflicting duplicate
pointers are rejected.

This complete map is canonical-record state. Route projections derive a separate
delivery map after transformation as specified by
`04-redaction-contract.md` §7.1: it is the surviving subset of original
classification provenance and cannot retain the name or presence of an object
property removed by redaction. It does not synthesize a class for a structural
`null` created only by recursive pruning. The canonical map itself is never
mutated.

Object member names are structural schema vocabulary, not a covert content
channel. Producer- or provider-controlled names, arbitrary tool-argument map keys,
labels, and other dynamic names MUST be represented as explicitly classified
string values (for example, ordered `{name, value}` entries), never copied into
JSON property names. P2 current typed adapters enforce this as a producer contract;
P5 generated family builders and registry conformance make it mechanical for every
schema. A destination adapter cannot infer that a property name is safe, and
recursive projection pruning is not a substitute for this builder rule.

Classification is exact, not inherited: a class at the root or a parent container
does not classify any descendant. Without generated schema proof, every scalar,
null, empty-object, and empty-array leaf has its own explicit pointer entry. This
prevents a caller from labelling a parent `metadata` and thereby upgrading unknown
nested content to a safe class.

The map MAY be empty only when the registered family schema derives a field class
for every dynamic field in the selected payload. Otherwise every dynamic field not
classified by that schema MUST have an explicit pointer entry. Schema-derived and
explicit classifications MUST agree. This makes an empty map evidence of complete
registered classification, not an unclassified-payload escape hatch.

The ordinary generic constructor accepts only complete explicit classification.
Schema-derived construction is an internal generated-builder capability backed by
the registered family schema; it is not a public Boolean or caller assertion. In
the same way, producers cannot set `mandatory` directly: the current classified-log
builder resolves producer kind, registered key, and typed facts through the reviewed
classification catalog. When collection is disabled, its separate floor builder
accepts no ordinary body and emits an internally marked minimal placeholder body
containing only `floor_only: true` and `detail_state: omitted`, both classified as
metadata. The router requires this marker for floor admission and rejects it on the
ordinary path. P5 generated family floor builders may replace that placeholder with
additional reviewed safe fields, but can never admit ordinary content/evidence/
credential bodies to the floor path.

Pointers never include the envelope arm name. For example, a log body field
`{"message":"hello"}` is classified by `/message`, a trace attribute is
classified by `/attributes/defenseclaw.source`, and a metric label is classified
by `/attributes/defenseclaw.connector.source`. `/body/message` and
`/instrument_data/attributes/...` are invalid because neither `body` nor
`instrument_data` is inside the selected payload root. Generated builders expand
array positions to concrete RFC 6901 indices before constructing the record.

P2 owns the immutable generic record constructor, deterministic serializer,
registered bucket/signal/event identity validation, canonical outcome validation,
and the current classified-log adapter needed to move representative producers onto
the router. The generic constructor accepts an already-typed payload object; it does
not infer a family-specific body or instrument shape. P5-WP02 remains the sole owner
of generated log/trace/metric family builders, their detailed required/conditional
fields, applicable outcome subsets, lower family bounds, generated field-class
maps, and family-schema validation. Generated builders MUST terminate at this same
generic P2 constructor. The unexported schema-derived log constructor is the only
generated path that may pass catalog-derived `mandatory=true`; it accepts a private
generated-family contract carrying the exact log identity and derived mandatory
decision rather than a caller-supplied boolean, rejects a nil/non-log/mismatched
contract, and does not expose floor authority to ordinary callers.

### 3.6 Typed structural registry contract

The detailed shape above and every signal-specific payload shape are authored once
in `schemas/telemetry/v8/registry.yaml` under the typed `structural_contract`
defined by `12-telemetry-schema-architecture.md` §5.2.2. The manifest contract is
bound to the existing Go `Record`, `RecordInput`, and `Value` types and their
constants. It MUST NOT create a second canonical envelope or serializer.

The signal union is exact:

| Signal | Required payload/state | Forbidden payload/state |
|---|---|---|
| `logs` | `body`, Boolean `mandatory` | `instrument_data`, `span_name` |
| `traces` | `body`, `span_name` | `instrument_data`, `mandatory` |
| `metrics` | `instrument_data` | `body`, `span_name`, `mandatory`, `severity`, `log_level`, envelope `outcome` |

The generic immutable constructor enforces the signal-arm prohibitions as well as
the generated family builders, so direct in-package construction cannot serialize
a metric severity, log level, or envelope outcome that the registry forbids.

A log body is the exact object resolved from its one registered body group. A trace
body is the exact structural span object in `11-trace-and-span-contract.md` §5.4
plus the family’s resolved attributes, events, and link relations. A metric
`instrument_data` object is exactly `{value, attributes}`: the family identity,
instrument kind, value type, unit, description, temporality, and histogram
boundaries come from the registered metric family and are not copied into every
sample. `value` is a finite `int64` or `double` matching the family value type, and
`attributes` is its exact canonical label object, possibly empty. SDK aggregation,
not the raw observation, constructs OTLP sum, gauge, or histogram data points.

Every structural object uses `additionalProperties: false`. Family builders reject
unknown payload members, a metric label absent from the resolved label schema,
duplicate instrument metadata inside `instrument_data`, and any envelope field
forbidden by the selected signal arm. The generated top-level public bundle uses
the same discriminated union; it cannot accept a shape that the generated builder
would reject.

## 4. Severity

Canonical security severity uses the five-level vocabulary already ranked by
`internal/audit.SeverityRank` and scanner findings:

`INFO < LOW < MEDIUM < HIGH < CRITICAL`

DefenseClaw currently has two producer ladders: audit/scanner records use
`INFO..CRITICAL`, while guardrail/judge evaluation uses
`NONE < LOW < MEDIUM < HIGH < CRITICAL`. `NONE` means a clean evaluation with no
security concern; it is a valid producer value but not a sixth canonical security
rung. Both producer ladders merge into the five canonical values below.

`WARN`/`WARNING` is not a sixth security rung. Current code uses it in some
`gatewaylog`, audit, and OTel operational paths, but the audit/scanner comparison
functions do not rank it consistently. v8 resolves that inconsistency as follows:

| Producer value | Canonical `severity` | Optional `log_level` |
|---|---|---|
| `NONE` (clean guardrail/judge evaluation) | `INFO` | Absent unless the producer also has an operational level |
| `DEBUG` | `INFO` when a severity is required; otherwise absent | `DEBUG` |
| `INFO` | `INFO` | `INFO` |
| `LOW` | `LOW` | Producer level if known |
| `WARN` / `WARNING` (including `slog` WARN) | `MEDIUM` | `WARN` |
| `MEDIUM` / `MED` | `MEDIUM` | Producer level if known |
| `ERROR` | `HIGH` | `ERROR` |
| `HIGH` | `HIGH` | Producer level if known |
| `FATAL` / `CRITICAL` | `CRITICAL` | `FATAL` when applicable |

The original producer value MAY be retained as bounded metadata. Unknown severity is
invalid when a specific event contract requires severity and is otherwise absent,
not silently coerced to `INFO`.

The original `NONE` value remains expressible through the evaluation decision/result
fields and MAY also be retained as bounded producer metadata. It must never cause a
clean evaluation record to fail schema validation.

`min_severity` route comparison uses only the five canonical values. A record without
severity does not match a selector containing `min_severity`. `log_level` is not a
substitute for security severity and is not used by `min_severity` in v8.

## 5. Security Finding Contract

### 5.1 Required fields

A `security.finding` log MUST include:

- Unique occurrence `finding_id`.
- Stable `rule_id` or producer namespaced detection ID.
- `title`.
- Canonical severity.
- `source`.
- Target reference.
- Scan ID or evaluation ID when produced by a scan/evaluation.

### 5.2 Optional fields

- Category.
- Confidence in `[0,1]`.
- Safe location and line number.
- Evidence summary.
- Evidence fingerprint.
- Redacted evidence excerpt.
- Remediation guidance.
- Tags from a bounded or source-qualified vocabulary.

### 5.3 Evidence summary generation

The pipeline MUST NOT ask a general-purpose model to invent an evidence summary.
The normalizer chooses the first available source:

1. A producer-supplied structured, already bounded summary.
2. A deterministic versioned template associated with the rule ID.
3. A deterministic fallback: rule title, target type, and safe location.

The summary MUST NOT contain the complete matched credential, prompt, response, tool
argument, tool result, or file contents. It remains a `content` field and is
redacted again per route.

Evidence should prefer structured rule ID, source, target, location, confidence,
hash/fingerprint, and a redacted bounded excerpt over prose.

### 5.4 Remediation generation

Remediation is optional. Resolution order is:

1. Valid producer-supplied remediation.
2. A versioned remediation template associated with the rule ID or category.
3. Omit the field.

The record MUST identify the remediation source and catalog version when a catalog
template is used. The pipeline MUST NOT fabricate specific facts, claim that a fix
was applied, or treat guidance as an enforcement outcome.

Existing scanner-provided remediation remains supported. Producers that currently
emit no remediation are valid.

### 5.5 No finding workflow status in v8

This scope records immutable finding observations. It MUST NOT add `status: open`
to every occurrence. DefenseClaw currently does not own a finding case lifecycle,
and a logging refactor must not imply one.

If case management is added later, it requires a separate specification covering
stable deduplication fingerprints, state versus analyst disposition, concurrent
updates, source-of-truth ownership, APIs, TUI, remote synchronization, retention,
and transitions such as resolved and reopened.

### 5.6 Alert acknowledgement is a separate projection

Acknowledging or dismissing an alert does not mutate a finding occurrence,
overwrite its canonical severity, or add a finding workflow status. The mutable
alert acknowledgement projection stores the linked occurrence/event ID, current
disposition (`unreviewed`, `acknowledged`, or `dismissed`), actor, timestamps, and a
monotonically increasing per-alert `projection_version`. An absent row is
`unreviewed` at version zero.

Every acknowledgement or dismissal command MUST carry a stable `operation_id` and
the `expected_projection_version` observed by the caller. A state-changing command
is a compare-and-swap: it applies only when the expected version equals the stored
version and then advances the version by exactly one. The first transaction that
successfully commits that comparison is the winner; a concurrent command with the
same expected version is rejected with the now-current version. Wall-clock time,
actor identity, and lexical operation-ID order MUST NOT override commit order. A
command that already requests the current disposition succeeds with outcome
`no_change` and does not advance the version. Bulk operations apply this precondition
independently to every target and report per-target outcomes; they cannot perform a
blind last-write-wins update.

The target MUST identify either an immutable
`security.finding / finding.observed` occurrence already present in local event
history, a recognized legacy alert occurrence, or an alert that already has
protected acknowledgement state or receipts. A first-seen command for an absent
identifier, a non-finding event, or an arbitrary caller-supplied string fails before
creating an operation receipt, compliance event, or projection. Age retention of
the event-history row does not make an alert ineligible after protected alert state
or receipts exist.
For an unbucketed v7 row, “recognized legacy alert” means the explicit legacy
`alert` action or an action whose fixed audit-action classification is
`security.finding`; severity alone is not sufficient. A protected baseline already
created from a historical `ACK` remains eligible because v7 irreversibly erased the
original severity/action context and rollback compatibility cannot reconstruct it.

The first accepted use of an operation ID creates exactly one immutable, mandatory
`compliance.activity` event with canonical severity `INFO`. Its event name is
`alert.acknowledgement.requested` or `alert.dismissal.requested`; its body records the
operation ID, target occurrence/event ID, requested disposition, actor, outcome,
expected and observed versions, and projection versions before and after. Applied,
`no_change`, and stale-version `rejected` outcomes are all audited. The idempotency
record, compliance event, and any projection change are committed in one SQLite
transaction.

An exact retry with the same operation ID and normalized command fingerprint MUST
return the original outcome, event ID, and resulting version without changing the
projection, timestamps, or event count. Reusing an operation ID with a different
target, actor, action, expected version, or requested disposition is an idempotency
conflict: it cannot mutate the projection or replace the original event and is
audited as a rejected request through the ordinary request-audit path.

The normalized command fingerprint MUST be a domain-separated HMAC-SHA-256 over a
deterministic encoding of the complete normalized command, including the governed
actor value, using the stable process correlation key. Its protected receipt value
records the algorithm/version and key identity with the digest. An unavailable or
inconsistent key fails the first-seen operation closed. Neither the fingerprint nor
raw key material is part of the canonical compliance-event body, exported telemetry,
health diagnostics, or error text; an unkeyed digest would permit offline guessing
of low-entropy actor identities and is forbidden.

For one alert, applied operation receipts are ordered by
`projection_version_after`, with every transition satisfying `before = N` and
`after = N + 1`; timestamps and record IDs are not ordering authorities. Rejected
and `no_change` receipts carry the version they observed but do not enter the
applied transition sequence. The immutable operation receipt ledger, including a
versioned baseline derived from legacy acknowledgement evidence, is authoritative
for the alert state machine and exact retries. Matching `audit_events` remain the
authoritative observability representations while retained, but age retention may
remove them without invalidating a receipt. Reconciliation MUST derive expected
state from the contiguous applied receipt sequence, transactionally rebuild a
missing or stale projection, accept a missing age-reaped audit representation, and
fail closed when a still-retained audit event contradicts its receipt. A receipt
gap, conflicting receipt at one version, or projection state ahead of the receipt
ledger MUST produce a mandatory `platform.health` record, block further mutation of
that alert, and never be resolved by guessing from timestamps. Reconciliation does
not fabricate a modern operator action for a legacy baseline.

Legacy v7 `audit_events` rows whose `severity` was overwritten with `ACK` are read
as compatibility evidence of acknowledgement, not as a sixth canonical severity.
The v8 reader preserves raw `ACK` in legacy provenance, excludes it from severity
ranking, and materializes the acknowledgement projection. When the original value
cannot be recovered, the compatibility read model reports
`legacy_original_severity: unknown` and does not synthesize a canonical
`security.finding` record, because that bucket requires a real canonical severity.
It does not put a sentinel in the canonical `severity` field, rewrite historical
bytes, or guess the lost severity.

## 6. Boundary Examples

### 6.1 Model inspection

One model request can produce:

1. `model.io / model.request` — provider/model, content or content reference, token
   metadata.
2. `guardrail.evaluation / guardrail.evaluation.completed` — pre-model stage,
   policy versions, rule IDs, block decision, evaluation duration, input reference.
3. Zero or more `security.finding / finding.observed` — concrete detected risks.
4. `enforcement.action / enforcement.block.applied` — only if DefenseClaw actually
   blocked the call.

The four records share request, trace, and evaluation identifiers. They do not copy
the same body.

### 6.2 Tool inspection

One tool attempt can produce:

1. `tool.activity / tool.invocation.requested`.
2. `guardrail.evaluation / guardrail.evaluation.completed` with the invocation ID.
3. Optional findings.
4. Optional enforcement action.
5. `tool.activity / tool.invocation.blocked` or completed outcome.

### 6.3 Asset scan and quarantine

One scan can produce:

1. `asset.scan / scan.started`.
2. Trace spans for phases.
3. `asset.scan / scan.completed` with counts.
4. Zero or more `security.finding / finding.observed` records.
5. `enforcement.action / enforcement.quarantine.applied` if policy takes action.
6. `asset.lifecycle / asset.quarantined` only after the asset state actually changes.

## 7. Classification Rules

1. If the fact is “a control ran and decided,” use `guardrail.evaluation`.
2. If the fact is “a concrete risk was observed,” use `security.finding`.
3. If the fact is “a control was imposed,” use `enforcement.action`.
4. If the fact is “the governed object changed state,” use `asset.lifecycle`.
5. If the fact is “a scanner ran,” use `asset.scan`.
6. If the fact is model content/transport metadata, use `model.io`.
7. If the fact is a tool request/result, use `tool.activity`.
8. If the fact is an operator or system control-plane mutation, use
   `compliance.activity`.
9. An event name MUST NOT be assigned by matching arbitrary free-form message text.
10. Every producer added or migrated MUST have a classification-table test.

## 8. Recommended Audience Profiles

| Audience | Enable | Usually suppress or reduce |
|---|---|---|
| Compliance | Compliance activity, enforcement, asset lifecycle, high-severity findings, audit-integrity health | Model/tool content, diagnostics, detailed evaluation traces |
| SOC | Findings, guardrail evaluations, enforcement, egress, discovery, scans, platform health | Raw model/tool content except incident workflows |
| AI safety/detection engineering | Evaluations, sampled/redacted model I/O and tool activity, findings, evaluation traces/metrics | Unrelated lifecycle detail |
| Platform/SRE | Platform health, telemetry ingest, agent lifecycle, metrics and traces | Model/tool content logs |
| Developer troubleshooting | Temporarily enabled diagnostics, model/tool/evaluation traces and selected logs | Long retention and broad remote fan-out |
| Privacy-minimal production | Mandatory local floor, high-severity findings, enforced outcomes, aggregate metrics | Content-bearing logs and diagnostics |
