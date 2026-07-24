# Inbound OTLP Accepted-Record Import and Re-export Contract

## 1. Scope and non-negotiable boundary

This document is the normative accepted-record contract for the authenticated
DefenseClaw OTLP/HTTP receiver. It completes the intentionally open requirement in
05 section 8 and the acceptance requirement in 07 section 9.5.

Inbound OTLP is a producer protocol. It is not a trusted canonical-record protocol,
a raw-event archive, or a request to forward an opaque OTLP leaf. DefenseClaw MUST
decode a request with the official OTLP protobuf model, classify each leaf through
one generated binding, enforce collection, and construct a new local canonical
record before local persistence or optional export. No request field may directly
select a bucket, mandatory-floor status, route, destination, redaction profile,
field class, local source, or trusted provenance.

In this document:

- A **leaf** is one `LogRecord`, one `Span`, or one metric data point. An OTLP
  metric descriptor containing three data points therefore contains three leaves.
- **Import** means constructing a new local canonical record for the leaf through a
  generated family builder.
- **Derive** means constructing one or more new canonical observations from exact
  source facts. A derived observation is not represented as a faithful copy of the
  source leaf.
- **Unsupported** means no canonical record is constructed. The raw leaf is not
  persisted or exported.
- **Native** means an OTLP projection produced by a DefenseClaw v8 exporter and
  validated against the local registry. A native marker is a shape discriminator,
  not proof that the sender is trusted.

This contract introduces no new `config.yaml` knob. The authenticated receiver and
its existing connector source are the admission boundary; the ordinary bucket
collection and destination policy remain the only observability policy controls.

## 2. Mapping authority

### 2.1 One closed generated catalog

`schemas/telemetry/v8/registry.yaml` MUST own an `inbound_bindings` section in the
same materialized registry view as the families and canonical-to-OTLP mappings.
There is no runtime hand list and no user-authored binding grammar. The registry
compiler MUST generate:

- a Go discriminator and typed normalizer used by the receiver;
- a machine-readable `schemas/telemetry/generated/compatibility/inbound-otlp.json`;
- positive, negative, and single-fault OTLP JSON/protobuf fixtures; and
- the support table in the generated human catalog.

Every binding has the following closed properties:

| Property | Contract |
|---|---|
| `class_id` | Stable binding-class identifier matching `^otlp\.[a-z0-9][a-z0-9._-]{0,127}$` |
| `variant_id` | Stable class-local exact discriminator variant; authored for finite aliases and compiler-derived from the exact family/instrument ID for native expansions |
| `signal` | Exactly one of `logs`, `traces`, or `metrics` |
| `sources` | One or more authenticated receiver source IDs, or the explicit token `any_authenticated` |
| `mode` | Exactly `import`, `derive`, or `import_and_derive` |
| `discriminator` | Exact resource/scope/schema URL/instrument/event/attribute predicates; no substring, suffix, case-folded guess, or first-match order |
| `target_families` | One or more registered canonical families materialized as separate one-target descriptors; an `import` match has exactly one primary target while `derive`/`import_and_derive` may have explicit augmentation targets |
| `field_bindings` | Exact typed source-to-target mappings, normalization, absence behavior, and source precedence |
| `source_unit_rule` | Compiler-resolved exact source-unit spellings, sealed target unit, and scale for a metric mapping; `none` for mappings that do not consume a metric unit |
| `time_rule` | Exact source timestamp and fallback rule |
| `outcome_rule` | Exact fixed or status-derived canonical outcome, when the target family requires one |
| `unknown_fields` | Always `drop_and_count` for v8 |
| `native_round_trip` | Boolean allowed only when the compiler proves the OTLP representation is reversible for the supported leaf shape |

The compiler MUST materialize two levels. One generated **match descriptor** owns
one exact discriminator and is identified by `class_id + variant_id`. One or more
generated **target descriptors** reference that match and each owns exactly one
canonical target; a target ID is `match_id + target_family_id`. Ambiguity is
evaluated among match descriptors, never among the explicit targets of one match.
The materialized-view digest, compatibility-catalog digest, generated Go inbound
plan digest, and generated output inventory MUST cover the sealed target instrument
unit and the complete ordered `source_unit_rule`. A changed spelling, order, scale,
target unit, or rule kind is semantic drift and MUST fail the corresponding
generation/drift check; it cannot be repaired by a runtime fallback table.

The compiler MUST prove that match discriminators are mutually exclusive for the
same signal and authenticated source. Zero matches is `unsupported_identity`;
more than one match is `ambiguous_identity`. Neither case may fall back to a
generic log, span, metric, bucket, family, or raw-body record.

The target family is the sole bucket, event/family/instrument name, schema version,
allowed outcome, field type, and field-class authority. Payload attributes named
`defenseclaw.bucket`, `defenseclaw.event.name`, or
`defenseclaw.span.family` are consistency assertions only in a native binding and
MUST equal the generated target. They never classify a non-native leaf.

The compiler emits a separate private `import_context` capability exactly for
imported log targets. That extra capability exists to remove the local
mandatory/floor program from an otherwise identical log-family descriptor. Trace
and metric families have no mandatory-floor or SQLite construction path, so their
exact sealed generated target descriptor is itself the private construction
capability. A trace/metric constructor MUST still require an import-role target,
validate its concrete descriptor and authenticated-source match, and remain
incapable of accepting an arbitrary family ID, descriptor, field-class map, or raw
payload. The absence of trace/metric `import_context_id` rows is therefore
intentional and MUST NOT be filled by a handwritten parallel context registry.

An authored row described as a **binding class** below is compiler shorthand, not
one wildcard runtime binding. The compiler MUST expand it into exact generated
match and target entries in `inbound-otlp.json`. For native expansions the exact
family/instrument supplies the compiler-derived variant; for finite external
aliases, such as the five duration instrument names, each exact alias has an
authored variant so two wire identities targeting the same family cannot collide.
For example, the native log class produces a match such as
`otlp.native.log.v8.log.model.request` and a separate one-target descriptor, not a
runtime `any registered log` branch. A GenAI operation match may own its imported
span target plus the explicit elapsed-time duration augmentation without becoming
two ambiguous matches. The generated discriminator includes the target's exact
event/family/instrument identity and schema/version/shape rules. Generation fails
on missing eligible coverage, duplicate match or target IDs, overlapping match
discriminators, a target not owned by the same materialized view, or a sender value
that can choose a target outside the generated expansion.

Before match evaluation, the compiler-generated recognizer classifies the reserved
DefenseClaw marker set as exactly `native_exact`, `native_malformed`, or `external`.
Native bindings require `native_exact`; connector and standard GenAI bindings
require `external`. Any partial, inconsistent, or malformed reserved marker set is
`native_malformed` and cannot fall through to an external binding merely because
it also carries a standard GenAI or connector discriminator.

The compiler also generates one exact **self-echo recognizer** per registered
native outbound family, including non-reversible histogram families. A recognizer
may only identify a self candidate when the native shape and the reserved
`defenseclaw.telemetry.forward.instance_id` transport value match the local
instance; the semantic resource `defenseclaw.instance.id` is never used for this
comparison. `OTLP-I03` still validates the remaining transport metadata before
returning `self_suppressed`. The recognizer has no builder, target-construction,
routing, or floor capability. This allows an echo of a locally exported aggregate
to terminate even when another instance's same aggregate would correctly have no
reversible import binding.

### 2.2 Required v8 binding inventory

The first v8 release MUST contain exactly the following binding classes. Adding a
source identity later is a registry change with generated fixtures, not a receiver
code heuristic.

| Binding ID/class | Exact inbound identity | Required disposition |
|---|---|---|
| `otlp.native.log.v8` | Log body is a JSON string containing one exact v8 projected record; resource has the original nonempty semantic `defenseclaw.instance.id`; leaf has exact nonempty `defenseclaw.record.id`, `defenseclaw.bucket`, `defenseclaw.signal=logs`, registered `defenseclaw.event.name`, and valid forward instance/destination/hop transport keys; envelope/provenance registry versions, projection metadata, bucket, and event agree with the local registry | Compiler expands one binding per registered log family. Import an other-instance leaf through the import-only family context; suppress only when the forward instance is local |
| `otlp.native.span.v8` | Scope `schema_url=https://defenseclaw.io/schemas/telemetry/v8`, scope name `defenseclaw.telemetry`, resource `schema_url=https://opentelemetry.io/schemas/1.42.0`, original nonempty semantic resource instance ID, valid forward instance/destination/hop transport keys, valid trace/span IDs, and exact registered bucket/family/family-schema markers | Compiler expands one binding per registered span. Import when its generated reverse mapping validates every required field, kind, name, timing, status, event, link, and dropped count; suppress only when the forward instance is local |
| `otlp.native.metric.v8` | Scope name `defenseclaw.telemetry`, scope `schema_url=https://defenseclaw.io/schemas/telemetry/v8`, resource `schema_url=https://opentelemetry.io/schemas/1.42.0`, original nonempty semantic resource instance marker, exact forward instance/destination/hop transport keys on the hop-tier resource, exact registered instrument name, and source unit byte-equal to the sealed target instrument unit | Compiler expands one binding per reversible registered instrument. Import only a gauge point for a gauge family or a delta-sum point for a counter/up-down-counter family. The v8 exporter MUST add both schema URLs and the separate forward keys; current metric output without them is not native shape. An already aggregated histogram is not a raw observation and is not native-importable in v8 |
| `otlp.genai.span.operation.v1` | Authenticated source; exact pinned `gen_ai.operation.name`; valid ended span and IDs | Compiler expands one binding per operation/target: `invoke_agent` with required `defenseclaw.agent.type` to `span.agent.invoke`; `chat` with required `gen_ai.request.model` to `span.model.chat`; `embeddings` with required request model to `span.model.embeddings`; `execute_tool` with required `gen_ai.tool.name` to `span.tool.execute`; `retrieval` with required `defenseclaw.retrieval.source.id` to `span.retrieval.search`; `invoke_workflow` with exact `gen_ai.workflow.name` normalized into required `defenseclaw.workflow.name` to `span.workflow.run` |
| `otlp.codex.user_prompt.v1` | Authenticated source `codex`; exact `event.name=codex.user_prompt` | Import `log.model.request`, fixed outcome `attempted`; map only the exact content and correlation aliases in section 2.3 |
| `otlp.claudecode.user_prompt.v1` | Authenticated source `claudecode`; exact `event.name=claude_code.user_prompt` | Import `log.model.request`, fixed outcome `attempted`; map only the exact content and correlation aliases in section 2.3 |
| `otlp.codex.response_completed.v1` | Authenticated source `codex`; exact `event.name=codex.sse_event` and exact `event.kind=response.completed` | One match imports `log.model.response`, fixed outcome `completed`, and owns explicit token/duration augmentation targets from the same leaf |
| `otlp.claudecode.token_usage.v1` | Authenticated source `claudecode`; exact instrument `claude_code.token.usage`; Sum or Gauge point; exact supported `type`; exact source unit in `{"", "{token}", "token", "tokens"}` | Derive `metric.gen_ai.client.token.usage` at scale 1. The source metric is not imported as though it were already that canonical histogram |
| `otlp.genai.duration.metric.v1` | Exact instrument name in `{gen_ai.client.operation.duration, gen_ai.operation.duration, llm.operation.duration, claude_code.operation.duration, codex.operation.duration}` and one exact source-unit spelling from section 4.4 | Derive `metric.gen_ai.client.operation.duration`; no substring fallback. Gauge/Sum values normalize to seconds by the generated exact scale. A histogram point derives one explicitly mean-valued observation from `sum/count`; the source aggregate is not imported or described as lossless |
| `otlp.genai.duration.span.v1` | Target augmentation on a match accepted by `otlp.genai.span.operation.v1`; it is not an independent discriminator match | In addition to the imported span, derive one `metric.gen_ai.client.operation.duration` observation from `end-start` |

The standard GenAI span binding MUST NOT infer PR #403 lifecycle, execution,
root-agent, parent-agent, turn, tool-call, or phase IDs. It preserves those facts
only when they are present under their exact registered keys. A normal GenAI span
without those overlay facts remains a valid bounded operation; it does not become a
fabricated full agent-lifecycle trace.

`gen_ai.workflow.name` to `defenseclaw.workflow.name` is the one intentional
standard-to-overlay discriminator mapping. It uses the existing `identifier-v1`
normalization, maximum 128 UTF-8 bytes, and
`^[a-z0-9][a-z0-9_.-]{0,127}$`; absence or normalization failure makes that
expanded `invoke_workflow` binding unsupported. The inbound rendered span name is
never reverse-parsed to obtain the workflow name.

### 2.3 Exact connector compatibility mappings

For the three connector compatibility bindings above, source precedence and aliases
are closed as follows. A present higher-precedence value that fails its target type
or bound rejects that mapped value; the normalizer MUST NOT silently select a
lower-precedence alias.

| Canonical fact | Exact source precedence |
|---|---|
| authenticated connector/source | Receiver path-token identity; payload `source`, `connector`, and `service.name` cannot override it |
| conversation/session ID | `gen_ai.conversation.id`, `conversation.id`, `session.id`, `session_id` |
| transport request ID | `defenseclaw.request.id`, `request.id` |
| prompt/response turn ID | `defenseclaw.turn.id`, `codex.turn.id`, `turn.id`, `turn_id` |
| provider | `gen_ai.provider.name`, then authenticated source; `service.name` is retained only as bounded import provenance, not authority |
| request model | `gen_ai.request.model`, `gen_ai.response.model`, `model` |
| input content | `gen_ai.input.messages`, `prompt`, `user_prompt`, `gen_ai.prompt`, `llm.prompt`, `codex.prompt`, `message`, `content`, then scalar log body |
| output content | `gen_ai.output.messages`, `response`, `output`, then scalar log body |
| input tokens | `gen_ai.usage.input_tokens`, `input_token_count`, `input_tokens`, `prompt_token_count`, `prompt_tokens`, `codex.turn.token_usage.input_tokens`, `codex.turn.token_usage.prompt_tokens` |
| output tokens | `gen_ai.usage.output_tokens`, `output_token_count`, `output_tokens`, `completion_token_count`, `completion_tokens`, `generated_token_count`, `generated_tokens`, `codex.turn.token_usage.output_tokens`, `codex.turn.token_usage.completion_tokens` |
| operation | Exact `gen_ai.operation.name`; absent connector log operation resolves to the binding constant `chat` |
| log duration seconds | First valid positive value in `{gen_ai.client.operation.duration, gen_ai.operation.duration, duration_seconds, duration_s, elapsed_seconds, elapsed_s, latency_seconds, latency_s, response.duration, codex.turn.duration_seconds}`; otherwise the corresponding exact `_ms` or `_ns` set declared in the generated binding |

Ambiguous duplicate OTLP keys, a wrong AnyValue arm, non-finite number, negative
count/duration, integer overflow, or conflicting exact aliases rejects the affected
derived/imported target with `invalid_mapped_field`; it is never coerced through a
map or formatted as a string. The token-type mapping is exactly:

| Source value | Canonical `gen_ai.token.type` |
|---|---|
| `input` | `input` |
| `output` | `output` |
| `cacheRead` | `cacheRead` |
| `cacheCreation` | `cacheCreation` |

No other token type is accepted. PR #412 metric labels remain exactly those listed
in 14 section 8.4; request, turn, trace, span, prompt, response, argument, result,
reason, evidence, URL, user, error, record, origin, and hop values MUST NOT become
metric labels or Agent360 dimensions.

## 3. Normalization procedure

The receiver MUST run the following order independently for each leaf. The stable
step IDs are acceptance-test references.

1. **`OTLP-I01 decode`**: authenticate the existing receiver boundary, enforce the
   request byte limit and content type, decode with the official OTLP protobuf
   model, reject unknown protobuf/JSON fields, and materialize no generic map-based
   record.
2. **`OTLP-I02 identify`**: resolve the authenticated source, run the generated
   self-echo recognizers, then run only the generated binding discriminators.
   Determine self, zero, one, or ambiguous matches without reading arbitrary
   content.
3. **`OTLP-I03 loop`**: validate native/local-instance and forward-hop metadata.
   Suppress a proven local echo and compute the local ingress hop state before
   canonical construction.
4. **`OTLP-I04 collect`**: resolve the target family and bucket from the binding and
   evaluate that bucket's signal collection policy. Disabled collection stops
   before full field extraction, builder allocation, SQLite persistence, routing,
   or derivation for that target. Imported records never acquire mandatory-floor
   eligibility from the sender.
5. **`OTLP-I05 map`**: extract only registered fields using generated typed
   mappings. Unknown attributes/body members are dropped and counted. No unknown
   value is retained in a hidden raw field.
6. **`OTLP-I06 validate`**: run the generated family validator and the private
   construction capability: the separate import-only context for logs, or the
   sealed exact target descriptor for traces and metrics. Validate
   required/conditional fields, types, bounds, outcome, correlation, field
   classes, trace topology, metric descriptor, and canonical serialization limits.
   The log import context reuses the exact family descriptor but has no
   mandatory/floor fact input and constructs imported logs with `mandatory=false`
   and the unexported floor-only marker false. Trace/metric target constructors have
   no SQLite or floor path and cannot accept caller-selected descriptor authority.
7. **`OTLP-I07 persist`**: for a collected imported log, commit the ordinary local
   SQLite projection before any optional log export. Traces and metrics do not gain
   a new SQLite persistence claim.
8. **`OTLP-I08 route`**: evaluate normal destination routes against the new local
   canonical identity. Apply destination-specific redaction from the canonical
   record and enqueue each selected projection independently.
9. **`OTLP-I09 account`**: aggregate content-free per-disposition counts and emit
   one normalized/partial batch outcome plus bounded drop reasons. Never include
   payload values, attribute names supplied only by the sender, endpoints, tokens,
   or error text.
10. **`OTLP-I10 respond`**: return the existing retry-suppressing wire response
    described in section 8 after all leaves have an internal disposition.

Collection is per target, including derived targets. A log may therefore be
imported while its token metric derivation is disabled, or the log may be disabled
while a separately enabled derived metric is recorded. A route cannot resurrect a
target stopped at `OTLP-I04`.

## 4. Field, body, resource, event, and link treatment

### 4.1 Unknown and dynamic data

Unknown resource attributes, scope attributes, leaf attributes, log-body members,
span events, event attributes, links, and metric point attributes are
`drop_and_count`. They do not reject an otherwise valid supported leaf unless they
duplicate a registered key or make the registered mapping ambiguous.

The only open structured values are those already permitted by P-069/P-070. Their
generated normalizer converts producer-controlled object members into ordered typed
entries whose key is a classified string value; it does not create a dynamic Go
map, arbitrary JSON property, or caller-supplied field-class pointer. Unknown
dynamic member values use the local registry's `content` class. Every surviving
canonical leaf receives the local exact field-class map; inbound field-class or
sensitivity claims are ignored.

For a native projected log, the JSON string body is parsed as an already projected
record, validated against its registered family, and copied into a new canonical
occurrence only through the generated builder. The inbound projection profile and
field-class map are consistency/provenance inputs, not a redaction bypass. A token
that merely looks like a DefenseClaw redaction token remains untrusted input.

### 4.2 Resource and scope

Resource and scope values are copied only when the target family's inbound mapping
names the exact key, placement, type, class, and bound. `service.name` and
`service.instance.id` may supply bounded provider/service provenance where a
binding declares them; they never define the authenticated source or local
instance. Scope name/version/schema URL are identity predicates or canonical trace
fields only where registered. Unknown resource/scope members are dropped.

### 4.3 Span topology

An imported span preserves valid 16-byte trace and 8-byte span IDs. A nonzero valid
parent span ID is preserved even when the parent is absent from the batch; an
invalid or self parent rejects the span. The local canonical record receives a new
record ID but retains the imported trace topology in correlation/body fields.

Only events registered for the target family are retained. A malformed registered
event or unsupported event is dropped and increments the span's canonical dropped
event count in addition to the upstream count. Links follow the same rule and may
retain only registered relation attributes plus valid trace/span IDs and trace
state. Unknown attributes increment the corresponding dropped-attribute count.
Overflow beyond the canonical `uint32` limit rejects the span; counts never wrap or
saturate silently.

For standard GenAI spans, the generated name is rendered from the canonical target
fields; the inbound span name is not reverse-parsed. A native span additionally
requires the inbound name, kind, family, and rendered target name to agree. OTel
status maps to outcome as follows unless a validated native canonical outcome is
present: explicit `error.type=policy_denied` maps to `denied`; status `ERROR` maps
to `failed`; ended status `OK` or `UNSET` without an error maps to `completed`.
Other outcomes require an exact registered DefenseClaw outcome and are never
guessed from free text.

### 4.4 Metric leaves

The unit, instrument type, monotonicity, temporality, value arm, and attributes of
each point MUST satisfy its generated binding. Delta sums may produce additive
canonical observations. Cumulative `claude_code.token.usage` is converted to a
delta by state keyed by authenticated source, bounded service and instance IDs,
instrument, model, token type, conversation, and start time. An exact repeat or an
older value is ignored; a greater value emits the positive difference; a changed
start time starts a new series. This is the only v8 receiver deduplication rule.

The OTLP metric `unit` is interpreted as an exact, case-sensitive UTF-8 token. An
absent OTLP unit is represented by the exact empty string `""`. The receiver MUST
NOT trim whitespace, case-fold, apply Unicode normalization, singularize,
pluralize, parse a unit path, or infer a unit from the instrument name, source path,
authenticated path token, attributes, or metric value. The generated source-unit
rules are exactly:

| Mapping strategy | Accepted source unit -> scale into sealed target unit |
|---|---|
| `duration-metric-v1` -> `s` | `""`, `s`, `second`, `seconds` -> `1`; `ms`, `millisecond`, `milliseconds` -> `0.001`; `us`, `microsecond`, `microseconds` -> `0.000001`; `ns`, `nanosecond`, `nanoseconds` -> `0.000000001` |
| `claude-token-usage-v1` -> `{token}` | `""`, `{token}`, `token`, `tokens` -> `1` |
| `generated-reverse-metric-v1` | The source unit MUST be byte-equal to that target family's sealed instrument unit, including equality of two empty strings; scale is `1` |

Every other mapping has `source_unit_rule.kind=none` and MUST NOT consult a source
metric unit. The compiler materializes each rule on both the match and its metric
target; catalog loading fails if the two differ. Runtime code obtains the target
instrument unit and exact scale only through the immutable generated catalog
accessors. It MUST NOT maintain a second list, perform free-form normalization, or
accept a unit merely because its dimension appears compatible. In particular,
`{token}` in this table is the literal OTel unit token and has no relationship to
the receiver's bearer/path authentication token.

An inbound histogram has already lost its individual observations. Except for the
explicit PR #412 mean derivation in section 2.2, it is unsupported. DefenseClaw
MUST NOT replay buckets, manufacture repeated samples, or call an arithmetic mean a
lossless import.

## 5. Record identity, time, source, and provenance

Every imported or derived canonical occurrence receives a new UUID record ID from
the local builder. An inbound `defenseclaw.record.id` is never reused as local
identity. Optional import provenance records a valid bounded upstream ID so a
downstream consumer can correlate or deduplicate without DefenseClaw claiming
exactly-once import.

The structural registry MUST add the following exact optional `provenance.import`
object. It is generated with the envelope and is not a caller-owned dynamic map.

| Field | Type/class | Rule |
|---|---|---|
| `protocol` | constant string / metadata | Exactly `otlp` |
| `binding_id` | bounded string / identifier | Generated binding ID |
| `mode` | enum / metadata | Exactly `import`, `derive`, or `import_and_derive` |
| `derivation` | optional enum / metadata | Exactly `field_value`, `elapsed_time`, `cumulative_delta`, or `arithmetic_mean` when `mode` derives a target |
| `source_aggregate_count` | optional `uint64` / metadata | Required only for `arithmetic_mean`; the exact validated inbound histogram count |
| `authenticated_source` | bounded string / identifier | Receiver path-token source |
| `upstream_instance_id` | optional bounded string / identifier | Original native canonical resource `defenseclaw.instance.id`; preserved across re-export, never local or last-hop authority |
| `upstream_record_id` | optional UUID-or-stable-token / identifier | Preserved only when valid |
| `upstream_service_name` | optional bounded string / metadata | Preserved only when a binding declares it |
| `upstream_redaction_profile` | optional stable token / metadata | Informational only; cannot select local projection behavior |
| `ingress_hop_count` | `uint32` / metadata | Prior completed DefenseClaw export legs, section 6 |
| `last_hop_instance_id` | optional bounded string / identifier | Immediate exporter from `defenseclaw.telemetry.forward.instance_id`; distinct from `upstream_instance_id` |
| `last_hop_destination` | optional bounded string / identifier | Immediate exporter's configured destination from `defenseclaw.telemetry.forward.destination`; provenance only for another instance |

The import object has one executable normalization boundary. Every bounded string
in this table is valid UTF-8 and at most 512 bytes. The
`upstream_redaction_profile` is instead an existing lower-case stable token and is
therefore at most 128 ASCII bytes. `upstream_record_id` is valid only when it is
either a canonical hyphenated RFC 4122 UUID (hexadecimal is compared
case-insensitively and the received bytes are preserved) or an existing
lower-case stable token. Empty optional strings are absent, not present values.
`derivation` is required exactly when `mode` is `derive` or
`import_and_derive`, and is forbidden for `import`. `source_aggregate_count` is
required and greater than zero exactly for `arithmetic_mean`; it is forbidden for
every other derivation and for a pure import. `ingress_hop_count` is in the closed
range zero through four.

The normal local provenance continues to identify the local importer binary,
registry schema, build, config generation, and config digest. Inbound producer or
provenance values never replace those trusted local fields.

Timestamp rules are exact:

- a log uses nonzero `time_unix_nano`, then nonzero `observed_time_unix_nano`, then
  local receipt time;
- a span record timestamp is its validated end time while its body preserves start
  and end;
- a metric observation uses nonzero point time, then local receipt time;
- a selected upstream time more than five minutes after local receipt is invalid;
  there is no past-age rewrite; and
- canonical `observed_at` is always the local receipt time.

Trace/span IDs come only from valid OTLP wire fields. Other request, conversation,
turn, lifecycle, execution, evaluation, finding, policy, scan, enforcement, and
approval IDs are preserved only through exact registered field bindings. Missing
IDs remain absent.

## 6. Origin and hop contract

The fixed v8 maximum is four completed DefenseClaw export legs
(`max_forward_hops=4`). It is an internal protocol constant, not a config knob.
Every DefenseClaw OTLP exporter stamps transport metadata after route projection:

- the exporting local instance ID;
- the configured destination name;
- the outgoing hop count; and
- the stable local record ID when the OTLP signal shape can carry it without
  creating a metric label.

The exact wire keys are:

| Placement | Key | Value |
|---|---|---|
| Semantic OTLP resource | `defenseclaw.instance.id` | Original canonical DefenseClaw process/resource instance; an importer preserves it across re-export and never rewrites it to the forwarding instance |
| log/span leaf; metric hop-tier resource | `defenseclaw.telemetry.forward.instance_id` | Immediate exporting DefenseClaw instance ID |
| log/span leaf; metric hop-tier resource | `defenseclaw.telemetry.forward.destination` | Configured destination name |
| log/span leaf; metric hop-tier resource | `defenseclaw.telemetry.forward.hop_count` | Unsigned decimal/integer hop count |
| log/span leaf | `defenseclaw.record.id` | Stable local record ID |

`defenseclaw.instance.id` remains semantic resource data. On first local production
it identifies that producing instance. When another DefenseClaw imports and
re-exports the occurrence, it preserves that original value as
`provenance.import.upstream_instance_id` and the semantic resource marker; it uses
the separate forward key for its own instance. For a non-native connector record
with no original DefenseClaw resource marker, the first local canonical occurrence
may use the importing instance as its newly established semantic resource identity.

For logs and spans the three forward keys are reserved leaf attributes. For metrics
they are reserved hop-tier resource/scope transport metadata emitted by one
destination-private provider per bounded hop tier; they MUST NOT be data-point
labels or dashboard dimensions. A locally produced record exports with hop `1`.
An imported record at hop `H` exports with `H+1`.

The receiver behavior is:

- missing hop metadata on a non-native connector record means ingress hop `0`;
- a valid native record must carry mutually consistent hop metadata;
- a negative, wrong-type, or greater-than-four hop is `invalid_hop`;
- a record at hop four may be imported and, for logs, stored locally, but is not
  eligible for any optional re-export;
- a native leaf is a self echo only when
  `defenseclaw.telemetry.forward.instance_id` equals the local instance ID; the
  semantic `defenseclaw.instance.id` is never consulted for self suppression; and
- local same-destination suppression requires the forward pair `(local instance
  ID, destination name)`. Only that local pair may populate the runtime routing
  seam `OriginDestination`. A `last_hop_destination` sent by another instance is
  retained only as import provenance and MUST NOT populate local
  `OriginDestination`, even when its text equals a local destination name.

Hop/origin values are loop-control annotations, not authentication. They cannot
grant native classification, collection, floor, routing, privacy, or schema trust.
The existing bearer/path-token boundary remains authoritative. Honest
DefenseClaw-to-DefenseClaw forwarding preserves the counter, so a configuration
cycle across different instances relies on the fixed four-hop bound and terminates
after at most four legs; a remote destination name is not treated as a comparable
local route identity. An attacker able to submit fresh
authenticated requests can submit fresh hop-zero records and is controlled by the
existing authentication, request-size, rate, and queue boundaries rather than a
spoofable counter.

## 7. Collection, SQLite, routing, redaction, and duplicates

Imported records are ordinary non-floor records. Collection is checked after the
generated discriminator identifies a target but before the full builder. When
disabled, no ordinary canonical target is built and no destination can resurrect
it. The normal generated log builder for a locally produced mandatory family MUST
NOT be called by the importer, because that builder's private family contract may
set `mandatory=true`. Instead, the registry compiler emits a private import-only
validator/constructor bound to the same family descriptor, schema, field classes,
and outcome rules but structurally incapable of accepting mandatory facts or
setting mandatory/floor state. Tests MUST exercise every mandatory log family and
prove an otherwise valid imported occurrence is `mandatory=false`, is stopped by
disabled collection, and never reaches the local floor. The separate mandatory
`telemetry.batch.rejected` health record remains governed by the local receiver's
own trusted failure path, not by the sender's target family.

Every successfully imported log follows D-014: local projection/redaction and a
successful SQLite transaction precede optional export. A local persistence failure
prevents remote delivery of that log and produces the normal safest platform-health
signal. Imported traces and metrics follow their normal signal pipelines and are
not written to `audit_events`. A source log in `derive` mode creates no raw source
log row; each successfully enabled derived log target, if one is ever registered,
would follow the same SQLite rule.

All destination selection uses the target's local bucket and family. Omitted
destination policy therefore sends every successfully collected supported target
unredacted to every capable selected destination, exactly as D-021 requires. A
route-specific profile applies the central projector to the new canonical record.
No adapter receives the inbound body, decoded proto, upstream projection, or a
projection produced for another destination.

Inbound projection metadata does not create trusted idempotence. `none` preserves
the locally mapped canonical values; `sensitive`, `content`, `strict`, custom
profiles, and `legacy-v7` run under their ordinary contracts. Detection and
field-class failures fail closed without recovering the inbound value.

Receiver delivery is at-least-once at the request boundary. Two deliveries of the
same upstream log/span/metric leaf normally produce two new local record IDs and,
when collected, two observations. `upstream_record_id` permits downstream
deduplication but does not change storage semantics. One local occurrence keeps its
local record ID across destination fan-out and bounded transport retry, preserving
P-064. The cumulative-token rule in section 4.4 is the sole exception.

## 8. Partial batches and wire response

Each decoded leaf receives exactly one primary disposition:

`imported`, `derived_only`, `imported_and_derived`, `collection_disabled`,
`self_suppressed`, `hop_limit`, `unsupported_identity`, `ambiguous_identity`,
`invalid_mapped_field`, `invalid_record`, or `local_persistence_failed`.

Derivative targets are additionally counted as `recorded`, `collection_disabled`,
`invalid_derived_record`, or `delivery_degraded`. One leaf failing does not roll
back an independent sibling. A log's SQLite failure blocks that log's optional
delivery but does not roll back already committed siblings. Optional destination
failure remains asynchronous and cannot change the receiver acknowledgement.

For an authenticated, size-valid request that decodes as the expected OTLP signal,
permanent leaf-level unsupported/invalid/drop outcomes MUST retain the current empty
OTLP success response (`{}` for JSON in the existing receiver) to prevent an
uncorrectable retry storm. They are represented internally by
`telemetry.batch.normalized` with `outcome=completed|partial` and bounded aggregate
`telemetry.records.dropped` reason counts. DefenseClaw MUST NOT echo payload values
in an OTLP `partial_success.error_message`. Authentication, media-type, method, and
request-size failures retain their existing HTTP boundary behavior. A syntactically
malformed OTLP body follows 05 section 8's retry-suppression rule and emits the
mandatory safe rejection record.

The accounting invariant is executable for every well-formed batch:

```text
decoded leaves
  = imported
  + imported_and_derived
  + derived_only
  + collection_disabled
  + self_suppressed
  + hop_limit
  + unsupported_identity
  + ambiguous_identity
  + invalid_mapped_field
  + invalid_record
  + local_persistence_failed
```

The batch health record is metadata about admission. It is not a copy of an
imported leaf and does not substitute for a successfully imported record.

Batch-health emission follows this exact mapping:

- a decoded empty batch is `telemetry.batch.normalized` with `outcome=completed`;
- a nonempty batch containing only `imported`, `imported_and_derived`,
  `derived_only`, `collection_disabled`, and/or a mixture containing
  `self_suppressed` is `completed`;
- any `hop_limit`, `unsupported_identity`, `ambiguous_identity`,
  `invalid_mapped_field`, `invalid_record`, or `local_persistence_failed` makes
  the batch `partial`, even when independent siblings succeed; and
- the singular nonempty all-`self_suppressed` case emits no canonical batch log,
  ingest metric, or receive/normalize trace. A health record for a proven local
  echo would itself be exported back into the receiver and create an unbounded
  sequence. Mixed batches still emit their one normal outcome; a later echo of
  that outcome terminates under this all-self rule.

`telemetry.records.dropped` is emitted at most once for each nonzero permanent
drop reason in the fixed six-reason set above (`hop_limit` through
`local_persistence_failed`), ordered exactly as listed. Its `record_count` is the
count for that reason and its byte fields describe the whole measured batch, not
an invented per-record size. `collection_disabled` and `self_suppressed` remain
visible in bounded batch counters/metrics but are policy/loop dispositions, not
`records.dropped` occurrences. No derivative-target count participates in the
primary accounting equation or changes the wire acknowledgement.

## 9. Upgrade and compatibility

`defenseclaw upgrade` requires no new operator choice for this behavior. The v8
cutover removes v7 opaque decoded OTLP/HEC forwarding and broad name/content
heuristics. The generated binding catalog replaces them atomically with the v8
runtime. Existing config migration continues to preserve collection, routes,
destinations, and redaction; it does not manufacture an inbound mapping from
legacy sink configuration.

PR #403 remains authoritative for root/subagent and lifecycle topology. Imported
standard GenAI spans retain real IDs and relationships but never fill missing PR
#403 facts. Native v8 spans can round-trip every registered PR #403 field whose
generated reverse representation validates.

PR #412 remains authoritative for the two GenAI metric names, exact labels/token
types, 60-second application export, Collector delta-to-cumulative conversion,
Agent360 dimensions, and local dashboard ownership. The exact connector-derived
bindings in section 2 preserve that data. The removed v7 substring duration/span
heuristics are not part of the compatibility floor.

## 10. Executable acceptance matrix

The named tests below are required release tests. JSON and protobuf variants MUST
share generated fixtures and produce byte-equivalent canonical records after
removing locally generated record/observed timestamps.

| ID | Required test/proof | Expected result |
|---|---|---|
| `OTLP-A01` | `TestOTLPInboundGeneratedBindingsAreClosedAndUnambiguous` | Every required class expands to stable exact match IDs and separate one-target IDs; explicit augmentations share one match; finite same-target aliases remain distinct variants; native-exact/native-malformed/external shapes cannot fall through; expanded coverage/discriminators are complete and unambiguous; class wildcard execution, overlap, hand runtime binding, unknown target, or non-generated field map fails generation |
| `OTLP-A02` | `TestOTLPInboundJSONProtobufParity` | All three signals normalize identically; unknown JSON/protobuf fields and duplicate keys fail before leaf mapping |
| `OTLP-A03` | `TestOTLPInboundNativeLogRoundTripOtherInstance` | Every registered log-family fixture imports through its builder with a new local ID and upstream provenance; no raw body survives |
| `OTLP-A04` | `TestOTLPInboundNativeSpanRoundTripOtherInstance` | Every reversible span fixture preserves topology, exact registered fields/events/links/status/counts, and gets a new local record ID |
| `OTLP-A05` | `TestOTLPInboundNativeMetricReversibleShapesOnly` | Gauge and delta-sum supported shapes import only when the source unit is byte-equal to the sealed target unit; cumulative/aggregate/type/temporality/unit mismatches and histograms do not masquerade as raw observations |
| `OTLP-A06` | `TestOTLPInboundGenAISpanFamilyMatrix` | Six exact operation mappings select the stated family/bucket/name/kind; missing required discriminator facts and heuristic names are unsupported |
| `OTLP-A07` | `TestOTLPInboundConnectorLogMatrix` | Codex/Claude prompt and Codex completed-response bindings map exact content/correlation flags/outcomes; wrong source/event/kind and alias conflicts do not import |
| `OTLP-A08` | `TestOTLPInboundPR412DerivedMetricMatrix` | Exact token/duration identities and every section 4.4 accepted source-unit spelling produce only the two canonical metrics at the exact generated scale, exact labels, and four token types; case/whitespace/unknown-unit and broad-substring variants are rejected |
| `OTLP-A09` | `TestOTLPInboundHistogramMeanIsExplicitDerivation` | One aggregate point derives one mean observation using the same exact generated source-unit scale with derivation provenance; source buckets/count are not claimed as losslessly imported |
| `OTLP-A10` | `TestOTLPInboundUnknownFieldsDropAndCount` | Unknown attrs/body/event/link members never reach canonical/projected output; registered duplicate/ambiguous keys reject the affected target |
| `OTLP-A11` | `TestOTLPInboundFieldClassAndDynamicMemberConformance` | Every surviving leaf uses local exact classes; dynamic keys are values; spoofed classes/sensitivity and redaction-shaped strings grant no trust |
| `OTLP-A12` | `TestOTLPInboundIdentityTimeAndProvenance` | New record IDs, original semantic `upstream_instance_id`, distinct immediate `last_hop_instance_id`, valid upstream IDs, timestamp precedence/future bound, local observed time/source/build/config provenance, re-export preservation, and absence behavior are exact |
| `OTLP-A13` | `TestOTLPInboundSelfOtherAndMixedBatch` | Exact local native leaves, including non-reversible metric aggregates, suppress individually through generated echo recognizers; other-instance reversible leaves import; mixed batches do not disappear through batch-wide self detection |
| `OTLP-A14` | `TestOTLPInboundHopAndOriginMatrix` | Missing/0..4/wrong/overflow hops; self comparison using only the forward instance key; semantic-resource mismatch; local destination pair populating `OriginDestination`; other-instance name collision never populating it; four-node cycle; and no metric-label leakage obey section 6 |
| `OTLP-A15` | `TestOTLPInboundCollectionBeforeConstruction` | Disabled primary/derived targets allocate no builder record and reach no SQLite/route; one target's policy does not disable its sibling derivation; every imported mandatory-family log uses the private import context, remains `mandatory=false`, and cannot enter the floor |
| `OTLP-A16` | `TestOTLPInboundSQLiteBeforeRemote` | Imported logs commit once before fan-out; SQLite failure exports nowhere; traces/metrics create no audit row |
| `OTLP-A17` | `TestOTLPInboundDestinationFanoutAndRedactionIsolation` | Two capable destinations receive independent selected projections; log-only gets logs; central profiles apply; no adapter can read decoded inbound data |
| `OTLP-A18` | `TestOTLPInboundPartialBatchAccountingAndAck` | Every mixed-batch leaf has one disposition, the accounting equation holds, completed/partial and the ordered fixed six drop-reason occurrences are exact, bounded health contains no payload, an all-self-suppressed batch emits no recursive health/metric/trace, and permanent leaf drops return empty success without retry |
| `OTLP-A19` | `TestOTLPInboundDuplicateAndCumulativeSemantics` | Repeated ordinary leaves create distinct local IDs; retry keeps one local ID; exact cumulative-token repeats/out-of-order/resets follow section 4.4 |
| `OTLP-A20` | `TestOTLPInboundReloadGenerationIsolation` | In-flight import remains on one generation lease from collection through delivery; new binding/config publication is atomic and retired generations leak no work |
| `OTLP-A21` | `TestOTLPInboundPR403TopologyAndMissingData` | Native lifecycle traces preserve root/subagent/turn/tool relations; generic GenAI traces never fabricate absent PR #403 facts |
| `OTLP-A22` | `TestOTLPInboundPR412LiveLocalObservability` | Live Loki/Prometheus/Tempo/Grafana validation retains dashboard data, 60-second cadence, cumulative local series, exact Agent360 dimensions, and no origin/hop labels |
| `OTLP-A23` | `FuzzOTLPInboundNoRawBypass` | Arbitrary bounded AnyValue trees, keys, bodies, events, links, numbers, and mixed batches cannot escape generated mapping, limits, field classes, or redaction |
| `OTLP-A24` | race/vet/portability gate | Receiver/runtime/destination tests pass under `-race`; `go vet` and Windows compile pass; generated and spec drift checks are clean |

Minimum command gate:

```bash
make check-observability-v8-spec
make check-schemas
go test ./internal/gateway ./internal/observability/... ./internal/telemetry/... -count=1
go test -race ./internal/gateway ./internal/observability/... ./internal/telemetry/... -count=1
go vet ./internal/gateway ./internal/observability/... ./internal/telemetry/...
GOOS=windows GOARCH=amd64 go test ./internal/gateway ./internal/observability/... ./internal/telemetry/... -run '^$'
python3 scripts/check_local_observability_dashboards.py
```

The live PR #412 test additionally starts the bundled local stack, sends the
generated Codex/Claude/native fixtures, waits at least one configured application
metric interval, queries all fourteen dashboard dependencies, and tears the stack
down without deleting its volumes. A live Galileo conformance test consumes the
same imported canonical span fixtures only after the route-specific
`galileo-rich-v2` projection; it never sends the inbound span directly.

## 11. Decision reconciliation

No locked product decision is reversed. This contract makes the following existing
decisions more precise:

- D-015/D-021 apply to successfully constructed supported canonical targets, not
  every arbitrary OTLP leaf.
- D-014 applies to imported logs and does not add trace/metric SQLite storage.
- P-046 requires the explicit derived PR #412 bindings and forbids origin/hop or
  content from becoming dashboard dimensions.
- P-058's exact provenance object gains the optional generated `import` member in
  section 5; upstream provenance never replaces local provenance.
- P-061/P-069/P-070 govern inbound dynamic members and builders. The new generated
  binding catalog is part of the same materialized registry and cannot become a
  parallel schema authority.
- P-064 governs retries of a local projection; it does not deduplicate repeated
  inbound requests.

The earlier prose could otherwise be read as requiring arbitrary OTLP pass-through,
trusting `defenseclaw.*` sender attributes, or losslessly re-importing aggregated
histograms. Those readings conflict with P-058/P-061/P-069 and are explicitly
rejected by D-023 and P-071 through P-075.
