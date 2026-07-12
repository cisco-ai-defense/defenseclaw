# Simplified Telemetry Schema Architecture

## 1. Decision

DefenseClaw v8 uses a **composed schema**, not a DefenseClaw-only replacement and
not GenAI conventions alone:

```text
stable OTel resource / HTTP / RPC / error conventions
                         +
version-pinned OTel GenAI conventions for agent/model/tool/retrieval
                         +
small DefenseClaw overlay for security, policy, enforcement, lifecycle,
correlation, provenance, collection bucket, and redaction field classes
                         +
generated destination projections (Galileo/OpenInference compatibility)
```

This is the most open and understandable option:

- Standard consumers can use `gen_ai.*`, HTTP/RPC, resource, status, and error
  fields without knowing DefenseClaw.
- DefenseClaw does not misuse `gen_ai.*` for security concepts that the standard
  does not define.
- Galileo and other backends receive generated compatibility projections rather
  than becoming the canonical schema.
- One logical registry with a small focused authoring set replaces many
  independently maintained JSON files.

Relevant upstream sources:

- OpenTelemetry semantic-convention registry:
  <https://github.com/open-telemetry/semantic-conventions>
- OpenTelemetry GenAI registry model:
  <https://github.com/open-telemetry/semantic-conventions-genai>
- OpenTelemetry core semantic-conventions `v1.42.0` release:
  <https://github.com/open-telemetry/semantic-conventions/releases/tag/v1.42.0>
- OpenTelemetry GenAI registry revision used by v8:
  <https://github.com/open-telemetry/semantic-conventions-genai/tree/b028dceecdad117461a785c3af35315e7184e813>
- OpenInference semantic-conventions `v0.1.30` release:
  <https://github.com/Arize-ai/openinference/releases/tag/python-openinference-semantic-conventions-v0.1.30>
- OpenTelemetry specification guidance that semantic-convention YAML is the source
  for generated constants:
  <https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/overview.md>

## 2. Why GenAI Alone Is Insufficient

OTel GenAI conventions cover portable AI operation semantics such as agent calls,
model inference, tool execution, conversations, request/response models, usage, and
content. They do not fully define DefenseClaw concepts such as:

- Collection bucket and route identity.
- Guardrail strategy, phase, decision, severity, would-block, and enforced state.
- Security finding, scan, enforcement action, approval, and asset lifecycle IDs.
- Connector/root-agent/session/lifecycle/execution correlation.
- Redaction field class and destination projection state.
- Config generation, policy version, audit-mandatory status, or evidence
  fingerprint.

Forcing those into invented `gen_ai.*` attributes would look standard while being
non-standard. DefenseClaw-specific semantics therefore remain in the
`defenseclaw.*` namespace.

### 2.1 Registry scope

The logical telemetry registry owns canonical observability log/event bodies, span
families, span events/links, resources, and metric instruments. It generates or is
referenced by JSONL, OTLP, SQLite projection, CLI export, and vendor compatibility
schemas.

Unrelated product contracts remain separate: configuration schema, release/upgrade
manifest, plugin/registry manifest, API request/response schemas, and other non-
telemetry data do not get forced into the telemetry registry.

## 3. Canonical Namespace Ownership

| Namespace | Owner | DefenseClaw rule |
|---|---|---|
| OTel resource/general | OpenTelemetry | Use pinned standard name/type/meaning; do not redefine |
| `http.*`, `url.*`, `server.*`, `network.*`, `rpc.*`, `error.*`, exception event | OpenTelemetry | Use stable protocol/error conventions |
| `gen_ai.*` | Pinned OTel GenAI profile | Portable agent/model/tool/retrieval fields only |
| `db.*` | OpenTelemetry | Retrieval/database operation semantics when applicable |
| `openinference.*` | OpenInference compatibility profile | Generated compatibility alias/projection, not primary ownership |
| `defenseclaw.*` | DefenseClaw | Security, policy, lifecycle, provenance, correlation, bucket, and privacy overlay |
| `galileo.*` | Galileo adapter | Destination-specific resource/routing projection only; never producer-canonical |

A field has exactly one canonical owner. Aliases declare `alias_of` and a removal
version; they do not become independent values.

## 4. One Logical Source of Truth

### 4.1 Authoring layout

The target authoring layout is intentionally small but not one enormous file. One
registry manifest composes three focused domain files:

```text
schemas/telemetry/v8/
  registry.yaml              # manifest, versions, dependencies, group imports
  genai.yaml                 # GenAI groups and agent/model/tool/retrieval/workflow families
  security.yaml              # security groups and guardrail/finding/enforcement/approval families
  operations.yaml            # operational families, including span.destination.* and span.admin.*
  semconv.lock.yaml          # exact upstream dependency versions/digests
  examples.yaml              # valid/invalid representative records

schemas/telemetry/runtime/
  telemetry.schema.json.gz   # deterministic storage for the complete bundle
  catalog.json.gz            # deterministic storage for the machine catalog
  compatibility/galileo-rich-v2.json.gz
  compatibility/openinference-v1.json.gz
  compatibility/local-observability-v1.json.gz # dashboard/query consumer profile
  compatibility/v7-exporter-selection.json.gz  # migration eligibility/profile map

internal/observability/
  zz_generated_telemetry_*.go # generated typed runtime API and metadata
```

The compiler uses logical raw output names under
`schemas/telemetry/generated/`, and also constructs `catalog.md`, normalized
examples, exact inbound OTLP bindings, and OTLP conformance fixtures on every
generation/check. Only the six release/runtime JSON artifacts are repository
owned, stored as byte-equivalent deterministic gzip members under
`schemas/telemetry/runtime/`; the remaining reproducible reports/corpora are
validated in memory but not checked in.

The manifest, three domain model files, lock, and curated examples are the only
human-authored sources of canonical telemetry semantics. Common attributes are
defined once and referenced across those files. Machine-derived normalized
upstream snapshots are immutable build inputs named and digested by the lock, not
additional authoring surfaces. Bundled dashboards, rules, Collector configuration,
datasource configuration, and their packaged copies remain independently owned
consumer assets that the compiler parses; they are not copied into a second
hand-maintained telemetry manifest. The runtime gzip members and generated Go
files are reproducible, and CI fails on drift. Contributors normally touch one
domain file for a new family; consumers use the generated catalog, bundle, or
typed runtime API.

The manifest also owns the closed cross-domain `inbound_bindings` catalog from 15
section 2. A binding may reference a family in any domain file, but cannot define a
family, bucket, field class, dynamic shape, or mandatory rule. Keeping this
transport mapping in `registry.yaml` preserves the one-manifest/three-domain-file
authoring model; there is no fourth hand-authored schema file or runtime binding
list.

There is no separately authored trace or span-family file. Each span family from
`11-trace-and-span-contract.md` section 7 is owned by its primary semantic domain:

| Authoring file | Span-family ownership |
|---|---|
| `genai.yaml` | `span.agent.invoke`, `span.workflow.run`, `span.model.*`, `span.tool.*`, and `span.retrieval.*` |
| `security.yaml` | `span.guardrail.*`, `span.enforcement.*`, `span.approval.*`, and `span.finding.*`; `span.guardrail.judge` may reference the GenAI model groups without changing ownership |
| `operations.yaml` | `span.agent.transition`, `span.asset.*`, `span.network.*`, `span.ai.discovery.*`, `span.telemetry.*`, `span.destination.*`, `span.config.*`, `span.admin.*`, and `span.diagnostic.*` |

Log and metric families follow the same primary-domain rule. Reusable groups may
be referenced across files, but a family definition has exactly one authoring
owner. `registry.yaml` composes the three sets into the versioned trace profile.

### 4.2 OTel registry compatibility

The registry MUST use the OpenTelemetry semantic-convention registry model and
OTel Weaver-compatible groups/references wherever they represent the required
contract. DefenseClaw extensions are limited to namespaced metadata required by
this product:

- `bucket`
- `field_class`
- `sensitivity`
- `cardinality`
- `route_selector`
- `mandatory_floor`
- `compatibility_aliases`
- `projection_profiles`

If upstream Weaver cannot preserve an extension, the compiler keeps it in a
namespaced `x-defenseclaw-*` block rather than forking the meaning of an upstream
field.

The v8 lock was reviewed against the authoritative upstream repositories on
2026-07-02 and pins these immutable revisions:

| Dependency | Version/profile | Immutable revision |
|---|---|---|
| OpenTelemetry core semantic conventions | `v1.42.0` | `ae3a98640194ed405c4c797281502e4d3bd258b3` |
| OpenTelemetry GenAI semantic conventions | `otel-genai-b028dceecdad117461a785c3af35315e7184e813` | `b028dceecdad117461a785c3af35315e7184e813` |
| OpenInference semantic conventions | `openinference-semantic-conventions-v0.1.30` | `789d41974c08a9a13147977f28ef4142a07e2106` |

The core `v1.42.0` release moved `gen_ai.*` ownership to the dedicated GenAI
repository. That repository had no release tag for this snapshot, so v8 uses its
full commit as the profile identifier rather than a mutable branch name. Builds do
not fetch mutable `main` definitions, and a tag moving to a different commit fails
lock validation.

Every lock member names the upstream repository, immutable revision, normalized
snapshot path, normalization format, and SHA-256 digest. The compiler validates the
digest before loading the snapshot and fails if a referenced standard field's name,
type, stability, enum/deprecation metadata, or original source pointer is absent or
inconsistent. Normal registry generation is entirely offline. A snapshot may be
refreshed only by an explicit dependency-update operation that derives it from the
pinned revision and produces a reviewed semantic diff; a self-authored subset plus
its own digest is not sufficient provenance.

The dependency-update operation serializes writers with one repository-root
advisory lock held from the initial no-follow lock-file read through publication.
Publication compare-and-swaps the exact original lock inode and bytes, verifies
every snapshot and structural-input path/digest referenced by the complete
candidate lock (including unselected dependencies) immediately before and after
installing the lock commit marker, and fails rather than overwriting an intervening
edit. Installed targets are rechecked by no-follow inode identity and exact bytes,
so replacement and same-inode mutation cannot produce a successful mixed lock.
The final lock fsync plus the second complete-reference validation is the commit
point. A later private-transaction cleanup failure reports the stable explicit
state `update committed; transaction cleanup failed`; it never claims rollback
after the new lock is live. A failure before that commit point restores prior bytes
when safe, or preserves transaction evidence rather than deleting a foreign inode.

OpenInference normalization uses only the pinned Python semantic-conventions
package version source, its trace and resource constant modules, and
`spec/semantic_conventions.md`. The Reserved Attributes table is authoritative for
direct trace-attribute names, types, and meanings, while the released Python
constants prove that the SDK symbol exists. Direct trace entries are the exact
intersection, except OTel-standard exception fields remain OTel-core owned;
`openinference.project.name` is the explicit resource-module exception. The
released package has no per-row stability field, so the normalized stability is a
documented compatibility-profile policy rather than an upstream row claim.
Instrumentation, examples, tests, internal documentation, and other language SDKs
never contribute attributes to the Python `0.1.30` profile.

OpenInference unions and structured collections retain their upstream wire shape.
`String/Integer` is a closed scalar union. `List of objects` is an indexed,
zero-based flattened-prefix template and `Image Object` is an object-prefix
template; neither becomes a literal OTLP array or object attribute. Prefix/template
components are projection metadata, not generic DefenseClaw attribute types.

Dependency overlap records provenance, not shared canonical ownership. The
dedicated GenAI snapshot owns every current definition it contains. Deprecated
core definitions moved to that repository are legacy migration provenance; an
active duplicate is accepted only when its complete shape is equal, an active
conflict fails, and a deprecated/current type change requires an explicit migration
disposition. Core-only deprecated GenAI definitions cannot satisfy an ordinary
family reference. OTel core remains the canonical owner of standard fields also
named by OpenInference, while OpenInference-only fields are compatibility-projection
inputs and never override OTel or OTel GenAI ownership.

## 5. Registry Composition Model

The registry defines reusable groups rather than copying every common attribute
into every span schema.

### 5.1 Reusable groups

The v8 reusable groups are:

| Group | Contents |
|---|---|
| `resource.core` | Service, deployment, instance, host, tenant/workspace, device identity, one bounded dynamic custom-member contract, and documented derived compatibility aliases |
| `span.core` | Bucket, family, family schema version, source, config generation, outcome |
| `correlation.request` | Request/turn/trace identifiers |
| `correlation.agent` | Conversation, agent, root/parent, lifecycle, execution, phase, sequence |
| `correlation.security` | Evaluation, finding, scan, policy, enforcement, approval IDs |
| `content.input` | Input messages/value, reported/state/length/hash/MIME and field class |
| `content.output` | Output messages/value, reported/state/length/hash/MIME and field class |
| `error.core` | OTel status/error type plus bounded redacted description |
| `genai.agent` | Pinned standard agent operation fields |
| `genai.model` | Pinned model request/response/usage fields |
| `genai.tool` | Pinned tool operation/call fields |
| `genai.retrieval` | DB/retrieval fields |
| `security.guardrail` | Decision, severity, phase, source, evidence/reference fields |
| `security.enforcement` | Requested/effective action, mode, outcome, state transition |
| `lifecycle.agent` | Lifecycle event/state/source/resume/depth |
| `transport.http` | Stable HTTP client/server fields |

### 5.2 Family definitions

A span/log/metric family references groups and declares only its unique shape. A
conceptual authoring entry looks like:

```yaml
groups:
  - id: span.model.chat
    type: span
    stability: stable
    brief: One model chat invocation.
    extends:
      - span.core
      - correlation.request
      - correlation.agent
      - content.input
      - content.output
      - error.core
      - genai.model
    span:
      name: "chat {gen_ai.request.model}"
      kind: client
    x-defenseclaw:
      bucket: model.io
      family_schema_version: 1
      events: [model.stream.first_token, model.retry, guardrail.decision]
      compatibility_profiles: [openinference-v1, galileo-rich-v2]
```

The compiler's concrete YAML grammar MUST encode these semantic rules and MUST NOT
weaken them. Grammar-only refinements do not reopen the reviewed family ownership,
group composition, version, privacy, or compatibility decisions.

Every placeholder in a span `name_pattern` is a complete inherited attribute
reference. The compiler rejects unknown placeholders, aliases, format expressions,
and attributes classified as content, path, credential, reason, evidence, error,
or high-cardinality. Fixed names need no placeholder. Span names therefore remain
bounded even when the corresponding span carries richer values as attributes.

#### 5.2.1 Deterministic group resolution

The compiler preserves every direct attribute use and also materializes one
immutable resolved-use contract for every family. Resolution is structural and
monotone; source order or a nearest-parent override never weakens a requirement.

- An `attribute_group` resolves its inherited and direct uses as attributes.
- A `body_group` transposes every inherited and direct use into `body_fields`.
  A log family extends exactly one `body_group` and no non-body group, so all of
  its resolved payload uses have an unambiguous body role.
- Span, resource, metric, and span-event families cannot inherit a body use.
  Their resolved uses remain attributes; metric attributes are the canonical
  label schema described in section 5.4.
- Repeated references merge by the non-weakening requirement lattice
  `required > conditional > recommended > optional`. A required use dominates a
  conditional use. If conditional is the strongest surviving level, every
  surviving use must reference the same stable root-catalog condition ID or
  compilation fails; free-form conditional prose is invalid.
- Per-use constraints merge only by a representable restrictive intersection:
  lower maxima, higher minima, enum intersection, and identical portable patterns.
  An empty/inconsistent range or enum, two different patterns, an invalid item
  bound, or any other non-representable intersection fails. An absent constraint
  never removes a constraint declared by another use.
- The compiler retains the contributing direct uses for provenance and emits the
  resolved role, requirement, condition, and effective constraints for builders,
  schemas, the catalog, and field-class derivation. Unknown, cyclic, mixed-role,
  or unresolved inheritance fails before any output is written.

The checked v1 source satisfies these rules without an exception: every log
extends exactly one body group, body transposition resolves its inherited
correlation/content/security fields, and every duplicate requirement has one
non-weakening result. Generated code MUST consume the materialized result rather
than independently walking the YAML hierarchy.

Every log/span family registers both `outcome_requirement` and
`allowed_outcomes`. `outcome_requirement` is exactly `required`, `optional`, or
`forbidden`. A required/optional family has a nonempty, canonical-order subset of
the global outcome vocabulary; a forbidden family has an explicit empty list and
rejects an envelope outcome. The global vocabulary is not a family default:
copying every canonical outcome into a family without family-specific
applicability and tests is invalid. Generated builders reject a missing required
outcome and a globally valid but family-inapplicable outcome.

Metric families omit both keys because instrument recording is not an
outcome-bearing envelope operation. A metric label may still reference the
canonical `defenseclaw.outcome` attribute, in which case its live values use the
canonical outcome vocabulary and any old `ok`, `success`, `delivered`,
`accepted`, `upstream-error`, `cooldown_suppressed`, `circuit_open`, or arbitrary
`http-N` label is migrated through an explicit compatibility projection/reason or
status-code label. It is never modeled as the metric family's envelope outcome.

The registry manifest also owns immutable semantic-profile bindings. The
`defenseclaw-genai-rich-v1` entry is exactly:

```yaml
id: defenseclaw-genai-rich-v1
trace_schema_version: defenseclaw-trace-v1
gen_ai_semconv_profile: otel-genai-b028dceecdad117461a785c3af35315e7184e813
openinference_profile: openinference-semantic-conventions-v0.1.30
galileo_compatibility_profile: galileo-rich-v2
```

These are four independent literal identifiers. The envelope `schema_version` and
each span's `family_schema_version` remain separate versions and are not members of
this tuple. The four profile members cannot be overridden independently in config;
changing one creates a new semantic-profile ID. Registry validation fails if this
tuple's upstream-pinned OTel core, GenAI, and OpenInference members disagree with
`semconv.lock.yaml`. The DefenseClaw-owned trace-schema and Galileo compatibility
profile IDs are validated against their registry entries instead of being invented
as upstream lock members.

The effective plan derives this tuple from the embedded registry and lock; the Go
runtime does not duplicate repository URLs, snapshot paths/digests, or upstream
revision provenance. It separately compares the derived tuple with the semantic
profile, trace schema, GenAI/OpenInference vocabulary, and Galileo projection
capabilities compiled into the binary. Source derivation determines what was
authored, while the capability check proves this binary implements it. A changed
tuple under the same profile ID therefore fails closed, and a new profile ID remains
unsupported until its builders and adapters ship together.

#### 5.2.2 Typed structural contract

`registry.yaml` contains exactly one authored `structural_contract`. It is the
source for the canonical envelope and signal payload structures that cannot be
expressed by domain attribute groups alone:

```yaml
structural_contract:
  id: defenseclaw.canonical-record
  version: 1
  runtime_binding:
    record: internal/observability.Record
    input: internal/observability.RecordInput
    value: internal/observability.Value
    schema_derived_constructor: internal/observability.newSchemaDerivedRecord
    schema_derived_log_constructor: internal/observability.newSchemaDerivedLogRecord
  limits:
    record_id_utf8_bytes: 512
    correlation_id_utf8_bytes: 512
    span_name_utf8_bytes: 512
    binary_version_utf8_bytes: 256
    provenance_hex_ascii_bytes: 128
    stable_token_ascii_bytes: 128
    payload_depth: 32
    payload_members: 8192
    payload_encoded_bytes: 1048576
    record_encoded_bytes: 4194304
  envelope:
    additional_properties: false
    fields: [] # the authored source contains the closed envelope field list
    signal_arms: [] # the authored source contains logs/traces/metrics arms
  correlation: {additional_properties: false, fields: []}
  provenance: {additional_properties: false, fields: []}
  trace:
    derivations: [] # eleven authored typed equality bindings
    body: {additional_properties: false, fields: [], relations: []}
    resource: {additional_properties: false, fields: []}
    scope: {additional_properties: false, fields: []}
    status: {additional_properties: false, fields: []}
    events: {additional_properties: false, fields: []}
    links: {additional_properties: false, fields: []}
  metric:
    instrument_data: {additional_properties: false, fields: []}
  canonical_to_otlp: {} # exact typed mappings are authored here
```

This is a source-shaped hierarchy excerpt: empty collections stand only for
omitted authored entries. There are no `objects`, root `signal_arms`, or
`otlp_representations` keys; copying those conceptual labels into the source is a
schema error.

`trace.derivations` is the sole executable authority for the eleven trace-derived
values. An attribute row is exactly
`{id,target_attribute,source,equality,presence}`; the one structural-field row is
exactly `{id,target_field,source,equality,presence}`. It binds
`defenseclaw.bucket` to `envelope.bucket`,
`defenseclaw.span.family` to `family.id`,
`defenseclaw.span.family_schema_version` to `family.family_schema_version`,
`defenseclaw.source` to `envelope.source`, and
`defenseclaw.config.generation` to `provenance.config_generation` whenever the
target is registered. It binds `defenseclaw.outcome` to `envelope.outcome` only
when the target is registered and the envelope source is present. It also binds
resource `service.version` and structural `trace_scope.version` to
`provenance.binary_version`, scope `defenseclaw.trace.schema_version` and
`defenseclaw.semantic_profile` to the selected semantic profile fields, and link
`defenseclaw.link.relation` to the typed link relation. Every binding uses exact
typed-JSON equality. Missing, duplicate, misplaced, unused, context-incompatible,
or altered bindings fail compilation; builders and later renderers consume this
IR instead of hard-coding the equalities again.

After inheritance resolution, every active span family MUST resolve the five
unconditional span targets as unconditional required attributes. Its outcome
target MUST be absent when outcome is forbidden; otherwise it MUST retain the
exact `operation-terminal-v1` conditional presence that represents a present
terminal source outcome. `resource.core`, `scope.core`, `link.core`, and
`trace_scope.version` must each contain their exact required derived target. This
total-family/context check applies even when no curated example references the
span.

The compiler accepts no second structural-contract ID or version and no unknown
member. `runtime_binding` is an asserted parity boundary, not a code-generation
request for a new record. Generated Go builders construct the existing
`RecordInput`, materialize the registered body and field-class map, and terminate
at the existing unexported schema-derived constructor. Generated log builders use
the separate log-only schema-derived constructor when the catalog derives
`mandatory`; ordinary callers still cannot assert either trust marker. Tests
compare every bound, version, vocabulary, and regex with the existing Go constants
and validation; a registry/Go mismatch fails generation.

Each structural field is a closed record with `name`, `type`, `required`, and,
where applicable, `const`, `enum`, `object_ref`, `item_ref`, `semantic_ref`,
`semantic_format`, `field_class`, `sensitivity`, `normalization`, and `otlp`. Its
`type` is exactly one of `boolean`, `int64`, `uint32`, `uint64`, `double`,
`metric_number`, `string`, `timestamp`, `object`, `array`, `canonical_json`, or
`field_class_map`. `metric_number` is resolved per family to exactly finite
`int64` or `double`; it is not a third wire-number type and never coerces an integer
through binary float. `semantic_ref` inherits type, privacy, and normalization from
one ordinary registry attribute or resolves one closed registry-owned dynamic
family/group contract; it cannot be an unchecked string. An inline dynamic leaf
supplies all three itself. `semantic_format` is closed to the executable nonzero
OTel trace/span ID formats. Timestamps are UTC RFC 3339-nano on the canonical wire.
`uint32`/`uint64` use exact nonnegative JSON integers rather than binary-float
coercion.

The envelope, exact twenty-key correlation object, provenance object, signal arms,
and payload-rooted field-class rules are those in
`02-taxonomy-and-data-model.md` §§3-3.6. In particular, metrics forbid envelope
outcome/severity/log-level state and `instrument_data` is only `{value,
attributes}`; repeated instrument identity/type/unit/temporality data is invalid.
Every object sets `additionalProperties: false`.

The trace-body, status, resource, scope, event, link, equality, privacy, and nested
dropped-count structures are exactly `11-trace-and-span-contract.md` §§5.4-5.5.
The structural registry registers `defenseclaw.trace.schema_version`,
`defenseclaw.semantic_profile`, `defenseclaw.link.relation`, and the bounded
low-cardinality `defenseclaw.workflow.name`; reusable scope/link groups reference
those attributes rather than hiding strings in adapters. The canonical workflow
name pattern is exactly `workflow {defenseclaw.workflow.name}`. The producer
supplies that identifier under its explicit 128-byte ASCII token bound; neither a
migration nor a destination projector derives a missing value by parsing a
rendered name. A Galileo projection may add its versioned compatibility-profile
attribute after route redaction; canonical scope data remains destination-neutral.

The trace signal arm explicitly requires `correlation.trace_id` and
`correlation.span_id`. `otel-trace-id-v1` and `otel-span-id-v1` reject all-zero or
wrong-width identifiers. The trace-body relation `trace-time-order-v1` requires
positive start/end nanoseconds and `start_time_unix_nano <=
end_time_unix_nano`. These builder-enforced relations remain annotations in JSON
Schema where the dialect cannot compare two instance fields.

`field_classes` contains concrete RFC 6901 pointers rooted at the selected payload,
not at the envelope. The compiler derives structural leaf classes from this
contract and domain leaf classes from the resolved family. At runtime the builder
expands each concrete array index and materializes the complete map. `/message`,
`/attributes/defenseclaw.source`, and
`/attributes/defenseclaw.connector.source` are valid examples;
`/body/message` and `/instrument_data/attributes/...` are invalid. No container
classification covers descendants.

Structural privacy is closed. Trace kind, timestamps, dropped counts, status code,
schema URLs, and scope name/version are `metadata`/`safe`; parent/link IDs are
`identifier`/`internal`; link trace state is `metadata`/`internal`; and status
description is `error`/`sensitive`. Metric observation value is
`metadata`/`safe`. Registered attributes inherit their ordinary registry class and
sensitivity without an override. Envelope and provenance fields are not selected-
payload leaves and therefore do not appear in `field_classes`, but the structural
contract still marks their safe/internal handling: occurrence and correlation IDs
are identifiers, connector/config digest are internal, and versions, timestamps,
bucket/signal/severity/log-level/action/phase/outcome/mandatory are bounded
metadata. A structural field with missing privacy metadata fails compilation.

Structural normalization reuses the root normalizer catalog. Exact OTel IDs add a
nonzero lowercase-hex format check; timestamps use UTC RFC 3339-nano; counts use
finite numeric ranges; W3C trace state is at most 512 UTF-8 bytes; and every text
field remains under the P2 bounds above or a stricter family bound. The structural
contract cannot introduce a prose-only normalizer or weaken a P2 maximum.

The typed OTLP representation declares an exact canonical source and protobuf
target for each field. It covers trace/span/parent IDs, rendered name, kind,
timestamps, status, resource/scope schema URLs, every attribute set, events, links,
and all span/resource/scope/event/link dropped counts. Its value table maps each
canonical scalar/array/structured type to a compatible non-null OTLP `AnyValue`
arm without stringification: Boolean to `boolValue`, `int64` and bounded `uint32`
to `intValue`, finite
double to `doubleValue`, string to `stringValue`, array to `arrayValue`, and object
to `kvlistValue`; canonical null has explicit `null_value_policy: reject`. The
closed `object_contexts` map identifies exact protobuf placement for Span,
ResourceSpans resource, ScopeSpans scope, Status, Event, and Link fields, so a leaf
target such as `schemaUrl` cannot accidentally bind to the wrong wrapper. The
closed `field_context_overrides` map handles the two wrapper-owned leaves:
`trace_resource.schema_url` belongs to `ResourceSpans` and
`trace_scope.schema_url` belongs to `ResourceSpans.scopeSpans[]`. The resource and
scope containers themselves do not map to nonexistent Span fields; the projector
traverses them and re-roots their registered children in those wrapper contexts.
Metric
mappings record the raw value and exact labels through the generated SDK instrument
so SDK aggregation owns OTLP data-point and
temporality shape. The v8 OTLP-log compatibility representation remains an
explicit versioned projection of the already route-redacted record; changing it to
a different structured log-body representation requires its own profile/version
and golden migration rather than an adapter-local reinterpretation.

##### Stable conditions

Conditional uses reference `conditional: <id>`; prose in a use is invalid. The root
`conditions` catalog accepts exactly `enforcement.kind: json_schema`,
`enforcement.kind: builder_fact`, or `enforcement.kind: boolean_attribute`. A
JSON-Schema condition supplies a closed typed predicate over independent record
fields. A builder-fact condition supplies one closed fact token; generated builders
evaluate it from typed producer state before record construction. A
boolean-attribute condition binds to one registered source Boolean without giving
callers a second independent fact. Each row declares
`false_requirement: optional|forbidden`; an adapter cannot treat omission and
permission as the same fallback. The current ten conditions contain eight
independent `builder_fact` values and two attribute-derived values:

| ID | Typed truth condition | False behavior |
|---|---|---|
| `connector-known-v1` | A positively normalized nonempty connector identity exists; an `unknown` placeholder does not count | Conditioned connector field forbidden |
| `operation-terminal-v1` | Terminal evidence exists for this bounded operation; when true the final outcome and trace end are present and coherent | Conditioned outcome remains optional because a nonterminal `attempted` observation is valid |
| `technical-failure-v1` | The operation/control itself technically failed under the status contract; a successful block decision or caller cancellation alone is not such a failure | Conditioned error field optional because a prevented requested operation may still use `policy_denied` |
| `guardrail-terminal-decision-available-v1` | The control reached a final typed decision | Conditioned decision forbidden |
| `security-severity-available-v1` | A recognized producer severity exists or was canonically normalized, including `NONE` to `INFO` | Conditioned severity forbidden |
| `judge-output-parse-failed-v1` | Judge output parsing failed and a bounded centrally redacted parse-error value exists | Conditioned parse error forbidden |
| `admin-principal-known-v1` | A positively authenticated/authorized administrative principal is known; submitted credentials and origin metadata cannot synthesize one | Conditioned principal forbidden |
| `agent-reported-cost-available-v1` | The connector explicitly supplied the registered reported-cost presence Boolean | Conditioned reported cost forbidden |
| `telemetry-canary-enabled-v1` | The producer explicitly supplied the registered canary marker Boolean | Canary-only fields forbidden |
| `destination-test-failed-v1` | The explicit destination test reached the terminal `failed` result | Conditioned bounded failure class forbidden |

Calling one of these `json_schema` merely because the conditioned field is present
would be a tautology and is forbidden. Group resolution compares stable condition
IDs, not human prose. Generated-schema annotations identify builder-fact
enforcement for offline consumers, while emitted-record conformance proves the
builder applied it.

##### Agent phase/code value catalog

The root `registry.yaml` `value_catalogs` owns one catalog
`agent-phase-v1` with exact `kind: string-int64-bijection`. Its ordered
`value_attributes` are `defenseclaw.agent.phase`,
`defenseclaw.agent.phase.previous`, `defenseclaw.agent.phase.from`, and
`defenseclaw.agent.phase.to`; `paired_value_attribute` identifies the current
phase paired with `code_attribute: defenseclaw.agent.phase.code`. Its authored
closed `compatibility` object reserves `code: 0`, `value: unknown`, and
`canonical_emittable: false`; the compiler never synthesizes this metadata. The
immutable canonical entries are:

```text
1 session       2 planning      3 model       4 tool
5 approval      6 waiting       7 responding  8 maintenance
9 completed    10 failed       11 interrupted 12 observed
```

The compiler derives the exact four string enums and numeric range `1..12`; the
attributes cannot hand-author a different enum/range. When current phase and code
coexist, their pair must match. Code `0` remains reserved for
unknown/unrecognized compatibility input, has `canonical_emittable: false`, and is
not part of either canonical normalizer. Evolution is append-only: an existing
value/code cannot be renamed, removed, or renumbered, and a new phase receives the
next unused positive code.

##### Group and family lifecycle

Every group has required top-level `introduced_in` and optional top-level
`deprecated_in` and `removed_in`, matching attribute lifecycle vocabulary rather
than adding a second nested dialect. Deprecated stability requires
`deprecated_in`, and removal requires deprecation. Removed families remain in the
historical catalog but cannot be built or route-selected.

The semantic-diff gate evaluates each fully resolved family, including inherited
group changes. A required-field, type, meaning, bucket, span-name/kind, applicable
outcome, field-class, or sensitivity break requires a family-schema-version bump
and reviewed compatibility disposition. Editing a reusable group cannot evade that
rule; an optional safe addition may retain the family version.

Pre-release consistency correction: the initial v8 `telemetry-registry-v1`
families have not shipped, and the trace kernel has always required every field
substituted into a registered span-name program in order to render that name. The
source therefore marks all nineteen span-name field occurrences as unconditional
required string attributes, including sixteen family-local strengthenings that
remove an optional-input/required-kernel contradiction. This correction remains
family schema version 1 because no released v8 family accepted the missing values;
it does not authorize changing a released family in place. Migration preserves the
existing missing-data rule: producers supply the value or construction fails, and
no adapter fabricates or reverse-parses it from a rendered name.

##### Complete single-fault examples

Every `examples.yaml` valid record is a complete canonical record accepted by the
generated builder and public bundle, not a partial illustrative fragment. Trace
examples place IDs only in envelope correlation and the rendered name only in
`span_name`; their body uses the snake_case structure in §5.4 with status,
resource, and scope. Log and trace field-class pointers are payload-rooted. Metric
examples omit envelope outcome, use only `{value, attributes}` in
`instrument_data`, and use canonical label names rather than compatibility labels.

Each invalid example is derived from `base_example` by one closed `mutation`
whose `kind` equals the exact stable error code and whose ordered `changes` use
RFC 6901 pointers rooted at `{signal,family?,record}`. Each change is `add`,
`replace`, or `remove`; values are required for add/replace and forbidden for
remove. The compiler applies that one semantic mutation and requires byte-equivalent
structured equality with the authored invalid vector. It MUST NOT omit unrelated
required fields or contain a second defect that could fail first. The minimum
single-fault corpus covers both-arm/neither-arm and forbidden-envelope states;
envelope-prefixed field-class pointers; unknown structural members; trace
camelCase/duplicate identity fields; zero/malformed IDs; end-before-start; invalid
status aliases; every nested dropped-count overflow; scope/profile and family
equality mismatch; metric unknown labels and outcome; each condition true with its
field absent and each forbidden false-state field present; all twelve valid phase
pairs, a mismatched pair, and reserved phase code zero.

#### 5.2.3 Generated-builder source grammar and candidate render contract

P-069 remains the sole authority for canonical record structure. The following
source is additional P-070 generation authority: it supplies facts that cannot be
reconstructed from an emitted record, closed structured input shapes, and stable
language symbols. It MUST NOT redefine an envelope field, family field, privacy
class, normalizer, outcome, or OTLP placement already owned by P-069.

The registry root adds exactly `mandatory_rule_catalog`, `structured_types`,
`structured_bindings`, `go_symbol_policy`, and optional `go_symbol_overrides`.
Unknown members fail. Domain files continue to own families and ordinary
attributes; they do not acquire local copies of these root catalogs.

##### Mandatory-rule catalog

`mandatory_rule_catalog` is the closed object `{version, rules}` with
`version: 1`. Each rule is exactly `{id, enforcement}`. `enforcement` is one of
`{kind: constant, value: true}` or `{kind: builder_fact, fact: <stable-token>}`.
Rule IDs and builder-fact tokens are unique. Version 1 contains exactly the
following twelve rules:

| Rule ID | Enforcement |
|---|---|
| `always` | constant true |
| `control_plane_mutation` | builder fact `control_plane_mutation` |
| `approval_resolution` | builder fact `approval_resolution` |
| `alert_mutation` | builder fact `alert_mutation` |
| `protected_boundary_auth_failure` | builder fact `protected_boundary_auth_failure` |
| `enforced_outcome` | builder fact `enforced_outcome` |
| `enforcement_state_change` | builder fact `enforcement_state_change` |
| `schema_validation_failure` | builder fact `schema_validation_failure` |
| `sqlite_failure` | builder fact `sqlite_failure` |
| `exporter_initialization_failure` | builder fact `exporter_initialization_failure` |
| `durable_health_transition` | builder fact `durable_health_transition` |
| `destination_test_activity` | builder fact `destination_test_activity` |

Only log families may declare `mandatory_floor`; every listed ID resolves through
this catalog. A log occurrence is mandatory when at least one referenced rule is
true. An absent/empty rule list is false. The compiler never equates a nonempty
rule list with a true occurrence, and producers never supply a raw `mandatory`
Boolean. Facts not referenced by the selected family are rejected rather than
silently ignored. The `always` rule requires no producer fact.

The selected canonical family is the sole floor authority. A producer mapping's
`mandatory_rules` list records only the pre-cutover legacy
`Classification.isMandatory` behavior; it is not a second v8 floor program or a
capability declaration. The transitional broad `MandatoryFacts` carrier can
represent all ten builder facts. After identity selection, the generated adapter
reads only facts referenced by the selected family's program and rejects any
unrelated fact asserted true; unrelated false members assert nothing and are
ignored. Generated family inputs expose only the selected family's facts, so an
unrelated fact is unrepresentable there. The generated producer adapter never
uses the legacy mapping-level result, and that evaluator is removed at the atomic
producer cutover. Family floors are updated before cutover where a legacy mapping
represented a genuine durable family property that must remain mandatory.
Specifically, the nine asset-state families `asset.activated`, `asset.admitted`,
`asset.disabled`, `asset.discovered`, `asset.quarantined`, `asset.registered`,
`asset.released`, `asset.removed`, and `asset.updated` add
`enforcement_state_change`; the fact remains false for observations that did not
change durable state.

##### Structured types and bindings

`structured_types` is an ordered list of named definitions. Every row has exactly
`{id, kind, introduced_in}` plus the members required by its kind. The ordinary
kinds remain closed; `canonical_json` is the single compiler-owned, bounded,
non-null recursion exception required by the pinned OTel GenAI shapes:

Version 1 contains exactly these twenty-one fully qualified type IDs, in this
order: `gen_ai.canonical_json`, `gen_ai.tool_call_arguments`,
`gen_ai.tool_call_result`, `gen_ai.input_messages`, `gen_ai.output_messages`,
`gen_ai.message_parts`, `gen_ai.message_part`, `gen_ai.chat_message`,
`gen_ai.output_message`, `gen_ai.text_part`, `gen_ai.tool_call_request_part`,
`gen_ai.tool_call_response_part`, `gen_ai.server_tool_call_part`,
`gen_ai.server_tool_call_response_part`, `gen_ai.blob_part`, `gen_ai.file_part`,
`gen_ai.uri_part`, `gen_ai.reasoning_part`, `gen_ai.compaction_part`,
`gen_ai.generic_part`, and `gen_ai.generic_server_tool_payload`. The named P-070
type `gen_ai.canonical_json` is not P-069's primitive structural
`type: canonical_json`: the named type is reachable only through the four
structured bindings below and does not reclassify or replace any P-069 field.

- `kind: object` adds `additional_properties: false`, `fields`, and optional
  `dynamic_members`. `fields` is nonempty unless `dynamic_members` is present. A
  fixed field uses exactly one closed arm. The scalar-leaf arm is authored as
  `{name, required, type, field_class, sensitivity, normalization}`, where `type`
  is one ordinary scalar registry type. After exact upstream-property disposition,
  the compiler enriches the materialized scalar descriptor with
  `encoding_annotation`; it is absent except for the closed version-1 value
  `json-base64-bytes-v1` derived from pinned upstream `format: binary` on
  `gen_ai.blob_part.content`. Generated JSON Schema emits
  `contentEncoding: base64` and `x-defenseclaw-upstream-format: binary`, while
  typed builders continue to accept a string and do not turn the upstream SHOULD
  into a new decoding/rejection MUST. Moving, adding, or removing the upstream
  format fails compilation rather than requiring a duplicate authored registry
  fact. The container/reference arm is
  `{name, required, structured_ref}` and carries no `field_class`, `sensitivity`,
  `normalization`, or `encoding_annotation`; those properties belong only to the
  referenced concrete leaves. `dynamic_members`, when present, is the following closed block (with
  concrete finite normalization/bounds in the registry):

  ```yaml
  dynamic_members:
    member_id: entry
    name:
      type: string
      field_class: identifier
      sensitivity: internal
      normalization: {id: bounded-v1, overrides: {max_utf8_bytes: 256}}
    value: {structured_ref: gen_ai.canonical_json}
    max_items: 256
    public_encoding: ordered_typed_entries
    wire_encoding: native_object_properties
    duplicate_name_policy: reject
    fixed_name_collision_policy: reject
    post_redaction_name_collision_policy: reject
  ```

  `value.structured_ref` may instead name another compatible bounded structured
  value. Public APIs retain ordered typed name/value entries. Canonical wire
  encoding flattens those entries into native JSON properties alongside fixed
  fields; it never emits an entry-array wrapper. Duplicate dynamic names and a
  dynamic name equal to any fixed field fail before encoding and again after
  destination redaction/normalization. A post-redaction collision rejects that
  destination projection with stable code `structured_member_name_collision` and
  exporter-health accounting; it never drops or overwrites a member. An object
  with empty `fields` and no `dynamic_members` is invalid.
  `member_id` is the stable compile-time identity used for symbols and descriptors;
  it is never wire data. `name` is the producer-supplied runtime member name. Every
  open object in the version-1 closure uses `member_id: entry`, scoped by its
  owning type, including the tool roots, `gen_ai.generic_part`, and
  `gen_ai.generic_server_tool_payload`.
- `kind: array` adds `items`, `min_items`, and `max_items`. Bounds are finite,
  nonnegative, and ordered. Scalar items use exactly
  `{type, field_class, sensitivity, normalization}`, where `type` is one ordinary
  scalar registry type. Structured items use exactly `{structured_ref}` and defer
  classification, sensitivity, and normalization to the child leaves. The array
  container itself is never classified.
- `kind: tagged_union` adds `discriminator`, at least two `variants`, and optional
  `dynamic_variant`. Each
  variant is exactly `{tag, structured_ref}`; tags and targets are unique and the
  discriminator is the explicit scalar-leaf object
  `{name, type: string, field_class, sensitivity, normalization}`. Its `name` is a
  fixed schema-owned object field, and its registered bounded normalization has a
  closed enum equal to the variant tags when `dynamic_variant` is absent.
  `dynamic_variant` is exactly
  `{arm_id, tag_normalization, structured_ref, exclude_registered_tags: true}` and admits
  an arbitrary bounded string tag except every registered `variants[].tag`; its
  target is normally a GenericPart object with `dynamic_members`. A false/missing
  exclusion, registered-tag overlap, an unbounded tag, and a dynamic tag with a
  different normalization are compile errors.

  Version 1 has one tagged union, `gen_ai.message_part`. Its `dynamic_variant` is
  exactly:

  ```yaml
  dynamic_variant:
    arm_id: generic
    tag_normalization: {id: bounded-v1, overrides: {max_utf8_bytes: 256}}
    structured_ref: gen_ai.generic_part
    exclude_registered_tags: true
  ```

  Its registered variants are exactly:

  | Tag and stable arm ID | Structured target |
  |---|---|
  | `text` | `gen_ai.text_part` |
  | `tool_call` | `gen_ai.tool_call_request_part` |
  | `tool_call_response` | `gen_ai.tool_call_response_part` |
  | `server_tool_call` | `gen_ai.server_tool_call_part` |
  | `server_tool_call_response` | `gen_ai.server_tool_call_response_part` |
  | `blob` | `gen_ai.blob_part` |
  | `file` | `gen_ai.file_part` |
  | `uri` | `gen_ai.uri_part` |
  | `reasoning` | `gen_ai.reasoning_part` |
  | `compaction` | `gen_ai.compaction_part` |

  A registered tag is also that variant's stable arm identity. The union owns the
  only wire `type` discriminator; target objects do not redeclare it. The compiler
  adds `type` to every target's effective fixed/reserved-name collision set and
  rejects a target fixed field with that name. Runtime validation rejects a
  dynamic `type` member before and after redaction with
  `structured_member_name_collision`. The encoder emits the discriminator exactly
  once before flattening dynamic members. The open discriminator and dynamic tag
  use the same effective bounded normalization, and the dynamic arm always
  excludes all registered tags.
- `kind: canonical_json` is recognized only for the reserved
  `gen_ai.canonical_json` definition. Authors cannot create another instance. Its
  source shape is exactly the following closed compiler schema; no omitted or
  extension key is allowed:

  ```yaml
  id: gen_ai.canonical_json
  kind: canonical_json
  introduced_in: telemetry-registry-v1
  discriminator: {visibility: internal, wire: false}
  arms: [boolean, int64, finite_double, string, array, object]
  leaf_privacy: {field_class: content, sensitivity: sensitive}
  array: {items_ref: gen_ai.canonical_json}
  object:
    members:
      member_id: entry
      name:
        type: string
        field_class: identifier
        sensitivity: internal
        normalization: {id: bounded-v1, overrides: {max_utf8_bytes: 256}}
      value: {structured_ref: gen_ai.canonical_json}
    public_encoding: ordered_typed_entries
    wire_encoding: native_object_properties
  limits:
    max_depth: 8
    max_aggregate_members: 256
    max_array_items: 256
    max_string_utf8_bytes: 4096
    max_member_name_utf8_bytes: 256
    max_item_bytes: 32768
    max_canonical_bytes: 65536
  ```

  Its public type is one sealed union of Boolean, Int64, finite Double, String,
  Array, and Object arms; Array contains the same union and Object contains ordered
  typed member entries whose values use the same union. The arm discriminator is
  private compiler/runtime state and is never serialized to canonical JSON or
  OTLP. Null is not an arm: canonical validation and every destination projection
  reject null at any nesting depth. Nonfinite doubles fail, and this self-reference
  is the only permitted structured recursion. Bindings may only tighten, never
  remove or increase, these limits.

  All limits are inclusive and are rechecked after every destination redaction or
  normalization pass. The root object or array is at depth zero; entering a child
  object or array increments depth by one, while scalar leaves do not. Across one
  canonical value, `max_aggregate_members` counts every object entry plus every
  array element at every depth; `max_array_items` separately caps each array.
  String and member-name limits count normalized unescaped UTF-8 content, and the
  member-name normalizer's effective bound must equal
  `max_member_name_utf8_bytes`. `max_item_bytes` counts the canonical UTF-8 JSON
  encoding of each immediate object-member value or array-element subtree,
  including its own quoting, escaping, and nested delimiters but excluding an
  enclosing object key and colon; the root is not an item. Its 32-KiB bound is
  intentionally larger than the 4-KiB unescaped string bound so worst-case JSON
  escaping does not make an otherwise valid string contradictory.
  `max_canonical_bytes` counts the complete canonical UTF-8 JSON encoding. A
  pre-redaction or post-redaction value exceeding any bound is rejected rather
  than truncated.

  `gen_ai.tool_call_arguments` and `gen_ai.tool_call_result` are distinct closed
  `kind: object` roots with `additional_properties: false`, empty `fields`, and the
  exact `dynamic_members` block above pointing values to
  `gen_ai.canonical_json`. This preserves the pinned object-only root shape:
  Boolean, number, string, array, and null are invalid as the whole arguments or
  result value even though bounded non-null scalar/array arms are valid beneath a
  dynamic object member.

Apart from the compiler-owned `canonical_json` self-reference, definitions form an
acyclic graph and every reachable string/array/object retains an effective bound.
Open objects without `dynamic_members` and untagged or overlapping unions are
invalid. Provider-, tool-, or producer-controlled names use registered ordered
typed member entries internally; only `dynamic_members` may turn those names into
native JSON property names at canonical-encoding time.

After expansion, every reachable fixed concrete scalar leaf, including scalar
array items and tagged-union discriminators, has exactly one effective
`field_class`, `sensitivity`, and bounded `normalization`. A dynamic member's
referenced canonical-JSON `leaf_privacy` applies recursively to its value leaves;
member names retain their separately bounded identifier classification and never
upgrade the value's safety. Central redaction therefore traverses canonical-JSON
String arms and other dynamic leaves exactly as it traverses fixed leaves,
preserving the remaining typed shape. If a profile transforms a dynamic name, the
projector repeats normalization, duplicate, and fixed-name collision validation
before serialization. Object, array, variant, and `structured_ref` containers
have none. Missing, duplicate, inherited-conflicting, or container-level privacy
annotations fail compilation; P-069 payload-rooted leaf coverage remains the sole
emitted-record classification authority.

`structured_bindings` is an ordered list of exact `{attribute, structured_type,
public_encoding, canonical_wire_encoding}` rows. Version 1 is exactly:

| Attribute | Structured type | Public encoding | Canonical wire encoding |
|---|---|---|---|
| `gen_ai.input.messages` | `gen_ai.input_messages` | `sealed_typed` | `native_json` |
| `gen_ai.output.messages` | `gen_ai.output_messages` | `sealed_typed` | `native_json` |
| `gen_ai.tool.call.arguments` | `gen_ai.tool_call_arguments` | `ordered_typed_entries` | `native_json_object` |
| `gen_ai.tool.call.result` | `gen_ai.tool_call_result` | `ordered_typed_entries` | `native_json_object` |

Nested `dynamic_members` still use `ordered_typed_entries` at the public boundary
and `native_object_properties` on the canonical wire. Local scalar arrays,
including `defenseclaw.guardrail.rule_ids` and `defenseclaw.approval.argv`, are not
structured bindings. A binding cannot change the upstream name, owner, or
primitive wire meaning. Missing, duplicate, unused, additional, or
shape-incompatible bindings fail compilation. Generated public APIs use only the
sealed typed union and ordered member types; they may not expose `map[string]any`,
`any`, `interface{}`, a raw/untyped `Value`, or an equivalent escape hatch.

The compiler consumes the following exact offline upstream structural inputs.
They are part of the lock contract independently of the normalized snapshot and
are read from the pinned OTel semantic-conventions commit
`b028dceecdad117461a785c3af35315e7184e813`:

| Input | SHA-256 |
|---|---|
| `model/gen-ai/gen-ai-input-messages.json` | `034fcd8c87f1e013f3a5a5018503210e2bee4d2499c361823b96e906d40a50ad` |
| `model/gen-ai/gen-ai-output-messages.json` | `a825a6c0cc1b7b22fdbfb9488d8dc3a318be3897ef6d3dbae01a10297bb6e569` |
| `model/gen-ai/gen-ai-tool-call-arguments.json` | `73607a8e8d9e84393475ef460108c59dbb9e1d2ddc0d0177fce6f735a62367ea` |
| `model/gen-ai/gen-ai-tool-call-result.json` | `44eb4a93b05eea7da14489f1d253814c6429772d1fe869f8f6fc1749d7593412` |

For each property reachable from those inputs, the compiler records exactly one
disposition: fixed field, `dynamic_members`, `dynamic_variant`, nullable-optional
omission, or explicit rejection. It rejects an undisposed property and never
silently drops an unknown extra. Upstream nullable optional properties normalize
only by omission: an absent property stays absent, and an explicit null may be
omitted at the typed producer boundary only when the lock marks that property both
optional and nullable. Required null, all other null, and emitted null fail under
P-069; null is never a default or union arm.

##### Go symbol policy and table

`go_symbol_policy` is exactly:

```yaml
go_symbol_policy:
  version: 1
  package: observability
  separators: ['.', '-', '/', '_']
  brand_spellings:
    defenseclaw: DefenseClaw
    opentelemetry: OpenTelemetry
    otel: OTel
  initialisms: [AI, API, DB, HEC, HTTP, ID, JSON, LLM, OTEL, OTLP, PII, RPC, SDK, SQL, TLS, URL, UTF8]
  reserved_word_policy: reject
  collision_policy: reject
  auto_suffix_policy: reject
```

The separators split source tokens, and every token must be nonempty ASCII. The
normalization precedence is exact: lowercase `brand_spellings` lookup first,
uppercase `initialisms` lookup second, and ordinary title-case last. Namespace
assignment is closed and exact. The reviewed `OTEL` initialism remains in the
closed set, but the `otel: OTel` brand entry intentionally wins for that token:

Structured declarations tokenize the complete fully qualified type ID, so the
public structured type for `gen_ai.canonical_json` is
`TelemetryStructuredGenAICanonicalJSON`.
`<MemberName>` comes from a fixed field `name` or from `member_id` for a controlled
dynamic entry. `<ArmName>` comes from a registered `tag`, or from `arm_id` for a
dynamic variant. Identical `entry` member IDs are scoped by owning structured type
and therefore remain distinct declarations.

| Declaration | Required Go symbol |
|---|---|
| Attribute ID | `TelemetryAttribute<Name>` |
| Family ID | `TelemetryFamily<Name>` |
| Log-event ID | `TelemetryEvent<Name>` |
| Span-event ID | `TelemetrySpanEvent<Name>` |
| Link-relation ID | `TelemetryLinkRelation<Name>` |
| Metric-instrument ID | `TelemetryInstrument<Name>` |
| Condition ID | `TelemetryCondition<Name>` |
| Condition-fact ID | `TelemetryConditionFact<Name>` |
| Phase ID | `TelemetryPhase<Name>` |
| Phase-code ID | `TelemetryPhaseCode<Name>` |
| Semantic-profile ID | `TelemetrySemanticProfile<Name>` |
| Structured public type | `TelemetryStructured<Name>` |
| Structured-member ID | `TelemetryStructuredMember<TypeName><MemberName>` |
| Structured public arm type | `TelemetryStructuredArm<TypeName><ArmName>` |
| Typed structured-member input | `<TypeName><MemberName>MemberInput` |
| Typed structured-member constructor | `New<TypeName><MemberName>Member` |
| Per-family input | `Log<Name>Input`, `Span<Name>Input`, or `Metric<Name>Input` according to the family signal |
| Per-family builder method | `BuildLog<Name>`, `BuildSpan<Name>`, or `BuildMetric<Name>` according to the family signal |
| Typed span-event input | `Span<FamilyName><EventName>EventInput` |
| Typed span-event constructor | `NewSpan<FamilyName><EventName>Event` |
| Typed link input | `Span<FamilyName><RelationName>LinkInput` |
| Typed link constructor | `NewSpan<FamilyName><RelationName>Link` |

Every `GoSymbolTableIR` row carries one compiler-owned `declaration_form` from
the closed set `exported_const`, `exported_type`, `exported_function`, and
`family_builder_method`. The 21 structured-type rows and 17 structured-arm rows
are `exported_type`: their symbols are the sealed public Go declarations, while
their stable source IDs/tags remain private generated-catalog descriptor values
and are never exported as duplicate constants. The 49 structured-member rows and
all other ID rows are `exported_const`. Input, constructor, and builder rows use
their matching non-constant declaration form. A renderer emits every row exactly
once in its recorded form and never infers a form from its prefix or source kind.

Structured-member, arm, input, and constructor rows are derived from the authored
structured-type definitions. Fixed fields remain typed fields of their owning
input, union constructors supply their discriminator, and controlled dynamic
members receive scoped `<type>#<member>` identities. No global row count is an
authored contract.

The table order is the declaration-kind order above, followed by bytewise ASCII
`source_id` order within each kind. Its digest payload is compact UTF-8 JSON with
no trailing line feed and `ensure_ascii=false`, shaped as
`[[kind,source_id,symbol,declaration_form], ...]` and prefixed by
`DefenseClaw GoSymbolTableIR v1` plus one NUL byte. The digest proves internal
determinism and binds generated outputs to the exact table compiled in that run;
it is not a hand-maintained acceptance value.

The authored registry and generated Go declarations are the review artifacts.
The compiler derives row counts, declaration-form counts, file partitions, and
the table digest, then independently reconciles every symbol source with the
authored registry. Tests verify ordering, uniqueness, semantic naming, complete
source coverage, declaration ownership, safety bounds, and digest
self-consistency. Adding a valid family or attribute never requires editing a
count, digest, or digest-addressed symbol-table baseline. Removal or renaming is
governed by entity lifecycle and compatibility rules, with prior epochs retained
in Git history.

The five successor declarations are exactly attributes `user.id`,
`defenseclaw.tool.id`, `defenseclaw.agent.reported_cost.present`, and
`defenseclaw.agent.reported_cost.usd`, plus condition
`agent-reported-cost-available-v1`; no prior declaration is removed or renamed.
Families `span.agent.transition`, `span.agent.invoke`, `span.workflow.run`,
`span.model.chat`, and `span.tool.execute` all gain the source-reported interaction
context and reported-cost group. Transition, invoke, and workflow spans additionally
accept optional model and tool identity context. Every one of the five builders
requires the availability Boolean: `false` forbids the USD value, while `true`
requires a finite nonnegative value and treats reported zero as present. The value
is cumulative agent/session cost reported by the connector, never an estimate.
`llm.cost.total` is not a default alias because its operation scope need not equal
the agent/session scope.

`span.agent.transition` remains a native lifecycle span and advertises only
`local-observability-v1`. Its registry binding is explicitly Galileo-ineligible
because it cannot honestly supply Galileo's invoke-agent operation, provider,
input-message, and output-message semantics. A projector must omit it from that
profile rather than fabricate any of those values.

For family declarations, `<Name>` omits the leading signal token from the stable
family ID; for example, `span.model.chat` produces `SpanModelChatInput` and
`BuildSpanModelChat`. Event and link type/constructor names include the owning
span family, so reusable event or relation IDs cannot collide across typed APIs.
The compiler rejects an empty token, non-ASCII symbol result, Go
keyword/predeclared-identifier collision, leading digit, or two source identities
that produce one symbol in any namespace. It never appends a numeric, signal, or
hash suffix to repair a collision.

`go_symbol_overrides`, when present, is a closed ordered table of
`{kind, source_id, symbol, reason}`. It is allowed only to resolve a reviewed
collision or preserve a released public symbol; it cannot remove the
required namespace prefix/suffix, change the declaration kind/signature, or evade
brand spelling. Duplicate, unused, or policy-equivalent overrides fail. An
override is the only reviewed collision resolution; automatic suffixing remains
forbidden.

The override `kind` vocabulary is exactly `attribute`, `family`, `log_event`,
`span_event`, `link_relation`, `metric_instrument`, `condition`,
`condition_fact`, `phase`, `phase_code`, `semantic_profile`, `structured_type`,
`structured_member`, `structured_arm`, `structured_member_input`,
`structured_member_constructor`, `family_input`, `family_builder`,
`span_event_input`, `span_event_constructor`, `span_link_input`, and
`span_link_constructor`. The override key is the pair `(kind, source_id)`; a
`source_id` alone is not globally unique across declaration kinds.

For unscoped ID, family input, and family-builder rows, `source_id` is the exact
stable registry identity owned by that row. Structured members, arms, ordered
member inputs, and ordered member constructors use
`<structured_type_id>#<member_id_or_arm_id>`. Family-scoped span-event and link
inputs/constructors use `<span_family_id>#<event_name_or_relation>`. The same
compound `source_id` may intentionally occur for matching input/constructor rows,
but their `kind` values differ. Empty components, additional `#`, aliases, Go
symbols in place of registry identities, and a span event's internal `event.`
group ID are invalid.

Override eligibility is machine-checked. A row may be overridden only when its
policy-derived symbol participates in the pre-override collision being resolved,
or when the exact `(kind, source_id, symbol)` is present in a named, digest-pinned
prior released-symbol baseline for the new registry epoch. A free-standing rename
of a noncolliding symbol is invalid even with a reason. Registry v1 has no prior
released-symbol baseline and its policy-derived table has no collisions, so its
`go_symbol_overrides` is absent or an empty list. A future epoch cannot use the
released-symbol arm until its source contract names that prior baseline as a
locked compiler input. This rule keeps `reason` reviewable prose rather than an
authorization bypass.

The compiler materializes a complete immutable `GoSymbolTableIR` for every symbol,
including unoverridden rows, and records `declaration_form` on every row. Renderers
consume that table, emit no row as both a constant and a type, and do not repeat
the tokenization algorithm.

##### Derived-value and compiler-owned Go API plan

The compiler-derived symbol table is the package-declaration ABI; it deliberately
does not contain owner-scoped struct fields. A second immutable `GoAPIPlanIR` is
compiler output, never authored YAML and never renderer policy. It closes the
shape of every generated declaration while keeping the reviewed declaration table
stable. Renderers receive already-resolved plans and perform only syntax emission.

P-069 `trace.derivations` is the only authored source of non-input trace values.
A derivation targets either `target_attribute` or `target_field`, never both.
`target_attribute` is scoped to its registered trace occurrence (span, resource,
scope, event, or link), so the trace derivation for `defenseclaw.outcome` cannot
affect the metric label with the same attribute ID. `target_field` version 1
accepts only `trace_scope.version`. The closed value-source vocabulary is:

| Value source | Exact producer value |
|---|---|
| `input` | Typed public field selected by the plan |
| `constant` | P-069 field `const` |
| `envelope.bucket` | Selected family's registered identity bucket |
| `family.id` | Selected family ID |
| `family.family_schema_version` | Selected family schema version |
| `envelope.source` | `FamilyEnvelopeInput.Source` |
| `provenance.config_generation` | `FamilyEnvelopeInput.Provenance.ConfigGeneration` |
| `envelope.outcome` | The selected builder's typed outcome, when present |
| `provenance.binary_version` | `FamilyEnvelopeInput.Provenance.BinaryVersion` |
| `semantic_profile.trace_schema_version` | Selected semantic profile trace schema version |
| `semantic_profile.id` | Selected semantic profile ID |
| `link.relation` | Generated typed link constructor's registered relation |

Compiler precedence is exact: a P-069 `const` yields `constant`; an exact
trace-derivation target yields its declared source; every other registered leaf
yields `input`. There is no name-based fallback. Version 1 authors the existing
six span derivations plus `service.version <- provenance.binary_version`,
`trace_scope.version <- provenance.binary_version`,
`defenseclaw.trace.schema_version <- semantic_profile.trace_schema_version`,
`defenseclaw.semantic_profile <- semantic_profile.id`, and
`defenseclaw.link.relation <- link.relation`. Scope name and schema URL are the
constants `defenseclaw.telemetry` and
`https://defenseclaw.io/schemas/telemetry/v8`; resource schema URL remains typed
producer input. A missing, duplicate, context-incompatible, or unused derivation
fails compilation.

`GoAPIPlanIR` is composed of these recursively immutable records:

| Record | Required contents |
|---|---|
| `GoDeclarationPlanIR` | Symbol-table key, declaration form, exact output file/order, and exactly one constant/type/input/callable target; constants carry a closed `string|integer` literal kind and exact typed value |
| `GoTypeRefIR` | Closed AST arm `builtin`, `named`, `optional`, or `slice`; nested type refs, never renderer-built Go text |
| `GoFieldPlanIR` | Owner, exact selector, type ref, order, presence, semantic source ID, enriched descriptor ID, value source, target slot, condition/mandatory binding, and conversion op |
| `GoInputPlanIR` | Symbol-table declaration key, exact output file, ordered fields, private kernel target, and referenced event/link/resource plans |
| `GoCallablePlanIR` | Declaration key, optional receiver, ordered parameters/results, error contract, and one private kernel/conversion target |
| `GoStructuredPlanIR` | Owner shape, ordered fixed fields/items/arms/dynamic members, private discriminator, and complete recursive conversion plan |
| `GoDescriptorPlanIR` | Pre-resolved family/field/limit/name/event/link/metric/mandatory contracts accepted by the private kernel |
| `GoFilePlanIR` | One of the exact seven paths, ordered declaration keys, private descriptor/projection sections, and expected digest headers |

The Go type mapping is closed: `string -> string`, `boolean -> bool`,
`int64 -> int64`, `uint32 -> uint32`, `uint64 -> uint64`, `double -> float64`,
`string[] -> []string`, and a structured binding to its named public structured
type. Required values use `T`; recommended, optional, and conditional values use
`Optional[T]`. A metric's `Value` is the registry's exact `int64` or `float64` and
the plan selects `familyInt64MetricNumber` or `familyDoubleMetricNumber`.
Conversion ops are a closed enum covering required scalar, optional scalar,
copied string slice, structured encoder, metric number, condition fact,
mandatory fact, trace event, and trace link. A plan that the private kernel cannot
represent fails before rendering.

Owner-scoped selectors use the same already-compiled token policy as package
symbols, but the compiler—not a renderer—applies it. For an ordinary canonical
attribute, the selector is the complete attribute ID without a declaration
prefix (`gen_ai.request.model -> GenAIRequestModel`). Fixed structured members
use their wire member name within the owning type. Condition selectors are
`Condition<FactName>` and mandatory selectors are `Mandatory<FactName>`.
Common structural selectors are frozen below. Owner-local collisions with another
semantic selector, common selector, Go keyword/predeclared identifier, or reserved
structured selector fail; no suffix repair is permitted. The plan stores the
final selector and renderers never strip `TelemetryAttribute`, tokenize an ID, or
invent a field name.

Generated family input layouts are exact:

| Signal/input | Ordered common fields before generated value fields |
|---|---|
| Log | `Envelope FamilyEnvelopeInput`; `Severity Optional[Severity]`; `LogLevel Optional[LogLevel]`; then `Outcome` as `Outcome`, `Optional[Outcome]`, or omitted according to the family outcome policy |
| Span | `Envelope FamilyEnvelopeInput`; `Outcome Outcome`; `Kind string`; `StartTimeUnixNano uint64`; `EndTimeUnixNano uint64`; `ParentSpanID Optional[string]`; `TraceState Optional[string]`; `Flags uint32`; `Status TraceStatusInput`; `Resource TraceResourceInput`; `Scope TraceScopeInput`; `DroppedAttributesCount Optional[uint32]`; `Events []TraceEventInput`; `DroppedEventsCount Optional[uint32]`; `Links []TraceLinkInput`; `DroppedLinksCount Optional[uint32]` |
| Metric | `Envelope FamilyEnvelopeInput`; `Value int64|float64` |
| Span event | `TimeUnixNano uint64`; `DroppedAttributesCount Optional[uint32]` |
| Span link | `TraceID string`; `SpanID string`; `TraceState Optional[string]`; `DroppedAttributesCount Optional[uint32]` |

Resolved public log-family and metric-label fields follow those common fields in
resolved source order. For spans, the thirteen input-sourced `resource.core`
fields follow the common fields in resolved resource order, followed by the
input-sourced family span attributes in resolved family order. Only
`value_source: input` fields are public. Family-scoped
condition fields follow their conditioned values in first-use order, deduplicated
by fact. Nonconstant mandatory fields follow log values in mandatory-rule order.
Required outcome is a plain value, optional outcome is `Optional[Outcome]`, and a
forbidden outcome has no selector. There is no public bucket, family, schema
version, span name, scope identity/profile, link relation, mandatory Boolean,
field-class map, or private descriptor selector.

Every family method has the exact signature
`func (*FamilyBuilder) Build<Family>(input <FamilyInput>) (Record, error)`.
Every typed event constructor is
`func New<Family><Event>Event(input <EventInput>) (TraceEventInput, error)`, and
every typed link constructor is
`func New<Family><Relation>Link(input <LinkInput>) (TraceLinkInput, error)`.
They take no context, catalog, descriptor, variadic option, map, or raw value.
Future cancellation belongs outside deterministic record construction; changing a
signature is a reviewed public-API epoch change, not renderer discretion.

`TraceResourceInput` remains the common structural input with
`SchemaURL string` and `DroppedAttributesCount Optional[uint32]`; its registered
values stay package-private. It additionally accepts only the generated sealed
`resource.core` custom-member value plus the generation's compatibility-alias
decision through a copy-returning generated attach function. No raw map, slice,
`any`, per-span custom field, or destination-owned parser is part of the API. Each
generated span-family input then owns the
thirteen `resource.core` attributes whose value source is `input`, using selectors
`Resource<FullAttributeSelector>` so the fields are emitted and versioned with the
family API. The derived `service.version` has no public selector. Required resource
attributes use plain types and recommended attributes use `Optional[T]`.
`TraceScopeInput` owns only `DroppedAttributesCount Optional[uint32]`; scope name,
version, schema URL, profile attributes, and its private values are derived.
Generated wrappers copy family-local resource fields into a local
`TraceResourceInput.values`, merge the sealed bytewise-sorted custom members, and
derive enabled aliases from their canonical fixed values before calling the
kernel. The generated dynamic descriptor assigns every custom pointer its exact
`metadata`/`internal` classification and rejects duplicates, collisions, invalid
types, secret/path/process-owned names or values, and aggregate overflow.
No generated public field is added manually to a handwritten common type.

Standard JSON Schema is the portable structural view of this dynamic contract,
not the only validator. It expresses the fixed members, common string shape,
reserved and forbidden key patterns, and the
`x-defenseclaw-dynamic-member-contract` extension. JSON Schema cannot portably
count only unmatched custom members, count UTF-8 bytes rather than code points,
sum aggregate key/value bytes, or compare distinct keys after Prometheus
normalization. DefenseClaw consumers therefore MUST run the generated semantic
resource validator in addition to ordinary JSON Schema validation before
accepting a resource for canonical construction or destination projection. That
validator is normative for the 64-member, 16-KiB, byte-bound,
normalized-collision, and forbidden path/credential-value rules. A schema-valid
document that fails the generated semantic validator is invalid; adapters MUST
NOT treat the extension keywords as descriptive-only annotations.
The generated `ValidateTelemetryResourceAttributes(map[string]any) error` entry
point exists only at untrusted record/destination boundaries so it can reject
non-string forged values. It returns no constructed resource, mutates nothing,
and cannot attach data to `TraceResourceInput`; it is therefore not an alternate
free-form construction API.

A condition fact lives with the smallest generated component whose presence
activates it: family/metric/resource/scope conditions on the family input, event
conditions on the typed event input, and link conditions on the typed link input.
`TraceEventInput` and `TraceLinkInput` retain
private condition facts beside their private contract/values. The wrapper merges
facts only from instantiated components; duplicate active facts must carry the
same state. It therefore never sends an event-only false fact when that event is
absent, and the kernel can continue rejecting missing or extra active facts.

Each log has a `ResolvedMandatoryProgramIR` containing its ordered rule IDs,
constant terms, distinct typed fact terms, and exact public selectors. Generated
code ORs those terms once, creates a package-private resolved log contract, and
passes the resulting private Boolean to `newSchemaDerivedLogRecord`. The public
input contains facts, not a caller-controlled mandatory result. `always` adds no
field; an empty program resolves false. The broad handwritten `MandatoryFacts`
type is only a transition carrier for generic producer adapters and is not reused
as a generated family-builder input.

Structured public shapes are also fixed by the plan:

- a P-070 object is an exported struct with ordered typed fixed fields followed by
  `Entries []<MemberInput>` when it has `dynamic_members`;
- an array is an exported struct with `Items []<ItemType>`;
- a tagged union is an exported interface with an unexported marker method, and
  each exported registered arm is `{Value <TargetType>}`; a dynamic arm is
  `{Tag string; Value <TargetType>}`;
- `gen_ai.canonical_json` is a sealed exported interface. Its Boolean, Int64,
  Double, and String arms are `{Value T}`, its Array arm is
  `{Items []TelemetryStructuredGenAICanonicalJSON}`, and its Object arm is
  `{Entries []<CanonicalMemberInput>}`;
- every controlled member input is exactly `{Name string; Value <RefType>}` and
  its constructor is `func New...(name string, value <RefType>) (<Input>, error)`.

Optional fixed structured fields use `Optional[T]`. The selectors `Entries`,
`Items`, `Name`, `Value`, and `Tag` are reserved in their applicable owner scopes.
The private conversion plan validates member names, duplicate/fixed/reserved-name
collisions, tags, finite doubles, null exclusion, recursion and aggregate bounds,
then returns canonical private values; it never exposes a map, `any`, interface
escape hatch, or raw `Value`.

Output ownership is exact, but generated Go declaration names and file partitions
are implementation details of the unreleased `internal/observability` package,
not a customer ABI. The compiler derives stable wire constants, the existing
typed producer façade, and a compact private descriptor/identity-set model; no
file or test pins declaration totals, row totals, or a digest of the compiler's
current implementation shape. An exported constant's literal is still resolved
from its semantic source, including numeric phase codes and wire/member
identities.

The index retains `materialized_view_sha256` and separately computes
`candidate_render_index_sha256` over the complete enriched descriptors and
`GoAPIPlanIR`. Its digest input is the ASCII domain prefix
`DefenseClaw CandidateRenderIndex v1`, one NUL byte, and the same deterministic
typed canonical JSON encoding used for the immutable view. The hashed canonical
index record explicitly includes `materialized_view_sha256` alongside the
enriched descriptors and `GoAPIPlanIR`; it is not metadata appended after hashing,
so the candidate digest cryptographically binds the exact source view. Every generated Go
file header carries the source digests needed for review. The renderer coordinator
compares the complete in-memory seven-file set before publication. Repository
publication uses one explicit output list, same-directory temporary files, atomic
replacement, fixed modes, and stale-output checks. Generated artifacts are
reproducible build outputs, so interruption recovery is simply a rerun; there is
no durable journal, rollback database, ownership manifest, or compiler-internal
ABI ledger.

##### Builder context in examples

Every `ExampleIR` gains required `builder_context`. A valid example uses the
closed explicit arm:

```yaml
builder_context:
  inheritance: {mode: explicit}
  occurrence:
    timestamp: '2026-07-03T12:00:00Z'
    record_id: rec-model-001
  condition_facts:
    operation_terminal: true
  mandatory_facts: {}
```

`occurrence` is exactly `{timestamp, record_id}` and supplies the deterministic
clock/ID results used by the real builder. They must equal the emitted record's
canonical occurrence fields. `condition_facts` contains exactly the registered
`ConditionIR.enforcement.fact` tokens (for example, `operation_terminal`)
referenced by the selected family's resolved fields, resource/scope fields,
instantiated events, and links; keys are never condition IDs, display names, or Go
symbols, and every value is Boolean. `mandatory_facts` contains
exactly the nonconstant mandatory facts referenced by the selected log family and
is empty for traces, metrics, and logs without such rules. Missing, extra,
duplicate, non-Boolean, or contradictory facts fail before construction.

An invalid example uses the closed inherited arm
`builder_context: {inheritance: {mode: exact_base, base_example: <id>}}` and has no
local occurrence/fact objects. The named example must equal `base_example`, must
be valid, and its complete builder context is inherited byte-for-byte. Invalid
mutations remain rooted only at `{signal,family?,record}`; they cannot alter facts
to introduce a competing failure. Inheritance is one level only and cycles are
impossible.

##### Compiler IR and one enriched candidate render index

The compiler adds immutable `MandatoryRuleIR`, `StructuredTypeIR`,
`StructuredBindingIR`, `GoSymbolPolicyIR`, `GoSymbolIR`, `BuilderContextIR`, and
typed occurrence/fact IR. All are retained recursively in
`MaterializedRegistryView` and its typed digest. The enrichment pass additionally
creates `EnrichedFieldDescriptor`, `EnrichedContainerDescriptor`,
`EnrichedFamilyDescriptor`, `EnrichedTraceDescriptor`,
`EnrichedMetricDescriptor`, `ResolvedMandatoryProgramIR`, parsed
`SpanNamePartIR`, expanded producer-row descriptors, and the complete
`GoAPIPlanIR`; these are candidate-index output, not duplicate registry source.

Before any candidate renderer runs, exactly one `CandidateRenderIndex` is derived
from that view. It contains:

- one `EnrichedFieldDescriptor` for every resolved scalar family/resource/scope/
  event/link use and every expanded structured concrete scalar leaf, joining
  canonical upstream ownership, primitive type, effective and per-use constraints,
  requirement/condition, class, sensitivity, cardinality, lifecycle, derivation
  source, input placement, exact Go selector/type/conversion when public, origin,
  and exact payload-rooted leaf path;
- one `EnrichedContainerDescriptor` for every object, array, tagged-union variant,
  and structured-reference edge, retaining closed shape, bounds, requirement,
  lifecycle, origin, and child links but carrying no field class, sensitivity, or
  scalar normalization;
- exact active/historical family identities, outcomes, dynamic mandatory rules,
  parsed span name parts/kinds/events/links, metric instruments, expanded producer
  identity rows with selected-family mandatory programs, semantic profiles,
  conditions, value catalogs, Go symbols, and the exact Go API/file plans;
- the four exact upstream structural-input paths, pinned commit, SHA-256 digests,
  and complete property-disposition table; exactly four structured bindings; and
  every fixed/dynamic member, dynamic-variant exclusion, canonical-JSON recursion
  bound and exact counting rule, union-owned discriminator, effective reserved-name
  set, stable member/arm ID, every structured type/member/arm Go symbol, and the
  ordered-member input/constructor Go symbols;
- normalized examples with explicit/inherited builder contexts; and
- the complete P-069 structural objects, relations, derivations, and OTLP
  representation.

The index is recursively immutable, complete, sorted only where the source
declares set semantics, and has a separate domain-separated digest that includes
and binds the materialized-view digest. Bundle, catalog, Markdown, normalized examples, OTLP fixtures, Go IDs,
catalog, producer maps, builders, and fixture tests receive this same index
instance. A renderer may not read registry YAML, current public schemas, current
handwritten Go registries, prior generated bytes, or recompute inheritance,
ownership, constraint intersection, value sources, parsed span names, public
selectors/signatures, file ownership, symbol names, or structured bindings.

The compiler validates each example ID against `^[a-z][a-z0-9-]{0,127}$` and
materializes canonical repository-relative POSIX output-path facts in the index.
Before rendering a payload or returning any bytes to the repository writer, the
renderer coordinator preflights the complete output set. Normalized-example and
OTLP-fixture paths are direct children of their declared generated directories and
are derived only from the validated ID. Every output remains beneath the generated
root. Absolute paths, empty/`.`/`..` segments, backslashes, NUL, doubled or trailing
separators, traversal, nested example IDs, and platform-reserved path syntax fail.
Candidate IDs and paths are unique both byte-for-byte and after NFC case folding.
The coordinator rejects all collisions before invoking a renderer; the direct
writer repeats containment, symlink, exact-inventory, and collision checks as
defense in depth.

##### Generated kernel and seven-file acceptance

Generated public family inputs expose only typed producer data. Required fields
are plain values; recommended/optional fields use `Optional[T]`. A conditional
field governed by `builder_fact` uses an optional typed value plus the exact
builder fact. A conditional field governed by `boolean_attribute` instead exposes
the source Boolean as a required typed field and the governed value as optional;
the generated wrapper derives the private condition directly from that Boolean
and exposes no independent condition selector that could disagree. Resource, scope,
event, and link helpers bind private catalog contracts. Bucket, signal, event or
family identity, family/registry version, span name, instrument metadata,
field-class maps, mandatory/floor state, and derivation values remain private.
Every wrapper terminates at the existing private `buildGeneratedLog`,
`buildGeneratedTrace`, or `buildGeneratedMetric` kernel. Compatibility-only
`legacy.audit.*` identities and removed families have no builder.

The Go candidate output set is exactly these seven files:

```text
internal/observability/zz_generated_telemetry_ids.go
internal/observability/zz_generated_telemetry_catalog.go
internal/observability/zz_generated_telemetry_producers.go
internal/observability/zz_generated_telemetry_builders_genai.go
internal/observability/zz_generated_telemetry_builders_security.go
internal/observability/zz_generated_telemetry_builders_operations.go
internal/observability/zz_generated_telemetry_builder_fixtures_test.go
```

The compiler validates all seven as one in-memory candidate. A strict subset,
extra generated Go path, handwritten marker, stale digest, symbol-table
disagreement, missing family entrypoint, or builder for a
compatibility-only/removed identity fails before candidate acceptance. This
all-or-none guarantee applies to the validated candidate and final committed
checked-in state, not to transient filesystem visibility while the seven files
are installed independently. `scripts/generate_telemetry_registry.py --write`
therefore expects no concurrent mutation of its explicit output paths. An
interrupted write may expose a partial generated set, but the next `--write`
deterministically repairs it and `--check` rejects every missing, stale,
wrong-mode, or extra owned output. No runtime process reads these repository
files during generation.

The static API gate derives the exact `FamilyBuilder` method/input contract from
the generated family descriptors, then validates both generated source and the
compiled method set. It still rejects a missing or extra family method, a generic
`Build`, map/`any` input, caller-controlled catalog state, or direct
schema-derived-constructor call outside `family_builder.go`; no duplicate JSON
method inventory is embedded in a generated test.

##### Current implementation state

The former candidate-generation blockers are resolved: derived bindings, constant
scope identity, enriched descriptors, the independent candidate digest,
`GoAPIPlanIR`, generated component-scoped condition facts, resolved mandatory
programs, direct publication, and runtime-schema generation are checked-in
authority. The active additive epoch extends that same pipeline with canonical
trace state/full flags and the sealed `resource.core` custom-member/alias contract.
Production activation still depends on the generated two-span canary,
runtime-generation lease E2E, complete producer migration, and destination
projection gates tracked by `spec.md`; renderers MUST NOT substitute handwritten
state for any of those remaining inputs.
5. The exact seven generated Go outputs exist and are validated as one candidate,
   then written through the explicit direct-output list. Desired strict subsets
   and unowned generated paths remain invalid.
6. The twenty-one retained v7 public schema paths and applicable mirrors/embeds
   remain fixed-path compatibility/reference views with Draft 2020-12, fixture,
   semantic, producer-parity, and byte-parity checks. They are not v8 authoring
   inputs and cannot override registry authority. Producer call sites, Galileo,
   and local-observability consumers retain their explicit downstream parity and
   activation gates.

### 5.3 Canonical families and producer mappings

Canonical log families and current producer identities are different registry
concepts. The fourteen gateway event types and 188 audit actions are producer
mappings; they are not 202 additional log-family definitions. Each mapping records
its typed producer key, source, event-name policy, default identity or closed set of
allowed contextual identities, severity policy, mandatory-floor rules, companion
rules, and compatibility lifecycle. It references registered log identities and
MUST NOT define a body schema, override a referenced family's bucket, or create an
implicit family.

For mandatory-floor purposes, a mapping's `mandatory_rules` field is frozen
pre-cutover compatibility metadata only. After contextual identity selection, the
generated producer row evaluates only the selected canonical family's
`ResolvedMandatoryProgramIR` against the typed broad transition carrier.
Compatibility-only default identities carry no canonical floor and cannot be
selected by a v8 generated family builder. This distinction lets a generic
lifecycle producer select `authentication.failed` and correctly apply its
protected-boundary floor without also making every lifecycle event mandatory.

To keep this exact mapping inventory reviewable, a repeated closed contextual set
is declared once as a named producer-identity set and mappings reference exactly
one set. The compiler expands references only in its bounded validation input,
then emits a compact runtime index containing one exact identity table, one copy
of each contextual set, and one default/set reference per producer. The expanded
producer-by-set Cartesian product is never a checked-in generated artifact or a
second runtime authority. Sets cannot include other sets, use wildcard
members, inherit, union, or supply a fallback. Empty, duplicate, unknown, unused,
or policy-incompatible sets are errors, so factoring cannot broaden a producer's
allowed identities.

The canonical log-identity inventory is derived from the authored families and
producer compatibility mappings. It includes `guardrail.judge.completed`,
whose existing fixed `judge` producer mapping and distinct judge payload require a
canonical guardrail log family rather than an alias to
`guardrail.evaluation.completed`. Producer-derived contextual identities and
compatibility-window `legacy.audit.*` identities are registered through producer
mappings rather than copied into another family list. A `legacy.audit.*` identity
is explicitly compatibility-only and has no generated family builder. The compiler
fails if the current source inventories differ from the mappings, if a mapping can
resolve to an unregistered identity, or
if a non-legacy resolved identity's bucket conflicts with its canonical family.
Generated route/classification registries consume these mappings directly.

### 5.4 Metric labels and compatibility projections

For a metric family, its inherited `attributes` are its complete canonical label
schema. The metric block adds `empty_labels_reason` if and only if the resolved set
is empty; an unexplained empty set is invalid. During the v7-to-v8 cutover, the
machine-derived current-state inventory records the exact labels observed at every
real `Add`/`Record` callsite and the reason for each genuinely label-free
instrument. The compiler requires equality for every inventoried family. After callsites
use generated per-family APIs, those APIs and real-producer conformance replace the
temporary bootstrap extractor; Go does not remain a second authoring source.

Canonical labels use pinned standard names or the `defenseclaw.*` namespace.
Current unqualified, deprecated, or otherwise compatibility-only names are emitted
through a family-local projection:

```yaml
metric:
  # instrument_name/type/value_type/unit/description/temporality/boundaries omitted
  label_projections:
    - profile: local-observability-v1
      mappings:
        - ref: http.request.method
          label: http.method
```

There is at most one entry per profile. Every mapping source is a resolved
canonical label and appears once; projected names are unique. An omitted canonical
label projects unchanged. The projected set, not the canonical set, must equal the
frozen v7/local-observability inventory. This preserves current Prometheus queries
without making deprecated `http.method`, nonstandard `gen_ai.agent.type`, or an
ambiguous unqualified `state` canonical. Alias collisions, unknown profiles, and
unqualified custom canonical attributes fail.

Ordinary metric families reject high-cardinality labels and content, credential,
path, reason, evidence, and error classes. The only application-metric exceptions
are the exact six Agent360 native families and the two pinned GenAI client families
listed by `local-observability-v1`, with their exact label sets. Each remains under
the current 2,048-tuple application-family cardinality limit. Separately, the
derived Agent360 spanmetrics projection retains its existing Collector limits:
10,000 dimension-cache entries, 1,000 resource-metrics-cache entries, and 24-hour
series expiration. Neither exception has a wildcard, set composition, or effect on
unlisted OTLP metric schemas.

The registry metric default is `cardinality_limit: 2048`, enforced on each
ordinary family's distinct canonical label tuple before export. A non-Agent360
string label uses `enum-v1`, or uses `bounded-v1`/`identifier-v1` with an effective
`max_utf8_bytes` bound and the family tuple cap; a `low`/`bounded` declaration or
human note alone is insufficient. Known status, type, severity, code, and subsystem
vocabularies use closed enums. The eight exact compatibility families above retain
the same 2,048 application limit and do not raise it globally.

## 6. Generated Public Artifacts

### 6.1 One bundle for most consumers

`telemetry.schema.json` is the recommended public artifact. It contains:

- A top-level discriminated union by signal and family.
- Reusable `$defs` for resources, envelopes, attributes, content state, events,
  links, metrics, and domain bodies.
- Stable `$id` and version.
- No copied definitions with divergent meaning.

Transport envelopes such as gateway JSONL and CLI scan export either become
generated views or reference generated canonical body `$defs`. Transport-only
fields remain with the transport envelope; domain fields are not re-authored.

External consumers can validate one bundle and select a `$defs` pointer. They do
not need to discover which of many similarly named files applies.

The candidate bundle is acceptable only when its top-level union and every family
definition are generated from the same materialized structural/domain IR as the
builders. All curated valid examples must pass both, and every single-fault invalid
example must fail both with the declared code. A candidate that merely renders
attribute skeletons, lacks the exact envelope/correlation/provenance or signal
arms, permits unknown members, omits structural privacy, conditions, lifecycle,
phase/code, or OTLP mapping metadata, or accepts a builder-rejected shape is not a
complete `telemetry.schema.json` and cannot become public authority.

Before any renderer runs, the compiler converts the fully validated `RegistryIR`
into one recursively immutable `MaterializedRegistryView`. Dataclass identity and
every field are retained, mappings are key-sorted immutable mappings, and ordered
tuples retain their validated semantic order. Only tuple fields explicitly declared
set-valued by exact IR type and field name, plus intrinsically unordered frozen
sets, are canonically ordered; shape-based inference is forbidden. Immutable byte
facts remain bytes in the view and use a deterministic hex-encoded `bytes` type tag
for digesting, distinct from strings and numeric types. No mutable source dictionary
or list crosses this boundary. One domain-separated typed-canonical-JSON SHA-256
covers the complete view, including structural fields, resolved families, producer
mappings, examples, lifecycle/privacy metadata, and OTLP placement. The current
generated Go headers and runtime artifact markers record the relevant source
digests; no separate ownership manifest duplicates the output inventory.

For candidate generation, the compiler then derives the P-070
`CandidateRenderIndex` exactly once from that view. Every generated public artifact
and fixture consumes the same enriched descriptors, rule results, structured
bindings, symbol table, and builder contexts; no output-specific join or source
fallback is permitted.

### 6.2 Compact catalog

`catalog.json` is designed for SDKs, setup tools, UI, and downstream mapping. For
each family it exposes:

- Signal, bucket, stable family ID, name pattern, and kind.
- Required/conditional/optional attributes.
- Type, stability, owner, field class, sensitivity, and cardinality.
- Allowed events/links.
- Compatibility-profile identifiers and links to their generated manifests.
- Introduced/deprecated/removed versions.

The portable catalog MUST NOT contain dashboard consumers, datasource or dashboard
UIDs, normalized Prometheus names/labels/buckets, Loki/Tempo query fields, or
dashboard-query aliases. Those consumer-specific mappings live only in the
logical generated artifact
`compatibility/local-observability-v1.json` (stored in Git as
`schemas/telemetry/runtime/compatibility/local-observability-v1.json.gz`).

The compiler renders the bundle, catalog, and compatibility manifests as raw
canonical JSON in memory. Git stores the six large reproducible runtime artifacts
as deterministic gzip members under `schemas/telemetry/runtime/`. Go decompresses
each embedded member once and returns copy-safe exact raw bytes; Python wheel
staging restores the same six raw `.json` resource names. Compression changes
review storage only, not any runtime, wire, package, or schema API.

### 6.3 Human reference

`catalog.md` provides:

- One-page namespace decision.
- Trace-tree examples.
- Per-family required and useful fields.
- Redaction classification.
- Backend compatibility matrix.
- Query examples using standard fields first and DefenseClaw overlay second.

It is generated from the same registry, so documentation cannot silently drift.

### 6.4 Per-family files only when required

Some integrations or installed binaries may require a new v8 standalone schema.
Such new files are generated views of the bundle, never separately authored
contracts. A small generated standalone set is acceptable for:

- Runtime embedding where a whole bundle is too expensive.
- A CLI `--schema` command.
- A vendor conformance harness.
- A downstream system that cannot resolve `$ref` into the bundle.

`compatibility/local-observability-v1.json` is generated because it is a consumer
manifest rather than a canonical family schema. It is the only generated registry
artifact that binds registry fields to the exact metric normalization, bounded
labels, histogram buckets, Loki JSON fields, Tempo attributes,
datasource/dashboard UIDs, and aliases consumed by the bundled dashboards. The
portable catalog may link to this manifest by compatibility-profile ID but does not
copy its mappings. The dashboard checker parses every query and fails when its
dependency is absent from this manifest.

`compatibility/v7-exporter-selection.json` is the migration counterpart. For every
current v7 log, trace, metric, audit action, gateway JSONL/console event, OTel span
filter operation, and destination-specific emission path, it records the canonical
v8 signal, bucket, source, event/family/instrument identity, eligibility, and
`legacy-v7` projection disposition. The converter consumes this generated artifact
and MUST NOT contain a hand-maintained duplicate family list. It is versioned with
the registry, deterministic, secret-free, and fails generation when a current
producer/exporter has no unambiguous disposition.

`compatibility/inbound-otlp.json` is the accepted-record counterpart. It contains
the exact signal/source discriminators, target families, typed field mappings,
timestamp/outcome rules, unknown-field disposition, reverse-mapping eligibility,
and import-versus-derivation mode from 15 section 2. Authored classes are expanded
to one exact artifact entry per eligible target; runtime wildcard target selection
is forbidden. The receiver consumes the generated Go form of the same materialized
data, including target-specific self-echo recognizers and private import-only log
contexts that reuse family validation/classes but cannot set mandatory/floor state.
The compiler rejects missing/duplicate/overlapping expansion, a target not owned by
the registry, an unclassified mapped leaf, a non-reversible
`native_round_trip` claim, a heuristic name predicate, or a mapping that could
supply identity/floor/classification authority from an inbound value.

### 6.5 Retained public compatibility schemas and embed APIs

The existing telemetry paths under `schemas/` and `schemas/otel/` are retained
v7 compatibility/reference contracts, not canonical v8 authoring sources. Their
fixed public paths remain subject to Draft 2020-12, local-reference, fixture,
semantic, producer-parity, and mirror/embed checks where applicable. New v8
standalone public schemas are generated views of the canonical bundle rather
than separately authored family contracts.

The compiler owns the v8 bundle, catalog, compatibility profiles, deterministic
runtime gzip members, and generated Go runtime declarations. `schemas/embed.go`
retains copy-safe configuration, registry, dependency-lock, bundle, catalog, and
compatibility-profile accessors. Gateway and CLI copies needed by retained v7
interfaces remain byte-identical mirrors checked by `check_schemas.py`; their
continued enforcement does not give them authority over v8 families.

## 7. Standard Base Plus DefenseClaw Overlay

### 7.1 Agent/model/tool/retrieval

These families use OTel GenAI names and meanings as their portable primary fields.
Examples:

- `gen_ai.operation.name`
- `gen_ai.provider.name`
- `gen_ai.agent.*`
- `gen_ai.conversation.id`
- `gen_ai.request.*`
- `gen_ai.response.*`
- `gen_ai.usage.*`
- `gen_ai.tool.*`
- `gen_ai.input.messages`
- `gen_ai.output.messages`

DefenseClaw adds only what the standard does not represent, such as bucket, policy,
guardrail, enforcement, connector lifecycle, config generation, and redaction
state.

### 7.2 Guardrail/enforcement/finding

These are DefenseClaw domain families because no stable GenAI convention fully
defines them. They still reuse standard status, error, resource, HTTP/RPC, and GenAI
model-call groups where applicable.

An LLM judge therefore composes:

```text
standard model chat span
+ DefenseClaw guardrail evaluation correlation
+ route-specific content projection
```

It is not a proprietary “judge span” that loses model observability, nor is the
whole guardrail decision incorrectly forced into a model attribute.

### 7.3 OpenInference

OpenInference fields remain useful for Galileo and other AI-observability tools, but
they are a generated compatibility view:

- `openinference.span.kind` is derived from the canonical family.
- `input.value` and `output.value` derive from the same redacted canonical content
  as GenAI messages.
- Alias equality and redaction parity are tested.
- The generated profile owns family eligibility, OpenInference kind, allowed span
  kinds, canonical input/output source fields, and MIME values. The runtime keeps
  no second family list and rejects profile/catalog/runtime capability drift.
- General OTLP applies this destination-private view only to eligible families.
  Unsupported families retain canonical OTel/GenAI output without compatibility
  aliases; malformed eligible projections fail closed rather than falling back to
  raw or pre-redaction values.
- Consumers are directed to the OTel GenAI fields for portable new integrations.

## 8. Required Registry Metadata

Every attribute definition includes:

| Metadata | Purpose |
|---|---|
| `type` | Wire type; no implicit stringification |
| `brief` and `examples` | Human understanding |
| `requirement_level` | Required, conditional, recommended, optional |
| `stability` | Development, stable, deprecated |
| `owner` | OTel, OTel GenAI, OpenInference compatibility, or DefenseClaw |
| `field_class` | Metadata, identifier, content, reason, evidence, error, path, credential |
| `sensitivity` | Safe, internal, sensitive, critical |
| `cardinality` | Low, bounded, high; metrics reject high-cardinality dimensions |
| `normalization` | Versioned normalizer plus typed effective constraints; prose notes are non-semantic |
| `introduced_in` | First schema version |
| `deprecated_in` / `removed_in` | Lifecycle when applicable |
| `alias_of` | Canonical source for compatibility aliases |

Missing field-class or sensitivity metadata is a compiler error for dynamic strings
and structured content.

Pinned upstream definitions receive a DefenseClaw `attribute_extensions` entry
whenever a canonical family references them. An extension supplies exactly
`field_class`, `sensitivity`, `cardinality`, and `normalization`; it cannot override
the upstream name, type, owner, or stability. Every referenced upstream attribute
has exactly one extension, and unknown, duplicate, missing, or unreferenced
extensions fail. This is how standard fields such as `gen_ai.input.messages` enter
the same centralized redaction and metric-cardinality policy as DefenseClaw fields.

The registry root owns the closed versioned normalizer catalog. Each entry has
`id`, `kind`, `default_constraints`, and `allowed_overrides`; v1 contains exactly
`identity-v1`, `bounded-v1`, `enum-v1`, `identifier-v1`,
`numeric-range-v1`, `structured-content-v1`, `redacted-content-v1`, `path-v1`,
`url-v1`, and `digest-v1`. Attribute and extension use is exact:

```yaml
normalization:
  id: identifier-v1
  overrides:
    max_utf8_bytes: 128
  notes: Human explanation only; generated validators ignore this text.
```

Effective constraints are catalog defaults replaced only by named allowlisted
overrides; a null value cannot remove a bound. Supported constraint keys are
`enum`, portable-RE2 `pattern`, `min`, `max`, `min_items`, `max_items`,
`max_utf8_bytes`, `max_item_utf8_bytes`, `max_depth`, and `max_properties`.
Enums are nonempty unique typed JSON scalars. Because JSON Schema considers the
numeric values `1` and `1.0` equal, generated enum schemas carry an explicit typed
membership annotation and the builder/runtime typed-enum gate remains authoritative.
Numeric bounds are finite, type-correct, and ordered; `numeric-range-v1` has no
implicit range, so every numeric field states both bounds. Counts are integers,
minima are nonnegative, maxima are positive, and
item bounds are ordered. For a scalar string, `max_utf8_bytes` counts its raw UTF-8
bytes; for arrays, objects, and other structured values it counts canonical JSON
UTF-8 bytes for the complete value. `max_item_utf8_bytes` bounds each string element
or structured string leaf. Structured values always have byte, item, depth, and
property bounds. Regexes reject lookaround, backreferences, named groups, and other
constructs outside the shared
Go/Python/ECMAScript subset. The compiler rejects a normalizer incompatible with the
attribute type, so human prose can never be the only executable validation rule.

Constraint evaluation is shape-aware and has one meaning across generated
consumers. Base-normalizer and per-use constraints are conjunctive: minima tighten
upward, maxima tighten downward, and enums intersect. Repeated patterns are
idempotent only when byte-identical; a distinct second pattern is a nonrepresentable
intersection and compilation/rendering fails. For array-valued attributes,
`enum`, `pattern`, `min`, and `max` apply to every element; `min_items` applies to
the root collection and is invalid for scalar values. Values that may be either a
scalar or collection (`canonical_json`/unbound `any_value`) reject `min_items > 1`
until their root shape is statically bound. `pattern` means a portable RE2 full
match, never a substring search. The conservative shared subset
rejects possessive quantifiers, Unicode shorthand classes, Python Unicode escapes,
lookaround, backreferences, and named/inline constructs. Public JSON Schema emits a
start-anchored wrapper with a strict absolute-end assertion, plus the original
pattern and an explicit full-match enforcement annotation, while the builder/runtime
portable-RE2 gate remains authoritative. `max_items` counts every object entry and
array element in the complete recursive value, not only the root collection. A generated schema may
emit root `maxItems`/`maxProperties` as a safe subset, but it also marks the required
recursive aggregate runtime gate. `max_properties` likewise counts object entries
across the recursive value, and `max_depth` measures maximum container depth with
the root container at zero; root `maxProperties` and annotations do not replace
those runtime checks. Ordinary `max_utf8_bytes` and `max_item_utf8_bytes` are also
emitted as enforcement annotations: the builder/runtime gate measures canonical
UTF-8 bytes using the scalar-versus-structured rule above and every string leaf,
respectively. A general JSON Schema validator does not, by itself, satisfy these
runtime gates.

The candidate renderer treats the materialized view as a typed trust boundary. It
revalidates the exact v1 normalizer catalog, binds every normalization ID,
allowlisted override, and effective map to that catalog, and checks constraint keys,
types, finite values, ranges, shape compatibility, non-weakening, and portable
patterns. For every resolved use it recomputes traversal order, direct-reference
provenance, typed enum/bound intersections, dominant requiredness, and the unique
dominant conditional from the group DAG; the condition must name a registered
`ConditionIR`. Any mismatch in direct refs, origin closure/order, resolution order,
duplicate resolved-use views, or the resolved projection fails before rendering.

## 9. Schema and Configuration Are Separate

Operators do not choose arbitrary schemas in `config.yaml`. The producer family
selects the canonical contract. Config controls:

- Whether the bucket/signal is collected.
- Which destinations receive it.
- Route-specific redaction.
- Trace limits and the shipped semantic profile.
- Whether temporary documented compatibility aliases are emitted.

An administrator cannot define arbitrary new attributes, redefine standard types,
or upload a vendor schema through YAML. Custom producer/plugin schemas require a
separately reviewed extension namespace and registration process.

## 10. Version and Compatibility Model

### 10.1 Independent versions

The system tracks:

- Config schema version.
- Bucket catalog version.
- Telemetry registry version.
- Trace semantic-profile schema version (`trace_schema_version`).
- Individual family schema version (`family_schema_version`, emitted on spans as
  `defenseclaw.span.family_schema_version`).
- Upstream OTel general semantic-convention version.
- Upstream OTel GenAI profile version.
- OpenInference compatibility-profile version.
- Destination compatibility-profile version.

These are not collapsed into one `schema_version` integer. The canonical record
envelope retains `schema_version`, which versions the complete record shape.
Instrumentation-scope/schema metadata uses `trace_schema_version` for the composed
trace contract selected by the semantic profile. Each span independently carries
its family's `family_schema_version`. A family change does not by itself change the
envelope version, and an envelope change does not renumber unchanged span families;
a new composed trace profile may bind a new mix of family and dependency versions.
The effective view and record provenance identify all relevant versions without
forcing unrelated changes to bump every contract.

### 10.2 Change rules

| Change | Rule |
|---|---|
| Add optional safe attribute | Additive family change; regenerate fixtures/docs |
| Add required attribute | Breaking family version unless safely derivable for all producers |
| Rename standard attribute | Follow pinned upstream migration; compatibility alias and release note |
| Change type or meaning | Breaking family version |
| Add family | Additive registry change plus bucket/privacy/route review |
| Remove alias | Only at declared removal version with query migration |
| Change Galileo profile | Version profile; preview eligible-span diff |
| Change field class/sensitivity | Security-relevant breaking review even if wire name is unchanged |

### 10.3 Upstream updates

A dedicated command/report compares the pinned OTel/GenAI registry with a candidate
version and classifies added, changed, deprecated, and removed definitions. Updates
are deliberate pull requests, not dependency side effects. Refresh validates the
complete immutable upstream archive in memory, but the repository snapshot stores
only the exact attribute closure used by authored families and compatibility
profiles. Archive, extracted-tree, full-normalized-inventory, and selection
digests preserve reviewable provenance without checking in thousands of unused
definitions or magic global counts.

## 11. Simplified Developer Workflow

To add or change telemetry:

1. Choose an existing standard attribute before adding a DefenseClaw attribute.
2. Add or update one family/group in the appropriate focused domain file.
3. Assign bucket, field class, sensitivity, cardinality, and compatibility profiles.
4. Regenerate the bundle, catalog, docs, constants, and fixtures.
5. Update the producer using generated constants/builders.
6. Run emitted-record conformance tests and destination projections.
7. Review the generated semantic diff.

Developers do not manually synchronize a Go string, Python string, four JSON
schemas, a Galileo filter, and a Markdown table.

### 11.1 Compiler and repository command

`scripts/generate_telemetry_registry.py` is the sole registry compiler. It accepts
`--write` to materialize every output and `--check` to compile and validate every
output without requiring reproducible reports or test corpora to be checked in.
Check mode still byte-compares repository/runtime outputs: generated Go and the
deterministic compressed telemetry schema, catalog, and compatibility manifests.
Retained v7 public compatibility/reference schemas are validated by
`scripts/check_schemas.py`; they are not canonical v8 compiler inputs. The
compiler validates imports, lock digests,
semantic-profile tuples, aliases, lifecycle metadata, field classes, sensitivity,
bucket ownership, event selectors, and vendor projection requirements before
emitting anything.

The supported contributor workflow is:

```text
make telemetry-generate   # compile and publish the owned generated outputs
make telemetry-check      # compile in memory and compare owned outputs
```

`scripts/check_schemas.py` also invokes the compiler in `--check` mode, so the
existing `make check-schemas` and CI paths retain the same gate. Counts, file
partitions, descriptor totals, expanded-producer totals, and compiler-output
digests are derived facts, never hand-maintained acceptance constants.

## 12. Generated APIs and Builders

The registry compiler MUST generate:

- Go and Python constants for stable family/event/attribute IDs.
- Typed builder validation for required fields and correct value types.
- Field-class maps for destination redaction.
- Route/classification registry entries.
- Schema fixtures and documentation.
- Galileo/OpenInference projection validators.
- The local-observability consumer manifest and checker inputs for Prometheus,
  Loki, Tempo, datasource/dashboard identities, and query compatibility.

Generated builders do not hide domain decisions. Required/conditional fields remain
visible to the caller, and unavailable data stays unavailable rather than receiving
synthetic defaults.

The seven Go files in §5.2.3 have these non-overlapping contracts:

- `zz_generated_telemetry_ids.go` contains only `GoSymbolTableIR` rows whose
  `declaration_form` is `exported_const`. It uses only the exact ID namespaces
  `TelemetryAttribute`/`TelemetryFamily`/`TelemetryEvent`/`TelemetrySpanEvent`/
  `TelemetryLinkRelation`/`TelemetryInstrument`/`TelemetryCondition`/
  `TelemetryConditionFact`/`TelemetryPhase`/`TelemetryPhaseCode`/
  `TelemetrySemanticProfile`/`TelemetryStructuredMember` and never repeats raw
  normalization. In particular, the 21 `TelemetryStructured*` owning types and
  17 `TelemetryStructuredArm*` types are absent as constants.
- `zz_generated_telemetry_catalog.go` contains immutable private family, field,
  event, link, outcome, and instrument descriptors plus copy-safe candidate
  lookups. It does not wire the current public event-registry functions before
  cutover.
- `zz_generated_telemetry_producers.go` stores every identity once, every named
  identity set once, and each of the fourteen gateway plus 188 audit producers as
  a default/identity-set reference. It never materializes the producer-by-family
  Cartesian product; mappings cannot create a family or override its bucket.
- The three domain builder files contain one
  `Log<Name>Input`/`Span<Name>Input`/`Metric<Name>Input` and one matching
  `BuildLog<Name>`/`BuildSpan<Name>`/`BuildMetric<Name>` method on
  `*FamilyBuilder` for each active canonical family owned by that domain. Span
  events use `Span<FamilyName><EventName>EventInput` plus
  `NewSpan<FamilyName><EventName>Event`; links use
  `Span<FamilyName><RelationName>LinkInput` plus
  `NewSpan<FamilyName><RelationName>Link`. There is no generic builder entrypoint.
- `zz_generated_telemetry_builders_genai.go` declares the 21 sealed structured
  owning types and 17 sealed arm types exactly once as `exported_type` rows. Their
  source type IDs and registered/dynamic arm tags live only in private descriptors
  in `zz_generated_telemetry_catalog.go`; no second exported string declaration is
  generated. Structured inputs use sealed generated union arms and
  `<TypeName><MemberName>MemberInput` plus
  `New<TypeName><MemberName>Member` for ordered members. The discriminator for
  `gen_ai.canonical_json` remains private and non-wire. No generated structured
  type, member, arm, or constructor exposes `map`, `any`, `interface{}`, or raw
  `Value`.
- `zz_generated_telemetry_builder_fixtures_test.go` runs the normalized explicit
  builder contexts and compares exact canonical record bytes/classes and stable
  failures with the bundle and catalog. Compile-only coverage remains validated
  in the fixture IR; the catalog-derived static API gate proves every active
  descriptor/input/method relationship without emitting hundreds of dead test
  functions.

All exported input structs are closed under the static gate: no map, `any`, raw
`Value`, catalog identity, version, instrument metadata, field classes, or
mandatory/floor field may cross the public boundary. A generated method may call
only the matching private kernel entrypoint and cannot call the schema-derived
record constructor directly.

## 13. Migration From Current Schema Files

The current telemetry files are migration inputs:

- `resource.schema.json`
- `metrics.schema.json`
- Runtime agent, LLM, tool, and approval span schemas.
- Lifecycle, asset, scan, finding, alert, and connector event schemas.
- Galileo export profile.
- Gateway event envelope and its activity/scan/finding child schemas.
- Audit, hook-audit, and network-egress event schemas.
- CLI scan-result schema where it overlaps canonical scan/finding bodies.
- Merged PR #403 root/subagent lifecycle, runtime span, gateway envelope,
  hook-decision, metric, Collector spanmetrics, and missing-data contracts.
- Merged PR #412 dashboard queries, corrected metric/label/histogram contracts,
  datasource cadence, source/packaged parity, and static/live checker inventory.

Migration proceeds in stages:

1. Inventory and validate all twenty-one retained public v7
   compatibility/reference schemas, including identities, local references,
   runtime meanings, and applicable byte-identical mirrors.
2. Detect duplicate definitions and incompatible meanings for the same key.
3. Assign standard/DefenseClaw/compatibility ownership.
4. Extract common resource, correlation, content, error, lifecycle, and security
   groups.
5. Generate the canonical v8 bundle/catalog and prove its runtime projections
   preserve the reviewed compatibility obligations of the retained OTel and
   event contracts.
6. Add the rich v8 fields/families from `11-trace-and-span-contract.md`.
7. Switch conformance tests to the generated bundle/catalog.
8. Keep existing public per-family paths as retained v7 compatibility/reference
   views; enforce Draft 2020-12, `$id`/`$ref`, fixture, semantic, and
   mirror/embed parity in the schema gate. Generate any new standalone v8 view
   from the canonical bundle.
9. Generate `local-observability-v1`, prove all fourteen dashboards and rules are
   covered, and keep aliases/dual emission until every current and historical query
   fixture has migrated.
10. Generate the v7 exporter/family compatibility selection, prove every current
    producer/action/signal/export path has one migration disposition, and make the
    converter fail when the generated artifact lacks an exact mapping.

No current schema is deleted merely because the registry exists. The release gate
requires a machine-generated inventory showing every old field as preserved,
renamed with alias, intentionally removed, or corrected with a breaking note.

## 14. Validation Layers

The architecture retains distinct enforcement levels:

- **Builder/runtime validation:** required type/shape/size checks before canonical
  record acceptance, without running a general JSON Schema interpreter on every hot
  span mutation.
- **Destination projection validation:** redaction, capability, and vendor-shape
  checks before export.
- **CI emitted-record conformance:** real Go/Python producers emit records compared
  with the registry/generated schema.
- **Public JSON Schema:** downstream and offline validation.
- **Annotated runtime-only constraints:** recursive aggregate item counts,
  recursive property counts, root-zero container depth, shape-aware UTF-8 byte
  budgets, per-string-leaf UTF-8 byte budgets, typed JSON enum membership, and
  portable full-match regex semantics remain named builder/runtime gates even when
  the public schema also emits a safe structural subset.
- **Golden semantic diff:** release review of schema changes.

## 15. Galileo as a Projection, Not a Schema Fork

`compatibility/galileo-rich-v2.json` is generated from:

- Galileo’s supported agent, LLM, tool, retriever, and workflow shapes.
- The canonical OTel GenAI groups.
- Required OpenInference aliases.
- DefenseClaw’s safe overlay allowlist.
- Destination-specific headers/resource projection and error requirements.

It answers “can this already-redacted span be ingested usefully by Galileo?” It does
not redefine the canonical family. General OTLP destinations continue to receive
native guardrail, scan, enforcement, network, platform, and compliance spans.

## 16. Generated Discoverability

The v8 release requires generated catalog and reference documentation. The
following interactive schema/explain commands are explicitly deferred follow-up
surfaces rather than blockers for the core configuration and registry migration:

```text
defenseclaw observability schema list
defenseclaw observability schema show span.model.chat
defenseclaw observability schema show --attribute gen_ai.request.model
defenseclaw observability schema compatibility span.model.chat galileo
defenseclaw observability schema diff --from REGISTRY_VERSION --to REGISTRY_VERSION
defenseclaw observability explain-event --family span.model.chat
```

Output shows portable standard fields first, then the DefenseClaw overlay,
redaction classes, examples, compatibility, and version provenance. It never prints
live content or secret values.

## 17. Acceptance Criteria

- One logical registry with the fixed manifest/GenAI/security/operations authoring
  set is the canonical telemetry source.
- Every current schema field appears in the migration inventory.
- Generated bundle, catalog, docs, constants, fixtures, and projections are
  deterministic and drift-free.
- Agent/model/tool/retrieval consumers can operate using standard fields without
  DefenseClaw-specific parsing.
- Security/policy consumers get the full DefenseClaw overlay without overloaded
  standard keys.
- OpenInference and Galileo aliases are provably derived from the same redacted
  canonical values.
- Go and Python producers pass the same generated conformance fixtures.
- Upstream semantic-convention changes cannot enter without a pinned-version diff.
- A new family normally changes one registry entry and producer code, not many
  hand-maintained schemas.
- Human documentation clearly distinguishes canonical, compatibility, required,
  optional, sensitive, and deprecated fields.
- P-070's exact mandatory-rule catalog, structured types/bindings, Go symbol
  policy/table, and explicit valid/inherited example builder contexts compile with
  P-069 into one complete immutable `CandidateRenderIndex`; every candidate
  renderer consumes that index without inference or fallback.
- The generated builder surface contains only symbol-table-allowlisted typed
  methods and private-kernel calls. Compatibility-only/removed identities have no
  builder, and public inputs expose no map/`any`, raw `Value`, identity, version,
  field-class, instrument, or mandatory/floor authority.
- The exact seven generated Go files in §5.2.3 are validated and accepted as one
  candidate set or none, and the final committed checked-in state contains the
  complete set. Publication uses an explicit output inventory and atomic
  per-file replacement; `--check` rejects partial, stale, wrong-mode, or extra
  outputs, and rerunning `--write` repairs interruption without a durable
  transaction subsystem.
- Every PR #403 lifecycle identity/event/state/phase, operation boundary,
  connector-facing decision, missing-data flag, and Agent360 dimension has an
  explicit registry disposition.
- Every PR #412 metric name/label/histogram/cadence correction is represented by
  `local-observability-v1`; all fourteen source dashboards match their packaged
  copies and pass static plus live query validation.
- The generated v7 exporter-selection artifact covers every current producer,
  action, signal, span-filter operation, and destination eligibility rule; the
  migration converter consumes it without a duplicate hand-authored family list.
- The generated inbound-OTLP artifact and Go normalizer cover every identity in 15
  section 2.2, have mutually exclusive exact discriminators, and pass 15 section
  10 without a hand-coded fallback, raw body path, or sender-controlled bucket,
  floor, field class, route, or redaction decision.
