# Rich Trace and Span Contract

## 1. Purpose

This contract defines the v8 trace graph, span families, attributes, events, links,
redaction boundary, Galileo projection, limits, versioning, and verification. Its
goal is the richest useful telemetry that DefenseClaw can produce without turning
traces into an unbounded content archive or a second, inconsistent audit stream.

“Rich” means:

- Preserve every currently useful Galileo, OpenTelemetry GenAI, OpenInference, and
  DefenseClaw correlation field.
- Add complete security-decision, lifecycle, timing, retry, error, provenance,
  enforcement, retrieval, and workflow context when the producer knows it.
- Represent missing data honestly rather than inventing zeroes or content.
- Keep values bounded, typed, redacted, and independently projected per
  destination.
- Keep the full graph available to general OTLP destinations even when a vendor
  accepts only a compatible subset.

## 2. Standards and Versioning Position

DefenseClaw follows, in priority order:

1. Stable OpenTelemetry semantic conventions for resources, HTTP, RPC, errors,
   exceptions, and network operations.
2. A build-time-pinned OpenTelemetry GenAI semantic-convention profile.
3. OpenInference compatibility attributes required by supported GenAI backends.
4. The `defenseclaw.*` namespace for security, policy, connector, lifecycle, and
   provenance facts not covered by a stable standard.

The GenAI conventions are still evolving. DefenseClaw MUST NOT silently change
span names, kinds, attribute names, types, or event shapes merely because a library
dependency updates. The `defenseclaw-genai-rich-v1` profile is locked to exactly
these four literal identifiers:

| Profile member | Literal identifier |
|---|---|
| `trace_schema_version` | `defenseclaw-trace-v1` |
| `gen_ai_semconv_profile` | `otel-genai-b028dceecdad117461a785c3af35315e7184e813` |
| `openinference_profile` | `openinference-semantic-conventions-v0.1.30` |
| `galileo_compatibility_profile` | `galileo-rich-v2` |

The GenAI identifier is an immutable commit because the authoritative dedicated
OpenTelemetry GenAI repository has not published a release tag for that snapshot.
`semconv.lock.yaml` additionally pins its OTel core dependency to
`v1.42.0`/`ae3a98640194ed405c4c797281502e4d3bd258b3` and pins the OpenInference
release tag to commit `789d41974c08a9a13147977f28ef4142a07e2106`.
Each dependency entry also names its upstream repository, immutable revision,
normalized vendored-snapshot path, normalization format, and SHA-256 digest.
Normal builds are offline: they validate the snapshot digest before resolving
any standard field. A normalized snapshot records every referenced upstream
field's name, type, stability, enum/deprecation metadata, and original source
pointer. Refreshing one is an explicit reviewed convention-update operation;
ordinary builds never fetch mutable upstream definitions.

The values are emitted in instrumentation-scope/schema metadata and visible in the
effective configuration, doctor output, and upgrade migration summary. A convention upgrade
requires schema fixtures, compatibility aliases where promised, release notes, and
before/after golden traces.

Normative external references:

- OpenTelemetry semantic conventions: <https://opentelemetry.io/docs/specs/semconv/>
- Pinned OpenTelemetry core semantic-conventions release:
  <https://github.com/open-telemetry/semantic-conventions/releases/tag/v1.42.0>
- Pinned OpenTelemetry GenAI registry revision:
  <https://github.com/open-telemetry/semantic-conventions-genai/tree/b028dceecdad117461a785c3af35315e7184e813>
- Pinned OpenInference semantic-conventions release:
  <https://github.com/Arize-ai/openinference/releases/tag/python-openinference-semantic-conventions-v0.1.30>
- OpenTelemetry trace conventions:
  <https://opentelemetry.io/docs/specs/semconv/general/trace/>
- Galileo OTel/OpenInference recommendations:
  <https://docs.galileo.ai/sdk-api/third-party-integrations/opentelemetry-and-openinference/integration-recommendations>
- Galileo custom spans:
  <https://docs.galileo.ai/sdk-api/third-party-integrations/opentelemetry-and-openinference/start-galileo-span>

## 3. Current Galileo Baseline That v8 Must Preserve

The v7 implementation already provides substantial functionality. The migration
MUST preserve the following semantics before adding new span families.

The baseline includes merged PR #403, commit
`9e417889c4c456bc3c7e6c160ee98c1add1094ee`. Its root/subagent identity,
lifecycle/execution semantics, real-time operation completion, explicit
connector-facing decisions, Agent360 dimensions, and missing-data behavior are
normative even when the v8 registry changes their internal construction. The full
consumer contract is `14-agent-lifecycle-and-dashboard-compatibility.md`.

| Capability | Current contract to preserve |
|---|---|
| Transport | Traces-only OTLP HTTP/protobuf destination with Cloud or self-hosted endpoint |
| Routing headers | API-key secret reference plus project and log-stream routing |
| Timeliness | Bounded asynchronous export; the v7 global/default scheduled delay is 5,000 ms |
| Supported operations | `chat`, `invoke_agent`, and `execute_tool` |
| Standard fields | `gen_ai.operation.name`, provider, request/response model, conversation, input/output messages, token usage, finish reasons, tool name/call/arguments/result |
| OpenInference fields | `openinference.span.kind`, `input.value`, `input.mime_type`, `output.value`, and `output.mime_type` where applicable |
| DefenseClaw overlay | Run, agent, root/parent, session, lifecycle, execution, phase, sequence, operation, connector, tool, policy, and deployment identifiers when known |
| Missing-data fidelity | Input/output/token `reported` indicators distinguish absent telemetry from reported zero/empty values |
| Privacy | Persistent-sink-safe content projection rather than an ungoverned raw producer copy |
| Trace shape | Short per-operation or per-hook-delivery traces correlated into longer sessions through stable IDs; no hours-long open session span |
| Filtering | Schema-pinned Galileo eligibility filter that does not alter other OTLP destinations |
| Delivery evidence | Observed/eligible/attempted/delivered/rejected/failed counters, partial-success handling, health, and exact-trace canary acknowledgement |

Migration is semantic, not byte-for-byte. Legacy duplicate content aliases may be
retained for a documented compatibility window, but they MUST be derived from the
same destination-projected value as the canonical field and can never bypass the
selected profile.

## 4. Trace Boundary and Topology

### 4.1 Bounded traces

A trace represents one bounded operation, normally one inbound request, agent turn,
hook delivery, model invocation, tool invocation, scan, or administrative action.
It MUST NOT remain open for an entire multi-hour agent session.

Long-lived continuity uses stable identifiers:

- `gen_ai.conversation.id`
- `defenseclaw.agent.root.id`
- `defenseclaw.agent.parent.id`
- `defenseclaw.session.root.id`
- `defenseclaw.session.parent.id`
- `defenseclaw.agent.lifecycle.id`
- `defenseclaw.agent.execution.id`
- `defenseclaw.operation.id`
- `defenseclaw.run.id`

### 4.2 Preferred agent-turn graph

```text
invoke_agent <agent>                         [agent.lifecycle]
├── apply_guardrail <name> input             [guardrail.evaluation]
│   ├── guardrail.regex
│   ├── guardrail.ai_defense
│   ├── chat <judge-model>                    [guardrail judge model call]
│   ├── guardrail.policy
│   └── guardrail.finalize
├── chat <model>                              [model.io]
│   ├── apply_guardrail <name> output
│   └── model/tool-call events
├── execute_tool <tool>                       [tool.activity]
│   ├── apply_guardrail <name> tool
│   ├── exec.approval                         [enforcement.action]
│   ├── HTTP/RPC client attempt               [network.egress]
│   └── enforcement <action>                  [enforcement.action]
└── agent lifecycle/phase events
```

Not every connector exposes enough timing or parent context for this exact tree.
When parenthood is known, use a parent-child edge. When work is asynchronous,
reconstructed later, or caused by several inputs, use span links with typed
correlation attributes rather than inventing a false parent.

### 4.3 Hook and streaming behavior

- Each hook delivery has a short bounded `invoke_agent` anchor. A pre-operation
  hook starts or records the operation timestamp.
- A matching post-operation hook completes the span using the original timestamp
  and exports it as soon as terminal evidence is known.
- Duplicate terminal hooks do not create duplicate completed spans.
- Streaming model spans record first-byte/first-token timing when available and end
  only at terminal response, cancellation, or failure.
- Start, completion, compaction, resume, subagent, and terminal hooks remain visible
  during long turns; export does not wait for the agent process to exit.
- A connector `Stop` hook MAY be a model-completion fallback, but `Stop` or session
  end is never a prerequisite for exporting a completed turn, model call, tool call,
  approval, decision, or transition.
- Correlation caches are bounded, expiring, and observable when an unmatched start
  or completion is evicted.

## 5. Universal Span Contract

### 5.1 Required structural fields

Every recording span has:

| Field | Requirement |
|---|---|
| Trace ID and span ID | Valid OTel identifiers |
| Parent span ID or links | Present when a real relationship is known |
| Name | Stable low-cardinality pattern from the span-family registry |
| Kind | Correct `INTERNAL`, `SERVER`, `CLIENT`, `PRODUCER`, or `CONSUMER` semantics |
| Start/end timestamp | Producer-observed timestamps; end is mandatory for export |
| Status | Follows section 11; not used as the only security-decision field |
| Resource | Required resource schema from section 6 |
| Instrumentation scope | Name, binary version, trace-schema version, and schema URL/profile |

### 5.2 Required DefenseClaw attributes

Every DefenseClaw-authored span carries:

| Attribute | Meaning |
|---|---|
| `defenseclaw.bucket` | Exactly one primary v8 bucket |
| `defenseclaw.span.family` | Stable family ID, independent of display span name |
| `defenseclaw.span.family_schema_version` | Version of this registered span family; distinct from the canonical record `schema_version` |
| `defenseclaw.source` | Producer identity |
| `defenseclaw.connector.source` | Connector when known |
| `defenseclaw.config.generation` | Effective immutable runtime-graph generation |
| `defenseclaw.run.id` | Gateway/sidecar run ID when available |
| `defenseclaw.operation.id` | Stable operation ID when available |
| `defenseclaw.outcome` | Stable result enum when the operation ends |

Empty strings are not emitted as known values. If an event contract requires a
field but the producer did not supply it, use a separate bounded availability
state; do not fabricate an identifier.

### 5.3 Common optional correlation attributes

The canonical registry supports, when known:

- Request, session, turn, trace, span, agent, agent-instance, root-agent, parent-
  agent, root-session, parent-session, lifecycle, execution, evaluation, scan,
  finding, enforcement-action, approval, model-request/response, tool-call,
  policy, destination, tenant, workspace, and user-principal identifiers.
- Connector event sequence, phase, previous phase, phase code, lifecycle event,
  lifecycle state, session source, resume state, and agent depth.
- Safe hashes/fingerprints for content, target, policy input, or evidence where the
  raw value is not appropriate.

Identifier field classes and tenant boundaries are schema-declared. An arbitrary
user string cannot be promoted to a safe identifier merely because it resembles an
ID.

For agent lifecycle observations, conversation, current agent, root agent, root
session, lifecycle, execution, lifecycle event/state, and depth are required by the
family contract. Lifecycle IDs remain stable across gateway restarts for the same
root/subagent; execution IDs change for each start/resume attempt. Parent agent and
session describe delegation, not OTel parentage. Phase codes `1..12` retain the
immutable mapping in `14-agent-lifecycle-and-dashboard-compatibility.md` section
3.3, and sequence is monotonically increasing within one execution.

### 5.4 Canonical trace body

The canonical record keeps trace/span IDs and the rendered name in the envelope:
`correlation.trace_id`, `correlation.span_id`, and `span_name`. It MUST NOT copy
them into `body` as `traceId`, `spanId`, or `name`. The exact trace body uses
snake_case and contains the fields below. Both correlation IDs are required,
nonzero, lowercase OTel IDs for every trace record; a family builder cannot rely
on a body copy or synthesize either ID.

| Field | Requirement and type |
|---|---|
| `kind` | Required enum: `INTERNAL`, `SERVER`, `CLIENT`, `PRODUCER`, or `CONSUMER`; also constrained by the family |
| `parent_span_id` | Optional nonzero lowercase 16-hex OTel span ID |
| `start_time_unix_nano` | Required positive `uint64` |
| `end_time_unix_nano` | Required `uint64`, greater than or equal to start |
| `trace_state` | Optional canonical W3C tracestate string, at most 512 bytes; malformed or non-canonical values fail closed |
| `flags` | Required complete OTLP `uint32` flags word; for an SDK-runtime-sourced span, bits 10–31 MUST be zero |
| `attributes` | Required exact family-resolved attribute object |
| `dropped_attributes_count` | Optional `uint32`; absence means zero |
| `events` | Optional bounded array of registered event objects |
| `dropped_events_count` | Optional `uint32`; absence means zero |
| `links` | Optional bounded array of link objects |
| `dropped_links_count` | Optional `uint32`; absence means zero |
| `status` | Required exact status object |
| `resource` | Required exact resource object |
| `scope` | Required exact instrumentation-scope object |

`status` is exactly `{code, description?}`. `code` is `UNSET`, `OK`, or `ERROR`;
`description` is bounded, field class `error`, sensitivity `sensitive`, and passes
central destination redaction. Numeric status codes and the old `message` spelling
may be accepted only by an explicitly generated inbound compatibility normalizer;
canonical builders never emit them.

The structural registry encodes nonzero ID checks as `otel-trace-id-v1` and
`otel-span-id-v1`, and encodes timestamp ordering as the builder-enforced
`trace-time-order-v1` relation. These are executable contracts even where JSON
Schema cannot express a comparison between two instance values.

An event is exactly `{name, time_unix_nano, attributes,
dropped_attributes_count?}`. `name` identifies one event declared by the span
family, time is `uint64`, attributes resolve from that event group, and the nested
dropped count is `uint32`. A link is exactly `{trace_id, span_id, trace_state?,
attributes, dropped_attributes_count?}`. Its IDs are nonzero lowercase 32-hex and
16-hex respectively, `trace_state` is bounded to the W3C 512-byte limit, its
attributes contain one registered family-allowed relation, and its nested dropped
count is `uint32`. Unknown event/link fields fail rather than disappearing.

`resource` is exactly `{schema_url, attributes, dropped_attributes_count?}`. Its
resolved `resource.core` use requires `service.name`, `service.version`,
`service.namespace`, `service.instance.id`, `deployment.environment.name`, and
`defenseclaw.instance.id` for a DefenseClaw-authored exported trace. Host, OS,
tenant, workspace, deployment-mode, claw-mode, and device-fingerprint fields are
emitted only when known and allowed. The fixed fields are merged with the one
generated immutable custom-resource value. Its bytewise-sorted keys are bounded
and classified `metadata`/`internal`; collision, secret/path/process-owned input,
or a value outside its validated string contract fails before record construction.
Documented legacy aliases are derived only when the generation's
`compatibility_aliases` policy is true and inherit the canonical value/class; they
are never custom entries. `scope` is exactly `{name, version,
schema_url, attributes, dropped_attributes_count?}` and requires the canonical
`defenseclaw.trace.schema_version` and `defenseclaw.semantic_profile` values bound
by the selected semantic profile. `defenseclaw.galileo.compatibility_profile` is
destination-projection metadata and MUST NOT be stamped into a general canonical
scope merely because a Galileo destination also exists.

All structural objects use `additionalProperties: false`. The family builder also
enforces these equalities: body `defenseclaw.bucket` equals the envelope bucket;
`defenseclaw.span.family` equals `event_name`; family schema version equals the
registered family version; `defenseclaw.source` equals envelope source;
`defenseclaw.config.generation` equals provenance config generation; and body
`defenseclaw.outcome` equals the envelope outcome when present. Every structural
leaf receives the field class and sensitivity declared by the structural registry;
family, resource, scope, event, and link attributes inherit theirs from the
ordinary attribute registry.

### 5.5 Canonical-to-OTLP representation

The registry representation is executable mapping data, not adapter prose. It
maps envelope correlation IDs to `Span.trace_id`/`Span.span_id`,
`body.parent_span_id` to `Span.parent_span_id`, `span_name` to `Span.name`, and
`body.trace_state`/`body.flags` directly to `Span.trace_state`/`Span.flags`; it
maps every other canonical body field to its matching OTLP protobuf field. The
full `uint32` flags word survives projection. For a span created from the OTel
SDK runtime representation, bits 0–7 preserve the W3C trace flags, bit 8 states
that parent-remoteness is known, bit 9 records a remote parent, and bits 10–31
are zero. Resource/scope
`schema_url` maps to `ResourceSpans.schema_url`/`ScopeSpans.schema_url`, not to a
field on `Resource` or `InstrumentationScope`. Status codes map `UNSET=0`, `OK=1`,
and `ERROR=2`; description maps to the OTLP status message. Every span-, event-,
link-, resource-, and scope-level dropped count survives.

`canonical_to_otlp.object_contexts` supplies the default protobuf message for
each canonical object. `field_context_overrides` is a closed exception table for
leaf fields owned by an enclosing wrapper rather than that default message:
`trace_resource.schema_url` targets `ResourceSpans`, and
`trace_scope.schema_url` targets `ResourceSpans.scopeSpans[]`. The canonical
`body.resource` and `body.scope` containers have no direct Span field mapping;
projection traverses them and places their registered children in the declared
resource/scope wrapper contexts.

Strings, Booleans, signed integers, bounded `uint32` values, finite doubles, arrays, and structured
non-null values use the matching OTLP `AnyValue` arm. Canonical attributes never
stringify a typed value merely to satisfy a backend. A value that cannot be
represented under the pinned type fails projection for that destination without
mutating the canonical record or another destination projection.

### 5.6 Generation-owned ended-span handoff

Generated builders produce the immutable canonical `Record`; the OTel SDK span is
only the timing/sampling callback carrier. A generation-owned handoff registers a
clone-isolated ended-span value before ending the SDK span, then atomically consumes
that value from the synchronous `OnEnd` callback. Destination consumers receive
the value form and can obtain only a cloned `Record`; they never receive an
`sdktrace.ReadOnlySpan` or retain provider-owned SDK state.

Registration requires all of the following to agree before any canonical fanout:

- the provider generation is active, trace collection for the record bucket is
  enabled, and the physical span is both recording and sampled;
- the canonical record has valid nonzero trace/span identity and exact start/end,
  kind, parent, rendered name, status, bucket, family, family schema version,
  source, scope, resource, config generation, and nonempty plan digest;
- record generation and plan digest equal the provider's immutable runtime plan;
  and
- the synchronous SDK callback observes exact physical/canonical parity for the
  registered fields.

The end helper always ends the physical span. Before successful registration it
uses the caller's ordinary SDK end path; after registration it supplies the exact
canonical end timestamp. It reports `registered` only after the callback consumes
the same pending identity. All rejection, panic, duplicate, parity-failure,
retirement, and concurrent-end paths atomically cancel or retire pending ownership.
No path may leak a pending count or encoded byte.

Pending handoff state is generation-private and bounded by the P-062 defaults of
2,048 records and 64 MiB of exact canonical encoded bytes. One physical callback
fans out the consumed immutable value independently to every canonical destination
and the physical SDK value independently to every legacy destination. A named
destination configures exactly one of those arms, destination names and child
identities are unique, and a missing or rejected canonical registration never
falls back to the legacy arm. Enqueue is nonblocking; destination return values and
panics cannot change the application operation or suppress sibling destinations.

Shutdown closes provider and composite-callback intake before waiting for callbacks
that already entered the composite processor. After those callbacks drain, it
retires pending handoff state and traverses children in reverse order; flush
traverses children in configured order. Candidate rollback and malformed
partial-pipeline cleanup visit both arms, deduplicate the same child by pointer
identity, and contain child panics. An OTLP child exposes a terminal cleanup signal
that closes only after its worker and exporter have actually ended, including when
the public shutdown deadline expires or exporter shutdown panics; generation-owned
canary acknowledgement cannot outlive that signal.

The generated `Record` owns W3C `trace_state` and the complete OTLP flags word,
including sampled and remote-parent bits. The physical callback performs exact
parity only; no handoff or projector may recover, overwrite, or repair either
canonical value from SDK state. Runtime-sourced records with any reserved flag bit
set fail before handoff registration, while the registry retains the general
lossless `uint32` representation needed for equivalent OTLP input. This substrate
still does not authorize canonical destination activation: configured safe custom
resource attributes first require one typed bounded canonical representation, not
acceptance as unregistered SDK-only extras. Activation additionally requires
the generated two-span root-agent/model canary, a runtime-graph lease/reload E2E
from start through end, PR #403 producer and Galileo projection migration, and PR
#412 local-observability validation through the dedicated Agent360 branch that
excludes exact Boolean-marked diagnostic canaries from spanmetrics while retaining
them in Tempo.

## 6. Resource and Scope Attributes

Every exported trace resource includes:

- `service.name`
- `service.version`
- `service.namespace`
- `service.instance.id`
- `deployment.environment.name` or the pinned compatible convention
- `host.name`, `host.arch`, and `os.type` where local policy permits
- `tenant.id` and `workspace.id` when configured
- DefenseClaw deployment mode, connector/claw mode, instance ID, and device-public-
  key fingerprint

Secrets, home-directory paths, tokens, authorization values, and arbitrary config
values are forbidden resource attributes. Per-session or per-user values belong on
spans, not the process resource. A destination adapter MUST NOT falsely stamp its
vendor preset as a process-wide resource when several destinations coexist.

Resource-to-span mirroring is allowed only for a reviewed set of join keys needed by
backends that flatten spans without resource context. The schema lists those keys;
adapters cannot mirror arbitrary resource data.

The SDK resource and canonical `body.resource` are views of the same immutable
generation snapshot. Handoff parity is exact-set equality, not subset equality.
General OTLP logs, traces, and metrics retain the same snapshot. Galileo may adapt
wrappers but preserves every validated custom resource entry and enabled alias;
another destination's projection cannot mutate it. Native Prometheus continues to
omit arbitrary resource labels. The local Collector may promote process-stable
OTLP metric resources downstream, but those promoted keys are not Agent360-required
labels and normalized-key collisions fail closed.

The local process resource is constructed without truncation: invalid or excess
members reject the generation instead of incrementing a dropped-member counter.
Its `dropped_attributes_count` is therefore absent/zero across SDK traces and
metrics, OTLP logs, generated local canonical spans, and Galileo. SDK handoff
rejects a locally generated canonical span that claims a nonzero resource dropped
count because the SDK resource cannot represent that claim. A normalized inbound
OTLP record may preserve an upstream nonzero count in its canonical record and
destination projection, but it does not use the local SDK handoff or process
resource snapshot.

## 7. Span Family Catalog

The v8 producer registry includes at least these families. The table reproduces
the registry's exact `span.name_pattern` values; braces identify canonical
attribute substitutions, while literal names have no suffix or hidden identifier.
Required attributes are machine-readable schema contracts.

| Bucket | Stable family | Span-name pattern | Kind | Purpose |
|---|---|---|---|---|
| `agent.lifecycle` | `span.agent.invoke` | `invoke_agent {defenseclaw.agent.type}` | INTERNAL or CLIENT | One bounded agent/turn/hook anchor |
| `agent.lifecycle` | `span.agent.transition` | `agent.transition {defenseclaw.agent.lifecycle.event}` | INTERNAL | Resume, compact, subagent, terminal, and phase transitions |
| `agent.lifecycle` | `span.workflow.run` | `workflow {defenseclaw.workflow.name}` | INTERNAL | One bounded orchestration/workflow step; the stable family ID is valid in `event_names` route selectors |
| `model.io` | `span.model.chat` | `chat {gen_ai.request.model}` | CLIENT | Model inference or completion |
| `model.io` | `span.model.embeddings` | `embeddings {gen_ai.request.model}` | CLIENT | Embedding request when supported |
| `tool.activity` | `span.tool.execute` | `execute_tool {gen_ai.tool.name}` | INTERNAL or CLIENT | Tool invocation and result |
| `tool.activity` | `span.retrieval.search` | `retrieve {defenseclaw.retrieval.source.id}` | CLIENT or INTERNAL | Search/retrieval represented using DB and OpenInference conventions |
| `guardrail.evaluation` | `span.guardrail.apply` | `apply_guardrail {defenseclaw.guardrail.name} {defenseclaw.guardrail.target_type}` | INTERNAL | Whole control execution and decision |
| `guardrail.evaluation` | `span.guardrail.phase` | `guardrail.{defenseclaw.guardrail.phase}` | INTERNAL or CLIENT | Regex, AI Defense, judge, policy, and finalize phase |
| `guardrail.evaluation` | `span.guardrail.judge` | `chat {gen_ai.request.model}` | CLIENT | LLM judge call, also a valid GenAI chat span |
| `enforcement.action` | `span.enforcement.apply` | `enforcement {defenseclaw.enforcement.effective_action}` | INTERNAL or CLIENT | Block, deny, quarantine, release, redact, revoke, terminate |
| `enforcement.action` | `span.approval.resolve` | `exec.approval` | INTERNAL | Approval wait and resolution; approval identity remains an attribute/correlation value |
| `security.finding` | `span.finding.enrich` | `finding.enrich {defenseclaw.source}` | INTERNAL or CLIENT | Optional expensive enrichment/correlation, not every finding log |
| `asset.scan` | `span.asset.scan` | `asset.scan` | INTERNAL | Whole asset scan |
| `asset.scan` | `span.asset.scan.phase` | `asset.scan.phase` | INTERNAL | Enumeration, fetch, unpack, analyze, correlate, persist |
| `asset.lifecycle` | `span.asset.transition` | `asset.transition {defenseclaw.asset.transition}` | INTERNAL | Actual install/update/quarantine/release transition |
| `network.egress` | `span.network.request` | `{http.request.method} outbound` | CLIENT | Each outbound attempt using protocol conventions |
| `ai.discovery` | `span.ai.discovery` | `defenseclaw.ai.discovery` | INTERNAL | Discovery scan |
| `ai.discovery` | `span.ai.discovery.detector` | `defenseclaw.ai.discovery.detector` | INTERNAL | One detector execution |
| `telemetry.ingest` | `span.telemetry.receive` | `{http.request.method} telemetry` | SERVER | OTLP/HEC receive boundary |
| `telemetry.ingest` | `span.telemetry.normalize` | `telemetry.normalize {defenseclaw.telemetry.signal}` | INTERNAL | Decode, validate, normalize, and classify |
| `platform.health` | `span.destination.export` | `telemetry.export {defenseclaw.destination.id}` | CLIENT | Optional diagnostic/export attempt span; never recursively exported to itself |
| `platform.health` | `span.config.reload` | `config.reload` | INTERNAL | Parse, validate, build, swap, and drain transaction |
| `compliance.activity` | `span.admin.operation` | `{defenseclaw.admin.operation}` | SERVER or INTERNAL | Authenticated administrative operation |
| `diagnostic` | `span.diagnostic.canary` | `defenseclaw.telemetry.canary` | INTERNAL | Isolated destination-path canary |

`span.diagnostic.canary` is the ordinary single-span diagnostic family. It is not
the release-blocking generated GenAI pipeline canary. That exact canary is a
two-span trace consisting of a marked `span.agent.invoke` root in
`agent.lifecycle` and a marked `span.model.chat` child in `model.io`; neither span
is renamed or re-bucketed as `span.diagnostic.canary` by sampling or a destination
projection.

`security.finding`, health-state changes, and compliance outcomes remain logs when
they are discrete facts. A span is added only when there is meaningful duration or
causal structure; v8 does not create zero-duration spans merely to duplicate every
log.

## 8. Rich GenAI and Agent Attributes

### 8.1 Agent/workflow spans

Required when available and applicable:

- `gen_ai.operation.name=invoke_agent`
- `gen_ai.provider.name`
- `gen_ai.agent.name`, `gen_ai.agent.id`, and `defenseclaw.agent.type`
- `gen_ai.conversation.id`
- `openinference.span.kind=AGENT`
- Redacted `gen_ai.input.messages` and `gen_ai.output.messages`
- OpenInference input/output aliases for the compatibility window
- Root/parent/session/lifecycle/execution/depth/phase/sequence/operation IDs
- Connector, run, user-principal reference, stream mode, session source, and resume
  indicator
- Input/output availability states and original byte lengths

`gen_ai.agent.type` is retained only as a projection-only compatibility alias of
`defenseclaw.agent.type`; it is not part of the pinned OTel GenAI convention. The
alias and canonical field derive from the same destination-redacted value, and
canonical builders accept only the DefenseClaw-owned field.

Workflow spans require the bounded, low-cardinality
`defenseclaw.workflow.name` used by the registered
`workflow {defenseclaw.workflow.name}` name pattern. They use
`openinference.span.kind=CHAIN` or the pinned equivalent and describe bounded
orchestration such as one turn, scan pipeline, or retrieval-augmented step. They
do not expose internal chain-of-thought or hidden reasoning.

The producer MUST supply `defenseclaw.workflow.name` as a canonical identifier of
at most 128 ASCII bytes matching `^[a-z0-9][a-z0-9_.-]{0,127}$`. The span name is
then rendered from that value. Migration and Galileo projection MUST NOT reverse
parse a missing workflow attribute from an existing `workflow ...` span name;
missing, invalid, or mismatched pairs are rejected without fabrication.

### 8.2 Model spans

The model family records, when supplied:

- Operation, system/provider, requested model, response model, response ID, server
  address/port, and safe endpoint identity.
- Request parameters: maximum tokens, temperature, top-p, choice count, output type,
  seed, frequency penalty, presence penalty, and bounded stop reason metadata.
- Response finish reasons.
- Usage: input, output, total, cache-read, cache-write, and reasoning-token counts
  when the provider explicitly reports them.
- Streaming state, retry count, attempt number, queue time, upstream time, time to
  first byte/token, total duration, cancellation, and timeout class.
- Tool-call count and tool-call IDs/names without copying arguments into metadata.
- Redacted structured input/output messages, safe byte lengths, MIME/content type,
  hashes, and availability/redaction state.
- Agent, conversation, request/response, evaluation, policy, and enforcement
  correlation.

A missing provider token count is omitted and marked `not_reported`; it is never
converted into a reported zero. Cost MAY be recorded only when based on a versioned
price catalog with currency, catalog version, and explicit estimated/actual state.

### 8.3 Tool spans

The tool family records:

- Standard operation, tool name/type, tool-call ID, and OpenInference kind.
- Provider class (`builtin`, `skill`, `mcp`, remote API, or connector-native), safe
  skill/rule/catalog ID, MCP server identity, destination application, and policy ID.
- Redacted structured arguments/result, MIME type, byte lengths, safe hashes,
  availability/redaction state, exit code, and stable error type.
- Requested/effective action, dangerous classification, matched rule ID (not raw
  matched secret/pattern), approval ID/result, and enforcement-action ID/outcome.
- Start source, retry/attempt, timeout/cancel state, and total/remote execution time.

### 8.4 Retriever spans

Retrieval is represented when DefenseClaw or an integrated tool can distinguish it:

- `db.operation.name` or the pinned compatible key with `query`/`search`.
- `openinference.span.kind=RETRIEVER`.
- Data-source ID/type, collection/index name only when bounded and non-sensitive,
  result count, top-k, score range, and duration.
- Redacted query input and redacted/bounded document summaries or references.
- Document IDs/hashes and ranks; no complete source document unless an explicit
  eligible content route permits it.

Retrieval performed through a tool remains primary bucket `tool.activity`; the span
family makes the retrieval semantics queryable without adding a new v1 bucket.

## 9. Security, Policy, and Enforcement Attributes

### 9.1 Guardrail evaluation

The outer evaluation and its phase spans carry, when known:

- Evaluation ID, strategy, stage, phase, direction, target type, model/tool
  reference, policy/rule-set ID and version, config generation, and source.
- Detector/judge name and version, judge model/provider, cache-hit state, attempt,
  latency, score/confidence, matched rule IDs, and finding IDs/count.
- Decision, raw action, effective action, enforcement mode, would-block, enforced,
  severity, outcome, failure class, and enforcement-action IDs.
- Safe input hash/reference and redacted bounded reason/evidence summary.

An LLM judge call is a child `chat` span with the full model-span contract plus
guardrail evaluation correlation. This makes it visible to Galileo as a valid LLM
operation while the outer guardrail span remains visible to general OTLP backends.

### 9.2 Findings

The span that produced a finding MAY add `security.finding.observed` events with:

- Finding occurrence ID, stable rule ID, category, canonical severity, confidence,
  target reference, safe fingerprint, and evaluation/scan ID.

It MUST NOT attach full evidence, model/tool content, or a fabricated remediation.
The authoritative finding is the linked `security.finding` log/projection.

### 9.3 Enforcement and approval

Enforcement spans carry action ID, requested/effective action, mode, initiator,
target reference, evaluation/finding/policy references, outcome, failure class,
previous/resulting state, and duration.

Approval spans additionally carry approval ID, safe command name, argument count,
redacted command/argv/cwd only when the route permits, actor/principal reference,
auto/manual state, requested/resolved timestamps, result, reason, dangerous state,
and tool/enforcement correlations.

### 9.4 Final connector-facing hook decision

The scanner/guardrail verdict and the final connector response are distinct. The
canonical `hook_decision` records connector/event/result, raw action, effective
action, canonical severity, mode, would-block, enforced, bounded step/latency/reason,
evaluation ID, at most eight rule IDs, and every known agent/session/lifecycle/
execution/operation correlation.

It is emitted as a `guardrail.evaluation` durable log and as a bounded
`hook.decision` event or equivalent registered fields on the active hook span. An
actually imposed control also creates a separate linked `enforcement.action`
record. It MUST NOT advance lifecycle phase/sequence a second time, invent a
retry/recovery, or replace the full evaluation record. The next actual hook/event
is the source of truth for what the agent did after the decision.

## 10. Span Events and Links

### 10.1 Event catalog

Events are bounded milestones inside an operation, not a substitute for required
logs. Initial event names include:

| Event | Typical parent | Safe attributes |
|---|---|---|
| `model.stream.first_token` | model | elapsed time, attempt |
| `model.retry` | model | attempt, backoff, error type |
| `tool.flagged` | tool | rule ID, category, severity |
| `approval.requested` | tool/enforcement | approval ID, mode |
| `approval.resolved` | approval/tool | result, actor type, elapsed time |
| `guardrail.decision` | agent/model/tool | evaluation ID, decision, effective action, severity, would-block, enforced |
| `hook.decision` | active hook/agent anchor | connector, event, evaluation ID, raw/effective action, severity, mode, would-block, enforced, bounded rule IDs |
| `security.finding.observed` | evaluation/scan | finding ID, rule ID, category, severity, fingerprint |
| `enforcement.requested` | evaluation/tool | action ID, action, mode |
| `enforcement.applied` | enforcement/asset | action ID, resulting state |
| `enforcement.failed` | enforcement | action ID, failure class |
| `content.redacted` | content-bearing span | field class, profile, detector count; no matched value |
| `content.truncated` | any | field class, original bytes, retained bytes |
| `exception` | failed operation | standard exception attributes after redaction |
| `telemetry.dropped` | pipeline operation | destination, signal, bounded reason, count |

Events repeat only enough security summary to interpret the waterfall. Full logs
remain linked through IDs. Event count overflow increments a dropped-events count
and adds one terminal overflow marker if capacity remains.

### 10.2 Links

Use links for:

- A scan finding produced after the scan span ended.
- An enforcement action caused by several findings/evaluations.
- A resumed session connected to its predecessor execution.
- An asynchronous exporter or normalization operation.
- A reconstructed hook completion where the original parent context is no longer
  safely available.

Each link includes only bounded relation metadata such as `caused_by`, `resumes`,
`derived_from`, or `correlates_with`. Never create a new random parent to make a
waterfall look complete.

## 11. Status, Outcome, and Errors

- `defenseclaw.outcome` uses the exact canonical outcome vocabulary in
  `02-taxonomy-and-data-model.md` section 3.2. Each span family registers its allowed
  subset; unregistered family-specific synonyms are invalid.
- Guardrail evaluation that successfully decides `block` is an operationally
  successful evaluation and normally has unset/OK OTel status. Its decision fields
  carry the block.
- The model/tool/agent operation prevented by that decision MAY have OTel ERROR
  status with `error.type=policy_denied` because the requested operation did not
  complete.
- Technical failure, timeout, invalid response, exporter rejection, and unhandled
  exception set OTel ERROR and a stable `error.type`.
- Cancellation intentionally requested by the caller uses outcome `cancelled`; it
  is not automatically a technical error.
- Error descriptions are bounded and centrally redacted. Stack traces are span
  events only when configured for an eligible route and are never metric labels.
- HTTP and RPC spans follow their stable protocol status rules rather than a custom
  global `status >= 400` shortcut.

This separates “the security control worked and blocked” from “the control itself
failed.” Compatibility dashboards that relied on block-as-ERROR receive a migration
query and, during the compatibility window, a bounded decision attribute rather
than forcing the incorrect status forever.

## 12. Content, Redaction, and Missing Data

### 12.1 Destination-specific projection

The canonical recording span may hold typed source values only inside the bounded
in-process SDK lifecycle. Before each exporter sees a span, DefenseClaw creates a
destination-owned projection and applies that route’s profile to:

- Attributes.
- Span events.
- Link attributes.
- Status descriptions.
- Exception messages and stack traces.
- GenAI/OpenInference input/output fields.

No producer may call a global sink redactor before the destination fan-out, because
that would make independent route profiles impossible. No destination may mutate the
shared SDK span.

### 12.2 Content-state attributes

Every optional input/output/arguments/result body has independently safe metadata:

- `reported`: whether the producer supplied it.
- `state`: `not_reported`, `preserved`, `partially_redacted`, `whole_redacted`,
  `truncated`, or `failed_closed`.
- `original_bytes`: bounded integer when known.
- `content_type`/MIME type.
- Safe keyed hash only when policy permits correlation.

For a Galileo-required input/output field whose producer did not report content,
the projection MAY use an empty structured array (`[]`) solely to satisfy the
backend shape, but MUST also set `reported=false` and `state=not_reported`. It MUST
NOT invent user, assistant, tool, retrieval, or reasoning text.

### 12.3 Duplicate aliases

During a documented compatibility window, standard GenAI, OpenInference, and
legacy `defenseclaw.*` content aliases may coexist. They are generated from one
already-redacted typed value. A canary test asserts that no alias receives a less
restrictive value. Compatibility aliases have a removal version and are visible in
the effective trace schema.

## 13. Galileo Rich Projection

### 13.1 Preset contract

`preset: galileo` expands to the immutable compatibility profile
`galileo-rich-v2`, while preserving operator overrides that do not weaken required
validation. The effective view shows the expanded profile.

It preserves:

- Exact configured Cloud/self-hosted trace endpoint.
- API-key secret reference and project/log-stream headers.
- HTTP/protobuf traces only unless Galileo adds and the operator selects another
  supported signal.
- The `galileo-rich-v2` preset deliberately defaults `scheduled_delay_ms` to 1,000.
  This is a v8 preset choice, not the v7 global default of 5,000 ms. An explicit v7
  operator override is preserved by migration.
- Independent count-and-byte queue, delivery health, partial-success parsing, and
  exact canary under the common destination-delivery contract.
- Route-specific redaction.

### 13.2 Supported Galileo span shapes

The v8 profile accepts and validates:

| Shape | Discriminator | Required projection |
|---|---|---|
| Agent | `gen_ai.operation.name=invoke_agent` | provider, agent name, input, output, valid name/kind |
| LLM | operation `chat`, `text_completion`, or supported pinned equivalent | provider, request model when known, input, output |
| Tool | `gen_ai.operation.name=execute_tool` | tool name, call ID when known, arguments/result, input/output |
| Retriever | DB operation `query` or `search`, optionally OpenInference `RETRIEVER` | input query plus bounded/redacted document output |
| Workflow | OpenInference `CHAIN` or versioned workflow discriminator | explicit `defenseclaw.workflow.name`, exact rendered name, input, output |

The current three shapes are therefore retained, and retriever/workflow spans are
added. Agent kind is INTERNAL for in-process orchestration and CLIENT for a remote
agent. Model and remote-tool/retrieval calls use CLIENT; local tools use INTERNAL.

### 13.3 Security enrichment visible in Galileo

Galileo-compatible agent, model, tool, retriever, and workflow spans retain safe
DefenseClaw overlay attributes and bounded events for guardrail decisions, finding
IDs, approvals, and enforcement outcomes. Full guardrail phase, policy, scan,
network, health, and compliance spans remain available to general OTLP destinations
even if Galileo does not classify their native shapes.

LLM judge calls are valid child LLM spans and MAY be sent to Galileo when the
`guardrail.evaluation` trace route is enabled. Their inputs/outputs follow the same
redaction profile as every other content-bearing span and are marked as judge calls
through DefenseClaw attributes.

The preset compatibility validator is separate from bucket routing:

1. Collection decides whether the span exists.
2. The destination route decides whether Galileo is eligible to receive it.
3. Route redaction creates the Galileo projection.
4. The Galileo schema profile accepts or rejects that projected shape.
5. A rejection increments `ineligible`/`schema_missing_required` counters and does
   not affect other destinations.

### 13.4 No vendor lock-in

Canonical span families do not use Galileo-specific names. Galileo headers and
optional resource projection are adapter-owned. General OTLP destinations receive
the same standard/DefenseClaw graph without Galileo filtering. Renaming a Galileo
destination does not disable its compatibility profile; `preset` identity, not
destination name, selects the profile.

## 14. Limits and Cardinality

Rich telemetry remains bounded. The v8 `trace_policy.limits` defaults and
non-overridable hard ceilings are:

| Config field / limit | Family minimum | Default | Hard maximum |
|---|---:|---:|---:|
| `max_attributes_per_span` | 32 | 128 | 256 |
| `max_events_per_span` | 1 | 64 | 128 |
| `max_links_per_span` | 1 | 32 | 64 |
| `max_attributes_per_event` (also applied to link attributes) | 4 | 32 | 64 |
| `max_attribute_value_bytes` | 256 bytes | 16,384 bytes | 65,536 bytes |
| `max_projected_span_bytes` | 4,096 bytes | 262,144 bytes (256 KiB) | 1,048,576 bytes (1 MiB) |
| `max_stacktrace_bytes` | 256 bytes | 32,768 bytes (32 KiB) | 131,072 bytes (128 KiB) |
| `max_message_items` | 1 | 128 | 512 |

An explicitly configured limit MUST be an integer from its family minimum through
its hard maximum;
omission selects the listed default. Startup/reload rejects values above a hard
maximum instead of clamping them. Effective limits also respect any lower
SDK/collector limit. Runtime overflow is deterministic, fails closed for content,
retains core identity/outcome fields, and records dropped counts. Required Galileo
shape fields take priority over optional aliases. The projected-span byte limit is
evaluated independently on each destination projection after redaction and
compatibility-alias generation.

High-cardinality IDs are allowed on traces and logs where needed for investigation,
but not copied to metric labels. Span names never contain request, session, user,
finding, scan, URL path, arbitrary model output, or unbounded command text. Tool,
model, detector, scanner, and agent names are normalized and bounded before entering
span names; the original safe value may remain as a redacted attribute.

## 15. Trace Configuration Contract

The complete v8 surface adds explicit trace limits and schema selection:

```yaml
observability:
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
```

This is an all-knobs example. If sampler settings are omitted, explicitly collected
traces use `parentbased_always_on`; catalog defaults collect every defined trace
family unless a bucket/default override disables it.

`semantic_profile` selects a shipped immutable schema profile; arbitrary custom
attribute schemas are not accepted from YAML. The
`defenseclaw-genai-rich-v1` entry in `schemas/telemetry/v8/registry.yaml` binds one
exact tuple listed in section 2. The effective view displays those four literal
identifiers. Operators cannot override its members independently; changing any
member requires a new semantic-profile ID. A missing or mismatched lock/profile
binding is a build/startup error. `compatibility_aliases` controls only documented
old aliases and defaults to true for migrated v7 installations until their removal
release. It never changes the selected projection profile.

Richness is primarily a schema guarantee, not hundreds of per-attribute switches.
Operators choose which bucket traces exist, which destinations receive them, and
which route redaction applies. Limits control bounded resource use.

Assuming trace collection is enabled for the selected buckets, the Galileo
destination becomes:

```yaml
- name: galileo
  kind: otlp
  preset: galileo
  endpoint: https://api.galileo.ai/otel/traces
  headers:
    Galileo-API-Key: {env: GALILEO_API_KEY}
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

The compiler generates the effective route and trace transport from `send`. The
preset’s schema projection determines which selected spans Galileo can ingest.
Effective config and `observability plan` show both route and vendor-shape
eligibility.

## 16. Sampling

- Bucket collection is evaluated before span construction.
- Parent-based sampling preserves a coherent bounded trace.
- The sampling decision and reason are observable in safe debug/health data.
- A route cannot resurrect an unsampled span.
- Security findings and enforced outcomes remain durable logs even when their trace
  is unsampled.
- Operators needing decision-aware tail sampling should use an OTel Collector policy
  keyed by canonical severity, outcome, error type, bucket, or guardrail decision.
  DefenseClaw ships an example policy but does not claim local tail-sampling
  durability.
- Canary traces bypass normal ratio sampling only for the explicitly targeted
  diagnostic operation and remain marked as canaries.

## 17. Delivery and Health

Per destination, expose bounded counters for:

- observed
- collection-disabled
- unsampled
- route-unmatched
- route-dropped
- schema-ineligible
- redaction-failed-closed
- queued
- queue-dropped
- attempted
- delivered/collector-accepted
- partially rejected
- rejected
- failed
- retried

Counts distinguish spans from batches. Health reports last success/failure time,
last safe error class, queue utilization, dropped counts, active compatibility
profile, schema versions, and canary acknowledgement. It never exposes a header,
content value, status description containing content, or remote response body.

## 18. Migration Requirements

The v7-to-v8 migration must:

1. Preserve all four existing runtime span schemas (agent, LLM, tool, approval),
   the agent lifecycle event schema, gateway envelope correlation, and
   `hook_decision` as input fixtures.
2. Preserve current Galileo operation eligibility, headers, endpoint,
   routing/delivery counters, and canary behavior. Preserve an explicit v7 batch
   delay; when v7 used the inherited 5,000 ms default, materialize the deliberate v8
   Galileo preset default of 1,000 ms and report that preset-default change in the
   migration summary.
3. Convert `span_filter` intent into v8 bucket routes plus the versioned Galileo
   compatibility profile without broadening export silently.
4. Preserve current conversation/current-agent/root-agent/parent-agent,
   root/parent-session, lifecycle/execution/run/operation, lifecycle event/state,
   phase/previous-phase/code, depth, sequence, source/resume, and user correlation.
   Root/parent delegation remains distinct from trace parentage.
5. Replace producer-global sink redaction with per-destination span projection.
6. Add universal bucket/family/schema/source/config-generation fields.
7. Add retriever/workflow schemas and guardrail/enforcement/event contracts.
8. Mark legacy content aliases with a removal version and prove equal redaction.
9. Provide query migrations for the corrected status/outcome semantics.
10. Preserve completed-operation export without waiting for `Stop`, semantic
    terminal deduplication, bounded correlation-cache behavior, and honest
    `reported=false`/`not_reported` token, cost, input, and output state.
11. Generate and verify `local-observability-v1` so every Agent360 Prometheus,
    Loki, and Tempo consumer has a preserved/aliased/migrated field disposition.

If an existing operator span filter cannot be represented exactly by bucket routes
and the compatibility profile, migration emits a hard review item and shows the
before/after eligible span families.

## 19. Verification and Acceptance

### 19.1 Schema completeness

- Every registered span family has name/kind, bucket, required/optional attributes,
  field classes, events, links, status rules, limits, and family schema version.
- Build fails if an emitted attribute/event is absent from its schema or a required
  field is no longer emitted.
- Attribute names and types are identical across Go, Python, schemas, docs, canary,
  and migration fixtures.

### 19.2 Golden trace graphs

Golden tests cover:

- Allowed model call.
- Input-blocked model call.
- Output-blocked model call.
- Model provider retry and timeout.
- Streaming completion with first-token timing.
- Tool call with approval and successful enforcement.
- Tool denied before execution.
- Tool execution failure.
- Guardrail evaluation with regex, AI Defense, judge, policy, finding, and block.
- Clean evaluation with no finding.
- Retriever inside a workflow.
- Agent resume, compaction, subagent, and terminal transition.
- Root agent with nested subagents, stable lifecycle across gateway restart, new
  execution on resume, and delegation links distinct from trace parents.
- Long-running session where completed turn/model/tool spans and logs appear before
  any `Stop` or session-end hook.
- Raw block downgraded by observe mode/capability mapping, followed by an actual
  retry/model/tool/stop event without a fabricated recovery transition.
- Missing tokens, cost, parent, timing, input, and output with explicit not-reported
  state rather than zero/empty fabrication.
- Asset scan with several findings and quarantine.
- Inbound OTLP normalization and exporter partial success.

Tests assert exact parent-child/link shape, span count, IDs, names, kinds, statuses,
events, and correlations without requiring content equality.

### 19.3 Galileo compatibility

- Current `chat`, `invoke_agent`, and `execute_tool` fixtures remain eligible.
- Retriever and workflow fixtures are eligible under `galileo-rich-v2`.
- LLM judge child spans are eligible when the guardrail route is enabled.
- Native guardrail/policy/scan/health spans remain available to general OTLP and are
  not silently misclassified merely to enter Galileo.
- Missing input/output is represented as structured empty plus explicit
  `reported=false`, never fabricated content.
- Errors carry `error.type` and ERROR status; successful block decisions remain
  distinguishable from control failures.
- A Galileo schema miss increments the correct reason counter and does not affect
  another OTLP destination.
- Direct and runtime canaries use the same pinned schema and exact-trace
  acknowledgement behavior.

### 19.4 Privacy and robustness

- The same canonical span projected to `strict`, `content`, `sensitive`, and `none`
  optional routes produces independent expected results.
- Sensitive canaries are absent from all aliases, events, links, error descriptions,
  exception fields, and vendor wrappers that should not receive them.
- A default `none` projection does not weaken another destination that explicitly
  selects a redacting profile.
- Oversize attributes/events fail closed and retain required identity/outcome.
- Unicode, malformed JSON messages, fake redaction tokens, deep structures, and
  destination serialization errors are covered.
- Fuzzing proves projection never mutates the SDK’s shared canonical span.

### 19.5 Performance

- Disabled bucket traces allocate no body/event structures.
- Rich enabled-span overhead is benchmarked for agent/model/tool/guardrail paths.
- Projection cost scales with enabled matching destinations, not all configured
  destinations.
- Queue, correlation cache, event, link, and projected-byte limits remain bounded
  under adversarial high-cardinality input.
