# Architecture and Requirements

## 1. Problem

DefenseClaw currently has multiple partially independent observability paths:

- Gateway JSONL events and console rendering.
- SQLite audit events and normalized audit tables.
- Audit sink fan-out.
- Native OpenTelemetry logs, traces, and metrics.
- Inbound OTLP ingestion and normalization.
- Connector-specific sink overrides.
- Several redaction call sites with different field coverage.
- A separate forensic judge-body database.

Operators cannot express one coherent policy that answers all of the following:

- Which semantic classes of activity should be collected?
- Which signal types should be produced for each class?
- Which destinations should receive each class and signal?
- What redaction should each destination receive?
- What must remain locally durable even under aggressive suppression?
- How long should local event and evidence history be retained?

The fragmented paths also make it possible for a new producer to bypass intended
redaction or export policy.

## 2. Goals

### G-1: One policy surface

`config.yaml` MUST be the authoritative policy for bucket collection, destination
routing, redaction, exporter settings, and local retention. Normal source YAML MUST
support a concise authoring form that compiles deterministically into the same full
runtime graph used by advanced routes and the effective view.

### G-2: Semantic control

Operators MUST configure policy using stable vendor-neutral buckets rather than
having to enumerate every internal Go action or event type.

### G-3: Signal independence

Logs, traces, and metrics MUST be independently collectable and routable. Disabling
content logs MUST NOT require disabling aggregate metrics.

### G-4: Destination independence

One record MAY be exported to zero, one, or many optional destinations. Failure,
backpressure, or redaction choice at one destination MUST NOT change another
destination’s output.

### G-5: Central privacy boundary

All outbound and persistent log records MUST traverse the same redaction engine.
No producer or destination adapter may be an undocumented redaction bypass.

### G-6: Durable minimum audit trail

DefenseClaw MUST retain a narrow, local record of security-relevant operator and
system mutations, enforced outcomes, and failures that affect audit integrity.

### G-7: Preserve useful existing functionality

The design MUST preserve SQLite audit history, JSONL, console output, OTel/OTLP
metrics and the operator-side observability bundle, OTLP logs/traces, Galileo
through OTLP configuration, Splunk HEC, HTTP JSONL, current
correlation identifiers, scan projections, judge response retention, dashboards,
health reporting, and operator setup flows.

A gateway-native `kind: prometheus` pull destination is new v8 functionality. It
does not claim to preserve an existing native v7 destination; existing metric
intent is migrated from OTel/OTLP, while Prometheus is an explicit opt-in.

### G-8: Predictable operation

Configuration validation, route precedence, redaction failure behavior, retention,
and live reload MUST be deterministic and testable.

### G-9: Operable configuration at scale

The live operator-authored config MUST remain compact. Required local persistence,
versioned defaults, generated route names, and OTLP signal activation MUST NOT require
boilerplate in normal source YAML. DefenseClaw MUST provide a fully resolved
effective view and generated all-knobs reference without requiring operators to
retain dormant examples.

### G-10: Safe taxonomy evolution

Adding a future bucket MUST NOT silently begin non-SQLite delivery through an old
wildcard route. Bucket identity and catalog evolution MUST be explicit and
reviewable.

### G-11: Automatic upgrade migration

One authenticated target-release resolver command MUST automatically stage supported
POSIX v7 installations through the published `0.8.4` protocol-2 bridge, re-exec under
a fresh bridge controller, and run the required registered v8 migration. A failed
conversion, target start, or health check MUST restore the exact healthy `0.8.4`
CLI, gateway, v7 source, cursor, and custodied state and MUST NOT leave a v8 gateway
running against v7 configuration. No separate plan or second apply command is
required. A platform without a published bridge, including Windows for this hard
cut, MUST refuse before service stop or installed-state mutation.

### G-12: Rich portable traces

DefenseClaw MUST preserve the current Galileo agent/model/tool trace experience and
add bounded workflow, retrieval, security-decision, lifecycle, timing, retry,
error, event, and link context using portable OTel/GenAI conventions plus a focused
DefenseClaw overlay.

### G-13: Understandable schemas

One logical OTel-compatible telemetry registry, split into a small fixed set of
focused authoring files, MUST generate the public
schema bundle, compact catalog, human reference, constants/builders, redaction
field classes, conformance fixtures, and vendor compatibility projections. A
developer must not manually synchronize many independent schema files for one
telemetry change.

### G-14: Preserve full agent traceability and local dashboards

The merged PR #403 root/subagent lifecycle, execution, turn/model/tool/approval,
phase/sequence/operation, hook-decision, real-time completion, and missing-data
semantics MUST survive the unified pipeline. The merged PR #412 dashboard
metric/label/bucket/cadence corrections and the fourteen-dashboard local bundle
MUST remain functional across automatic upgrade without resetting local history.

### G-15: Hard runtime cutover

The released target binary MUST run one v8 observability implementation. It may
read v7 configuration only inside the `defenseclaw upgrade` conversion boundary or
its read-only preview, and may retain v7 artifacts only for exact rollback,
previous-binary recovery, and historical conformance fixtures. Gateway/sidecar
startup, reload, live producers, routing, destination delivery, and ordinary
configuration commands MUST NOT select, emit, or fall back to a v7 runtime path.
Generated backend projections and legacy-shaped local read columns remain valid v8
consumer compatibility and do not authorize a legacy producer/provider.

## 3. Non-goals

- Replacing OpenTelemetry protocols or SDKs.
- Making webhooks a general-purpose log exporter. Webhooks remain notifications.
- Implementing a full security case-management system.
- Adding `open`, `resolved`, `reopened`, or analyst-disposition state to findings.
- Guaranteeing remote delivery during process crash without a future durable remote
  spool.
- Allowing administrators to execute arbitrary regular expressions in the
  redaction path.
- Storing complete traces or raw metric samples in SQLite.
- Performing automatic runtime conversion of legacy configuration in gateway
  startup or reload. The staged target-release resolver and migration controller
  perform the one-time conversion.
- Making all existing internal actions public configuration vocabulary.
- Turning YAML into a policy language with includes, arbitrary expressions, runtime
  scripts, or mutable hidden audience presets.
- Requiring the live source file to enumerate every default and every possible knob;
  that belongs in generated effective/reference views.
- Guaranteeing zero-downtime conversion across mutually incompatible v7/v8 config.
  The normal upgrade may briefly stop and restart the gateway.

## 4. Conceptual Pipeline

The required processing order is:

1. **Producer classification** — a producer identifies the primary bucket, signal,
   stable event name, severity, source, connector, action, correlation context, and
   typed body.
2. **Collection decision** — the bucket policy decides whether the signal should be
   constructed. Disabled signals stop here and avoid normal runtime cost.
3. **Mandatory-floor decision** — qualifying log events disabled by collection MAY
   produce a minimal mandatory record addressed only to SQLite.
4. **Canonical normalization** — the accepted signal becomes an immutable canonical
   record with classified fields.
5. **Canonical validation** — the record is checked against its signal and event
   contract. Invalid records create a correlated schema-failure record and are not
   delivered as if valid.
6. **Local persistence** — every normally collected log, plus mandatory-floor logs,
   is persisted by the built-in SQLite store using the bucket/default redaction
   profile.
7. **Destination routing** — every optional destination evaluates its generated
   capability-default send, compiled concise-send route, or ordered advanced routes
   independently for that signal.
8. **Per-route projection** — a matching send route clones the canonical record,
   applies the effective redaction profile, validates the projected shape, and
   computes any integrity signature over the final projected bytes.
9. **Destination delivery** — destination-owned queues, batching, retry, and health
   state handle the projected record.

The canonical record MUST NOT be mutated during steps 6 through 9.

## 5. Core Invariants

### INV-1: One primary bucket

Every canonical record MUST have exactly one bucket from the catalog. Related
facts are represented as linked records, not one record duplicated into several
buckets.

### INV-2: Collection precedes routing

If ordinary collection for a bucket and signal is disabled, optional routes MUST
NOT receive that signal. The SQLite compliance-floor exception applies only to a
new minimal log record and only to SQLite.

### INV-3: Implicit SQLite coverage

The built-in SQLite store is always present and receives every normally collected
log. It cannot be disabled or routed around. Source YAML only overrides its path,
judge-body path, and retention settings; the effective graph exposes its generated
local catch-all projection.

### INV-4: Full-fidelity collection default

An unspecified bucket inherits full log/trace/metric collection and `none`
redaction. Collected logs are persisted locally unredacted. Nothing is remotely
exported until an optional destination is enabled; an enabled destination without
explicit policy receives every bucket in the effective reviewed catalog version
and all signals its kind supports. Runtime buckets newer than that version retain
the same full-fidelity, unredacted collection and local-persistence defaults but do
not enter optional-destination wildcards until the catalog version is advanced.

### INV-5: Destination-local precedence

First-match-wins is evaluated separately for every `(destination, signal, record)`
tuple. A match in one destination has no effect on route evaluation elsewhere.

### INV-6: Independent redaction

Different destinations MAY receive different projections of the same canonical
record. The default projection is unredacted, but an explicitly redacting
destination MUST NOT be weakened by another destination or the local `none`
projection.

### INV-7: No hidden content copies

Disabling `model.io` or `tool.activity` content logs MUST NOT be defeated by copying
the same content into `guardrail.evaluation`, `security.finding`, `diagnostic`, span
attributes, metric attributes, error messages, or destination-specific wrappers.

### INV-8: Bounded labels

Metric attributes MUST use a documented bounded vocabulary. Prompts, responses,
tool arguments, tool results, paths, error bodies, evidence, user identifiers, and
unbounded rule text MUST NOT become metric labels.

### INV-9: Integrity after privacy

Destination integrity hashes or HMAC signatures MUST be calculated after redaction
and serialization, so they authenticate the exact bytes delivered.

### INV-10: Failure isolation

Exporter failure MUST NOT stop producers, SQLite persistence, or other exporters.
SQLite initialization failure is different: startup MUST fail because the required
local audit floor cannot be guaranteed.

### INV-11: Version-pinned non-SQLite wildcard

Any optional-destination route using bucket wildcard matches only buckets included
in the effective reviewed bucket catalog version. The built-in local store covers
every runtime bucket so new data remains locally visible.

### INV-12: Source is not effective configuration

Omitted defaults and generated preset values MUST be observable in the masked
effective view with provenance. Runtime behavior may not depend on an undocumented
default absent from the canonical configuration schema.

### INV-13: No mixed upgrade state

A v7 gateway with v8 source and a v8 gateway with v7 source are invalid. A required
conversion failure must leave or restore the exact v7 source and use the existing
gateway-binary recovery artifact when restart of the previous gateway is needed.

### INV-14: Agent and dashboard compatibility is end-to-end

Preserving a field name without preserving its identity semantics, event boundary,
reported-state behavior, metric cadence, backend ownership, or consuming query is
not compatibility. Registry, producers, Collector, dashboards, packaged assets,
upgrade, and static/live tests change together under
`14-agent-lifecycle-and-dashboard-compatibility.md`.

### INV-15: Migration compatibility never becomes runtime ownership

After a successful required upgrade cursor entry, the target process accepts only
validated v8 source and every live signal is constructed by generated v8 family
authority before local persistence or optional projection. A missing runtime
capability, disabled signal, sampling decision, validation failure, reload race, or
destination failure cannot resurrect a legacy writer, provider, sink, bridge, or
direct OTel emission. Repository checks MUST distinguish allowed migration/history
references from forbidden live-runtime references.

## 6. Mandatory Compliance Floor

### 6.1 Included events

The mandatory floor includes only log records for:

1. Configuration, policy, redaction-profile, destination, retention, and
   unredacted-delivery changes, including rejected attempts.
2. Enforcement-state changes and actual enforced outcomes: block, deny, quarantine,
   redact, revoke, terminate, release, and approval resolution.
3. Alert acknowledgement or dismissal mutations, recorded as immutable
   `compliance.activity` without changing the underlying finding/event severity.
4. Authentication or authorization failures at protected boundaries, classified by
   the boundary being protected: administrative/operator failures are
   `compliance.activity`; inbound telemetry receiver failures are
   `telemetry.ingest`; outbound destination credential/authentication failures are
   `platform.health`.
5. Explicit operator destination-test attempts and terminal outcomes. The ordinary
   `compliance.activity` record contains only destination name, probe ID, test mode,
   bounded result, and bounded failure class; it never contains a credential,
   endpoint, response body, or probe payload.
6. Canonical or projected schema validation failures.
7. SQLite write, migration, corruption, and retention failures.
8. Exporter or sink initialization failures and durable health-state transitions.

### 6.2 Excluded events

The floor does not automatically include:

- Every successful model request.
- Every tool call.
- Every guardrail evaluation.
- Every scan phase.
- Debug diagnostics.
- Aggregate metrics or traces.
- Remote delivery of a record collected only because of the floor.

### 6.3 Floor behavior

- Floor records MUST be written to SQLite even when their bucket’s log collection
  is false.
- A floor-only record MUST be minimal and MUST NOT contain complete prompts,
  responses, tool arguments, tool results, evidence bodies, credentials, or judge
  bodies.
- When disabled ordinary collection reduces a destination-test activity to its
  floor-only form, destination/probe/result details are deliberately omitted; the
  full content-free fields are present only on the single ordinary record.
- Floor-only records MUST NOT be considered collected for remote routing, JSONL,
  console, trace, or metric purposes.
- If ordinary collection is enabled, the ordinary canonical record is used; the
  implementation MUST NOT emit a second duplicate floor record.
- Floor qualification MUST be encoded in a reviewed catalog rather than determined
  through ad hoc string matching.

## 7. Actor Attribution for Compliance Activity

Compliance logging itself is mandatory; actor identity is best available.

A compliance record MUST include:

- Actor type: `user`, `service`, `system`, `file_watcher`, or `unknown`.
- Stable actor identifier when authenticated.
- Authentication mechanism when known.
- Origin class, such as CLI, local API, connector, config reload, or internal task.
- Requested action, target type, and target identifier.
- Sanitized change summary or structured diff.
- Outcome: the control-plane subset `attempted`, `validated`, `applied`, `rejected`,
  or `failed` from the canonical vocabulary in
  `02-taxonomy-and-data-model.md` §3.2.
- Configuration generation or revision when applicable.
- Correlation identifiers.

The system MUST use `unknown` rather than attributing an action to an unverified
human. Secret values MUST be omitted from both sides of a diff; the diff may state
that a secret-bearing field changed.

## 8. Signal Requirements

### 8.1 Logs

- Logs represent discrete facts.
- Every collected log MUST be stored in SQLite.
- Logs MAY also be sent to JSONL, console, Splunk HEC, HTTP JSONL, or OTLP.
- A log body MUST follow the event-name contract for its bucket.

### 8.2 Traces

- Span creation MUST be a no-op when collection for the bucket is disabled.
- Every DefenseClaw-authored span MUST carry `defenseclaw.bucket`, stable family and
  schema identity, source/config generation, outcome when known, and available
  correlation attributes.
- Stable OTel resource, HTTP/RPC/error, and pinned GenAI conventions are the
  portable base. `defenseclaw.*` adds only security, policy, lifecycle,
  correlation, provenance, bucket, and privacy semantics not owned by a standard.
- Agent, model, tool, retriever, workflow, guardrail, enforcement, approval, scan,
  discovery, network, ingest, health-operation, compliance-operation, and diagnostic
  families follow `11-trace-and-span-contract.md`.
- Span events and links preserve bounded milestones and asynchronous causality;
  discrete authoritative outcomes still use logs and are not duplicated wholesale
  into span content.
- Destination filtering and redaction MUST operate on cloned span data and span
  attributes, events, links, status descriptions, and exceptions, not mutate the
  SDK’s shared record.
- Sampling remains a global trace concern and is applied in addition to bucket
  collection and destination routing.
- Stable trace and span identifiers MUST be preserved across destinations.
- Trace attribute/event/link/byte limits are explicit, deterministic, and
  observable. Overflow retains required identity/outcome and fails closed for
  content.
- One logical OTel-compatible registry with focused GenAI, security, and operations
  authoring files generates span/event schemas,
  constants, fixtures, documentation, redaction field classes, and destination
  compatibility projections as defined in
  `12-telemetry-schema-architecture.md`.

### 8.3 Metrics

- Instrument creation or recording MUST skip disabled bucket metrics.
- Every metric instrument MUST be registered in a catalog that names its bucket,
  unit, description, type, and allowed attributes.
- Destination filtering MUST happen before export.
- Content-bearing values are forbidden from metric attributes.

## 9. Validation and Error Behavior

### 9.1 Startup validation

Startup MUST fail for:

- Built-in SQLite initialization or schema migration failure.
- Unknown bucket, signal, selector, destination kind, profile, detector, or field
  class.
- Duplicate destination names.
- Source use of the reserved generated local destination, local routing/redaction
  fields, or legacy OTLP signal-enable maps.
- A destination route containing an unsupported signal.
- Invalid endpoint, TLS, secret reference, batching, or retry configuration.
- Legacy v7 observability blocks in a v8 runtime configuration.
- Unsupported explicit bucket catalog version, or explicit use of a bucket
  introduced after the effective catalog version.
- Duplicate YAML keys, YAML aliases, or merge keys in v8 policy files.
- A destination that mixes concise `send` and advanced `routes` policy forms.

### 9.2 Runtime producer errors

An invalid canonical event MUST be replaced by one correlated schema-failure event.
The invalid payload MUST NOT be serialized into the error message. Recursion MUST
be prevented if the schema-failure event itself cannot validate.

### 9.3 Redaction errors

Redaction errors follow the fail-closed rules in `04-redaction-contract.md`. The
record remains deliverable using a safer projection, and a bounded health signal is
emitted.

### 9.4 Exporter errors

Exporter errors update destination health, increment bounded metrics, and emit
rate-limited mandatory audit transitions. They MUST NOT be recursively exported to
the failing destination without rate and recursion guards.

## 10. Availability and Concurrency

- Producers MUST read one immutable active policy snapshot without holding a global
  configuration lock across I/O.
- Every optional log/trace destination, including JSONL and console, MUST use a
  bounded destination-owned count-and-byte queue. Prometheus remains pull-based,
  and metric SDK readers/exporters retain their documented SDK backpressure model.
- Queue admission is nonblocking and drops the newest attempted enqueue when
  either limit is full; it MUST expose bounded dropped counts without evicting
  older queued work.
- SQLite writes MUST use bounded transactions and respect context cancellation.
- Shutdown MUST stop intake, flush bounded queues within a configured deadline,
  record final health when possible, and close providers in dependency order.
