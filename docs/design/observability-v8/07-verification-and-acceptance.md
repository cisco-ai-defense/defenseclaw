# Verification and Acceptance

## 1. Verification Strategy

The implementation is accepted only when behavior is demonstrated at five levels:

1. Pure unit tests for taxonomy, collection, selectors, redaction, and retention.
2. Component tests for SQLite, each destination adapter, OTel processors/readers,
   and reload.
3. Contract tests for schemas, CLI/config parity, and migration.
4. End-to-end tests for representative operator configurations and producer flows.
5. Security, race, performance, and failure-injection tests.

Tests must validate outputs, not merely that functions returned no error.

## 2. Traceability Matrix

| Requirement | Required evidence |
|---|---|
| One primary bucket | Exhaustive producer classification test and schema rejection of zero/multiple buckets |
| Canonical record substrate | Version, exact payload union, immutability, bounds, deterministic JSON, exact correlation/provenance/field-class objects, registered identity, outcome, and P2/P5 builder-boundary tests in §3.4 |
| Separate collection controls | Unit and integration tests proving disabled log/trace/metric construction stops independently |
| Mandatory local floor | Tests for every floor event class with bucket logs disabled; built-in local row present and all optional destinations absent |
| SQLite coverage | One-row-per-collected-log integration tests without a source SQLite destination or catch-all route |
| Multi-destination fan-out | One collected log persisted once to implicit local SQLite and delivered independently once to each configured optional destination: JSONL, a Splunk fake, and a general OTLP fake |
| Capability, concise, and advanced routing | Omitted policy compiles to one all-bucket capability route; `send` compiles to one deterministic narrowing route; advanced send/drop ordering remains first-match-wins and destination-independent |
| Selector logic | AND across fields, OR within a field, wildcard rules, absent-field behavior, severity threshold |
| Per-destination redaction | Golden concise-send and advanced-route projections under none/sensitive/content/strict/legacy-v7/custom profiles |
| Immutable canonical record | Deep equality before/after all destination projections and race testing |
| Fail-closed redaction | Injected detector/parser/serializer failures and safe delivered projection/health result |
| Profile-faithful content | Under `none`, governed content is preserved only in schema-defined content fields; under redacting profiles, sensitive canaries are absent everywhere those profiles govern; metrics never contain content labels |
| Atomic reload | Invalid reload keeps old graph; valid reload swaps once and drains old exporters |
| Runtime v8 cutover | Target startup/reload and ordinary CLI mutation reject v7 with an actionable upgrade pointer; a repository allowlist proves all remaining v7 readers/writers live only in converter/preview, historical fixtures, rollback/recovery, or additive consumer projections, and fault injection proves no live fallback/provider/sink/bridge/direct OTel path exists |
| Automatic migration | Golden v7-to-v8 conversions, generated family selection, deterministic protocol splitting, metric-conflict rejection, legacy environment materialization, ancillary `.env` promotion/rollback, `legacy-v7`, complete pre-write validation, atomic write/backup, and retry/idempotence |
| Global retention | Fake-clock boundary tests across every history table and both databases |
| Preserve state tables | Reaper tests showing actions/snapshots/schema metadata remain |
| Finding semantics | Occurrence fields/remediation/evidence tests and explicit absence of synthetic workflow status |
| Compact/effective/reference config | Golden compact source, fully expanded masked effective view, and schema-generated reference parity |
| Comment preservation | CLI/TUI/setup mutations retain seeded ASCII/header/inline/route comments and ordering |
| Bucket evolution | Catalog-version tests prove future buckets remain in built-in local history and do not enter pinned optional-destination wildcards |
| Upgrade integration | One-command registered migration, ordinary confirmation/`--yes`, complete pre-write validation, exact-config backup/recovery, cursor semantics, and incompatible-start prevention |
| Rich trace contract | Golden agent/model/tool/retrieval/workflow/security graphs with exact families, parents/links, events, status/outcome, fields, limits, and redaction |
| Trace sampling invariants | Explicit collection-before-construction, unsampled-route, durable-log, parent-coherence, safe-decision-debug, and targeted-canary tests in section 9.2 |
| Simplified telemetry schemas | One logical registry with a small focused authoring set generates deterministic bundle/catalog/docs/constants/fixtures/projections; every current field has a migration disposition |
| Deterministic registry inheritance | DAG, diamond, body-role transposition, non-weakening requiredness, conditional-clause, restrictive-constraint-intersection, and zero-unresolved-family tests; every generated consumer uses the same materialized resolved-use contract |
| Generated-builder source authority | The closed P-070 mandatory-rule catalog, structured types/bindings, Go symbol policy/table, and explicit example builder contexts compile with P-069 into one immutable enriched `CandidateRenderIndex`; builder, bundle, fixture, and exact seven-file all-or-nothing acceptance tests consume that index without inference or partial authority |
| Public-schema baseline integrity | Full-commit/tree/blob/source/canonical digest tests; exact 21-path identity/dialect/reference inventory; lossless numeric lexemes; strict JSON/depth/ref rejection; typed field/open-object coverage; generated-marker recursion rejection; pre-cutover refresh and explicit new-epoch tests |
| Agent lifecycle and dashboard compatibility | PR #403 root/subagent lifecycle, execution, phase, operation, decision, real-time completion, and missing-data goldens plus PR #412 metric/label/bucket/cadence, UID, query, live inventory, and source/packaged dashboard checks |
| Push network safety | HTTP JSONL, OTLP, and Splunk tests cover every prohibited address class, guarded dialing/DNS rebinding, disabled redirects, failure isolation, and narrowly bounded private/CGNAT opt-ins |
| Bounded destination delivery | Every queue-backed destination resolves count and byte defaults, drops the newest attempted enqueue when either limit is full, bounds encoded push batches by count and bytes, and remains isolated under saturation |
| Splunk projection-only compatibility | Every HEC alias is equal to a value in that destination's already-redacted projection or absent; raw/canonical/producer/other-destination fallback is impossible |

Decision-level coverage for `D-001` through `D-024`, `S-001` through `S-012`, and
`P-001` through `P-070` is normative in `13-decision-traceability.md`; this matrix is
the requirement-level summary rather than a competing decision index.

## 3. Taxonomy Tests

### 3.1 Catalog completeness

Tests MUST enumerate:

- Every current `gatewaylog.EventType`.
- Every current `audit.Action`.
- Every registered span family.
- Every metric instrument.
- Every inbound OTLP normalization output.
- Every normalized projection writer.

The test fails when a new item lacks a bucket, stable name, signal, schema/field
classification, and mandatory-floor decision.

### 3.2 Boundary cases

Required cases:

- A guardrail evaluation with no findings and allow decision.
- A guardrail evaluation with a finding but no enforcement.
- A guardrail block caused by policy without a security finding.
- A tool request, its evaluation, its finding, and its block as separate records.
- A clean asset scan with no findings.
- A scan with multiple findings.
- Failed quarantine with no asset lifecycle transition.
- Successful quarantine with linked enforcement and lifecycle records.
- Config reload rejection producing compliance activity plus platform-health state.
- Administrative authentication failure as mandatory `compliance.activity`,
  inbound telemetry authentication failure as mandatory `telemetry.ingest`, and
  destination credential rejection as mandatory `platform.health`, each with the
  owning bucket's ordinary logs disabled and no credential value persisted.
- AI Defense finding represented as `security.finding` with `source: ai_defense`.
- Every current `WARN`/`WARNING` producer normalizes to security severity `MEDIUM`
  (optionally `log_level: WARN`); severity threshold tests use only the canonical
  five-rung ladder.
- Clean guardrail/judge `NONE` normalizes to canonical `INFO`, retains clean-decision
  semantics, validates successfully, and compares at the `INFO` route threshold.
- Two identical finding observations create two occurrence IDs and two immutable
  rows; query aggregation may group them but logging does not deduplicate them.
- Finding schema rejects `status: open`. Acknowledge/dismiss updates only the
  mutable alert projection and creates one canonical-`INFO` compliance event; the
  finding row and severity remain byte-for-byte unchanged.
- Acknowledgement/dismissal tests require operation ID plus expected projection
  version and cover applied, `no_change`, stale-version `rejected`, and
  operation-ID/payload-conflict outcomes. Exact retries return the original event ID
  and result without changing event count, version, actor, or timestamps.
- A legacy `ACK` severity row materializes acknowledgement state, preserves raw
  `ACK` only as provenance, does not participate in severity ranking, and does not
  invent the lost original severity.
- Remediation precedence is producer value, then versioned catalog template, then
  absent. Tests cover each branch, source/catalog provenance, and prove no advice or
  applied-fix claim is fabricated.

### 3.3 No-duplication assertions

For each representative action, assert exact event counts and IDs. In particular,
the old audit-to-gateway bridge and direct writer fan-out must not produce a second
copy after producer migration.

### 3.4 Canonical record substrate

P2 generic-substrate acceptance MUST include all of the following. The bullets that
explicitly name generated family ownership are completed by P5-WP02 rather than by
a parallel hand-authored P2 registry:

- The P2 constructor emits only integer `schema_version: 1` and integer
  `bucket_catalog_version: 1` and exposes no caller-controlled version field. P5
  generated envelope schemas reject strings, zero, negative, and unsupported future
  versions before routing.
- Table-driven union tests prove logs and traces require `body` and reject
  `instrument_data`, metrics require `instrument_data` and reject `body`, and every
  signal rejects both-arms-present and neither-arm-present records.
- Constructor-input mutation, returned-value mutation attempts, concurrent
  destination projection, redaction, and repeated serialization leave a deeply
  equal canonical record unchanged and expose no mutable aliases.
- Boundary fixtures cover exactly 32 levels, 8,192 members/elements, 1 MiB of
  deterministic payload bytes, 4 MiB of complete record bytes, and every envelope
  text bound in 02 §3.3, plus one-over failures. Cycles, invalid UTF-8, non-string
  keys, non-finite numbers, and implementation-specific values fail without
  returning a partial record or echoing payload or rejected metadata contents in
  errors.
- Golden deterministic-JSON vectors cover differently ordered nested maps, arrays,
  Unicode keys and values, escaping, integers, high-precision and large-exponent
  finite decimal numbers, and negative zero. Exact envelope goldens prove recursive
  lexical object-key order. Repeated, concurrent, and cross-language implementations
  produce byte-identical output independent of map iteration, locale, process, or
  destination; no decimal is silently rounded through binary floating point.
- Correlation accepts the empty object and every §3.1 optional nonempty-string key,
  while rejecting unknown keys, null/numeric values, and invented IDs. Provenance
  accepts exactly its four required and two optional fields and rejects missing,
  extra, malformed-token, nonpositive-registry-version, negative-generation, and
  non-lowercase-hex cases.
- P2 registered-identity tests accept catalog buckets plus exact registered
  signal/name membership and stable source/producer tokens, and reject unknown or
  signal-mismatched identities before any route or exporter observes the record.
  P5 generated-registry tests add exact event-to-bucket ownership.
- P2 accepts every globally canonical outcome and rejects unregistered synonyms.
  P5 generated family tests enforce each log/span family's required, optional, or
  forbidden contract, accept only its exact registered subset, and reject missing
  required or family-inapplicable outcomes. Metric families reject authored
  envelope-outcome contracts; metric outcome labels accept only canonical values
  before explicit compatibility projection.
- Field-class tests cover all eight classes, JSON Pointer escaping/resolution,
  unknown/conflicting/unresolved entries, exact non-inherited leaf coverage, and
  rejection when any dynamic field remains unclassified. Tests prove ordinary
  callers cannot assert schema derivation. P5 generated-builder tests prove complete
  schema derivation, materialize concrete payload-rooted pointers for every leaf,
  and reject explicit/schema conflicts and envelope-prefixed pointers.
- Producer-builder tests prove structural JSON property names come only from the
  owned schema vocabulary. Dynamic map keys, labels, tool-argument names, and
  provider-controlled names are encoded as classified string values; P5 generated
  builders reject any schema that would place them in property names.
- Mandatory-floor tests prove producer kind/key/typed facts are resolved through
  the reviewed catalog; public inputs cannot forge `mandatory`. Disabled ordinary
  events never invoke a builder. A floor build accepts no ordinary body, carries the
  internal floor marker and exact minimal placeholder schema, reaches SQLite only,
  and is rejected if it contains or is replaced by an ordinary content, evidence,
  credential, prompt/tool, or judge-body payload. An enabled mandatory event uses
  one ordinary record and never emits the floor placeholder as a duplicate.
- Builder-boundary tests prove the generic P2 constructor accepts already-typed
  JSON payload objects and the current classified-log adapter terminates at that
  constructor. P2 contains no hand-authored detailed trace/metric family builders;
  P5-WP02 generated family builders terminate at the same constructor and own
  family required/conditional fields and lower bounds.
- Structural-contract parity tests load the one registered contract and compare its
  runtime binding, versions, limits, stable-token/provenance patterns, outcome and
  field-class vocabularies, correlation keys, and signal arms with the existing Go
  record implementation. Missing/duplicate contracts and any mismatch fail before
  output generation.
- The generated envelope and builder accept exactly the same complete records.
  Table tests cover log bodies, snake_case trace bodies, and the minimal metric
  `{value, attributes}` observation, and reject repeated metric instrument metadata,
  forbidden signal-envelope state, unknown members, and both/neither payload arms.
- Generic-record tests independently reject metric severity, log level, and
  envelope outcome before serialization. The log-only schema-derived constructor
  accepts only a non-nil private generated-family contract whose exact registered
  log identity matches the record and whose mandatory state was catalog-derived;
  it accepts no raw mandatory boolean, and a trace or metric cannot acquire
  mandatory/floor authority through it.
- P-070 generated-builder boundary tests resolve mandatory state only by OR-ing
  the closed catalog rules whose exact typed facts are true. Every rule, signal
  restriction, condition-fact reference, and mandatory-fact reference is
  exhaustive; an unknown/missing fact or caller-supplied `mandatory` value fails
  before the P2 constructor is called.
- Structured-value tests prove every registry binding resolves to a bounded typed
  shape and canonical encoding. The sole recursion exception is the compiler-owned
  non-null `gen_ai.canonical_json` sealed union; dynamic members remain ordered
  typed entries internally and flatten to native JSON only at encoding. No public
  generated input, constructor, field, or method admits `map[string]any`, `any`,
  `interface{}`, raw `Value`, or a generic catalog lookup.
- Go symbol and generated-output tests prove the closed policy plus reviewed
  overrides produces one complete collision-free `GoSymbolTableIR`. The generated
  builder kernel and all renderers consume the same immutable
  `CandidateRenderIndex`; the exact seven generated Go files in 12 §5.2.3 are
  accepted together or none is accepted.

## 4. Configuration Tests

### 4.1 Defaults

Verify:

- Every unspecified bucket: logs, traces, and metrics true with catalog
  `redaction_profile: none`; logs persist locally unredacted.
- Schema-defined model/tool/message/evidence/error/path content supplied by a
  producer is captured and preserved by default with no hidden second content gate;
  genuinely absent content remains `reported=false`.
- Unspecified `model.io`, `tool.activity`, and `diagnostic` follow the same
  full-fidelity default rather than a hidden exception.
- With no optional destination, nothing is remotely exported. A present enabled
  destination with no `send`/`routes` receives all buckets in the effective
  reviewed catalog version, unredacted, and exactly its capability signals: logs
  for log-only kinds, metrics for Prometheus, and logs/traces/metrics for general
  OTLP. Newer runtime buckets remain collected and locally persisted under the
  full-fidelity default but are not remotely wildcard-routed until review.
- Bucket overrides affect only named fields and inherit the remainder.
- Effective redaction resolves concise-send/advanced-route, then bucket, then
  configured global default, then built-in `none`.
- Built-in local SQLite exists without source boilerplate and retention defaults to
  90 days.
- A present optional destination defaults to enabled.
- OTLP selected route signals automatically enable their transports; omitted policy
  selects all three transports.
- Omitted trace/metric policy resolves to parent-based always-on sampling for
  collected traces and 60-second delta metrics; the bundled collector converts
  delta sums to cumulative Prometheus series and Grafana advertises at least 60s.
- Omitted `batch` on JSONL, console, Splunk HEC, HTTP JSONL, and OTLP resolves to
  a 2,048-record/67,108,864-byte isolated queue. Push kinds additionally resolve
  to 512 records/8,388,608 bytes/5,000 ms per batch, except the documented
  Galileo 1,000 ms delay. Normal source YAML need not spell out these defaults.

### 4.2 Invalid configuration matrix

Startup/reload validation MUST reject:

- `kind: sqlite` under source `destinations`.
- Operator-authored destination name `local-sqlite`.
- `enabled`, `send`, `routes`, or `redaction_profile` under `observability.local`.
- Duplicate destination/route names.
- Unknown destination kind, bucket, signal, selector, profile, detector group, field class,
  or transformation mode.
- Empty selector value list.
- Wildcard mixed with other values.
- Unsupported signal for destination.
- A destination mixing `send` and `routes`.
- Concise `send` containing advanced selectors, exclusions, or route-only fields.
- `signal_overrides` naming a signal not selected by `send`/`routes`.
- Custom profile attempting to extend another custom profile; single-level
  inheritance makes cycles unrepresentable.
- Custom profile extending or aliasing `none`.
- Custom profile extending or aliasing immutable `legacy-v7`.
- Empty effective detector groups for a `detect` mode, `credential: preserve`, or
  `preserve` on a dynamic content/reason/evidence/error/path class, or any custom
  mode other than `preserve` for metadata/schema-approved identifiers.
- Any custom redaction-profile member other than `extends`, `detectors`, and
  `field_classes`, including size, scan, candidate, match, excerpt, report, key
  material, or key-path knobs; equivalent v8 environment inputs are also rejected.
- Enabled OTLP destination with no selected signal or resolved endpoint.
- A nonempty OTLP `signal_overrides.<signal>.path` with `grpc` or
  `grpc/protobuf`; path overrides are HTTP/protobuf-only.
- Legacy `signal_transports` or a transport-level `enabled` flag.
- Invalid protocol, TLS, listener, queue, batch, interval, sampler, or retention.
- A queue count outside 1..65,536, queue bytes outside
  4,198,400..268,435,456, push batch count outside 1..8,192, push batch bytes
  outside 4,263,936..67,108,864, or scheduled delay outside 1..600,000.
- Push batch count greater than queue count, push-only batch fields on
  JSONL/console, or any `batch` field on Prometheus. Queue bytes count projected
  payloads and batch bytes count encoded requests, so no ordering between those
  independently bounded byte fields is inferred.
- Invalid/unsafe push endpoint, inline URL credentials, prohibited resolved address,
  or unsupported `network_safety` field/value.
- Unknown trace semantic profile, incompatible compatibility-alias setting, or
  trace limit outside safe/family-required bounds.
- Arbitrary event names outside the telemetry registry; registry-declared dotted
  IDs and canonical snake_case lifecycle/compatibility names such as
  `session_start` and `hook_decision` remain valid.
- Secret reference that cannot be resolved for an enabled destination.
- Legacy `otel`, `audit_sinks`, or `privacy.disable_redaction`.
- Legacy `observability.connectors[*].audit_sinks` while continuing to accept the
  separately typed notification-only `observability.connectors[*].webhooks` child.
- Unsupported explicit bucket catalog version or a bucket newer than the effective
  version.
- `bucket_sets`, `@set`, `observability.from`, or any include/source indirection.
- Duplicate YAML keys, merge keys, aliases, oversized source, or excessive parsed
  nodes/routes/profiles.

Validation errors must identify the YAML path and corrective action without printing
secret values.

### 4.3 Configuration UX and source tests

- An absent observability block and `observability: {}` are both valid and produce
  identical full-fidelity collection plus unredacted local-log defaults.
- A bare logs-only, Prometheus, and general OTLP destination each compile to the
  documented capability-default send without authoring route boilerplate.
- A concise Galileo destination with no `enabled`, route wrapper, route name,
  selector object, or signal-enable map compiles to the same effective graph as its
  explicit advanced equivalent.
- Source validation rejects generated effective-only fields and the reserved
  `local-sqlite` destination identity.
- Minimal source resolves to the documented full-fidelity defaults.
- `config show --source` identifies the source file and masks secrets.
- `config show --effective` expands defaults, generated local storage, concise send
  routes, derived OTLP transports, presets, profiles, and wildcard catalog
  membership with provenance.
- Reference YAML/Markdown/JSON Schema are generated from the same schema and CI
  detects drift.
- `observability plan` produces an accurate bucket/signal/destination matrix.
- `config validate` performs no network I/O; an explicit destination test defaults
  to a non-mutating handshake. A backend-required write is refused unless the
  operator supplies `--write-probe`; the resulting marked synthetic non-sensitive
  probe uses a dedicated backend test namespace when supported, is written directly
  and exclusively through the named adapter, and has credentials/response bodies
  masked. The probe does not enter ordinary collection, routing, SQLite history,
  any other destination, or dashboard counts; a separate local-only
  `compliance.activity` record audits the test attempt and outcome without the
  probe body.
- Invalid source updates retain the previous runtime graph.
- Custom resource attribute boundary tests cover 64/65 entries, 128/129-byte
  ASCII keys, 1/1,024/1,025-byte UTF-8 values, exact/over-16-KiB aggregate data,
  blank/control/invalid-UTF-8 values, secret/path heuristics, registered and alias
  collisions, deterministic bytewise order, detached snapshots, and value-free
  errors in both Go and Python.
- Mutating an unrelated scalar/list preserves seeded ASCII header, section comments,
  inline comments, route comments, order, style where safe, permissions, and lock
  semantics.
- Full normalization is performed only by an explicit command.
- Legacy/standard observability environment variables do not silently override an
  explicit v8 policy; explicit secret references and documented bootstrap variables
  resolve with masked provenance.
- Go and Python validators accept/reject the same v8 fixtures, including exact
  detector groups `pii`, `credentials`, and `secrets`; each rejects an unknown
  detector group and unmodeled observability field.
- Migration goldens cover top-level `audit_db`, `judge_bodies_db`, `otel.logs`,
  gateway JSONL/console, JSONL rotation, `DEFENSECLAW_JSONL_DISABLE`,
  `DEFENSECLAW_DISABLE_REDACTION`, display-only `DEFENSECLAW_REVEAL_PII`, and
  connector audit-sink/webhook coexistence; explicit/absent
  `guardrail.retain_judge_bodies`, every recognized
  `DEFENSECLAW_PERSIST_JUDGE` off spelling, and true/false/absent
  `ai_discovery.emit_otel` preserve their effective behavior.
- CLI/TUI/API policy mutations persist source YAML before runtime reload; restart
  proves no in-memory-only policy drift.

### 4.4 Bucket catalog evolution

Use catalog fixtures v1 and v2 where v2 adds a synthetic sensitive bucket:

- A v1 config on a v2 runtime collects the new bucket’s logs to the built-in local
  store only.
- A v1 optional-destination wildcard does not match the v2 bucket.
- The generated local catch-all does match the v2 bucket.
- Doctor, TUI, and `observability plan` identify the unreviewed bucket.
- Explicitly naming the v2 bucket while declaring v1 is invalid.
- Advancing to v2 changes the effective route plan only after a preview/write
  action and creates compliance activity.
- Concise sends and advanced routes cannot explicitly reference the new bucket until
  the catalog version advances.
- Historical v1 records retain their original bucket IDs.
- A deprecation keeps the old ID valid/routable for its declared window and emits a
  lint/doctor warning; early removal is rejected.
- A split allocates new bucket IDs, preserves the old ID for historical records and
  compatibility input, and requires an explicit catalog-advance preview showing
  every affected optional route; historical rows are not rewritten.
- A merge follows the same rule: new records use the reviewed successor, old IDs
  remain queryable, aliases carry a removal version, and pinned wildcards do not
  broaden silently.
- Catalog validation rejects rename-by-deletion, split/merge without lifecycle and
  migration metadata, an alias removed before `removed_in`, and reuse of a retired
  bucket ID.

## 5. Routing Tests

Use a table-driven fake destination suite with these minimum cases:

| Destination policy | Record | Expected |
|---|---|---|
| logs-only kind, no `send`/`routes` | any collected log | deliver unredacted; traces/metrics unsupported |
| Prometheus, no `send`/`routes` | any eligible metric | expose full metric; logs/traces unsupported |
| general OTLP, no `send`/`routes` | any collected log/trace/metric in the effective reviewed catalog version | deliver all three signals for that version; logs/traces use `none` |
| explicit concise `send` on OTLP | unselected bucket/signal | no delivery, proving explicit policy replaces rather than augments capability default |
| concise `send` selects finding logs | security finding | one generated send route delivers |
| `security.finding send`, `* drop` | security finding | send |
| `diagnostic drop`, `* send` | diagnostic | drop |
| `* send`, `diagnostic drop` | diagnostic | send, proving first match wins |
| bucket + source + connector | all fields match | send |
| bucket + source + connector | one field differs | unmatched |
| sources `[a,b]` | source b | send, proving OR |
| `min_severity: HIGH` | HIGH/CRITICAL | send |
| `min_severity: HIGH` | absent/MEDIUM | unmatched |
| no route matches | any | no delivery |

Fan-out test: one `security.finding` log is persisted locally and matches JSONL,
Splunk, and OTLP; it must appear once in each with the same record/correlation IDs
and each destination policy’s expected redaction.

Queue test matrix for each queue-backed kind:

- Omitted `batch` resolves to the exact count/byte defaults without adding source
  boilerplate; effective output shows their compiled provenance.
- With capacity for two records, enqueue A and B, then attempt C. C is dropped,
  A/B remain FIFO, SQLite still contains all three, and other destinations receive
  their matching records.
- Repeat with record count below the limit but projected bytes at the byte limit;
  the next item is dropped without transient overshoot or oldest-item eviction.
- Maximum accepted values allocate only after complete validation; maximum+1 and
  invalid cross-field relationships fail before worker/queue construction.
- Push packing stops before both the count and encoded-byte ceilings. Separator,
  HEC wrapper, and protocol-envelope bytes are included; no intermediate request
  exceeds the configured byte ceiling.
- A reload leaves already queued immutable bytes under the old generation/profile
  while new records use the new limits and projection.

Collection test: disable the same log at bucket collection; it appears nowhere.
Repeat with a mandatory compliance record; it appears once in the built-in local
store only.

## 6. Redaction Tests

### 6.1 Detector corpus

The Go detector engine consumes one detector-catalog-v1 golden corpus and produces
the expected candidate acceptance, byte intervals, detector IDs, and replacements.
It contains positive, near-miss, boundary, Unicode-adjacent, multiline, oversized,
and overlap cases for all 14 IDs:

| Detector | Required positive and exclusion cases |
|---|---|
| `credentials.api_token` | Every literal provider prefix, minimum/maximum/exact suffix length and alphabet; reject short/long, wrong alphabet, missing boundary, similar prefix, and public/test identifiers. |
| `credentials.private_key` | Every allowed matching PEM label and multiline body; reject public keys, certificates, mismatched labels, invalid base64 lines, incomplete blocks, and >64 KiB blocks. |
| `credentials.authorization` | Every allowed scheme and case variation; select only credential material when split; reject empty/unknown schemes and header names in prose. |
| `credentials.cookie` | Every cataloged sensitive member among safe members; reject attributes, empty values, and noncataloged members. |
| `credentials.connection_string` | Every cataloged scheme with userinfo/query/member secret; reject host-only, unsupported/opaque, empty-password, and malformed DSNs. |
| `secrets.assignment` | Every assignment key/separator/case; reject missing/empty values, null/Boolean, placeholders, and unassigned prose. |
| `secrets.high_entropy` | Exact 20/256-byte boundaries and all alphabets above threshold; reject 19/257 bytes, low entropy/repetition, UUID/trace/span/record IDs, approved hashes, dictionary placeholders, and credential-detector winners. |
| `secrets.url_query` | Every key with percent-encoded/raw values, repeated keys, and mixed safe keys; reject empty/unlisted keys and malformed URI/percent escapes. |
| `secrets.cloud_account_identifier` | Labeled/catalog-position AWS, Azure, and GCP values; reject unlabelled numbers, UUIDs, and DNS-like strings. |
| `pii.email` | Maximum local/total/label boundaries and reserved synthetic domains; reject Unicode/IDNA, missing host dot, numeric/invalid final label, and overlong parts. |
| `pii.telephone` | Separated North American and `+1` variants, parentheses, and each separator; reject unseparated, mixed separator, invalid area/exchange, extension, date/version, non-`+1`, and longer run. |
| `pii.national_identifier` | Valid synthetic SSNs; reject `000`, `666`, `900`-`999` areas, `00` group, `0000` serial, repeated/example, unseparated, and embedded values. |
| `pii.payment_card` | 13-19 digit Luhn-positive synthetic candidates with each separator; reject Luhn-negative, identical digits, mixed separators, boundary violations, and dates/telephone shapes. |
| `pii.ip_address` | IPv4/IPv6 values accepted by Go `net/netip.ParseAddr`; reject leading-zero IPv4, ports, CIDRs, zones, malformed, and boundary violations. |

Overlap goldens prove transitive overlap clusters replace their complete union
without leaking lower-priority tails; token identity follows `credential > secret >
pii`, then catalog order, start, and length; adjacent winners remain separate. All
regex sources compile under Go RE2. Python and Go configuration/catalog parsers accept
the same version, groups, and member manifest, but Python does not duplicate the
detector executor. No fixture contains a live credential or real personal
identifier.

The machine catalog at
`schemas/telemetry/v8/redaction/detector-catalog-v1.yaml` validates against its
schema, generates the ordered Go catalog and Python constants, and has no generated
drift. Corpus assertions cover the exact input-context prohibition, original-byte
replacement/HMAC intervals for quoted and percent-encoded values, all parser bounds,
and every literal grammar/key/label set in 04 §6.2.

### 6.2 Structural cases

- Built-in profile goldens exhaust the 04 §3 matrix across all eight field classes:
  `none` preserves all classes without detectors; `sensitive` detects four dynamic
  text classes, hashes paths, removes credentials, and preserves metadata/IDs;
  `content` wholes those four classes, hashes paths, removes credentials, and
  preserves metadata/IDs; `strict` removes every non-metadata/non-identifier class.
  All three redacting profiles inherit all groups, while modes that do not use
  `detect` invoke no detector. Remediation text is always `reason`.
- Object `remove` omits the property; array `remove` writes `null`; both retain
  empty containers and array indices unless the exact empty-container leaf is
  removed. A nonempty container emptied solely by descendant removal is pruned
  recursively as an object property or becomes `null` in an array, so dynamic
  parent keys cannot remain as empty shells. The delivery `field_classes` map omits
  every removed object pointer and retains the pointer only when an exact classified
  leaf becomes array `null`; a descendant-pruned container `null` receives no
  synthesized class. Removed-field counters include both configured leaf removals
  and each additional property/slot removed by recursive pruning. The untouched
  canonical map remains complete.
- `preserve` retains all canonical scalar types; `detect` scans only strings;
  whole/hash transform strings and canonical Boolean/number text; null survives;
  binary-encoded input remains an explicitly classified string.
- Explicit P2 field maps resolve every leaf. Missing/stale/ambiguous/extra pointers
  fail the complete projection before value traversal with `classification_failed`;
  no detector/serializer sees a scalar and no guessed container token or partial
  output is delivered. Unknown dynamic members become `content`, and
  metadata-looking key names never upgrade trust. P5 generated resolvers produce
  equivalent decisions.
- Metric metadata/approved identifiers pass without detector invocation; any
  content, credential, unknown, or unresolved metric leaf rejects the sample.
- Canonical/projected payload, canonical 4,194,304-byte record, projected
  4,198,400-byte record, 4 KiB projection-headroom, depth/member/string limits are
  exercised at boundary and boundary+1. An exact-maximum canonical `none` record
  receives projection metadata successfully. A 256 KiB string is scanned; 256
  KiB+1 is wholly replaced as
  `oversize.CLASS` with no raw prefix/middle/suffix.
- Exactly 512 lexical candidates and 256 accepted matches in a field pass; the next
  candidate/match fails that whole field closed. Exactly 4,096 accepted record
  matches pass; exhaustion protects current/subsequent fields without undoing
  prior safe transformations. The 33rd safe-report entry is omitted while
  aggregate counts and `failures_truncated` remain truthful.
- Malformed JSON kept as an explicitly classified content string is treated as
  text. Invalid UTF-8 and injected matcher/validator/output-limit errors use the
  registered failure token and never partial raw output.

### 6.3 Properties

| Property | Acceptance evidence |
|---|---|
| Determinism/immutability | Map-order permutations serialize identically; race tests prove canonical records and two destination projections share no mutable memory. |
| Exact metadata | Projected JSON adds only the exact `projection` object; `raw`, `inspected`, `transformed`, and `failed_closed` transitions and all counters are golden-tested. Safe reports contain at most 32 value-free entries and caller-emitted health cannot recursively invoke the engine. |
| Token and hash parity | Go goldens verify exact detect, whole, oversize, failed-closed, byte length, 12-hex key ID, 16-hex truncated HMAC, and distinct domains. One Go/Python fixture contains every `hash-v1` success and expected safe error; neither language duplicates a malformed-input list. Equivalent Unicode/path/URI normalizations have equal `(class,key,hmac)` even when original-length fields make full tokens differ. Same type/value correlates across profiles/destinations; different type/domain does not. |
| Key custody | Fresh writable startup atomically creates exactly 32 random bytes at `${data_dir}/redaction-correlation.key` mode 0600. Symlink, non-regular, wrong owner, group/other bits, wrong length, interrupted create, concurrent create, and read-only cases are tested. `none` works without a key; every redacting mode fails affected data closed with `key_unavailable`; no YAML/env/path override or unkeyed fallback is accepted. Rotation changes key ID/future tokens, audits safe IDs, and leaves history unchanged. |
| Trusted idempotence | Same-engine/profile/key/catalog reprojection is an equal deep clone. Changed engine/profile/key/catalog is rejected as `projection_context_mismatch`, and the caller reprojects the canonical `Record`; no projection retains hidden raw data. Token-shaped user input is untrusted and processed. Only exact `legacy-v7` placeholders receive the scoped compatibility exception. |
| Legacy extraction | Pure v7 helper goldens cover string/entity/content/reason/evidence, long-value threshold, spoofing, repeat application, and absent/present evidence coordinates. Tests prove no helper reads environment or mutable `DisableAll`/reveal state and no coordinates are invented. |
| Path/URI parity | Shared success/error goldens cover the pinned Unicode-13.0 repertoire and rejected newer/unassigned scalars; POSIX, Windows drive-relative/absolute, UNC with/without share and root-crossing parents; opaque/hierarchical/invalid URI, encoded dots after percent normalization, invalid escapes, userinfo, duplicate/query order, fragment, zero-padded HTTP/HTTPS defaults, and preserved nondefaults. Windows drive recognition wins over URI parsing. |
| Reporting truth | Producer-present data keeps `reported=true` under partial/whole/hash/remove/oversize/failure; absent data stays `reported=false/not_reported`. P5 maps every operation to the 11 §12.2 state without fabricating content. |
| Profile fidelity | Injected detector/parser/serializer/key failures under every redacting profile protect the field, never switch to `none`, and preserve independent successful destinations. Intentional `none` skips detectors but retains schema/type/size/serialization enforcement. |

### 6.4 Canary test

Inject unique canary values into prompt, response, tool arguments, tool results,
evidence, reason, error, path, headers, and unknown dynamic fields. Search all
captured outputs, SQLite tables, trace attributes/events, metrics, health errors,
JSONL, and fake remote requests. In the default `none` case, canaries appear only in
the schema-defined content fields delivered to local storage and capability-default
destinations; they never become metric labels, resource attributes, headers, or
unrelated wrapper fields. Repeat with `sensitive`, `content`, and `strict` overrides
and prove their projected outputs contain no prohibited canary while a parallel
`none` destination remains unchanged.

## 7. SQLite and Projection Tests

- Fresh database migration.
- Upgrade from representative historical schema versions.
- One event-history row for every collected log.
- Correct bucket/event/source/profile/mandatory/provenance columns.
- Correct record schema and bucket catalog versions for historical interpretation.
- Correct redacted `payload_json`, exact stored `projected_record_json`, unchanged
  v7 `schema_version`/`content_hash` provenance semantics, and distinct
  `record_schema_version`/`projection_hash` values; verification by record ID/range
  recomputes the projection hash/HMAC from stored bytes
  without returning content.
- SQLite rejects a projection whose metadata profile differs from the effective
  local route profile passed by the compiled runtime graph.
- Atomic event plus required projection insert.
- Projection failure rollback/degraded behavior.
- Projection, signing, unsigned, and SQLite-write health callbacks run only after
  their originating transaction ends and Store lifecycle ownership is released. A
  reporter that queries, writes through, or closes the same single-connection Store
  completes without deadlock and cannot change the committed/rolled-back event
  result. A blocked/reentrant reporter plus concurrent signed recovery and a later
  unsigned commit preserves commit-ordered state, bounded dispatch, and the later
  unsigned transition under the race detector.
- Concurrent readers and writers under WAL.
- SQLite initialization and disk/write failure behavior.
- Judge-body database initialization is required and fatal when capture is enabled
  or cutover work exists, is skipped safely when capture is disabled with no
  cutover work, and always uses the shared retention age rather than a second age.
- Existing scan, alert, egress, activity, and judge query compatibility.
- Mutable alert acknowledgement projection remains separate from immutable finding
  and event history. Two different commands racing from the same version yield
  exactly one applied `N -> N+1` transition and one stale-version rejection; a
  controlled transaction order proves the first committed compare-and-swap wins,
  with one immutable compliance event per first-seen operation and no finding-row
  mutation.
- Per-alert applied operation receipts form a gap-free version sequence regardless
  of equal or skewed timestamps. Reconciliation repairs a missing/stale projection,
  ignores rejected and `no_change` receipts for state replay, preserves the legacy
  baseline provenance, accepts a missing age-reaped audit event, and fails closed
  with mandatory health on a receipt gap/conflict, projection ahead of receipts, or
  a retained audit event that contradicts its receipt.
- Reaping every alert compliance event, or only a prefix, leaves receipt-based
  reconstruction and the next `N -> N+1` transition valid. Exact retry after event
  deletion returns the original result/event ID/timestamp and does not recreate
  history. A previous-release `ACK` written after the original v8 migration is
  baselined on the next startup before it can be reaped.
- A first-seen operation against a missing identifier or non-finding v8 event is
  rejected without an operation receipt, compliance event, or projection; the same
  target remains eligible after event retention when protected alert state/receipts
  exist.
- A generic unbucketed v7 audit row with canonical severity is rejected. Only the
  explicit legacy `alert` action or an action with a fixed `security.finding`
  classification is eligible before protected state exists; a rollback-era `ACK`
  baseline remains eligible without guessing erased provenance.
- Command fingerprints use the stable correlation key and a versioned,
  domain-separated HMAC-SHA-256 encoding. Tests prove that the protected receipt
  changes when any normalized command field changes, that low-entropy raw actor
  values cannot be recovered by comparing an unkeyed digest, that key
  unavailability fails closed, and that no fingerprint appears in the canonical
  event payload or an export projection.
- No raw judge body in ordinary event/projection tables.
- New and migrated DB files preserve required owner/managed permissions, reject
  untrusted/symlinked paths, and never widen existing permissions.
- Unix tests reject a sticky world-writable immediate parent while allowing that
  directory only as an ancestor of an owner-only parent, and verify SQLite
  `-wal`/`-shm` files have no group/other access.
- Windows tests reject untrusted owners, permissive or inheritable read/write
  DACLs, mutable ancestors, and leaf/parent reparse points; compile-only coverage
  is not a substitute for the platform ACL test lane.
- Disk-full/quota failure changes health safely and never causes a raw remote
  fallback.
- Per-projection HMAC verifies after redaction, differs for differently redacted
  projections, records key identity, and reports unsigned state when no key exists.
- Integrity documentation/tests do not imply deletion-proof or append-only storage.

## 8. Retention Tests

Use a fake clock; tests MUST NOT wait for wall time.

Required cases:

- Default 90-day cutoff.
- Row one nanosecond/second before cutoff is deleted.
- Row exactly at cutoff is retained.
- Row after cutoff is retained.
- `retention_days: 0` schedules no deletion.
- `retention_days: 0` produces the required persistent lint/doctor unbounded-capacity
  warning without exposing stored content.
- 1,001 eligible rows require two transactions with maximum batch size 1,000.
- Child findings deleted before parent scans with foreign keys enabled.
- All included event/evidence tables are covered.
- `actions`, `target_snapshots`, and schema metadata are preserved.
- Both legacy and separate judge-response tables are reaped.
- Judge-body migration copy is idempotent by stable ID, preserves exact body bytes
  and correlation, and never dual-writes. V8 startup cannot fall back to writing
  `audit.db` after cutover.
- Authorized export completes and verifies before purge. Cross-database retention
  deletes legacy copies first and authoritative rows second; injected failure after
  either commit resumes safely without reappearing or duplicating a body.
- Cancellation stops between batches.
- Reload from 90 to 30 days affects the next asynchronous run.
- Reload to invalid retention leaves the old policy active.
- Contention with a reader/writer does not hold one unbounded transaction.
- Failure emits one rate-limited health transition and preserves undeleted data.
- No automatic blocking VACUUM.

## 9. OTel Tests

### 9.1 Traces

- Disabled bucket creates no recording span/body work.
- Enabled bucket adds `defenseclaw.bucket`.
- Every span carries registered family/schema/source/config-generation metadata and
  truthful available correlations.
- Sampling and collection both apply.
- Destination filters work independently.
- Span attributes, events, links, status descriptions, exceptions, content aliases,
  and vendor wrappers are independently redacted per destination.
- Trace/span IDs remain stable across projections.
- The generation-owned end helper always ends the physical span. It reports
  success only when the sampled, recording, collected span is synchronously
  consumed under the same nonempty plan digest and config generation; rejected,
  duplicate, over-capacity, retired, cancelled, and parity-mismatched
  registrations leave no pending canonical record or encoded-byte ownership.
- Per destination, canonical-consumer and legacy-processor arms are an exact XOR.
  Names and child identities are unique, one callback fans out exactly once to
  every selected arm, a missing/mismatched canonical handoff never falls back to
  the legacy arm, and destination panics/failures do not suppress siblings.
- The pending handoff enforces both 2,048-record and 64-MiB exact-canonical-byte
  limits. Concurrent end, retirement, shutdown, duplicate identity, and panic
  tests prove terminal states cannot leak count or byte capacity.
- Physical/canonical parity covers trace/span/parent IDs, rendered name, exact
  start/end, kind, status, bucket/family/family-version/config-generation,
  canonical scope metadata, and every registered resource key; canonical-record
  validation separately fixes source and plan digest. The generated record owns
  canonical W3C trace state and the full OTLP flags word; the SDK callback may
  only verify exact parity and cannot recover or overwrite either value. Direct
  adversarial tests reject malformed/oversized/non-canonical tracestate, invalid
  numeric words, and reserved bits 10–31 on SDK-runtime-sourced spans. Canonical
  destination activation remains closed on the other requirements in section 9.1.
- Flush visits children in destination order. Shutdown first closes provider and
  callback intake, waits for already-entered callbacks, retires pending handoff
  state after that drain, and visits children in reverse order. Malformed partial
  construction still cleans both XOR arms once by pointer identity, and a timed-out
  or panicking OTLP exporter eventually closes its terminal-cleanup signal before
  generation-owned canary registration is released.
- Canonical traces keep IDs in envelope correlation and the rendered name in
  `span_name`; `traceId`, `spanId`, `name`, and other camelCase OTLP-JSON copies in
  `body` are rejected.
- One OTLP destination failure does not stop another.
- Golden trace trees cover bounded agent turns, model streaming/retry, tools,
  approvals, guardrail phases/judges/findings/enforcement, retrieval/workflows,
  scans, discovery, network, ingest, reload, export, and canaries.
- OTel status distinguishes successful security block decisions from control
  failures and blocked requested operations; technical errors include stable
  `error.type`.
- Missing token/content/timing fields are not fabricated; reported/state metadata
  distinguishes absent, preserved, redacted, truncated, and failed-closed values.
- Attribute/event/link/byte overflow follows deterministic priority and preserves
  required identity/outcome.
- Span, event, link, resource, and scope dropped-attribute/event/link counts survive
  canonical construction, independent redaction, general OTLP, and Galileo
  projection at their exact protobuf levels.
- Galileo retains current agent/LLM/tool eligibility and validates new
  retriever/workflow and judge-chat shapes without affecting general OTLP
  destinations.
- General OTLP derives OpenInference aliases for every family in the generated
  `openinference-v1` manifest, including embeddings, and no others. Tests prove
  exact kind and canonical input/output source bindings, route-redaction parity,
  W3C topology preservation, destination isolation, immutable results, and
  fail-closed behavior for malformed kind, alias collision, bucket mismatch, or
  generated capability drift. Unsupported canonical families remain ordinary
  generic OTLP spans and acquire no OpenInference claims.
- Activation coverage constructs the generated two-span root-agent/model canary,
  carries one runtime-graph lease coherently from start through canonical end and
  reload, migrates the PR #403 root/subagent/model/tool producers and Galileo
  projection, preserves the PR #412 Tempo/resource compatibility aliases, and
  proves the exact Boolean-marked generated pair retains its canonical
  `agent.lifecycle`/`model.io` families in Tempo but does not enter Agent360
  spanmetrics. The independent single-span `span.diagnostic.canary` family is not
  substituted for either member of that pair.
- Resource coverage proves 0/1/64 custom entries, exact key/value/aggregate
  boundaries, bytewise deterministic output, accessor mutation isolation, and
  content-free collision/secret/path/process-key failures. Every generated span
  family receives the same immutable resource set and exact field classes.
- Portable resource validation runs both ordinary JSON Schema and the generated
  `x-defenseclaw-dynamic-member-contract` semantic validator. Tests prove that
  schema-valid inputs still fail closed for a 65th custom member, aggregate UTF-8
  overflow, byte-versus-code-point overflow, normalized custom/custom collision,
  and whitespace-prefixed path or credential material; no destination accepts a
  record by treating the extension as descriptive-only metadata.
- `compatibility_aliases` true/false coverage proves the three documented aliases
  equal their canonical source or are absent across canonical records, SDK traces,
  OTLP logs/traces/metrics, Galileo, and reload generations. Handoff rejects any
  missing, changed, non-string, or extra physical resource member by exact-set
  equality and never falls back to a legacy arm.
- HTTP and gRPC protobuf tests prove custom resources survive general OTLP and
  Galileo projection without shared mutation; Galileo preserves resource-level
  dropped counts. OTLP log queues retain the resource snapshot of their owning
  generation across reload. Native Prometheus exposes no arbitrary custom labels;
  local Collector promotion rejects normalized-key collisions and does not make a
  custom key an Agent360/dashboard-required dimension.

### 9.2 Sampling

- With bucket trace collection disabled, no span, attributes, events, content body,
  or sampling work is constructed even if the process sampler would record it.
- With collection enabled and `always_off` or a deterministically unsampled ratio
  decision, a matching destination route exports nothing; changing the route cannot
  resurrect the span.
- A finding and an enforced outcome produced inside an unsampled trace still create
  their required durable SQLite log records, with correlation available when known.
- Parent-based tests prove an unsampled parent produces non-recording children and no
  orphan exports, while a sampled parent preserves one coherent trace ID and valid
  parent/span relationships across children and destination projections.
- Sampling decision/reason appears only in bounded safe diagnostic/health metadata;
  it contains no prompt, result, evidence, header, credential, or arbitrary error
  text.
- Ratio sampling applies to ordinary operations. Only the exact targeted canary
  operation bypasses it, carries the canary marker, cannot enable sibling/parent
  production spans, and is acknowledged only by its selected destination.

### 9.3 Metrics

- Disabled bucket records no measurement.
- Instrument registry is exhaustive.
- Allowed attributes are bounded.
- Content canaries never appear as labels.
- Prometheus and OTLP filters independently include/exclude instruments.
- Temporality/interval validation rejects incompatible configuration.

### 9.4 Logs

- OTLP log body and attributes derive from the route projection.
- Individual finding emission honors collection and routes.
- Severity mapping follows the canonical vocabulary.
- Clean guardrail/judge producer severity `NONE` maps to canonical `INFO`; `WARN`
  maps to `MEDIUM`; neither creates an extra canonical rung.
- Existing resource/correlation fields are preserved.

### 9.5 Inbound receiver

- The complete executable matrix is 15 section 10, `OTLP-A01` through
  `OTLP-A24`; every row is a release requirement, not an optional example.
- Logs, traces, and metrics with one exact generated binding normalize to the
  registered target bucket/family. Unknown and ambiguous identities have no
  generic/raw fallback.
- Collection is enforced before full family construction, SQLite persistence,
  derivation, or re-export, independently for every primary and derived target.
- Malformed input records safe telemetry-ingest rejection.
- Unknown attributes and bodies are dropped and counted; local exact field classes,
  generated builders, and central route redaction prove that no opaque decoded
  HEC/raw body bypass survives.
- Every imported occurrence gets a new local record ID and trusted local
  provenance. The original semantic resource instance remains distinct from the
  immediate forward-instance transport key; only the latter can suppress an exact
  local echo or populate local `OriginDestination`. The fixed four-hop matrix
  prevents cross-instance loops without trusting a remote destination name.
- Mixed-batch accounting has exactly one primary disposition per decoded leaf and
  retains the empty-success permanent-drop acknowledgement required to suppress
  retry storms.
- Native PR #403 spans preserve real topology and never fabricate missing
  lifecycle facts. Exact PR #412 Codex/Claude derivations preserve the two metric
  families, labels, token types, cadence, and local dashboard consumers without
  placing record/origin/hop/content values in metric labels.

### 9.6 Telemetry registry and generated schemas

- The logical registry’s focused authoring files validate together against the
  pinned OTel/GenAI registry dependencies and DefenseClaw extension rules.
- Normal registry generation performs no network access. Tests corrupt each
  normalized upstream snapshot digest and referenced
  name/type/shape/stability/source/version tuple in turn and require a closed
  failure before any output is emitted.
- OpenInference normalization accepts exactly the pinned Python package's trace,
  resource, version, and Reserved Attributes specification files. Instrumentation,
  example, test, and internal-documentation decoys are excluded; a missing or
  mismatched package version, malformed/duplicate table row, unknown type, or
  constant/table mismatch fails atomically.
- OpenInference scalar, primitive-list, scalar-union, indexed-prefix, and
  object-prefix shapes round-trip without implicit stringification or conversion of
  flattened structures into literal OTLP arrays/objects. Fixtures cover bare
  `metadata`, the resource-only project name, OTel-owned exception fields, and
  constants-only prefix components.
- The pinned overlap inventory is checked explicitly: dedicated GenAI wins the 60
  current core overlaps; deprecated transitions and active-identical definitions
  are distinguished; active conflicts fail; `gen_ai.request.top_k` has a reviewed
  `double`-to-`int64` migration disposition; and core-only deprecated GenAI fields
  cannot satisfy ordinary family references. Core retains ownership of compatible
  OpenInference `session.id` and `user.id` overlaps, and incompatible overlaps fail.
- Reordering upstream archive members produces identical snapshots, locks, and
  generated outputs.
- The machine-derived migration inventory covers every legacy instrument and its
  real SDK or replacement generated-builder callsite. Generated-only additions are
  declared once in the registry and are not copied into the migration inventory. Each canonical family's inherited
  labels, family-local `local-observability-v1` projection, and projected current
  label set compare exactly; an undeclared, missing, extra, dynamic, or silently
  dropped key fails. After generated per-family recorders replace current
  callsites, the bootstrap extractor is retired rather than becoming a second
  source of truth. Open string labels without an effective byte bound or ordinary
  2,048-tuple family cap fail; enum labels reject values outside their closed set.
- The high-cardinality application exception accepts only the six named Agent360
  native families, the two named GenAI client families, their exact
  canonical/projected labels, and the 2,048-tuple family limit. The separate
  derived spanmetrics exception accepts only its exact dimensions and pinned
  Collector cache/series limits. Moving an allowed label, adding a ninth native
  family, or omitting a limit fails. Ordinary metric families still reject high
  cardinality and content, credential, path, reason, evidence, and error classes.
- Every one of the 25 span name patterns compiles. Each placeholder resolves to a
  declared inherited low/bounded-cardinality metadata or identifier field; unknown,
  alias, content, path, credential, reason, evidence, error, and high-cardinality
  placeholders fail. Hostile path, address, PII, and unbounded strings never enter
  a span name.
- Registry inheritance resolves every group once in DAG order. Fixtures cover
  diamond de-duplication, attribute-to-body transposition, required/conditional/
  recommended/optional strengthening, identical and conflicting conditional
  clauses, compatible restrictive constraint intersection, empty/incompatible
  intersection, body-role crossings, log parent cardinality, and cycles. The real
  registry has zero unresolved family uses, and generated Go, Python, schema,
  catalog, redaction, and fixture outputs consume the same materialized tuple.
- Constraint-parity fixtures prove string-array enums and numeric/string patterns
  apply to each element, numeric enums retain typed membership even where JSON
  Schema equates `1` with `1.0`, and unanchored source patterns still require a
  portable RE2 full match for scalar and scalar/array union arms, including rejection
  of a trailing newline. Distinct pattern intersections, possessive quantifiers,
  Unicode shorthand classes, and Python-only Unicode escapes fail. Nested aggregate
  `max_items` cannot pass the named runtime gate merely because root `maxItems`
  passes public JSON Schema. Multibyte scalar and nested string-leaf fixtures also
  prove shape-aware scalar-raw/structured-canonical `max_utf8_bytes` and
  `max_item_utf8_bytes` remain explicit builder/runtime gates rather than
  unenforced JSON Schema annotations. Nested
  object fixtures make the same proof for root-zero `max_depth` and recursive
  `max_properties` when a safe root `maxProperties` subset still passes.
  Re-digested-view fixtures reject unknown/wrong-type constraints, scalar
  `min_items`, polymorphic `min_items > 1`, nonportable patterns, typed-enum swaps,
  invalid type/constraint combinations, normalizer-catalog/effective-map forgery,
  use-level weakening, and disagreement between direct refs, group resolution
  order, resolved copies, origin closure/order, dominant requiredness, or registered
  conditional IDs before candidate rendering.
- Conditional uses accept only the eight registered stable IDs. Seven catalog
  entries are independent `builder_fact` predicates. The eighth,
  `agent-reported-cost-available-v1`, is a `boolean_attribute` predicate derived
  directly from the required `defenseclaw.agent.reported_cost.present` input; it
  does not add an eighth condition-fact selector. True/false builder fixtures
  enforce required/forbidden or optional behavior, and the generated public
  schema exposes the enforcement annotation without pretending the conditioned
  value proves its own predicate. Unknown IDs, prose clauses, duplicate facts,
  a missing/nonrequired/non-Boolean source attribute, a false forbidden-field
  emission, and a true missing field fail.
- Additive trace-contract tests prove `user.id`, `defenseclaw.tool.id`, the
  reported-cost presence/value pair, and
  `agent-reported-cost-available-v1` retain their stable symbols and semantics.
  The five core runtime families—`span.agent.transition`,
  `span.agent.invoke`, `span.workflow.run`, `span.model.chat`, and
  `span.tool.execute`—all expose interaction and cost state. Builder tests prove
  false-plus-value is `forbidden_field`, true-without-value is `missing_required`,
  and reported zero succeeds. Projection tests prove no default `llm.cost.total`
  alias and prove `span.agent.transition` remains local-observability eligible but
  Galileo-ineligible without fabricated invoke-agent/provider/input/output data.
- Every `semantic_ref` resolves to one registered attribute/group or one closed
  compiler-owned dynamic-family contract. Type, normalization, field class, and
  sensitivity mismatches fail; unknown pseudo-references and hardcoded scope/link
  field lists outside the materialized registry fail drift checks.
- `agent-phase-v1` derives the exact four phase enums and code range `1..12`.
  Fixtures accept every registered pair, reject every mismatched pair and code
  zero, prove zero is reserved/non-emittable, and fail on reorder, rename,
  renumber, removal, duplicate, or a non-append-only addition.
- Every group declares `introduced_in`; deprecated/removed fixtures enforce the
  ordered lifecycle. A semantic-diff fixture changes a
  reusable parent and proves every affected resolved family requires the correct
  family-schema-version change; group inheritance cannot bypass versioning.
- Trace-structure fixtures cover exact IDs, outer identity/name ownership,
  snake_case body fields, start/end ordering, family kind/name/equality rules,
  status, resource, canonical scope, events, links, and span/resource/scope/event/
  link dropped counts at zero, maximum, and one-over. OTLP protobuf goldens prove
  schema URLs and every dropped count reach the correct level and typed values are
  never implicitly stringified.
- OTLP mapping mutation tests cover every span/resource/scope/status/event/link
  target and reject duplicate targets or a type-incompatible encoding. The exact
  AnyValue table covers Boolean, int64, bounded uint32-to-int projection, finite
  double, string, array, and object;
  null and implicit stringification fail.
- `span.workflow.run` uses exactly
  `workflow {defenseclaw.workflow.name}`. Missing, unbounded, high-cardinality,
  sensitive, and content-like workflow names fail before span construction, while
  Galileo and general OTLP projections retain the same rendered name. Galileo
  tests also reject a missing typed attribute and an attribute/rendered-name
  mismatch; no projector reverse parses or fabricates the attribute.
- Public-view baseline fixtures cover all twenty-one paths and both exact dialects;
  commit/tree/blob/source and domain-separated canonical digests; numeric lexeme,
  object-key, array-order, Unicode, line-ending, and trailing-newline stability;
  duplicate/lone-surrogate/nonfinite/depth failures; local and three-resource
  offline reference closure; unsupported nested/dynamic/recursive semantics;
  atomic rollback; same-epoch refresh; explicit new epoch; and rejection when a
  per-file marker or generated manifest identifies the source as generated.
- The closed normalizer catalog, defaults, overrides, and type applicability are
  tested in Go and Python from shared fixtures. Missing numeric bounds, removed
  effective bounds, invalid item/depth/property/UTF-8 limits, nonportable regexes,
  duplicate enums, wrong scalar types, and prose-only normalization fail.
- Every valid curated record has a complete exact registry-derived field-class map
  for all payload leaves. Missing, stale, extra, or wrong pointers fail; stable
  error codes remain metadata while dynamic error text follows the configured
  error-class transform.
- The P-070 `mandatory_rule_catalog` accepts exactly version 1 and its thirteen
  registered rules. Each rule is exercised with its one typed fact true, all facts
  false, and in combination with every other applicable rule to prove deterministic
  OR semantics; unknown rules/facts, missing referenced facts, non-log use, and a
  raw/caller-controlled mandatory Boolean fail closed. Expanded producer-row tests
  prove the selected family's program is authoritative, a true unrelated fact is
  rejected, unrelated false transition-carrier members are inert, and the legacy
  mapping-level evaluator cannot affect a generated occurrence.
- Every P-070 ordinary `structured_type` object, array, and tagged union is closed,
  acyclic, and bounded. The only recursive type is the compiler-owned, non-null
  `gen_ai.canonical_json` sealed union with Boolean, Int64, finite Double, String,
  Array, and ordered-member Object arms and an internal non-wire discriminator.
  Positive/negative fixtures exercise exact depth, aggregate-member, item,
  per-string/name UTF-8, per-item, and total-canonical-byte limits; ordinary
  reference cycles, null, and nonfinite doubles fail.
- Version 1 locks exactly four `structured_binding` rows for
  `gen_ai.input.messages`, `gen_ai.output.messages`,
  `gen_ai.tool.call.arguments`, and `gen_ai.tool.call.result`; local scalar arrays
  are not bindings. Arguments and result bind distinct object-only roots whose
  dynamic member values use the canonical-JSON union; whole-root scalar, array,
  and null fixtures fail. The compiler verifies the exact commit and all four
  SHA-256 upstream inputs, then records one disposition for every reachable
  upstream property. Golden round trips preserve unknown message/part/tool extras through
  `dynamic_members`, preserve arbitrary bounded unregistered GenericPart tags
  through `dynamic_variant`, and retain native JSON wire shape. Missing or extra
  bindings, an undisposed property, registered/dynamic tag overlap, duplicate
  dynamic keys, fixed/dynamic name collision, or an empty object without
  `dynamic_members` fails.
- Scalar object leaves, scalar array items, and tagged-union discriminators carry
  exact class/sensitivity/normalization; structured references and every
  object/array/variant container carry none. Expansion proves every reachable
  concrete leaf exactly once. Redaction fixtures traverse dynamic and recursively
  nested string leaves, transform only classified content, and prove unknown
  extras cannot bypass the selected profile. A post-redaction dynamic/fixed or
  dynamic/dynamic name collision fails with `structured_member_name_collision`
  and exporter-health accounting; no member is dropped or overwritten. Upstream nullable optionals normalize
  only by omission; explicit emitted null and required null fail under P-069.
  Public Go/Python APIs expose no map, `any`, `interface{}`, raw `Value`, or other
  untyped escape hatch.
- The pinned BlobPart binary annotation is preserved exactly once on
  `gen_ai.blob_part.content`: removing it, moving it to another string, or adding
  another binary-formatted property fails. Candidate JSON Schema emits advisory
  `contentEncoding: base64` and `x-defenseclaw-upstream-format: binary`; builders
  keep the upstream SHOULD advisory and do not invent a mandatory base64 decoder.
- The exact P-070 `go_symbol_policy` is compiled before rendering. Golden fixtures
  cover every ID/input/method/event/link/structured-type/structured-member/
  structured-arm/member-constructor namespace, initialism, exact
  `DefenseClaw`/`OpenTelemetry`/`OTel` brand spelling, and deterministic
  separators/casing. They also cover reserved-word rejection, invalid identifiers,
  cross-kind and same-kind collisions, and reviewed exact-key overrides. Collisions
  are never repaired with an automatic suffix. The complete `GoSymbolTableIR`
  contains one stable symbol for every generated declaration; no renderer derives,
  normalizes, or repairs a name independently. Every row also has one exact
  compiler-owned `declaration_form`. Fixtures prove all 21 structured-type and 17
  structured-arm rows are emitted exactly once as `exported_type`, never as
  `zz_generated_telemetry_ids.go` constants; all 49 structured-member rows remain
  `exported_const`. A row emitted in two forms or omitted from its form fails.
  Override fixtures cover all closed `kind` tokens and exact unscoped,
  structured `type#member-or-arm`, and family-scoped `family#event-or-relation`
  source IDs. Duplicate/unknown/unused keys, extra or empty components, arbitrary
  noncollision renames, policy-equivalent overrides, declaration-form changes,
  brand evasion, and post-override collisions fail. Registry v1 proves the
  override table is empty because there is no default collision; a prose reason
  never authorizes a rename. ROOT compilation proves the fixed kind/source order,
  recomputed kind and declaration-form counts, unique source/symbol identities,
  complete authored-source reconciliation, and a domain-separated digest that
  matches the table used for that compilation. Missing, renamed, reordered,
  byte-tampered, row-tampered, or digest-mismatched state fails. Additive rows do
  not require a hand-edited count, digest, or symbol-table baseline.
- Derived-value fixtures cover all eleven trace derivations and both P-069 scope
  constants. They prove span/resource/scope/event/link context scoping,
  `service.version` and scope version equality with provenance, profile ID/version
  equality, private link relation, input resource schema URL, and that the metric
  `defenseclaw.outcome` label remains producer input. Missing, duplicate, unused,
  wrong-context, name-inferred, or source-incompatible derivations fail.
- The complete compiler-owned `GoAPIPlanIR` is digest-bound independently of the
  derived declaration table. Tests cover every selector, type AST,
  required/optional presence, field order, callable parameter/result/error
  contract, conversion operation, private descriptor binding, exact constant
  literal kind/value, and file assignment.
  They prove the fixed common log/span/metric/event/link layouts, the common typed
  resource/scope structural inputs, family-local typed resource values,
  selected-family condition/mandatory fields, parsed span-name
  parts, and a complete derived declaration partition with every declaration
  assigned exactly once. Renderer tests receive
  only this plan and fail if asked to tokenize an ID, strip a symbol prefix, join a
  condition/constraint, parse a span name, infer a value source, or choose a file.
- Structured API-plan tests cover all 21 owner shapes, 31 fixed fields, 17 ordered
  member inputs/constructors, 17 arm types, and the canonical JSON six-arm sealed
  union. Compile/static tests reject map/`any`/raw `Value`, unsealed public unions,
  wrong `Optional[T]` use, nonfinite doubles, reserved selector collisions,
  constructor signature drift, and conversion plans that bypass the private
  structured validator.
- Every valid example has an explicit `builder_context` with occurrence,
  condition, mandatory, and inheritance facts. Deterministic fixtures prove the
  same context yields the same timestamp/record identity inputs and exact facts.
  Every invalid example names one valid base, inherits its context unchanged, and
  applies only its declared mutation; mutations cannot create, remove, or alter
  condition/mandatory facts or occurrence identity.
- The compiler materializes the P-069 structure and all P-070 facts into one
  recursively immutable `CandidateRenderIndex`, including complete
  scalar-leaf `EnrichedFieldDescriptor` joins, unclassified
  `EnrichedContainerDescriptor` structure, typed family/trace/metric descriptors,
  parsed span names, symbol and Go API plans, mandatory-rule programs, the four
  upstream structural inputs and property dispositions, structured bindings/
  dynamic rules, examples, expanded producer rows, and projection descriptors.
  Its domain-separated digest is distinct from and binds the materialized-view
  digest, is stable under source-map iteration, and every bundle, catalog, documentation,
  fixture, projection, and Go/Python renderer receives this same index. Tests make
  raw registry/snapshot access unavailable to renderers and reject any recomputed
  join, inferred default, incomplete descriptor, or post-materialization mutation.
- Generated-kernel tests enforce the exact method/signature allowlist from the
  complete symbol table, per-family typed inputs, typed event/link constructors,
  exact family identity, and private constructor termination. Generic build-by-name,
  caller catalog access, map/`any` inputs, direct schema construction, builders for
  `legacy.audit.*`, and builders for compatibility-only/deprecated-removed
  identities are compile- or generation-time failures.
- Candidate publication accepts exactly the seven generated Go paths in 12 §5.2.3
  as one validated set: all seven exist, match the same candidate
  digest, materialized-view digest, and symbol table, compile with the fixture
  suite, and agree with the complete candidate bundle, or none is accepted. The
  final committed checked-in state contains the complete set. The direct writer
  uses an explicit path inventory, same-directory temporary files, fixed modes,
  and atomic replacement. Tests prove an interruption leaves no false success,
  rerunning `--write` converges on the complete set, and `--check` rejects every
  missing, extra, stale,
  mixed-digest, partially written, independently generated, or current-authority
  files fail before cutover. The compiled package must contain no duplicate
  constant/type declaration: the 38 structured owning/arm symbols are types only
  and are absent from the IDs file.
- Portable example-output preflight runs before any renderer or repository
  writer. It accepts only IDs matching `^[a-z][a-z0-9-]{0,127}$`, direct-child
  normalized-example/OTLP-fixture outputs, and unique canonical repository-relative
  POSIX paths under the generated root. Fixtures reject `a/../../catalog`,
  `a/../b`, `a/b`, `a:b`, uppercase/case-fold aliases, 129-character IDs,
  absolute/backslash/NUL/doubled/trailing-separator paths, exact output collisions,
  and NFC-case-fold collisions before renderer invocation; the direct writer
  repeats containment, symlink, and exact-inventory validation.
- Upstream dependency refresh tests serialize two concurrent subset updates,
  compare-and-swap the original lock inode and bytes, and validate every path and
  digest named by the complete candidate lock before and after the lock commit.
  Pre-/post-lock inode replacement, same-inode byte mutation, stale external lock
  edits cannot report success or publish a mixed lock. Concurrent core and
  OpenInference subset refreshes may both succeed only after serialization; the
  second derives from the first committed lock and the final lock coherently
  retains both updates. Post-commit cleanup injection reports the explicit
  committed state while retaining the new coherent lock; pre-commit failures
  restore prior bytes or preserve evidence without deleting foreign state.
- Each curated valid record passes the real generated builder and complete candidate
  bundle. Each invalid record names one valid `base_example` plus exactly one typed
  mutation. The compiler applies its ordered RFC 6901 changes to the base
  `{signal,family?,record}` vector and requires exact equality before proving that
  builder and bundle both fail with the declared stable code; a second missing
  field or other competing defect fails the example corpus itself.
- Generated JSON Schema bundle, compact catalog, Markdown reference, Go/Python
  constants/builders, field-class maps, fixtures, and Galileo/OpenInference
  projections are deterministic and checked for drift.
- Inventory tests derive the complete log/trace/metric family and producer
  inventories from the authored registry. They prove producer mappings do not
  create implicit families or override canonical bucket ownership. Named
  producer-identity sets validate to the same exact tuples as the source
  mappings, while generated Go stores identities and contextual sets once rather
  than materializing every producer/set pair. Empty, duplicate, unknown, unused,
  nested, wildcard, union, and policy-incompatible sets fail.
- Every current OTel schema field, event, name/kind pattern, and Galileo requirement
  has an explicit preserved/aliased/removed/corrected migration disposition.
- Real Go and Python producers are validated, not hand-built substitute objects.
- GenAI fields retain upstream name/type/meaning; security extensions remain in the
  `defenseclaw.*` namespace.
- Every compatibility alias equals the canonical destination-redacted value.
- Splunk HEC compatibility fixtures prove aliases are extracted solely from the
  selected projected byte envelope. A field removed by the Splunk profile produces
  no alias even when it exists in the canonical record, producer event, or another
  destination's `none` projection; opaque extra-event input is rejected.
- A pinned upstream semantic-convention update produces a reviewed machine-readable
  diff and cannot enter through an ordinary dependency update.
- The public bundle resolves all `$ref` values and generated standalone views are
  equivalent to their bundle definitions.
- Candidate-bundle acceptance rejects an attribute-only skeleton or any bundle
  missing the exact envelope/correlation/provenance union, structural privacy,
  stable conditions, phase/code and group lifecycle metadata, typed OTLP mappings,
  complete examples, or a family shape accepted differently by its builder.
- Every existing public telemetry-schema compatibility view retains its exact
  `$id`, resolves its local `$ref` values without network access, validates the
  migration fixtures, and is byte-identical to any gateway/CLI mirror or embedded
  accessor. A repository check proves those paths are generator-owned after
  cutover rather than independently authored.
- Changing an attribute's `field_class` or `sensitivity` fails the ordinary
  additive-change path and requires the security-breaking review/version evidence
  declared by the registry rules.
- Removing an alias before its declared `removed_in` version fails; removal at that
  version still requires the query migration, compatibility fixture update, and
  reviewed generated semantic diff.
- The `defenseclaw-genai-rich-v1` manifest entry resolves exactly the four pinned
  profile/version members; independent overrides and lock mismatches fail.
- The canonical record `schema_version` and span `family_schema_version` coexist in
  fixtures without collision or ambiguous generated names.
- Generated v7 exporter selection covers every current log, trace, metric, audit
  action, JSONL/console event, OTel filter operation, and destination path; removing
  one mapping fails generation, and converter tests prove no duplicate hand list or
  wildcard fallback exists.
- `local-observability-v1` is regenerated by parsing the checked-in dashboards,
  rules, Collector, datasource, compose/package, and packaged-copy assets. Tests
  reject a separate hand-maintained consumer field/query list and prove the
  generated compatibility manifest covers every extracted dependency.

### 9.7 Agent lifecycle and local dashboards

- Import merged PR #403 and PR #412 fixtures before changing producers or schemas;
  each field/query receives a preserved, aliased, migrated, or intentionally
  corrected disposition.
- Root agent plus nested subagents retain distinct conversation, current-agent,
  root/parent-agent, root/parent-session, lifecycle, execution, operation, run,
  trace, and span identities. Delegation lineage remains distinct from OTel parent
  edges and typed links.
- Lifecycle events/states, depth, session source/resume, monotonically increasing
  per-execution sequence, and the immutable phase-code map `1..12` pass golden
  schema plus real-producer tests. The invalid PR #403 fixture
  `model`/`turn`/`4` is explicitly corrected to `model`/`planning`/`3` and is not
  retained as an alias.
- A long-running session exports completed turn, model, tool, approval, decision,
  and transition work before any `Stop`/session-end hook. Duplicate/out-of-order
  completion does not duplicate spans, logs, or metric counts.
- `hook_decision` preserves raw versus effective action, mode, would-block,
  enforced, evaluation/rule correlation, and the enclosing lifecycle/execution
  identity without advancing phase/sequence or inventing a retry.
- Regular, synthetic, rejected, and unified connector-hook traffic uses only the
  generated hook/inspect/token/dispatch families. A metrics-only destination
  receives the complete compatibility metric set without constructing a trace or
  requiring a legacy Provider; prompt/completion/total token points use the
  bounded `defenseclaw.metric.kind` field rather than `gen_ai.token.type`.
- The generated hook-decision log is raw by default and applies redaction only in
  each destination projection. Its OTLP projection promotes canonical trace ID,
  span ID, event timestamp, and log level into the standard `LogRecord` fields so
  log-to-trace joins do not depend on parsing the canonical JSON body.
- Missing parent, content, tokens, cost, and timing remain absent/not-reported; no
  dashboard renders an invented zero or empty report.
- A completed EventRouter assistant message with no source start time produces one
  zero-duration generated model span, no duration metric, and independently
  collected token metrics. Its ended W3C context parents only an exact or unique
  same-session tool; cross-session, ambiguous, expired, and unanchored approval
  cases remain roots. The bounded cache retains no live span or graph lease.
- The generated `local-observability-v1` profile covers every metric, allowed
  label, exact histogram boundary, Loki field, Tempo attribute, dashboard variable,
  link, datasource UID, and dashboard UID consumed by the bundle.
- Critical PR #412 contracts include approval (`result`, `auto`, `dangerous`),
  connector-hook outcome (`action`, `connector`, `event_type`, `severity`,
  `would_block`), guardrail evaluation (`guardrail_action_taken`,
  `guardrail_connector`, `guardrail_scanner`), and schema violation (`code`,
  `event_type`) labels plus the exact hook-latency histogram buckets.
- Inspect dashboards filter on the first-class `connector` label rather than
  parsing connector identity from `tool`. Concrete runtime-alert panels consume
  `defenseclaw_alert_count_total`; they do not infer alerts from guardrail action.
  Source clean severity `NONE` is absent from canonical selectors because it
  normalizes to `INFO`; non-clean panels filter by action instead.
- Gateway metrics default to 60-second delta export; the local Collector performs
  delta-to-cumulative conversion through one application remote-write path; the
  Grafana Prometheus datasource interval is at least 60 seconds.
- Agent360 durable counts/chronology use Loki, aggregates/phase/topology use
  Prometheus, and trace search/waterfall use Tempo. Static tests fail if a panel
  silently changes those semantics.
- All fourteen dashboard UIDs and the three stable datasource UIDs are unique and
  provisioned. Source and CLI-packaged dashboards/config are byte-identical.
- Static validation rejects nonexistent labels/fields and bad percentile/legend/
  bucket/cadence/query shapes. Live validation classifies expected-idle,
  unexpected-empty, and backend-unavailable instead of accepting every `No data`.

## 10. Reload and Concurrency Tests

- Valid reload swaps the graph exactly once.
- Invalid parse/validation/exporter initialization retains the exact old graph.
- Failure after one exporter initializes and failure inside a partially initialized
  exporter both close that component and every acquired child resource in reverse
  order; no worker, listener, connection, timer, or duplicate transport survives.
- Injected teardown failure is bounded, reported through the still-active graph as
  platform health plus mandatory compliance activity, and still does not publish
  the rejected graph.
- Concurrent producers see either old or new policy, never a partially built mix.
- Removed exporter drains within deadline.
- Changed route affects new records only; queued projected payloads retain old
  projection/profile.
- SQLite path and judge-body path reload are rejected as restart-required.
- Both `guardrail.retain_judge_bodies` transitions are rejected as
  restart-required with the exact field path, and active capture state remains
  unchanged until restart.
- Retention age reload is accepted.
- Race detector reports no mutation of canonical records or policy snapshots.

## 11. Migration Tests

Golden fixtures MUST cover:

- Named OTel destinations with all signal combinations.
- Named `local-observability` destination with logs/traces/metrics, loopback/private
  endpoint intent, full `local-observability-v1` capability, and a deliberately
  narrowed fixture that preserves intent while reporting partial dashboard support.
- Every explicit loopback/RFC1918/IPv6-ULA v7 literal, across local and non-local
  destinations, materializes only that destination's `allow_private_networks`
  intent; metadata/link-local/always-prohibited targets remain blocked and no
  process-wide bypass appears.
- Galileo preset and span filter.
- Same-source OTel signals with differing protocols split into stable suffixed
  destinations without losing endpoint, TLS, credentials, batch, route, enabled,
  or profile intent.
- Multiple metric destinations with equal effective interval/temporality converge
  on one process policy; conflicting values fail before write and name the exact
  align-or-remove remediation.
- Current resource/metrics/runtime-span/event schema set imported into the one
  registry with generated-artifact parity.
- Audit JSONL, Splunk, HTTP JSONL, and OTLP log sinks.
- Same endpoint but different credentials or batching, proving no unsafe merge.
- Connector-specific inherit, replace, and suppress behavior.
- Redaction enabled and globally disabled.
- Judge-body retention with explicit true/false, absent default true, and every
  off-like `DEFENSECLAW_PERSIST_JUDGE` value; migrated v8 ignores later environment
  changes and retains the materialized choice.
- `ai_discovery.emit_otel` true/false/absent, proving false does not disable local
  discovery logs and true preserves only the legacy OTLP signal intent without a
  second runtime emission gate. The baseline inventory test also proves there is no
  unhandled connector-level `emit_otel` config field.
- Inline and environment/key-store credential forms.
- Inline tokens, bearer tokens, exact references, and interpolated headers such as
  an authorization scheme plus token. Promotion uses deterministic environment
  names, places complete effective values only in the ancillary `.env` edit,
  masks all output/object representations, and is idempotent on retry.
- Every supported DefenseClaw/OpenClaw/standard OTel enablement, endpoint, signal
  endpoint, protocol, signal protocol, and TLS-insecure environment input, proving
  effective non-secret behavior is materialized and later environment changes do
  not alter v8 policy.
- Splunk `sourcetype_overrides`, OTLP-log `logger_name`, and the complete
  `legacy-v7` field/helper compatibility corpus.
- Already-v8 input.
- Current valid v7 input with `config_version: 7`, an absent stamp, and numeric zero;
  all three produce equivalent v8 semantics. Missing/zero mixed with a v8-only key
  is rejected as ambiguous without mutation.
- Malformed/partially migrated input.

Assertions:

- Dry-run changes no bytes, timestamps, or permissions.
- Diff and error output contain no resolved secret.
- The normal upgrade creates the expected backup and atomically writes valid v8
  YAML through the registered required migration.
- Unrelated config remains semantically identical.
- Existing comments and ASCII guidance survive automatic migration.
- Current family eligibility is read from the generated registry compatibility
  selection; a removed/ambiguous entry fails before write rather than broadening a
  route.
- Migration emits no source SQLite destination/catch-all, uses concise `send` where
  one selector is sufficient, and uses advanced routes only when legacy exclusions
  or detailed selectors require them.
- A migrated destination never omits both `send` and `routes` unless its v7 behavior
  was already every supported signal, every catalog bucket, unredacted. Redacted or
  narrower v7 installations receive explicit collection/profile/routes and do not
  broaden to the fresh-v8 defaults.
- Migrated OTLP policy uses route-derived signals plus `signal_overrides`, not a
  second signal-enable map.
- Active migrated destinations omit redundant `enabled: true`; disabled legacy
  destinations retain explicit `enabled: false`.
- Generated config passes gateway and Python CLI parsing.
- After Phase 4 version dispatch, an unrelated Python setup/TUI/config write to a
  v8 source preserves the complete observability block and never invokes the v7
  connector-only serializer.
- The migration cursor records the conversion only after successful activation;
  already-v8 and retry cases do not duplicate output.
- Running v8 gateway rejects original legacy blocks with actionable instructions.
- The installed local bundle backup/refresh preserves arbitrary custom files and
  every history volume, refreshes mutually compatible DefenseClaw-owned Collector/
  datasource/dashboard/rule files, and restarts/verifies a previously running
  stack without a separate migration command.

## 12. End-to-End Scenarios

### E2E-1: Full-fidelity local default

- Use an otherwise empty observability block; do not configure a local destination.
- Produce one record from each bucket.
- Verify every defined signal is collected, every collected log is stored locally
  unredacted, no network exporter starts, and model/tool/diagnostic families have no
  hidden default exception.

### E2E-2: Multi-destination security operations

- Configure three optional destinations: JSONL, a Splunk fake, and a general OTLP
  fake; use implicit local SQLite storage.
- Emit a high finding and successful block.
- Verify each collected log is persisted once to implicit local SQLite and
  delivered independently once to each matching optional destination. Correlations
  match, redaction differs as configured, and local SQLite projections are
  queryable.

### E2E-3: AI Defense source filtering

- Route `security.finding` where `source: ai_defense` to a dedicated OTLP endpoint.
- Emit equivalent findings from AI Defense and CodeGuard.
- Verify only the AI Defense record reaches that endpoint while both remain local.

### E2E-4: Galileo traces only

- Enable model/tool/agent/guardrail traces and Galileo OTLP traces.
- Disable model/tool logs.
- Verify Galileo receives compliant redacted agent, model, tool, retriever,
  workflow, and judge-chat spans with current correlation fields plus safe security
  events; no content logs are created and metrics follow their independent policy.
- Verify native guardrail/policy/scan/health spans remain present at a general OTLP
  destination and are not misclassified merely to pass Galileo compatibility.
- Verify observed/eligible/ineligible/attempted/delivered/partial/rejected/failed
  counters and exact-trace canary acknowledgement.

### E2E-5: Capability-default export

- Add enabled JSONL, Prometheus, and general OTLP destinations with transport fields
  but no `send` or `routes`.
- Verify JSONL receives every log, Prometheus exposes every eligible metric, and
  OTLP receives every eligible log, trace, and metric; all content-bearing
  projections use `none`.
- Add an explicit strict destination and verify it remains redacted while the
  capability-default destinations remain unredacted.
- Verify effective/plan/doctor/TUI display generated routes, all-bucket membership,
  capability signals, `none`, and the implicit queue/batch count-and-byte defaults
  plainly, without requiring a warning.

### E2E-6: Exporter isolation

- Make one remote exporter fail and fill its queue first by count and then by
  projected bytes. Repeat with blocked JSONL/console writers.
- Verify the newest attempted enqueue is dropped in every case, older FIFO work is
  retained, the built-in local store and other exporters continue, drops/health
  are bounded and visible, and recovery transitions to healthy.

### E2E-7: Retention

- Seed both databases and all event tables around a fake cutoff.
- Run reaper.
- Verify exact rows removed/preserved and current state unchanged.
- Verify the four protected alert tables and readiness state are never reaped, and
  report their capacity separately from age-retained event history.

### E2E-8: Atomic reload

- Begin with a valid graph and active traffic.
- Attempt invalid reload; verify old routing continues.
- Apply valid reload; verify new traffic follows the new graph and old exporter drains.

### E2E-9: Root agent, subagents, and local dashboards across upgrade

- Start the current bundled stack and emit a root session with two turns, reported
  and unreported model usage, tool/approval, raw-versus-effective hook decision,
  direct and nested subagents, compaction, resume, and a completed operation before
  session end.
- Run the ordinary upgrade and automatic v8 config/local-bundle migration while
  preserving Prometheus, Loki, Tempo, and Grafana volumes.
- Emit a second execution after upgrade. Verify stable lifecycle and root lineage,
  new execution identity, monotonic per-execution sequence, correct phase codes,
  no duplicate old/new pipeline events, and completed activity visible before
  `Stop`.
- Validate all fourteen Grafana UIDs and every query inventory entry. Agent360 must
  show the root tree, both executions, exact Loki chronology/counts, Prometheus
  phase/topology/latency, reported versus not-reported usage/cost, decision recovery,
  and a Tempo waterfall while historical pre-upgrade data remains queryable.

## 13. Security and Robustness Tests

- Fuzz canonical event parsing and dynamic body traversal.
- Fuzz route selectors and config decoding.
- Fuzz redaction around Unicode boundaries and malformed encodings.
- For each HTTP JSONL, OTLP, and Splunk adapter, endpoint validation and the actual
  dial path reject loopback, RFC1918, IPv6 ULA, RFC 6598, link-local, unspecified,
  multicast/reserved, mixed public/private answers, and representative cloud and
  container metadata/task-credential endpoints.
- DNS-rebinding tests validate a public answer followed by a private dial answer;
  the guarded dial rejects it. Redirect tests prove exporters do not follow any hop.
- Temporary DNS/network failure sends no request and degrades only that destination;
  an unsafe literal/resolution rejects the candidate graph and leaves the old graph
  active.
- A resolution/connect/deadline failure before any request write is transient. A
  timeout or connection failure after the complete or partial request may have
  reached the peer is an ambiguous acknowledgement: bounded retry uses the exact
  same projected bytes and record ID, never re-runs redaction, and the test permits
  downstream duplicates only for that ambiguity. Authentication, permanent
  payload, and unsafe-endpoint outcomes do not enter the retry loop.
- `allow_private_networks` permits only loopback/RFC1918/IPv6 ULA and
  `allow_cgnat` permits only RFC 6598. Both produce warnings/audit. Link-local,
  metadata/task-credential, unspecified, multicast/reserved, and inline credentials
  remain blocked under both opt-ins; no environment-only bypass works.
- TLS certificate and hostname validation defaults secure.
- Plaintext HTTP with Splunk authentication, a bearer token, an
  authentication-like header, or a secret-backed header emits exactly one
  content-free `plaintext_credentials` warning per prepared destination;
  unauthenticated HTTP and HTTPS do not emit that warning.
- Header/token masking across error, health, doctor, TUI, migration, and compliance
  output.
- Log-injection/newline handling for console, JSONL, and HEC.
- For Splunk, seed a secret canary in the canonical body and route `none` to one
  destination and `strict` to Splunk. Search the complete HEC request, including
  aliases and wrappers; the canary and removed-field alias must be absent while
  allowed aliases equal the strict projected values.
- Compression and decompression size limits.
- Inbound record and batch size limits.
- Queue count/byte and outbound batch count/byte exhaustion tests at every exact
  boundary and boundary+1. A configured maximum is validated before allocation,
  and a single destination can never retain more projected bytes than its queue
  ceiling or encode a request larger than its push-batch ceiling.
- Recursive health/export failure guards.

## 14. Performance Acceptance

Benchmarks must be captured before and after producer migration on the same machine:

- Disabled log, trace, and metric hot paths.
- One built-in-local-only log.
- One locally persisted log plus three in-memory fake destinations.
- Sensitive redaction of representative plain text and nested JSON.
- Rich agent/model/tool/retrieval/workflow/guardrail span creation and one-, two-,
  and four-destination projection.
- Metric recording.
- Reaper batches of 1,000 rows under concurrent reads.

Acceptance requirements:

- Disabled collection does not construct content payloads or invoke redaction.
- Remote network I/O is absent from producer goroutines.
- Memory remains bounded by configured queue count/byte and payload limits; push
  request construction remains bounded by the configured encoded-batch byte
  ceiling.
- Reaper transactions never exceed the specified batch size.
- No benchmark shows uninvestigated time or allocation regression greater than 10%
  against the approved baseline; intentional regressions require documented review.

## 15. Commands Required in PR Test Plans

At minimum, after implementation paths exist, run and record observed results for:

```bash
go test ./internal/config ./internal/redaction ./internal/gatewaylog ./internal/audit ./internal/telemetry ./internal/scanner ./internal/gateway -count=1
go test -race ./internal/config ./internal/redaction ./internal/gatewaylog ./internal/audit ./internal/telemetry -count=1
go test ./test/e2e -run 'Observability|V8' -count=1
uv run python -m pytest cli/tests -q
go vet ./...
make check-schemas
make check-grafana-dashboards
uv run python -m pytest cli/tests/test_agent360_dashboard.py cli/tests/test_grafana_dashboards.py -q
make check-upgrade-manifest
make upgrade-smoke-matrix ARGS="--target-version X.Y.Z --baseline-mode seed"
```

Phase PRs may run a justified subset while stacked, but the final integration PR
must run the full list plus the applicable end-to-end harnesses. The release job
also runs the finalized-artifact matrix with `--release-dir dist` and, against the
started local stack:

```bash
python scripts/check_grafana_dashboards.py --live --inventory --require-packaged
```

PR descriptions must show actual pass/fail counts or command results, not only
intended commands.

## 16. Automatic Upgrade Tests

### 16.1 Candidate generation and validation

- One ordinary latest-version request resolves tested v7 sources through the
  verified `0.8.4` controller bridge, re-executes in a fresh process, and creates
  the expected deterministic v8 candidate under the `0.8.5` hard cut.
- The automatic flow and optional standalone command generate byte-equivalent
  semantic candidates from the same fixture.
- Candidate generation and target validation complete before either active source
  file is replaced.
- Invalid, unsupported, or ambiguous v7 input fails with source files and migration
  cursor unchanged and never starts a v8 gateway against the v7 source.
- An already migrated v8 source is a no-op; retries do not duplicate destinations,
  routes, or database migrations.
- Migration output and the normal confirmation summary contain no resolved secrets
  or governed content.
- The pure converter returns declarative ancillary edits without I/O; preview and
  upgrade consume the same result. Generated v7 family selection supplies every
  eligibility decision and a missing mapping is a pre-write error.
- Per-signal protocol splits are deterministic, equal metric policies validate,
  and conflicting metric policies fail with the documented destination/field
  remediation.

### 16.2 Backup and atomicity

- Exact config bytes, mode, ownership metadata, path, and hash are captured before
  replacement.
- Comment-heavy fixtures preserve ASCII guidance, comments, order, unrelated
  sections, and safe scalar/list style.
- Config activation uses locking, temporary files, fsync, and atomic rename.
- Ancillary `.env` promotion uses the same lock/backup/rollback unit;
  complete inline/interpolated values never enter YAML/diff/output, and an injected
  failure after either file write restores both original byte streams.
- A failure before rename never exposes a partial v8 file.
- Insufficient permissions or disk space fail before gateway shutdown where they
  can be determined locally.

### 16.3 Success, failure, and rollback

- A release-stamped `0.8.4` manifest requires protocol 1 and advertises a protocol
  2 controller, but does not contain the v8 migration row. A release-stamped
  `0.8.5` manifest requires protocol 2, minimum source/bridge `0.8.4`, and the
  manifest-required `0.8.5` row.
- An explicit `0.8.3`-or-older to `0.8.5` request is rejected after contract
  verification but before confirmation, backup, service stop, gateway install, or
  wheel install; output states that no changes were made. The target-owned updater
  enforces the same source gate, so following an immutable old controller's updater
  hint cannot bypass the bridge.
- A normal latest-version request from each source in
  `release/upgrade-baselines.json` verifies and installs `0.8.4`, proves bridge
  health, terminates the old execution path, and invokes `0.8.5` through a fresh
  bridge process. An unlisted source fails closed with the exact supported path.
- The `0.8.5` wheel has config capability 8, a compatible synchronous runner, and
  the required `0.8.5` row. Stamp mismatch, missing or forward/unreachable required
  row, malformed/duplicate registry, incompatible runner call shape, and
  unsupported/future source schema fail at the same pre-mutation boundary.
- The target runner calls the pre-0.8.4 signature without
  `upgrade_handles_local_bundle`, calls the new keyword-compatible signature with
  it, does not retry `TypeError`, and uses isolated Python mode. A missing config
  is an explicit migration no-op rather than a post-install failure.
- Interactive upgrade uses the existing confirmation; noninteractive upgrade uses
  ordinary `--yes` with no additional plan/hash/phrase step.
- A successful upgrade starts v8, activates the expected config generation, writes
  SQLite, compiles the observability graph, marks the existing migration cursor
  complete, passes a fresh-process health check, and only then finalizes a success
  receipt.
- Inject failures before validation and during multi-file config activation. The
  exact v7 source bytes remain or are restored, the cursor remains unapplied, and
  the v8 gateway is not started against v7 configuration.
- Manifest-required migration failure, ancillary-write failure, cursor failure,
  target start failure, and target health timeout all exercise the hard-cut
  rollback transaction: exact bridge config/`.env`/cursor/bundle state is restored,
  the retained verified bridge CLI/gateway are reinstalled, restored bridge health
  is checked in a fresh process, exit is nonzero, and no success banner/receipt is
  emitted.
- Failure injection covers every boundary after stop, gateway install, wheel
  install, migration activation, bundle refresh, restart, and health. Rollback
  failure is reported distinctly while preserving the original failure code.
- The additive v8 database schema remains readable by the immediately previous
  supported release.
- An unavailable optional remote exporter reports degraded runtime health but does
  not roll back a healthy gateway with writable SQLite.
- Re-running after interruption or rollback is safe and converges on one valid v8
  configuration.

### 16.4 Permissions and historical matrix

- Administrator-owned/read-only config fails the upgrade permission preflight
  without chmod, replacement, or service interruption and identifies the path that
  must be made writable by its owner.
- The release matrix is the machine-readable
  `release/upgrade-baselines.json` and covers every supported v7 baseline with named OTel
  destinations, audit sinks, connector overrides, global redaction disablement,
  JSONL/console behavior, Galileo, non-default paths, WAL databases, and
  comment-heavy YAML.
- Direct v8 gateway startup with v7 configuration rejects it and points first to
  the staged upgrade resolver, with the standalone preview as an optional diagnostic.
- Python config/setup/TUI and gateway entrypoints dispatch on `config_version`:
  v7 remains on the legacy path before upgrade, while v8 validation/mutation never
  traverses the v7 observability dataclass or writer.
- A seeded local-observability bundle is backed up and refreshed automatically;
  custom files and persistent volumes survive, DefenseClaw-owned files match the
  target package, a previously running stack is restarted/verified, and optional
  stack failure is reported as degraded without rolling back a healthy gateway.
- When refresh/restart is fault-injected, the immediately previous PR #403/#412
  dashboard query contract still returns data through declared aliases, while
  upgrade/doctor reports the stale bundle and target-only capability gap.

## 17. Release Gates

Release is blocked until:

- Every catalog item is classified.
- Every collected log reaches SQLite exactly once.
- Canary tests prove content appears only where the effective `none` policy and
  schema allow it and is removed by every configured redacting profile.
- Effective unredacted/redacted policies are visible, and every policy mutation is
  audited.
- Legacy configuration rejection and migration are documented and tested.
- No duplicate old/new pipeline outputs remain.
- Retention protects current-state tables.
- All enabled destinations have independent health and failure isolation.
- Invalid live reload is proven non-disruptive.
- CLI, gateway, TUI, doctor, schemas, examples, and dashboards agree on v8.
- PR #403 root/subagent lifecycle and real-time traceability goldens pass, including
  operation completion without `Stop`, final hook decisions, and truthful missing
  usage/cost/content.
- PR #412 metric/label/histogram/cadence corrections remain intact;
  `local-observability-v1`, all fourteen dashboard UIDs, three datasource UIDs,
  source/packaged parity, and static/live query inventories pass.
- One-command upgrade refreshes compatible local-stack assets without resetting
  Prometheus/Loki/Tempo/Grafana history or requiring another migration command.
- Release publication consumes one sealed candidate artifact set only after
  protocol-refusal, bridge-success, rollback-fault, Linux, macOS, native Windows,
  and live four-volume continuity gates all pass. Repository governance and
  environment configuration remain outside this code change.
- Source/effective/reference views agree, comment-preserving mutation passes, and
  bucket catalog evolution cannot cause silent new optional-destination delivery.
- Historical one-command upgrades, failure injection, exact-config recovery,
  retry/idempotence, and permission tests pass for the v8 boundary.
- P-070's closed mandatory rules, structured bindings, Go symbol table, example
  builder contexts, and enriched candidate index pass the §3.4/§9.6 conformance
  suite. The exact seven generated Go files are accepted all-or-nothing and remain
  candidate-only until the independently specified authority cutover; any current
  blocker listed in 12 §5.2.3 keeps this gate open.
- The repository-required PR structure and linked-follow-up rule are satisfied.
