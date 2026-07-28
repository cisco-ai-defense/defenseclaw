# Decisions, Assumptions, and Exclusions

## 1. Locked Product Decisions

These decisions came directly from the planning discussion and should not be
reopened during implementation without a spec amendment.

| ID | Decision |
|---|---|
| D-001 | Use two-stage control: collection first, routing second. |
| D-002 | Use fixed semantic buckets with source, connector, action, event name, and severity selectors. |
| D-003 | Use the fourteen-bucket catalog in this package. |
| D-004 | Treat AI Defense as a source, not a separate bucket. |
| D-005 | Replace separate OTel destinations and audit sinks with one optional-destination registry; keep mandatory local SQLite as an implicit built-in store backed by the same canonical pipeline. |
| D-006 | Allow a record to fan out to every independently matching destination. |
| D-007 | Use first-match-wins route precedence within each destination and signal only when the advanced `routes` form is selected. |
| D-008 | Let omitted destination policy express the full capability default; provide one concise `send` block for narrowing and explicit send/drop actions in the mutually exclusive advanced form. |
| D-009 | Use capability-default/per-destination/simple-send or per-advanced-route profile resolution with bucket/global fallback. |
| D-010 | Make `none` valid and default for catalog, local, and optional-destination projections; it needs no break-glass switch or warning, while policy changes remain audited. |
| D-011 | Provide built-in redaction profiles plus single-level custom composition from one built-in redacting profile using built-in detectors/field classes; no custom-to-custom inheritance or arbitrary regex. |
| D-012 | Fail closed to whole-field redaction on redaction processing failure and continue safe delivery. |
| D-013 | Provide exactly one always-enabled implicit SQLite event-history destination backed by `audit.db`; do not require a destination or catch-all route in source YAML. The separate `judge_bodies.db` forensic database is not an event-history destination and is excluded from this exactly-one rule. |
| D-014 | Persist every collected log to SQLite plus normalized projections. |
| D-015 | Use versioned full-fidelity catalog defaults: every bucket collects every defined log/trace/metric signal and uses `none`; no remote transport starts until a destination is selected. |
| D-016 | Provide a mandatory local compliance/security floor that bypasses collection only for SQLite. |
| D-017 | Use one global retention age for event, evidence, and judge-body history. |
| D-018 | Default retention to 90 days; `0` retains forever. |
| D-019 | Use atomic live reload; invalid new configuration leaves old behavior active. |
| D-020 | One authenticated target-release resolver command automatically stages supported POSIX v7 installations through the published `0.8.4` protocol-2 bridge and performs the one-time v7-to-v8 conversion under a fresh controller; the gateway has no startup auto-migration or dual-format mode, the standalone migration CLI is optional, and platforms without a published bridge fail before mutation. |
| D-021 | An enabled destination with no `send` or `routes` receives every catalog bucket unredacted and all signals supported by that destination kind: logs for log-only kinds, metrics for Prometheus, and logs/traces/metrics for general OTLP. |
| D-022 | Preserve the merged PR #403 full root/subagent lifecycle and traceability model and PR #412 local-dashboard data corrections as the v8 compatibility floor; the staged upgrade refreshes mutually compatible DefenseClaw-owned local assets without resetting history volumes or requiring another migration command. |
| D-023 | Treat inbound OTLP as a closed registry-generated producer surface: only an exact supported binding may construct a new local canonical record or explicit derived observation; arbitrary decoded leaves are never persisted or re-exported as opaque telemetry. |
| D-024 | Make the released gateway/sidecar/runtime v8-only after `defenseclaw upgrade`: v7 parsing is confined to the converter, read-only migration preview, historical fixtures, exact backup/rollback, and previous-binary recovery. Live producers, routers, destinations, reload, ordinary config mutation, and startup have no v7 fallback, dual-write, direct legacy OTel/sink path, or runtime compatibility branch. Generated Galileo/local/OpenInference projections and legacy-shaped SQLite read columns are additive v8 consumer projections, not v7 runtime ownership. |

## 2. Semantic Decisions Added During Clarification

| ID | Decision |
|---|---|
| S-001 | `compliance.activity` is the audit trail of operator/service/system control-plane actions, including attempted and rejected changes. Logging is mandatory; actor attribution is best available. |
| S-002 | `security.finding` is a concrete risk observation; it is not the automatic final stage of a guardrail evaluation. |
| S-003 | `guardrail.evaluation` records a control execution and decision and is not a superset of model or tool content. |
| S-004 | `model.io` owns model request/response content; other buckets reference it. |
| S-005 | `tool.activity` owns tool request/result content; guardrail evaluation references it. |
| S-006 | `asset.scan` is scan execution/summary; `security.finding` contains individual issues. |
| S-007 | `asset.lifecycle` records actual state transitions; `enforcement.action` records attempts to impose controls. Successful quarantine normally produces linked records in both buckets; failed quarantine does not invent a lifecycle transition. |
| S-008 | Every record has one primary bucket. Relationships use correlation IDs rather than multi-bucket duplication. |
| S-009 | v8 finding logs are immutable observations and do not add `status: open` or case-management transitions. |
| S-010 | Existing producer remediation remains supported; evidence summary and remediation normalization must be deterministic and safe, not silently hallucinated. |
| S-011 | Administrative authentication/authorization failures are `compliance.activity`; inbound telemetry authentication failures are `telemetry.ingest`; outbound destination authentication failures are `platform.health`. All are mandatory-floor logs. |
| S-012 | Alert acknowledgement and dismissal never mutate an immutable event's canonical severity or emit noncanonical `ACK` severity. Mutable acknowledgement state lives in a separate alert-state projection keyed to an existing finding/legacy alert or previously protected alert state; arbitrary or non-finding targets fail before any write. Every first-seen acknowledgement/dismissal operation emits an immutable mandatory `compliance.activity` event plus a protected immutable operation receipt in the same transaction. The protected receipt carries a versioned, domain-separated, correlation-keyed HMAC command fingerprint that is never placed in the canonical/exported event body. The baseline plus applied receipts are the retention-independent state-machine/idempotency authority; retained audit events are cross-checked, while an event missing after normal age retention is valid and is not recreated by retry. Legacy acknowledgement action rows map to canonical `INFO`; historical rows whose original severity was overwritten with `ACK` remain readable through a startup-refreshed baseline with explicit legacy-acknowledged metadata and no invented original severity. |

## 3. Specification Defaults Introduced to Remove Ambiguity

These defaults have been reviewed with the locked product direction and are the
approved v8 implementation defaults. Changing one requires the specification,
traceability target, and affected tests to change together before implementation
diverges.

| ID | Default | Rationale |
|---|---|---|
| P-001 | Preserve `audit_events` as the v8 event-history compatibility anchor and add canonical columns. | Minimizes API/history migration while making structured v8 queries possible. |
| P-002 | The compiler generates the local SQLite catch-all; source YAML cannot remove or bypass it. | Enforces “every collected log is local” without operator boilerplate. |
| P-003 | Every DefenseClaw-owned optional log/trace queue, including JSONL and console, drops the newest attempted enqueue when either its count or byte limit is full. Prometheus has no push queue, and metric SDK reader/exporter backpressure follows the documented SDK contract. | Preserves older queued log/trace order, prevents disk/terminal/remote backpressure from blocking producers, retains the canonical local record, and does not invent queue semantics for pull or SDK-managed metric delivery. |
| P-004 | Canonical security severity is `INFO < LOW < MEDIUM < HIGH < CRITICAL`. Guardrail/judge producer `NONE` maps to `INFO` while retaining clean-evaluation semantics; `WARN`/`WARNING` maps to `MEDIUM` and may retain `log_level: WARN`; ERROR maps HIGH and FATAL maps CRITICAL. | Merges the existing audit `INFO` ladder and guardrail `NONE` ladder into one comparable five-level envelope without rejecting clean evaluations or inventing a WARN rung. |
| P-005 | Retention deletes rows strictly older than the cutoff; equality is retained. | Avoids boundary ambiguity. |
| P-006 | Reaper starts after startup and repeats every six hours in batches of 1,000. | Balances prompt cleanup with SQLite contention. |
| P-007 | Finding observations are not automatically deduplicated. | Avoids accidentally introducing mutable case semantics; downstream can aggregate using stable fields. |
| P-008 | Remediation catalog enrichment is optional and additive; absent remediation remains valid. | Preserves current producers and avoids fabricated advice. |
| P-009 | Live source uses implicit local storage and omitted destination policy for full-capability delivery; concise `send` expresses narrowing, while effective/reference views expose the generated graph. | Keeps common full-fidelity policy small without creating a second runtime pipeline or hiding defaults. |
| P-010 | Do not add `observability.from` or another include mechanism in v8. | Concise authoring removes the immediate size pressure and avoids multi-file trust, watch, and atomicity complexity. |
| P-011 | Do not add user-defined bucket sets in v8; presets materialize explicit bucket lists. | Keeps selectors obvious and avoids another indirection layer. |
| P-012 | Require comment-preserving mutation of existing v8 YAML. | The current Python full-file `safe_dump` path strips comments and would destroy embedded operator guidance. |
| P-013 | For `config_version: 8`, omitted `bucket_catalog_version` resolves to catalog 1; an explicit value is required only to advance beyond it. Optional-destination wildcards remain pinned to the effective version. | Preserves safe evolution without making normal users maintain an internal version knob. |
| P-014 | Materialize audience presets into explicit YAML at authoring time rather than resolving mutable audience presets at runtime. | Later preset changes become reviewable config diffs instead of silent policy changes. |
| P-015 | Reject YAML aliases, merge keys, and duplicate keys in v8 policy files. | Avoids hidden precedence, parser parity problems, alias expansion attacks, and comment-preserving edit ambiguity. |
| P-016 | Do not allow implicit observability environment variables to override an explicit v8 graph; allow only documented bootstrap values and source-declared secret references. | Keeps `config.yaml` the central reviewable policy and makes effective provenance reliable. |
| P-017 | The authenticated target-release resolver automatically detects supported POSIX v7 configuration, installs the verified `0.8.4` bridge, re-execs under its fresh controller, and then runs the target v8 migration from one user command. | Keeps the operator workflow to one command while making the mandatory controller boundary explicit and verifiable. |
| P-018 | The registered migration builds and validates the complete candidate before replacing any source file. | A conversion error never exposes partial v8 YAML. |
| P-019 | A required conversion, target-start, or health-check failure restores the exact healthy `0.8.4` CLI, gateway, v7 configuration, cursor, and custodied state and never leaves the v8 gateway running against v7 policy. | Protocol-2 rollback prevents an invalid mixed-version state and preserves the original failure in a durable receipt. |
| P-020 | Reuse the verified release, backup, service stop/start, health-check, and migration-cursor mechanisms inside a protocol-2 staged transaction; statically verify both bridge and target capabilities before confirmation or mutation, and re-exec under the fresh `0.8.4` controller before entering the hard cut. | A checksum-valid artifact can still expose an incompatible controller or migration protocol; the published bridge and fresh-process handoff make rollback ownership explicit while keeping the operator workflow to one command. |
| P-021 | Keep v8 SQLite migrations additive and readable by the immediately previous supported release. | Makes ordinary rollback sufficient for this feature. |
| P-022 | The existing upgrade confirmation or `--yes` is sufficient; the redacted migration summary appears in that prompt. | Avoids a plan file, hash, typed phrase, or second apply operation. |
| P-023 | The standalone migration CLI is an optional preview/support surface using the exact same library as upgrade. | Prevents preview and automatic conversion from drifting. |
| P-024 | Fail the normal upgrade permission preflight when active config cannot be backed up and atomically replaced; do not change ownership. | Respects configuration ownership without inventing a managed-config transaction. |
| P-025 | Optional exporter unavailability is degraded runtime health, not an upgrade rollback condition, when the gateway and built-in SQLite store are healthy. | Avoids making a valid local upgrade depend on remote service availability. |
| P-026 | Detector catalog v1 exposes exactly `pii`, `credentials`, and `secrets`, with the stable detector-ID membership defined in the redaction contract. | Makes custom-profile validation and behavior implementable and portable across Go/Python validation. |
| P-027 | OTLP signal transports are enabled by the union of signals selected by `send` or `routes`; `signal_overrides` changes endpoint/path details but has no second `enabled` gate. | Removes a common “route exists but transport is disabled” failure mode. |
| P-028 | Keep v7 notification-only `observability.connectors[*].webhooks` as a typed compatibility child while migrating/rejecting connector `audit_sinks`. | Avoids silently turning notifications into log sinks or expanding this breaking change into a notification redesign. |
| P-029 | Use pinned OTel stable and GenAI conventions as the portable trace base, with a focused `defenseclaw.*` overlay for security, policy, lifecycle, correlation, provenance, bucket, and privacy semantics. | Keeps common AI telemetry interoperable without forcing non-standard security concepts into apparently standard keys. |
| P-030 | Replace separately hand-authored OTel schema files with one logical OTel-registry-compatible registry, split into focused GenAI/security/operations authoring files, that generates the JSON Schema bundle, catalog, docs, constants/builders, fixtures, field classes, and vendor projections. | Avoids both a forest of duplicate schemas and one giant file; changes normally require one domain entry rather than synchronized artifacts. |
| P-031 | Treat OpenInference and Galileo shapes as generated compatibility projections from canonical OTel GenAI plus DefenseClaw data. | Preserves backend compatibility without making one vendor or alias schema canonical. |
| P-032 | Preserve current Galileo agent/LLM/tool behavior and add retriever/workflow shapes, judge-chat spans, safe security events, rich correlation/timing/error metadata, and full general-OTLP security graphs. | Provides richer AI observability while respecting Galileo’s supported shapes and retaining vendor-neutral traces. |
| P-033 | Use bounded short operation traces, span events, and links rather than one hours-long agent-session span. | Preserves real-time export, avoids backend finalization problems, and correlates long sessions through stable IDs. |
| P-034 | A successful security control returning block/deny is not itself an OTel error; the prevented requested operation may be an error with `error.type=policy_denied`. | Separates successful security decisions from control failure while keeping blocked operations visible. |
| P-035 | Compile omitted capability policy and concise source YAML into the same immutable effective route graph as advanced policy; generated objects never become a second runtime path. | Separates operator simplicity from internal completeness. |
| P-036 | Require only validate, effective/reference, plan, and destination-test UX for v8; defer path explain, advanced lint, event explanation, and interactive schema browsing. | Prevents optional diagnostics from delaying the core simplification. |
| P-037 | Gate rich telemetry/schema consolidation as a separate implementation phase built on the unified router. | Preserves the requested rich signals without coupling them to basic configuration parsing and migration. |
| P-038 | Use one cross-language HMAC-SHA-256 `hash-v1` contract with a shared Unicode-13.0 repertoire, percent-normalization-before-dot-segment URI order, numeric default-port handling, a shared success/error fixture, and a versioned token; fail closed when the installation key is unavailable. | Prevents Go/Python/Unicode-version drift and unkeyed reversal/correlation surprises. |
| P-039 | Apply guarded validation and dialing to every push exporter. Private/CGNAT collector access requires explicit per-destination YAML opt-ins; metadata/link-local endpoints remain blocked. | Makes the asserted SSRF safety a real transport contract while supporting intentional local collectors visibly. |
| P-040 | Bind `defenseclaw-genai-rich-v1` to one immutable four-version tuple and use `scripts/generate_telemetry_registry.py` through the existing `make check-schemas` gate. | Removes schema/profile ambiguity and avoids naming CI targets that do not exist. |
| P-041 | Preserve judge-body retention independently from its relocated path: explicit YAML wins except the current off-like environment override, absence remains default true, and the environment gate is retired after migration. | Prevents an upgrade from silently turning raw forensic retention on or off. |
| P-042 | Use one canonical outcome vocabulary in the envelope; each log/span family registers a required/optional/forbidden outcome contract plus an exact applicable subset and cannot invent synonyms. Metrics have no family envelope-outcome contract; any outcome label is a separately validated canonical dimension with explicit legacy projection. | Keeps logs, traces, routing, dashboards, and generated schemas comparable without making metric recording look like a completed operation or accepting globally valid but family-impossible outcomes. |
| P-043 | Treat the Galileo 1,000 ms scheduled delay as a deliberate v8 preset default; the real v7 inherited default is 5,000 ms and explicit operator values are preserved. | Corrects the baseline while making the v8 behavior change visible in migration. |
| P-044 | Automatic migration materializes any narrower or redacted v7 behavior instead of allowing fresh-v8 full-fidelity defaults to broaden an upgraded installation. | Makes the new default simple for new configurations without silently changing existing operators' collection, routing, or privacy posture. |
| P-045 | Keep the real 60-second delta metric-export default; the bundled Collector converts delta sums to cumulative Prometheus series, uses one application-metric path, and Grafana advertises a Prometheus interval of at least 60 seconds. | Preserves current runtime semantics and prevents the false `No data`/zero behavior fixed by PR #412. |
| P-046 | Generate a versioned `local-observability-v1` consumer profile from the telemetry registry and dashboard inventory, preserving Loki chronology, Prometheus aggregates, Tempo waterfall ownership, Agent360 spanmetrics dimensions, datasource/dashboard UIDs, aliases, source/packaged parity, and the immediately previous bundled query contract for one declared compatibility window. | Makes dashboards an explicit tested consumer instead of an implicit collection of fragile query strings and keeps a temporarily stale optional bundle useful after upgrade. |
| P-047 | Make `judge_bodies.db` the sole authoritative v8 judge-body store. Upgrade copies legacy `audit.db.judge_responses` idempotently by stable ID, verifies target commits before writer cutover or source cleanup, deduplicates compatibility reads/authorized local exports with the authoritative store first, completes export before purge, purges legacy copies before authoritative rows, and removes the runtime fallback that writes new bodies to `audit.db`. | Prevents dual writes, duplicate forensic results, unverified destructive cleanup, and silent reintroduction of raw judge bodies into the mandatory event-history database. |
| P-048 | Resolve omitted adapter transport values to the exact compiler defaults in 03 §4.4: JSONL 50 MiB/five backups/30 days/compressed, HTTP `POST`, 10-second push timeout, 2,048/512/5,000 ms push batching, general OTLP `grpc`, and Galileo HTTP/protobuf with a 1,000 ms delay. | Makes the effective graph reproducible and prevents SDK or ambient-environment defaults from silently changing operator behavior. |
| P-049 | Enforce the v1 trace-family minimums in 11 §14 as well as hard ceilings, and fail startup when the embedded semantic-profile registry disagrees with the pinned semantic-convention lock or compiled instrumentation tuple. | Guarantees that a configured “rich” trace can retain required identity/shape fields and that dependency updates cannot silently change its schema. |
| P-050 | Promote v7 inline tokens, bearer tokens, and interpolated secret headers to deterministic environment references; confine complete effective values to ancillary locked/backed-up/rollback-capable `.env` edits and exclude them from YAML, candidates/diffs, representations, and output. | Preserves valid legacy credentials without adding an inline-secret v8 grammar or leaking resolved values during automatic migration. |
| P-051 | Provide immutable built-in `legacy-v7` as a non-extendable route projection implemented by the central Phase 2 engine and selected only where migration must preserve effective v7 redaction. | Fresh v8 can remain full-fidelity by default while upgraded redacting installations retain exact string/entity/content/reason/evidence behavior without a permanent legacy pipeline. |
| P-052 | Preserve Splunk `sourcetype_overrides` and OTLP-log `logger_name` as typed adapter-owned v8 destination fields. | These are observable operator contracts that cannot be dropped merely because they do not change canonical record classification. |
| P-053 | Split v7 destinations with differing effective per-signal protocols into deterministic signal-suffixed v8 destinations; reject conflicting effective metric interval/temporality policies before write with an exact align-or-remove remediation. | Preserves representable transport intent and fails explicitly where v8 process-wide metric policy cannot losslessly represent v7 independent readers. |
| P-054 | Materialize `allow_private_networks` separately for every translated destination with an explicit v7 loopback/RFC1918/IPv6-ULA literal, including required warning/audit, while retaining unconditional blocks and prohibiting a global bypass. | Keeps working private collectors working without weakening the destination-scoped SSRF model. |
| P-055 | Materialize all effective non-secret legacy DefenseClaw/OpenClaw/standard OTel environment inputs into v8 source; preserve secret-bearing inputs as references or deterministic ancillary promotions, then retire ambient policy overrides. | Prevents environment-backed v7 installations from silently disabling or retargeting telemetry at cutover while keeping v8 policy explicit and reproducible. |
| P-056 | Generate a versioned v7 exporter/family compatibility-selection artifact from the canonical telemetry registry and require the converter to consume it without a hand-maintained family list or wildcard fallback. | Makes no-broadening migration mechanically complete across current logs, traces, metrics, actions, filters, and destination paths. |
| P-057 | Keep Phase 1 migration work side-effect-free; deliver ordinary Python writer/runtime `config_version` dispatch in Phase 4 and all activation, ancillary backup/rollback, cursor, required-failure restart-gate, and service lifecycle changes in Phase 7. | Preserves phase boundaries and prevents a pure converter from acquiring live-write/service authority or a v8 source from passing through the legacy serializer. |
| P-058 | Fix canonical record envelope version and bucket catalog version at integer `1`; use an immutable, bounded, losslessly and deterministically serialized generic record with an exact log/trace `body` versus metric `instrument_data` union, exact correlation/provenance objects, exact non-inherited field classification, catalog-derived mandatory state, and an internally marked minimal floor builder. Ordinary callers provide complete explicit classes and cannot assert schema derivation or floor eligibility. P2 owns this generic substrate and current classified-log adapter, while P5-WP02 exclusively owns generated detailed family builders, applicable outcome subsets, and schemas. | Gives the router one safe identity, privacy, floor, and serialization boundary now without duplicating or pre-empting the generated telemetry-family API. |
| P-059 | Version detector catalog v1 as an exact ordered machine-readable 14-detector contract; compile the authoritative built-in profile/class matrix into one immutable per-route projection engine with fixed work/output/report bounds and 4 KiB projected-record headroom. Explicit complete field maps fail the whole projection before value traversal when invalid. Keyed domain-separated correlation tokens, fixed-path owner-only key custody, exact projection metadata, same-context-only trusted idempotence, and pure scoped `legacy-v7` helpers are required. Custom size/excerpt/key knobs and global bypass state are excluded. | Makes substring precision, fail-closed behavior, cross-language correlation, route independence, and compatibility mechanically testable while preserving the fresh-v8 `none` default and preventing destination adapters or token-shaped input from bypassing central policy. |
| P-060 | Keep metadata and schema-approved identifiers immutable under every custom redacting profile, and derive each delivery projection's `field_classes` map from the surviving projected leaves while leaving the canonical complete map unchanged. Removed object properties cannot survive as pointer names; a nonempty container emptied solely by descendant removal is pruned recursively. Array `null` replacements retain stable indices, but only an exact classified leaf retains its class; no container class is synthesized. | Prevents configurable transforms from rewriting truthfulness/correlation metadata and prevents strict removal from leaking user-controlled property names or presence through stale classification entries or empty parent shells. |
| P-061 | Treat JSON object member names as schema-owned structural vocabulary. Producer/provider/tool-controlled names and arbitrary dynamic-map keys are encoded as explicitly classified string values rather than property names; P2 current adapters own this producer contract and P5 generated registry builders enforce it mechanically. | Keeps field-name handling simple and interoperable without adding a second key-classification language, while closing the remaining property-name content channel that value-only redaction and empty-shell pruning cannot solve. |
| P-062 | Give every queue-backed optional destination implicit 2,048-record/64-MiB count-and-byte limits and an optional common `batch` override; JSONL/console accept only that queue subset. Push kinds additionally default to 512 records/8 MiB/5,000 ms per batch, with the practical hard maxima, count relationship, and distinct byte-accounting domains in 03 §4.4. | Keeps common source YAML concise, makes advanced capacity tunable in `config.yaml`, and prevents a bounded record count from still allocating gigabytes through maximum-sized projections or batches. |
| P-063 | Build Splunk HEC compatibility aliases only from the already-redacted, schema-validated immutable projection selected for that Splunk destination; omit an alias whose source was removed and never fall back to a canonical record, producer object, raw body, or another destination projection. | Preserves useful downstream compatibility without reopening a destination-specific privacy bypass or making the HEC wrapper a hidden copy of raw content. |
| P-064 | Permit bounded retry for both pre-write transient transport failures and post-write ambiguous acknowledgement loss. Every retry reuses the exact immutable destination projection and record ID; authentication, permanent-payload, and unsafe-endpoint outcomes remain terminal for that delivery sequence. | A collector may commit a request before its acknowledgement is lost. Retrying preserves availability while the stable record ID makes the explicitly permitted duplicate window deduplicable without re-running redaction or recovering canonical content. |
| P-065 | Permit `signal_overrides.<signal>.path` only for OTLP HTTP/protobuf transports and reject it for gRPC transports. Per-signal endpoint overrides remain valid for every protocol. | OTLP gRPC service method paths are fixed and the Go exporters expose no safe custom method-path contract; rejection prevents a configured knob from being silently ignored while preserving useful HTTP collector layouts. |
| P-066 | Preserve explicit plaintext HTTP compatibility for HTTP JSONL and Splunk, but emit one content-free `plaintext_credentials` warning/audit whenever resolved authentication or secret-backed headers would cross it. | Keeps intentional local/legacy collectors usable while making credential exposure visible without leaking the endpoint, header, reference, or resolved secret. |
| P-067 | Resolve telemetry registry groups once in DAG order with signal-owned roles: attribute groups remain attributes, body groups transpose inherited uses to body fields, and each log extends exactly one body group. Duplicate references merge only through the non-weakening `required > conditional > recommended > optional` lattice and representable restrictive constraint intersection; ambiguity fails and generated consumers use the materialized resolved contract. | Preserves intentional stronger lifecycle/body requirements, prevents source order or renderer-specific inheritance from weakening schemas, and gives Go, Python, JSON Schema, redaction, and catalog generation one exact family shape. |
| P-068 | Keep the twenty-one already-published public schemas and their five mirrors/embeds directly owned at their established paths. Validate their Draft 2020-12 shape, identifiers, local reference closure, fixtures, and exact mirror/embed parity through a fixed path inventory; do not import or regenerate them through the telemetry compiler. | Preserves published bytes and useful schema checks without a 15,000-line public-view IR, historical baseline subsystem, adoption protocol, or a second authority for files that already exist. |
| P-069 | Define one typed `registry.yaml` `structural_contract` as the only authored source for the canonical envelope, exact correlation/provenance objects, signal payload union, payload-rooted field classifications, trace/resource/scope/event/link structure, raw metric observations, condition and lifecycle catalogs, and canonical-to-OTLP representations. Generated builders reuse `internal/observability.Record`, `RecordInput`, `Value`, and their existing constants rather than creating a parallel record model. | Makes the composed domain registry sufficient to generate a complete public bundle and runtime builders, closes the remaining prose-only structural gaps, and prevents examples, vendor adapters, Go, Python, and JSON Schema from independently inventing incompatible wire shapes. |
| P-070 | Add one closed generated-builder source contract for dynamic mandatory rules, structured value types/bindings, explicit derived trace values, and deterministic example builder contexts; materialize it with P-069 into one immutable enriched `CandidateRenderIndex`, and validate the exact seven generated Go files as one in-memory candidate and final committed checked-in set. Publication uses an explicit output list, canonical gzip for six large runtime JSON artifacts, same-directory temporary files, fixed modes, atomic per-file replacement, and deterministic rerun repair—never a durable journal, rollback database, ownership manifest, or synthetic ABI for an unreleased `internal/` package. Stable wire IDs and existing typed producer calls remain; generated filenames, private descriptor types, declaration totals, and compiler IR shapes do not become compatibility contracts. The selected canonical family is the sole mandatory-floor program. Generated/runtime authority stores each exact identity once, each contextual identity set once, and each producer as a default/set reference; it never checks in the producer-by-set Cartesian product. The sole structured-recursion exception remains the bounded non-null canonical-JSON sealed union over the four digest-pinned OTel GenAI structural inputs. Public inputs expose no map/`any`/raw `Value`; portable output paths pass exact and NFC-case-fold uniqueness preflight; compatibility-only/removed identities have no builder. | Preserves the wire/runtime contract, typed call sites, deterministic safety, and structured GenAI validation while removing compiler bookkeeping, expanded producer rows, and text artifacts that made routine additive changes unreviewable. |
| P-071 | Add one closed `registry.yaml` `inbound_bindings` catalog to the P-069/P-070 materialized authority. Authored classes expand into exact discriminator match descriptors (`class_id + variant_id`) and separate one-family target descriptors (`match_id + target_family_id`), so explicit import/derivation augmentations are not classifier ambiguity and finite aliases cannot collide on one target. Generated native-exact/native-malformed/external shape classification, discriminators, self-echo recognizers, typed mappings, private non-floor log import contexts, sealed exact trace/metric target construction capabilities, fixtures, and the inbound compatibility manifest are the only accepted-record path; trace/metric families deliberately have no parallel `import_context_id` registry because they have no mandatory-floor or SQLite path. Zero/ambiguous matches, malformed reserved-native shapes, and arbitrary unknown fields have no generic fallback. | Makes bucket/family/classification authority reviewable and generated while preventing runtime wildcards, hand-coded name heuristics, sender-selected buckets/floor state, decoded raw pass-through, and connector fallback for incomplete native records. |
| P-072 | Give every imported/derived occurrence a new local record ID and trusted local provenance plus an exact optional generated `provenance.import` object. Preserve semantic `defenseclaw.instance.id` as the original upstream resource identity, carry the immediate exporter separately as `defenseclaw.telemetry.forward.instance_id`, cap completed DefenseClaw forwarding at four hops, and suppress self/same-destination output only from the local forward-instance/destination pair. Another instance's destination name remains provenance and never populates local `OriginDestination`. | Preserves correlation without conflating original process identity with transport provenance, prevents cross-instance destination-name collisions from suppressing local routes, and terminates honest remote cycles through the hop bound rather than a spoofable name. |
| P-073 | Run inbound processing in the exact `OTLP-I01` through `OTLP-I10` order: decode, generated identity, loop check, collection before full construction, typed mapping, generated validation, SQLite-first imported-log persistence, ordinary routing, content-free accounting, and retry-safe acknowledgement. Unknown values are dropped and counted; local registry classes and per-route redaction always apply. | Completes the collection/redaction/storage contract without a raw-body bypass or a second inbound pipeline. |
| P-074 | Classify every decoded leaf with one primary disposition, process mixed batches independently, keep permanent record-level drops on the existing empty-success retry-suppression response, and make ordinary repeated inbound leaves new at-least-once occurrences. Emit completed versus partial batch health and the fixed six permanent drop-reason occurrences exactly as 15 §8 defines; a nonempty all-self-suppressed batch emits no new canonical health, metric, or trace that could restart the loop. Only the exact cumulative Claude token-series rule deduplicates observations; one local projection retains its record ID across P-064 retry. | Makes partial outcomes and duplicates truthful without retry storms, batch-wide loss, recursive health telemetry, or an unsupported exactly-once claim. |
| P-075 | Preserve PR #403 through exact native/generated span reverse mappings without fabricating missing lifecycle facts, and preserve PR #412 through the exact Codex/Claude token and duration derivations. Already aggregated histograms are not lossless canonical observations; the one required duration compatibility case is explicitly one arithmetic-mean derived observation, never raw import. | Keeps the current lifecycle/dashboard value while removing broad substring heuristics and false claims about reconstructing data that OTLP aggregation has already discarded. |
| P-076 | Treat OpenClaw EventRouter lifecycle frames as bounded, outcome-free `log.agent.run.observed` occurrences. Retain and validate optional `sessionId`, agent, parent-session, and depth facts from the current broadcast; derive lifecycle/execution identity only from a real session incarnation and agent; resolve parent/root identity only through a bounded cache of separately observed source-backed sessions. Never relabel literal run `start`/`end`/`error` observations as session/subagent transitions or retain a live trace/generation lease across deliveries. | Preserves real recursive OpenClaw lineage when supplied while preventing source-poor frames, reused routing keys, configured defaults, retry errors, or reconnect gaps from fabricating topology, outcomes, duration, or reload-blocking handles. |

## 4. Explicitly Excluded Behavior

The following MUST NOT appear incidentally in the v8 observability implementation:

- A global redaction-disable environment variable that bypasses all destinations.
- `DEFENSECLAW_REVEAL_PII` altering persistence, export, or judge-body retention;
  if retained, it is an authorized local display-only control.
- An enabled optional destination with omitted policy silently doing less than its
  documented all-bucket, all-capability, unredacted default.
- A route enabling a signal whose bucket collection is disabled.
- Built-in SQLite persistence being optional, disabled, or dependent on a
  user-authored catch-all route.
- Remote export of a floor-only record.
- Full prompt/tool content hidden in evaluation or finding fields.
- Arbitrary administrator regex redaction.
- Model-generated evidence/remediation treated as authoritative without explicit
  provenance and a separately approved feature.
- Finding case status, analyst assignment, SLA, comments, or ticket synchronization.
- Webhooks reclassified as generic log sinks.
- Exactly-once remote delivery claims.
- Automatic blocking VACUUM.
- Reaping current enforcement state or asset snapshots.
- Gateway startup or reload automatically rewriting v7 configuration. The staged
  target-release resolver and migration controller perform the one-time migration.
- Running old and new observability pipelines in permanent parallel.
- Configuration includes, scoped policy files, or remote/globbed sources.
- Mutable runtime audience presets whose meaning can change after upgrade without a
  source-config diff.
- Silently delivering buckets introduced after the config's reviewed catalog
  version through a non-SQLite wildcard.
- Supported CLI/TUI mutations that strip operator comments or section guidance.
- Continuing a failed required v8 migration and asking the operator to repair it
  after the new gateway starts.
- Requiring users to hand-copy configuration as the normal rollback mechanism.
- Bypassing the existing verified release mechanism for an upgrade that mutates
  configuration.
- A DefenseClaw-only replacement for standard OTel/GenAI agent, model, tool, or
  retrieval fields when an applicable pinned standard field exists.
- Galileo-specific fields in the canonical producer model or Galileo becoming a
  forked canonical span schema.
- Independently hand-maintained per-family OTel schemas after the generated registry
  architecture is committed.
- Unbounded span names, attributes, events, links, content, or stack traces in the
  name of richer telemetry.
- Collapsing root-agent lineage, upstream conversation, stable lifecycle, execution
  attempt, operation, and bounded trace identity into one ID.
- Waiting for `Stop`/session end before exporting already completed model, tool,
  turn, decision, or lifecycle work.
- Treating a dashboard query that parses but addresses a nonexistent label/field,
  returns a cadence-induced false zero, or loses root/subagent scope as compatible.
- Resetting local Prometheus, Loki, Tempo, or Grafana volumes as part of upgrade.
- Keeping a resolved v7 inline/interpolated credential in v8 YAML or any migration
  summary, diff, diagnostic, object representation, or compliance record.
- Approximating effective v7 redaction with `sensitive`, `content`, or `strict`
  instead of the immutable `legacy-v7` compatibility projection.
- A converter-local hand list of current producer/exporter families or a wildcard
  fallback when generated v7 compatibility selection is missing.
- Guessing one protocol across different v7 per-signal protocols, or silently
  selecting one of several conflicting effective metric policies.
- Routing a v8 source through the connector-only v7 Python serializer, or placing
  required-failure restart/rollback behavior inside the Phase 1 pure converter.

## 5. Review Checklist

Before marking the spec approved, reviewers should answer yes to each question:

### Taxonomy

- Can every current producer fact be assigned one bucket without copying content?
- Are model/tool/evaluation/finding boundaries sufficiently clear?
- Are AI Defense and connector distinctions expressible through selectors?
- Is omission of finding workflow status intentional for this scope?
- Is the `NONE`-to-`INFO` clean-evaluation mapping acceptable while keeping the
  canonical five-rung route ladder?

### Configuration

- Does the YAML permit required audience profiles without hidden global behavior?
- Is multi-destination fan-out plus concise-versus-advanced routing clear?
- Is automatic, non-disableable local persistence acceptable without source
  boilerplate?
- Are full-fidelity `none` defaults and generated capability-wide destination sends
  visible enough in source/effective/plan/doctor/TUI views?
- Is compact source plus effective/reference output preferable to an enormous live
  all-knobs file?
- Is one concise source file sufficient without includes or bucket-set indirection?
- Are materialized authoring presets understandable?
- Is bucket-catalog pinning acceptable for optional-destination wildcards?
- Is route-derived OTLP signal activation clearer than a separate enablement map?
- Are the focused v8 CLI release gates sufficient, with advanced diagnostics
  deferred?
- Is preserving comments across every supported config mutation a release gate?
- Are private/CGNAT push-collector opt-ins narrow and visible enough, with metadata
  and link-local endpoints still unconditionally blocked?

### Privacy

- Can disabling content logs be verified end to end?
- Are field classes and unknown-field behavior fail-safe?
- Is the local judge-body exception sufficiently isolated?
- Are redaction failures safe and observable without leaking failed values?
- Is the cross-language keyed `hash-v1` normalization/token contract suitable for
  path correlation and key rotation?

### Operations

- Is 90 days and one global age acceptable?
- Is six-hour/1,000-row reaping appropriate?
- Is remote drop-newest backpressure acceptable?
- Are restart-required and reloadable fields correctly divided?
- Are the PR #403 lifecycle identity/event/phase and missing-data contracts
  preserved without requiring session end for completed-operation export?
- Do Loki, Prometheus, and Tempo retain their documented dashboard ownership, with
  60-second delta export and Collector delta-to-cumulative conversion?
- Do all fourteen dashboard UIDs, the Agent360 variable/query contracts, and
  source/packaged parity remain release-gated?

### Migration and upgrade

- Can every supported local v7 installation migrate with one ordinary
  `defenseclaw upgrade` command?
- Can connector-specific v7 overrides be translated without losing intent?
- Is the complete target candidate validated before the source file is replaced?
- Does a required conversion failure preserve exact v7 config and prevent an
  incompatible v8 gateway start?
- Are additive/backward-readable SQLite migrations sufficient for rollback?
- Does the optional standalone command produce exactly the same candidate as the
  automatic upgrade?
- Does read-only configuration fail early with an actionable path and no ownership
  change?
- Does the automatic migration preserve judge-body retention state independently of
  its database-path move and correctly disclose the Galileo preset-delay change?
- Are inline/interpolated secrets promoted without entering YAML/output, with the
  ancillary `.env` included in exact backup and rollback?
- Do differing signal protocols split deterministically, conflicting metric
  policies fail with exact remediation, and every private literal receive only a
  destination-scoped opt-in?
- Is every effective legacy OTel environment input materialized and every current
  family selected from generated registry compatibility data rather than a hand
  list?
- Is `legacy-v7` exact and non-extendable, and can an unrelated Python writer never
  erase a v8 observability graph?
- Are setup, doctor, TUI, dashboards, and docs included before release?
- Does the ordinary upgrade refresh compatible DefenseClaw-owned local-stack assets,
  preserve custom files and history volumes, and verify readiness without requiring
  a separate migration command?

## 6. Spec Change Control

Any implementation PR that intentionally differs from a normative requirement must:

1. Update this specification first or in the same reviewed stack base.
2. Identify the changed decision and downstream documents/tests.
3. Describe the compatibility, security, privacy, and operator impact.
4. Add or update acceptance tests.
5. List any remaining future work only through linked GitHub issues, following the
   repository PR instructions.

Every decision in this document is indexed by
`13-decision-traceability.md`. Spec lint MUST reject an ID missing from that
appendix, a duplicate mapping, or a mapping without both contract and verification
targets.
