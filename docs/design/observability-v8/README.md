# DefenseClaw Observability v8 Specification Package

## Status

Approved contract for spec-driven implementation. The execution ledger records
phase-specific implementation and verification progress.

- Target configuration version: `8`
- Prepared: 2026-07-02
- Approved for implementation: 2026-07-02 at `963b1bc9f`
- Repository baseline: DefenseClaw configuration v7
- Repository location: `docs/design/observability-v8/`
- Execution ledger: [`../../../spec.md`](../../../spec.md)
- Decision registry: 23 locked product decisions, 12 semantic decisions, and 75
  ambiguity-removal decisions (110 total)

## Purpose

This package specifies a unified logging, audit, OpenTelemetry, destination-routing,
redaction, local-retention, and security-finding pipeline for DefenseClaw. It
consolidates the two design plans developed during discovery and incorporates the
subsequent semantic clarifications about audit activity, security findings,
guardrail evaluations, model I/O, tool activity, scan execution, asset lifecycle,
and enforcement.

The implementation is intended to be driven from these requirements. If
implementation discovers a requirement that is ambiguous or infeasible, the spec
must be amended and reviewed before behavior is silently changed.

## Normative Language

The terms **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and
**MAY** are normative. “Record” means one canonical DefenseClaw signal record.
“Log” means a discrete event record, not all observability signals collectively.

## Document Map

| Document | Contents |
|---|---|
| [01-architecture-and-requirements.md](01-architecture-and-requirements.md) | Goals, non-goals, pipeline architecture, invariants, failure behavior, and mandatory compliance floor |
| [02-taxonomy-and-data-model.md](02-taxonomy-and-data-model.md) | Fourteen buckets, classification rules, examples, correlations, finding evidence/remediation semantics |
| [03-configuration-contract.md](03-configuration-contract.md) | Complete `config.yaml` v8 contract, routing grammar, selectors, destination capabilities, validation, and reload |
| [04-redaction-contract.md](04-redaction-contract.md) | Central projection/redaction profiles, unredacted defaults, field classes, detectors, transformation behavior, and fail-closed behavior |
| [05-storage-retention-and-delivery.md](05-storage-retention-and-delivery.md) | Mandatory SQLite behavior, canonical and projection storage, reaper, delivery isolation, and health reporting |
| [06-migration-and-implementation.md](06-migration-and-implementation.md) | Current-state mapping, automatic v8 upgrade migration, phased implementation, removal of duplicate paths, operator surfaces |
| [07-verification-and-acceptance.md](07-verification-and-acceptance.md) | Traceable acceptance criteria, test matrices, scenarios, performance checks, and release gates |
| [08-decisions-and-exclusions.md](08-decisions-and-exclusions.md) | Locked decisions, assumptions, explicitly excluded behavior, and review checklist |
| [09-configuration-ux-and-bucket-evolution.md](09-configuration-ux-and-bucket-evolution.md) | Concise/effective/reference config model, focused CLI discoverability, comment preservation, catalog evolution, and bucket-change difficulty |
| [10-automatic-upgrade-and-migration.md](10-automatic-upgrade-and-migration.md) | Automatic v7-to-v8 migration inside `defenseclaw upgrade`, reuse of existing mechanisms, validation, backup/recovery, and release tests |
| [11-trace-and-span-contract.md](11-trace-and-span-contract.md) | Rich trace topology, span families, GenAI/OpenInference attributes, events, links, Galileo projection, limits, and acceptance |
| [12-telemetry-schema-architecture.md](12-telemetry-schema-architecture.md) | One OTel-compatible schema registry, standard-plus-DefenseClaw composition, generated artifacts, versioning, and migration from hand-authored schema files |
| [13-decision-traceability.md](13-decision-traceability.md) | Mechanical mapping from every D-/S-/P- decision to its normative contracts and required verification |
| [14-agent-lifecycle-and-dashboard-compatibility.md](14-agent-lifecycle-and-dashboard-compatibility.md) | PR #403 root/subagent lifecycle and traceability compatibility, PR #412 dashboard data contracts, local-stack signal ownership, and upgrade verification |
| [15-inbound-otlp-import-and-reexport.md](15-inbound-otlp-import-and-reexport.md) | Closed generated inbound OTLP mappings, accepted-record construction, provenance/hops, partial batches, redaction/re-export, and executable acceptance matrix |
| [current-state-inventory.yaml](current-state-inventory.yaml) | Machine-readable v7/current config, producer, schema, metric, dashboard, datasource, and compatibility baseline with migration dispositions |
| [config-v8-observability-minimal.yaml](config-v8-observability-minimal.yaml) | Recommended compact starting point with explanatory ASCII banner |
| [observability.yaml](../../../schemas/config/v8/reference/observability.yaml) | Fully commented reference showing all observability knobs and destination kinds |

## Executive Decisions

1. Every event has exactly one primary semantic bucket.
2. Logs, traces, and metrics have separate collection controls per bucket.
3. Collection happens before routing. A route cannot resurrect a disabled signal.
4. A built-in SQLite store is mandatory and implicit; source YAML only overrides
   its local path and retention settings.
5. A narrowly defined compliance floor can create a local SQLite log even when
   ordinary log collection for its bucket is disabled.
6. Remote export begins when an optional destination is enabled. With no explicit
   policy it receives every catalog bucket, unredacted, and all signals its kind
   supports. Concise `send` and advanced routes narrow or redact that default.
7. A matching record can be sent to multiple destinations; advanced-route
   precedence is first-match-wins independently within each destination and signal.
8. Redaction is centralized and evaluated per destination policy. Each destination
   receives an independently redacted projection of an immutable canonical record.
9. `redaction_profile: none` is the catalog, local, and capability-default profile.
   Every defined signal is collected by default, and every collected log is stored
   locally unredacted. Redacting profiles are explicit opt-ins.
10. Built-in redaction profiles are composable from built-in detectors and field
    classes. Arbitrary administrator regex is not supported in v8.
11. Redaction failures fail closed at field level and do not silently drop the
    entire record.
12. Configuration v8 is a runtime cutover. Legacy `otel`, top-level and connector
    `audit_sinks`, and `privacy.disable_redaction` blocks are rejected by runtime
    validation; connector `webhooks` remain notification-only compatibility data.
13. The normal `defenseclaw upgrade` command automatically migrates supported v7
    configuration. A standalone CLI command is optional for preview/support; the
    gateway performs no startup migration and runs no dual-format mode.
14. Valid configuration reload is atomic. Invalid reload leaves the previous
    runtime graph active.
15. Local retention defaults to 90 days and applies to event, evidence, and judge
    response history. Enforcement state and current asset state are never reaped.
16. `security.finding` is an immutable observation in this scope. The v8
    observability change does not introduce case management or a synthetic
    `status: open` lifecycle.
17. The live source config stays compact through implicit local storage,
    capability-default destination sends, concise narrowing policies,
    route-derived OTLP signal activation, and optional advanced routes. Fully
    resolved and documented views are generated on demand.
18. Configuration v8 does not add includes or scoped files; the concise authoring
    form removes the immediate need for them.
19. Bucket IDs are append-only and governed by an effective catalog version that
    defaults deterministically from `config_version`. New runtime buckets remain
    local-only until the operator reviews and advances that catalog version;
    optional-destination wildcards do not silently absorb them.
20. Supported config mutations must preserve comments, key order, and the concise
    ASCII operator guide in existing v8 YAML.
21. A supported v7 installation needs only the ordinary `defenseclaw upgrade`
    workflow and its existing confirmation or `--yes`; no intermediate release,
    plan file, plan hash, or second apply step is required.
22. The target release runs one registered required migration that builds, validates,
    and atomically activates the v8 candidate after the ordinary upgrade backup.
23. A failed required conversion leaves or restores the exact v7 source and never
    starts a v8 gateway against it; the existing gateway-binary snapshot remains the
    recovery artifact rather than a new rollback protocol.
24. The optional standalone migration command uses the same library as upgrade but
    is not a prerequisite for ordinary locally managed installations.
25. Trace collection uses a rich, bounded semantic contract that preserves the
    current Galileo agent/model/tool experience and adds workflow, retrieval,
    security-decision, lifecycle, timing, error, event, and link context.
26. OTel/GenAI conventions are the portable base; `defenseclaw.*` is a focused
    security/correlation overlay. One logical registry with focused authoring files
    generates the public schemas, catalog, docs, constants, fixtures, and vendor
    projections.
27. Core configuration/router work and rich telemetry/schema work have separate
    implementation phase gates. Both use the same canonical graph, but schema
    expansion does not complicate or block the concise authoring compiler.
28. The v8 release requires validate, effective/reference views, observability plan,
    and explicit destination testing. Path explain, advanced lint, event explanation,
    and interactive schema browsing are deferred UX rather than release blockers.
29. Audit/scanner `INFO` and guardrail/judge `NONE` producer ladders merge into the
    five canonical severities; clean `NONE` maps to `INFO`, while `WARN` maps to
    `MEDIUM` rather than becoming a new rung.
30. All push exporters use guarded endpoint validation and dialing. Intentional
    private/CGNAT collectors require visible per-destination opt-ins; metadata and
    link-local targets remain blocked.
31. Path hashing uses one cross-language, keyed, versioned `hash-v1` algorithm, and
    judge-body retention state is explicitly preserved by the automatic migration.
32. The config schema has a named repository path/owner, and one named telemetry
    registry compiler integrates with the existing `make check-schemas` gate.
33. The merged PR #403 lifecycle model is a compatibility floor: root/subagent,
    lifecycle/execution, turn/model/tool/approval, phase/sequence/operation,
    hook-decision, and missing-data semantics cannot disappear during unification.
34. The merged PR #412 dashboard corrections are a compatibility floor. The
    telemetry registry owns a generated `local-observability-v1` consumer profile
    covering metric names/labels/buckets, Loki/Tempo fields, datasource/dashboard
    UIDs, and source/packaged parity.
35. Gateway metrics retain the real 60-second delta default. The local Collector
    converts delta sums to cumulative Prometheus series, and Grafana's Prometheus
    datasource advertises at least that interval.
36. The ordinary upgrade backs up and refreshes the mutually compatible
    DefenseClaw-owned local-observability bundle without resetting history volumes
    or requiring a second migration command.
37. Alert acknowledgement/dismissal is mutable projection state plus immutable
    compliance activity; it never mutates a finding/event severity or creates an
    `ACK` severity rung.
38. `judge_bodies.db` is the sole authoritative v8 forensic body store. Upgrade
    performs a verified idempotent cutover and removes the runtime write fallback
    to `audit.db`.
39. V7 inline tokens and interpolated secret headers migrate to deterministic
    environment references; complete values are confined to ancillary locked,
    backed-up, rollback-capable `.env` edits and never enter YAML or output.
40. Effective v7 redaction is preserved by immutable, non-extendable `legacy-v7`
    in the central projection engine, not by approximating it with another v8
    profile or retaining a parallel pipeline.
41. Splunk sourcetype overrides and OTLP log scope names remain typed adapter
    fields. Different per-signal protocols split deterministically, while
    conflicting metric policies fail before write with exact remediation.
42. Every explicit v7 private literal gets only a destination-scoped network opt-in,
    and all effective non-secret legacy OTel environment inputs become explicit v8
    source policy before ambient overrides retire.
43. Current-family migration eligibility is generated from the canonical telemetry
    registry and consumed by the converter; no hand-maintained family list or
    wildcard broadening fallback is permitted.
44. Phase 1 owns pure candidate conversion, Phase 4 owns Python writer/runtime
    version dispatch, and Phase 7 owns activation, ancillary backup/rollback,
    required-failure restart gating, cursor state, and service lifecycle.
45. Every DefenseClaw-owned, queue-backed optional log or trace destination uses
    implicit count-and-byte queue limits with drop-newest overload behavior.
    Advanced overrides use the same concise `batch` grammar; push destinations
    additionally enforce count-and-byte ceilings on each encoded request.
46. Splunk compatibility wrappers and aliases derive only from the immutable,
    already-redacted and schema-validated projection for that Splunk destination;
    they can never recover producer, canonical, pre-redaction, or another
    destination's data.
47. One typed `registry.yaml` structural contract owns the canonical envelope,
    signal payload arms, trace/resource/scope/event/link shapes, raw metric
    observation, field classification, stable conditions, phase/code bijection,
    group lifecycle, and canonical-to-OTLP mappings. Generated APIs reuse the
    existing immutable `internal/observability` record substrate.
48. Inbound OTLP uses one closed generated binding catalog. Supported leaves become
    new locally validated canonical occurrences or explicitly labeled derived
    observations; unsupported leaves never pass through raw, and exact per-leaf
    self suppression plus a fixed four-hop ceiling bounds re-export cycles.

## Review Method

Review in this order:

1. Confirm the locked decisions in `08-decisions-and-exclusions.md`.
2. Validate the bucket boundaries and examples in
   `02-taxonomy-and-data-model.md`.
3. Validate the YAML contract and route behavior in
   `03-configuration-contract.md`.
4. Validate privacy and failure behavior in `04-redaction-contract.md`.
5. Validate config ergonomics and bucket evolution in
   `09-configuration-ux-and-bucket-evolution.md`.
6. Validate automatic upgrade migration and rollback behavior in
   `10-automatic-upgrade-and-migration.md`.
7. Validate rich trace/Galileo semantics in `11-trace-and-span-contract.md`.
8. Validate the simplified schema model in
   `12-telemetry-schema-architecture.md`.
9. Validate merged agent-lifecycle and local-dashboard compatibility in
   `14-agent-lifecycle-and-dashboard-compatibility.md`.
10. Validate accepted-record import and re-export in
    `15-inbound-otlp-import-and-reexport.md`.
11. Validate migration and acceptance scope before implementation begins.
