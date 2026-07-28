# Configuration UX and Bucket Evolution

## 1. Design Position

`config.yaml` remains the central authority, but it must not become a mandatory
catalog dump containing every default and every possible knob.

DefenseClaw distinguishes three views:

1. **Source configuration** — the compact operator-authored YAML containing only
   choices that differ from defaults.
2. **Effective configuration** — the fully resolved, secret-masked runtime snapshot,
   including defaults, generated local storage, concise-send expansion, advanced
   route order, profile inheritance, destination presets, and provenance.
3. **Reference configuration** — a generated, fully commented example that shows
   every supported field and enum but is not the operator’s live file.

The source remains reviewable. The effective view makes hidden defaults visible.
The reference shows all knobs without forcing operators to maintain them.

## 2. Operator Mental Model

Generated configuration and documentation MUST use this ASCII model:

```text
  PRODUCERS                  POLICY                         OUTPUTS
  ─────────                  ──────                         ───────

  audit actions ─┐
  scanners ──────┤       ┌─ collection off ──────────────> stop
  guardrails ────┤       │
  model I/O ─────┼──────> bucket + signal
  tool calls ────┤       │
  OTLP ingest ───┤       └─ collection on
  platform ──────┘                    │
                                     ├──────────────> SQLite (automatic, unredacted logs by default)
                                     │
                                     └─ for each optional destination
                                          │
                                          ├─ no policy -> all supported signals, all buckets, unredacted
                                          ├─ explicit concise send match, OR
                                          ├─ first explicit advanced route = drop/send
                                          │       │
                                          │       └─ project/redact -> sign -> deliver
                                          └─ explicit policy unmatched -> skip
```

And this configuration-resolution model:

```text
  config.yaml
      │
      v
                    strict parse + schema
                              │
                 defaults + catalog + presets
                              │
        local-store + capability/concise-send expansion
                              │
                     compiled route graph
                              │
              masked effective config + provenance
                              │
                       atomic runtime swap
```

## 3. Compact Source Configuration

### 3.1 Omit defaults

The default generated source file MUST contain only:

- `config_version`.
- Only bucket collection/profile overrides selected by the operator.
- Only optional destinations selected by the operator.
- Only custom redaction profiles actually used.
- `local` only when path or retention differs from built-in defaults.

It MUST NOT enumerate every bucket in the effective versioned catalog, declare a
SQLite destination, create a local catch-all route, explicitly enable a present
destination, repeat OTLP signal enablement, add an all-bucket/all-signal send to a
destination, or copy built-in default values.

### 3.2 Minimal example

```yaml
config_version: 8

# ┌──────────────────────────────────────────────────────────────┐
# │ Observability: collect -> store locally -> route -> redact   │
# │ Inspect: defenseclaw observability plan                     │
# │ Reference: defenseclaw config reference observability       │
# └──────────────────────────────────────────────────────────────┘
observability: {}
```

The catalog defaults collect every defined log, trace, and metric and use
`redaction_profile: none`; collected logs are stored locally unredacted. There is no
remote export until a destination is selected. This behavior is visible in
`config show --effective` and `observability plan`.

### 3.3 Common authoring patterns

Send everything unredacted to a general OTLP destination (the default for OTLP):

```yaml
observability:
  destinations:
    - name: otel
      kind: otlp
      endpoint: https://otel.example.test
```

The compiler generates all buckets in the effective reviewed catalog version plus
logs, traces, and metrics. A logs-only destination with the same omitted policy
generates logs only; Prometheus generates metrics only. Newer runtime buckets keep
the full-fidelity, unredacted local default but do not enter that remote wildcard
until review advances the catalog version.

Collect ordinary logs only for selected buckets:

```yaml
observability:
  defaults:
    collect: {logs: false, traces: false, metrics: false}
  buckets:
    compliance.activity:
      collect: {logs: true}
      redaction_profile: strict
    security.finding:
      collect: {logs: true}
    enforcement.action:
      collect: {logs: true}
      redaction_profile: strict
```

The mandatory local floor still creates its documented minimal records even when
ordinary collection is false. `observability plan` distinguishes ordinary and
floor-only records.

Send the same finding log to two remote destinations with different redaction:

```yaml
observability:
  destinations:
    - name: splunk
      kind: splunk_hec
      endpoint: https://splunk.example.test/services/collector/event
      token_env: SPLUNK_HEC_TOKEN
      send:
        signals: [logs]
        buckets: [security.finding]
        redaction_profile: strict

    - name: archive
      kind: http_jsonl
      endpoint: https://archive.example.test/events
      bearer_env: ARCHIVE_TOKEN
      send:
        signals: [logs]
        buckets: [security.finding]
        redaction_profile: sensitive
```

Each destination evaluates independently, so the record is also retained locally
and delivered to both matching destinations. For OTLP, selecting `traces` or
`metrics` in `send.signals` automatically enables that signal transport.

## 4. One Source File in v8

Configuration v8 adds no `observability.from`, generic include, remote include,
glob, or nested source mechanism. The concise form removes the mandatory local
destination, catch-all route, transport-enable maps, and repeated route wrapper
from ordinary source YAML, so a second file is not required to keep normal policy
readable.

If real deployments later demonstrate that one file remains unmanageable, a
separately reviewed include contract may be added without changing the compiled
runtime graph. It is deliberately not part of the v8 release gate.

## 5. Explicit Bucket Lists

Configuration v8 does not add user-defined bucket-set indirection. Concise `send`
blocks and advanced selectors contain exact bucket IDs or the sole wildcard `"*"`.
This keeps a security review self-contained: the reviewer can see exactly what a
destination receives without resolving an `@name` elsewhere in the file.

Authoring presets may generate explicit lists. The effective view always shows the
exact compiled list. A future reusable-set feature would require demonstrated
repetition in real configurations and a separate spec amendment.

## 6. Presets Without Hidden Runtime Magic

The CLI may offer authoring presets:

- `local-safe`
- `privacy-minimal`
- `security-operations`
- `ai-safety`
- `platform-sre`
- `developer-debug`

Selecting an audience preset writes explicit bucket overrides, exact bucket lists,
concise send blocks or advanced routes, and profiles into source YAML. The runtime
does not continually reinterpret a mutable name such as `preset: soc`, because
changing a built-in preset in a later release would silently change an operator’s
export policy.

Destination transport presets such as `preset: galileo` remain supported because
they are versioned adapter defaults and the effective view expands them. Security-
relevant preset changes require release notes and an effective-config diff.

## 7. Config Discoverability Commands

The v8 release requires only the existing `config validate` plus the focused
surfaces in 7.1, 7.2, 7.5, and 7.8. Sections marked deferred are useful follow-ups,
not blockers for the pipeline/configuration simplification.

### 7.1 `defenseclaw config show`

- `--source`: display the exact source file with secrets masked.
- `--effective`: display every resolved default and expansion; this is the default
  for machine troubleshooting.
- `--provenance`: annotate each value with default, file/line, preset, environment,
  or runtime source.
- `--section observability`: limit output without changing resolution.

### 7.2 `defenseclaw config reference [section]`

- Render a fully commented, version-matched reference from the canonical schema.
- Support `--output PATH`.
- Support `--format yaml|json-schema|markdown`.
- Never read or resolve secret values.

### 7.3 Deferred: `defenseclaw config explain PATH`

For a dotted path such as
`observability.destinations[].routes[].redaction_profile`, show:

- Type and allowed values.
- Default and inheritance order.
- Security/privacy sensitivity.
- Whether it is live reloadable or restart-required.
- Example.
- Schema/config version introduced.
- Current effective value and provenance when a config is loaded.

### 7.4 Deferred: `defenseclaw config lint`

Lint is stricter and more advisory than validation. It reports:

- Unreachable/shadowed routes after first-match analysis.
- Optional-destination wildcard policies.
- Effective unredacted local and destination profiles.
- Collected signals with no optional destination when remote export appears
  intended.
- Enabled destination with no records matched by the current policy.
- Unused custom profiles.
- Duplicate effective bucket entries.
- Content buckets sent remotely and their effective projection profiles, reported as
  posture information rather than an error solely because `none` is selected.
- New runtime buckets not yet reviewed under the configured catalog version.
- Oversized source files or excessive route counts.

### 7.5 `defenseclaw observability plan`

Render a matrix of bucket × signal × destination showing:

- Collected or disabled.
- First matched route.
- Send/drop/unmatched.
- Effective redaction profile.
- Span-family and destination compatibility-profile eligibility where applicable.
- Mandatory-floor behavior.
- Live/restart status.

Support filters by bucket, signal, connector, source, action, event name, and
severity.

### 7.6 Deferred: `defenseclaw observability explain-event`

Given a synthetic metadata envelope or an existing record ID, explain collection
and every destination route decision in order. Output must never reveal redacted
content.

### 7.7 Deferred: `defenseclaw observability schema`

The generated telemetry registry is discoverable without opening many schema files:

- `schema list` lists signal families, buckets, stability, and versions.
- `schema show FAMILY` shows portable OTel/GenAI fields first, followed by the
  DefenseClaw security/correlation overlay, field classes, cardinality, events,
  links, and examples.
- `schema compatibility FAMILY DESTINATION_OR_PROFILE` explains Galileo or other
  vendor eligibility and missing required fields.
- `schema diff --from VERSION --to VERSION` shows added, changed, deprecated,
  removed, sensitivity, and compatibility changes.

These commands read generated catalog data and never inspect live prompt/tool
content or resolve secret values.

### 7.8 `defenseclaw observability destination test NAME`

- `config validate` remains offline and deterministic; it does not contact remote
  services.
- An explicit destination test resolves that destination's credentials, TLS, DNS,
  endpoint, and protocol.
- The default command performs only a non-mutating protocol handshake. Where the
  backend requires a real write, the command refuses by default and requires the
  separate explicit `--write-probe` opt-in. With that flag, send a synthetic
  non-sensitive probe clearly marked as a test and report its probe ID; use a
  backend-supported dedicated test namespace/stream/index when one is available.
- The probe bypasses ordinary collection and routing and is written directly and
  exclusively through the named destination adapter. It MUST NOT enter SQLite
  event history, any other destination, normal logs/traces/metrics, or dashboard
  counts.
- Persist a separate local-only `compliance.activity` record for the operator's
  test attempt and outcome. It contains the destination name, probe ID, result,
  and bounded failure class, but no credential, sensitive response body, or probe
  body.
- Never sample a real prompt, response, finding evidence, or tool payload for a
  connectivity test.
- Mask credentials and sensitive response bodies in all output.

## 8. Canonical Schema and Generated Reference

The machine-readable source of truth is
`schemas/config/v8/defenseclaw-config.schema.json`, owned by the
`internal/config` maintainers as defined in `03-configuration-contract.md` §1.1.
Each field definition includes:

- Type and required/optional status.
- Enum/range/pattern.
- Default.
- Description.
- Example.
- Secret classification.
- Live reload or restart requirement.
- Version introduced/deprecated.
- Destination capability constraints when applicable.

Go config types, Python config types, CLI reference output, website reference, TUI
forms, examples, and validation parity tests must be derived from or checked against
the same schema. A field present in one runtime but absent in the other is a release
blocker.

The generated reference artifact is versioned in the repository. CI regenerates it
and fails on an uncommitted diff.

## 9. Precedence and Environment Variables

The goal of a central policy file is undermined if arbitrary environment variables
silently override routing, redaction, or collection. v8 therefore uses this model:

1. Compiled schema defaults.
2. Operator source YAML in `config.yaml`.
3. Explicit secret references and the small documented bootstrap environment
   surface.

Authoring presets are already materialized into source YAML and are not a runtime
precedence layer.

The only DefenseClaw-specific bootstrap environment names allowed to affect config
discovery or config-file trust are:

| Name | Exact scope |
|---|---|
| `DEFENSECLAW_HOME` | Selects the data directory and therefore the default `config.yaml` location when `DEFENSECLAW_CONFIG` is absent |
| `DEFENSECLAW_CONFIG` | Selects one explicit config source path |
| `DEFENSECLAW_DEPLOYMENT_MODE` | May force managed-enterprise trust and write-protection checks; it does not override observability policy values |
| `MIGRATION_DEFENSECLAW_HOME` | Upgrade-subprocess-only data-directory handoff; the normal gateway and config reload path MUST ignore it |

No other DefenseClaw environment name may select a source file, weaken source trust,
or override a non-secret v8 configuration value. Ordinary operating-system home
resolution is not an observability-policy override. Environment names explicitly
referenced by a secret-bearing YAML field are secret providers, not bootstrap
inputs, and affect only that field.

Allowed environment behavior otherwise is:

- Secret-bearing fields resolve environment/key-store values only through an
  explicit source reference such as `{env: OTEL_AUTHORIZATION}` or `token_env`.
- A reference name may appear in source/effective output; its resolved value must
  never appear.
- Existing standard OTel or legacy DefenseClaw environment settings may be accepted
  as migration inputs, but they MUST NOT silently override an explicit v8
  observability graph at runtime.
- `privacy.disable_redaction` and its global environment equivalent have no v8
  precedence and are rejected/ignored with actionable migration diagnostics. The
  normal upgrader preserves the effective legacy redacted/unredacted behavior using
  explicit v8 profiles where it differs from the new full-fidelity defaults.

The effective view includes provenance for every non-secret value. Configuration
hashes include policy and secret-reference identity, but not resolved secret values.
Credential rotation through an environment/key store does not rewrite policy;
destination reconnect/reload behavior must be explicit and observable.

All supported CLI/TUI/API policy mutations patch source YAML first and then request
an atomic reload. There is no durable in-memory-only observability policy that can
drift from the source file.

## 10. Comments and ASCII Art Preservation

Comments are operator documentation and must survive supported mutations.

Current risk: the Python `Config.save()` path serializes with PyYAML `safe_dump`,
which strips comments. Existing Go targeted YAML patching preserves comments for
scalar updates. v8 therefore requires:

- All mutations of an existing v8 file use a YAML node/round-trip editor that
  preserves comments, key order, scalar style where safe, and the section ASCII
  banner.
- Full object serialization is allowed only when creating a new file or when the
  operator explicitly requests normalization/reformatting.
- CLI, TUI, setup, migration, and automated policy changes use the same
  comment-preserving writer contract.
- List edits preserve comments attached to unaffected elements and route order.
- Atomic write, permission preservation, lock behavior, backup, and validation
  remain mandatory.
- Tests seed distinctive header, inline, and route comments and assert byte or node
  preservation after unrelated mutations.

The live source file MUST contain a concise ASCII flow and discovery commands,
not hundreds of lines of dormant commented settings. The separate generated
reference contains all knobs and extensive explanations.

## 11. YAML Safety and Diagnostics

- Reject duplicate keys at every mapping level.
- Reject YAML merge keys and aliases in v8 policy files to avoid hidden precedence,
  alias expansion attacks, and mutation surprises.
- Enforce the exact structural limits below before constructing an effective graph:

| Source structure | Hard limit |
|---|---:|
| Raw bytes in one config source | 4,194,304 bytes (4 MiB) |
| Parsed YAML nodes | 65,536 |
| YAML nesting depth, with the document root at depth 1 | 32 |
| Optional destinations | 64 |
| Explicit advanced routes in one destination | 256 |
| Explicit advanced routes across all destinations | 4,096 |
| Custom redaction profiles | 128 |
| Entries in any YAML mapping | 1,024 |

Raw bytes are counted before decoding. The node count includes every mapping,
sequence, mapping key, and scalar value produced by the YAML parser before defaults
or presets expand. Depth counts mapping/sequence nesting and treats the document
root as depth 1. These are rejection limits, not truncation targets. Aliases and
merge keys remain forbidden, so they cannot bypass node/depth accounting. Concise
`send` blocks and built-in preset expansion count toward effective-graph validation
but do not consume the explicit advanced-route source quota.
- Validation errors include source file, line, column, dotted path, received value
  class, and actionable expected values.
- Error output masks secret-bearing fields and headers.
- Unknown fields are errors with nearest-name suggestions.
- Every secret reference required by an enabled destination MUST resolve during
  startup/reload validation. A missing environment or key-store reference is a
  hard validation error with a masked path and corrective action, never deferred
  advisory lint.
- `config validate` verifies both Go and Python schema parity in CI; normal operator
  execution uses the local implementation without starting the gateway.

## 12. Versioned Bucket Catalog

### 12.1 Catalog version

For `config_version: 8`, omitted `observability.bucket_catalog_version` resolves to
initial catalog version `1`. The effective view always shows the resolved version.
Source YAML writes the field only when the operator intentionally advances to a
later catalog.

The catalog manifest records for every bucket:

- Stable ID.
- Human display name and description.
- Version introduced.
- Deprecated version when applicable.
- Default collection and redaction behavior.
- Sensitivity classification.

Config schema version and bucket catalog version are separate. Adding a bucket does
not necessarily require redesigning the YAML grammar.

### 12.2 Pinned behavior when runtime knows newer buckets

Suppose a config resolves to catalog version 1 (explicitly or through the
`config_version: 8` default) and a newer binary supports version 2:

- Existing v1 bucket policy is unchanged.
- A v2 bucket inherits the built-in full-fidelity fallback: collect its defined
  logs, traces, and metrics with `none`; logs enter the built-in local store.
- Optional-destination policy using `buckets: ["*"]` expands only to buckets known
  to the effective catalog version. The new bucket remains in built-in local
  history and is not delivered elsewhere until reviewed.
- The generated local catch-all always covers all runtime buckets, including newer
  ones.
- Doctor, TUI, `observability plan`, and startup health display the unreviewed new
  bucket.
- The gateway continues running; it does not fail merely because the runtime catalog
  is newer.

The operator reviews the effective diff and uses a targeted config mutation or
setup command to write the new explicit catalog version. Updating it is compliance
activity.

### 12.3 Explicit new bucket references

A config cannot explicitly reference a bucket introduced after its effective
catalog version. The operator must first update `bucket_catalog_version`. This makes
review intent explicit.

### 12.4 Bucket ID stability

- Bucket IDs are append-only public contracts.
- Display names and descriptions may improve without changing IDs.
- Do not rename an ID for wording preference.
- Do not reuse a deprecated ID for new semantics.
- Persisted historical records are never bulk rewritten merely because a producer
  is reclassified later.
- Queries may provide explicit versioned compatibility aliases, but canonical new
  records use one current ID.

### 12.5 Split, merge, and deprecation

If one bucket becomes semantically overloaded:

1. Add one or more new buckets in a new catalog version.
2. Keep the old bucket readable and routable.
3. Migrate producers in a documented release.
4. Provide a config migration preview showing affected concise sends and advanced
   routes.
5. Update dashboards and queries to include old historical IDs where appropriate.
6. Deprecate rather than immediately remove the old ID.

## 13. Difficulty of Bucket Changes

| Change | Difficulty | Reason |
|---|---|---|
| Improve display name/description | Low | No record or route identity changes |
| Add a new bucket for new producers | Medium | Catalog/schema, classification, docs, config reference, route planner, metrics, dashboards, and tests must change |
| Move one new/unreleased event between buckets | Low/medium | Classification and tests only if no persisted contract shipped |
| Reclassify an existing shipped event | High | Changes queries, dashboards, routes, exports, historical comparisons, and customer expectations |
| Split an existing bucket | High | Requires catalog bump, producer migration, route migration suggestions, and historical query compatibility |
| Rename or remove a bucket ID | Very high; avoid | Breaks stored data, strict config validation, remote queries, dashboards, and SIEM rules |

With the versioned catalog and pinned non-SQLite wildcard behavior, adding a bucket is a
controlled medium-sized change rather than a configuration-schema redesign. The
hard part is classification and downstream compatibility, not the enum addition.

## 14. Locked Configuration Assertions

The configuration review is complete. The following are implementation
requirements and are not implementation-time choices:

- Compact source/effective/reference separation.
- Implicit local SQLite storage and generated catch-all.
- Omitted capability-default destination policy, concise narrowing `send`, and
  mutually exclusive advanced `routes`.
- Route-derived OTLP signal activation with optional transport overrides.
- No includes or user-defined bucket sets in v8.
- Materialized authoring presets rather than mutable runtime audience presets.
- Comment-preserving writer requirement.
- Defaulted effective bucket catalog version and pinned optional-destination wildcard
  semantics.
- The exact source byte, node, depth, destination, route, profile, and map limits
  in section 11.
- The exact four-name bootstrap environment allowlist in section 9; all other
  non-secret environment overrides are outside the v8 config precedence model.
