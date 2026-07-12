# Automatic v7-to-v8 Upgrade Migration

## 1. Locked Decision

For a normal locally managed installation, the complete operator workflow is:

```text
defenseclaw upgrade
```

`defenseclaw upgrade` resolves a manifest-declared staged transaction. When the
installed controller predates the safe v8 migration protocol, the release-owned
resolver first installs the `0.8.4` controller bridge, verifies it in a fresh
process, and then hands the requested `0.8.5` hard cut to that controller. The
existing confirmation prompt, or the existing `--yes` option, is sufficient.

The operator does not manually install the bridge, generate or approve a plan,
run a separate apply command, type a special acknowledgement, or switch
configuration files. The intermediate release is an internal upgrade phase, not a
second user workflow.

The gateway itself remains strict: a v8 gateway does not rewrite v7 configuration
at startup or reload, and the runtime does not support v7 and v8 formats in
parallel. The released target runtime contains no live v7 producer, provider,
router, sink, bridge, or fallback path. V7 parsing remains only in this converter,
its read-only preview, historical fixtures, and rollback/recovery artifacts;
generated backend projections and legacy-shaped local read columns are v8 consumer
compatibility rather than a second runtime.

## 2. Reuse the Existing Upgrade Path

This change extends the current upgrader; it does not create another upgrade
framework.

| Existing mechanism | v8 use |
|---|---|
| Verified target artifacts | Retains integrity/provenance verification and adds a non-executing target-wheel migration-capability preflight |
| Ordinary upgrade confirmation / `--yes` | Shows that observability config will be migrated |
| `_create_backup` | Backs up the root config and, when installed, DefenseClaw-owned local-observability bundle files that the migration will replace |
| Installed-version migration registry | Registers the v8 observability conversion once |
| Migration cursor | Makes conversion retry-safe and prevents duplicate application |
| `upgrade-manifest.json` transition policy | Separates controller capability from target minimum protocol, declares the required bridge/minimum source, and limits automatic staging to tested published baselines |
| Atomic config writer | Replaces the source only after the complete candidate validates |
| Fresh-process handoff | Ends the legacy phase and runs the hard cut under the newly installed `0.8.4` controller; target code is never continued through stale imports |
| Existing service stop/start and health poll | Starts and verifies each phase; service-start and health timeouts are fatal |
| Retained bridge artifacts and exact state snapshot | Restore the verified `0.8.4` CLI, gateway, config, environment, cursor, and managed bundle if the hard-cut phase fails |
| Durable upgrade receipt | Records bridge, hard-cut, health, and rollback outcomes without declaring success early |

The bridge and hard cut are separate releases. `0.8.4` requires protocol 1 so
published `0.8.3` and older tested controllers can reach it, but installs a
controller that supports protocol 2. `0.8.5` and later require protocol 2 and a
minimum source of `0.8.4`. These are distinct manifest facts and MUST NOT share a
single constant. They may be reviewed in one pull request only when that pull
request has a short linear history containing distinct bridge and hard-cut
source trees. A reviewed release-source map pins both tree hashes, and the
release workflow resolves the matching first-parent commits after merge. A
squash merge, missing tree, duplicate tree match, or off-main source fails
closed.

### 2.1 Required release order and soak

`0.8.4` MUST be published from its pinned bridge source tree and left as the
latest release before `0.8.5` is cut from the later pinned hard-cut tree. During
that bridge window, release owners MUST run the published-baseline matrix against
the immutable `0.8.4` assets, verify macOS/Linux/Windows installation and
fresh-controller health, and confirm that ordinary `0.8.3` clients can reach the
bridge. Only after that published evidence is green may `0.8.5` become latest.
The window also lets ordinary users adopt the bridge through the frozen built-in
updater before the two-hop resolver becomes necessary.

The `0.8.5` release workflow independently downloads the published `0.8.4`
assets and reruns the complete bridge-to-target transaction. Missing, mutable,
or incapable bridge assets are a release-blocking failure; source-tree tests or
an unpublished local bridge are not substitutes.

### 2.2 Target-wheel migration capability preflight

After release integrity verification, the upgrader MUST inspect the target wheel
without importing or executing its code. It requires exactly one DefenseClaw
metadata record whose version equals the requested release; exactly one
synchronous `run_migrations` with the supported four-position argument contract;
a literal, unique, three-field `MIGRATIONS` registry whose callable references are
module-level functions; and a literal `SUPPORTED_CONFIG_VERSIONS` capability when
the target declares one. Every CLI migration required by `upgrade-manifest.json`
MUST exist in the registry and be at or below the target release version.

Any existing config requires explicit hard-cut target support for schema v8. A
legacy, unversioned, or numeric-zero source additionally requires a target stamped
`0.8.5` or later with the `0.8.5` conversion row. Malformed, mismatched, missing,
or incompatible capability fails before the confirmation prompt, backup, service
interruption, gateway replacement, or wheel installation and reports that no
installed artifact or service was changed.

### 2.3 Manifest-driven bridge resolver

The signed hard-cut manifest declares `min_upgrade_protocol`,
`controller_upgrade_protocol`, `minimum_source_version`,
`required_bridge_version`, and `auto_bridge_from`. The last field is generated
from `release/upgrade-baselines.json`, the same strictly descending matrix used by
release gates. A source outside that tested set is never guessed into an automatic
path.

Before stopping any service, every updater MUST verify this contract and the
artifacts needed by its next phase. A normal latest-version request from a tested
pre-bridge source resolves to:

```text
0.8.3 or older tested source
  -> verified 0.8.4 bridge
  -> fresh 0.8.4 controller process
  -> verified 0.8.5 hard cut
```

An explicit attempt to install the hard cut from a source below the signed
minimum fails before backup, stop, or install and states that no changes were
made. The release-owned shell and PowerShell resolvers may perform the automatic
two-hop flow. An immutable older built-in controller that cannot resolve the graph
MUST reject protocol 2 and direct the operator to that release-owned resolver; it
must not attempt the hard cut itself.

## 3. Upgrade Flow

The v8 release follows this sequence inside the existing user command:

1. Detect the installed version before any service interruption.
2. Resolve and cryptographically verify the requested target manifest.
3. If the signed minimum source is not met, require the declared bridge and ensure
   the installed source is in the published-baseline matrix. Explicit bridge skips
   and unsupported sources fail with no changes.
4. Download and verify the bridge artifacts and statically verify the bridge
   advertises a controller protocol capable of the final target.
5. Statically verify the next wheel's version, migration callable/registry,
   manifest-required rows, and config-version capability as defined in section
   2.1. Do not import target code.
6. Add a concise, redacted observability summary to the normal upgrade prompt.
7. Back up the exact bridge-phase state and retain verified bridge CLI/gateway
   artifacts in a private handoff directory.
8. Stop the gateway, install `0.8.4`, restart it, and require a fresh-process
   health check. No v8 conversion runs in this phase.
9. Terminate the legacy execution path and launch a fresh `0.8.4` controller for
   the requested hard cut. Do not continue through modules imported by the older
   process.
10. Back up the exact config source, ancillary `.env`, migration cursor, installed
   CLI/gateway, and any installed DefenseClaw-owned local-observability files that
   will be refreshed. Preserve custom files and
   persistent volumes. Because a released older upgrader creates this directory
   before it installs the target wheel, the target migration descriptor-safely
   narrows a real, trusted-owner, non-writable legacy backup root from `0755` to
   `0700`; symlinked, untrusted, writable, or unsafe-ACL roots still fail closed.
11. Stop the gateway and install the hard-cut artifacts through the existing path.
12. Run the registered target-version migrations. The observability migration
   builds the complete v8 candidate in memory,
   validates it, and atomically writes it.
13. Record the migration in the existing cursor only after the write succeeds.
14. Refresh the installed local-observability bundle to the target Collector,
   datasource, dashboard, rule, and config set. If it was running, use the existing
   stop/restart path without resetting volumes. Released upgrade clients that
   predate this phase invoke the same target-wheel transaction from the required
   migration in a clean interpreter; current clients declare ownership of the
   phase so it is not run twice.
15. Restart the gateway and require a fresh-process health check; perform bounded
    local-stack readiness/query checks when that optional stack is installed.
16. Mark the durable receipt successful only after step 15. On any second-phase
    failure, restore and health-check the retained `0.8.4` state before returning
    nonzero with the original failure and rollback outcome.

Example prompt addition:

```text
This upgrade will also migrate observability config v7 -> v8:
  3 OTel destinations
  2 audit sinks
  SQLite, JSONL, console, and Galileo settings preserved
  Agent360 lifecycle and local dashboard compatibility preserved
  existing redacted/unredacted behavior preserved under v8 profiles
```

No prompt, response, tool content, evidence, credential, or resolved secret may
appear in this summary.

## 4. Registered Migration Contract

The migration is implemented as one normal entry in
`cli/defenseclaw/migrations.py`, at the release version that introduces config v8.
It calls one deterministic conversion function shared with the optional preview.

The freshly installed target interpreter inspects `run_migrations` before calling
it. It passes `upgrade_handles_local_bundle=True` only when that exact parameter is
declared and accepts keyword use; pre-0.8.4 wheels are called without it. The
runner never calls, catches `TypeError`, and retries, because that could execute a
migration body twice. It runs in isolated Python mode so ambient `PYTHONPATH` and
the caller's working directory cannot replace the verified target package.

The conversion function is side-effect-free: it returns the v8 candidate,
secret-free summary/warnings, and declarative ancillary `.env` edits. Hard-cut
upgrade integration alone locks, backs up, applies, restores, restarts, and marks
the cursor. Ordinary target-release Python writers are v8-only and refuse a v7
source with an upgrade instruction. Only this migration boundary dispatches by
source version, so neither preview nor upgrade can accidentally re-save a v8 source
through the legacy connector-only dataclass.

The conversion function MUST:

- Treat an already valid v8 source as a no-op.
- Treat a missing config file as an unconfigured-installation no-op; a later setup
  command creates a native v8 document.
- Accept every supported v7 shape documented in
  `06-migration-and-implementation.md`.
- Treat an absent or numeric-zero version stamp as v7 only after the complete
  document validates as the current v7 shape with no v8-only observability key;
  reject an ambiguous mixed shape rather than guessing.
- Preserve unrelated config sections and notification-only webhooks.
- Preserve comments, key order, the ASCII operator guide, file mode, and ownership.
- Preserve destination identity when endpoint, credentials, TLS, batching,
  enabled signals, or routing intent differs.
- Promote every inline token/bearer token and interpolated secret header to a
  deterministic environment reference. The complete effective value exists only
  in the locked ancillary `.env` edit and backup/rollback unit; it never
  enters YAML, candidate/diff objects, or output.
- Materialize every effective non-secret legacy OTel environment input into v8
  destination policy. Secret-bearing environment/header inputs remain references
  or use the deterministic ancillary promotion above; v8 does not continue ambient
  OTel policy overrides after migration.
- Split a v7 destination with different effective per-signal protocols into stable
  signal-suffixed destinations. If effective metric interval/temporality policies
  conflict, fail before write and name the destinations/fields plus the exact
  align-or-remove remediation instead of broadening or guessing.
- Preserve Splunk `sourcetype_overrides` and OTLP-log `logger_name` as typed v8
  adapter fields.
- Materialize `network_safety.allow_private_networks: true` separately on every
  translated destination whose explicit v7 literal is loopback, RFC1918, or IPv6
  ULA, with warning/audit and no global bypass. Always-prohibited address classes
  remain invalid.
- Preserve the effective behavior of SQLite, judge-body storage, JSONL, console,
  OTel, audit sinks, connector overrides, Galileo, resource attributes, sampling,
  metric policy, and span filters as defined by the mapping table.
- Preserve judge-body retention enablement separately from the relocated database
  path, including the current off-like `DEFENSECLAW_PERSIST_JUDGE` override and the
  default-true case, then retire runtime consultation of that variable.
- Preserve explicit Galileo batch delays; disclose and materialize the deliberate
  v8 1,000 ms preset only where v7 inherited its 5,000 ms default.
- Preserve legacy redacted/unredacted intent for both local and optional
  destinations. Because fresh v8 defaults are unredacted and all-signals, migration
  materializes any narrower v7 collection, routing, or redaction needed to avoid
  broadening an upgraded installation. Effective v7 redaction uses immutable
  built-in `legacy-v7`; a v7 global bypass uses `none`.
- Derive current v7 log/trace/metric/action/exporter eligibility from the generated
  telemetry-registry compatibility selection. A missing/ambiguous family mapping
  fails before write; the converter has no hand-maintained family list or wildcard
  broadening fallback.
- Preserve the merged PR #403 root/subagent lifecycle, execution, phase, operation,
  hook-decision, real-time completion, and missing-data behavior and the merged PR
  #412 dashboard metric/label/bucket/cadence corrections through the
  `local-observability-v1` compatibility profile.
- Migrate the named local-observability destination with logs/traces/metrics and
  every required family unless explicit v7 narrowing must be preserved; report the
  resulting partial dashboard capability when policy remains narrower.
- Back up and refresh target-owned local Collector/datasource/dashboard/rule/config
  assets, preserve arbitrary custom files and all Prometheus/Loki/Tempo/Grafana
  volumes, validate the complete target asset manifest before restart, restore the
  backed-up managed file set on partial refresh, and retain the only copy of any
  overwritten local modification in the upgrade backup.
- Emit `config_version: 8`; omitted bucket catalog resolves deterministically to 1.
- Never resolve a secret into YAML, an in-memory display/diff candidate, or
  diagnostic output. A complete value needed for ancillary promotion is confined
  to the locked `.env` write object, excluded from representations, and
  discarded after activation/rollback.
- Validate the entire candidate before changing the source file.
- Use lock, temporary file, fsync, and rename for activation.
- Be idempotent so an interrupted or retried upgrade does not duplicate routes,
  destinations, comments, or schema migrations.

The full field mapping remains in `06-migration-and-implementation.md`; it is not
duplicated here.

## 5. Required-Failure Behavior

The current migration framework may continue after an individual migration
function raises, then use the release manifest and migration cursor to decide
whether a missing migration is fatal. The v8 release MUST list this migration as
required and use failure policy `fail`.

For this required migration, the upgrader MUST NOT follow the frozen controller's
unconditional restart path or start a v8 gateway against v7 config. Instead:

- Candidate construction or validation failure leaves the original source bytes
  untouched.
- A partial multi-file activation restores the config and every ancillary changed
  file from the backup.
- The command exits nonzero, prints the original phase error and rollback outcome,
  and does not report upgrade success.
- The verified bridge wheel and gateway are retained before the hard cut. A
  second-phase failure restores the exact `0.8.4` config, `.env`, cursor, managed
  local bundle, CLI, and gateway; the restored gateway is health-checked in a
  fresh process before rollback is reported successful.
- Each phase publishes a bounded, owner-only, secret-free recovery journal and
  fsyncs its exact custody before the first stop or installed-state mutation.
  Every resolver/controller entry checks that journal before installed-version
  detection or config loading. A SIGKILL, terminated parent, or reboot therefore
  resumes idempotent rollback rather than interpreting a mixed installation as a
  new same-version upgrade.
- A fixed private mutator lease is inherited by wheel, migration, bundle, and
  service children. Recovery cannot begin while a child from a killed controller
  is still able to mutate the installation.
- A rollback failure is a distinct fail-closed terminal state. It never overwrites
  the original failure code or becomes an upgrade-success receipt.
- After journaled recovery closes, retrying `defenseclaw upgrade` reruns the
  unapplied migration through the existing cursor semantics.

Package managers and manual artifact paths that cannot execute this transaction
MUST enforce the signed minimum-source preflight and refuse a bridge skip before
replacing artifacts. Installing a hard-cut package and relying on strict gateway
startup after replacement is not an acceptable substitute for preflight.

An unavailable optional remote exporter is not a migration failure. If the v8
gateway starts, SQLite is writable, and the observability graph compiles, ordinary
destination health reports the exporter as degraded.

Likewise, failure to start or query an installed optional local-observability stack
is reported as degraded upgrade status after its files are safely backed up. It
does not roll back a healthy gateway/SQLite migration. The report identifies the
failing service and points to ordinary `setup local-observability up/status` recovery;
it does not require another schema/config migration or a volume reset.
The target keeps the immediately previous bundled query contract through generated
aliases for at least one compatibility release, so a temporarily stale PR #403/#412
bundle remains useful while target-only panels are reported as unavailable.

## 6. Optional Preview

For support and managed deployments, the same converter MAY be exposed read-only:

```text
defenseclaw setup observability migrate-v8 --dry-run
```

It prints a secret-free diff and warnings but does not modify live configuration.
It is optional, is not mentioned as a prerequisite in the normal upgrade flow, and
does not have a second apply/commit protocol. `defenseclaw upgrade` remains the
normal writer.

If configuration permissions prevent backup or atomic replacement, the upgrade
fails before mutation with the path and required permission fix. It does not change
ownership or invent a separate managed-config transaction.

## 7. Verification

Acceptance requires tests proving:

- A release-stamped `0.8.4` bridge manifest requires protocol 1 while advertising
  a controller that supports protocol 2; it contains no v8 conversion row.
- A release-stamped `0.8.5` hard-cut manifest requires protocol 2, minimum source
  and bridge `0.8.4`, and the required `0.8.5` conversion row.
- An explicit `0.8.3`-or-older to `0.8.5` attempt is rejected before backup,
  service stop, gateway install, or wheel install and says no changes were made.
- A normal latest-version request from every source in
  `release/upgrade-baselines.json` performs the verified bridge, terminates the
  old execution path, and continues under a fresh `0.8.4` controller. A source
  outside the matrix fails closed with the exact supported path.
- A mismatched package stamp, forward/unreachable or missing required migration,
  malformed registry/call shape, unsupported/future source schema, and ambiguous
  config fail at the same pre-mutation boundary.
- The installed-target runner invokes an old signature without the local-bundle
  keyword and a new signature with it, never retries a `TypeError`, and imports in
  isolated mode.
- One release-owned updater command stages representative supported v7 fixtures
  through `0.8.4`, converts them under `0.8.5`, and starts a healthy v8 gateway.
- Interactive confirmation and ordinary `--yes` both work without another flag or
  acknowledgement.
- The migration registry and release manifest run the conversion exactly once.
- Already-v8 and retry cases are no-ops without duplicate destinations or routes.
- Every mapping in `06-migration-and-implementation.md` has a golden fixture.
- Inline/interpolated credentials become stable references, ancillary `.env`
  values never appear in YAML/output, retry is idempotent, and an injected second-
  file failure restores both exact originals.
- Per-signal protocol differences split deterministically; conflicting metric
  policies fail with the documented remediation and no write.
- Generated registry compatibility selection, not a converter-local family list,
  determines current v7 eligibility; missing mappings fail closed.
- Every explicit private literal gets only its own reviewed opt-in, and all legacy
  non-secret OTel environment inputs are materialized before those inputs retire.
- Splunk sourcetype overrides, OTLP logger scope, and `legacy-v7` projections match
  pre-upgrade adapter/redaction goldens.
- Comments, ASCII guidance, order, unrelated sections, and permissions survive.
- Invalid candidates never replace the original source.
- A required migration, target start, or health failure never starts v8 against
  v7 config and never reports success.
- Fault injection after every stop/install/migrate/activate/restart/health stage
  restores byte-exact `0.8.4` state, reinstalls the retained verified bridge
  artifacts, and proves restored health from a fresh process.
- Output contains no governed content or resolved secrets.
- The optional preview and automatic migration produce the same semantic candidate.
- Temporarily unavailable optional exporters do not fail an otherwise healthy
  upgrade.
- Installed local-observability assets are backed up and refreshed to one mutually
  compatible version; custom files and persistent volumes survive, a previously
  running stack restarts, and all services plus static/live dashboard inventory are
  verified.
- Pre-upgrade and post-upgrade root/subagent activity remains queryable in the same
  Agent360 dashboard with stable lifecycle/root identity and distinct execution
  attempts.
- Injected local-stack restart/refresh failure leaves the previous dashboard query
  contract functional through declared aliases and reports the stale bundle/target-
  only capability gap without hiding it as success.

The supported historical-version matrix belongs in the existing upgrade smoke
tests. No second upgrade harness is introduced for observability v8.
