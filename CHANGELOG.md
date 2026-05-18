# DefenseClaw Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com) and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — Hook collector unification

This rollup unifies the agent hook collector across all 7
connectors (codex, claudecode, hermes, cursor, windsurf, geminicli,
copilot) onto a single declarative `HookProfile`-driven pipeline.
There are **no new environment variables** — the unification is the
default and only path; the V1 OTLP builders and the per-phase
feature flags that existed in early review iterations have been
deleted.

### Behaviour changes (no flag)

- **W3C trace propagation is always on** for hook routes
  (`/api/v1/<connector>/hook`, `/api/v1/codex/notify`). The gateway
  consumes `traceparent` / `tracestate` so hook spans root on the
  agent's parent trace; `_hardening.sh` v6 emits the headers from
  every hook script. Extraction is route-scoped via
  `shouldExtractHookTrace`; all other routes (health, REST, OTLP
  ingest) continue to mint a fresh root span regardless of what
  the caller sent.
- **Native OTLP for codex / claudecode / geminicli is spec-driven**
  through the shared `connector.NativeOTLPSpec` renderer
  (`TOMLBlock` / `EnvBlock` / `JSONBlock`). The V1 builders are
  gone; shape tests in
  `internal/gateway/connector/native_otlp_golden_test.go` lock the
  wire format codex/claudecode/gemini consume.
- **Audit `details` column always carries both forms**: the
  structured `HookAuditEnvelope` JSON (under the `details_json=`
  key) and the legacy `connector=… action=… raw_action=…` tail.
  Existing operator log greps keep matching; jq pipelines can
  parse the JSON inline. No env-var toggle.
- **Codex `/api/v1/codex/notify` synthesizes a Stop event** through
  `handleAgentHookSynthetic`. The canonical
  `codex.notify.<sanitized-type>` audit row is preserved one-per-
  inbound; the synthetic envelope is persisted under
  `audit.ActionConnectorHookSynthetic` so SIEM rules pinned on
  `codex.notify%` keep their row counts and new dashboards can
  reason about the synthesized Stop separately.
- **codex / claudecode dispatch through `handleUnifiedConnectorHook`**
  (which delegates evaluation to the existing bespoke handlers for
  PluginInput-v1 / notify-bridge response shaping). The wrapper is
  the single gate that guarantees the audit / metrics / dedup /
  trace-propagation code paths ran.

### Observability parity

- `defenseclaw_connector_hook_outcome_total` and
  `defenseclaw_connector_hook_tokens_total` counters added to
  `internal/telemetry/metrics.go`; emitted by every hook handler
  including the synthetic path. Dashboards can compute block rate
  and cost per connector via PromQL without joining the native
  OTLP channel.
- `defenseclaw_connector_hook_unified_dispatch_total` added so
  operators can confirm traffic is flowing through the unified
  pipeline (vs. an out-of-tree handler registration that bypasses
  audit/metrics).
- New audit action `connector-hook-synthetic` (Go +
  `cli/defenseclaw/audit_actions.py` + `OBSERVABILITY-CONTRACT.md`)
  for the synthetic Stop visibility row.

### Connector profile surface

- New `connector.HookProfile.Decode`, `MapVerdict`, and `Respond`
  function fields let codex / claudecode declare their per-event
  wire shape declaratively.
- `connector.AcceptLoopbackWithWarning` centralizes the loopback
  authentication carve-out (currently used by
  `CodexConnector.Authenticate`). The helper now panics on
  `warned == nil` so a future caller cannot silently disable the
  `[SECURITY] loopback bypass` log via a typo; operators continue
  to see one warning per process when a gateway token is configured
  but loopback is exercised. See the expanded paragraph in
  `.deepsec/data/defenseclaw/INFO.md`.

### Security fixes folded in

- **Trace propagation route scope (H1).**
  `extractIncomingTraceContext` is now path-aware
  (`shouldExtractHookTrace`) so only hook + notify routes consume
  inbound `traceparent`. Closes the regression where any caller
  hitting `/health` could splice a trace ID into the gateway's
  trace tree.
- **Synthetic audit visibility (M1).** The synthetic codex notify
  path now persists a `HookAuditEnvelope` under
  `ActionConnectorHookSynthetic` instead of suppressing the row;
  SIEM dashboards no longer regress when codex notify fires.
- **Loopback bypass footgun (M2).** `AcceptLoopbackWithWarning`
  panics on `nil` `warned` argument so a misuse cannot silently
  re-enable silent trust of loopback callers.

### Follow-ups from live E2E testing (F1, F2)

- **Codex `[otel]` block no longer carries `service_name` /
  `resource_attributes` (F1).** Earlier review iterations of this PR
  set both fields on `CodexConnector.HookProfile().NativeOTLPSpec` —
  but codex's documented `[otel]` schema (see codex
  config-reference) doesn't define those keys, and the published
  schema is strict
  ([openai/codex#17012](https://github.com/openai/codex/issues/17012)).
  Writing them risks codex rejecting the operator's config at
  startup.

  Codex also already emits richer intrinsic identity tags
  (`originator`, `model`, `auth_mode`, `app.version`,
  `session_source`) and uses different `service.name` values for
  its sub-processes (`codex-app-server`, `codex_exec`); forcing
  `service.name=codex` from outside would have *collapsed* the
  natural distinction. M3 (consistent resource attributes across
  connectors) therefore applies only to env-block-style connectors
  (claudecode); TOML/path-token connectors that self-identify
  (codex, geminicli) keep their upstream tags.

  `TestNativeOTLPShape_Codex` now asserts the *absence* of
  `service_name` / `resource_attributes` so a future contributor
  can't silently re-introduce the regression.
- **Hook audit rows now carry `session_id` and `agent_id` (F2).**
  `CorrelationMiddleware` snapshots the audit envelope from the
  inbound HTTP headers — but no DefenseClaw-managed hook shell
  script sets `X-DefenseClaw-Session-Id`, the session id always
  arrives in the JSON payload. Result before F2: every audit row
  written by `logConnectorHookAuditEnvelope` (`connector-hook` AND
  `connector-hook-synthetic`) landed with `session_id=NULL` and
  `agent_id=NULL`, defeating SIEM correlation between hook
  decisions and the matching LLM events.

  `enrichAgentHookContext` now refreshes the audit envelope with
  `req.SessionID` and the resolved agent identity, so both regular
  and synthetic hook rows correlate. Header-supplied identity is
  preserved when the payload doesn't override (see
  `TestRefreshAuditEnvelopeFromHook_*`).

  Operators upgrading from a prior build will see
  `session_id`/`agent_id` populate immediately on the next hook
  event; pre-existing audit rows are not back-filled.

## [Previous-Unreleased] — Codex / Claude Code hook-only enforcement (no proxy data path)

This rollup removes the LLM-proxy data path for the Codex and Claude
Code connectors and unifies them on the agent's native hook bus for
both observation and enforcement. The `PreToolUse` hook returns a
`permissionDecision: "deny"` verdict on policy hits and the agent
blocks the tool call inside its own permission flow. Codex and
Claude Code now talk directly to their native upstreams in both
`observe` and `action` mode.

### Breaking changes

- **`guardrail.codex_enforcement_enabled` removed** from
  `~/.defenseclaw/config.yaml`. The field was the on/off switch for
  the now-deleted proxy-driven enforcement path. Enforcement is now
  selected by the existing `guardrail.mode` field (`action` returns
  a PreToolUse deny verdict on policy hits; `observe` records only).
  The upgrade migration strips the field automatically — see
  "Migrations" below.
- **`guardrail.claudecode_enforcement_enabled` removed** from
  `~/.defenseclaw/config.yaml`. Same shape and rationale as the
  Codex flag above. The upgrade migration strips the field
  automatically.
- **`SetupOpts.CodexEnforcement` and `SetupOpts.ClaudeCodeEnforcement`
  removed** from the Go connector `Setup()` contract. Out-of-tree
  connector implementations that read these fields must drop the
  references; they were always observable booleans without their own
  feature surface, and `Mode` is the canonical knob now.
- **Codex / Claude Code proxy listener no longer binds** at gateway
  start when the active connector is `codex` or `claudecode`, even
  if `guardrail.mode=action`. Port 4000 stays closed — the
  enforcement path is the hook bus, not the proxy. Operators who
  relied on the proxy URL (`http://localhost:4000/...`) appearing in
  the agent config need to remove those overrides; the connectors
  patch the agent's native upstream back to its vendor default at
  upgrade time.

### Enforcement

- **`defenseclaw setup codex --mode action`** and
  **`defenseclaw setup claude-code --mode action`** newly provision
  hook-driven enforcement: the PreToolUse hook returns a deny
  verdict on policy hits and the agent blocks the tool call inside
  its own permission flow. `--mode observe` (the default) keeps the
  previous record-only behavior.
- The shared connector-alias factory used by the other hook-
  enforced connectors (`hermes`, `cursor`, `windsurf`, `geminicli`,
  `copilot`) gains the same `--mode {observe,action}` knob.
- The interactive wizard (`defenseclaw setup guardrail`) drops the
  Codex/Claude Code "observability-only vs. proxy" fork; the
  standard observe/action mode prompt now drives both connectors.
- The TUI overview's Enforcement row reflects the effective mode
  per connector: `<Agent> hook enforcement (action)` when
  `guardrail.mode=action`, otherwise `<Agent> hook observability
  (observe)`. `defenseclaw doctor` likewise reports `hook-enforced
  for codex (mode=action via PreToolUse deny) — proxy port
  intentionally closed` in its `Guardrail proxy` check.

### CLI plumbing

- The `_OBSERVABILITY_ONLY_CONNECTORS` set in `cli/defenseclaw/
  commands/cmd_setup.py` was split into `_PROXY_BACKED_CONNECTORS`
  (`openclaw`, `zeptoclaw`) and `_HOOK_ENFORCED_CONNECTORS`
  (everything else). The old name remains as a backstop alias so
  out-of-tree imports keep resolving. New call sites must use the
  named sets.
- `_apply_connector_observability_only` was renamed to
  `_apply_hook_connector_setup` and now takes a `mode` argument
  (defaulting to `observe`). The legacy name remains as a thin
  shim that forces `observe` for any out-of-tree callers.
- Inert helpers `_set_connector_enforcement`,
  `_connector_enforcement_flag`, and `_connector_enforcement_enabled`
  were deleted along with their last call sites.

### Migrations

- New 0.5.0 sub-step
  **`_migrate_0_5_0_strip_codex_enforcement_keys`** rewrites
  `~/.defenseclaw/config.yaml` to remove
  `guardrail.codex_enforcement_enabled` and
  `guardrail.claudecode_enforcement_enabled` if present. The strip
  is byte-level (no YAML round-trip) so operator comments, blank
  lines, and surrounding key order under `guardrail:` are preserved
  exactly. `guardrail.mode` is left untouched — the operator's
  existing enforcement posture carries through to the hook surface.
- Migration is idempotent and runs automatically on
  `defenseclaw upgrade`. Failures are logged via `defenseclaw
  doctor --fix` and never block the upgrade.
- **`defenseclaw setup codex` now heals pre-PR-#265 installs in place.**
  The legacy setup rewrote `~/.codex/config.toml`'s top-level
  `openai_base_url` to `http://127.0.0.1:<port>/c/codex`. PR #265
  deleted the matching proxy mount but left the operator's
  `config.toml` carrying a now-broken value, so every Codex turn
  failed with `stream disconnected before completion` against the
  closed loopback port. `patchCodexConfig` now strips any
  `openai_base_url` whose URL shape matches the loopback `/c/codex`
  pattern DefenseClaw itself wrote (scheme `http(s)`, host
  `127.0.0.1` / `localhost` / `::1`, path beginning `/c/codex`). An
  operator's enterprise gateway URL is preserved unchanged —
  `TestCodex_Setup_DefaultObservability_NoProxyRewrite` continues
  to gate that contract, and `TestIsDefenseClawCodexProxyRedirect`
  pins the strip detector's full accept/reject surface.
- **Known follow-up:** `Teardown` does not yet apply the same heal,
  so `defenseclaw teardown codex` against a pre-PR-#265 install can
  restore the stale `openai_base_url` from the managed-file backup
  snapshot captured at the original Setup. Operators uninstalling
  DefenseClaw should re-run `setup codex` once before `teardown`,
  or hand-strip the line. Tracked as the immediate next PR.

### Tests

- Go test suite updated:
  - `TestSetupOpts_HookFailMode_RespectsOperatorChoice` no longer
    references `CodexEnforcement` / `ClaudeCodeEnforcement`.
  - `TestProxyShouldBindForConnector` /
    `TestAPIStatusEmitsConnectorMode` /
    `TestShouldRunProviderProbeForConnector` assert the proxy stays
    unbound for codex/claudecode regardless of `Guardrail.Mode`.
  - `TestConnector_AllowedHostsProvider_ProxyBuiltinsImplement`
    (renamed from `_AllBuiltinsImplement`) only covers
    proxy-backed connectors.
  - `TestCodex_Teardown_RemovesLegacyEnvFiles` and the analogous
    Claude Code env-file tests were removed alongside the helpers
    they covered.
  - `TestModePickerModal_PreviewMatchesSetupAliases` updated for
    the new "proxy-backed connector setup" / "hook-driven
    connector setup" preview strings.
- Python CLI test suite updated:
  - `test_cmd_init.py` and `test_cmd_doctor.py` no longer assert
    on `codex_enforcement_enabled`.
  - `test_cmd_setup_mode.py`,
    `test_cmd_setup_observability.py`,
    `test_cmd_setup_codex_claudecode_alias.py`, and
    `test_guardrail.py` were rewritten to cover the hook-driven
    mode contract end-to-end.

## [Pre-PR-265] — PR #194 single-rollup (security floor + connector polymorphism + test parity)

This rollup closes the audit gaps identified in the v3 connector
review and lands PR #141's matrix in a single coherent set of
changes. Ordering: Phase A (P1 mechanical) → Phase B (S0 security
floor) → Phase C (S1/S2/S7 + matrix-TODO cleanup) → Phase E (test
parity for ZeptoClaw + Claude Code + Codex) → Phase D (test sweep +
docs).

### Security

- **S0.8** Inspect hook scan timeout tightened from 5s to 200ms; per-IP
  rate limiter (20 rps, 40 burst) applied to `/api/v1/inspect/*` so a
  malicious or runaway hook caller cannot DoS the gateway. Loopback
  callers stay exempt so dev iteration is unaffected.
- **S0.13** CSRF middleware no longer exempts `OPTIONS` from
  `Sec-Fetch-Site` checks. Cross-origin preflights are now rejected by
  default.
- **S0.12** `Connector.ProviderProbe` interface added; the gateway
  refuses to start with zero usable upstreams unless
  `cfg.Guardrail.AllowEmptyProviders` is set explicitly. ZeptoClaw,
  Codex, ClaudeCode, OpenClaw all implement the probe.
- **S0.3** ZeptoClaw `Authenticate` no longer trusts loopback
  unconditionally. Local processes must present a valid `X-DC-Auth`
  bearer once a gateway token has been provisioned. `Route` now gates
  `RawAPIKey` capture behind `isChatPath`; non-chat traffic gets
  passthrough mode and an empty key.
- **S0.2** First-boot `DEFENSECLAW_GATEWAY_TOKEN` synthesis. The
  gateway and sidecar generate a 32-byte CSPRNG hex token at startup
  (atomic `0o600` write to `~/.defenseclaw/.env`) and persist it across
  reboots. The empty-token loopback allow path was removed; an empty
  token now fails closed. `TestTokenAuth_DisabledWhenEmpty` was
  inverted and renamed `TestTokenAuth_FailsClosedWhenEmpty`.
- **S0.5** `defenseclaw setup rotate-token` CLI subcommand. Generates a
  new gateway token, rewrites `~/.defenseclaw/.env`, refreshes hook
  `.token` files, and prompts the operator to restart the agent.
- **S0.4** Hook scripts (`hooks/*.sh`) source a new
  `hooks/_hardening.sh` that pins `GIT_CONFIG_NOSYSTEM=1`, an
  ephemeral `HOME`, `ulimit -t 5 -v 524288 -n 32`, and an allow-list
  regex for payload-derived paths.
- **S0.10** Telemetry payloads carry an HMAC-SHA-256 derived from the
  device key via HKDF (`info="defenseclaw-telemetry-v1"`). The
  `redaction.AssertNoCredentials` guard panics in dev / no-ops in
  prod when a known key prefix appears in egress payloads — defense
  in depth against a future refactor accidentally adding an
  `APIKey` field.
- **S0.1 (descoped)** ed25519 plugin manifest signing is deferred. The
  existing sha256-pin + symlink containment + perm check remain the
  baseline, augmented by an owner-UID check and an audit-pipeline
  `EventPluginLoadRejected` event. ed25519 signing tracked as a
  follow-up.

#### PR #141 audit follow-ups (additive security hardening)

These items land the seven security-floor fixes introduced in
PR #141 commit `45cf241d3cea4d90606de835a6746ae6a2b3270e` against this
branch's baseline. Each is additive — there is no removed protection.

- **C1** PATCH `/v1/guardrail/config` re-validates the gateway token
  inside the handler in addition to the existing `tokenAuth`
  middleware. A future refactor that exposes the handler outside the
  middleware chain will not silently re-open the bypass — mode
  changes (`action` ↔ `observe`) require an authenticated caller
  unconditionally. Returns `403` with a clear operator-facing message
  when the token is missing or wrong.
- **H1** Codex `Authenticate()` emits a one-time `[SECURITY]` line on
  stderr the first time loopback is trusted while
  `DEFENSECLAW_GATEWAY_TOKEN` is configured. Codex remains permissive
  on loopback because the codex-cli native Rust binary has no
  fetch-interceptor seam to inject `X-DC-Auth` (see the existing
  `TestCodex_Authenticate_NativeBinaryLoopback`). The warn surfaces
  the architectural gap without breaking codex routing. ZeptoClaw was
  already strict-reject post-B1 on this branch and needs no change.
- **H2** `Registry.RegisterPlugin` now returns an error when a plugin
  declares a name that collides with a built-in connector
  (openclaw / zeptoclaw / claudecode / codex). `DiscoverPlugins`
  surfaces the rejection on stderr and continues processing the
  remaining plugins instead of failing the boot. A malicious `.so`
  dropped into the plugin directory can no longer shadow-override
  the auth seam routed via `Get(name)`.
- **H4** OPA evaluator hardening:
  `rego.UnsafeBuiltins(http.send, opa.runtime, net.lookup_ip_addr)` +
  `rego.StrictBuiltinErrors(true)`. User-supplied Rego in policy
  bundles can no longer reach an outbound network primitive or leak
  build / host info, and silent builtin failures become hard
  evaluation errors so a banned builtin cannot noop into a `pass`
  verdict.
- **H9** `deriveMasterKey()` now uses PBKDF2-SHA256 with 100k
  iterations and a 32-byte (64-hex-char) output, replacing the
  previous single-round HMAC-SHA256 truncated to 32 hex chars.
  **BREAKING for any persisted `sk-dc-` value derived under the old
  algorithm:** those will no longer match the master key the proxy
  recomputes at boot. `sk-dc-` is an internal fallback credential and
  not the supported caller-side bearer; operators relying on it must
  re-read it from `gateway.log` after upgrade. Adds direct
  `golang.org/x/crypto` dep (was indirect).
- **M1** `isPrivateHost()` resolves hostnames through `net.LookupHost`
  and inspects every returned address before deciding whether to
  flag the host. The previous "skip hostnames" branch was a DNS-
  rebinding hole — an attacker-controlled DNS record could resolve
  to `127.0.0.1` / `169.254.169.254` and bypass the IP-literal guard.
  Lookup failures continue to fail-open (return `false`) to prevent
  legitimate-LLM-endpoint over-block; callers needing a hard
  guarantee must layer a network-level egress allowlist on top.
- **M5/M6** `redaction.ForSinkReason` is now applied to the
  `Details` field of `guardrail-inspection` rows the proxy writes
  directly to the audit store. The TUI still renders the unredacted
  reason via the logger path (operator local intent), but third-party
  sinks (Splunk forwarder, Loki, Cisco AID telemetry) inheriting from
  `audit.Store` no longer leak the matched literal. In `api.go` the
  `redactedReason` declaration moves above the `details` composer so
  the persisted row, the `gateway.log` line, and the sink-forwarded
  copy all carry the same redacted form.

### Connectors

- **C1 (S2.4)** Hard-coded per-connector `case` switches replaced by a
  generic `registerHookHandler` registration table. The gateway now
  iterates `HookEndpoint`-implementing connectors via
  `registerConnectorHookRoutes` instead of name-keyed dispatch in
  `api.go`. Adding a new connector is a single `registerHookHandler`
  call plus a `HookEndpoint` implementation. The follow-up move of
  the handler bodies (`claude_code_hook.go`, `codex_hook.go`) into the
  `connector/` package is deliberately split into a second commit per
  the plan's own commit-splitting guidance — the registration seam in
  `hook_register.go` already lets the relocation happen without
  touching call sites.
- **C2 (S2.5)** `HookScriptOwner` interface drives hook-script
  generation. `WriteHookScriptsForConnectorObject` is the new
  interface-driven entry point; the legacy package-level
  `connectorHookScripts` map remains as a backward-compatible shim and
  delegates through the connector registry.
- **C3** ZeptoClaw `before_tool` and Codex hook invocation are
  documented as **WONTFIX (architectural)** in
  `docs/CONNECTOR-MATRIX.md`. Both are limitations of the host agents
  (no settings-based external-script hook support); the proxy-side
  Route() path provides the actual security guarantee.
- **C4 (S1.3)** New `sidecar_watcher_matrix_test.go` exercises
  `resolveWatcherDirs` for all four connectors. The watcher correctly
  picks `~/.<connector>/skills` and `~/.<connector>/plugins` based on
  the active connector configuration.
- **C5 (S7.6)** New Python `cli/tests/test_install_smoke.py` runs
  `setup → disable → uninstall` round-trip across all four connectors
  with isolated `$HOME` contexts.
- **C6** `defenseclaw plugin list` now enumerates host-owned plugins
  for non-OpenClaw connectors. Each connector's plugin directories are
  scanned for manifest files (`plugin.json` / `package.json` /
  `plugin.yaml`); merged output labels each entry with `source:
  "defenseclaw"` or `source: "host"`.
- **C7** AIBOM (`defenseclaw aibom`) gains per-connector adapters for
  agents, tools, model providers, and memory. Filesystem-based
  enumeration only — no live tool-registry queries (deferred to a
  follow-up). Provider entries never leak raw API keys (only env-var
  names + base URLs).
- **A5** Removed dead `AgentRestarter` and `HookEventHandler`
  interfaces. Both had zero implementations across the four built-in
  connectors. Reintroduce as `S2.6`/`S2.7` if a real call site
  surfaces.

### Test Parity (Phase E)

OpenClaw's test footprint — 14+30 Go tests, 31+ Python files, a full
`scripts/test-e2e-full-stack.sh` Phase 7 — was significantly ahead of
ZeptoClaw, ClaudeCode, and Codex. This rollup brings the other three
to parity at the integration / acceptance / e2e tiers without adding
any production-code coupling between the four.

- **E1** Go integration parity: per-connector subtests added across
  `sidecar_test.go`, `proxy_test.go`, `gateway_test.go`,
  `connector_cmd_test.go`, `device_test.go`, `watcher/rescan_test.go`.
  Notable additions: `TestProxy_PerConnectorPrefixStrip`,
  `TestSwitchConnector_PerConnectorPersistsState`,
  `TestApplyRuntime_PerConnectorSwitch`,
  `TestHandleGuardrailEvent_OTelAgentName_PerConnector`,
  `TestConnectorVerify_CleanPerConnector`.
- **E2** Python CLI parity: new `test_zeptoclaw_config.py`,
  `test_claudecode_config.py`, `test_codex_config.py` exercise
  per-connector config shape, MCP enumeration, skill/plugin path
  resolution, and patch/restore round-trips. New
  `test_cmd_guardrail_matrix.py` parametrizes
  `guardrail status/enable/disable` over all four connectors with
  mocked `_restart_services`.
- **E3** Acceptance / `test/e2e/` parity: new
  `connector_lifecycle_matrix_test.go`,
  `v7_observability_connector_matrix_test.go`. Existing
  `TestConnectorVerifyCleanOnFreshDataDir` now covers all four
  connectors via `*PathOverride` seams. New
  `test/e2e/connectormatrix.go` provides the canonical
  `connectorMatrix(t)` fixture helper.
- **E3.4** S3.4 carry-overs: per-connector golden directories under
  `test/e2e/testdata/v7/golden/{openclaw,zeptoclaw,claudecode,codex}/`,
  new `goldenPathForConnector` helper, layout-locking
  `TestGoldenPerConnectorLayout` test. `assertThreeTierIdentity`
  doc comment block now enumerates all four connectors.
- **E4** Live shell e2e + GH Actions matrix:
  `scripts/test-e2e-full-stack.sh` gains `phase_connector_artifact_matrix`
  (Phase 2C) that asserts per-connector hook-script presence on disk.
  `.github/workflows/e2e.yml` gains a `connector-matrix` job with a
  `[openclaw, zeptoclaw, claudecode, codex]` matrix axis (fail-fast:
  false) that runs the four connector lifecycle / verify / OTel parity
  test packages on `ubuntu-latest`. The `e2e-required` gate enforces
  all four cells.
- **E5** Shared fixtures: new Go `internal/gateway/connector/connectortest/`
  test-only subpackage with `WithTempHome`, `SeedZeptoClawConfig`,
  `SeedClaudeCodeSettings`, `SeedCodexConfig`, `SeedSkillDir`,
  `SeedPluginDir`. New Python `cli/tests/connector_fixtures.py`
  with `make_zeptoclaw_config`, `make_claudecode_settings`,
  `make_codex_config`, `with_connector` context manager. Shared
  fixture data under `test/fixtures/connectors/<name>/`.

### Documentation

- New `docs/CONNECTOR-MATRIX.md` — canonical statement of by-design
  connector limitations (ZeptoClaw `before_tool`, Codex hook
  invocation), what the matrix supports today, and the proxy-side
  enforcement model.
- New `test/e2e/testdata/v7/golden/README.md` — explains the
  per-connector golden subdirectory layout and how it interacts with
  the connector-agnostic baseline.
- `docs/CONNECTOR-REMAINING-FIXES.md` — items resolved by this rollup
  (file locking, atomic writes, dead interface removal,
  HandleHookEvent stub) marked DONE; the remaining items continue to
  track what's deferred.

### Verification (Phase D)

The rollup is gated by a four-step verification suite:

1. `go test ./... -race -count=1` — must pass (locked-in test updates
   from Phase B already reflected in the codebase).
2. `cd cli && python -m pytest -x -q` — must pass (1419 + new tests).
3. `cd extensions/defenseclaw && npm test` — must pass (TypeScript
   plugin telemetry + correlation context).
4. **D4** S8.1/S8.2/S8.3 verification:
   - **S8.1** Codex env scoping: `~/.codex/config.toml`
     `[providers.openai].base_url` is patched; no global
     `OPENAI_BASE_URL` is exported to user shell rc.
   - **S8.2** Setup writes only the picked agent: a
     `setup guardrail --agent codex` run leaves `~/.claude/settings.json`
     byte-identical.
   - **S8.3** Observe mode: a known-block prompt under
     `cfg.Guardrail.Mode = "observe"` exits the hook with `0` and
     records a `would_have_blocked` audit entry.

   If any of the three regress, Phase F supplies a pre-staged fallback
   for re-implementation.

### Explicitly out of scope

- **ed25519 plugin manifest signing** (S0.1) — deferred.
- **ZeptoClaw `before_tool` hook wiring** — architecturally not
  feasible (host-side limitation); documented as WONTFIX in C3.
- **Codex external-script hook invocation** — host-side limitation;
  the `[hooks]` block we write is forward-compat, never invoked
  by today's `codex` binary.
- **Hook-handler body relocation into `internal/gateway/connector/`**
  (C1 second commit) — the registration seam landed; the 1.4 KLoC
  body move is staged for the follow-up to keep this rollup
  reviewable. No production-code coupling depends on the move.
- **Live tool-registry enumeration in AIBOM** — querying a running
  gateway / MCP servers for their dynamic tool listings requires a
  connected gateway, deferred.
- **Migration of `Config.ClaudeCode` / `Config.Codex` typed fields to
  a polymorphic `connectors.<name>.<settings>` keyspace** — separate
  refactor PR after this rollup lands.
- **`UninstallPlan.revert_<connector>` per-flag expansion** (E2/item 4
  literal wording) — superseded by the connector-aware
  `_connector_teardown(plan)` path that already dispatches via
  `--connector $name`. Per-connector teardown coverage lives in
  `cli/tests/test_install_smoke.py::test_smoke_matrix`.
