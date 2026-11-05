# Requirements: Integration Resilience Layer

**Status:** Draft

## Context

DefenseClaw supports 14 agent connectors (2 proxy, 12 hook-only) through
the `Connector` interface in `internal/gateway/connector/connector.go`.
The interface design is sound: `ConnectorSignals` decouples agent-specific
extraction from agent-agnostic inspection, and 18 optional interfaces let
connectors declare capabilities without polluting the core contract.

Three systemic risks cut across all connectors:

1. **Silent interception failure.** Proxy connectors (OpenClaw, ZeptoClaw)
   patch transport layers or rewrite config files, but nothing verifies
   these patches remain intact at runtime. Hook connectors register shell
   scripts or plugin artifacts, but nothing proves the agent actually
   invokes them. A new upstream release that changes its networking or
   config format causes DefenseClaw to pass traffic unguarded with no
   alert.

2. **No centralized credential injection.** Each agent manages its own
   LLM provider API keys. DefenseClaw cannot inject, rotate, or revoke
   keys. The `TokenResolverFunc` and `DisableLocalKeyResolution` APIs
   exist in `internal/gateway/token_resolver.go` but have no shipped
   implementation. ZeptoClaw's provider snapshot goes stale when users
   rotate keys outside DefenseClaw.

3. **Unverified version compatibility.** The hook contract system declares
   version bands per connector, but `validated_versions.json` is empty
   for every connector. No automated test sends real traffic through a
   connector at a specific version. The `doctor` command checks file
   presence but does not probe the observe/act pipeline.

Additionally, the Python CLI (`cli/defenseclaw/connector_paths.py`,
`cli/defenseclaw/inventory/claw_inventory.py`) and macOS app
(`macos/.../SkillScanner.swift`) reimplement connector path resolution,
config parsing, and discovery instead of consuming the Go gateway's
already-exported `ConnectorCapabilities`, `AgentPaths`, and
`ConnectorLocations` structs.

This spec introduces three new optional connector interfaces and
supporting infrastructure to address these risks. The existing
`Connector` interface and all 18 optional interfaces remain unchanged.

### Connector inventory (14 connectors)

| Name | Type | Struct | Version bands | Platform |
|------|------|--------|---------------|----------|
| openclaw | Proxy | Dedicated | Not gated | macOS, Linux |
| zeptoclaw | Proxy | Dedicated | Not gated | macOS, Linux |
| claudecode | Hook | Dedicated | v1 (2.1.154-2.1.219), v2 (>=2.1.219) | All |
| codex | Hook | Dedicated | v1-v4, 5 contracts (>=0.124.0) | All |
| hermes | Hook | Generic | v1 (0.19.0-0.21.0) | All |
| cursor | Hook | Generic | v1 (exact: 2026.07.23-e383d2b) | All |
| devin | Hook | Generic | v1 (exact: 3000.4.25) | All |
| geminicli | Hook | Generic | v1 (>=0.26.0, deprecated) | Deprecated |
| copilot | Hook | Generic | v1 (1.0.18-1.0.76), v2 (>=1.0.76) | All |
| openhands | Hook | Generic | v1 (>=1.12.0) | macOS, Linux |
| antigravity | Hook | Generic | v2 (>=1.1.8) | All |
| opencode | Hook | Generic (plugin) | v1 (1.18.10-1.18.20) | All |
| amp | Hook | Dedicated wrapper (plugin) | v1 (>=0.0.1785334225) | All |
| omnigent | Hook | Dedicated | v1 (0.7.0-0.8.0) | All |

### Scope exclusions

- The `Connector` interface in `connector.go` is not modified.
- Existing optional interfaces are not modified.
- No new mandatory methods are added to any connector.
- Connector hook contracts, correlation provenance, and policy are unchanged.
- The geminicli connector (deprecated) is not required to implement new interfaces.

## EARS Requirements

### R1: Interception Verification

- **REQ-01**: Where a connector implements `InterceptionVerifier`, the
  gateway shall probe each declared transport layer independently and
  report per-layer health.

- **REQ-02**: When an interception probe detects a non-functioning
  transport layer, the system shall emit an audit event with
  `reason="interception-gap"` naming the connector and failed layer.

- **REQ-03**: When all transport layers of a proxy connector report
  failure, the system shall escalate the connector status to `degraded`
  and emit a `severity=critical` telemetry event.

- **REQ-04**: While the gateway is running, the system shall re-verify
  interception on a configurable interval (default 60 seconds) for
  proxy connectors that implement `InterceptionVerifier`.

- **REQ-05**: Where a hook-only connector implements
  `InterceptionVerifier`, the system shall probe hook registration
  integrity (config file contains expected entries, hook script is
  executable and reachable).

- **REQ-06**: The OpenClaw `InterceptionVerifier` implementation shall
  probe all five transport layers: globalThis.fetch, https.request,
  http.request, http.get, and undici global dispatcher.

- **REQ-07**: The ZeptoClaw `InterceptionVerifier` implementation shall
  verify that the active `config.json` has `api_base` values pointing
  at the proxy address for all configured providers.

- **REQ-08**: Hook-only connectors (claudecode, codex, hermes, cursor,
  devin, copilot, openhands, antigravity, opencode, amp, omnigent)
  that implement `InterceptionVerifier` shall verify their hook config
  file contains the expected DefenseClaw hook entries and that hook
  scripts or plugin artifacts exist on disk and are executable or
  readable as appropriate.

### R2: Credential Hydration

- **REQ-09**: Where a connector implements `CredentialHydrator`, the
  gateway shall push LLM provider API keys to the connector through
  the connector's native credential delivery mechanism.

- **REQ-10**: The system shall expose a `PUT /v1/credentials/{provider}`
  API endpoint that accepts a provider name and API key, stores it in
  the in-memory credential store, and triggers delivery to all
  connectors implementing `CredentialHydrator`.

- **REQ-11**: The system shall expose a `GET /v1/credentials/{provider}`
  API endpoint authenticated by `X-DC-Auth` that returns the hydrated
  API key for a given provider, for use by the OpenClaw fetch
  interceptor plugin.

- **REQ-12**: The OpenClaw `CredentialHydrator` shall make hydrated
  keys available via the `GET /v1/credentials/{provider}` endpoint so
  the fetch interceptor can read them at intercept time instead of
  extracting from request headers.

- **REQ-13**: The ZeptoClaw `CredentialHydrator` shall update both the
  in-memory provider snapshot and the on-disk `config.json` `api_key`
  field for the specified provider.

- **REQ-14**: When `DisableLocalKeyResolution()` has been called, the
  system shall reject LLM requests that do not have a hydrated key
  available, returning a 403 with a clear error message.

- **REQ-15**: The `CredentialHydrator` shall support a
  `RefreshSnapshot()` method that reloads credential state from the
  agent's config file, solving ZeptoClaw's stale-snapshot problem on
  user-initiated key rotation.

- **REQ-16**: Hook-only connectors (claudecode, codex, hermes, cursor,
  devin, copilot, openhands, antigravity, opencode, amp, omnigent)
  shall not be required to implement `CredentialHydrator` because they
  do not route LLM traffic through the proxy.

### R3: Compatibility Probing

- **REQ-17**: Where a connector implements `CompatibilityProbe`, the
  system shall send a synthetic test event through the full
  observe-act pipeline and report whether interception, authentication,
  verdict shaping, and telemetry emission each succeed.

- **REQ-18**: The `ProbeResult` shall contain four boolean fields:
  `Intercepting`, `Authenticating`, `Blocking`, `Reporting`, plus a
  `Failures` list with human-readable descriptions.

- **REQ-19**: The `defenseclaw doctor --verify-connector` command shall
  invoke `CompatibilityProbe` for the active connector and display
  results as a pass/fail checklist.

- **REQ-20**: When a compatibility probe succeeds, the system shall
  record the agent version and DefenseClaw version in
  `validated_versions.json` under the connector's entry.

- **REQ-21**: Proxy connectors (openclaw, zeptoclaw) shall implement
  `CompatibilityProbe` by sending a synthetic HTTP request through the
  proxy and verifying it arrives at the inspect pipeline.

- **REQ-22**: Hook-only connectors that implement `CompatibilityProbe`
  shall send a synthetic hook event payload to their hook API endpoint
  and verify the response matches the expected verdict shape.

- **REQ-23**: When the detected agent version falls outside all declared
  hook contract bands, the compatibility probe shall return
  `Intercepting=false` with a failure message naming the version and
  the nearest known band.

### R4: Connector Metadata API

- **REQ-24**: The gateway shall expose a
  `GET /v1/connectors/{name}/metadata` API endpoint returning the
  connector's `ConnectorCapabilities`, `AgentPaths`, and
  `ConnectorLocations` as JSON.

- **REQ-25**: The Python CLI shall consume
  `/v1/connectors/{name}/metadata` for path resolution, config
  discovery, and capability checks instead of reimplementing
  connector-specific logic in `connector_paths.py`.

- **REQ-26**: If the gateway is not reachable, the Python CLI shall
  fall back to the existing hardcoded path resolution with a warning
  that metadata may be stale.

### R5: Version-Aware Connector Config

- **REQ-27**: Each connector implementation shall organize its
  version-specific constants (home directory path, config file name,
  config schema assumptions, hook event list, default provider URLs)
  into a version-indexed lookup rather than top-level constants.

- **REQ-28**: When a connector detects an agent version at Setup time,
  the system shall select the matching version profile and use its
  constants for all path resolution, config patching, and hook writing.

- **REQ-29**: When the detected version does not match any declared
  profile, the system shall fall back to the latest known profile and
  log a warning with the detected version and the profile used.

### R6: ZeptoClaw Snapshot Refresh

- **REQ-30**: The ZeptoClaw connector shall watch
  `~/.zeptoclaw/config.json` for changes using the existing watcher
  infrastructure in `internal/watcher/`.

- **REQ-31**: When a config file change is detected, the system shall
  reload the provider snapshot (api_base and api_key per provider) and
  re-verify that api_base values point at the proxy.

- **REQ-32**: If a reloaded config shows api_base values that no
  longer point at the proxy, the system shall emit an audit event with
  `reason="zeptoclaw-config-drift"` and re-patch the config if
  auto-repair is enabled.

## Acceptance Criteria

- **AC-01** (REQ-01, REQ-06): OpenClaw interception verifier reports
  per-layer status for all 5 transport layers and the gateway logs
  layer-level health on each verification cycle.
- **AC-02** (REQ-02, REQ-03): When a transport layer is broken, the
  audit store contains an `interception-gap` event; when all layers
  fail, the telemetry stream contains a `severity=critical` event.
- **AC-03** (REQ-05, REQ-08): For each hook-only connector, the
  verifier correctly detects missing or modified hook entries and
  reports them.
- **AC-04** (REQ-07, REQ-30, REQ-31): ZeptoClaw verifier detects when
  `api_base` values have drifted from the proxy address; config
  watcher triggers snapshot reload within 5 seconds of file change.
- **AC-05** (REQ-09, REQ-12, REQ-13): A key pushed via
  `PUT /v1/credentials/openai` is served by
  `GET /v1/credentials/openai` for OpenClaw and written to both
  snapshot and config.json for ZeptoClaw.
- **AC-06** (REQ-14): When `DisableLocalKeyResolution` is active and no
  hydrated key exists, an LLM request returns 403 with error message.
- **AC-07** (REQ-15): After ZeptoClaw user rotates their key in
  config.json, `RefreshSnapshot()` picks up the new key within the
  watcher interval.
- **AC-08** (REQ-17, REQ-21): Proxy connector compatibility probe sends
  a synthetic request through the proxy and receives a 200 with probe
  marker; `ProbeResult.Intercepting=true`.
- **AC-09** (REQ-17, REQ-22): Hook connector compatibility probe sends
  a synthetic hook payload and receives a correctly-shaped verdict
  response; `ProbeResult.Blocking=true`.
- **AC-10** (REQ-19, REQ-20): `defenseclaw doctor --verify-connector`
  displays a 4-field pass/fail checklist and populates
  `validated_versions.json` on success.
- **AC-11** (REQ-24, REQ-25): Python CLI `connector_paths` module
  fetches metadata from `/v1/connectors/{name}/metadata` when the
  gateway is reachable and returns the same paths as the current
  hardcoded logic.
- **AC-12** (REQ-27, REQ-28, REQ-29): Each connector's Setup uses a
  version-indexed profile; unrecognized versions fall back to latest
  profile with a logged warning.

## Traceability

| REQ | Architecture Section | Acceptance Criteria |
|-----|---------------------|---------------------|
| REQ-01..08 | ARCHITECTURE.md §Connectors | AC-01, AC-02, AC-03, AC-04 |
| REQ-09..16 | ARCHITECTURE.md §Gateway API | AC-05, AC-06, AC-07 |
| REQ-17..23 | ARCHITECTURE.md §Connectors, §Verification rule | AC-08, AC-09, AC-10 |
| REQ-24..26 | ARCHITECTURE.md §Gateway API | AC-11 |
| REQ-27..29 | ARCHITECTURE.md §Connectors | AC-12 |
| REQ-30..32 | ARCHITECTURE.md §Connectors | AC-04, AC-07 |
