# Plan: Integration Resilience Layer

## Scope

### In scope

- Three new optional interfaces: `InterceptionVerifier`,
  `CredentialHydrator`, `CompatibilityProbe` in `connector` package.
- Implementations for all 14 connectors (except geminicli which is
  deprecated).
- `CredentialStore` and credential API endpoints
  (`GET/PUT/DELETE /v1/credentials/{provider}`).
- `GET /v1/connectors/{name}/metadata` API endpoint.
- Python CLI `connector_metadata.py` module and `connector_paths.py`
  refactor to consume gateway metadata.
- `defenseclaw doctor --verify-connector` flag.
- ZeptoClaw config file watcher + snapshot refresh.
- Version-aware config profiles inside existing connector
  implementations.
- CI target `make connector-certify` and `validated_versions.json`
  population.

### Out of scope

- Changes to the `Connector` interface or existing optional interfaces.
- New hook contracts or changes to existing version bands.
- Correlation provenance or telemetry schema changes.
- macOS Swift app refactor (deferred; the Python CLI refactor
  demonstrates the pattern; Swift follows later).
- Enterprise cloud integration for credential push (this spec builds
  the local infrastructure; the cloud push channel is a separate spec).
- Credential rotation scheduling (the hydration interface supports
  push; automated rotation policy is a separate concern).
- On-disk credential persistence (credentials are in-memory only).

## Dependencies

### Internal

- `internal/gateway/connector/connector.go` — existing interface
  (read-only dependency; not modified).
- `internal/gateway/token_resolver.go` — existing `TokenResolverFunc`
  (wired, not modified).
- `internal/gateway/api.go` — route registration for new endpoints.
- `internal/watcher/` — file watcher for ZeptoClaw config.
- `internal/audit/` — audit event emission for interception gaps.
- `extensions/defenseclaw/src/fetch-interceptor.ts` — self-test probe
  protocol (read by OpenClaw verifier).

### External

- No new external dependencies. All work is within the existing
  codebase and existing Go/Python/TypeScript toolchains.

## Rollout Plan

### Phase 1: Interface definitions + proxy connector implementations

1. Add `resilience.go` with the three interface definitions.
2. Implement `InterceptionVerifier` for OpenClaw and ZeptoClaw.
3. Add `CredentialStore`, credential API endpoints, and
   `CredentialHydrator` for OpenClaw and ZeptoClaw.
4. Add `CompatibilityProbe` for OpenClaw and ZeptoClaw.
5. Add ZeptoClaw config watcher + `RefreshSnapshot()`.

This phase is self-contained. Proxy connectors get full coverage first
because they have the highest-risk observe/act pipeline.

### Phase 2: Hook connector implementations

6. Implement generic `InterceptionVerifier` for `hookOnlyConnector`
   (shared logic: check config file, check entries, check script).
7. Override per-connector where needed:
   - Claude Code: check `settings.json` hook entries + OTel env block.
   - Codex: check `config.toml` hook entries + notify bridge.
   - Hermes: check `config.yaml` hooks + allowlist + script.
   - Cursor: check `hooks.json` entries + script (+ `.ps1` on Windows).
   - Copilot: check `defenseclaw.json` in `~/.copilot/hooks/` or
     workspace `.github/hooks/`.
   - Devin: check config hook entries + script.
   - OpenHands: check `hooks.json` entries + script.
   - Antigravity: check `hooks.json` entries + script.
   - OpenCode: check `defenseclaw.js` plugin artifact exists.
   - Amp: check `defenseclaw.ts` plugin artifact exists.
   - OmniGent: check `.pth` file + `defenseclaw_omnigent_policy.py` +
     `config.yaml` policy reference.
8. Implement generic `CompatibilityProbe` for `hookOnlyConnector`
   (shared logic: POST synthetic payload, check response shape).
9. Override per-connector verdict shape assertions:
   - Hermes: expect `{"decision":"block","reason":"..."}`.
   - Cursor: expect per-event output shapes.
   - Copilot: expect `copilot_output` field.
   - Claude Code: expect `claude_code_output` field.
   - Codex: expect `codex_output` field.
   - Antigravity: expect antigravity-specific output.
   - OpenCode/Amp: expect empty output (plugin translates internally).
   - OmniGent: expect empty output (Python policy translates).
   - Others: expect generic `hook_output` field.

### Phase 3: Metadata API + Python CLI refactor

10. Add `GET /v1/connectors/{name}/metadata` endpoint.
11. Add `connector_metadata.py` Python client module.
12. Refactor `connector_paths.py` to call metadata API with fallback.
13. Refactor relevant `claw_inventory.py` functions to use metadata.

### Phase 4: Doctor integration + CI certification

14. Add `--verify-connector` flag to `defenseclaw doctor`.
15. Add `make connector-certify` target.
16. Update `validated_versions.json` schema and population logic.
17. Add version-aware config profiles to each connector
    implementation.

### Phase 5: Extension-side transport negotiator

18. Refactor `fetch-interceptor.ts` to use `transport-negotiator.ts`
    (probe-install-verify per layer).
19. Add `credential-resolver.ts` for plugin-side hydrated key reads.
20. Update self-test to report per-layer results in the format
    `InterceptionVerifier` expects.

### Backward compatibility

- All new interfaces are optional. Existing behavior is preserved for
  connectors that do not implement them.
- The metadata API endpoint is additive; no existing endpoints change.
- The credential endpoints are new; no existing auth flow changes
  unless `DisableLocalKeyResolution()` is explicitly called.
- The Python CLI fallback ensures `defenseclaw scan` and other offline
  commands work without a running gateway.
- Version-aware profiles fall back to the latest known profile for
  unrecognized versions, matching existing hook contract behavior.

## Observability Plan

### Logs

- `InterceptionVerifier` results logged at `info` on healthy, `warn`
  on gaps, `error` when all layers fail.
- `CredentialHydrator` key delivery logged at `info` (provider name
  only, never the key value).
- `CompatibilityProbe` results logged at `info` (full `ProbeResult`).
- ZeptoClaw snapshot refresh logged at `info` on success, `warn` on
  drift detection.

### Metrics

- `defenseclaw_interception_layer_healthy` (gauge, labels: connector,
  layer) — 1 when healthy, 0 when broken.
- `defenseclaw_interception_gaps_total` (counter, labels: connector) —
  incremented on each gap detection.
- `defenseclaw_credential_hydrations_total` (counter, labels:
  connector, provider) — incremented on each successful hydration.
- `defenseclaw_compatibility_probes_total` (counter, labels:
  connector, result) — incremented on each probe (pass/fail).

### Traces

- No new spans. Interception verification and compatibility probing
  run outside the request hot path.

### Audit events

- `interception-gap`: emitted when a transport layer fails
  verification. Fields: connector, layer, detail.
- `zeptoclaw-config-drift`: emitted when ZeptoClaw's config.json
  api_base no longer points at the proxy. Fields: provider, expected,
  actual.
- `credential-hydrated`: emitted when a provider key is pushed.
  Fields: connector, provider (no key value).

## Security Plan

### Auth/Authz

- `GET/PUT/DELETE /v1/credentials/{provider}` require `X-DC-Auth`
  bearer token or master key (`sk-dc-...`). Same auth as existing
  gateway API endpoints.
- `GET /v1/connectors/{name}/metadata` requires `X-DC-Auth`.
- Credential store is in-memory only; no on-disk secret file is
  created.

### Data handling

- API keys stored in `CredentialStore` are never logged, never written
  to the audit store, and never included in telemetry events.
- `credential-hydrated` audit event contains provider name only.
- `GET /v1/credentials/{provider}` response body contains the raw key;
  this endpoint is loopback-only and authenticated.

### Multi-tenancy

- Not applicable. DefenseClaw is a single-tenant endpoint agent. The
  credential store is per-sidecar instance.

### Threat model additions

- **Credential endpoint exfiltration**: A local process that obtains
  the gateway token can read all hydrated keys. Mitigation: gateway
  token is generated per-boot, stored at `~/.defenseclaw/.env` with
  mode 0600, and scoped to loopback. This is equivalent to the
  existing risk surface where any process reading `.env` can
  impersonate the agent.
- **Config file TOCTOU**: ZeptoClaw's `HydrateProviderKey` writes to
  `config.json` which the user or agent may also be writing.
  Mitigation: atomic write with temp file + rename; connector setup
  lock held during write.
