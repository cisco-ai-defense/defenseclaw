# Tasks: Integration Resilience Layer

## Tasks

### Phase 1: Interface definitions + proxy connectors (REQ-01..15, REQ-30..32)

1. [ ] **Define the three optional interfaces** — Create
   `internal/gateway/connector/resilience.go` with
   `InterceptionVerifier`, `CredentialHydrator`, `CompatibilityProbe`
   and their associated types (`LayerStatus`, `InterceptionStatus`,
   `ProbeResult`, etc.). Add `resilience_test.go` with interface
   satisfaction compile-time checks for all connectors that will
   implement them.
   _Maps to: REQ-01, REQ-09, REQ-17_

2. [ ] **Implement OpenClaw InterceptionVerifier** — Surface the
   existing TypeScript self-test results (reported via
   `/v1/events/egress` with branch=selftest) into the Go
   `InterceptionVerifier`. Parse the self-test events to extract
   per-layer status (fetch, https, http, http.get, undici). When no
   self-test events have arrived within the verification interval,
   report all layers as unknown with a gap message.
   _Maps to: REQ-01, REQ-06_

3. [ ] **Implement ZeptoClaw InterceptionVerifier** — Read
   `~/.zeptoclaw/config.json`, iterate the `providers` map, verify
   each provider's `api_base` starts with the configured proxy address
   (`http://127.0.0.1:{port}/c/zeptoclaw`). Report per-provider layer
   status. Also verify the config file exists and is parseable.
   _Maps to: REQ-01, REQ-07_

4. [ ] **Implement ZeptoClaw config watcher + RefreshSnapshot** —
   Register `~/.zeptoclaw/config.json` with `internal/watcher/` on
   sidecar boot. On change event: reload the provider snapshot (parse
   config, extract api_base and api_key per provider), re-verify
   api_base values point at proxy. If drift detected, emit
   `zeptoclaw-config-drift` audit event and re-patch if auto-repair
   is enabled.
   _Maps to: REQ-15, REQ-30, REQ-31, REQ-32_

5. [ ] **Implement CredentialStore** — Create
   `internal/gateway/token_hydrator.go` with an in-memory
   `CredentialStore` (map of provider name to `StoredCredential`).
   Wire it as the backing store for `TokenResolverFunc` via
   `SetTokenResolver`. When the store has a key for a provider, return
   it; otherwise fall through to existing resolution chain.
   _Maps to: REQ-09, REQ-14_

6. [ ] **Implement credential API endpoints** — Create
   `internal/gateway/api_credentials.go` with:
   - `GET /v1/credentials/{provider}` — return hydrated key (for
     OpenClaw plugin).
   - `PUT /v1/credentials/{provider}` — accept key, store in
     `CredentialStore`, dispatch to all `CredentialHydrator`
     connectors.
   - `DELETE /v1/credentials/{provider}` — remove key, dispatch
     revocation.
   Auth: X-DC-Auth or master key. Register routes in `api.go`.
   _Maps to: REQ-10, REQ-11_

7. [ ] **Implement OpenClaw CredentialHydrator** — The OpenClaw
   implementation stores the key in the `CredentialStore` (which the
   `GET /v1/credentials/{provider}` endpoint serves). No config file
   writes needed. `RefreshSnapshot` is a no-op (credentials flow via
   headers). `SupportedProviders` returns empty (all providers).
   _Maps to: REQ-12_

8. [ ] **Implement ZeptoClaw CredentialHydrator** — Write the key to
   both the in-memory provider snapshot and the on-disk
   `~/.zeptoclaw/config.json` `api_key` field for the specified
   provider. Use atomic write with the connector setup lock.
   `RefreshSnapshot` re-reads config.json and rebuilds the snapshot.
   `SupportedProviders` returns the list of providers in the snapshot.
   _Maps to: REQ-13, REQ-15_

9. [ ] **Implement OpenClaw CompatibilityProbe** — Send a synthetic
   HTTP request to `http://127.0.0.1:{proxyPort}/v1/chat/completions`
   with `X-DC-Probe: 1` header and valid `X-DC-Auth`. Check:
   - Intercepting: request reached the proxy (not 502/timeout).
   - Authenticating: response is not 401/403.
   - Blocking: send a second request with known-blocked content,
     verify synthetic 200 block response.
   - Reporting: check audit store for probe event within 5s.
   _Maps to: REQ-17, REQ-21_

10. [ ] **Implement ZeptoClaw CompatibilityProbe** — Send a synthetic
    request to `http://127.0.0.1:{proxyPort}/c/zeptoclaw/v1/chat/completions`
    with a provider bearer from the snapshot. Same four-stage check as
    OpenClaw.
    _Maps to: REQ-17, REQ-21_

11. [ ] **Wire interception verification into sidecar boot + timer** —
    After `connector.Setup()` succeeds, call `VerifyInterception` if
    available. Log results. Start a ticker (configurable via
    `guardrail.interception_verify_interval`, default 60s) that
    re-runs verification and emits audit/telemetry events on gaps.
    _Maps to: REQ-04_

### Phase 2: Hook connector implementations (REQ-05, REQ-08, REQ-22, REQ-23)

12. [ ] **Implement generic hookOnlyConnector InterceptionVerifier** —
    The generic implementation checks:
    (a) Hook config file exists at the connector's declared path.
    (b) Config file contains expected DefenseClaw hook entries (match
    against `HookProfile.SupportedEvents`).
    (c) Hook script or plugin artifact exists on disk and is
    executable/readable.
    Returns `LayerStatus` per check. Connectors with special needs
    override this.
    _Maps to: REQ-05, REQ-08_

13. [ ] **Per-connector InterceptionVerifier overrides** — Implement
    overrides for connectors with non-standard verification needs:
    - **Claude Code**: Verify `~/.claude/settings.json` has hooks
      block + OTel env entries. Verify `claude-code-hook.sh` exists.
      Optionally verify CodeGuard plugin if installed.
    - **Codex**: Verify `~/.codex/config.toml` has hooks + OTel +
      notify bridge entries. Verify `codex-hook.sh` exists. On
      Windows verify `managed_config.toml`.
    - **Hermes**: Verify `config.yaml` hooks block has all 23 entries.
      Verify `shell-hooks-allowlist.json` has matching approvals.
      Verify `hermes-hook.sh` exists.
    - **Cursor**: Verify `~/.cursor/hooks.json` has entries. Verify
      script (`.sh` on Unix, `.ps1` on Windows).
    - **Copilot**: Verify `~/.copilot/hooks/defenseclaw.json` or
      workspace `.github/hooks/defenseclaw.json`. Verify script.
    - **Devin**: Verify config hook entries. Verify script.
    - **OpenHands**: Verify `~/.openhands/hooks.json` entries. Verify
      script. On Darwin also verify NativeOTLP path token.
    - **Antigravity**: Verify `~/.gemini/config/hooks.json` entries.
      Verify script.
    - **OpenCode**: Verify `~/.config/opencode/plugins/defenseclaw.js`
      exists and is readable.
    - **Amp**: Verify `~/.config/amp/plugins/defenseclaw.ts` exists
      and is readable.
    - **OmniGent**: Verify `.pth` file in site-packages. Verify
      `defenseclaw_omnigent_policy.py` exists. Verify `config.yaml`
      references the policy handler.
    _Maps to: REQ-08_

14. [ ] **Implement generic hookOnlyConnector CompatibilityProbe** —
    The generic implementation:
    (a) Builds a synthetic hook payload matching the connector's first
    blockable event (from `HookProfile.Capabilities.BlockEvents[0]`).
    (b) POSTs to the connector's `HookAPIPath()` with scoped hook
    token.
    (c) Checks response status is 200.
    (d) Parses response body and checks it contains the expected
    output field (`HookProfile.ResponseFieldName`).
    (e) For Reporting: checks audit store for the synthetic event.
    Returns `ProbeResult`.
    _Maps to: REQ-17, REQ-22_

15. [ ] **Per-connector CompatibilityProbe verdict shape assertions** —
    Each connector checks the response matches its specific verdict
    shape:
    - **Hermes**: Response contains
      `{"decision":"block","reason":"..."}` (not
      `{"action":"deny"}`).
    - **Claude Code**: Response contains `claude_code_output` field
      with `result="deny"` or `result="allow"`.
    - **Codex**: Response contains `codex_output` field.
    - **Cursor**: Response contains `permission`/`deny`/`ask` per
      event type.
    - **Copilot**: Response contains `copilot_output` field.
    - **Antigravity**: Response matches antigravity-specific shape.
    - **OpenCode**: Response is empty JSON (plugin translates
      internally).
    - **Amp**: Response is empty JSON (plugin translates).
    - **OmniGent**: Response is empty JSON (Python policy translates).
    - **Devin**: Response contains generic `hook_output` field.
    - **OpenHands**: Response contains generic `hook_output` field.
    _Maps to: REQ-22_

### Phase 3: Metadata API + Python CLI (REQ-24..26)

16. [ ] **Implement connector metadata API endpoint** — Create
    `internal/gateway/api_connector_metadata.go` with
    `GET /v1/connectors/{name}/metadata`. Resolve the connector from
    the registry. Type-assert `ConnectorCapabilityProvider`,
    `AgentPathProvider`, and `InterceptionVerifier` if available.
    Return JSON with capabilities, paths, locations, interception
    status (if available), and version bands (from hook contract).
    Register in `api.go`.
    _Maps to: REQ-24_

17. [ ] **Implement Python connector_metadata.py client** — Create
    `cli/defenseclaw/connector_metadata.py` with a
    `ConnectorMetadataClient` class that calls
    `GET /v1/connectors/{name}/metadata`. Cache response for the CLI
    session. Handle connection failures gracefully (return None so
    callers can fall back).
    _Maps to: REQ-25_

18. [ ] **Refactor connector_paths.py to use metadata API** — For each
    function in `connector_paths.py` that returns hardcoded paths
    (`_openclaw_skill_dirs`, `_hermes_skill_dirs`,
    `_zeptoclaw_skill_dirs`, etc.), try the metadata API first. If
    available, return paths from the `locations.surfaces.skills.read_paths`
    field. If unavailable, fall back to existing hardcoded logic with
    a `logger.debug` message.
    _Maps to: REQ-25, REQ-26_

19. [ ] **Refactor claw_inventory.py config parsers** — For functions
    that parse connector configs directly
    (`_agents_from_zeptoclaw_json`, `_tools_from_zeptoclaw_json`,
    `_providers_from_zeptoclaw_config`, etc.), try the metadata API
    for path resolution. The actual parsing remains (inventory needs
    to read the files), but the paths come from metadata rather than
    hardcoded strings.
    _Maps to: REQ-25, REQ-26_

### Phase 4: Doctor + CI + version profiles (REQ-19..20, REQ-27..29)

20. [ ] **Add --verify-connector to defenseclaw doctor** — Add a new
    flag `--verify-connector` to the Python CLI `cmd_doctor.py`. When
    set: resolve the active connector from the gateway API
    (`GET /v1/status`), invoke `CompatibilityProbe` via
    `POST /v1/connectors/{name}/probe` (new internal endpoint), and
    display results as a 4-field checklist with pass/fail indicators.
    _Maps to: REQ-19_

21. [ ] **Add make connector-certify CI target** — Add a Makefile
    target that: (a) starts the sidecar with a test config, (b) runs
    `defenseclaw doctor --verify-connector`, (c) on success writes the
    agent version + DefenseClaw version to `validated_versions.json`.
    Integrate with the existing `connector-matrix` CI job.
    _Maps to: REQ-20_

22. [ ] **Implement version-aware config profiles** — For each
    connector implementation, extract hardcoded constants (home dir,
    config file, hook event list, default URLs) into a
    `versionProfile` struct with a version range. At `Setup` time,
    match the detected `AgentVersion` against profiles and use the
    matched profile's constants. If no match, fall back to latest
    profile with a logged warning.
    Connectors and their profile contents:
    - **OpenClaw**: home=`~/.openclaw`, config=`openclaw.json`,
      plugin paths, SDK type shapes.
    - **ZeptoClaw**: home=`~/.zeptoclaw`, config=`config.json`,
      default provider URLs (8 entries), model format.
    - **Claude Code**: home=`~/.claude`, config=`settings.json`,
      event lists per v1/v2 contract.
    - **Codex**: home=`~/.codex`, config=`config.toml`, event lists
      per v1-v4, notify bridge config.
    - **Hermes**: home=`~/.hermes` (Unix) or `%LOCALAPPDATA%\hermes`
      (Windows), config=`config.yaml`, 23 events, allowlist format.
    - **Cursor**: home=`~/.cursor`, config=`hooks.json`, 21 events.
    - **Copilot**: home=`~/.copilot`, config=`hooks/defenseclaw.json`,
      14 events per v2.
    - **Devin**: config paths (user vs workspace scope), 8 events.
    - **OpenHands**: home=`~/.openhands`, config=`hooks.json`,
      6 events, Darwin NativeOTLP.
    - **Antigravity**: home=`~/.gemini`, config=`config/hooks.json`,
      5 events.
    - **OpenCode**: plugin path=`~/.config/opencode/plugins/`,
      10 events.
    - **Amp**: plugin path=`~/.config/amp/plugins/`, 5 events.
    - **OmniGent**: policy bridge path, `.pth` target, config ref,
      6 events.
    - **GeminiCLI**: skip (deprecated).
    _Maps to: REQ-27, REQ-28, REQ-29_

### Phase 5: Extension-side transport negotiator (REQ-06)

23. [ ] **Create transport-negotiator.ts** — Extract transport layer
    patching from `fetch-interceptor.ts` into a
    `transport-negotiator.ts` module with a `TransportLayer` interface
    (probe, install, verify). Implement for each of the 5 existing
    layers. Add a `negotiateTransport()` function that iterates
    layers, probes each, installs if patchable, verifies after install,
    and returns `InstalledLayers` with per-layer results.
    _Maps to: REQ-06_

24. [ ] **Create credential-resolver.ts** — Add
    `extensions/defenseclaw/src/credential-resolver.ts` that calls
    `GET /v1/credentials/{provider}` with X-DC-Auth. Used by the
    fetch interceptor to resolve hydrated keys when building proxy
    headers (instead of extracting from request headers). Falls back
    to header extraction when the endpoint returns 404 or is
    unreachable.
    _Maps to: REQ-12_

25. [ ] **Update self-test reporting format** — Modify the self-test
    in `fetch-interceptor.ts` to report per-layer results as
    structured JSON in the `/v1/events/egress` selftest event, matching
    the `LayerStatus` schema the Go `InterceptionVerifier` expects.
    Include: layer name, healthy boolean, detail string per layer.
    _Maps to: REQ-01, REQ-06_

26. [ ] **Spec updates + CONTEXT.md** — Update this spec's status
    from Draft to Implemented. Update `docs/specs/README.md` index.
    Append CONTEXT.md entry.
    _Maps to: all REQs_

## Test Plan

### Unit Tests

- **resilience.go**: Compile-time interface satisfaction for all
  implementing connectors.
- **OpenClaw InterceptionVerifier**: Mock self-test event parsing;
  test healthy/partial/all-failed scenarios.
- **ZeptoClaw InterceptionVerifier**: Fixture `config.json` files with
  correct/drifted/missing api_base values.
- **ZeptoClaw RefreshSnapshot**: Test snapshot before/after config
  change, atomic write correctness.
- **CredentialStore**: Concurrent read/write safety, key lifecycle
  (store/read/delete), provider enumeration.
- **Credential API**: Auth enforcement (reject without token), CRUD
  operations, dispatch to hydrators.
- **Metadata API**: Response shape for each connector, fallback when
  optional interfaces are absent.
- **Generic hookOnlyConnector verifier**: Mock config files with
  present/absent/corrupted hook entries.
- **Generic hookOnlyConnector probe**: Mock HTTP handler that returns
  expected/unexpected verdict shapes.
- **Per-connector probes**: Golden response fixtures per connector
  matching their HookProfile.Respond output.
- **Version profiles**: Version matching against declared ranges,
  fallback to latest on unknown version, warning logged.

### Integration Tests

- **Proxy connector E2E**: Start sidecar, configure OpenClaw connector
  (mock agent), send request through proxy, verify
  `InterceptionVerifier` reports healthy, `CompatibilityProbe` passes,
  `CredentialHydrator` delivers key.
- **Hook connector E2E**: Start sidecar, configure Claude Code
  connector, POST synthetic hook event, verify
  `InterceptionVerifier` reports hook entries present,
  `CompatibilityProbe` passes with expected verdict shape.
- **Python CLI metadata**: Start sidecar, run `connector_paths`
  functions with gateway available and unavailable, verify same
  results with and without gateway.
- **ZeptoClaw watcher**: Write config.json, modify api_base, verify
  `RefreshSnapshot` triggers, verify drift audit event emitted.

### Golden Fixtures (per-connector)

Expand existing `test/e2e/golden/` per-connector directories:

| Connector | Existing | Added |
|-----------|----------|-------|
| openclaw | 16 files | probe-pass.golden.json, probe-fail.golden.json, interception-healthy.golden.json |
| zeptoclaw | 3 files | probe-pass.golden.json, interception-drift.golden.json, credential-hydrate.golden.json |
| claudecode | 1 file | probe-pass.golden.json, interception-hooks-present.golden.json |
| codex | 1 file | probe-pass.golden.json, interception-hooks-present.golden.json |
| hermes | 1 file | probe-pass.golden.json, interception-config-present.golden.json |
| cursor | 1 file | probe-pass.golden.json |
| copilot | 1 file | probe-pass.golden.json |
| devin | 1 file | probe-pass.golden.json |
| openhands | 1 file | probe-pass.golden.json |
| antigravity | 1 file | probe-pass.golden.json |
| opencode | 1 file | probe-pass.golden.json, interception-plugin-present.golden.json |
| amp | 1 file | probe-pass.golden.json, interception-plugin-present.golden.json |
| omnigent | 1 file | probe-pass.golden.json, interception-policy-present.golden.json |

### CI Integration

- `make connector-certify` runs in the `connector-matrix` CI job
  after the existing `make connector-matrix-test`.
- Version radar workflow (`connector-version-radar.yml`) extended to
  run `make connector-certify` when a new upstream version is
  detected, populating `validated_versions.json` automatically.
