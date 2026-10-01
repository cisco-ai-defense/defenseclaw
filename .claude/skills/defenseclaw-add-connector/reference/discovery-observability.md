# Discovery, inventory and observability

The **slug** is the value `Connector.Name()` returns. The same string is used as:
- the metric label `connector`;
- the OTLP `source` and `defenseclaw.connector.source`;
- the audit `connector` column;
- the `/otlp/<scope>/...` path segment and the token filename;
- the discovery report key.

**Slug limits:**
- 1–64 characters for the hook audit envelope and audit events (`schemas/hook-audit-envelope.json`, `schemas/audit-event.json`).
- Up to 128 bytes for discovery.
- `observability.IsStableToken` for metric labels (`hookDecisionMetricConnector`).

**Unrelated counts:** several tests pin the number 14 for things other than connectors, such as observability buckets (`internal/config/observability_v8_*_test.go`) and redaction detectors (`internal/observability/redaction/*_test.go`). Don't bump those.

## 1. Order of work

### A. Prerequisites that other layers own

1. **Registry.** `newBuiltinConnectors` (core.md). The discovery endpoint drops unknown names with error class `unknown_connector`, and returns HTTP 400 if every name is unknown (`internal/gateway/agent_discovery.go` `validateAgentDiscoveryReport`).
2. **Windows row.** `windowsConnectorSupport`. Without it, `inventoryConnectorAvailableOnOS` hides the connector from Windows inventory and from MCP rows.
3. **Python list.** `KNOWN_CONNECTORS` (`cli/defenseclaw/connector_paths.py`). `test_connector_surface_parity.py` and `test_registry_manifest.py` treat it as the source of truth.
4. **Hook route.** The `internal/gateway/hook_register.go` `init()` list. Without a route, no events arrive.

### B. AI discovery signatures

1. **Signature entry.** Add one entry to `internal/inventory/ai_signatures.json` with `id`, `name`, `vendor`, `category:"supported_connector"`, `supported_connector:"<slug>"`, `confidence` and `specificity`, plus whichever of these apply: `binary_names`, `process_names`, `config_paths`, `mcp_paths`, `skill_paths`, `plugin_paths`, `rule_paths`, `application_names`, `env_var_names`, `domain_patterns`, `history_patterns`.
   - The struct is `AISignature` (`internal/inventory/ai_catalog.go`), embedded with `//go:embed`.
   - `validateAISignature` requires id, name, vendor and an allowed category, and bounds the values.
   - Copy the `copilot`, `kiro` or `amp` entry as a template.
2. **Python mirror.** Copy the file byte for byte to `cli/defenseclaw/inventory/ai_signatures.json` (`test_packaged_catalog_is_byte_identical_to_go_authority`).
3. **Parity tests** (`internal/inventory/connector_parity_test.go`):
   - `TestSupportedConnectorParityMatrix`: needs one of mcp, skill or plugin paths, or an entry in `zeroSurfacesExempt` with a reason.
   - `TestSupportedConnectorMCPOnEveryConnector`: needs `mcp_paths` unless the slug is in `mcpExempt`.
   - `TestSupportedConnectorCountMatchesRegistry`: **bump** `const expected`.
4. **Per-OS rules.**
   - **Paths:** Windows `$VAR` values in paths resolve through Known Folders (`platformDiscoveryVariable`, `ai_discovery_platform_windows.go`); on POSIX they are plain environment lookups.
   - **`application_names`:** these must match what each OS reports. macOS uses `.app` bundles. Windows uses Start-menu names, the Uninstall `DisplayName` and AppsFolder (`ai_discovery_apps_windows.go`).
   - **Process names:** on Windows, a process name claimed by two signatures is dropped silently (`windowsProcessAliases`, `internal/inventory/process_snapshot.go`).
5. **Promotion churn.** Promoting a signature from `ai_cli` to `supported_connector` changes its fingerprints, so each user sees a one-time gone/new pair (the `promotedAgentKinds` comment in `ai_catalog.go`).
6. **Unusual skill layouts.** Add a detector branch next to the Hermes and Codex ones in `internal/inventory/ai_discovery.go`.
7. **Windows managed installs.** Add the agent's profile dot-directory to `inventoryDACLDotdirs` (`internal/enterprisehooks/inventory_dacl_windows.go`). Otherwise the gateway's service account gets access-denied and the signals disappear without an error.
8. **Sensor host plane.** Add the executable name to `agentProcessPattern` (`internal/sensor/tactics/agent.go`); every host-plane signal requires a known agent ancestor (`TestIsAgentProcessMatchesKnownAgentsOnly`). Add vendor egress tokens to `vendorCategories` (`internal/sensor/catalog/catalog.go`).

### C. CLI agent discovery

1. **Spec** (`cli/defenseclaw/inventory/agent_discovery.py`):
   - Add the slug to `DISCOVERY_PRECEDENCE`.
   - Add `_SPECS[<slug>] = _AgentSpec(config_candidates, binary_name, version_args, binary_names, windows_binary_names, macos_bundle_binaries)`.
   - If the config location is dynamic (an env home, `%APPDATA%`, workspace files), add a branch to `_scan_agent`.
   - If the version probe is slow, add a longer timeout in `_version_for_binary`.
   - GUI bundles are read from `Info.plist` and never launched.
   - Bump `CACHE_SCHEMA_VERSION` if the signal shape changes.
2. **Rules.**
   - `installed` is true only when a binary is found under a trusted prefix **and** its version probe succeeds.
   - `configured` means a config **file** exists; a directory on its own is never evidence.
3. **Report path.** `cmd_agent.py` `_sanitized_discovery_report` sends only basenames and `sha256:` path hashes. The report goes to `gateway.py` `emit_agent_discovery`, then `POST /api/v1/agents/discovery`. The gateway decoder uses `DisallowUnknownFields` and caps a report at `maxAgentDiscoveryAgents` (32).
4. **Tests.**
   - `cli/tests/test_agent_discovery.py`: rows in `test_each_connector_tracks_meaningful_config_separately_from_installation` and `test_empty_connector_directories_are_not_install_evidence`, plus probe tests.
   - `cli/tests/test_connector_surface_parity.py` `test_agent_discovery_covers_every_active_connector`.

### D. Managed endpoint inventory (`ai_component.observed`)

- **Connector rows.** `endpointConnectorComponentsForOS` (`internal/gateway/inventory_events.go`) builds them from the registry. `Description()` must be meaningful. `ToolInspectionMode` must be one of `pre-execution`, `response-scan` or `both`, and `SubprocessPolicy` one of `sandbox`, `shims` or `none`.
- **MCP per user home.** Add the slug to `hasNativeMCPReader` **and** add a case to `readMCPServersUnderHomeForOS`. Owner attribution comes from `inventoryHomeOwner`.
- **Tests.** `TestEndpointConnectorComponentsWindowsExactNativeRoster` (exact roster), `TestReadMCPServersUnderHomeUsesCanonicalUserConfigs` and `TestPerConnectorMCPEntriesWindowsExcludesUnsupportedAndDeprecated`.

### E. Public schemas with closed connector lists

| File and field | What it is | Pinned by |
|---|---|---|
| `schemas/otel/resource.schema.json` `defenseclaw.claw.mode` | resource attribute; also allows `multi` and `""`; update the `claw.home_dir` description too | `scripts/check_schemas.py` `EXPECTED_CLAW_MODE_ENUM`, `cli/tests/test_check_schemas.py` |
| `schemas/registry-manifest.schema.json` | three `connector` lists | `cli/tests/test_registry_manifest.py` vs `KNOWN_CONNECTORS`; `cli/defenseclaw/registries/manifest.py` |
| `schemas/otel/connector-telemetry-event.schema.json` `defenseclaw.connector.source` | log attribute | **nothing**; update it by hand |
| `schemas/otel/metrics.schema.json` connector metrics | `connector` on the `defenseclaw.connector.hook.*` metrics, `source` on the `defenseclaw.otel.ingest.*` metrics | **nothing**; update it by hand |

These fields are free-form, so they need no enum change: the hook audit envelope and audit event `connector`, `agent-lifecycle-event`, `defenseclaw.connector.source` in `schemas/telemetry/v8/genai.yaml`, `defenseclaw.agent.discovery.connector`, and the `connector` metric label. Run `make check-schemas`.

### F. Telemetry normalizers

A missing entry here doesn't fail. The value becomes `unknown` or `other`.

1. **OTLP source.** Add the slug to `normalizeConnectorTelemetrySource` (`internal/gateway/otel_ingest.go`). It is used by `handleOTLPSignal` (the `X-DefenseClaw-Source` header), `parseOTLPPathToken`, OTLP auth in `api.go`, and `otlpAuthFailureConnector`. A missing slug gives `unknown`, `agentIdentityForOTLPSource` then returns an empty identity, and path-token auth can't find the scope. Add the slug to `TestNormalizeConnectorTelemetrySourceIncludesHookOnlyBuiltins`.
2. **Metric event type.** `NormalizeHookEventTypeLabel` (`internal/telemetry/normalization.go`) maps vendor event names onto prompt, tool_call, tool_result, response, stop, subagent_start/stop, notification, session_start/end, compact, other or unknown. It matches after lowercasing and stripping `_ - .`; anything unmapped becomes `other`. Test: `internal/telemetry/model_label_normalize_test.go`.
3. **Agent lifecycle.** `canonicalHookLifecycleEvent` (`internal/gateway/llm_event_emit.go`) maps to session, turn, tool or compact start/end; anything unmapped becomes `event`. If the agent has no subagent events, add it to `connectorNeedsInferredDelegation` and `isAgentSpawnerTool`.
4. **Event classes.** In `internal/gateway/agent_hook.go`: `canonicalEvent`, `isGenericToolInspectionEvent`, `isPromptLikeEvent`, `isResultLikeEvent`, and `normalizeHookEventLabel`, which builds the `connector:event` tool label.
5. **Turn counter.** `isPromptClassHookEvent` (`internal/gateway/hook_telemetry.go`) marks the `step_idx` turn boundary when there is no TurnID. It matches only `userpromptsubmit`, `user_prompt_submit`, `userprompt` and `prompt`, and does **not** strip separators.
6. **Correlation lifecycle.** `correlationLifecycleForContract` compares names exactly, case included.

### G. Correlation profile (required for every built-in connector)

See core.md §3.4. The tests:
- `TestBuiltinCorrelationProfilesAreVersionedAndValid`: bump `want`; requires a non-explicit profile with `Connector == name` that passes `Validate()`.
- `TestCorrelationContractSourcesAndFixturesAreImmutable`.
- `TestNativeTelemetryRegistryIsExplicit`: add the slug to the map.
- `TestHookLifecycleBindingsUseOnlyReviewedContractEvents`.

### H. Native OTLP (only if the vendor exports OTel)

- **Exporter.** `NativeOTLPSpec` (`internal/gateway/connector/native_otlp.go`) supports `env_block` (Claude Code), `toml_block` (Codex) and `file_sink`. Set `PathToken`/`PathScope` when the exporter can't send headers.
- **Credentials.** In `otlp_token.go`, add an `OTLPScope<X>` constant to both `OTLPPathTokenScopes()` and `OTLPPathTokenScopeForConnector`. This allowlist is closed. Tokens are 64 lowercase hex characters.
- **Auth.** Loopback only. The header form uses the normalized `X-DefenseClaw-Source`, and the path form is `/otlp/<scope>/<token>/v1/<logs|metrics|traces>`. The standalone profile requires user-scoped credentials (`connector.UserScopedOTLPCredential`).
- **Mapping.** Add `binding_classes` with `sources: [<slug>]` under `inbound_bindings` in `schemas/telemetry/v8/registry.yaml` (copy the Codex and Claude Code classes). Then run `make telemetry-generate`, which regenerates `internal/observability/zz_generated_telemetry_*.go` and `schemas/telemetry/runtime/*.json.gz`. `make telemetry-check` fails on drift.
- **Status.** Add the connector's channels (hooks, otel, notify, policy-api) in `connectorModeFor` (`internal/gateway/api.go`). Whether a connector shows as proxy or hooks comes from `connectorProxyBindsByName`, not from a name list.
- **Tests.** `native_otlp_golden_test.go`, `otlp_token_test.go`, `internal/gateway/otlp_path_token_test.go`, `user_scoped_credentials_test.go`.

### I. New attributes or event families (only for a new surface)

The ACP commit `f05a9d3c` added `defenseclaw.acp.*` attributes to `schemas/telemetry/v8/security.yaml`. Each one declares type, brief, examples, stability, owner, field_class, sensitivity, cardinality, normalization and `introduced_in`, and is referenced with `requirement_level: optional`. The emitter is `internal/gateway/api_guardrail_event_observability_v8.go`. Regenerate after editing the YAML.

### J. Audit attribution

- **Audit fields.** `internal/audit/store.go` has `Connector`, `StepIdx`, `Enforced` and `RulePackDir`. They are stamped by `stampHookEnvelopeIdentity` (`hook_telemetry.go`). `TestMultiConnectorSinkParity` (`internal/audit/parity_test.go`) checks the field set across all sinks.
- **User identity headers.** Shell hooks must send `X-DefenseClaw-User-Id` and `X-DefenseClaw-User-Name` (`hook_user_identity_test.go`, which globs `hooks/*-hook.sh`). **In-agent plugins are a hand-kept list:** add yours to `TestPluginTransportsReportIdentityToo`, and guard `uid >= 0` for Windows. The native runner sends them from `hookexec.go`.
- **Email.** `internal/useridentity/email.go` `EmailForConnector` covers only claudecode, codex and cursor. Add a connector only if the vendor stores a verified account; never synthesize an address.

### K. Health and status

- **Gateway counters.** `internal/gateway/health.go`: `ConnectorHealth`, `RegisterConnectorWithSource`, `RecordConnectorRequestFor`, `RecordConnectorErrorFor`, `RecordToolInspectionFor` and `RecordToolBlockFor`. A load heartbeat (`RecordConnectorLoadHeartbeatFor`) exists only for opencode. Plugin connectors that can fail to load silently should follow it.
- **Display names.** Add the slug to:
  - `internal/cli/status.go` `friendlyConnectorName`;
  - `cli/defenseclaw/commands/cmd_status.py` `_FRIENDLY_CONNECTOR_NAMES` (pinned by `test_status_friendly_names_cover_every_known_connector` in `cli/tests/test_connector_surface_parity.py`);
  - `macos/DefenseClawMac/DefenseClawMac/DataLayer/Models.swift`, one of several macOS app lists (cli-tui.md step 15).
- **Doctor tables** (`cli/defenseclaw/commands/cmd_doctor.py`). Only `_CONNECTOR_LABELS` is pinned; update the rest by hand: `_DOCTOR_MARKERS`, `_GENERATED_HOOK_SENTINELS`, `_GENERATED_HOOK_REGEN_COMMANDS`, `_HOOK_HEALTH_FALLBACK`, `_HOOK_HEALTH_LABELS`, `_SETUP_READINESS_PRIMARY_LABELS`, `_CONNECTOR_RESIDUE_ARTIFACTS`, `_HOOK_ENFORCED_CONNECTORS`.
- **Managed runtime descriptor.** `internal/managed/runtime_descriptor.go` `MachinePolicyConnectors` must be canonical lowercase and unique.

### L. Dashboards

`bundles/local_observability_stack/grafana/dashboards/defenseclaw-agent-identity.json` and `defenseclaw-hitl.json` hard-code a `custom` connector list, which `scripts/check_grafana_dashboards.py` doesn't check. The other panels use `label_values` and pick new connectors up automatically.

## 2. How connector kinds differ here

| Kind | Status channels | Notes |
|---|---|---|
| Shell hook (cursor, hermes, devin, copilot, antigravity) | hooks | the `*-hook.sh` glob covers the identity headers |
| Hook binary (claudecode, codex; Kiro on Windows) | hooks + otel (+ notify for codex) | native OTLP for claudecode and codex |
| In-agent plugin (opencode, amp) | hooks | add to the plugin identity list; OpenCode has a load heartbeat |
| Policy API (omnigent) | policy-api | exempt from the parity tests; `ReceiptTargets` is nil |
| Proxy (openclaw, zeptoclaw) | llm_proxy | the e2e `DestinationApp` label comes from `/c/<name>/` |
| ACP (kiro) | hooks + ACP | ACP correlation surface; `defenseclaw.acp.*` attributes; the ACP registry copies must match |

## 3. Per-OS differences

- **Windows:**
  - Inventory needs a Supported or Preview row.
  - Paths use Known Folders, and the gateway needs DACL grants on the profile folders.
  - Process names are matched on the basename without `.exe`/`.cmd`.
  - Discovery runs no version probe for Kiro.
  - Antigravity requires its canonical path plus a digest.
- **macOS:**
  - Bundle binaries are read from `Info.plist`, never launched.
  - OpenHands native OTLP exists only on darwin.
- **Schema mismatch:** the `os.type` enum in `schemas/otel/resource.schema.json` lists only darwin and linux, but Windows emits `windows`. This is an existing mismatch.

## 4. Mistakes from this branch's history

- OpenCode shipped without a `normalizeConnectorTelemetrySource` entry, so its telemetry source was `unknown` (`f29b76ec` fixed it and added the test).
- The inventory connector switch left out several connectors; `79c67cc5` fixed it and added the parity tests.
- Status showed "Data path: DefenseClaw proxy" for hooks-only Kiro because the value came from a name list (fixed in `f05a9d3c`).
- Removing a connector (`e508ba54`) had to edit `internal/telemetry/normalization.go`, the `llm_event_emit.go` lifecycle lists, `internal/sensor/catalog`, `internal/sensor/tactics/agent.go`, `correlation*.go` and the schema lists. Adding one fans out the same way.

## 5. Gaps at the time of writing

- Kiro is missing from the Grafana `custom` lists, `hasNativeMCPReader` and `readMCPServersUnderHomeForOS`, `inventoryDACLDotdirs` (also missing: `.omnigent`, `.copilot`), `agentProcessPattern` (also missing: hermes, agy, omnigent), `TestNormalizeConnectorTelemetrySourceIncludesHookOnlyBuiltins`, `TestNativeTelemetryRegistryIsExplicit`, and `test/e2e/connectormatrix.go`.
- The Swift `friendlyConnectorName` has no Kiro case.
