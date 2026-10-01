# Docs, tests and CI

A new connector shows up in about 40 places across docs, tests and CI. About half are checked by tests that fail when an entry is missing. Nothing checks the other half, and Kiro, the most recent connector, is missing from many of them (§8).

## 0. Sources of truth and their checks

```
Go registry: internal/gateway/connector/registry.go newBuiltinConnectors
  |  count pinned by r.Len()-style checks (connector_test.go, correlation_test.go)
  +- docs-site/data/capability-matrix.json
  |    checked by internal/gateway/connector/docs_capability_matrix_test.go
  |    (TestDocsCapabilityMatrixMatchesConnectors); feeds ConnectorCatalog, CapabilityMatrix,
  |    HookEventsList, ConnectorBrand, the command generator and the home-page count
  +- test/e2e/connectormatrix.go connectorMatrix   (hand-kept; not tied to the registry)

Python: cli/defenseclaw/connector_paths.py KNOWN_CONNECTORS
  +- cli/tests/test_connector_surface_parity.py (quickstart, init, doctor, discovery, TUI,
  |    palette, status, guardrail labels)
  +- cli/defenseclaw/inventory/hook_contracts.json
  |    checked by test_connector_contracts.py test_manifest_covers_every_connector
  +- cli/defenseclaw/platform_support.py WINDOWS_CONNECTOR_SUPPORT <-> Go platform_support.go
       checked by test_platform_support.py (regex against Go, plus hard-coded sets) and
       test_windows_release_claims.py test_windows_release_metadata_is_exact (hard-coded sets)
       +- docs-site/content/docs/connectors/meta.json pages (minus index, compatibility)
       |    must equal the WINDOWS_CONNECTOR_SUPPORT keys
       +- each <id>.mdx "## Platform support" rows + connectors/index.mdx platform table
       |    checked by test_connector_pages_are_the_canonical_cross_platform_support_source
       +- scripts/install.ps1 $ConnectorChoices
            checked by test_windows_installer_tracks_supported_connectors
```

## 1. Docs

### Connector page: `docs-site/content/docs/connectors/<id>.mdx`

- **Frontmatter.** `title`, `description` and a `keywords:` list. The schema is in `docs-site/source.config.ts`.
- **Navigation.** The sidebar comes from `meta.json` files. `docs-site/content/docs/meta.json` already lists the `connectors` folder, so a new page needs only its id in `connectors/meta.json` (§2).
- **Section order.** Follow `copilot.mdx`, `claudecode.mdx`, `codex.mdx` or `hermes.mdx`:
  1. `## Platform support`
  2. `## Setup`, with `<Tabs items={['macOS / Linux', 'Windows']}>`
  3. `## Files DefenseClaw will modify`
  4. `## Hook capabilities`, with `<HookEventsList connector="<id>" />` and a `<Callout>` on native ask or the fallback
  5. `## Enterprise deployments`
  6. Telemetry
  7. `## Disable`
- **Platform table.** The exact form is regex-pinned:
  - `| macOS and Linux | **Supported** | ... |`
  - `| Native Windows x64 | **Supported|Preview|Not certified|Unsupported** | ... |`

  `## Platform support` must appear exactly once. "Supported — native degraded" is reserved for omnigent, and a test asserts that.
- **Claims that tests pin.** When a page states a version or a boundary, a pytest pins it to the source. Examples in `cli/tests/test_windows_release_claims.py`: `test_antigravity_windows_claims_match_official_hook_boundary`, `test_hermes_latest_source_recheck_matches_the_pinned_contract`. Add one for the new connector's pinned claims.
- **Commands.** Every `defenseclaw ...` command in a shell fence is parsed against the real Click tree by `scripts/check_docs_cli_commands.py` (run through `cli/tests/test_docs_cli_commands.py`). `defenseclaw-gateway ...` commands are parsed against Cobra by `internal/cli/docs_commands_test.go` `TestDocumentedGatewayCommandsParse`. So `defenseclaw setup <id>` must exist and its flags must be real. The checker reads connector choices from `cmd_setup._CONNECTOR_NAMES_FALLBACK`.

## 2. Docs data and components

| File | What to add | Checked by |
|---|---|---|
| `docs-site/content/docs/connectors/meta.json` | the page id in `pages` | `test_windows_release_claims._active_connector_docs` (must equal the Windows taxonomy) |
| `docs-site/data/capability-matrix.json` | a row with `id`, `label`, `windowsSupport`, `windowsNote`, `summary`, `family`, `toolInspection`, `subprocessPolicy`, `hooks{canBlock,canAskNative,askEvents,blockEvents,supportsFailClosed,scope}`, `hilt`, `notes`; bump `_lastVerified` | Go test: `family` (from `LLMTrafficModeForConnector`), `toolInspection` (`ToolModeBoth` is spelled `"pre-execution + response-scan"`), `subprocessPolicy`, and the exact `HookCapabilities()`. `docs-site/scripts/test-feature-demos.ts` checks that `windowsSupport` is present. **Nothing** cross-checks `windowsSupport` against `platform_support.go`. |
| `docs-site/data/connector-icons.ts` | LobeHub source, target and accent | `docs-site/scripts/sync-connector-icons.ts` runs at `postinstall`; commit `docs-site/public/connector-icons/<id>.svg` |
| `docs-site/components/connector-brand.tsx` `FALLBACKS` | initials and color when there is no LobeHub icon (zeptoclaw, omnigent) | nothing |
| `docs-site/lib/hero-connectors.ts` `TERMINAL_CONNECTORS` | id, label, setup command, modeId | nothing |
| `docs-site/content/docs/connectors/index.mdx` | frontmatter count and keywords, the Integration families card, a Platform support row (`\| [Label](/docs/connectors/<id>) \| **Supported** \| **<win>** \| ... \|`), a Capability summary row | the platform row is regex-pinned; the rest isn't |
| `docs-site/content/docs/connectors/compatibility.mdx` | a row per contract band: `\| <ConnectorLabel id="<id>" /> \| gate \| range \| contract / script gen \| AID surfaces \|` | only the codex and claude rows are pinned; add a pin |
| `docs/CONNECTOR-MATRIX.md` | **nothing.** It only points to the website (`test_connector_matrix_delegates_current_support_to_the_website`) | |

## 3. Pages that list every connector

No test checks these. Review each one. They are the pages that name most connectors today; for each, a sibling grep (`git grep -n -w Copilot -- <page>`) finds the lines to change.

| Area | Pages |
|---|---|
| Connectors | `connectors/index.mdx`, `connectors/compatibility.mdx`, `capability-matrix.mdx`, `command-generator.mdx`, `index.mdx` |
| Setup and guardrails | `get-started/quickstart.mdx`, `setup/index.mdx`, `setup/guardrail/index.mdx`, `setup/guardrail/disabling.mdx`, `setup/guardrail/aliases.mdx`, `setup/unified-llm-key.mdx`, `setup/semantic-routing.mdx` |
| Reference | `reference/cli.mdx`, `reference/configuration.mdx`, `reference/gateway-api.mdx`, `reference/env-vars.mdx` (generated) |
| Features | `ai-discovery.mdx`, `hitl.mdx`, `stories/hitl-approvals.mdx`, `llm-judge-benchmark.mdx`, `policies/cel/tool-call-state.mdx` |
| Windows | `get-started/windows/telemetry-security.mdx`, `get-started/windows/paths-troubleshooting.mdx` |
| Enterprise | `enterprise/index.mdx`, `concepts.mdx`, `machine-policy.mdx`, `foreign-hook-guard.mdx`, `threat-model.mdx`, `windows.mdx`, `rollout.mdx`, `enrollment.mdx`, `operations.mdx`, `troubleshooting.mdx` |
| Repository docs | `docs/ENTERPRISE-THREAT-MODEL.md`, `docs/LINUX-ENTERPRISE-THREAT-MODEL.md`, `docs/MACOS-ENTERPRISE-THREAT-MODEL.md`, `docs/WINDOWS-ENTERPRISE-THREAT-MODEL.md`, `docs/WINDOWS-NATIVE-INSTALLER.md`, `docs/WINDOWS-NATIVE-CI.md` |

All `docs-site` pages above are under `docs-site/content/docs/`.

- **CHANGELOG.** `CHANGELOG.md` gets a line when the change reaches users. Standalone-enterprise-only changes don't.
- **Retired names.** Never add a retired connector name anywhere except the allowlisted files named in `cli/tests/test_retired_connector_names.py`.
- **Generated docs.** `openwiki/` is generated. Don't edit it by hand.

## 4. Tests

### 4.1 Hard-coded lists in tests (edit by hand)

| Test | File |
|---|---|
| `TestHookContractsCoverHookEndpoints` | `internal/gateway/connector/hook_contract_test.go` |
| `TestSupportedConnectorsSorted`, `TestNativeConnectorEndpointMatrix`, `TestForeignHookBlockNamesTheFileInEveryConnectorsResponse` | `internal/gateway/connector/hookexec/hookexec_test.go` |
| `TestHookRegister_HasBuiltinFactories` | `internal/gateway/hook_register_test.go` |
| `TestHookProfile_HasDispatchCallbacks` | `internal/gateway/connector/hook_profile_dispatch_test.go` |
| `TestWindowsConnectorSupportTaxonomy` name lists | `internal/gateway/connector/platform_support_test.go` |
| registry counts (`r.Len() != 14`, `want 14`) | `connector_test.go`, `correlation_test.go` |
| `TestSupportedConnectorCountMatchesRegistry` (`const expected`) | `internal/inventory/connector_parity_test.go` |
| `TestEndpointConnectorComponentsWindowsExactNativeRoster` | `internal/gateway/inventory_events_test.go` |
| `TestPluginTransportsReportIdentityToo` (plugins only) | `internal/gateway/connector/hook_user_identity_test.go` |
| `TestNormalizeConnectorTelemetrySourceIncludesHookOnlyBuiltins` | `internal/gateway/otel_ingest_test.go` |
| `TestNativeTelemetryRegistryIsExplicit` | `internal/gateway/connector/correlation_test.go` |
| `WINDOWS_SUPPORTED` and the other sets | `cli/tests/test_platform_support.py` |
| `test_windows_release_metadata_is_exact` | `cli/tests/test_windows_release_claims.py` |
| `test_unix_contract_matrix_covers_executable_shell_hook_connectors` (`expected`) | `cli/tests/test_connector_live_e2e_path_policy.py` |
| `test_every_file_opened_was_declared` | `cli/tests/test_connector_paths.py` |
| `TEN_CONNECTORS` / exact roster | `cli/tests/test_cmd_setup_connector_readiness.py` |
| `wizardConnectorChoices` pin | `cmd/defenseclaw-setup/wizard_windows_test.go` |
| `TestWindowsStandalonePerUserConnectorMappings` (the managed-runtime names) | `internal/enterprisehooks/peruser_managed_windows_test.go` |

These hand-kept lists don't fail when a connector is missing, so nothing reminds you to add it. Add a row so the new connector is covered:

| Test | File |
|---|---|
| `TestPlatformHookContractsPreservePR655Bands` (every contract band per OS) | `internal/gateway/connector/hook_contract_test.go` |
| `TestLLMTrafficModeForConnector` | `internal/gateway/connector/llm_traffic_mode_test.go` |
| `TestSwitchConnector_PerConnectorPersistsState` | `internal/gateway/proxy_connector_parity_test.go` |
| `TestHookConnectorFromArgsAcceptsStandalonePerUserHookConnectors` (Windows standalone) | `internal/cli/hook_standalone_peruser_windows_test.go` |
| `test_calls_gateway_teardown_for_every_native_connector_receipt` | `cli/tests/test_cmd_doctor_residue.py` |
| `_CONNECTORS` and the label map | `cli/tests/test_cmd_guardrail_matrix.py` |
| `CONNECTORS` | `cli/tests/test_install_smoke.py` |

### 4.2 Tests that iterate the registry or a manifest (they fail until you finish)

- `TestHookContractsManifestMatchesRuntime`
- `TestHookProfileMatrix_AllCapabilityProvidersHaveProfile`
- `TestDocsCapabilityMatrixMatchesConnectors`
- `TestCorrelationContractSourcesAndFixturesAreImmutable`
- `TestBuiltinCorrelationProfilesAreVersionedAndValid`
- `TestConnectorRegistry_ScopeAndHookHandlerInSync`
- `TestHandleAgentHook_FullChain_PerConnector` (registry completeness)
- `TestSupportedConnectorParityMatrix`, `TestSupportedConnectorMCPOnEveryConnector`
- `test_manifest_covers_every_connector`, `test_connector_surface_parity.py`, `test_all_connector_lists_share_one_taxonomy`, `test_windows_taxonomy_matches_go_mirror_and_has_reasons`
- `test_packaged_catalog_is_byte_identical_to_go_authority`
- `test_status_friendly_names_cover_every_known_connector`
- `test_registry_manifest.py` (enum parity)
- `test_connector_pages_are_the_canonical_cross_platform_support_source`, `test_windows_installer_tracks_supported_connectors`
- `test_envvars_codebase_coverage.py`, `test_retired_connector_names.py`

### 4.3 Per-connector tests

The per-layer references list these. Keep the PR lean: add a row to an existing table test wherever one exists, and add a new test function only for behavior that no table covers (a decode shape, a Windows shell exit, a vendor-specific projection). Don't add broad sweeps or tests that pin incidental wording.

## 5. e2e matrix and goldens

- **`test/e2e/connectormatrix.go` `connectorMatrix`.** Add a `ConnectorFixture{Name, DestinationApp, ClawMode, Apply}`. `Apply` points the connector's `*PathOverride` / home override at a temporary directory, so the test never touches the real `$HOME`. The matrix is used by:
  - `TestConnectorLifecycle_Matrix` (`connector_lifecycle_matrix_test.go`);
  - `TestGoldenPerConnectorLayout` (`v7_golden_per_connector_layout_test.go`).

  `TestConnectorVerifyCleanOnFreshDataDir` (`test/e2e/connector_test.go`) doesn't use the matrix; it checks a hand-kept list of four connectors.

  On Windows, `connectorLifecycleMatrix` filters out the connectors that need protected-executable evidence. It pins that count (four today), so update it if the new connector needs protected evidence too.
- **v7 golden.** `test/e2e/testdata/v7/golden/<id>/verdict-blocked.golden.json`.
- **Registry check.** `test/e2e/connector_test.go` `TestRegistryBuiltinConnectors` checks only a minimum set.

## 6. Live E2E harness and CI

| File | What to add |
|---|---|
| `scripts/live-connector-e2e/run.sh` `ALL_CONNECTORS` | only for an executable shell-hook contract (plugins and policy bridges have their own gates) |
| `scripts/live-connector-e2e/golden/<id>/pre_tool_allow.json`, `pre_tool_block.json` (+ `_windows` variants) | stdin payloads fed to the installed entrypoint by `contract-smoke.sh`. Allow means exit 0; block means exit 2 or a block/deny decision. The block payload uses a command the shipped rules deny with complete typed proof; the harness never executes it. |
| `scripts/live-connector-e2e/lib/setup.sh` `dc_setup_subcommand`, `dc_connector_config_file` | the setup subcommand, and the vendor config file used by the teardown assertion |
| `scripts/live-connector-e2e/drivers/<id>.sh` | a Layer B live driver, only if the agent has a headless mode that fires hooks; contract-only connectors skip it |
| `.github/workflows/connector-live-e2e.yml` | the `workflow_dispatch` `connector` options, the `full=` matrix JSON, and live `include:` cells with connector-scoped secrets (`matrix.connector == '<id>' && secrets.X \|\| ''`) |
| `.github/workflows/windows-native.yml` + `scripts/windows-native-ci.ps1` `ValidateSet` | the native Windows connector matrix and any pinned-download admission step |
| `.github/workflows/macos-app.yml` | nothing per connector; it runs `macos/DefenseClawMac/script/test_connector_onboarding.sh`. The other macOS app parity scripts run only through `make macos-app-test` (cli-tui.md step 15). |
| `scripts/live-connector-e2e/run-windows.ps1`, `test-windows.ps1` | the Windows contract harness |

The workflows are pinned by these tests:
- `cli/tests/test_connector_live_e2e_path_policy.py`: the full-matrix set must equal `ALL_CONNECTORS` and the dispatch options, and the path allowlist is fixed.
- `test_connector_live_secret_scoping.py`: secrets are connector-scoped.
- `test_connector_live_package_provenance.py`.
- `test_live_connector_upgrade_harness.py`.
- `test_ci_workflow_efficiency.py`.
- `test_windows_release_claims.py`.

A green synthetic or contract CI job is **not** connector certification. Certify interactively on each OS you claim before you add a `validated_versions.json` row or a "Supported" claim (enterprise.md §10).

## 7. Validation commands

Run the narrowest set that proves the change, and keep the complete failure output. For a new connector, run:

```bash
# Go: contract, registry, runner, gateway, inventory, telemetry
go test -count=1 ./internal/gateway/connector/... -run 'HookContract|Registry|Platform|Correlation|NativeTelemetry|HookProfile|DocsCapability|Decision|ForeignHook|SupportedConnectors|NativeConnector'
go test -count=1 ./internal/gateway -run 'HookRegister|HandleAgentHook_FullChain|HookOutputFor|RuntimeAssetCanEnforce|ToolJudgeIntent|NormalizeConnectorTelemetrySource|EndpointConnectorComponents|ReadMCPServersUnderHome|ResolveWatcherDirs'
go test -count=1 ./internal/inventory -run 'TestSupportedConnector'
go test -count=1 ./internal/config -run 'ReadMCPServersForConnector|ConnectorHomeDir|SkillDirs|PluginDirs'
go test -count=1 ./internal/telemetry -run NormalizeHookEventTypeLabel
go test -count=1 ./internal/enterprisepolicy ./internal/enterprisehooks ./internal/cli -run 'Route|Guard|Standalone|Hook'
go test -count=1 ./test/e2e -run 'TestConnectorLifecycle_Matrix|TestGoldenPerConnectorLayout|TestConnectorVerifyCleanOnFreshDataDir'
GOOS=windows go vet ./internal/gateway/connector/... ./internal/enterprisehooks/... ./internal/enterprisepolicy/... ./internal/cli/... ./cmd/defenseclaw-setup/...

# Python: parity, paths, discovery, setup, TUI, docs, tripwire
pytest -q cli/tests/test_connector_surface_parity.py cli/tests/test_platform_support.py \
  cli/tests/test_connector_contracts.py cli/tests/test_connector_paths.py \
  cli/tests/test_connector_mcp_writers.py cli/tests/test_agent_discovery.py \
  cli/tests/test_ai_signatures.py cli/tests/test_registry_manifest.py cli/tests/test_check_schemas.py \
  cli/tests/test_windows_release_claims.py cli/tests/test_connector_live_e2e_path_policy.py \
  cli/tests/test_docs_cli_commands.py cli/tests/test_envvars_codebase_coverage.py \
  cli/tests/test_retired_connector_names.py

# Generators and schema checks
make check-schemas            # plus: make telemetry-check if the registry YAML changed
python scripts/gen_envvars_docs.py --check
make connector-matrix-test    # wider Go + Python connector matrix
```

**Also run, when they apply:**
- `make amp-plugin-typecheck` (plugin templates);
- `make cli-test-snap` (TUI snapshots);
- `make macos-app-test` on a Mac with Xcode, when the macOS app lists change (cli-tui.md step 15);
- `make check-grafana-dashboards`;
- the Secure Client invariance check, which maintainers run outside the repo (enterprise.md §9);
- the docs-site checks in `docs-site/` (`npm run test:feature-demos`, `npm run validate-links`, `npm run build`).

## 8. Gaps at the time of writing

- Kiro is missing from `test/e2e/connectormatrix.go` and has no v7 golden directory.
- Kiro is missing from `docs-site/lib/hero-connectors.ts`, and `kiro.mdx` has no `keywords`.
- The capability matrix `windowsSupport` field is not cross-checked against `platform_support.go`.
- Most "pages that list every connector" (§3) aren't checked. A test that asserts every `KNOWN_CONNECTORS` label appears in each of them would close this gap.
