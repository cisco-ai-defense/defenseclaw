# New connector checklist

Copy this into the PR description or a tracking issue, and replace `<id>` with the connector ID. Each line is one touch point, followed by what verifies it. **none** means no test catches a miss, so check it by hand. Lines that don't apply to your connector's kind should be marked N/A with a reason, not deleted.

Before starting, pick the closest sibling and list its footprint: `git grep -l -i -w <sibling> -- ':!openwiki'`.

## 0. Research
- [ ] Vendor event list with the exact wire casing, one captured stdin sample per event per OS. Verify: the decode tests use these samples.
- [ ] How the vendor reads the result (stdout JSON, exit 2, stderr), what it does on timeout or failure, and its hook ordering and merge rules. Verify: recorded in the contract `Notes`.
- [ ] Config paths per OS, the redirect env vars, the version command, and the MCP/skills/plugins/rules/agents locations. Verify: recorded in the contract `Notes` and in assets.
- [ ] Shell and exec tool names and their argument keys. Verify: the guardrail normalization test.
- [ ] Machine-policy source (if any), ACP support, native OTel. Verify: the route decision in enterprise.md §0.

## 1. Core (`internal/gateway/connector/`)
- [ ] ID is lowercase `[a-z0-9]+`. Verify: `hookAPITokenScopeRE`, `validNativeHookConnector`.
- [ ] Connector type and constructor implementing `Connector` plus the optional interfaces. Verify: `go build ./...`, `TestHookProfileMatrix_AllCapabilityProvidersHaveProfile`.
- [ ] `HookScriptOwner` or `HookConfigReferenceOwner` implemented. Verify: `OwnsManagedHookRuntime` is true (enterprise enumeration test).
- [ ] `newBuiltinConnectors` entry. Verify: registry count tests (`r.Len()`, `want`), `TestConnectorRegistry_ScopeAndHookHandlerInSync`.
- [ ] `windowsConnectorSupport` row with a reason. Verify: `TestWindowsConnectorSupportTaxonomy`, `test_windows_taxonomy_matches_go_mirror_and_has_reasons`.
- [ ] `builtinHookContracts["<id>"]`: one `DefaultForUnversioned`, the right `ResponseFieldName`, BlockEvents and AskEvents in the contract. Verify: `TestHookContractsCoverHookEndpoints`, `TestApplyHookContractPinsProfileCapabilities`.
- [ ] Per-OS pins in `hookContractsForOS`, mirrored in the JSON `platform_overrides`. Verify: `TestHookContractsManifestMatchesRuntime`.
- [ ] `cli/defenseclaw/inventory/hook_contracts.json` entry. Verify: `TestHookContractsManifestMatchesRuntime`, `test_manifest_covers_every_connector`.
- [ ] `HookScriptVersion` equals the template marker (`# defenseclaw-managed-hook vN` / `// defenseclaw-managed-plugin vN` / `# defenseclaw-managed-policy vN`). Verify: **none**; compare by hand.
- [ ] Marker literals in verify, doctor and CI code updated whenever a marker changes (core.md §12). Verify: `git grep -n 'defenseclaw-managed-' -- ':!internal/gateway/connector/hooks'`.
- [ ] Contract bands added to `TestPlatformHookContractsPreservePR655Bands`. Verify: that test (it doesn't fail when the connector is missing).
- [ ] `<id>ToolCallLifecycle()`. Verify: `ValidateToolCallLifecycleContract`, `TestToolCallLifecycleRuntimeHelpers`.
- [ ] `CorrelationProfile<Id>V1` and the `CorrelationSpecForConnector` case, with the contract ID matching exactly. Verify: `TestBuiltinCorrelationProfilesAreVersionedAndValid`, `TestHookLifecycleBindingsUseOnlyReviewedContractEvents`.
- [ ] `correlationContractSources` entry (immutable revision, fixture sha256). Verify: `TestCorrelationContractSourcesAndFixturesAreImmutable`.
- [ ] `nativeTelemetryForConnector` / `mirrorIdentityTargets` / `declaredCorrelationAliases` where they apply. Verify: `TestNativeTelemetryRegistryIsExplicit`.
- [ ] `HookProfile` Decode, DecodeToolArgs, MapVerdict, Respond; `hookOnlyProfileRespond` case; `hookOnlyConnector.HookProfile` name case. Verify: `TestHookProfile_HasDispatchCallbacks`, Respond parity tests, decode tests with real payloads.
- [ ] Template `hooks/<id>-hook.sh` (or plugin, or `.ps1` adapter) and `connectorHookScripts["<id>"]`. Verify: a script exit test under bash (`TestOpenHandsHookScript_BlockExitsTwo` pattern), `hook_user_identity_test.go`.
- [ ] `hookexec` `specs["<id>"]` (style, outputField, failOpenOnly). Verify: `TestSupportedConnectorsSorted`, `TestNativeConnectorEndpointMatrix`, `TestDecisionGolden`.
- [ ] `hookexec` branches: event validation, `hookRequestTimeout` (below the timeout registered in the vendor config), `failForeignHookBlocked`, `emitHookResult`, `hookDialects`. Verify: `TestForeignHookBlockNamesTheFileInEveryConnectorsResponse`.
- [ ] `foreignHookStopEvent` has the exact-case stop and session-end events. Verify: a row in `TestManagedSessionStopEventsAllowWhileOtherEventsStayBlocked` (`hookexec/session_stop_test.go`).
- [ ] Every rendered argument exists on `defenseclaw-hook hook`; no positional arguments. Verify: an end-to-end rendered-command test (`TestKiroHookCommandRunsAndForwardsItsSurface` pattern, `hook_kiro_test.go`).
- [ ] `hookFailureExitCode`, if the vendor ignores exit 1. Verify: `TestHookPreRunFailureUsesTheConnectorsBlockingExit`.
- [ ] `hookInvocationCommandFor` Windows branch (encoded bridge, adapter, bash-quoted exe, or unsupported). Verify: a Windows shell test run through the host's real shell (`kiro_windows_shell_test.go` pattern).
- [ ] `ownedHookCommandNeedlesFor` for per-event commands. Verify: `hook_config_paths_test.go`.
- [ ] `managedNativeHookRuntimeConnector` / `protectedSetupSelectionConnectorForOS` if they apply. Verify: connector tests.
- [ ] Setup is idempotent, backs up before editing, and patches only owned entries. Verify: the setup round-trip test.
- [ ] Teardown recognizes every rendered command form, restores the pristine file, writes a tombstone if needed, and clears the lock entry. Verify: a row in `TestHookTeardownDoesNotCreateAMissingAgentConfig` (`hook_teardown_absent_config_test.go`).
- [ ] Fail mode is resolved correctly and persisted as `DEFENSECLAW_FAIL_MODE_<ID>`. Verify: fail-mode tests (`TestResponseFailure`, `TestUnreachable`, `TestMissingToken`).

## 2. Gateway and guardrails (`internal/gateway/`)
- [ ] `hook_register.go` `init()` list and the `api.go` fallback route list. Verify: `TestHookRegister_HasBuiltinFactories`.
- [ ] Trusted event header in `handleAgentHook`, if stdin lacks the event. Verify: an `agent_hook_*_test.go` case.
- [ ] Pre-tool event routes as structured-action (exact spelling), or is in `isGenericToolInspectionEvent`. Verify: `TestHandleAgentHook_FullChain_PerConnector` row (`expectAction=block`).
- [ ] New event spellings in `isPromptLikeEvent`, `isResultLikeEvent`, `isToolJudgeIntentEvent`, `isToolJudgeSessionBoundaryEvent`. Verify: `TestToolJudgeIntentEventsCoverConnectorTurnStarts`, `TestRuntimeAssetCanEnforce_HookOnlyEvents`.
- [ ] Shell tool name in every shell table (`dialect.go`, `argsExecutionTool`, `exactShellExecutionTool` / closed schema, `trustedBashExecutionTool`, `windowsCommandText`, `agentHookTrustedActionTool`, `isTerminalTool`). Verify: a normalization test asserting authoritative facts and a block.
- [ ] Vendor metadata keys projected away (`Decode`/`DecodeToolArgs` or `agentHookTrustedActionArgs`). Verify: the same test, plus "other shapes unchanged".
- [ ] File and write tool names (`lookupToolArgumentSemantics`, `isWriteToolName`). Verify: actionfacts and CodeGuard tests.
- [ ] MCP identity (`mcp_server_name` or `mcp__srv__tool`). Verify: an asset-policy runtime test.
- [ ] Legacy `hookOutputFor` in parity, or unused. Verify: `TestHookOutputFor_AllConnectors_AllActions`.
- [ ] Per-connector mode, HILT and disable. Verify: `TestAgentHookMode_HonorsPerConnectorOverride`, `TestAgentHookEnabled_PerConnectorDisableShortCircuits`.

## 3. Assets
- [ ] `Capabilities` for all five surfaces (supported, discovery-only or `unsupportedSurface`). Verify: a layout test (`hook_only_test.go` pattern).
- [ ] `ComponentScanner` implemented or inherited. Verify: rows in `TestResolveWatcherDirs_PerConnectorMatrix` / `TestResolveWatcherDirs_HookOnlyConnectorMatrix`.
- [ ] Watcher doesn't create other agents' roots. Verify: a "does not create foreign roots" case.
- [ ] `claw.go`: `ReadMCPServersForConnector`, `ConnectorHomeDir`, `SkillDirsForConnector`, `PluginDirsForConnector` explicit arms. Verify: `claw_test.go` "never reads OpenClaw" case.
- [ ] `hasNativeMCPReader` and `readMCPServersUnderHomeForOS` (per OS). Verify: `TestReadMCPServersUnderHomeUsesCanonicalUserConfigs`.
- [ ] `connector_paths.py`: `KNOWN_CONNECTORS`, `HOOK_ONLY_CONNECTORS` and every dispatcher. Verify: `test_<id>_resolves_its_own_surfaces_not_openclaw`.
- [ ] `mcp_source_locations` lists every file `mcp_servers` opens. Verify: `test_every_file_opened_was_declared` (add the name).
- [ ] `set_mcp_server` / `unset_mcp_server`, or `MCPWriteUnsupportedError`. Verify: `test_connector_mcp_writers.py`.
- [ ] AIBOM limitations notes and `_collect_mcp_config_files`. Verify: `test_claw_inventory.py`.
- [ ] Plugin manifest in `_MANIFEST_CANDIDATES`, `STANDARD_MANIFEST_DIRS` and `_PLUGIN_MANIFEST_FILES`, if new. Verify: `test_plugin_directories.py`.
- [ ] Bridge self-identity digests and dynamic lines, plus a row in the fingerprint test's `parametrize` list; policy first-party markers (4 files + `fallback.go`). Verify: `test_bridge_template_fingerprints_match_gateway_sources`.
- [ ] `registries/manifest.py` and the `schemas/registry-manifest.schema.json` enums. Verify: `test_registry_manifest.py`.

## 4. Discovery and observability
- [ ] `internal/inventory/ai_signatures.json` entry, copied byte for byte to the `cli/` copy. Verify: `TestSupportedConnectorParityMatrix`, `TestSupportedConnectorMCPOnEveryConnector`, `test_packaged_catalog_is_byte_identical_to_go_authority`.
- [ ] `TestSupportedConnectorCountMatchesRegistry` `expected` bumped. Verify: that test.
- [ ] `agent_discovery.py` `DISCOVERY_PRECEDENCE`, `_SPECS`, and `_scan_agent` if needed. Verify: `test_agent_discovery.py` rows, `test_agent_discovery_covers_every_active_connector`.
- [ ] `agentProcessPattern`, `vendorCategories`. Verify: `TestIsAgentProcessMatchesKnownAgentsOnly`.
- [ ] `inventoryDACLDotdirs` (Windows managed). Verify: **none**; check by hand.
- [ ] `schemas/otel/resource.schema.json` claw mode and `EXPECTED_CLAW_MODE_ENUM`. Verify: `make check-schemas`, `test_check_schemas.py`.
- [ ] `connector-telemetry-event.schema.json` and `metrics.schema.json` connector lists. Verify: **none**; update by hand.
- [ ] `normalizeConnectorTelemetrySource`. Verify: `TestNormalizeConnectorTelemetrySourceIncludesHookOnlyBuiltins` (add the name).
- [ ] `NormalizeHookEventTypeLabel`, `canonicalHookLifecycleEvent`, `isPromptClassHookEvent`, `normalizeHookEventLabel`. Verify: `model_label_normalize_test.go`, lifecycle tests.
- [ ] Native OTLP: `NativeOTLPSpec`, `OTLPScope<X>`, the registry YAML `binding_classes`, `connectorModeFor`. Verify: `native_otlp_golden_test.go`, `otlp_token_test.go`, `make telemetry-check`.
- [ ] Plugin identity headers. Verify: `TestPluginTransportsReportIdentityToo` (add the plugin).
- [ ] Display names in `status.go`, `cmd_status.py` and `Models.swift`. Verify: `test_status_friendly_names_cover_every_known_connector` (Python only).
- [ ] Doctor tables (`_CONNECTOR_LABELS` plus the unpinned ones). Verify: surface parity (labels only); the rest by hand.
- [ ] Grafana `custom` connector lists. Verify: **none**; update by hand.
- [ ] Endpoint inventory roster. Verify: `TestEndpointConnectorComponentsWindowsExactNativeRoster`.

## 5. CLI, TUI and installers
- [ ] `cmd_setup.py`: `_CONNECTOR_NAMES_FALLBACK`, `_CONNECTOR_META`, `_CONNECTOR_CHANGE_SURFACES`, `_HOOK_ENFORCED_CONNECTORS`, the setup loop. Verify: `test_all_connector_lists_share_one_taxonomy`, `test_docs_cli_commands.py`.
- [ ] `cmd_setup.py` branches: banner, summary, prompt, alias validation, `_hilt_support_note`, upgrade guidance, version check. Verify: `test_cmd_setup_connector_readiness.py`.
- [ ] `config_home_connectors` equals the Go `bindConnectorLifecycleConfigHome` cases. Verify: **none**; compare by hand.
- [ ] `cmd_init.py` and `cmd_quickstart.py` choices; `bootstrap._connector_readiness` arm. Verify: `test_connector_surface_parity.py`, `test_cmd_init.py`.
- [ ] `doctor_hooks.py` `_EXPECTED_CONTRACTS`, event tuples, Windows argv checks; `fail_mode.py` tables. Verify: `test_cmd_doctor_connector.py` (Windows doctor test pattern).
- [ ] `cmd_guardrail.py` labels and runtime fail-mode set. Verify: surface parity.
- [ ] `credentials._HOOK_POLICY_ONLY_CONNECTORS`. Verify: **none**; check by hand.
- [ ] `cmd_uninstall._CONNECTOR_BACKUP_MARKERS`, `_CONNECTOR_RESIDUE_ARTIFACTS`, `windows_native_uninstall.py` allowlist. Verify: `test_cmd_uninstall.py`.
- [ ] TUI: `cli_choices.CONNECTORS`, `MODE_PICKER_CHOICES`, `_SETUP_CONNECTOR_ALIASES`, `GO_PARITY_REGISTRY`, `_connector_setup_alias`, `first_run.CONNECTOR_CHOICES`, `overview_state` / `catalog_state` labels. Verify: `tui/test_mode_picker.py`, `test_setup_panel.py`, `test_tui_label_maps_have_explicit_brand_cases`, `make cli-test-snap`.
- [ ] Go CLI: `connector_cmd.go` reconcile allowlist and config-home case; `status.go` `friendlyConnectorName`. Verify: `connector_cmd_test.go`, `status_connectors_test.go`.
- [ ] `scripts/install.sh` `CONNECTOR_CHOICES`, `scripts/install.ps1` `$ConnectorChoices`. Verify: `test_windows_installer_tracks_supported_connectors`.
- [ ] Windows native Setup: `nativeLifecycleConnectorNames`, `normalizeConnector`, `wizardConnectorChoices`, transaction home resolution, `platform_windows.go` vendor home and executable, executable admission if Setup pins it, `nativeinstallstate`. Verify: `wizard_windows_test.go`, `main_test.go`, `transaction_test.go`.
- [ ] macOS app lists (`AppState.swift`, `SetupDefinitions.swift`, `FirstRunView.swift`, `ConfigEditorDefinitions.swift`, `CommandRegistry.swift`, `Models.swift`, `SkillScanner.swift`). Verify: `make macos-app-test` on a Mac (CI runs only the onboarding script).
- [ ] `internal/envvars/registry.json` entries for new `DEFENSECLAW_*` variables. Verify: `test_envvars_codebase_coverage.py`, `python scripts/gen_envvars_docs.py --check`.

## 6. Enterprise
- [ ] `RouteFor` case for each OS. Verify: a `TestKiroRouteFollowsItsEnrollment`-style test.
- [ ] Machine-policy `Target`, `targets` map, `paths.go`, `presence.go`, `machinePolicyDirs`, if machine policy. Verify: `TestPublishVerifyRemoveAll`, target tests.
- [ ] Exactly one of `guardConnectors`, `unixGuardConnectors` or `lockConnectors`, or none (with a threat-model residual). Verify: `TestPublicPolicyGuardFlags`.
- [ ] `connectorSources` (all user and project files, env redirects, Claude-format files); format scanner and cleanup if new. Verify: a source-coverage test, `TestCleanupRemovesUserForeignHooksAndBacksUp`.
- [ ] Owned command forms (4 and 6 args) and `ownedPluginPath`. Verify: `TestGuardHonorsPerUserOwnedCommandsOnlyOnPerUserRoute`.
- [ ] `standaloneForeignHookGuardBinary`, `foreignHookGuardedEvent`, session start, session keys, cwd keys. Verify: `TestStandaloneForeignHookGuardBinaryOnlyForStandalonePlugins`, the "each agent's session id" rows of `TestForeignHookGuardBlocksTheSessionOnlyForAHookPresentAtStart`.
- [ ] Guarded runtime runs the admin binary (or `--foreign-hook-check`), never a user-writable script. Verify: `installer_foreign_guard_test.go` pattern.
- [ ] `unixAgentProbes` entry and app-bundle binary. Verify: `agent_version_unix_test.go`.
- [ ] First-install stub or `standaloneOwnedHookConfigConnectors`. Verify: a row in `TestStandaloneVerifyFollowsModeSwitchesInOneHome`.
- [ ] Not-gated floor, if not gated. Verify: `installer_kiro_unix_test.go` pattern.
- [ ] Worker protocol carries every new `SetupOpts` / `InstallOptions` field. Verify: a worker round-trip test.
- [ ] Windows lists: `windowsStandalonePerUserConnectors`, `windowsStandaloneInAgentPluginConnector`, `windowsStandaloneRuntimeOnlyConnectors`, `windowsEnterpriseRefusedConnectors`, `WindowsStandalonePerUserConnectorNames`. Verify: `TestWindowsStandalonePerUserConnectorMappings` (its managed-runtime name list); the runtime kinds and refusal reasons **none**, so check them by hand.
- [ ] `ResolveWindowsManagedHookRuntime`, the generation selector, `parseWindowsManagedRuntimeBundleLeaf`, `windowsStandalonePerUserHookConnector`. Verify: `managed_runtime_generation_windows_test.go`, `GOOS=windows go vet`.
- [ ] Windows version discovery (both npm maps, native installers, WinGet). Verify: a row in `TestDiscoverWindowsStandalonePerUserAgentVersions`.
- [ ] Admission executable image and platform minimum. Verify: `peruser_admission_windows_test.go`.
- [ ] psm1 standalone `$teardownConnectors` line only. Verify: `test_windows_enterprise_standalone_contract.py`, plus the Secure Client invariance check that maintainers run outside the repo (enterprise.md §9).
- [ ] ACP catalog entry and Windows refusal reason, if ACP. Verify: the `check_acp_inventory_instances` step of `make check-schemas`.
- [ ] Secure Client lists, floors and templates unchanged. Verify: the in-repo pins in enterprise.md §9; maintainers run the full Secure Client invariance check outside the repo.
- [ ] Threat-model rows (B11, B12, R1, R15, R18, R19, R24, R25; the per-OS L, M and W rows). Verify: **none**; review by hand.

## 7. Docs
- [ ] `docs-site/content/docs/connectors/<id>.mdx` with one `## Platform support` in the exact table form. Verify: `test_connector_pages_are_the_canonical_cross_platform_support_source`.
- [ ] `connectors/meta.json` page. Verify: the same test.
- [ ] `connectors/index.mdx` platform row, families card, capability summary, count. Verify: platform row only (the same test).
- [ ] `connectors/compatibility.mdx` rows, plus a pin test. Verify: the new pin.
- [ ] `docs-site/data/capability-matrix.json` row (`windowsSupport` matching platform support). Verify: `TestDocsCapabilityMatrixMatchesConnectors`, `npm run test:feature-demos`.
- [ ] `connector-icons.ts` plus the committed SVG, or `connector-brand.tsx` `FALLBACKS`; `hero-connectors.ts`. Verify: **none**; check the rendered site.
- [ ] Pages that list every connector (docs-tests-ci.md §3). Verify: **none**; use a sibling grep.
- [ ] Enterprise docs (machine-policy routes, paths, writers; guard; troubleshooting). Verify: **none**; review by hand.
- [ ] Every documented command parses. Verify: `test_docs_cli_commands.py`, `TestDocumentedGatewayCommandsParse`.
- [ ] CHANGELOG line, if users are affected. Verify: review.
- [ ] No retired names anywhere. Verify: `test_retired_connector_names.py`.

## 8. Tests and CI
- [ ] Hard-coded test lists updated, including the hand-kept tables that don't fail when a connector is missing (docs-tests-ci.md §4.1). Verify: the listed tests.
- [ ] `test/e2e/connectormatrix.go` row and the `testdata/v7/golden/<id>/verdict-blocked.golden.json`. Verify: `TestConnectorLifecycle_Matrix`, `TestGoldenPerConnectorLayout`.
- [ ] Live harness: `run.sh` `ALL_CONNECTORS` (shell hooks), `golden/<id>/*`, `lib/setup.sh`, and a driver if the agent is headless. Verify: `bash scripts/live-connector-e2e/run.sh --layer contract --connector <id>`.
- [ ] `connector-live-e2e.yml` dispatch options, `full=` matrix, secret scoping; `windows-native.yml` matrix and `windows-native-ci.ps1` `ValidateSet`. Verify: `test_connector_live_e2e_path_policy.py`, `test_connector_live_secret_scoping.py`.
- [ ] Windows `_test.go` files compile. Verify: `GOOS=windows go vet ./...` on the touched packages.
- [ ] Narrow validation set passes. Verify: docs-tests-ci.md §7.
- [ ] Interactive live certification on each claimed OS, then a `validated_versions.json` row. Verify: a person, after a green run.
