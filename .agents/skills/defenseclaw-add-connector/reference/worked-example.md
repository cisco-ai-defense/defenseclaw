# Worked example: GitHub Copilot CLI, traced end to end

Copilot is the most complete connector on this branch. It uses:
- a per-event command hook, with the event bound outside stdin;
- a Unix shell script, plus a Windows PowerShell adapter;
- native ask;
- a fail-open vendor with a fail-closed managed override;
- a vendor machine-policy route on every OS, plus a per-user runtime row on Windows;
- the foreign-hook guard;
- MCP, skills and agents surfaces;
- discovery, telemetry and correlation;
- a CLI setup, TUI rows, installer rows, docs and a CI matrix.

This page lists every file, in the order you would write them for a connector like it. Reproduce the list with:

```bash
git grep -l -i -w copilot -- ':!openwiki' ':!docs/research' ':!CHANGELOG.md'
```

## 0. Vendor research

Record these, with the source for each, in the contract `Notes` and in the correlation provenance:
- **Events.** The camelCase events: `sessionStart`, `sessionEnd`, `userPromptSubmitted`, `userPromptTransformed` (current contract only), `preToolUse`, `postToolUse`, `permissionRequest`, `agentStop`, `subagentStart`, `subagentStop`, `postToolUseFailure`, `errorOccurred`, `preCompact`, `notification`.
- **Stdin.** The event name is **not** in stdin, so it has to be bound outside it.
- **Tool arguments.** `toolArgs` is a JSON string.
- **Native ask.** Only on `preToolUse`.
- **Blocking.** Only through JSON. Copilot treats a command hook timeout or failure as allow.
- **Config.** `~/.copilot/` (moved by `COPILOT_HOME`), the workspace `.github/hooks/`, and the machine `policy.d`.
- **Version probe.** `copilot --version`, from the npm package `@github/copilot`.

## 1. Connector core (`internal/gateway/connector/`)

1. `hook_only.go`:
   - the constructor (`name: "copilot"`), with `HookScriptNames` adding `copilot-hook.ps1` on Windows;
   - `copilotProfileDecode`, which parses the string `toolArgs`;
   - the paths: `copilotHooksPath`, `copilotSettingsPaths`, `copilotSkillReadPaths`, `copilotAgentReadPaths`, `copilotMCPReadPaths`, `copilotInstructionReadPaths`, `copilotWorkspaceAncestors`, `copilotHomePath`;
   - the per-event command, `copilotHookInvocationCommandForEvent`;
   - teardown emptiness, `copilotHooksDocumentEmpty`;
   - the `case "copilot"` in `Capabilities`.
2. `registry.go` `newBuiltinConnectors`.
3. `platform_support.go` `windowsConnectorSupport["copilot"]`: `PlatformSupported`, with a reason.
4. `hook_contract.go`:
   - the event lists `copilotLegacyHookEvents` and `copilotCurrentHookEvents`;
   - `ValidCopilotHookEvent`;
   - `builtinHookContracts["copilot"]`, with two bands: `copilot-hooks-v1` (min 1.0.18, max 1.0.76, exclusive) and `copilot-hooks-v2` (min 1.0.76, `DefaultForUnversioned`). Both use `HookScriptVersion: "v7"`, `ResponseFieldName: "hook_output"`, AskEvents `preToolUse`, BlockEvents `preToolUse`, `permissionRequest`, `agentStop` and `subagentStop`, `SupportsFailClosed: false`, and scope `user,workspace`.
5. `cli/defenseclaw/inventory/hook_contracts.json` `connectors.copilot`: `kind: hook`, `compatibility_gate: hook-contract`, `version_probe: "copilot --version"`, and the same two contracts.
6. `tool_call_lifecycle.go` `copilotToolCallLifecycle`.
7. `correlation.go`: `CorrelationProfileCopilotV1` (`copilot-correlation-v1`) and the `case "copilot"` in `CorrelationSpecForConnector`. Add the matching `correlation_provenance.go` source entry.
8. `hook_only_profile.go`: `copilotHookOutputForProfile`, plus the `hookOnlyProfileRespond` case. Preview it as preToolUse `permissionDecision=deny|ask`, permissionRequest `behavior=deny`, and stop `decision=block`.
9. The templates, with `subprocess.go` `connectorHookScripts["copilot"] = {"copilot-hook.sh"}`:
   - `hooks/copilot-hook.sh`, marker `# defenseclaw-managed-hook v7`;
   - `hooks/copilot-hook.ps1`, marker v7, which uses a `ProcessStartInfo` byte stream and fails open.
10. `hookexec/spec.go` `specs["copilot"]`: `style: styleHookEcho`, `failOpenOnly: true`, and endpoint `/api/v1/copilot/hook`.
11. The `hookexec/hookexec.go` branches:
    - `validCopilotEvent` requires a reviewed event;
    - `hookRequestTimeout` allows 29 s;
    - `managedCopilotFailClosed` makes managed Copilot fail closed despite `failOpenOnly`;
    - `failForeignHookBlocked` and `emitHookResult` produce the event-native bodies;
    - `foreignHookStopEvent` handles the stop events.
12. `helpers.go` `hookInvocationCommandFor`. On Windows it returns `windowsCopilotPowerShellAdapterCommand`: the `.ps1` adapter with `-Event '<e>'`, not the encoded bridge, because `Start-Process` doesn't preserve redirected stdin reliably.
13. `hook_config_paths.go` `ownedHookCommandNeedlesFor`: owned commands differ per event.
14. `subprocess.go` `managedNativeHookRuntimeConnector`: Copilot has a Windows machine-policy runtime.
15. `managed_policy_exports.go` `PerUserOwnedHookCommands`, for the guard's ownership check.

## 2. Gateway and guardrails (`internal/gateway/`)

1. `hook_register.go` `init()` list, plus the `api.go` fallback list.
2. `agent_hook.go` `handleAgentHook` requires and validates `X-DefenseClaw-Copilot-Event`, because stdin lacks the event.
3. `agent_hook.go` `agentHookTrustedActionTool` maps Copilot's `powershell` tool to `shell` on Windows (`77d215a8`), so that `chooseRawCommandDialect` picks PowerShell.
4. `asset_policy_runtime.go`: MCP identity comes from the tool naming.
5. `otel_ingest.go` `normalizeConnectorTelemetrySource`; `llm_event_emit.go` lifecycle mapping; `inventory_events.go` `hasNativeMCPReader` plus the `readMCPServersUnderHomeForOS` case.
6. `unified_hook_dispatch.go`, `raw_dedupe.go`, `hook_trace_v6.go`, `sidecar.go`: these generic paths name Copilot only in comments and need no per-connector code. The watcher gets its directories from `ComponentTargets`.

## 3. Assets

1. **Go.** `internal/config/claw.go`: the Copilot arms of `ReadMCPServersForConnector`, `ConnectorHomeDir`, `SkillDirsForConnector` and `PluginDirsForConnector`. Copilot plugins are command-backed, with no directories.
2. **Python paths.** `cli/defenseclaw/connector_paths.py`:
   - `copilot_home`;
   - `copilot_settings_paths`, `copilot_settings_resolution`;
   - `_copilot_skill_dirs`, `_copilot_custom_skill_dirs`;
   - `copilot_agent_dirs`;
   - `copilot_mcp_config_files`, `_copilot_mcp_servers`;
   - `copilot_instruction_paths`, `_copilot_workspace_ancestors`;
   - plus the `KNOWN_CONNECTORS` entry.
3. **Python inventory and skills.** `cli/defenseclaw/inventory/claw_inventory.py` has the Copilot MCP filter in `_collect_mcp_config_files`. `cli/defenseclaw/skill_discovery.py` handles Copilot commands. `cli/defenseclaw/codeguard_skill.py` handles the CodeGuard install target.
4. **Plugins.** `cli/defenseclaw/commands/cmd_plugin.py`: `_list_copilot_plugins` runs the trusted Copilot binary (`_trusted_copilot_binary`) instead of reading directories.

## 4. Discovery and observability

1. `internal/inventory/ai_signatures.json`: the entry with `id: "copilot"` and `supported_connector: "copilot"` (binary `copilot`). Copy it byte for byte to `cli/defenseclaw/inventory/ai_signatures.json`.
2. `cli/defenseclaw/inventory/agent_discovery.py` `_SPECS["copilot"]`:
   - config candidates `~/.copilot/mcp-config.json`, `.github/hooks/defenseclaw.json`, `.github/mcp.json` and `.mcp.json`;
   - binary `copilot`;
   - `--version`.
3. The sensor: `internal/sensor/tactics/agent.go` `agentProcessPattern`, `internal/sensor/tactics/indicators.go` (the `/.config/github-copilot/` config-path indicator), and `internal/sensor/catalog/catalog.go` `vendorCategories`.
4. `internal/agentprocess/agentprocess.go`: agent process identity, used by the guard session state. It is generic; Copilot appears only in a comment.
5. The schemas:
   - `schemas/otel/resource.schema.json`, `schemas/otel/metrics.schema.json`, `schemas/otel/connector-telemetry-event.schema.json`;
   - `schemas/registry-manifest.schema.json`, `schemas/telemetry/v8/genai.yaml`;
   - `scripts/check_schemas.py` `EXPECTED_CLAW_MODE_ENUM`.
6. The Grafana dashboards `bundles/local_observability_stack/grafana/dashboards/defenseclaw-{agent-identity,connector-detail,connectors,hitl,security}.json`.
7. `internal/cli/status.go` `friendlyConnectorName`; `cli/defenseclaw/commands/cmd_status.py` `_FRIENDLY_CONNECTOR_NAMES`; and the macOS app (`Models.swift`, `CommandRegistry.swift`, `SetupDefinitions.swift`, `FirstRunView.swift`, `ConfigEditorDefinitions.swift`, `SkillScanner.swift`, `AppState.swift`).

## 5. CLI, TUI and installers

1. **Setup.** `cli/defenseclaw/commands/cmd_setup.py`: `_CONNECTOR_NAMES_FALLBACK`, `_CONNECTOR_META`, `_CONNECTOR_CHANGE_SURFACES`, `_HOOK_ENFORCED_CONNECTORS`, and the observability setup loop. `defenseclaw setup copilot` comes from the shared factory.
2. **Onboarding.** `cmd_init.py` (the `--connector` choice plus the hidden `--native-setup-copilot`), `cmd_quickstart.py` and `bootstrap.py`.
3. **Doctor.** `cmd_doctor.py`: labels, markers, hook health, residue. `doctor_hooks.py`: `_EXPECTED_CONTRACTS`, `_COPILOT_CONTRACT_EVENTS`, and the exact Windows argv checks.
4. **Fail mode.** `fail_mode.py`: Copilot is in `_UPSTREAM_FAIL_OPEN_CONNECTORS` and `_EXPECTED_CONTRACTS`. `cmd_guardrail.py` has the labels. `credentials.py` has `_HOOK_POLICY_ONLY_CONNECTORS`.
5. **Uninstall.** `cmd_uninstall.py` `_CONNECTOR_BACKUP_MARKERS` (`connector_backups/copilot/config.json`) and `windows_native_uninstall.py`.
6. **Platform support.** `platform_support.py` `WINDOWS_CONNECTOR_SUPPORT["copilot"]`.
7. **Registries.** `registries/manifest.py` `KNOWN_CONNECTORS`.
8. **TUI:**
   - `tui/services/cli_choices.py` `CONNECTORS`;
   - `tui/screens/mode_picker.py` `MODE_PICKER_CHOICES`;
   - `tui/registry.py` and `tui/registry_data.py` (`GO_PARITY_REGISTRY` row `setup copilot`);
   - `tui/panels/setup.py`, `tui/panels/first_run.py`;
   - `tui/services/overview_state.py`, `tui/services/catalog_state.py`.
9. **Go CLI.** `internal/cli/connector_cmd.go` (reconcile allowlist, `bindConnectorLifecycleConfigHome` for `COPILOT_HOME`) and `connector_deferred_verify.go`.
10. **Installers:**
    - `scripts/install.sh` `CONNECTOR_CHOICES`;
    - `scripts/install.ps1` `$ConnectorChoices`;
    - `cmd/defenseclaw-setup/main.go`: `nativeLifecycleConnectorNames`, `normalizeConnector` (accepts `githubcopilot`, `github-copilot`), and the backup detection for `connector_backups/copilot/config.json`;
    - `cmd/defenseclaw-setup/wizard_windows.go` `wizardConnectorChoices` ("GitHub Copilot CLI");
    - `cmd/defenseclaw-setup/transaction.go` (`resolvePreviousConnectorHome` for the Copilot home);
    - `cmd/defenseclaw-setup/connector_reconciliation.go`;
    - `internal/nativeinstallstate/state.go` (`CopilotHome` / `COPILOT_HOME`).
11. **Env vars.** Add any `DEFENSECLAW_*` variables to `internal/envvars/registry.json`.

## 6. Enterprise managed mode

1. `internal/enterprisepolicy/types.go`: `ConnectorCopilot`, the `targets` map entry `copilotTarget{}`, and `RouteFor` returning `RouteMachinePolicy`.
2. `internal/enterprisepolicy/copilot.go` `copilotTarget`, which implements `Name`, `Paths`, `Reconcile`, `Verify`, `RemoveOwned` and `Export`. `internal/enterprisepolicy/paths.go` has the drop-ins:
   - `/etc/github-copilot/policy.d/90-defenseclaw.json` on Linux and macOS;
   - `%ProgramData%\GitHub\Copilot\policy.d\90-defenseclaw.json` on Windows.

   The Verify detail warns about HKLM policy subkeys.
3. `internal/enterprisepolicy/publicpolicy.go` `guardConnectors`: Copilot is guarded.
4. `internal/enterprisepolicy/guard.go`:
   - `connectorSources` `case ConnectorCopilot`, which reads `COPILOT_HOME` and includes the Claude-format files;
   - the `flat` format;
   - `ownedExecArgs`, the 6-arg `--event` form.

   Also `guard_env.go`, `guard_session.go`, `guard_digest.go` and `cleanup.go`.
5. `internal/enterprisepolicy/presence.go`, `windows_owned.go` (Go-owned on Windows) and `fsio_windows.go`.
6. `internal/enterpriseunix/layout.go` `machinePolicyDirs`: `/etc/github-copilot` and `/etc/github-copilot/policy.d`.
7. `internal/enterprisehooks/`:
   - `agent_version_unix.go` `unixAgentProbes["copilot"]` (npm `@github/copilot`, binary `copilot`);
   - `standalone_peruser_repair.go` `standaloneOwnedHookConfigConnectors` (the owned `~/.copilot/hooks/defenseclaw.json`);
   - `peruser_managed.go`: `windowsStandalonePerUserConnectors`, `windowsStandaloneRuntimeOnlyConnectors`, `WindowsStandalonePerUserConnectorNames`;
   - `peruser_managed_windows.go`;
   - `install_windows_runtime_only.go` `windowsRuntimeOnlyPolicyPath`;
   - `managed_runtime_windows.go`, `managed_runtime_generation_windows.go`;
   - `agent_version_peruser_windows.go`, `agent_version_managers_windows.go`;
   - `enumerator_windows.go`, `install_windows.go`, `installer.go`.
8. `internal/cli/`:
   - `hook_foreign_guard.go`: session start `sessionStart`, session keys `session_id` / `sessionId`;
   - `hook_trusted_state_windows.go`;
   - `enterprise_hooks_foreign_unix.go`, `enterprise_hooks_standalone_policy_windows.go`, `windows_managed_hooks_teardown_peruser.go`, `enterprise_policy.go`.
9. `packaging/windows/DefenseClawEnterprise.psm1`: the standalone `$teardownConnectors` line only.
10. `internal/acp/catalog.go`: a cataloged ACP entry (`copilot --acp --stdio`, `SupportCataloged`), mirrored in both `acp_registry.json` copies.

## 7. Docs

1. `docs-site/content/docs/connectors/copilot.mdx`: title "GitHub Copilot CLI"; `## Platform support`, `## Setup`, `## Files DefenseClaw will modify`, `## Hook capabilities`, `## Disable`.
2. `docs-site/content/docs/connectors/meta.json`, `connectors/index.mdx` and `connectors/compatibility.mdx` rows.
3. `docs-site/data/capability-matrix.json`, `docs-site/data/connector-icons.ts`, and the committed `docs-site/public/connector-icons/copilot.svg`.
4. The enterprise pages and the four threat models (enterprise.md §10).
5. `docs/development/copilot-native-windows-contract.md`: design notes for the Windows adapter.

## 8. Tests and CI

1. **Go connector tests:**
   - `internal/gateway/connector/hook_only_test.go` (the most Copilot cases), `hookwiring_test.go`, `hook_teardown_absent_config_test.go` (the Copilot leftover row), `hook_contract_test.go`, `hook_config_paths_test.go`, `correlation_test.go`, `connector_test.go`;
   - `cursor_hook_adapter_windows_test.go` (the shared adapter pattern);
   - `hookexec/hookexec_test.go`, including the managed Copilot case `TestManagedCopilotHookDeniesWhenDefenseClawCannotDecide`.
2. **Gateway:** `internal/gateway/agent_hook_test.go`, `inventory_events_test.go`.
3. **Enterprise:**
   - `internal/enterprisepolicy/cursor_copilot_test.go`, `guard_test.go`, `guard_env_test.go`, `guard_session_test.go`, `fsio_windows_test.go`;
   - `internal/enterprisehooks/peruser_managed_windows_test.go`, `peruser_removal_windows_test.go`;
   - `internal/cli/hook_foreign_guard_env_unix_test.go`, `connector_cmd_test.go`.
4. **Windows native Setup:** `cmd/defenseclaw-setup/main_test.go`, `transaction_test.go`, `connector_lifecycle_home_test.go`.
5. **Python:**
   - `cli/tests/test_cmd_doctor_windows_copilot.py`, `test_connector_paths.py`, `test_claw_inventory.py`, `test_cmd_plugin.py`, `test_agent_discovery.py`;
   - `test_cmd_init.py`, `test_cmd_setup_connector_readiness.py`, `test_connector_contracts.py`, `test_skill_discovery.py`;
   - `test_connector_live_e2e_path_policy.py` (`test_copilot_contract_normalizes_fixture_event_to_native_registration`).
6. **e2e:** the `test/e2e/connectormatrix.go` row and `test/e2e/testdata/v7/golden/copilot/verdict-blocked.golden.json`.
7. **Live E2E harness:**
   - `scripts/live-connector-e2e/golden/copilot/pre_tool_allow.json`, `pre_tool_block.json`, `pre_tool_block_windows.json`;
   - `drivers/copilot.sh`;
   - `lib/setup.sh`, where `dc_connector_config_file` gives `~/.copilot/hooks/defenseclaw.json`;
   - `run.sh` `ALL_CONNECTORS`;
   - `run-copilot-local.ps1`, `test-copilot-local.ps1`, `run-windows.ps1`, `test-windows.ps1`.
8. **CI:**
   - `.github/workflows/connector-live-e2e.yml` (dispatch options, the `full=` matrix, the `COPILOT_GITHUB_TOKEN` scoping);
   - `.github/workflows/windows-native.yml` (native matrix);
   - `scripts/windows-native-ci.ps1` `ValidateSet`;
   - `scripts/invoke-windows-setup-standard-user-ci.ps1`, `scripts/test-windows-setup-wizard.ps1`, `scripts/prepare-windows-contract-v8.py`.

## What Copilot teaches

- **An event missing from stdin must be bound in three places:** the rendered command (`--event` / `-Event`), the trusted header, and the guard's owned-command form. The event must also be validated against the reviewed list in both the runner (`validCopilotEvent`) and the gateway.
- **A fail-open vendor still fails closed when managed.** Keep `failOpenOnly` for per-user installs, and add the managed exception, `managedCopilotFailClosed`.
- **Windows stdin handling decides the adapter.** Where `Start-Process` loses redirected handles, ship a `.ps1` byte-stream adapter. Add it to `HookScriptNames`, to doctor's Windows registration validator (`doctor_hooks.py`), and to teardown's legacy command forms.
- **Machine policy plus per-user rows are both needed on Windows.** Machine policy delivers the hook registration. The per-user row delivers the protected runtime and the scoped token (`windowsStandaloneRuntimeOnlyConnectors`).
