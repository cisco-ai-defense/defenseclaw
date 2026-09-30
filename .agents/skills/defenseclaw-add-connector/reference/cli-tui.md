# CLI, TUI and installers

## 0. How the work is split

- **Python writes; the Go gateway applies.** `defenseclaw setup <x>` checks the version contract and the platform. It writes `config.yaml` (`guardrail.connector`, `claw.mode`, `guardrail.connectors.<x>`) and `<data_dir>/picked_connector`, then restarts the gateway. Go `Connector.Setup()` then writes the agent's hook, plugin and OTel files and seals `hook_contract_lock.json`. Python waits for that lock:
  - `cmd_setup._wait_for_connector_runtime`
  - `cmd_doctor.connector_setup_readiness`
  - `connector_contracts.connector_lock_contract_invariant`
- **Python never renders hook scripts or plugins.** It lists, validates and displays them.
- **Teardown belongs to Go.** Python uninstall runs `defenseclaw-gateway connector teardown|verify --connector <x>`. Only OpenClaw has a Python fallback (`cmd_uninstall._PYTHON_FALLBACK_CONNECTORS`).
- **Connector lists are hand-kept in many modules.** Most dispatchers fall back to OpenClaw or a generic proxy message for an unknown name. A missing arm rarely crashes; it silently does the wrong thing.

## 1. Which sets a connector joins, by kind

| Kind | Manifest `kind` / gate | Python sets |
|---|---|---|
| Proxy | `proxy` / `not-gated` | `platform_support.PROXY_CONNECTORS`, `cmd_setup._PROXY_BACKED_CONNECTORS`, `tui/services/cli_choices.GUARDRAIL_CONNECTORS`; setup through `_make_guardrail_connector_setup_command` |
| Hook (script or binary) | `hook` / `hook-contract` | `cmd_setup._HOOK_ENFORCED_CONNECTORS`, `cmd_doctor._HOOK_ENFORCED_CONNECTORS`, and the loop in `_make_observability_setup_command`. codex and claudecode have dedicated `setup_codex` / `setup_claude_code`. |
| In-agent plugin | `hook` / `hook-contract` | as above, plus `fail_mode._OPENCODE_FAIL_MODE_PATTERN` / `_AMP_FAIL_MODE_PATTERN` and `cmd_guardrail._RUNTIME_FAIL_MODE_CONNECTORS` |
| Policy API | `hook` | as above, plus the "policy" wording branches |
| ACP + native hooks | `acp-with-native-hook-defense-in-depth` / `not-gated` | as above; `platform_support.ACP_ONLY_CONNECTORS` for ACP-only agents |

## 2. Ordered checklist

### Step 1. ID and naming

- Use the squashed lowercase ID. Aliases go in `connector_paths.normalize` and `connector_contracts.normalize_connector` (core.md §1).
- The `setup` subcommand equals the ID, except `claude-code`. That exception is hard-coded in `_print_connector_observability_banner`, `tui/registry._SETUP_CONNECTOR_ALIASES` and `scripts/live-connector-e2e/lib/setup.sh` `dc_setup_subcommand`.
- Add the ID to `scripts/check_schemas.py` `EXPECTED_CLAW_MODE_ENUM` and to the schemas (discovery-observability.md §1.E).

### Step 2. Contract manifests

Update `hook_contracts.json` and `validated_versions.json` (core.md §3.2). Also update the duplicate contract tables, which no test ties to the manifest:
- `cli/defenseclaw/doctor_hooks.py` `_EXPECTED_CONTRACTS`, plus the per-connector event tuples (`_CODEX_CONTRACT_EVENTS`, `_DEVIN_EVENTS`, `_CLAUDE_CONTRACT_EVENTS`, `_COPILOT_CONTRACT_EVENTS`);
- `cli/defenseclaw/fail_mode.py` `_EXPECTED_CONTRACTS`.

Setup statuses:
- `unknown` is fatal in action mode. For OpenCode it is also fatal in observe mode (`strict_unknown`).
- The override is `DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1`.

### Step 3. Paths

`cli/defenseclaw/connector_paths.py` (assets.md §2, step 6). Every dispatcher needs an explicit arm.

### Step 4. Discovery and version probing

- `agent_discovery.py`: `DISCOVERY_PRECEDENCE` and `_SPECS` (discovery-observability.md §1.C). A config file is evidence only; it never proves the client is installed.
- The version probe runs only inside trusted prefixes. The TUI sends an untrusted binary to the Trusted Paths editor (`_route_untrusted_binary_to_panel`).
- Discovery-only agents go in `connector_paths.KNOWN_AGENT_KINDS`, kept in sync with Go `promotedAgentKinds`.
- If setup must pin the exact agent executable in the lock, add it to `agent_selection._SUPPORTED_CONNECTORS` and `_PROTECTED_LOCK_EXECUTABLE_NAMES`, plus the Go consumer `protectedSetupSelectionConnectorForOS`.

### Step 5. Platform support

- `cli/defenseclaw/platform_support.py` `WINDOWS_CONNECTOR_SUPPORT` takes a status (`supported`, `preview`, `not_certified` or `unsupported`) and a reason. It must match Go `windowsConnectorSupport`, which `test_windows_taxonomy_matches_go_mirror_and_has_reasons` checks by regex.
- A connector missing from the map is hidden from pickers and rejected by setup on Windows. macOS and Linux are always supported.
- Every picker filters through `supported_connectors()`. An explicitly chosen unsupported connector fails with the reason (`_PlatformConnectorChoice`, `_ensure_connector_available`).

### Step 6. `defenseclaw setup <x>` (`cli/defenseclaw/commands/cmd_setup.py`)

Tables:
- `_CONNECTOR_NAMES_FALLBACK`: the live list comes from `GET /v1/connectors`; the docs command checker also reads this one.
- `_CONNECTOR_META`: label, description, `tool_mode`, `subprocess_policy`.
- `_CONNECTOR_CHANGE_SURFACES`: the agent-owned files `_print_connector_mutation_notice` lists.
- `_HOOK_ENFORCED_CONNECTORS` and the setup loop tuple.

Branches to review for the new connector:

| Branch | What to check |
|---|---|
| `_print_connector_observability_banner`, `_print_observability_summary`, `_prompt_connector_mode` | connector-specific text and prompts |
| `_setup_observability_alias` | per-connector validation. Hermes checks the profile and refuses `fail_mode=closed`; Antigravity rejects `--workspace`. |
| `_apply_hook_connector_setup` | Cursor fail-mode and HILT cases |
| `_hilt_support_note` | don't leave the connector on the generic fallback |
| `_connector_contract_upgrade_guidance` | upgrade guidance text |
| `_check_connector_version_supported_for_setup` | version support check |
| `config_home_connectors` | who may pass `--config-home`. It must agree with Go `bindConnectorLifecycleConfigHome` (step 12). |

Batch mode (`setup -c a -c b --detected --all`, `--replace`), rollback and the change notice all work once the tables list the connector.

### Step 7. Onboarding

- `cmd_init.py`: the `--connector` Choice, plus the hidden Windows-installer flags (for example `--native-setup-copilot`).
- `cmd_quickstart.py`: the `--connector/--agent` Choice. It exits 2 on an ambiguous or contradictory choice.
- `bootstrap._connector_readiness`: one arm per connector. Without one it returns `warn "unknown connector"`.
- TUI first run: `tui/panels/first_run.CONNECTOR_CHOICES`.
- Installers (step 13).

### Step 8. Status, doctor, guardrail, fail mode

- **Status.** `cmd_status._FRIENDLY_CONNECTOR_NAMES`, plus the per-connector runtime-truth branches (`_opencode_runtime_truth`, `_omnigent_effective_runtime_state`).
- **Doctor** (`cmd_doctor.py`; tables listed in discovery-observability.md §1.K). `_check_connector_hooks` skips unknown connectors without a row. Kiro adds a scope row (`_check_kiro_global_scope`).
- **Windows hook registration** (`doctor_hooks.py` `validate_windows_hook_registration`). It checks registrations without running anything: `_EXPECTED_CONTRACTS`, `_REPAIR`, and exact argv checks. For Antigravity, anything other than `["hook","--connector","antigravity","--event",<Event>]` is flagged as stale. **Any change to how Go renders a command must be copied here.**
- **Guardrail.** `cmd_guardrail._CONNECTOR_LABELS` and `_RUNTIME_FAIL_MODE_CONNECTORS`.
- **Fail mode** (`fail_mode.py`):
  - `_UPSTREAM_FAIL_OPEN_CONNECTORS` (antigravity, copilot, hermes);
  - `_SHARED_RUNTIME_CONNECTORS`;
  - `_WINDOWS_LAUNCHER_CONNECTORS`;
  - `reconcile_connector_registration`, which calls `defenseclaw-gateway connector reconcile --json`.

### Step 9. Uninstall, upgrade, migration, retirement

- **Backup markers.** `cmd_uninstall._CONNECTOR_BACKUP_MARKERS` lists fixed backup file names under `connector_backups/<x>/`. `_teardown_connectors` uses them to also sweep inactive but dirty connectors.
- **Teardown failures.** `_connector_teardown` aborts uninstall if Go teardown fails for any connector other than openclaw. `_GATEWAY_UNKNOWN_CONNECTOR_EXIT = 2` turns a connector this build no longer ships into a warning.
- **Native installer state.** `commands/windows_native_uninstall.py` has the allowlist of connectors in authenticated native-installer state. `RETIRED_INSTALL_STATE_CONNECTORS` is in `retired_install_state.py`.
- **Renaming or retiring.** Use `legacy_connector.py`, which mirrors Go `internal/legacyconnector` (core.md §1). It lists every config map where a connector ID appears. `defenseclaw migrate` persists the change.

### Step 10. Credentials and registries

- `credentials._HOOK_POLICY_ONLY_CONNECTORS`: a connector left out is treated as proxy-backed when deciding whether the LLM key is required.
- `registries/manifest.KNOWN_CONNECTORS`.

### Step 11. TUI (`cli/defenseclaw/tui/`)

| File : symbol | Purpose |
|---|---|
| `services/cli_choices.CONNECTORS` | wizard picker order (proxies first) |
| `screens/mode_picker.MODE_PICKER_CHOICES` | wire name, label, unique hotkey, `guardrail_ok`, description (`ModeChoice`) |
| `registry._SETUP_CONNECTOR_ALIASES` | command-palette aliases |
| `registry_data.GO_PARITY_REGISTRY` | one `('setup <x>', 'defenseclaw', ('setup','<x>','--yes'), ...)` row per connector |
| `panels/setup.py` `_connector_setup_alias` → `connector_setup_command` | used by the mode picker and the Setup wizard (`_build_connector_setup_args`) |
| `services/overview_state.py` `friendly_connector_name`, `zero_connector_requests_notice`, `connector_source_label` | Overview labels, zero-event hints, source labels |
| `services/catalog_state.py` `friendly_connector_name`, `connector_source_label`, `mcp_unset_target_for_connector` | Skills, MCP and Plugins panels (duplicates of overview_state) |
| `app.py` | amp and omnigent wording ("policy plugin", "policy") |

Brand casing is explicit (`test_tui_label_maps_have_explicit_brand_cases`).

### Step 12. Go CLI (`internal/cli/`)

- **`connector_cmd.go`** (`defenseclaw-gateway connector ...`):
  - `bindConnectorLifecycleConfigHome`: a case for the vendor's `*_HOME` variable. Any other connector gets "explicit config home is unsupported".
  - The `runConnectorReconcile` allowlist.
  - `verify` exits 0, 1 or 2 (`connectorExit`).
  - `launch` is OpenHands-only.
- **`status.go`** `friendlyConnectorName`, tested by `status_connectors_test.go`.
- **`hook.go`** flags and `hookFailureExitCode` (core.md §5 and §8).
- **`--config-home` path safety:** `connector_config_home_{other,windows}.go`.

### Step 13. Installers and the Windows native Setup

| File : symbol | Notes |
|---|---|
| `scripts/install.sh` `CONNECTOR_CHOICES` | writes `picked_connector`, which `cmd_setup._read_picked_connector` reads |
| `scripts/install.ps1` `$ConnectorChoices` | must equal the Windows supported, preview and not-certified sets minus ACP-only, and end with `"none"` (`test_windows_installer_tracks_supported_connectors`) |
| `cmd/defenseclaw-setup/main.go` `nativeLifecycleConnectorNames`, `normalizeConnector`, per-connector cases | Windows native Setup: which connectors it can set up, plus accepted aliases (Copilot accepts `githubcopilot` and `github-copilot`) |
| `cmd/defenseclaw-setup/wizard_windows.go` `wizardConnectorChoices` | wizard labels; pinned by `wizard_windows_test.go` |
| `cmd/defenseclaw-setup/transaction.go`, `connector_reconciliation.go` | per-connector home resolution and rollback (`resolvePreviousConnectorHome`, backup names) |
| `cmd/defenseclaw-setup/platform_windows.go` (`defaultDevinConfigDir`, `defaultDevinExecutable`, `defaultHermesHome`, `officialAntigravityConfigHomeForTransaction`) | the vendor's Windows config home and executable location, when they aren't under the user profile's default |
| `cmd/defenseclaw-setup/devin_admission_windows.go` `verifyDevinExecutableAdmission` | pattern for a vendor whose executable Setup must admit (signer, identity and version output) before pinning it |
| `internal/nativeinstallstate/state.go` | persisted vendor homes (for example `CopilotHome` / `COPILOT_HOME`) |
| `packaging/macos/lib/installer_lib.sh` | **Secure Client allowlist; don't add connectors** |

### Step 14. Env vars and generated data

- **Env var registry.** Every new `DEFENSECLAW_<X>_*` variable (`_CONFIG_HOME`, `_EXECUTABLE`, `_TEST_*`) needs an entry in `internal/envvars/registry.json` with `name`, `category`, `purpose`, `default`, `accepted_values`, `security_impact`, `surface_in_doctor`, `consumers` and `since`.
  - `cli/tests/test_envvars_codebase_coverage.py` scans the repo for `DEFENSECLAW_*` tokens.
  - Regenerate with `python scripts/gen_envvars_docs.py`, which also writes `docs-site/content/docs/reference/env-vars.mdx`. CI runs it with `--check`.
- **Bundle data.** `make _bundle-data` copies bundle data into `cli/defenseclaw/_data/` (gitignored). The only per-connector content there is env vars. The hook contracts live in `cli/defenseclaw/inventory/` as package-data.

### Step 15. macOS app (`macos/DefenseClawMac/`)

The native macOS app keeps its own hand-kept connector lists. None of them read the Python or Go registries, and Kiro is missing from most of them today.

| File : symbol | Purpose |
|---|---|
| `DefenseClawMac/App/AppState.swift` `knownConnectors`, plus the hook-connector `case` list | catalog-scan and Connectors-table roster |
| `DefenseClawMac/Features/SetupDefinitions.swift` `TUIWizards.connectors` / `proxyConnectors` | setup wizard choices; `hookConnectors` is derived |
| `DefenseClawMac/Features/FirstRunView.swift`, `DefenseClawMac/Features/ConfigEditorDefinitions.swift` | first-run picker and config-editor connector choices |
| `DefenseClawMac/DataLayer/CommandRegistry.swift` | one `setup <id>` `CommandDefinition` row |
| `DefenseClawMac/DataLayer/Models.swift` | friendly name |
| `DefenseClawMac/DataLayer/SkillScanner.swift` | per-connector skill and MCP paths (a third copy of the asset tables; assets.md §1) |

Tests: `Tests/SetupDefinitionsParityTests.swift`, `Tests/ConnectorOnboardingTests.swift`, `Tests/ConnectorInventoryCompatibilityTests.swift` and `Tests/FirstRunConnectorSelectionTests.swift`, run by the matching `script/test_*.sh`. They need a Mac with Xcode: `make macos-app-test` runs them all, while CI (`.github/workflows/macos-app.yml`) runs only `test_connector_onboarding.sh`.

## 3. Conventions

- **Labels.** Human labels come from the label maps. Copilot is "GitHub Copilot CLI"; OpenCode, OmniGent and Kiro need explicit brand casing.
- **Contract pinning.**
  - Use exact version lists for vendors that break often.
  - Use platform overrides for per-OS pins.
  - Have exactly one `default_for_unversioned` per platform.
  - Moving a floor or ceiling means editing `hook_contracts.json`, `hook_contract.go` and the manually reviewed `validated_versions.json`.
- **Fail modes.**
  - The desired value comes from `guardrail.connectors.<x>.hook_fail_mode` or the global value.
  - Upstream fail-open vendors show "upstream fail-open" text that differs from the configured mode.
  - Hermes refuses `closed`.
  - Enterprise-managed hooks are always closed.
- **Exit codes.**
  - Python fails with `ClickException`, `Abort` or `SystemExit(1)`.
  - `quickstart` exits 2 on connector ambiguity, and Click usage errors also exit 2.
  - Go `connector verify` exits 0, 1 or 2.
  - Go `hook` exits 1, except Kiro fail-closed, which exits 2.
- **Per OS.**
  - Windows is hook-only: proxies are unsupported, and OpenHands is unsupported because it needs WSL.
  - Windows hooks use the native `defenseclaw-hook.exe` or encoded PowerShell bridges, not `.sh`.
  - Config homes differ per OS: Devin uses `%APPDATA%\devin` versus `~/.config/devin`, and Hermes uses `%LOCALAPPDATA%\hermes` versus `~/.hermes`.
- **Scope.**
  - Cursor owns only the user hook.
  - Antigravity owns only the global `~/.gemini/config/hooks.json` and rejects `--workspace`.
  - Kiro reports its global scope in doctor.

## 4. Mistakes from this branch's history

- `5fe9e093`: new connectors weren't detected or observed during quickstart.
- `cb96bc5d`, `cd6b6f2c`: the Kiro flag and the Windows exit-code issues (core.md §10).
- `bb78ad66`: OpenHands event casing, the Devin config root on macOS, and the OpenHands hooks file needed on first install.
- `b4aaedb3`: standalone Devin must report fail mode closed.
- `e508ba54`: renaming or retiring touches every config map listed in `legacy_connector.py`.
- Antigravity: `doctor_hooks` checks the exact argv, so any extra argument Go renders makes doctor call the registration stale.

**Kiro gaps at the time of writing** (none of these lists are covered by `test_connector_surface_parity.py`):
1. `tui/panels/setup.py` `_connector_setup_alias` has no kiro entry. The mode picker says "No setup command available", and the Setup wizard falls back to `('setup','openclaw','--yes')`.
2. `credentials._HOOK_POLICY_ONLY_CONNECTORS` has no kiro, so the LLM key is reported as REQUIRED.
3. `bootstrap._connector_readiness` has no kiro arm, so it reports "unknown connector".
4. `zero_connector_requests_notice` gives Kiro the proxy hint.
5. `_hilt_support_note` returns the generic text for amp and kiro.
6. The Go `connector reconcile` allowlist leaves out openhands and kiro, which the scoped fail-mode path can reach.
7. `_CONNECTOR_BACKUP_MARKERS` and `_CONNECTOR_RESIDUE_ARTIFACTS` have no Kiro entry, because its backup names are derived from paths. `config_home_connectors` includes kiro, but the Go side doesn't.

## 5. Tests

**Parity tests** (they fail automatically once the name is in `KNOWN_CONNECTORS`):
- `cli/tests/test_connector_surface_parity.py`: quickstart and init choices, doctor labels, discovery, the palette `setup <x>` row, status names, guardrail labels.
- `cli/tests/test_platform_support.py` `test_all_connector_lists_share_one_taxonomy`. It also has hard-coded Windows sets (`WINDOWS_SUPPORTED`, ...) that you edit by hand.
- `cli/tests/test_connector_contracts.py` `test_manifest_covers_every_connector`, plus pin tests.

**Per-connector:**
- `test_connector_paths.py`, `test_connector_mcp_writers.py`, `test_agent_discovery.py`, `test_cmd_doctor_connector.py`.
- `test_cmd_setup_connector_readiness.py`: the exact roster.
- `test_cmd_uninstall.py`, `test_windows_release_claims.py`, `test_check_schemas.py`, `test_ai_signatures.py`.
- TUI: `tui/test_mode_picker.py` (order and hotkeys), `test_first_run_panel.py`, `test_setup_panel.py`, `test_registry_platform.py`.
- A dedicated parity file modeled on `test_devin_connector_parity.py`; fixtures go in `cli/tests/connector_fixtures.py`.
- `test_envvars_codebase_coverage.py`, `test_retired_connector_names.py`.

**Go:**
- `internal/cli/connector_cmd_test.go`, `connector_config_home_test.go`, `status_connectors_test.go`.
- `cmd/defenseclaw-setup/wizard_windows_test.go`, `main_test.go`.

**macOS app:** `make macos-app-test` (step 15).

**Generic tests worth adding** (they would have caught the Kiro gaps). For every connector in `KNOWN_CONNECTORS`:
- `connector_setup_command(c)` is non-empty;
- `_connector_readiness` never says "unknown connector";
- every hook connector is in `_HOOK_POLICY_ONLY_CONNECTORS`;
- no hook connector gets the proxy notice;
- `_hilt_support_note` isn't the generic fallback;
- Python `config_home_connectors` equals the Go `bindConnectorLifecycleConfigHome` cases;
- the Go reconcile allowlist covers every connector the scoped fail-mode path can reach.

**Runners:**
- `make cli-test`
- `make connector-matrix-test` (Go `-run 'Connector|Hook|...'` plus `py-connector-matrix-test`)
- `make check-schemas`
- `make cli-test-snap` (TUI snapshots)
