# Assets: skills, MCP servers, plugins, rules, agents

A connector's asset paths live in **nine separate tables**, split between Go, Python and the macOS app. There is no single registry. Almost every table falls back to **OpenClaw** when it has no arm for a connector. An asset gap therefore never errors: it silently reads, watches or even creates `~/.openclaw/...`.

## 1. Who reads which table

| Consumer | Reads | Used for |
|---|---|---|
| Gateway install watcher (fsnotify + rescan) | `resolveWatcherDirs` (`internal/gateway/sidecar.go`). Order: explicit `gateway.watcher.{skill,plugin}.dirs`, then `ComponentScanner.ComponentTargets(cwd)`, then `cfg.SkillDirs()` / `cfg.PluginDirs()` | live admission scan, quarantine, block (`internal/watcher/watcher.go`) |
| Watcher MCP rescan | `cfg.ReadMCPServers()` → `ReadMCPServersForConnector(active)` (`internal/watcher/rescan.go` `enumerateTargets`) | MCP drift and rescan |
| Connector metadata and the contract lock | `ConnectorCapabilityProvider.Capabilities(opts)` → `ResolvedConnectorLocations` (`connector_state.go`) → surfaces | doctor, API metadata, `hook_contract_lock.json` |
| Managed endpoint MCP inventory | `perConnectorMCPEntriesForOS` (`internal/gateway/inventory_events.go`): pass 1 is gated by `hasNativeMCPReader`; pass 2 is `readMCPServersUnderHomeForOS` for each `ai_discovery.home_dirs` entry | SIEM inventory (`ai_component.observed`) |
| AI Discovery | `internal/inventory/ai_signatures.json` `mcp_paths`, `skill_paths`, `plugin_paths`, `rule_paths`, `config_paths` | discovery signals, `agent discover` |
| Python CLI (`skill`, `mcp` and `plugin` list/scan; `aibom`; TUI panels) | `cli/defenseclaw/connector_paths.py`, through `Config.skill_dirs` / `plugin_dirs` / `mcp_servers` and `claw_inventory._build_aibom_from_filesystem` | operator inventory, scans, the AIBOM |
| Runtime asset policy (hooks) | payload fields: `mcp_server_name`, `mcp__<srv>__<tool>` / `mcp:<srv>:<tool>`, and the skill fields (`internal/gateway/asset_policy_runtime.go`) | asset-policy block and allow; the runtime MCP block list |
| Go MCP scanner | `defenseclaw mcp scan --json <name>`; Python resolves the name (`internal/scanner/mcp.go`) | watcher and rescan MCP scans |
| macOS app | `macos/DefenseClawMac/DefenseClawMac/DataLayer/SkillScanner.swift`: its own per-connector skill and MCP path switches | the app's catalog panels; checked by `ConnectorInventoryCompatibilityTests.swift` (cli-tui.md step 15) |

The scanners themselves (`internal/scanner/*`, `internal/enforce/*`, `cli/defenseclaw/scanner/*`) have no connector logic. A new connector needs scanner changes only for a new plugin manifest format (§2, step 8) or a self-owned bridge file (§2, step 11).

## 2. Registration checklist, in order

1. **Decide each surface** from the vendor docs: mcp, skills, rules, plugins and agents. For each, choose supported and writable (install targets), discovery-only, or unsupported (with a reason). Record:
   - per-OS paths;
   - env overrides (`CODEX_HOME`, `CLAUDE_CONFIG_DIR`, `OPENCODE_CONFIG_DIR`, `HERMES_HOME`, `COPILOT_HOME`, ...);
   - workspace versus user scope;
   - vendor-bundled assets that must never be scanned.

   Every table below encodes these decisions again.

2. **Go capability** (`internal/gateway/connector/`):
   - **Fill `ConnectorCapabilities`** (`connector.go`): `MCP`, `Skills`, `Rules`, `Plugins` and `Agents` `SurfaceCapability`, each with `ConfigPaths`, `ReadPaths`, `WritePaths`, `InstallTargets`, `DiscoveryOnly`, `RequiresOptIn` and `Notes`. Use `unsupportedSurface(note)` for anything unsupported.
   - **Where capabilities go, by type.** Hook-only connectors add a `case` to `hookOnlyConnector.Capabilities` (`hook_only.go`). Standalone types implement `Capabilities` themselves (`KiroConnector.Capabilities`, `ClaudeCodeConnector.Capabilities`).
   - **`ComponentScanner`.** It has two methods: `ComponentTargets(cwd) map[string][]string` and `SupportsComponentScanning()`.
     - Hook-only connectors inherit `hookOnlyConnector.ComponentTargets`, which calls `addSurfaceTargets` to put ReadPaths and ConfigPaths into the keys `mcp`, `skill`, `rule`, `plugin` and `agent`.
     - A type without `ComponentScanner` makes the watcher fall back to the `cfg.SkillDirs()` switch. Kiro has this gap (§5).
   - **Bridge files.** Add `ManagedPluginArtifactOwner` for in-agent plugin bridges (`pluginArtifact: true`). The watcher binds those files through `SetManagedArtifacts`, and admission skips them.
   - **Package cycle.** `connector` can't import `config`. Roots that depend on the agent's own settings (Amp `amp.skills.path`, OpenCode's config root) are therefore special-cased in `resolveWatcherDirs` (`ampWatcherSkillDirs`, `opencodeWatcherDirs`).

3. **Go config resolvers** (`internal/config/claw.go`). Add an **explicit arm to all four** methods, even when the answer is empty; the `default:` arm returns OpenClaw paths.

| Method | Empty-answer form |
|---|---|
| `(*Config).ReadMCPServersForConnector` | `case "x": return nil, nil` |
| `(*Config).ConnectorHomeDir` | return the vendor home |
| `(*Config).SkillDirsForConnector` | add the name to the arm that returns `nil` |
| `(*Config).PluginDirsForConnector` | add the name to the arm that returns `nil` |

   - Names are normalized by `normalizeConnectorKey` (`internal/config/config.go`).
   - Export readers that others call per home (`ReadMCPServersOpenCodeUnderHome`, `ReadMCPServersAMPUnderHome`, `ReadMCPFromDevinConfig`).
   - Mark vendor-built MCP servers `Bundled`, as Codex does with `codexBuiltinShape`.

4. **Managed MCP inventory** (`internal/gateway/inventory_events.go`):
   - Add the name to `hasNativeMCPReader`, but **only** once step 3 has a real reader. Otherwise pass 1 duplicates OpenClaw servers under the new label.
   - Add a case to `readMCPServersUnderHomeForOS` with home-relative paths. Branch on `goos` where the vendor does; Devin uses `AppData/Roaming/devin/mcp_config.json` on Windows and `.config/devin/mcp_config.json` elsewhere.
   - Rows are gated by OS through `inventoryConnectorAvailableOnOS`, which needs the `windowsConnectorSupport` row.

5. **Signature catalogs** (discovery-observability.md §1.B). Add one entry to both `internal/inventory/ai_signatures.json` and `cli/defenseclaw/inventory/ai_signatures.json`, byte-identical, with `supported_connector` and non-empty `mcp_paths` (plus skill, plugin and rule paths where they apply). `internal/inventory/connector_parity_test.go` requires at least one surface, and MCP unless the connector is in `mcpExempt`.

6. **Python paths** (`cli/defenseclaw/connector_paths.py`). Add the name to `KNOWN_CONNECTORS` and, if it is hook-based, to `HOOK_ONLY_CONNECTORS`. Then add an explicit branch to each function below. Unknown names fall through to OpenClaw unless the table says otherwise.

| Function | Notes |
|---|---|
| `connector_home` | an unknown name returns `""` |
| `connector_config_files` | doctor and fail-mode rollback set; don't widen it casually |
| `skill_dirs` | discovery precedence order |
| `skill_write_dirs` | install target, used by CodeGuard `_target_path` (`codeguard_skill.py`) |
| `plugin_dirs` | write and custody roots |
| `plugin_inventory_dirs` | read-only roots that differ from the write roots (Cursor, OpenCode) |
| `agent_dirs`, `rule_dirs`, `rule_paths` | |
| `connector_policy_settings` | |
| `mcp_servers` | must honor `infer_workspace_from_cwd` and `diagnostic_sink` |
| `mcp_source_locations` | must list **every file `mcp_servers` opens**. An unknown name returns `[]`, and `mcp list` then exits 1 |
| `set_mcp_server` / `unset_mcp_server` | write, or raise `MCPWriteUnsupportedError`. An unknown name raises; these never write OpenClaw |
| `is_bundled_mcp_server` | vendor-managed MCP exclusion |

   Keep these in parity with the Go methods in step 3, and cross-reference them in comments. Put vendor config-home helpers here (`copilot_home`, `devin_config_home`, `hermes_home`), and honor the documented `*_HOME` variable.

7. **Python AIBOM** (`cli/defenseclaw/inventory/claw_inventory.py`):
   - `_build_aibom_from_filesystem` dispatches to `_enumerate_skills_filesystem`, `_enumerate_plugins_filesystem`, `_enumerate_mcp_filesystem`, `_agents_for_connector`, `_rules_for_connector`, `_tools_for_connector`, and the models and memory helpers.
   - Add typed limitations to `_PARTIAL_CONNECTOR_NOTES` (UNSUPPORTED) or `_UNVERIFIED_CONNECTOR_NOTES` (UNVERIFIED). Otherwise empty categories get the generic `_FILESYSTEM_ONLY_CONNECTOR_NOTES` text.
   - `_collect_mcp_config_files` has per-connector filters.

8. **Non-standard layouts:**
   - **Skills:** `skill_discovery.discover_skill_directories` (`cli/defenseclaw/skill_discovery.py`) has branches for the Codex `.system` container, Claude `SKILL.md` and commands, Copilot commands, Cursor nested roots, and the Hermes category tree. The Hermes tree has a Go mirror, `internal/hermesskills/skills.go`, which `rescan.go` uses.
   - **Bundled-skill exclusion:** `internal/enforce/bundled_skill.go` `IsBundledSkillPath`, and Python `is_bundled_skill_path`.
   - **Plugins:** `plugin_directories.discover_plugin_directories`. A new `.<vendor>-plugin/plugin.json` manifest must be listed in **all three** of `_MANIFEST_CANDIDATES` (`plugin_scanner/scanner.py`), `STANDARD_MANIFEST_DIRS` (`plugin_scanner/helpers.py`) and `_PLUGIN_MANIFEST_FILES` (`claw_inventory.py`).

9. **Runtime identity.** The asset policy sees only what the hook payload carries.
   - **MCP block list:** `mcpServerRuntimeBlock` (`mcp_runtime_block.go`). The hook path passes `payloadString(req.Payload, "mcp_server_name")`.
   - **Asset policy:** `collectAgentHookAssetDecisions` (`agent_hook.go`) → `mcpProbeFromFields` / `skillProbeFromFields` (`asset_policy_runtime.go`). The server name is recognized only from `mcp_server_name`, or from the tool names `mcp__<srv>__<tool>` / `mcp:<srv>:<tool>` (`serverFromMCPToolName`). Decode or the bridge must normalize the MCP identity.
     - OpenCode's bridge sets `mcp_server_name` and withholds it when sanitized prefixes collide; `openCodeProfileMapVerdict` then blocks in action mode.
     - Cursor has `cursorMCPProbeFromPayload`.
   - **Terminal MCP detection:** needs the shell name in `isTerminalTool`, or an alias in `agentHookTrustedActionTool`.
   - **Native skill selection:** enforced only for `_SKILL_RUNTIME_NATIVE_SELECTION_CONNECTORS` (`cmd_skill.py`: codex, claudecode). The plugin runtime probe exists only for claudecode (`cmd_plugin.py`). Add a connector only if a real gate exists.

10. **Hook-time component scan** (optional; Claude Code and Codex only today). `scanClaudeCodeComponents` / `claudeCodeComponentTargets` and `codexComponentTargets`, with the settings `scan_components`, `scan_on_session_start` and `component_scan_interval_minutes`. Keep them in step with `ComponentTargets`.

11. **First-party self-exemption** (in-agent plugin bridges):
    - `cli/defenseclaw/scanner/plugin_scanner/self_identity.py`:
      - `_BRIDGE_CONNECTOR_BY_FILENAME`;
      - `_BRIDGE_PUBLICATION_SCHEMA`;
      - `_BRIDGE_TEMPLATE_DIGESTS`: the SHA-256 of the normal and the `-secure-client` template;
      - `_BRIDGE_DYNAMIC_LINES`: every templated line, such as `DC_INSTALL_MARKER`.

      `test_bridge_template_fingerprints_match_gateway_sources` pins them. **Any edit to `internal/gateway/connector/hooks/<x>-plugin*` needs a digest bump.** The `-secure-client` digests never change, because those templates are frozen and `TestSecureClientPluginTemplatesArePinned` (`plugin_secure_client_pin_test.go`) pins their template and render hashes. A new bridge has no Secure Client copy: give it a `_BRIDGE_TEMPLATE_DIGESTS` entry with its own template digest, and add a row with only its template to the test's hand-kept `parametrize` list (it lists amp and opencode today).
    - **Policy markers:** add a home-anchored marker to `first_party_allow_list` in `policies/default.yaml`, `policies/strict.yaml`, `policies/permissive.yaml` and `policies/rego/data.json`. Update `internal/policy/fallback.go` and the Python matcher (`enforce/admission.py`, for example `_AMP_HOME_PREFIX`).
    - **Windows standalone plugins:** `windowsStandaloneInAgentPluginConnector` (`peruser_managed.go`), `windowsManagedPluginSDDLFormat` (`peruser_private_plugin_windows.go`) and `plugin_install_marker_windows.go`, all in `internal/enterprisehooks/` (enterprise.md §4).

12. **Other lists keyed by connector name:**
    - `cli/defenseclaw/registries/manifest.py` `KNOWN_CONNECTORS`, plus the three `connector` enums in `schemas/registry-manifest.schema.json`. Pinned by `cli/tests/test_registry_manifest.py`.
    - TUI `cli/defenseclaw/tui/services/catalog_state.py`: `mcp_unset_target_for_connector`, `friendly_connector_name`, `connector_source_label`.
    - `cli/defenseclaw/inventory/agent_discovery.py` `_SPECS` (discovery-observability.md).
    - The asset policy itself (`internal/config/asset_policy.go` `Connectors map[string]PerConnectorAssetPolicy`) and the rule `connector` match need no per-connector code.

## 3. How existing connectors differ

| Connector (kind) | Go targets | Watcher source | Go MCP reader / managed inventory | Python MCP write | Plugins surface |
|---|---|---|---|---|---|
| Claude Code (hook binary) | custom `ComponentTargets`; hook-time scan | connector; `name@marketplace` identity and cache watches | yes / yes (`CLAUDE_CONFIG_DIR`) | `~/.claude.json` through an ownership transaction | cache, skills-dir plugins, `installed_plugins.json` |
| Codex | custom; `.system` bundled | connector | yes (`Bundled` built-ins) / yes | `config.toml` | marketplace, `plugins/cache` |
| OpenClaw (proxy) | custom | connector | `openclaw config get mcp.servers`, then the file | `openclaw config set` | `<home>/extensions` |
| ZeptoClaw (proxy) | custom | connector | yes / yes | unsupported | `~/.zeptoclaw/plugins` |
| Hermes, Cursor, Devin, Copilot, OpenHands, Antigravity | `hookOnlyConnector` switch | connector surface read paths | yes / yes | Hermes YAML; Cursor, Copilot and OpenHands JSON; Devin `mcp_config.json`; Antigravity `serverUrl` | Hermes dirs + pip entry points; Cursor `~/.cursor/plugins/local` (discovery-only); Copilot command-backed (no dirs); Devin and OpenHands unsupported |
| OpenCode, Amp (bridge) | `hookOnlyConnector` + `pluginArtifact` | filtered to existing roots (`opencodeWatcherDirs`, `ampWatcherSkillDirs`) | yes / yes | OpenCode `opencode.json`; Amp read-only | TS/JS plugin files; the managed bridge is excluded |
| Kiro (ACP + hooks) | all surfaces unsupported; **no `ComponentScanner`** | **falls back to OpenClaw paths** | **Go: none**; Python: `.kiro/settings/mcp.json` | discovery-only error | none |
| OmniGent | `SupportsComponentScanning` false | explicit `nil` arms | nil / exempt | unsupported | none |

## 4. Conventions

- **An explicit empty arm counts as registered.** The `default:` fallback is OpenClaw by design.
- **Workspace.** Never infer it from the daemon's cwd. Use only `claw.workspace_dir` (`ConnectorWorkspaceDir`). Interactive CLI callers may opt in with `infer_workspace_from_cwd=True`; writers never do (`74fddaee`).
- **Discovery versus write.** Keep `ReadPaths`, `WritePaths` and `InstallTargets` separate. Likewise keep `skill_dirs` separate from `skill_write_dirs`, and `plugin_inventory_dirs` from `plugin_dirs`.
- **Bounded, no-follow reads.** MCP config is capped at 2 MiB (`_MCP_CONFIG_MAX_BYTES`), manifests at 64 KiB to 1 MiB, and directory walks at 32768 entries. Symlinks and reparse points are never followed.
- **The watcher creates what it watches.** `ensureAndWatch` runs `os.MkdirAll(dir, 0o700)`. Only put roots you own into the watch set, and filter other vendors' compatibility roots to ones that already exist.
- **Fail modes.**
  - The runtime MCP block fails closed on a store error.
  - `registry_empty_action` defaults to deny.
  - An unknown terminal MCP is downgraded to observe unless action mode with default-deny is set.
  - Managed artifacts are skipped by admission.
- **Exit codes.**
  - `mcp list` and `mcp scan` exit 1 when `mcp_source_locations` is empty.
  - `set_mcp_server` raises `MCPWriteUnsupportedError`.
  - `resolve_list_connectors` prints "no connector configured" and exits 0.
- **Multiple connectors.** The Python list and scan commands fan out over `active_connectors()`. The **Go watcher covers only the primary connector** (`configuredConnectorName`).

## 5. Known gaps and past mistakes

**Gaps at the time of writing:**
1. Kiro is missing from all four `claw.go` methods, from `hasNativeMCPReader` and `readMCPServersUnderHomeForOS`, and it has no `ComponentScanner`. With Kiro as the primary connector:
   - the watcher creates and watches OpenClaw skill and plugin directories;
   - rescan scans OpenClaw MCP servers under the Kiro label;
   - `~/.kiro/settings/mcp.json` never reaches gateway inventory.

   Python handles Kiro correctly (`test_kiro_resolves_its_own_surfaces_not_openclaw`). The OmniGent commit `f29b76ec` shows the explicit nil arms to copy.
2. Cursor's skill read paths include other agents' roots. `resolveWatcherDirs` applies the existence filter only to Amp and OpenCode, so a Cursor install could create those directories.
3. There is one watcher per gateway, bound to the primary connector.
4. `test_every_file_opened_was_declared` is a hand-kept list (it omits Devin, Amp and Kiro). `sidecar_watcher_matrix_test.go` omits Kiro, Devin, Antigravity and OmniGent.
5. Go `ConnectorHomeDir("antigravity")` and Python `connector_home("antigravity")` disagree.
6. `internal/acp` doesn't inventory MCP servers from ACP `session/new`.

**Past mistakes:**
- `74fddaee`: the Claude MCP reader ignored `~/.claude.json`. The fix added `mcp_source_locations`, exit 1 when nothing is known, and the declared-files test.
- `783db679`: stale bridge digests plus an unknown `DC_INSTALL_MARKER` line made DefenseClaw's own bridges look third-party.
- `f42ab614`: the gateway MCP scanner called a subcommand that doesn't exist. Scans now go through `defenseclaw mcp scan --json`.
- `cf576356` (Amp): added the watcher filter, the first-party markers in four policy files, and `_AMP_HOME_PREFIX`.
- `e508ba54`: removing a connector touches the same tables. Legacy desktop paths stay as read-only extras (`legacyconnector.DesktopLegacySkillPaths`).

## 6. Tests

- **Go config:** `internal/config/claw_test.go`. Add `TestReadMCPServersForConnector_<X>`, `TestConnectorHomeDir_<X>`, and a "never reads OpenClaw" case.
- **Go watcher:** `internal/gateway/sidecar_watcher_matrix_test.go`. Add rows to `TestResolveWatcherDirs_PerConnectorMatrix` and `TestResolveWatcherDirs_HookOnlyConnectorMatrix`, plus a "does not create foreign roots" case (`TestResolveWatcherDirs_OpenCodeDoesNotMaterializeCompatibilityRoots` pattern).
- **Go connector:** a `ComponentTargets` / `Capabilities` layout test, modeled on `hook_only_test.go` and `codex_inventory_test.go`.
- **Go managed inventory:** `internal/gateway/inventory_events_test.go`, `TestReadMCPServersUnderHomeUsesCanonicalUserConfigs`.
- **Go catalog:** `internal/inventory/connector_parity_test.go`. Bump `expected` or add an exemption with a reason.
- **Python paths:** `cli/tests/test_connector_paths.py`: a `test_<x>_resolves_its_own_surfaces_not_openclaw`, and add the name to `test_every_file_opened_was_declared`.
- **Python writers:** `cli/tests/test_connector_mcp_writers.py`.
- **Python inventory:** `cli/tests/test_claw_inventory.py`, `test_plugin_directories.py`, `test_scan_ux_connector_matrix.py`.
- **Catalog mirror and registry:** `cli/tests/test_ai_signatures.py`, `cli/tests/test_registry_manifest.py`.
- **Bridges:** `cli/tests/test_plugin_self_and_correlation_boundaries.py`.

**A guard worth adding:** a registry-driven test that loops over `NewDefaultRegistry()` and `KNOWN_CONNECTORS`. It would assert that no non-OpenClaw connector's `SkillDirsForConnector`, `PluginDirsForConnector`, `ReadMCPServersForConnector`, `resolveWatcherDirs`, `skill_dirs`, `plugin_dirs` or `mcp_servers` returns or opens a path under `claw.home_dir`. That single test would have caught gap 1.
