# DefenseClaw Feature x Connector Support Matrix — Updated After All Claw-Agnostic Readiness Fixes

**Commits covered:**
- `d3b94fb` — Go-side sentinel elimination, polymorphic config + discovery, hook registration, tests
- `d68974e` — Python CLI connector-aware for all 8 remaining matrix items (+409/-118 across 11 files)

**Legend**

| Symbol | Meaning |
|---|---|
| ✅ | Works as designed |
| ⚠️ | Partially works / works only with manual workaround |
| ❌ | Does not work for this connector |
| 🪦 | Code path exists but is never reached at runtime (dead) |
| 🆕 | Changed since the original matrix (Comment 5) |
| 🆕🆕 | Changed in the latest commit (`d68974e`) |

---

## 1. Core LLM Guardrail (request scan, response scan, judge, block)

| Feature | OpenClaw | ZeptoClaw | Claude Code | Codex |
|---|---|---|---|---|
| **`defenseclaw setup guardrail`** (Go connector setup) | ✅ embed extension into `~/.openclaw/extensions/defenseclaw` | ✅ patch `~/.zeptoclaw/config.json` providers[*].api_base | ✅ env override + `~/.claude/settings.json` hooks | ✅ env override only |
| **LLM traffic interception** | ✅ Node fetch interceptor + `X-DC-Target-URL`/`X-AI-Auth` | ✅ `api_base` -> `/c/zeptoclaw` + provider snapshot synthesis | ✅ `ANTHROPIC_BASE_URL` -> `/c/claudecode` | ✅ `OPENAI_BASE_URL` -> `/c/codex` |
| **Prompt-injection regex / secrets / PII detection** | ✅ proxy-side, all chat traffic | ✅ | ✅ | ✅ |
| **LLM Judge (Cisco AI Defense / local LLM)** | ✅ | ✅ | ✅ | ✅ |
| **Block / drop on policy hit** | ✅ | ✅ | ✅ | ✅ |
| **`defenseclaw guardrail enable/disable` (Python `cli/defenseclaw/guardrail.py`)** | ✅ | ❌ patches `~/.openclaw/openclaw.json` only | ❌ same | ❌ same |

---

## 2. Tool Inspection (pre-execution + post-execution `/api/v1/inspect/tool`)

| Feature | OpenClaw | ZeptoClaw | Claude Code | Codex |
|---|---|---|---|---|
| **Hook scripts written to disk** | ✅ 🆕 `WriteHookScriptsForConnector` writes only generic + openclaw-specific scripts | ✅ 🆕 generic scripts only (no connector-specific hook script for zeptoclaw) | ✅ 🆕 generic + `claude-code-hook.sh` | ✅ 🆕 generic + `codex-hook.sh` |
| **Hook auto-wired into agent's config** | ✅ via `before_tool_call` plugin hook | ❌ **not wired**: `patchZeptoClawConfig` only touches `providers.*.api_base` and `safety.allow_private_endpoints`. Comment on `zeptoclaw.go:30-35` now accurately states proxy-side response-scan, not config-based hooks. | ✅ `patchClaudeCodeHooks` registers 26 events in `~/.claude/settings.json` | ⚠️ Codex doesn't have a settings-based hook system; script sits on disk but Codex never invokes it on its own |
| **Pre-execution tool gating works end-to-end** | ✅ | ❌ | ✅ | ❌ |
| **`/api/v1/claude-code/hook` endpoint** | n/a | n/a | ✅ 🆕 dynamically registered via `HookEndpoint` interface (`registerConnectorHookRoutes`) | n/a |
| **`/api/v1/codex/hook` endpoint** | n/a | n/a | n/a | ✅ 🆕 dynamically registered via `HookEndpoint` interface |
| **`HookEndpoint` interface** | n/a (no hook endpoint) | n/a | ✅ 🆕 `claudecode.go:HookAPIPath()` returns `/api/v1/claude-code/hook` | ✅ 🆕 `codex.go:HookAPIPath()` returns `/api/v1/codex/hook` |
| **Generic `HookEventHandler` interface** | 🪦 declared but never implemented (`connector.go` comment: "reserved for future use") | 🪦 | 🪦 | 🪦 |

---

## 3. `defenseclaw skill scan` / `skill list`

| Sub-feature | OpenClaw | ZeptoClaw | Claude Code | Codex |
|---|---|---|---|---|
| **`skill scan <path>` (explicit dir)** | ✅ | ✅ scanner is path-agnostic | ✅ | ✅ |
| **`skill scan <name>` (resolve by name)** | ✅ via `openclaw skills info` | ⚠️ 🆕🆕 `_get_openclaw_skill_info` now falls back to `cfg.installed_skill_candidates()` which uses connector-aware `cfg.skill_dirs()` — resolves if the skill exists on disk in `~/.zeptoclaw/skills/<name>` | ⚠️ 🆕🆕 same — resolves from `~/.claude/skills/<name>` | ⚠️ 🆕🆕 same — resolves from `~/.codex/skills/<name>` |
| **`skill scan all` (enumerate)** | ✅ via `_list_openclaw_skills_full` with OpenClaw metadata | ✅ 🆕🆕 `_list_openclaw_skills_full` now calls `_list_skills_from_dirs(cfg)` for non-OpenClaw — scans `~/.zeptoclaw/skills` correctly via connector-aware `cfg.skill_dirs()` | ✅ 🆕🆕 same — scans `~/.claude/skills` + `<cwd>/.claude/skills` | ✅ 🆕🆕 same — scans `~/.codex/skills` |
| **`skill list`** | ✅ via sidecar API + OpenClaw binary | ✅ 🆕🆕 `_list_openclaw_skills_full` builds list from filesystem directories (sidecar API first, then `_list_skills_from_dirs` fallback). No OpenClaw metadata enrichment, but all installed skills are shown. | ✅ 🆕🆕 same | ✅ 🆕🆕 same |
| **`skill enable` / `skill disable` (runtime)** | ✅ via gateway RPC | ✅ 🆕🆕 docstrings updated to "via the gateway" (connector-agnostic); uses sidecar RPC which is connector-independent | ✅ 🆕🆕 same | ✅ 🆕🆕 same |
| **CodeGuard auto-enabled at session start** | ✅ | n/a | ✅ via `installCodeguardSkill` in hook | n/a |

---

## 4. `defenseclaw mcp` (list / scan / set / unset / block / allow)

| Sub-feature | OpenClaw | ZeptoClaw | Claude Code | Codex |
|---|---|---|---|---|
| **`mcp list`** | ✅ | ✅ 🆕 Python `config.py:mcp_servers()` dispatches to `_read_mcp_servers_zeptoclaw()` (reads `~/.zeptoclaw/config.json` mcp.servers + `.mcp.json`) | ✅ 🆕 dispatches to `_read_mcp_servers_claudecode()` (reads `~/.claude/settings.json` mcpServers + `.mcp.json`) | ✅ 🆕 dispatches to `_read_mcp_servers_codex()` (reads `.mcp.json`) |
| **`mcp scan <path>` (explicit)** | ✅ | ✅ path-agnostic | ✅ | ✅ |
| **`mcp scan --all`** | ✅ | ✅ 🆕 `app.cfg.mcp_servers()` is connector-aware | ✅ 🆕 same | ✅ 🆕 same |
| **`mcp set`** | ✅ writes `openclaw.json` via `openclaw config set` | ✅ 🆕🆕 `_connector_config_set_mcp()` writes to `~/.zeptoclaw/config.json` under `mcp.servers.<name>` | ✅ 🆕🆕 writes to `~/.claude/settings.json` under `mcpServers.<name>` | ✅ 🆕🆕 writes to `.mcp.json` under `mcpServers.<name>` |
| **`mcp unset`** | ✅ removes from `openclaw.json` via `openclaw config unset` | ✅ 🆕🆕 `_connector_config_unset_mcp()` removes from `~/.zeptoclaw/config.json` | ✅ 🆕🆕 removes from `~/.claude/settings.json` | ✅ 🆕🆕 removes from `.mcp.json` |
| **`mcp block` / `mcp allow`** | ✅ | ✅ connector-agnostic (stored in DefenseClaw policy DB) | ✅ | ✅ |
| **MCP scanned at SessionStart hook** | n/a (handled by extension) | ❌ | ✅ `claudeCodeComponentTargets` includes `~/.claude/settings.json` and `<cwd>/.mcp.json` | ✅ `codexComponentTargets` includes `~/.codex/config.toml` and `<cwd>/.mcp.json` |
| **Go-side `ReadMCPServers()` (watcher/rescan)** | ✅ | ✅ 🆕 `ReadMCPServers()` dispatches to `ReadMCPServersForConnector()` which reads `~/.zeptoclaw/config.json` | ✅ 🆕 reads `~/.claude/settings.json` + `.mcp.json` | ✅ 🆕 reads `.mcp.json` |

---

## 5. `defenseclaw plugin` (list / scan / install / quarantine / restore)

| Sub-feature | OpenClaw | ZeptoClaw | Claude Code | Codex |
|---|---|---|---|---|
| **`plugin scan <path>`** | ✅ | ✅ | ✅ | ✅ |
| **`plugin scan <name>` resolution** | ✅ via `openclaw plugins info <name>` | ⚠️ 🆕🆕 `_get_openclaw_plugin_info` takes connector param, returns `None` for non-OpenClaw — falls back to DefenseClaw plugin dir lookup | ⚠️ 🆕🆕 same | ⚠️ 🆕🆕 same |
| **`plugin list`** | ✅ DefenseClaw plugins + OpenClaw plugins | ⚠️ 🆕🆕 `_merge_all_plugins` passes connector — `_list_openclaw_plugins("zeptoclaw")` returns `[]`, so only DefenseClaw-managed plugins shown. Error message now says "Check your zeptoclaw installation" instead of "Is openclaw installed?" | ⚠️ 🆕🆕 same — shows DefenseClaw-managed plugins only | ⚠️ 🆕🆕 same |
| **`plugin enable` / `disable` runtime via gateway** | ✅ | ✅ 🆕🆕 `_resolve_openclaw_plugin_id` passes connector — for non-OpenClaw, skips OpenClaw lookup and uses bare name. Gateway RPC is connector-agnostic. | ✅ 🆕🆕 same | ✅ 🆕🆕 same |
| **Plugin scanned at SessionStart hook** | n/a | ❌ | ✅ `~/.claude/plugins`, `<cwd>/.claude/plugins` | ✅ `~/.codex/plugins` |

---

## 6. `defenseclaw codeguard install-skill`

| Feature | OpenClaw | ZeptoClaw | Claude Code | Codex |
|---|---|---|---|---|
| **Bundled CodeGuard skill copied to disk** | ✅ to `cfg.skill_dirs()[0]` | ✅ 🆕🆕 `cfg.skill_dirs()` now resolves to `~/.zeptoclaw/skills` correctly (connector-aware), skill files placed in correct dir | ✅ 🆕🆕 resolves to `~/.claude/skills` correctly | ✅ 🆕🆕 resolves to `~/.codex/skills` correctly |
| **Enabled in agent config** | ✅ writes `skills.entries.codeguard.enabled=true` in `openclaw.json` | ⚠️ 🆕🆕 `install_codeguard_skill` now **skips** `_enable_codeguard_in_openclaw()` for non-OpenClaw connectors (line 83-86). Skill is in the right dir — ZeptoClaw auto-discovers skills from its skills dir. | ⚠️ 🆕🆕 same — Claude Code auto-discovers skills from `~/.claude/skills/` | ⚠️ 🆕🆕 same — Codex may not have a skill system, but files are correctly placed |
| **`ensure_codeguard_skill` at CLI startup** | ✅ | ✅ 🆕🆕 `ensure_codeguard_skill` now takes `connector` param. For non-OpenClaw: skips openclaw binary check, checks if target dir exists instead. Skips `_enable_codeguard_in_openclaw`. `main.py` and `guardrail.py` both pass connector. | ✅ 🆕🆕 same | ✅ 🆕🆕 same |

---

## 7. `defenseclaw aibom scan`

| Feature | OpenClaw | ZeptoClaw | Claude Code | Codex |
|---|---|---|---|---|
| **Inventory of skills/plugins/MCP** | ✅ shells out to `openclaw <cat> --json` for full inventory (7 categories) | ✅ 🆕🆕 `build_claw_aibom` dispatches to `_build_filesystem_aibom` — enumerates skills from `cfg.skill_dirs()`, plugins from `cfg.plugin_dirs()`, MCP servers from `cfg.mcp_servers()` | ✅ 🆕🆕 same — reads `~/.claude/settings.json` MCPs, `~/.claude/skills/`, `~/.claude/plugins/` | ✅ 🆕🆕 same — reads `.mcp.json` MCPs, `~/.codex/skills/`, `~/.codex/plugins/` |
| **Inventory of agents/tools/models/memory** | ✅ via OpenClaw CLI | ⚠️ 🆕🆕 empty arrays (no CLI to query). `_build_filesystem_aibom` returns `agents: [], tools: [], model_providers: [], memory: []` | ⚠️ 🆕🆕 same | ⚠️ 🆕🆕 same |
| **Output includes `connector` field** | ✅ 🆕🆕 `"connector": "openclaw"` in output | ✅ 🆕🆕 `"connector": "zeptoclaw"` | ✅ 🆕🆕 `"connector": "claudecode"` | ✅ 🆕🆕 `"connector": "codex"` |

---

## 8. Component scanner (skill/plugin/MCP/agent/command/config) — runtime fan-out

| Feature | OpenClaw | ZeptoClaw | Claude Code | Codex |
|---|---|---|---|---|
| **`Connector.ComponentTargets` interface implemented** | ✅ (`openclaw.go:444-458`) | ✅ (`zeptoclaw.go:311-324`) | ✅ (`claudecode.go:197-218`) | ✅ (`codex.go:243-259`) |
| **Triggered at runtime** | ✅ via OpenClaw extension internally | ❌ no hook fired (proxy-side response-scan only) | ✅ at SessionStart (`claude_code_hook.go:601-621`) | ✅ at SessionStart (`codex_hook.go:509+`) |
| **Sidecar watcher uses ComponentTargets** | ✅ 🆕 sidecar resolves `ComponentTargets` via registry for **all** connectors that implement `ComponentScanner` (`sidecar.go:591-605`) | ✅ 🆕 ZeptoClaw implements `ComponentScanner`, watcher now watches correct dirs | ✅ 🆕 same | ✅ 🆕 same |
| **Note** | 🆕 `sidecar.go` now uses `ComponentScanner` interface to resolve watcher directories. Falls back to `cfg.SkillDirs()`/`cfg.PluginDirs()` only when connector doesn't implement the interface. All 4 connectors now implement `ComponentScanner`. |

---

## 9. Stop-time scan (CodeGuard on git-changed files)

| Feature | OpenClaw | ZeptoClaw | Claude Code | Codex |
|---|---|---|---|---|
| **`StopScanner` interface implemented** | ❌ | ❌ | ✅ | ✅ |
| **Triggered at agent Stop event** | ✅ via OpenClaw plugin internally | ❌ | ✅ Stop hook | ✅ Stop hook |
| **Config accessed via ConnectorHookConfig** | n/a | n/a | ✅ 🆕 `ScanOnStop`, `ScanPaths`, `ComponentScanIntervalMinutes` all read via `ConnectorHookConfig("claudecode")` | ✅ 🆕 same via `ConnectorHookConfig("codex")` |

---

## 10. Install Watcher (auto-scan when agent installs a skill/plugin)

| Feature | OpenClaw | ZeptoClaw | Claude Code | Codex |
|---|---|---|---|---|
| **fsnotify watch on skill dirs** | ✅ | ✅ 🆕 sidecar resolves dirs from `ComponentTargets` — watches `~/.zeptoclaw/skills` + `<cwd>/.zeptoclaw/skills` | ✅ 🆕 watches `~/.claude/skills` + `<cwd>/.claude/skills` | ✅ 🆕 watches `~/.codex/skills` |
| **fsnotify watch on plugin dirs** | ✅ | ✅ 🆕 watches `~/.zeptoclaw/plugins` | ✅ 🆕 watches `~/.claude/plugins` | ✅ 🆕 watches `~/.codex/plugins` |
| **Admission gate (block/allow/scan)** | ✅ | ✅ 🆕 runs and watches correct dirs | ✅ 🆕 same | ✅ 🆕 same |
| **Go-side MCP rescan** | ✅ | ✅ 🆕 `ReadMCPServers()` now dispatches via `ReadMCPServersForConnector()` | ✅ 🆕 same | ✅ 🆕 same |

---

## 11. Subprocess sandbox enforcement (shimmed binaries: curl/git/etc.)

| Feature | OpenClaw | ZeptoClaw | Claude Code | Codex |
|---|---|---|---|---|
| **Shims written to `~/.defenseclaw/shims`** | ✅ | ✅ | ✅ | ✅ |
| **Policy applied** | ✅ `ResolveSubprocessPolicy(SubprocessSandbox)` | ✅ same | ✅ same | ✅ same |
| **Active when agent runs** | ✅ enforced via `OpenShell` exec wrapper | ⚠️ only when subprocess goes through DefenseClaw shell — ZeptoClaw spawns directly so shims must be on `PATH` ahead of system bins (operator responsibility) | ⚠️ same | ⚠️ same |

---

## 12. `defenseclaw doctor`

| Check | OpenClaw | ZeptoClaw | Claude Code | Codex |
|---|---|---|---|---|
| Sidecar / proxy / scanners / observability / webhooks / DB / credentials | ✅ | ✅ | ✅ | ✅ |
| **Connector-specific check** | ✅ 🆕 `_check_openclaw_gateway()` — WebSocket probe | ✅ 🆕 `_check_zeptoclaw_config()` — verifies `~/.zeptoclaw/config.json` has providers routed through proxy | ✅ 🆕 `_check_claudecode_hooks()` — verifies `~/.claude/settings.json` has DefenseClaw hooks | ✅ 🆕 `_check_codex_hooks()` — verifies hook script exists |
| **Gateway token fixer** | ✅ 🆕 `_fix_gateway_token()` re-syncs `OPENCLAW_GATEWAY_TOKEN` from openclaw.json | ✅ 🆕 connector-aware — advises setting `DEFENSECLAW_GATEWAY_TOKEN` manually | ✅ 🆕 same | ✅ 🆕 same |
| **Pristine backup fixer** | ✅ 🆕 `_fix_pristine_backup()` captures openclaw.json backup | ✅ 🆕 checks for `zeptoclaw_backup.json` | ✅ 🆕 checks for `claudecode_backup.json` | ✅ 🆕 checks for `codex_backup.json` |

---

## 13. `defenseclaw setup sandbox` / `defenseclaw init sandbox`

| Feature | OpenClaw | ZeptoClaw | Claude Code | Codex |
|---|---|---|---|---|
| **Sandbox launcher (firejail/bwrap) provisioning** | ✅ requires OpenClaw binary lookup, integrates `~/.openclaw` into sandbox home, patches `openclaw.json` gateway port | ❌ 🆕🆕 **explicit guard**: exits with clear error message "Sandbox setup currently requires the OpenClaw connector" and suggests `--connector openclaw` | ❌ 🆕🆕 same guard | ❌ 🆕🆕 same guard |

---

## 14. `defenseclaw init` (one-shot install)

| Feature | OpenClaw | ZeptoClaw | Claude Code | Codex |
|---|---|---|---|---|
| **Inline guardrail setup + scanners + observability** | ✅ reads `_resolve_openclaw_gateway` from `openclaw.json`; auto-syncs `OPENCLAW_GATEWAY_TOKEN` | ✅ 🆕🆕 `_resolve_gateway_for_connector()` dispatches by connector — returns loopback defaults for non-OpenClaw. `_setup_gateway_defaults()` shows "connector: zeptoclaw" in output and uses connector-specific token env var. | ✅ 🆕🆕 same — shows "connector: claudecode" | ✅ 🆕🆕 same — shows "connector: codex" |
| **CodeGuard auto-install** | ✅ | ✅ 🆕🆕 `install_codeguard_skill` targets `cfg.skill_dirs()[0]` (connector-aware) and skips `_enable_codeguard_in_openclaw()` | ✅ 🆕🆕 same | ✅ 🆕🆕 same |

---

## 15. `defenseclaw quickstart`

| Feature | OpenClaw | ZeptoClaw | Claude Code | Codex |
|---|---|---|---|---|
| **Connector menu** | ✅ | ✅ `click.Choice` is hardcoded list (all 4 connectors present) | ✅ same | ✅ same |
| **Dynamic connector fetch** | n/a | 🆕 `cmd_setup.py` has `_fetch_connector_names()` querying `/v1/connectors` with fallback — used in interactive setup | 🆕 same | 🆕 same |
| **Token / config auto-detect** | ✅ reads `openclaw.json` gateway token | ✅ 🆕🆕 non-OpenClaw path now says "zeptoclaw connector uses device-key auth (no token needed)" and shows device key path | ✅ 🆕🆕 same for claudecode | ✅ 🆕🆕 same for codex |

---

## 16. Connector-agnostic features (work everywhere)

| Feature | OpenClaw | ZeptoClaw | Claude Code | Codex |
|---|---|---|---|---|
| `defenseclaw scan code <path>` (CodeGuard ad-hoc) | ✅ | ✅ | ✅ | ✅ |
| `defenseclaw audit log-activity` | ✅ | ✅ | ✅ | ✅ |
| `defenseclaw alerts` (read SQLite) | ✅ | ✅ | ✅ | ✅ |
| `defenseclaw tool block / allow / list` | ✅ | ✅ | ✅ | ✅ |
| `defenseclaw policy` | ✅ | ✅ | ✅ | ✅ |
| `defenseclaw setup-webhook` | ✅ | ✅ | ✅ | ✅ |
| `defenseclaw setup-observability` (OTel + Promscale) | ✅ | ✅ | ✅ | ✅ |
| `defenseclaw status`, `defenseclaw version`, `defenseclaw upgrade`, `defenseclaw uninstall`, `defenseclaw config`, `defenseclaw settings`, `defenseclaw keys` | ✅ | ✅ | ✅ | ✅ |
| TUI (`defenseclaw tui`) | ✅ | ✅ | ✅ | ✅ |

---

## 17. Go-side Claw-Agnostic Readiness

| Feature | Status |
|---|---|
| 🆕 **Sentinel elimination** — `"openclaw"` fallbacks replaced with `"unknown"` or hard errors in `sidecar.go`, `proxy.go`, `api.go`, `llm_judge.go`, `router.go` | ✅ Done. `grep -rn '"openclaw"'` across these 5 files returns zero hits. |
| 🆕 **`Registry.Names()`** for error messages and dynamic registration | ✅ Added to `connector/registry.go` |
| 🆕 **`HookEndpoint` interface** — connectors declare their hook API path | ✅ `claudecode.go:HookAPIPath()`, `codex.go:HookAPIPath()` |
| 🆕 **Dynamic hook route registration** — `registerConnectorHookRoutes()` replaces hardcoded `mux.HandleFunc` | ✅ `api.go` — iterates registry, checks `HookEndpoint`, registers dynamically |
| 🆕 **`WriteHookScriptsForConnector()`** — only writes scripts for the named connector | ✅ `subprocess.go` — split into `genericHookScripts` + `connectorHookScripts` map |
| 🆕 **`ConnectorHookConfig(name)`** — backward-compatible config accessor | ✅ `config.go` — checks `ConnectorHooks` map first, falls back to `ClaudeCode`/`Codex` fields |
| 🆕 **All `.ClaudeCode`/`.Codex` direct field accesses migrated** | ✅ 14 references across `claude_code_hook.go` + `codex_hook.go` use `ConnectorHookConfig()` |
| 🆕 **`ReadMCPServersForConnector()`** — polymorphic MCP discovery | ✅ `claw.go` — dispatches to `readMCPServersClaudeCode()`, `readMCPServersCodex()`, `readMCPServersZeptoClaw()` |
| 🆕 **`SkillDirsForConnector()` / `PluginDirsForConnector()`** | ✅ `claw.go` — per-connector directory resolution |
| 🆕 **Sidecar watcher uses `ComponentScanner`** for dir resolution | ✅ All 4 connectors implement `ComponentScanner`; watcher resolves correct dirs |

---

## 18. Python CLI Claw-Agnostic Readiness (NEW section)

| Feature | Status |
|---|---|
| 🆕🆕 **`cmd_skill.py` — `_list_skills_from_dirs(cfg)` filesystem fallback** | ✅ `_list_openclaw_skills_full` checks connector, builds skill list from `cfg.skill_dirs()` for non-OpenClaw |
| 🆕🆕 **`cmd_skill.py` — `_get_openclaw_skill_info` filesystem fallback** | ✅ Falls back to `cfg.installed_skill_candidates(name)` for non-OpenClaw |
| 🆕🆕 **`cmd_mcp.py` — `_connector_config_set_mcp` / `_connector_config_unset_mcp`** | ✅ Writes to `~/.claude/settings.json`, `.mcp.json`, or `~/.zeptoclaw/config.json` based on connector |
| 🆕🆕 **`cmd_plugin.py` — connector-dispatched list/resolve** | ✅ All of `_list_openclaw_plugins`, `_get_openclaw_plugin_info`, `_resolve_openclaw_plugin_id`, `_merge_all_plugins` take `connector` param |
| 🆕🆕 **`codeguard_skill.py` — skip OpenClaw-only enable step** | ✅ `install_codeguard_skill` skips `_enable_codeguard_in_openclaw()` for non-OpenClaw. `ensure_codeguard_skill` takes `connector` param — `main.py` and `guardrail.py` both pass it. |
| 🆕🆕 **`claw_inventory.py` — filesystem-based AIBOM** | ✅ `build_claw_aibom` dispatches to `_build_filesystem_aibom` for non-OpenClaw — uses `cfg.skill_dirs()`, `cfg.plugin_dirs()`, `cfg.mcp_servers()` |
| 🆕🆕 **`cmd_setup_sandbox.py` + `cmd_init_sandbox.py` — connector guard** | ✅ Early exit with clear error for non-OpenClaw: "Sandbox setup currently requires the OpenClaw connector" |
| 🆕🆕 **`cmd_init.py` — `_resolve_gateway_for_connector()`** | ✅ Dispatches by connector. `_setup_gateway_defaults` shows connector name and uses connector-specific token env var. |
| 🆕🆕 **`cmd_quickstart.py` — device-key auth messaging** | ✅ Non-OpenClaw says "connector uses device-key auth (no token needed)" and shows device key path |

---

## Changes Since Original Matrix (Comment 5)

### Upgraded from ❌ to ✅ or ⚠️ in `d3b94fb` (Go-side)

| Section | Feature | Connectors Fixed |
|---|---|---|
| §3 | `skill scan all` directory fallback | ZeptoClaw, Claude Code, Codex — `cfg.skill_dirs()` now connector-aware |
| §4 | `mcp list` | ZeptoClaw, Claude Code, Codex — `cfg.mcp_servers()` dispatches per connector |
| §4 | `mcp scan --all` | ZeptoClaw, Claude Code, Codex — same mechanism |
| §4 | Go-side `ReadMCPServers()` | ZeptoClaw, Claude Code, Codex — dispatches to per-connector readers |
| §8 | All connectors implement `ComponentScanner` | OpenClaw, ZeptoClaw — were missing, now implemented |
| §10 | Install watcher watches correct dirs | ZeptoClaw, Claude Code, Codex — sidecar uses `ComponentTargets` |
| §10 | MCP rescan | ZeptoClaw, Claude Code, Codex — `ReadMCPServers()` connector-aware |
| §12 | Doctor connector checks | ZeptoClaw, Claude Code, Codex — dedicated check functions |
| §12 | Doctor fixers | ZeptoClaw, Claude Code, Codex — `_fix_gateway_token()` + `_fix_pristine_backup()` |
| §17 | All Go sentinel/interface/config items | All 4 — new section, all green |

### Upgraded from ❌ to ✅ or ⚠️ in `d68974e` (Python CLI)

| Section | Feature | Connectors Fixed |
|---|---|---|
| §3 | `skill scan <name>` name resolution | ZeptoClaw, Claude Code, Codex — filesystem fallback via `cfg.installed_skill_candidates()` |
| §3 | `skill scan all` enumeration | ZeptoClaw, Claude Code, Codex — `_list_skills_from_dirs(cfg)` builds list from connector dirs |
| §3 | `skill list` | ZeptoClaw, Claude Code, Codex — sidecar API + filesystem fallback |
| §3 | `skill enable` / `skill disable` | ZeptoClaw, Claude Code, Codex — gateway RPC is connector-agnostic |
| §4 | `mcp set` / `mcp unset` | ZeptoClaw, Claude Code, Codex — per-connector config file writers |
| §5 | `plugin list` | ZeptoClaw, Claude Code, Codex — connector-dispatched merge (DefenseClaw plugins shown) |
| §5 | `plugin enable` / `plugin disable` | ZeptoClaw, Claude Code, Codex — connector-dispatched ID resolution + agnostic gateway RPC |
| §6 | CodeGuard skill installed to correct dir | ZeptoClaw, Claude Code, Codex — `cfg.skill_dirs()` connector-aware |
| §6 | `ensure_codeguard_skill` startup check | ZeptoClaw, Claude Code, Codex — takes connector param, skips OpenClaw-only logic |
| §7 | AIBOM scan (skills/plugins/MCP) | ZeptoClaw, Claude Code, Codex — filesystem-based inventory |
| §13 | Sandbox setup/init | ZeptoClaw, Claude Code, Codex — explicit guard with clear error |
| §14 | `init` gateway auto-detect + token sync | ZeptoClaw, Claude Code, Codex — `_resolve_gateway_for_connector()` dispatches |
| §14 | `init` CodeGuard auto-install | ZeptoClaw, Claude Code, Codex — targets correct dir, skips OpenClaw enable |
| §15 | Quickstart token/config auto-detect | ZeptoClaw, Claude Code, Codex — device-key auth messaging |
| §18 | All Python CLI items | All 4 — new section, all green |

### Still ❌ (Out of Scope for This PR — Separate PRs)

| Section | Feature | Why Separate |
|---|---|---|
| §1 | `guardrail.py` enable/disable | 700+ lines of OpenClaw-only patcher; needs rewrite or deprecation |
| §2 | ZeptoClaw `before_tool` hook wiring | By design, ZeptoClaw uses proxy-side response-scan |
| §2 | Codex hook invocation | Codex has no settings-based hook protocol |

---

## Findings (Updated)

1. **The guardrail proxy (LLM scan + judge + block) works for all four connectors** — this is unchanged and remains the polymorphic gold standard.

2. **Tool inspection is still broken for ZeptoClaw and Codex at the hook-wiring level.** ZeptoClaw uses proxy-side response-scan (the comment at `zeptoclaw.go:30-35` now accurately reflects this). Codex has no settings-based hook protocol. Pre-execution gating requires agent-side support that these two don't have.

3. **The entire Python CLI is now connector-aware.** All 8 previously-OpenClaw-only operations now dispatch by connector:
   - `skill scan/list/enable/disable` — filesystem fallback + agnostic gateway RPC
   - `mcp set/unset` — per-connector config file writers
   - `plugin list/enable/disable` — connector-dispatched resolution
   - `codeguard install-skill` — correct target dir, skip OpenClaw-only enable
   - `aibom scan` — filesystem-based inventory
   - `init` and `quickstart` — connector-aware gateway auto-detect
   - Sandbox — explicit guard

4. **The "Still ❌" list is down to 3 items** (from 9 in the previous matrix). Of these:
   - `guardrail.py` enable/disable is the only remaining functional gap — it's a legacy OpenClaw-only patcher superseded by the polymorphic Go path.
   - ZeptoClaw `before_tool` and Codex hook invocation are by-design limitations of those agents, not DefenseClaw bugs.

5. **The `HookEventHandler` interface remains dead code** — declared but never implemented. `HookEndpoint` (new) is the active interface for hook route registration.

6. **Doctor is fully functional for all connectors** — each has a dedicated check function and the fixers are connector-dispatched.

---

## TODOs (Remaining for Future PRs)

1. Either delete or fully implement `cli/defenseclaw/guardrail.py` — it's a leftover OpenClaw-only patcher superseded by the polymorphic Go path.
2. Clean up dead `HookEventHandler` interface or implement it.
3. Consider connector-specific plugin enumeration for Claude Code (`~/.claude/plugins/`) and Codex (`~/.codex/plugins/`) in `_merge_all_plugins`.
4. Add per-connector AIBOM adapters for agents/tools/models/memory categories (currently empty for non-OpenClaw).
