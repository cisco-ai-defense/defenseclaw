# PR #141 Code Walkthrough — Connector Architecture v3

**Branch**: `feature/connector-architecture-v3`
**Date**: 2026-04-24
**Files changed**: 53

This document walks through every file changed in PR #141, explaining each modification.

---

## Table of Contents

1. [CI & Build System](#1-ci--build-system)
2. [Shell Scripts](#2-shell-scripts)
3. [Python CLI — Config](#3-python-cli--config)
4. [Python CLI — Commands](#4-python-cli--commands)
5. [Python CLI — Guardrail Module](#5-python-cli--guardrail-module)
6. [Python Tests](#6-python-tests)
7. [Go Config Package](#7-go-config-package)
8. [Go Gateway Core](#8-go-gateway-core)
9. [Go Hook Handlers (New)](#9-go-hook-handlers-new)
10. [Go Inspection Endpoints (New)](#10-go-inspection-endpoints-new)
11. [Go Connector Package (New)](#11-go-connector-package-new)
12. [Hook & Shim Shell Scripts (New)](#12-hook--shim-shell-scripts-new)
13. [Documentation (New)](#13-documentation-new)
14. [Dependency Updates](#14-dependency-updates)

---

## 1. CI & Build System

### `.github/workflows/ci.yml`

**4 jobs gain Node.js setup + `make plugin`**: `go-lint`, `go-test`, `go-build`, `make-test`

```yaml
- uses: actions/setup-node@v4
  with:
    node-version: "20"
    cache: npm
    cache-dependency-path: extensions/defenseclaw/package-lock.json
- run: make plugin
```

**Why**: The OpenClaw connector now embeds the TypeScript plugin via `//go:embed all:openclaw_extension`. Go's embed directive requires the files to exist at build time. The Makefile's `sync-openclaw-extension` target copies the built TS plugin into the Go embed directory, but it needs the TS build first (`make plugin`). Without this, every Go job fails with `pattern all:openclaw_extension: no matching files found`.

**pip-audit ignores CVE-2026-3219**: Added `--ignore-vuln CVE-2026-3219` because pip 26.0.1 has a known vuln with no fix version available. pip is only used by pip-audit itself, not by DefenseClaw at runtime.

### `.gitignore`

```
+internal/gateway/connector/openclaw_extension/
```

The synced embed directory is a build artifact (canonical source is `extensions/defenseclaw/`). Added to gitignore so `git status` stays clean after builds.

### `Makefile`

**New target `sync-openclaw-extension`** (~35 lines): Copies the TS plugin's runtime files into `internal/gateway/connector/openclaw_extension/` for Go's `//go:embed`. Uses rsync when available (preserves tree structure, excludes `__tests__`, `.d.ts`, `.js.map`), falls back to find-based copy. Also copies `package.json`, `openclaw.plugin.json`, and required node_modules (`js-yaml`, `argparse`).

**4 targets gain `sync-openclaw-extension` as a prerequisite**:
- `gateway:` → ensures embed dir is fresh for local builds
- `gateway-cross:` → ensures cross-compilation works in CI
- `gateway-test:` / `go-test-cov:` → tests need the embed dir to compile
- `go-lint:` → linting needs the embed dir to parse the package

**`gateway:` renamed from bare target to `gateway: sync-openclaw-extension`** — was previously a standalone target with no prerequisites.

---

## 2. Shell Scripts

### `bundles/local_observability_stack/bin/openclaw-observability-bridge`

**5 array expansion fixes**: `"${PASSTHROUGH[@]}"` → `${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}`

Same pattern applied to `args[@]` arrays. This is a bash `set -u` (nounset) compatibility fix. When `PASSTHROUGH` is an empty array, `"${PASSTHROUGH[@]}"` triggers an "unbound variable" error under `set -u` in bash < 4.4. The `${var[@]+"${var[@]}"}` idiom means "expand if set, otherwise expand to nothing" — safe under strict mode on all bash versions.

Affected lines: `compose up -d`, `compose down`, `compose down -v`, `compose logs` (2 instances), and the catch-all compose passthrough.

---

## 3. Python CLI — Config

### `cli/defenseclaw/config.py`

**`GuardrailConfig` dataclass** — new field:
```python
connector: str = "openclaw"  # openclaw | zeptoclaw | claudecode | codex
```

This is the Python-side mirror of the Go config's `guardrail.connector` field. Written by `defenseclaw setup guardrail --agent=<name>` and read by quickstart/doctor/setup commands to know which agent framework is active.

**`_merge_guardrail()`** — reads the new field from YAML:
```python
connector=raw.get("connector", "openclaw"),
```

Defaults to `"openclaw"` for backward compatibility with configs written before multi-connector support.

---

## 4. Python CLI — Commands

### `cli/defenseclaw/commands/cmd_quickstart.py`

**New `--agent` option**:
```python
@click.option("--agent", "agent_name",
    type=click.Choice(["openclaw", "zeptoclaw", "claudecode", "codex"]),
    default=None)
```

Allows `defenseclaw quickstart --agent=claudecode` to set the connector non-interactively.

**Step 3 now connector-aware**: Token auto-detection is only attempted for the `openclaw` connector (reads from `openclaw.json`). Other connectors use loopback auth or credentials set via `defenseclaw setup`.

**Step 4 now writes `gc.connector`**: The guardrail config receives the selected connector name. The OpenClaw config file check is now conditional — only performed when `connector == "openclaw"`. Other connectors don't need an `openclaw.json` to exist.

**Step 4 status message** updated from `"mode={mode}, scanner={scanner_mode}"` to include `"connector={connector}"`.

### `cli/defenseclaw/commands/cmd_doctor.py`

**3 changes** make doctor checks connector-aware:

1. **`_check_openclaw_gateway()`** — now only called when the active connector is `openclaw`. Other connectors manage their own gateway processes.

2. **`_fix_openclaw_token()`** — returns `("skip", "connector is {name}, not openclaw")` when a non-OpenClaw connector is active. Previously it would try to sync from `openclaw.json` regardless.

3. **`_fix_pristine_backup()`** — same skip-if-not-openclaw guard. The pristine backup is an OpenClaw config snapshot; irrelevant for other connectors.

All three use `getattr(cfg.guardrail, "connector", "openclaw") or "openclaw"` for safe access with backward-compat default.

### `cli/defenseclaw/commands/cmd_setup.py`

This file has the largest changes. The key theme: **connector-specific setup logic moves from Python to Go**.

**New: Connector metadata table** (`_CONNECTOR_META`, `_CONNECTOR_NAMES`):
```python
_CONNECTOR_META = {
    "openclaw": {"label": "OpenClaw", "description": "fetch interceptor + before_tool_call plugin", ...},
    "zeptoclaw": {"label": "ZeptoClaw", "description": "api_base redirect + before_tool hook", ...},
    "claudecode": {"label": "Claude Code", "description": "env var + PreToolUse hook script", ...},
    "codex": {"label": "Codex", "description": "env var + hook script + response-scan", ...},
}
```

Mirrors `internal/gateway/connector/*.go` — used for the interactive setup menu and status display.

**New: `_select_connector_interactive()`** — numbered menu for choosing the agent framework during `defenseclaw setup guardrail` (interactive mode).

**New: `_print_connector_info()`** — displays connector details (tool inspection mode, subprocess policy) after selection. Warns when a connector only supports response-scan mode.

**`setup guardrail` command** — new `--agent` flag:
```python
@click.option("--agent", "agent_name",
    type=click.Choice(_CONNECTOR_NAMES), default=None)
```

In non-interactive mode: `if agent_name: gc.connector = agent_name`.
In interactive mode: calls `_select_connector_interactive()`.

**`execute_guardrail_setup()` — massively simplified** (from ~100 lines to ~30):

Removed:
- Pre-flight check for OpenClaw config file existence
- `install_openclaw_plugin()` call (7 error paths)
- `patch_openclaw_config()` call with master key derivation
- Azure endpoint auto-detection and `.env` writing
- Sandbox-specific plugin install and ownership restoration
- `_find_plugin_source()` discovery

Replaced with:
- Print connector name/mode/policy from `_CONNECTOR_META`
- Print "Connector setup will run automatically when the gateway starts"
- Save config + write `guardrail_runtime.json`

**Why**: The Go gateway's `Connector.Setup()` method now handles all connector-specific work at sidecar boot: plugin install, config patching, hook scripts, subprocess shims. The Python CLI only needs to persist the user's connector choice.

**`_disable_guardrail()` — simplified** (from ~60 lines to ~20):

Removed:
- `restore_openclaw_config()` call
- `uninstall_openclaw_plugin()` call
- Manual-steps warning section
- `openclaw gateway restart` subprocess call

Replaced with:
- Print connector label
- Set `gc.enabled = False`, save config
- Print "Connector teardown will run when the gateway restarts"
- Print `defenseclaw-gateway restart` instruction

**`_restart_services()` — connector-aware**:

New signature: `_restart_services(data_dir, oc_host, oc_port, connector="openclaw")`

When `connector == "openclaw"`: calls new `_restart_openclaw_gateway()` then `_check_openclaw_gateway()`.
When any other connector: prints that traffic will route through defenseclaw-gateway proxy.

**New: `_restart_openclaw_gateway()`** — extracted from inline code. Runs `openclaw gateway restart` with a 60s timeout. Handles `FileNotFoundError` (CLI not on PATH) and `TimeoutExpired` gracefully.

**`_check_openclaw_gateway()`** — two label changes:
- `"openclaw gateway: monitoring..."` → `"agent gateway: monitoring..."`
- `"Start manually: openclaw gateway"` → `"Start manually: defenseclaw-gateway start"`
- Log path `"~/.openclaw/logs/"` → `"~/.defenseclaw/logs/"`

**Summary table in `setup_guardrail`** — now includes `guardrail.connector` as the first row:
```python
("guardrail.connector", f"{connector_label} ({gc.connector})"),
```

**`_interactive_guardrail_setup()`** — new Step 0 at the top:
```python
if agent_name and agent_name in _CONNECTOR_META:
    gc.connector = agent_name
else:
    gc.connector = _select_connector_interactive(gc.connector or "openclaw")
_print_connector_info(gc.connector)
```

---

## 5. Python CLI — Guardrail Module

### `cli/defenseclaw/guardrail.py`

**`install_openclaw_plugin()` — deleted** (~70 lines). Replaced with a 5-line comment:

```python
# NOTE: install_openclaw_plugin lived here previously. The gateway's
# OpenClawConnector.Setup() now installs the embedded plugin directly
# into ~/.openclaw/extensions/defenseclaw and patches openclaw.json on
# every sidecar boot, so there is no separate Python-side install step.
```

`uninstall_openclaw_plugin()` is kept — needed by `defenseclaw uninstall` which must revert the plugin even if the gateway is already gone.

---

## 6. Python Tests

### `cli/tests/test_guardrail.py`

**`TestInstallOpenclawPlugin` class — deleted** (~120 lines, 6 tests). These tested the now-removed Python-side plugin install. Replaced with a comment pointing to `TestOpenClaw_Setup_InstallsExtensionAndPatchesConfig` in the Go test suite.

**`TestInstallOpenclawPluginEdgeCases` class — deleted** (~60 lines, 4 tests). Same reason.

**`TestSetupGuardrailCommand`** — 7 assertion updates:

| Old assertion | New assertion | Why |
|---|---|---|
| `"Guardrail proxy is built into the Go binary"` | `"Connector: OpenClaw (openclaw)"` | Setup now shows connector info instead of generic proxy message |
| `"OpenClaw config not found"` | `"Connector: OpenClaw (openclaw)"` + `"Connector setup will run automatically"` | Setup no longer requires OpenClaw config to exist |
| `"OpenClaw config patched"` + `"Original model saved for revert"` | `"Connector: OpenClaw (openclaw)"` + `"Connector setup will run automatically"` | Config patching moved to Go gateway |
| Test renamed: `test_preflight_aborts_when_openclaw_config_missing` | `test_setup_succeeds_without_openclaw_config` | Setup succeeds without openclaw.json now |
| Test renamed: `test_openclaw_config_patched_output` | `test_setup_shows_connector_info` | Reflects new output |

**`TestRestartServicesRestartsAgentGateway`** — new test class (2 tests):

1. `test_openclaw_connector_runs_openclaw_gateway_restart` — verifies `_restart_services()` invokes `["openclaw", "gateway", "restart"]` when connector is `"openclaw"`.
2. `test_non_openclaw_connector_does_not_run_openclaw_gateway_restart` — verifies the openclaw restart is NOT invoked for connector `"zeptoclaw"`.

**`TestSetupGuardrailRestart`** — 2 tests rewritten:

| Old test | New test |
|---|---|
| `test_disable_restarts_openclaw` — asserted `subprocess.run` called openclaw restart | `test_disable_shows_restart_instructions` — asserts teardown message + `"defenseclaw-gateway restart"` in output |
| `test_disable_without_restart_shows_instructions` — asserted openclaw restart call | `test_disable_shows_connector_teardown_message` — asserts `"Connector teardown will run when the gateway restarts"` |

Both no longer mock `subprocess.run` — disable no longer calls external processes.

**`TestDisableGuardrailFlow`** — 4 tests rewritten:

| Old | New |
|---|---|
| `test_successful_restore_with_original_model` — checked openclaw.json was restored | `test_successful_disable_saves_config` — checks config saved + teardown message |
| `test_restore_failure_shows_manual_steps` — tested with `/nonexistent/openclaw.json` | `test_disable_works_without_openclaw_config` — disable no longer needs openclaw.json |
| `test_uninstalls_plugin_during_disable` — checked extensions dir was deleted | `test_disable_does_not_touch_extensions` — verifies extensions dir is NOT deleted (teardown runs at gateway restart) |
| `test_no_original_model_still_disables` — mocked subprocess | Same test, no longer mocks subprocess. Asserts teardown message. |

---

## 7. Go Config Package

### `internal/config/config.go`

**New `AgentHookConfig` struct**:
```go
type AgentHookConfig struct {
    Enabled                      bool
    Mode                         string
    ScanOnSessionStart           bool
    ScanOnStop                   bool
    ScanPaths                    []string
    ComponentScanIntervalMinutes int
}
```

Added to `Config` as `ClaudeCode` and `Codex` fields. Controls per-agent hook behavior (enabled state, mode inheritance, session scanning).

**`GuardrailConfig` — new `Connector` field**:
```go
Connector string `mapstructure:"connector" yaml:"connector,omitempty"`
```

Written by `defenseclaw setup`, read by sidecar to select the active connector from the registry.

**Gateway token rename**: `OPENCLAW_GATEWAY_TOKEN` → `DEFENSECLAW_GATEWAY_TOKEN`

- `defaultOpenClawGatewayTokenEnv` → `defaultGatewayTokenEnv` = `"DEFENSECLAW_GATEWAY_TOKEN"`
- New `legacyGatewayTokenEnv` = `"OPENCLAW_GATEWAY_TOKEN"`
- `ResolvedToken()` checks `DEFENSECLAW_GATEWAY_TOKEN` first, then falls back to `OPENCLAW_GATEWAY_TOKEN`
- When `TokenEnv` is set to a custom var, only that var is checked (no fallthrough)

**`setDefaults()`** — 2 changes:
- `guardrail.connector` defaults to `"openclaw"`
- `gateway.token_env` defaults to `"DEFENSECLAW_GATEWAY_TOKEN"` (was `"OPENCLAW_GATEWAY_TOKEN"`)

**Comment update**: `// Future: ClawNemoClaw, ClawOpenCode, ClawClaudeCode` → `// Future: ClawNemoClaw` (Claude Code and Codex are now implemented as connectors, not claw modes).

### `internal/config/config_test.go`

**2 new test cases** for `TestGatewayConfigResolvedToken`:

1. `"defenseclaw env takes priority over openclaw env"` — sets both env vars, expects `"new-style"` from `DEFENSECLAW_GATEWAY_TOKEN`.
2. `"empty defenseclaw env falls back to openclaw env"` — sets `DEFENSECLAW_GATEWAY_TOKEN=""` and `OPENCLAW_GATEWAY_TOKEN="legacy-token"`, expects `"legacy-token"`.

---

## 8. Go Gateway Core

### `internal/gateway/api.go`

**New mutex fields** on `APIServer`:
```go
claudeCodeMu                sync.Mutex
claudeCodeLastComponentScan time.Time
codexMu                     sync.Mutex
codexLastComponentScan      time.Time
```

These rate-limit component scanning — the mutex + timestamp prevent redundant scans when multiple `SessionStart` events fire in quick succession.

**New route registrations**:
```go
mux.HandleFunc("/api/v1/inspect/request", a.handleInspectRequest)
mux.HandleFunc("/api/v1/inspect/response", a.handleInspectResponse)
mux.HandleFunc("/api/v1/inspect/tool-response", a.handleInspectToolResponse)
mux.HandleFunc("/api/v1/claude-code/hook", a.handleClaudeCodeHook)
mux.HandleFunc("/api/v1/codex/hook", a.handleCodexHook)
```

5 new endpoints. The 3 inspect endpoints complement the existing `/api/v1/inspect/tool`. The 2 hook endpoints receive lifecycle events from Claude Code and Codex via their hook scripts.

### `internal/gateway/proxy.go`

**New `connector` field** on `GuardrailProxy`:
```go
connector connector.Connector
```

When non-nil, authentication and request signal extraction are delegated to the connector.

**`NewGuardrailProxy` signature** — new `conn connector.Connector` parameter. Injected by `sidecar.go:runGuardrail()`.

**Gateway token resolution** — now checks `DEFENSECLAW_GATEWAY_TOKEN` first:
```go
gatewayToken := ResolveAPIKey("DEFENSECLAW_GATEWAY_TOKEN", dotenvPath)
if gatewayToken == "" {
    gatewayToken = ResolveAPIKey("OPENCLAW_GATEWAY_TOKEN", dotenvPath)
}
```

Warning message updated from "OPENCLAW_GATEWAY_TOKEN is not set" to "no gateway token is set".

**New helper methods**:
- `connectorName()` — returns the active connector's name for telemetry labels; falls back to `"openclaw"`
- `shouldScanResponseToolCalls()` — always returns true (defense-in-depth: even pre-execution connectors get response scanning)

**Comment updates**: Removed OpenClaw-specific comments about `openclaw.json baseUrl from patch_openclaw_config`.

### `internal/gateway/sidecar.go`

**Connector lifecycle in `runGuardrail()`** (~45 new lines):

1. Create `connector.NewDefaultRegistry()` (registers 4 built-in connectors)
2. Discover external plugins from `s.cfg.PluginDir` if configured
3. Look up the configured connector name from `s.cfg.Guardrail.Connector`
4. Fall back to `"openclaw"` if the configured name isn't found
5. Build `SetupOpts` with data dir, proxy addr, API addr, and baked gateway token
6. Call `conn.Setup(ctx, setupOpts)` — this is where the connector installs hooks, patches configs, writes shim scripts
7. Pass `conn` to `NewGuardrailProxy()`

**Comment updates**: "OpenClaw gateway" → "agent gateway" throughout. `sandbox_ip`/`openclaw_port` → `sandbox_ip`/`gateway_port` in health details.

### `internal/gateway/connect_handler.go` (NEW)

**HTTP CONNECT tunnel handler** (~120 lines). Intercepts CONNECT requests for TLS tunneling:

1. Extracts target host from `r.Host` or `r.URL.Host`
2. Logs the tunnel to stderr and audit
3. Dials TCP to the target with 10s timeout
4. Hijacks the client connection
5. Sends `HTTP/1.1 200 Connection Established`
6. Relays bytes bidirectionally with `io.Copy` in two goroutines
7. Properly closes write sides of TCP connections

The tunnel is opaque (no TLS decryption). Enables agents that use `http_proxy` (like some Codex configurations) to route through DefenseClaw.

### `internal/gateway/egress.go`

Single comment change: `X-DC-Auth: Bearer <OPENCLAW_GATEWAY_TOKEN>` → `X-DC-Auth: Bearer <DEFENSECLAW_GATEWAY_TOKEN>`.

### `internal/gateway/health.go`

**New `ConnectorHealth` struct**:
```go
type ConnectorHealth struct {
    Name               string
    State              SubsystemState
    Since              time.Time
    ToolInspectionMode connector.ToolInspectionMode
    SubprocessPolicy   connector.SubprocessPolicy
    Requests           int64
    Errors             int64
    ToolInspections    int64
    ToolBlocks         int64
    SubprocessBlocks   int64
}
```

**5 atomic counters** on `SidecarHealth` (lock-free hot path):
```go
connRequests, connErrors, connToolInspections, connToolBlocks, connSubprocessBlocks atomic.Int64
```

**`SetConnector()`** — initializes connector health tracking at sidecar boot.

**5 `Record*()` methods** — increment atomic counters (called from proxy hot path).

**`Snapshot()`** — now includes connector health with live counter values in the health endpoint response.

### `internal/cli/sidecar.go`

**2 deprecation message updates**:
- `"OPENCLAW_GATEWAY_TOKEN"` → `"DEFENSECLAW_GATEWAY_TOKEN"` in the `--token` flag help text and the runtime deprecation warning.

### `internal/tui/setup.go`

**3 label/help text updates**:
- Gateway wizard: `"OPENCLAW_GATEWAY_TOKEN env"` → `"DEFENSECLAW_GATEWAY_TOKEN env"`
- Claw section help: removed mention of `"nemoclaw, opencode, claudecode"` as future modes (they're now connectors)
- Token Env hint: `"default OPENCLAW_GATEWAY_TOKEN"` → `"default DEFENSECLAW_GATEWAY_TOKEN"`

---

## 9. Go Hook Handlers (New)

### `internal/gateway/claude_code_hook.go` (NEW, ~687 lines)

Handles `POST /api/v1/claude-code/hook`. The Claude Code hook script (`claude-code-hook.sh`) posts lifecycle events here.

**Request struct** (`claudeCodeHookRequest`): 30+ fields covering all Claude Code event types — session metadata, tool call info, prompts, file paths, MCP server names, etc. The `Payload` field preserves the raw JSON for passthrough.

**Response struct** (`claudeCodeHookResponse`): `action` (allow/block), `raw_action`, `severity`, `reason`, `findings`, `mode`, `would_block`, `additional_context`, `claude_code_output` (Claude Code–specific response format).

**`handleClaudeCodeHook()`**: Parses JSON body → unmarshals to struct → calls `evaluateClaudeCodeHook()` → logs via audit → writes JSON response.

**`evaluateClaudeCodeHook()`** — the dispatch table:

| Event | Action |
|---|---|
| `SessionStart` | Component scanning (MCP servers, skills, CLAUDE.md) if configured |
| `UserPromptSubmit`, `UserPromptExpansion` | Prompt injection + data exfiltration scanning |
| `PreToolUse`, `PermissionRequest`, `PermissionDenied` | Tool policy enforcement (OPA + rule pack) |
| `PostToolUse`, `PostToolUseFailure`, `PostToolBatch` | Tool output scanning (secret/PII leakage) |
| `Stop`, `SubagentStop`, `SessionEnd` | Changed-file scanning via git diff |
| `InstructionsLoaded`, `ConfigChange`, `FileChanged` | File content scanning + prompt injection check |
| `TaskCreated`, `TaskCompleted`, `TeammateIdle`, `PreCompact`, `PostCompact`, `Elicitation`, `ElicitationResult`, `Notification` | Generic content scanning |

**Mode enforcement**: In `observe` mode, blocks are downgraded to allow (logged as `would_block=true`). In `action` mode, blocks are enforced for events that support it (checked via `claudeCodeCanEnforce()`).

**`claudeCodeOutput()`** — formats the response in Claude Code's expected hook output format:
- `PreToolUse` blocks → `permissionDecision: "deny"` with reason
- `PermissionRequest` blocks → `behavior: "deny"` with message
- Task events → `continue: false` with `stopReason`
- `Elicitation` → `action: "decline"`
- Non-blocking events with findings → `additionalContext` system message

### `internal/gateway/claude_code_hook_test.go` (NEW, ~110 lines)

Tests for the Claude Code hook handler:
- `TestClaudeCodeHook_AllowByDefault` — empty SessionStart returns allow
- `TestClaudeCodeHook_MethodNotAllowed` — GET returns 405
- `TestClaudeCodeHook_InvalidJSON` — malformed body returns 400
- `TestClaudeCodeHook_MissingEventName` — missing `hook_event_name` returns 400
- `TestClaudeCodeHook_PreToolUse_Allow` — safe tool call returns allow
- `TestClaudeCodeHook_ResponseStructure` — validates all response fields present

### `internal/gateway/codex_hook.go` (NEW, ~630 lines)

Same pattern as Claude Code hook, adapted for Codex's event model. Handles `POST /api/v1/codex/hook`. Same dispatch table structure but with Codex-specific event names and response formatting.

### `internal/gateway/codex_hook_test.go` (NEW, ~105 lines)

Parallel test suite to the Claude Code tests.

---

## 10. Go Inspection Endpoints (New)

### `internal/gateway/inspect_hooks.go` (NEW, ~277 lines)

**Three new inspection endpoints** that complement the existing `/api/v1/inspect/tool`:

**`handleInspectRequest()`** — `POST /api/v1/inspect/request`
- Called before a user query reaches the LLM
- Scans content via `ScanAllRules()` with direction `"user-request"`
- Builds verdict via `buildVerdict()` with direction `"prompt"`
- Logs to OTel (`RecordInspectEvaluation`, `RecordInspectLatency`) and audit
- Returns sanitized verdict (PII-redacted reasons)

**`handleInspectResponse()`** — `POST /api/v1/inspect/response`
- Called after the LLM returns a response
- Scans content with direction `"llm-response"` / `"completion"`
- Same OTel + audit + verdict pipeline

**`handleInspectToolResponse()`** — `POST /api/v1/inspect/tool-response`
- Called after a tool finishes execution, before the result is fed back to the LLM
- Accepts tool name, output (JSON), and exit code
- Scans content with direction `"{tool}-response"` / `"tool_response"`
- Same OTel + audit + verdict pipeline

**`buildVerdict()`** — shared helper:
- No findings → `{action: "allow", severity: "NONE"}`
- Findings with HIGH/CRITICAL severity → `action: "block"`
- Lower severity → `action: "alert"`
- Aggregates up to 5 reasons as `"matched: RULE-ID:Title, ..."`

### `internal/gateway/inspect_hooks_test.go` (NEW, ~258 lines)

Tests for all 3 inspection endpoints:
- Empty content returns allow
- Valid content triggers scanning
- Method not allowed (GET)
- Invalid JSON body
- Missing required fields
- Verdict structure validation

---

## 11. Go Connector Package (New)

### `internal/gateway/connector/connector.go` (NEW, ~110 lines)

**The core Connector interface**:
```go
type Connector interface {
    Name() string
    Description() string
    ToolInspectionMode() ToolInspectionMode
    SubprocessPolicy() SubprocessPolicy
    Setup(ctx context.Context, opts SetupOpts) error
    Teardown(ctx context.Context, opts SetupOpts) error
    Authenticate(r *http.Request) bool
    Route(r *http.Request, body []byte) (*ConnectorSignals, error)
}
```

**Type definitions**: `ToolInspectionMode` (pre-execution | response-scan | both), `SubprocessPolicy` (sandbox | shims | none).

**`ConnectorSignals`**: Raw signals extracted from an HTTP request — API key, model, upstream URL, body, streaming flag, headers to strip/add.

**`SetupOpts`**: Passed to Setup/Teardown — data dir, proxy address, API address, API token.

**Optional interfaces**: `CredentialSetter`, `HookEventHandler`, `ComponentScanner`, `StopScanner` — connectors implement these as needed.

### `internal/gateway/connector/openclaw.go` (NEW, ~335 lines)

The **OpenClaw connector** — wraps the existing fetch-interceptor plugin approach behind the Connector interface.

- `Setup()`: Copies embedded TS plugin files from `openclaw_extension/` to `~/.openclaw/extensions/defenseclaw/`, patches `openclaw.json` to register the plugin. Uses `//go:embed all:openclaw_extension` to bundle the plugin at compile time.
- `Teardown()`: Removes the plugin from OpenClaw's extensions directory and unregisters from `openclaw.json`.
- `Authenticate()`: Validates `X-DC-Auth` header against the gateway token.
- `Route()`: Extracts signals from `X-DC-Target-URL`, `X-AI-Auth`, and `X-DC-Model` headers (set by the fetch interceptor).

### `internal/gateway/connector/zeptoclaw.go` (NEW, ~270 lines)

The **ZeptoClaw connector**. Uses `api_base` redirect with `before_tool` hook.

- `Setup()`: Backs up existing `api_base` in ZeptoClaw config, patches it to point to the DefenseClaw proxy, installs `before_tool` hook.
- `Teardown()`: Restores original `api_base` from backup. **Bug fix**: previous version permanently lost the user's original `api_base`.
- `Authenticate()`: Validates `X-DC-Auth` header.
- `Route()`: Extracts signals from ZeptoClaw-specific headers.

### `internal/gateway/connector/claudecode.go` (NEW, ~450 lines)

The **Claude Code connector**. Uses environment variable override with PreToolUse/PostToolUse hook scripts.

- `Setup()`: Patches `~/.claude/settings.json` to register DefenseClaw hook scripts for 8 event types (`PreToolUse`, `PostToolUse`, `PreCompact`, `PostCompact`, `UserPromptSubmit`, `SessionStart`, `Stop`, `SubagentStop`). Sets up subprocess shims. Writes hook scripts to data dir.
- `Teardown()`: Removes only DefenseClaw's hooks from `settings.json` (preserves user's other hooks). Removes shim scripts.
- `Authenticate()`: Validates request.
- `Route()`: Extracts signals from `ANTHROPIC_BASE_URL`-style requests.
- `HandleHookEvent()`: Stub implementation (real inspection runs at gateway level in `claude_code_hook.go`).

**Bug fixes in this file**:
- `removeOwnedHooks()` now returns the truncated slice properly (was returning nil due to Go interface type assertion issue)
- Removed invalid `UserPromptExpansion` hook event that doesn't exist in Claude Code's hook system

### `internal/gateway/connector/codex.go` (NEW, ~220 lines)

The **Codex connector**. Same pattern as Claude Code, adapted for Codex's hook model.

### `internal/gateway/connector/helpers.go` (NEW, ~130 lines)

**Shared utilities** extracted from connector-specific files:

- `isChatPath()` — checks if a URL path is a chat completions endpoint. Was previously trapped in `openclaw.go`.
- `IsLoopback()` — checks if an address is loopback. **Bug fix**: now uses `net.SplitHostPort()` + `net.ParseIP().IsLoopback()` to handle IPv6 and port-suffixed addresses.
- Various string/path helpers used by multiple connectors.

### `internal/gateway/connector/registry.go` (NEW, ~160 lines)

**Connector registry** — thread-safe store for built-in and plugin connectors.

- `NewRegistry()`, `RegisterBuiltin()`, `RegisterPlugin()`
- `Get(name)` — searches builtins first, then plugins
- `GetAll(names)` — batch resolve with error on unknown names
- `Available()` — returns sorted metadata for the setup menu
- `NewDefaultRegistry()` — pre-loads all 4 built-in connectors
- `DiscoverPlugins(dir)` — scans for Go plugin `.so` files

### `internal/gateway/connector/plugin_loader.go` (NEW, ~100 lines)

Loads external connectors from Go plugin `.so` files. Looks for a `NewConnector() Connector` symbol in each plugin. Enables third-party connector distribution.

### `internal/gateway/connector/subprocess.go` (NEW, ~270 lines)

Subprocess enforcement for the `sandbox` policy. Installs PATH-based shim scripts that intercept `curl`, `wget`, `nc`, `ssh`, `pip`, `npm` and route them through DefenseClaw's inspection endpoints before allowing execution.

**Bug fix**: Non-curl shims now resolve `curl` from outside the shim directory (`PATH` manipulation) to avoid recursive self-calls when curl is also shimmed.

### `internal/gateway/connector/connector_test.go` (NEW, ~2150 lines)

Comprehensive test suite for all 4 connectors:

- Registry tests (register, get, discover, available)
- Per-connector tests: Setup, Teardown, Authenticate, Route
- Hook script installation/removal verification
- Settings.json patching (only DefenseClaw hooks, preserve user hooks)
- Subprocess shim installation
- `removeOwnedHooks` slice handling (the critical bug fix)
- ZeptoClaw api_base backup/restore
- OpenClaw embedded plugin installation
- Edge cases: missing files, permission errors, concurrent access

---

## 12. Hook & Shim Shell Scripts (New)

### `internal/gateway/connector/hooks/` (6 scripts)

**`claude-code-hook.sh`** — Called by Claude Code's hook system. Posts the event JSON to `http://127.0.0.1:{port}/api/v1/claude-code/hook`. Checks the response action — exits 0 (allow) or 2 (block). **Bug fix**: Uses `--arg` instead of `--argjson` for tool output (handles arbitrary strings, not just JSON).

**`codex-hook.sh`** — Same pattern for Codex.

**`inspect-request.sh`** — Called before user queries reach the LLM. Posts to `/api/v1/inspect/request`.

**`inspect-response.sh`** — Called after LLM response. Posts to `/api/v1/inspect/response`.

**`inspect-tool.sh`** — Called before tool execution. Posts to `/api/v1/inspect/tool`.

**`inspect-tool-response.sh`** — Called after tool execution. Posts to `/api/v1/inspect/tool-response`.

All scripts fail-open by default (`|| { exit 0 }`) — if the gateway is unreachable, the agent continues.

### `internal/gateway/connector/shims/` (6 scripts)

**`curl.sh`**, **`wget.sh`**, **`nc.sh`**, **`ssh.sh`**, **`pip.sh`**, **`npm.sh`**

PATH-based shim scripts for subprocess enforcement. Each:
1. Extracts the target host/URL from arguments
2. Posts an inspection request to DefenseClaw
3. If allowed, resolves the real binary from outside the shim directory and exec's it
4. If blocked, prints an error and exits non-zero

**Bug fix**: Non-curl shims (`nc.sh`, `wget.sh`, `ssh.sh`, `pip.sh`, `npm.sh`) resolve `curl` by stripping the shim directory from `PATH` before looking it up, preventing recursive double-inspection.

---

## 13. Documentation (New)

### `docs/CONNECTOR-COMMIT-SUMMARY.md` (NEW, ~117 lines)

Executive summary of the connector architecture: problem, what changed (8 sections), outcomes, remaining work.

### `docs/CONNECTOR-REMAINING-FIXES.md` (NEW, ~196 lines)

Tracks 6 remaining findings from the code review that need design decisions:
- #6 HIGH: Only 8 of 22+ techspec events registered
- #7 HIGH: HandleHookEvent stub (always returns allow)
- #12 MEDIUM: InstallScope + FailClosed config not implemented
- #8 MEDIUM: X-DC-Auth Bearer prefix inconsistency
- #9 MEDIUM: No file locking on config read-modify-write
- #14 MEDIUM: Global test override variables

---

## 14. Dependency Updates

### `pyproject.toml`

New override dependencies for litellm 1.83.0 → 1.83.7 (GHSA-xqmj-j6mv-4862):

```toml
"litellm==1.83.7",
"click>=8.1.8",           # litellm 1.83.7 pins 8.1.8, scanner pins 8.3.1
"openai>=2.15.0",         # litellm 1.83.7 pins 2.30.0, scanner pins 2.15.0
"python-dotenv>=1.0.1",   # litellm pins 1.0.1, scanner pins 1.2.1
"python-multipart>=0.0.26", # CVE-2026-40347 fixed in 0.0.26
```

litellm 1.83.1+ switched from flexible dependency ranges to exact pins, creating conflicts with cisco-ai-skill-scanner's own pins. The `>=` overrides let uv resolve to any version that satisfies both.

### `uv.lock`

Auto-regenerated by `uv lock` to reflect litellm 1.83.0 → 1.83.7 and all transitive dependency changes.
