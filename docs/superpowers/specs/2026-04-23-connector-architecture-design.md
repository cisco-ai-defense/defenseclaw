# DefenseClaw Connector Architecture — Tech Spec

> **Status:** PARTIAL (~90% implemented via PR #194). All 4 connectors operational with full Setup/Teardown, authentication, proxy routing, managed backups, and hook event processing. Remaining: PermissionRequest not in Codex hookGroups, InstallScope/FailClosed config fields (#12), test override globals cleanup (#14).

**Date**: 2026-04-23
**Status**: Draft
**Scope**: Adapter layer — LLM traffic routing, tool call inspection, agent hook event handling, component scanning (skills, plugins, MCP), CodeGuard file scanning, subprocess enforcement, and per-agent OTel telemetry (metrics, traces, W3C propagation). Core inspection engine, OPA policy, PII redaction, audit sinks, and Bifrost provider resolution are unchanged.

---

## 1. Problem

DefenseClaw's guardrail proxy is hardcoded to OpenClaw in three ways:

1. **LLM traffic**: The proxy reads `X-DC-Target-URL` and `X-AI-Auth` headers set by OpenClaw's fetch interceptor plugin. Other agents can't send LLM traffic through the proxy.

2. **Tool call inspection**: OpenClaw's TypeScript plugin calls `/api/v1/inspect/tool` directly. Claude Code and Codex use shell script hooks that call agent-specific endpoints (`/api/v1/claude-code/hook`, `/api/v1/codex/hook`). ZeptoClaw uses `before_tool` config hooks. Each pattern has different request/response contracts, event sets, and component scanning paths — but they all feed into the same `inspectToolPolicy()` and `inspectMessageContent()` core functions.

3. **Component scanning**: Claude Code scans `~/.claude/` (skills, plugins, agents, commands, MCP configs, rules). Codex scans `~/.codex/` (skills, plugins, MCP configs). OpenClaw and ZeptoClaw have no component scanning. The scanning logic is duplicated per agent with hardcoded paths.

4. **Subprocess enforcement**: PATH shims and sandbox policies are written by each connector's Setup, but the plumbing is identical.

**Goal**: Refactor into a connector-based architecture where each connector owns **all** security surfaces for its agent:

| Surface | What it protects |
|---------|-----------------|
| **LLM traffic routing** | Intercepts agent→LLM HTTP requests, routes through guardrail proxy |
| **Tool call inspection** | Gates tool execution before/after it runs (pre-tool, post-tool) |
| **Agent hook events** | Handles agent lifecycle events (session start/stop, prompts, file changes, config changes) |
| **Component scanning** | Scans agent-specific skills, plugins, MCP servers, config files |
| **CodeGuard file scanning** | Scans git-changed files at session stop |
| **Subprocess enforcement** | Restricts shell commands spawned by plugins/extensions |

---

## 2. Design Principles

1. **Setup-driven, not detection-driven.** The user tells DefenseClaw which agents they're using.
2. **Multiple connectors active simultaneously.** Config is `connectors: [claudecode, codex]`. Each connector independently owns its agent's security surfaces. From the connector's `ConnectorSignals` output onwards, the proxy pipeline is fully agent-agnostic.
3. **Connector = setup + runtime translation + hook handling.** Setup wires the agent. Route translates HTTP requests into `ConnectorSignals`. Hook handler processes agent lifecycle events. Everything downstream of `ConnectorSignals` is shared.
4. **Shared inspection core.** All connectors feed into `inspectToolPolicy()` and `inspectMessageContent()`. Agent-specific logic is only: (a) inbound parsing, (b) outbound response formatting, (c) component paths, (d) event set.
5. **Each connector knows its agent.** OpenClaw knows fetch interceptors. Claude Code knows `~/.claude/settings.json` hooks. No generic abstraction that fits nothing well.
6. **Graceful degradation.** Not all agents support all surfaces. The connector declares its capabilities; DefenseClaw provides the best coverage possible.
7. **Independent lifecycle.** Each connector has its own Setup/Teardown, config section, OTel namespace, and backup files. Enabling or disabling one connector does not affect others.

---

## 3. Four Agents — Capability Matrix

| Capability | OpenClaw | ZeptoClaw | Claude Code | Codex |
|------------|----------|-----------|-------------|-------|
| **LLM traffic routing** | Fetch interceptor headers | `api_base` config patch | `ANTHROPIC_BASE_URL` env | `OPENAI_BASE_URL` env |
| **Pre-tool inspection** | Plugin calls REST API | `before_tool` config hook | `PreToolUse` hook event | `PreToolUse` hook event |
| **Post-tool inspection** | Plugin calls REST API | `after_tool` config hook | `PostToolUse` hook event | `PostToolUse` hook event |
| **Prompt inspection** | Plugin calls REST API | `before_request` config hook | `UserPromptSubmit` event | `UserPromptSubmit` event |
| **Response inspection** | Plugin calls REST API | `after_response` config hook | Response-scan in proxy | Response-scan in proxy |
| **Component scanning** | No | No | Yes (6 types) | Yes (3 types) |
| **CodeGuard (changed files)** | No | No | Yes (Stop event) | Yes (Stop event) |
| **Agent hook events** | No (plugin-driven) | No (config hooks) | Yes (20+ events) | Yes (6 events) |
| **Subprocess enforcement** | Sandbox + shims | Sandbox + shims | Sandbox + shims | Sandbox + shims |

**Key distinction**: OpenClaw and ZeptoClaw use **generic inspection endpoints** (`/api/v1/inspect/tool`, `/api/v1/inspect/request`, etc.) — their plugins/hooks call these directly. Claude Code and Codex use **agent-specific hook endpoints** (`/api/v1/claude-code/hook`, `/api/v1/codex/hook`) that receive structured lifecycle events and dispatch internally to the same `inspectToolPolicy()` / `inspectMessageContent()` core.

---

## 4. Connector Interface

**File**: `internal/gateway/connector/connector.go`

```go
package connector

import (
    "context"
    "net/http"
)

type ToolInspectionMode string

const (
    ToolModePreExecution ToolInspectionMode = "pre-execution"
    ToolModeResponseScan ToolInspectionMode = "response-scan"
    ToolModeBoth         ToolInspectionMode = "both"
)

type SubprocessPolicy string

const (
    SubprocessSandbox SubprocessPolicy = "sandbox"
    SubprocessShims   SubprocessPolicy = "shims"
    SubprocessNone    SubprocessPolicy = "none"
)

// ConnectorSignals holds raw signals extracted from an inbound HTTP request.
type ConnectorSignals struct {
    RawAPIKey       string
    RawModel        string
    RawUpstream     string
    RawBody         []byte
    Stream          bool
    PassthroughMode bool
    ConnectorName   string
    StripHeaders    []string
    ExtraHeaders    map[string]string
}

// SetupOpts is passed to Setup/Teardown during `defenseclaw setup`.
type SetupOpts struct {
    DataDir     string // ~/.defenseclaw/
    ProxyAddr   string // 127.0.0.1:4000 (guardrail proxy — LLM traffic)
    APIAddr     string // 127.0.0.1:18970 (API server — inspection endpoints)
    Interactive bool
}

// Connector is the contract every agent framework adapter implements.
type Connector interface {
    Name() string
    Description() string
    ToolInspectionMode() ToolInspectionMode
    SubprocessPolicy() SubprocessPolicy

    // Setup wires all security surfaces for the agent.
    Setup(ctx context.Context, opts SetupOpts) error
    Teardown(ctx context.Context, opts SetupOpts) error

    // Authenticate checks inbound proxy credentials.
    Authenticate(r *http.Request) bool

    // Route extracts raw signals from the inbound HTTP request.
    Route(r *http.Request, body []byte) (*ConnectorSignals, error)
}

// CredentialSetter — optional, connectors implement to receive
// gateway token and master key at sidecar boot.
type CredentialSetter interface {
    SetCredentials(gatewayToken, masterKey string)
}

// HookEventHandler — optional, connectors that handle agent lifecycle
// events (Claude Code, Codex) implement this. The gateway registers
// the hook endpoint automatically.
type HookEventHandler interface {
    // HookEndpointPath returns the path for this agent's hook endpoint.
    // e.g. "/api/v1/claude-code/hook", "/api/v1/codex/hook"
    HookEndpointPath() string

    // HandleHookEvent processes a lifecycle event from the agent.
    // The gateway calls this from the HTTP handler.
    HandleHookEvent(ctx context.Context, payload []byte) ([]byte, error)
}

// ComponentScanner — optional, connectors that support scanning
// agent-specific skills, plugins, MCP servers implement this.
type ComponentScanner interface {
    // ComponentTargets returns scan targets grouped by type.
    // Keys: "skill", "plugin", "mcp", "agent", "command", "config"
    ComponentTargets(cwd string) map[string][]string

    // SupportsComponentScanning returns true if the agent has
    // discoverable skill/plugin/MCP artifacts.
    SupportsComponentScanning() bool
}

// StopScanner — optional, connectors that scan git-changed files
// at session stop implement this.
type StopScanner interface {
    // SupportsStopScan returns true if the agent sends Stop events
    // that should trigger CodeGuard scanning of changed files.
    SupportsStopScan() bool
}
```

---

## 5. Built-in Connectors

### 5a. OpenClaw Connector

**File**: `internal/gateway/connector/openclaw.go`

**Inspection pattern**: Plugin-driven. OpenClaw's TypeScript plugin calls DefenseClaw's REST inspection endpoints directly. No agent-specific hook endpoint needed.

| Surface | Implementation |
|---------|---------------|
| **LLM traffic** | Fetch interceptor patches `globalThis.fetch()` → adds `X-DC-Target-URL` + `X-AI-Auth` headers. Connector extracts these in `Route()`. |
| **Pre-tool inspection** | Plugin calls `POST /api/v1/inspect/tool` before each tool. |
| **Post-tool inspection** | Plugin calls `POST /api/v1/inspect/tool-response` after each tool. |
| **Prompt inspection** | Plugin calls `POST /api/v1/inspect/request` before LLM call. |
| **Response inspection** | Plugin calls `POST /api/v1/inspect/response` after LLM response. |
| **Component scanning** | Not supported — no discoverable component directories. |
| **CodeGuard (stop)** | Not supported — no Stop lifecycle event. |
| **Subprocess enforcement** | Sandbox (Linux) or shims (macOS). |

**Interfaces implemented**: `Connector`, `CredentialSetter`

**Setup**:
1. Write generic hook scripts to `~/.defenseclaw/hooks/` (inspect-tool.sh, inspect-request.sh, etc.)
2. Setup subprocess enforcement (sandbox policy + PATH shims)

**Auth**: `X-DC-Auth` header vs gateway token, `Authorization` vs master key, loopback fallback.

**Route**: `X-DC-Target-URL` → `RawUpstream`, `X-AI-Auth` → `RawAPIKey`, body → `RawModel`, `Stream`. SSRF check on upstream URL. Non-chat paths → `PassthroughMode: true`.

### 5b. ZeptoClaw Connector

**File**: `internal/gateway/connector/zeptoclaw.go`

**Inspection pattern**: Config-driven hooks. ZeptoClaw's `config.json` supports `before_tool`, `before_request`, `after_response`, and `after_tool` hooks that point to DefenseClaw's generic inspection scripts.

| Surface | Implementation |
|---------|---------------|
| **LLM traffic** | Patches `~/.zeptoclaw/config.json` → `api_base` → `http://{ProxyAddr}/c/zeptoclaw`. |
| **Pre-tool inspection** | `before_tool` hook → `inspect-tool.sh` → `POST /api/v1/inspect/tool`. |
| **Post-tool inspection** | `after_tool` hook → `inspect-tool-response.sh` → `POST /api/v1/inspect/tool-response`. |
| **Prompt inspection** | `before_request` hook → `inspect-request.sh` → `POST /api/v1/inspect/request`. |
| **Response inspection** | `after_response` hook → `inspect-response.sh` → `POST /api/v1/inspect/response`. |
| **Component scanning** | Not supported — ZeptoClaw has no standardized skill/plugin directories. |
| **CodeGuard (stop)** | Not supported — no Stop lifecycle event. |
| **Subprocess enforcement** | Sandbox (Linux) or shims (macOS). |

**Interfaces implemented**: `Connector`, `CredentialSetter`

**Setup**:
1. Read `~/.zeptoclaw/config.json`, backup original providers + hooks
2. Patch `api_base` to proxy address
3. Patch hooks to point to DefenseClaw hook scripts
4. Write generic hook scripts to `~/.defenseclaw/hooks/`
5. Setup subprocess enforcement

**Auth**: Same as OpenClaw (X-DC-Auth, master key, loopback fallback).

**Route**: `Authorization` → `RawAPIKey`, body → `RawModel`. No upstream URL header — proxy core resolves from model name via `inferProvider()`.

### 5c. Claude Code Connector

**File**: `internal/gateway/connector/claudecode.go`

**Inspection pattern**: Agent hook events. Claude Code pipes structured JSON hook events to a shell script's stdin and reads the response from stdout. DefenseClaw handles all 20+ events via `/api/v1/claude-code/hook`.

| Surface | Implementation |
|---------|---------------|
| **LLM traffic** | `ANTHROPIC_BASE_URL` env var → `http://{ProxyAddr}/c/claudecode`. |
| **Pre-tool inspection** | `PreToolUse` / `PermissionRequest` hook events → `inspectToolPolicy()`. Can block tool execution. |
| **Post-tool inspection** | `PostToolUse` / `PostToolUseFailure` / `PostToolBatch` events → `inspectMessageContent(direction=tool_result)`. |
| **Prompt inspection** | `UserPromptSubmit` / `UserPromptExpansion` events → `inspectMessageContent(direction=prompt)`. |
| **Response inspection** | Response-scan in proxy (LLM response body). |
| **Component scanning** | `SessionStart` event → scan `~/.claude/` and workspace `.claude/` dirs for: skills, plugins, agents, commands, MCP configs, rules, settings. |
| **CodeGuard (stop)** | `Stop` / `SubagentStop` / `SessionEnd` events → scan git-changed files via CodeGuard. |
| **File change scanning** | `FileChanged` / `InstructionsLoaded` / `ConfigChange` events → CodeGuard scan of specific file. |
| **Subprocess enforcement** | Sandbox (Linux) or shims (macOS). |

**Interfaces implemented**: `Connector`, `CredentialSetter`, `HookEventHandler`, `ComponentScanner`, `StopScanner`

**Setup** (4 surfaces):
1. Write env override: `ANTHROPIC_BASE_URL=http://{ProxyAddr}/c/claudecode` to `~/.defenseclaw/claudecode_env.sh` + `claudecode.env`
2. Write all hook scripts to `~/.defenseclaw/hooks/` (includes `claude-code-hook.sh`)
3. Patch `~/.claude/settings.json` to register DefenseClaw hooks for all events
4. Setup subprocess enforcement

**Hook event → inspection mapping**:

| Event | Inspection | Can enforce? |
|-------|-----------|-------------|
| `SessionStart` | Component scan (skills, plugins, MCP, agents, commands, configs) | No (info only) |
| `UserPromptSubmit` | `inspectMessageContent(direction=prompt)` | Yes |
| `UserPromptExpansion` | `inspectMessageContent(direction=prompt)` | Yes |
| `PreToolUse` | `inspectToolPolicy(direction=tool_call)` | Yes |
| `PermissionRequest` | `inspectToolPolicy(direction=tool_call)` | Yes |
| `PermissionDenied` | `inspectToolPolicy(direction=tool_call)` | No |
| `PostToolUse` | `inspectMessageContent(direction=tool_result)` | Yes |
| `PostToolUseFailure` | `inspectMessageContent(direction=tool_result)` | No |
| `PostToolBatch` | `inspectMessageContent(direction=tool_result)` | Yes |
| `Stop` / `SubagentStop` / `SessionEnd` | CodeGuard scan of git-changed files | Yes (Stop, SubagentStop) |
| `InstructionsLoaded` / `ConfigChange` / `FileChanged` | CodeGuard scan of specific file, or content inspection | Yes (ConfigChange) |
| `TaskCreated` / `TaskCompleted` / `TeammateIdle` | `inspectMessageContent(direction=prompt)` | Yes |
| `PreCompact` / `PostCompact` | `inspectMessageContent(direction=prompt)` | Yes (PreCompact) |
| `Elicitation` / `ElicitationResult` | `inspectMessageContent(direction=prompt)` | Yes |
| `Notification` | `inspectMessageContent(direction=prompt)` | No |

**Component scanning targets** (`~/.claude/` + workspace `.claude/`):

| Type | Paths scanned | Scanner used |
|------|--------------|-------------|
| `skill` | `skills/*/` | SkillScannerFromLLM |
| `plugin` | `plugins/*/` | PluginScanner |
| `mcp` | `settings.json`, `.mcp.json` | MCPScannerFromLLM |
| `agent` | `agents/*/` | CodeGuardScanner |
| `command` | `commands/*/` | CodeGuardScanner |
| `config` | `settings.json`, `rules/*/`, `CLAUDE.md`, `.claude.json` | CodeGuardScanner |

**Hook response format** — agent-specific output payloads:
- `PreToolUse` block → `{hookSpecificOutput: {permissionDecision: "deny", permissionDecisionReason: "..."}}`
- `PermissionRequest` block → `{hookSpecificOutput: {decision: {behavior: "deny", message: "..."}}}`
- `TaskCreated/TaskCompleted/TeammateIdle` block → `{continue: false, stopReason: "..."}`
- `Elicitation` block → `{hookSpecificOutput: {action: "decline", content: {}}}`
- `CwdChanged/FileChanged` → `{watchPaths: [...]}`
- Allow with context → `{hookSpecificOutput: {hookEventName: "...", additionalContext: "..."}}`

**Auth**: Loopback trust (Claude Code is local). Gateway token + master key supported.

**Route**: `x-api-key` → `RawAPIKey`, body → `RawModel`. Sets `ExtraHeaders: {"anthropic-version": "..."}`.

### 5d. Codex Connector

**File**: `internal/gateway/connector/codex.go`

**Inspection pattern**: Agent hook events (same pattern as Claude Code, smaller event set). Codex pipes JSON hook events to a shell script via stdin.

| Surface | Implementation |
|---------|---------------|
| **LLM traffic** | `OPENAI_BASE_URL` env var → `http://{ProxyAddr}/c/codex`. |
| **Pre-tool inspection** | `PreToolUse` / `PermissionRequest` events → `inspectToolPolicy()`. |
| **Post-tool inspection** | `PostToolUse` event → `inspectMessageContent(direction=tool_result)`. |
| **Prompt inspection** | `UserPromptSubmit` event → `inspectMessageContent(direction=prompt)`. |
| **Response inspection** | Response-scan in proxy. |
| **Component scanning** | `SessionStart` event → scan `~/.codex/` and workspace dirs for: skills, plugins, MCP configs. |
| **CodeGuard (stop)** | `Stop` event → scan git-changed files via CodeGuard. |
| **Subprocess enforcement** | Sandbox (Linux) or shims (macOS). |

**Interfaces implemented**: `Connector`, `CredentialSetter`, `HookEventHandler`, `ComponentScanner`, `StopScanner`

**Setup** (4 surfaces):
1. Write env override: `OPENAI_BASE_URL=http://{ProxyAddr}/c/codex` to `~/.defenseclaw/codex_env.sh` + `codex.env`
2. Write all hook scripts to `~/.defenseclaw/hooks/` (includes `codex-hook.sh`)
3. Setup subprocess enforcement

**Hook event → inspection mapping**:

| Event | Inspection | Can enforce? |
|-------|-----------|-------------|
| `SessionStart` | Component scan (skills, plugins, MCP) | No (info only) |
| `UserPromptSubmit` | `inspectMessageContent(direction=prompt)` | Yes |
| `PreToolUse` | `inspectToolPolicy(direction=tool_call)` | Yes |
| `PermissionRequest` | `inspectToolPolicy(direction=tool_call)` | Yes |
| `PostToolUse` | `inspectMessageContent(direction=tool_result)` | Yes |
| `Stop` | CodeGuard scan of git-changed files | Yes |

**Component scanning targets** (`~/.codex/` + workspace):

| Type | Paths scanned | Scanner used |
|------|--------------|-------------|
| `skill` | `skills/*/` | SkillScannerFromLLM |
| `plugin` | `plugins/*/`, `plugins/cache/*/` | PluginScanner |
| `mcp` | `config.toml`, `.mcp.json` | MCPScannerFromLLM |

**Hook response format** — agent-specific output payloads:
- `PreToolUse` block → `{hookSpecificOutput: {permissionDecision: "deny", permissionDecisionReason: "..."}}`
- `PermissionRequest` block → `{hookSpecificOutput: {decision: {behavior: "deny", message: "..."}}}`
- `Stop` → `{continue: true}` or `{decision: "block", reason: "..."}`

**Auth**: Loopback trust. Gateway token + master key supported.

**Route**: `Authorization` → `RawAPIKey`, body → `RawModel`. Standard OpenAI-format.

---

## 6. Hook Event Handler Architecture

### Current state (duplicated)

Today, `claude_code_hook.go` and `codex_hook.go` are standalone handler files in `internal/gateway/`. Each has:
- A request struct (~30 fields for Claude Code, ~15 for Codex)
- A response struct
- An `evaluateXxxHook()` function that switches on event name
- An `xxxOutput()` function that builds agent-specific response payloads
- Component scanning functions with hardcoded paths
- Mode resolution functions
- ~600-700 lines each

### Target state (connector-owned)

The `HookEventHandler` interface moves the agent-specific logic into the connector, while the shared inspection functions (`inspectToolPolicy`, `inspectMessageContent`, component scanners) stay in the gateway.

**Gateway side** (shared, in `internal/gateway/`):
```go
// registerHookEndpoint is called by the sidecar for connectors
// that implement HookEventHandler.
func (a *APIServer) registerHookEndpoint(c connector.HookEventHandler) {
    path := c.HookEndpointPath()
    a.mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        body, _ := io.ReadAll(r.Body)
        resp, err := c.HandleHookEvent(r.Context(), body)
        if err != nil {
            a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
            return
        }
        w.Header().Set("Content-Type", "application/json")
        w.Write(resp)
    })
}
```

**Connector side** — `HandleHookEvent` is the single entry point:
```go
func (c *ClaudeCodeConnector) HandleHookEvent(ctx context.Context, payload []byte) ([]byte, error) {
    // 1. Parse agent-specific request format
    // 2. Switch on event name → call shared inspection functions
    // 3. Apply mode logic (observe vs action)
    // 4. Build agent-specific response format
    // 5. Return JSON bytes
}
```

**What stays in `internal/gateway/`** (shared for all agents):
- `inspectToolPolicy()` — rule-based tool call inspection
- `inspectMessageContent()` — message/prompt content inspection
- `ScanAllRules()` — rule engine
- `scanner.NewSkillScannerFromLLM()`, `scanner.NewPluginScanner()`, `scanner.NewMCPScannerFromLLM()` — component scanners
- `scanner.NewCodeGuardScanner()` — static analysis scanner
- `buildVerdict()` — verdict construction from findings
- `redaction.ForSinkReason()` — PII redaction
- `gitChangedFiles()`, `runGitList()` — git diff utilities

**What moves into the connector** (agent-specific):
- Request/response struct definitions
- Event → inspection dispatch logic
- Agent-specific response formatting (hookSpecificOutput payloads)
- Component path resolution (`~/.claude/` vs `~/.codex/`)
- Mode resolution (reads agent-specific config section)
- Enforceable event gating

### Shared inspection contract

All connectors call into the gateway's inspection layer via a shared interface:

```go
// InspectionAPI is the gateway-side interface that connectors use to
// invoke shared inspection logic. Passed to HandleHookEvent via context
// or constructor injection.
type InspectionAPI interface {
    InspectToolPolicy(req *ToolInspectRequest) *ToolInspectVerdict
    InspectMessageContent(req *ToolInspectRequest) *ToolInspectVerdict
    ScanComponent(ctx context.Context, component, target string) (*scanner.ScanResult, error)
    ScanCodeGuard(ctx context.Context, target string) (*scanner.ScanResult, error)
    LogScan(ctx context.Context, result *scanner.ScanResult)
    LogAction(ctx context.Context, subsystem, event, detail string)
}
```

This decouples the connector from `APIServer` internals while still giving it access to the full inspection pipeline.

---

## 7. Component Scanning Architecture

### Scan triggers

| Trigger | Agent | What is scanned |
|---------|-------|----------------|
| `SessionStart` event (if `scan_on_session_start: true`) | Claude Code, Codex | All component types for that agent |
| `Stop` / `SessionEnd` event (if `scan_on_stop: true`) | Claude Code, Codex | Git-changed files via CodeGuard |
| `FileChanged` / `InstructionsLoaded` event | Claude Code | Specific file via CodeGuard |
| Periodic (every N minutes, configurable) | Claude Code, Codex | All component types (rate-limited) |

### Component types and scanners

| Component type | Scanner | What it detects |
|----------------|---------|----------------|
| `skill` | `SkillScannerFromLLM` | Dangerous imports, network calls, file ops in skill code |
| `plugin` | `PluginScanner` | Malicious plugin manifests, capability escalation |
| `mcp` | `MCPScannerFromLLM` | Dangerous tool/resource exposure in MCP server configs |
| `agent` | `CodeGuardScanner` | Code vulnerabilities in agent definitions |
| `command` | `CodeGuardScanner` | Code vulnerabilities in command scripts |
| `config` | `CodeGuardScanner` | Injected instructions, prompt injection in config files |

### Rate limiting

Each agent's component scan is rate-limited independently:
```yaml
claude_code:
  component_scan_interval_minutes: 60   # default
codex:
  component_scan_interval_minutes: 60
```

The gateway tracks `lastComponentScan` per agent (mutex-protected timestamp). If a `SessionStart` arrives within the interval, the scan is skipped unless `scan_components: true` is explicitly set in the event payload.

---

## 8. Mode Resolution and Enforcement

### Mode chain

```
Per-agent config (claude_code.mode / codex.mode)
    ↓ if "inherit" or empty
Global config (guardrail.mode)
    ↓ if empty
Default: "observe"
```

### Enforcement behavior

| Mode | Verdict="block" | Verdict="alert" | Response field |
|------|-----------------|-----------------|----------------|
| `observe` | `action=allow`, `would_block=true` | `action=allow` | `additional_context` explains what would happen |
| `action` | `action=block` (if enforceable event) | `action=allow` | Agent blocks the operation |

### Non-enforceable events

Some events can't block even in action mode (e.g. `Notification`, `PostToolUseFailure`, `PermissionDenied`). The connector's `canEnforce(event)` function gates this:
- Non-enforceable + verdict="block" → `action=allow`, `would_block=true`
- Enforceable + mode="action" + verdict="block" → `action=block`

---

## 9. Connector Registry

**File**: `internal/gateway/connector/registry.go`

```go
type Registry struct {
    builtins map[string]Connector
    plugins  map[string]Connector
}

func NewRegistry() *Registry
func (r *Registry) Available() []ConnectorInfo
func (r *Registry) Get(name string) (Connector, bool)
func (r *Registry) GetAll(names []string) ([]Connector, error)
func (r *Registry) DiscoverPlugins(dir string) error
```

Built-in connectors registered at init:
```go
func NewRegistry() *Registry {
    r := &Registry{builtins: map[string]Connector{}}
    r.builtins["openclaw"] = NewOpenClawConnector()
    r.builtins["zeptoclaw"] = NewZeptoClawConnector()
    r.builtins["claudecode"] = NewClaudeCodeConnector()
    r.builtins["codex"] = NewCodexConnector()
    return r
}
```

`GetAll()` resolves the config's `connectors` list to concrete instances at sidecar boot. Each connector is independent — the registry is just a lookup table.

---

## 10. Configuration

### config.yaml

```yaml
guardrail:
  enabled: true
  connectors:                    # list of active connectors (replaces single "connector" field)
    - claudecode
    - codex
  mode: observe                  # global default mode

claude_code:
  enabled: true
  mode: inherit                  # "observe", "action", or "inherit" (uses guardrail.mode)
  scan_on_session_start: true
  scan_on_stop: true
  scan_paths: []                 # additional paths to scan at Stop
  component_scan_interval_minutes: 60
  install_scope: user            # "user" (~/.claude/) or "repo" (.claude/)
  fail_closed: false             # block operations if gateway unreachable

codex:
  enabled: true
  mode: inherit
  scan_on_session_start: true
  scan_on_stop: true
  scan_paths: []
  component_scan_interval_minutes: 60
  install_scope: user
  fail_closed: false
```

**Multi-connector config rules:**
- `guardrail.connectors` is a list. Order determines `Match()` priority (first match wins).
- Each listed connector must have a matching per-agent config section with `enabled: true`.
- A connector in the list with `enabled: false` is skipped at boot (logged as warning).
- OpenClaw and ZeptoClaw don't need agent-specific config sections — they use `guardrail.mode` directly.
- Per-agent config sections for unlisted connectors are ignored (no wasted resources).

**Backward compatibility**: If `guardrail.connector` (singular, string) is present instead of `connectors` (list), it is treated as a single-element list: `connectors: [<value>]`. This preserves existing configs.

### Backup files

| Connector | Backup file | What is backed up |
|-----------|-------------|-------------------|
| OpenClaw | `~/.defenseclaw/openclaw_backup.json` | Extension list |
| ZeptoClaw | `~/.defenseclaw/zeptoclaw_backup.json` | Original providers + hooks from config.json |
| Claude Code | `~/.defenseclaw/claudecode_backup.json` | Original hooks from settings.json, previous ANTHROPIC_BASE_URL |
| Codex | `~/.defenseclaw/codex_backup.json` | Previous OPENAI_BASE_URL |

---

## 11. Setup CLI Flow

### Interactive setup (multi-agent)

```
$ defenseclaw setup

  DefenseClaw — AI Agent Security Harness

  Which agent frameworks do you want to protect? (comma-separated, or 'all')

    1. OpenClaw     — fetch interceptor plugin
    2. ZeptoClaw    — api_base redirect + config hooks
    3. Claude Code  — env var + settings.json hooks (20+ events, component scanning)
    4. Codex        — env var + hook script (6 events, component scanning)

  Selection: 3,4

  Setting up Claude Code connector...
  ✓ Wrote ANTHROPIC_BASE_URL=http://127.0.0.1:4000/c/claudecode to ~/.defenseclaw/claudecode_env.sh
  ✓ Wrote hook scripts to ~/.defenseclaw/hooks/
  ✓ Patched ~/.claude/settings.json (22 hook events registered)
  ✓ Saved original settings to ~/.defenseclaw/claudecode_backup.json
  ✓ Installed PATH shims for: curl, wget, ssh, nc, pip, npm

  Setting up Codex connector...
  ✓ Wrote OPENAI_BASE_URL=http://127.0.0.1:4000/c/codex to ~/.defenseclaw/codex_env.sh
  ✓ Wrote hook scripts to ~/.defenseclaw/hooks/  (codex-hook.sh)
  ✓ Installed PATH shims for: curl, wget, ssh, nc, pip, npm  (shared, already exist)

  DefenseClaw is ready.  Active connectors: claudecode, codex
  Source env files before running your agents:
    source ~/.defenseclaw/claudecode_env.sh   # for Claude Code
    source ~/.defenseclaw/codex_env.sh        # for Codex
```

Each connector's Setup runs independently. Shared resources (hook scripts, shims) are idempotent — the second connector's Setup reuses existing files.

### Non-interactive

```bash
# Single connector
defenseclaw setup --agents claudecode

# Multiple connectors
defenseclaw setup --agents claudecode,codex
```

### Teardown

```bash
# Teardown all active connectors
defenseclaw setup --disable
```

Each connector's Teardown runs independently — restores its own backup files, env overrides, and config patches. Shared resources (shims, generic hook scripts) are removed when the last connector is torn down.

---

## 12. Sidecar Initialization

**File**: `internal/gateway/sidecar.go` — `runGuardrail()`

```go
registry := connector.NewRegistry()

// Resolve all connectors listed in config
connectors, err := registry.GetAll(cfg.Guardrail.Connectors)
if err != nil {
    return fmt.Errorf("resolve connectors: %w", err)
}

for _, c := range connectors {
    if cs, ok := c.(connector.CredentialSetter); ok {
        cs.SetCredentials(gatewayToken, masterKey)
    }
    if hh, ok := c.(connector.HookEventHandler); ok {
        apiServer.RegisterHookEndpoint(hh)
    }
    if otelProvider != nil {
        otelProvider.RegisterAgentMetrics(c.Name())
    }
}

proxy := NewGuardrailProxy(cfg, ..., connectors)
```

The loop wires each connector independently — credentials, hook endpoints, OTel. From the proxy's `ConnectorSignals` output onwards, the pipeline is agent-agnostic.

---

## 13. Proxy Changes

### GuardrailProxy struct

```go
type GuardrailProxy struct {
    // ... existing fields ...
    connectors map[string]connector.Connector   // keyed by name
}
```

### Connector-prefixed routing

Each connector's Setup already controls the URL the agent sends to (env var, config patch, or fetch interceptor). The proxy uses a **path prefix** to identify which connector owns each request — no format detection or header sniffing needed.

Each connector's Setup sets the agent's base URL to include a `/c/<connector-name>` prefix:

```
Claude Code → ANTHROPIC_BASE_URL=http://proxy:4000/c/claudecode
              → SDK sends to /c/claudecode/v1/messages

Codex       → OPENAI_BASE_URL=http://proxy:4000/c/codex
              → SDK sends to /c/codex/v1/chat/completions

ZeptoClaw   → api_base: http://proxy:4000/c/zeptoclaw
              → sends to /c/zeptoclaw/v1/messages (or /v1/chat/completions)

OpenClaw    → fetch interceptor sets X-DC-Target-URL, base URL includes /c/openclaw
              → sends to /c/openclaw/...
```

This avoids ambiguity entirely — even if multiple connectors use the same LLM provider (e.g., ZeptoClaw and Claude Code both using Anthropic), the path prefix identifies the connector.

### handleChatCompletion

```go
body, _ := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))

// Extract connector name from path prefix: /c/<name>/v1/...
connectorName, realPath := stripConnectorPrefix(r.URL.Path)
r.URL.Path = realPath

c := p.connectors[connectorName]
if c == nil {
    writeOpenAIError(w, http.StatusBadRequest, "unknown connector: "+connectorName)
    return
}

if !c.Authenticate(r) {
    writeAuthError(w)
    return
}

cs, err := c.Route(r, body)
if err != nil {
    writeOpenAIError(w, http.StatusBadRequest, err.Error())
    return
}

// existing provider resolution — unchanged
provider := resolveProvider(cs.RawUpstream, cs.RawModel, cs.RawAPIKey)

// existing pipeline: inspect → forward via Bifrost → inspect → respond
```

```go
func stripConnectorPrefix(path string) (name, realPath string) {
    // /c/claudecode/v1/messages → "claudecode", "/v1/messages"
    if strings.HasPrefix(path, "/c/") {
        rest := path[3:]
        if i := strings.IndexByte(rest, '/'); i > 0 {
            return rest[:i], rest[i:]
        }
    }
    return "", path
}
```

No format detection, no request fingerprinting. The connector's Setup controls the URL, the proxy reads the prefix, `Route()` sees the clean path. From `ConnectorSignals` onwards everything is agent-agnostic.

### Telemetry

All hardcoded `"openclaw"` strings become `cs.ConnectorName`.

---

## 14. Provider Resolution (Unchanged)

```
cs.RawUpstream → inferProviderFromURL() → "openai"
cs.RawModel    → splitModel()           → "anthropic" / "claude-sonnet-4-20250514"
cs.RawAPIKey   → inferProvider()         → "sk-ant-*" → "anthropic"
    ↓
NewProviderWithBase() → bifrostProvider → upstream
```

No changes to `provider_bifrost.go`, `getBifrostClient()`, `mapProviderKey()`, `toBifrostChatRequest()`.

---

## 15. API Endpoints Summary

| Endpoint | Used by | Purpose |
|----------|---------|---------|
| `POST /api/v1/inspect/tool` | OpenClaw plugin, ZeptoClaw hook, shims | Pre-execution tool inspection |
| `POST /api/v1/inspect/request` | OpenClaw plugin, ZeptoClaw hook | Pre-LLM prompt inspection |
| `POST /api/v1/inspect/response` | OpenClaw plugin, ZeptoClaw hook | Post-LLM response inspection |
| `POST /api/v1/inspect/tool-response` | OpenClaw plugin, ZeptoClaw hook | Post-tool output inspection |
| `POST /api/v1/claude-code/hook` | Claude Code hook script | All 20+ Claude Code lifecycle events |
| `POST /api/v1/codex/hook` | Codex hook script | All 6 Codex lifecycle events |

OpenClaw and ZeptoClaw use the four generic `/api/v1/inspect/*` endpoints.
Claude Code and Codex use their own `/api/v1/<agent>/hook` endpoints which internally dispatch to the same `inspectToolPolicy()` and `inspectMessageContent()` functions.

Generic `/api/v1/inspect/*` endpoints are always available. Agent-specific hook endpoints are registered at boot for each active connector that implements `HookEventHandler`.

---

## 16. Hook Scripts

Written to `~/.defenseclaw/hooks/` during Setup.

| Script | Used by | What it calls |
|--------|---------|--------------|
| `inspect-tool.sh` | ZeptoClaw `before_tool`, shims | `POST /api/v1/inspect/tool` |
| `inspect-request.sh` | ZeptoClaw `before_request` | `POST /api/v1/inspect/request` |
| `inspect-response.sh` | ZeptoClaw `after_response` | `POST /api/v1/inspect/response` |
| `inspect-tool-response.sh` | ZeptoClaw `after_tool` | `POST /api/v1/inspect/tool-response` |
| `claude-code-hook.sh` | Claude Code settings.json hooks | `POST /api/v1/claude-code/hook` |
| `codex-hook.sh` | Codex hook config | `POST /api/v1/codex/hook` |

All scripts fail open if DefenseClaw is unreachable (exit 0). Block = exit 2.

---

## 17. Health & Observability

### /health endpoint

```json
{
  "connectors": [
    {
      "name": "claudecode",
      "state": "running",
      "tool_inspection": "both",
      "component_scanning": true,
      "stop_scanning": true,
      "hook_events": 22,
      "subprocess_policy": "shims",
      "install_scope": "user",
      "fail_closed": false
    },
    {
      "name": "codex",
      "state": "running",
      "tool_inspection": "both",
      "component_scanning": true,
      "stop_scanning": true,
      "hook_events": 6,
      "subprocess_policy": "shims",
      "install_scope": "user",
      "fail_closed": false
    }
  ]
}
```

### CLI status

```
$ defenseclaw status

  Connectors (2 active):

    claudecode
      LLM routing:    ANTHROPIC_BASE_URL → 127.0.0.1:4000/c/claudecode
      Tool inspection: pre-execution hooks + response-scan
      Hook events:     22 registered in ~/.claude/settings.json
      Components:      skills, plugins, MCP, agents, commands, configs
      Subprocess:      PATH shims (macOS)
      Install scope:   user (~/.claude/)
      Fail closed:     no

    codex
      LLM routing:    OPENAI_BASE_URL → 127.0.0.1:4000/c/codex
      Tool inspection: pre-execution hooks + response-scan
      Hook events:     6 registered via codex-hook.sh
      Components:      skills, plugins, MCP
      Subprocess:      PATH shims (macOS)
      Install scope:   user
      Fail closed:     no

  Guardrail:  running, mode=observe
  Telemetry:  OTel enabled
    Metrics:   defenseclaw.{claude_code,codex}.hook.{invocations,latency,blocks,would_blocks,component_scans}
    Traces:    defenseclaw.{claude_code,codex}.hook spans (W3C propagation)
```

---

## 18. File Layout

```
internal/gateway/connector/
    connector.go                 # Interface, signals, optional interfaces
    registry.go                  # Registry (built-in connectors)
    helpers.go                   # ExtractAPIKey, ParseModelFromBody, IsLoopback, isChatPath
    subprocess.go                # Shim scripts, hook scripts, sandbox policy, enforcement
    openclaw.go                  # OpenClaw connector
    zeptoclaw.go                 # ZeptoClaw connector
    claudecode.go                # Claude Code connector (Route + Setup + HookEventHandler)
    codex.go                     # Codex connector (Route + Setup + HookEventHandler)
    hooks/
        inspect-tool.sh          # Generic pre-tool inspection
        inspect-request.sh       # Generic pre-request inspection
        inspect-response.sh      # Generic post-response inspection
        inspect-tool-response.sh # Generic post-tool inspection
        claude-code-hook.sh      # Claude Code event forwarder
        codex-hook.sh            # Codex event forwarder
    shims/
        curl.sh, wget.sh, ssh.sh, nc.sh, pip.sh, npm.sh

internal/gateway/
    inspect.go                   # Core: inspectToolPolicy, inspectMessageContent, ScanAllRules
    inspect_hooks.go             # Generic inspection handlers (/api/v1/inspect/*)
    api.go                       # Route registration (including hook endpoints)

internal/config/config.go        # AgentHookConfig, Config.ClaudeCode, Config.Codex
```

---

## 19. Backward Compatibility

| Scenario | Impact |
|----------|--------|
| Existing `connector: openclaw` (singular string) | Treated as `connectors: ["openclaw"]` — same behavior, same headers, same auth |
| `OPENCLAW_GATEWAY_TOKEN` env var | Still works — OpenClaw connector reads it |
| No `connector` or `connectors` field in config | Defaults to `connectors: ["openclaw"]` |
| Existing Claude Code hook setup | If `claude_code.enabled: false`, hook endpoint returns allow for all events |
| Existing Codex hook setup | Same — `codex.enabled: false` → all allow |
| New `connectors: [claudecode, codex]` (list) | Both connectors set up, both hook endpoints registered, proxy routes by request format |

---

## 20. Implementation Order

| Step | Files | Risk | Depends on |
|------|-------|------|-----------|
| 1. Connector interface + optional interfaces | `connector.go` | Low | — |
| 2. Shared helpers | `helpers.go` | Low | 1 |
| 3. OpenClaw connector | `openclaw.go` | Medium | 1, 2 |
| 4. ZeptoClaw connector | `zeptoclaw.go` | Medium | 1, 2 |
| 5. Claude Code connector (Route + Setup + patchClaudeCodeHooks) | `claudecode.go` | Medium | 1, 2 |
| 6. Claude Code HookEventHandler | `claudecode.go` | Medium | 5 |
| 7. Codex connector (Route + Setup) | `codex.go` | Medium | 1, 2 |
| 8. Codex HookEventHandler | `codex.go` | Medium | 7 |
| 9. Registry (`GetAll`) | `registry.go` | Low | 1, 3-8 |
| 10. Config fields (`connectors` list, `AgentHookConfig` + `InstallScope` + `FailClosed`, backward compat for singular `connector`) | `config.go` | Low | — |
| 11. OTel per-agent metrics + spans | `telemetry/metrics.go`, `telemetry/runtime.go` | Medium | 10 |
| 12. OTel W3C trace propagation | `telemetry/provider.go` | Low | 11 |
| 13. Refactor proxy.go (connector map + `resolveConnector`) | `proxy.go` | **High** | 3, 9, 10 |
| 14. Sidecar initialization (multi-connector loop) | `sidecar.go` | Medium | 9, 11, 13 |
| 15. Health reporting (array of connectors) | `health.go`, `api.go` | Low | 13 |
| 16. Setup CLI (`--agents` multi-select) | `cli/setup.go` | Medium | 9 |
| 17. Tests (hook eval, registry, setup, OTel, auth) | `*_test.go` | Medium | all |

Steps 1-2 first. Steps 3-8 can proceed in parallel. Steps 11-12 (OTel) can proceed in parallel with steps 3-8. Step 13 is the critical path.

---

## 21. OTel Telemetry

DefenseClaw emits per-agent metrics, traces, and W3C context propagation through the existing `internal/telemetry/` package. The connector architecture preserves agent-agnostic instrumentation — metrics and spans are namespaced per connector name.

### 21a. Per-Agent Metrics

**File**: `internal/telemetry/metrics.go`

Each connector that implements `HookEventHandler` gets five metrics. The metric names use the connector's `Name()` to namespace:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `defenseclaw.<agent>.hook.invocations` | Counter | `event`, `action`, `mode` | Total hook invocations |
| `defenseclaw.<agent>.hook.latency` | Histogram | `event` | Hook evaluation latency (ms) |
| `defenseclaw.<agent>.blocks` | Counter | `event`, `severity` | Actual blocks (action mode) |
| `defenseclaw.<agent>.would_blocks` | Counter | `event`, `severity` | Would-blocks (observe mode) |
| `defenseclaw.<agent>.component_scans` | Counter | `component`, `result` | Component scan results |

Where `<agent>` is `claude_code`, `codex`, etc.

**Registration** — metrics are created at sidecar boot for each active connector:

```go
func (t *Telemetry) RegisterAgentMetrics(agentName string) {
    prefix := "defenseclaw." + agentName
    t.hookInvocations[agentName] = t.meter.Int64Counter(prefix + ".hook.invocations")
    t.hookLatency[agentName] = t.meter.Float64Histogram(prefix + ".hook.latency")
    t.blocks[agentName] = t.meter.Int64Counter(prefix + ".blocks")
    t.wouldBlocks[agentName] = t.meter.Int64Counter(prefix + ".would_blocks")
    t.componentScans[agentName] = t.meter.Int64Counter(prefix + ".component_scans")
}
```

With multiple connectors, the sidecar calls `RegisterAgentMetrics()` in a loop:

```go
for _, c := range connectors {
    otelProvider.RegisterAgentMetrics(c.Name())
}
```

This creates independent metric series per agent — e.g., `defenseclaw.claude_code.blocks` and `defenseclaw.codex.blocks` are separate counters.

**Recording** — called from the hook handler after evaluation:

```go
func (t *Telemetry) RecordHook(ctx context.Context, agent, event, action, severity, mode string, wouldBlock bool, latencyMs float64) {
    t.hookInvocations[agent].Add(ctx, 1,
        metric.WithAttributes(
            attribute.String("event", event),
            attribute.String("action", action),
            attribute.String("mode", mode),
        ))
    t.hookLatency[agent].Record(ctx, latencyMs,
        metric.WithAttributes(attribute.String("event", event)))
    if action == "block" {
        t.blocks[agent].Add(ctx, 1,
            metric.WithAttributes(
                attribute.String("event", event),
                attribute.String("severity", severity),
            ))
    }
    if wouldBlock {
        t.wouldBlocks[agent].Add(ctx, 1,
            metric.WithAttributes(
                attribute.String("event", event),
                attribute.String("severity", severity),
            ))
    }
}

func (t *Telemetry) RecordComponentScan(ctx context.Context, agent, component, result string) {
    t.componentScans[agent].Add(ctx, 1,
        metric.WithAttributes(
            attribute.String("component", component),
            attribute.String("result", result),
        ))
}
```

### 21b. Per-Agent Trace Spans

**File**: `internal/telemetry/runtime.go`

Each hook evaluation emits a trace span with structured attributes:

```go
func (t *Telemetry) EmitHookSpan(ctx context.Context, agent, event, action, severity, mode string, wouldBlock bool, durationMs float64) error {
    spanName := "defenseclaw." + agent + ".hook"
    _, span := t.tracer.Start(ctx, spanName)
    defer span.End()

    span.SetAttributes(
        attribute.String("defenseclaw.agent", agent),
        attribute.String("defenseclaw.hook_event", event),
        attribute.String("defenseclaw.action", action),
        attribute.String("defenseclaw.severity", severity),
        attribute.String("defenseclaw.mode", mode),
        attribute.Bool("defenseclaw.would_block", wouldBlock),
        attribute.Float64("defenseclaw.duration_ms", durationMs),
    )

    if action == "block" || wouldBlock {
        span.SetStatus(codes.Error, "block or would_block")
    } else {
        span.SetStatus(codes.Ok, "")
    }
    return nil
}
```

### 21c. Handler Integration Pattern

The hook handler in each connector instruments every evaluation:

```go
start := time.Now()
resp := c.evaluateHookEvent(ctx, req)
elapsedMs := float64(time.Since(start).Milliseconds())

if c.otel != nil {
    c.otel.RecordHook(ctx, c.Name(), req.HookEventName, resp.Action, resp.Severity, resp.Mode, resp.WouldBlock, elapsedMs)
    _ = c.otel.EmitHookSpan(ctx, c.Name(), req.HookEventName, resp.Action, resp.Severity, resp.Mode, resp.WouldBlock, elapsedMs)
}
```

Component scans also emit telemetry:

```go
if c.otel != nil {
    c.otel.RecordComponentScan(ctx, c.Name(), component, status)
}
```

### 21d. W3C Trace Context Propagation

**File**: `internal/telemetry/provider.go`

The OTel provider initializes W3C trace context propagation so that spans from the hook shell scripts (via `traceparent` header in curl calls) are linked to the gateway-side spans:

```go
otel.SetTextMapPropagator(propagation.TraceContext{})
```

The hook scripts pass `traceparent` if the `TRACEPARENT` env var is set:

```bash
if [ -n "$TRACEPARENT" ]; then
  EXTRA_HEADERS="-H traceparent:$TRACEPARENT"
fi
```

### 21e. Lifecycle and Diagnostic Events

The hook handlers emit structured lifecycle and diagnostic log entries (via `emitLifecycle()` and `emitDiagnostic()` helpers) for session-level events that don't pass through the inspection pipeline:

```go
emitLifecycle(ctx, connectorName, "session_start", map[string]string{
    "cwd": req.CWD,
    "session_id": req.SessionID,
})

emitDiagnostic(ctx, connectorName, "component_scan", map[string]string{
    "component": component,
    "status": status,
})
```

These feed into the audit log sink (JSONL, webhooks) without going through the guardrail engine.

---

## 22. PR #140 Reusability Analysis

PR #140 (`codex/defenseclaw-codex-integration`) implements Claude Code and Codex hook handling on a separate branch. This section documents what to reuse and what to adapt for the connector architecture.

### 22a. What to Reuse Directly

| Component | PR #140 File | Target in Connector Architecture |
|-----------|-------------|----------------------------------|
| Hook evaluation logic | `claude_code_hook.go` (692 lines) | Move into `ClaudeCodeConnector.HandleHookEvent()` |
| Hook evaluation logic | `codex_hook.go` (613 lines) | Move into `CodexConnector.HandleHookEvent()` |
| OTel metrics definitions | `telemetry/metrics.go` | Generalize to per-agent registration (§21a) |
| OTel span emitters | `telemetry/runtime.go` | Generalize to agent-parameterized spans (§21b) |
| W3C trace propagation | `telemetry/provider.go` | Take as-is |
| Claude Code hook tests | `claude_code_hook_test.go` (194 lines) | Adapt assertions for connector response format |
| Codex hook tests | `codex_hook_test.go` (202 lines) | Adapt assertions for connector response format |

### 22b. What to Adapt (Not Take As-Is)

| Component | Issue | Adaptation |
|-----------|-------|-----------|
| `EmitCodexHookSpan()` / `EmitClaudeCodeHookSpan()` | Hardcoded per-agent methods | Replace with single `EmitHookSpan(agent, ...)` |
| `RecordCodexHook()` / `RecordClaudeCodeHook()` | Hardcoded per-agent methods | Replace with single `RecordHook(agent, ...)` |
| `CodexConfig` / `ClaudeCodeConfig` structs | Separate struct per agent | Merge into shared `AgentHookConfig` with `InstallScope` and `FailClosed` fields |
| Python CLI hook bridge (`cmd_claude_code.py`) | Shell→Python→HTTP chain | Keep shell script bridge (`claude-code-hook.sh`) as primary; document Python bridge as optional alternative for `FailClosed` support |
| Python CLI settings.json patching (`cmd_setup_claude_code.py`) | 350 lines of Python | Port to Go in `ClaudeCodeConnector.patchClaudeCodeHooks()` |

### 22c. Config Field Additions from PR #140

PR #140 adds two fields to per-agent config that are missing from our `AgentHookConfig`:

```go
type AgentHookConfig struct {
    Enabled                      bool     `mapstructure:"enabled"`
    Mode                         string   `mapstructure:"mode"`
    ScanOnSessionStart           bool     `mapstructure:"scan_on_session_start"`
    ScanOnStop                   bool     `mapstructure:"scan_on_stop"`
    ScanPaths                    []string `mapstructure:"scan_paths"`
    ComponentScanIntervalMinutes int      `mapstructure:"component_scan_interval_minutes"`
    // Added from PR #140:
    InstallScope                 string   `mapstructure:"install_scope"`  // "user" or "repo"
    FailClosed                   bool     `mapstructure:"fail_closed"`   // block on gateway unreachable
}
```

| Field | Values | Purpose |
|-------|--------|---------|
| `InstallScope` | `"user"` (default), `"repo"` | Whether hooks are installed in `~/.claude/settings.json` (user-wide) or `.claude/settings.json` (repo-specific). Affects Claude Code and Codex setup paths. |
| `FailClosed` | `false` (default) | When `true`, the hook script exits non-zero if DefenseClaw is unreachable, causing the agent to block the operation. Default is fail-open (exit 0 on unreachable). |

These fields are agent-agnostic — every connector's `AgentHookConfig` gets them, but only connectors that patch config files (Claude Code, ZeptoClaw) or register hooks (Claude Code, Codex) use `InstallScope`. `FailClosed` applies to any connector with hook scripts.

### 22d. Settings.json Patching Reference (from PR #140 Python CLI)

PR #140's `cmd_setup_claude_code.py` (350 lines) patches `~/.claude/settings.json` to register DefenseClaw hooks. The Go connector needs to port this logic. Key details:

**27 Claude Code events registered** (grouped by hook type):

| Hook type | Events |
|-----------|--------|
| `PreToolUse` | `Bash`, `Read`, `Edit`, `Write`, `Agent`, `WebFetch`, `WebSearch`, `NotebookEdit`, `Skill`, `ToolSearch` |
| `PostToolUse` | (all of the above) |
| `PreCompact` | (ungrouped) |
| `PostCompact` | (ungrouped) |
| `UserPromptSubmit` | (ungrouped) |
| `UserPromptExpansion` | (ungrouped) |
| `SessionStart` | (ungrouped) |
| `Stop` | (ungrouped) |
| `SubagentStop` | (ungrouped) |

**Hook entry structure** in `settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Edit|Write|Agent|WebFetch|WebSearch|NotebookEdit|Skill|ToolSearch",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/defenseclaw/hooks/claude-code-hook.sh",
            "timeout": 30000
          }
        ]
      }
    ]
  }
}
```

**Ownership protocol** — how DefenseClaw identifies its own hooks for safe removal:

```python
def _is_owned_hook(hook_entry):
    """A hook belongs to DefenseClaw if its command path contains 'defenseclaw'."""
    if isinstance(hook_entry, dict):
        for h in hook_entry.get("hooks", []):
            if "defenseclaw" in h.get("command", ""):
                return True
    return False
```

The Go `patchClaudeCodeHooks()` must:
1. Read `~/.claude/settings.json` (or repo `.claude/settings.json` if `InstallScope == "repo"`)
2. Remove any existing DefenseClaw-owned hooks (idempotent re-setup)
3. Add hook entries for all event groups with matchers and timeouts
4. Write back the file preserving non-DefenseClaw hooks
5. Save the original hooks to backup for teardown

### 22e. Hook Script Bridge Options

Two bridge patterns exist for getting agent events to DefenseClaw:

| Pattern | File | How it works | Pros | Cons |
|---------|------|-------------|------|------|
| **Shell script** (current) | `hooks/claude-code-hook.sh` | `cat` stdin → `curl` to gateway → parse JSON → exit code | Simple, no dependencies, embedded via `go:embed` | No correlation headers, fail-open only |
| **Python CLI** (PR #140) | `cmd_claude_code.py` | `sys.stdin` → `requests.post()` → parse → exit code | `FailClosed` support, correlation headers (`X-DC-Correlation-ID`), payload normalization | Requires Python, separate install |

**Recommendation**: Keep the shell script as the default bridge (zero dependencies, works everywhere). Add `FailClosed` support to the shell script by checking the curl exit code:

```bash
if [ "$FAIL_CLOSED" = "true" ]; then
    RESULT=$(curl ... -d "$PAYLOAD") || exit 2  # block on unreachable
else
    RESULT=$(curl ... -d "$PAYLOAD") || exit 0  # fail open
fi
```

The Python CLI bridge remains available as an optional alternative for environments that need correlation headers or payload normalization.

### 22f. Test Coverage Plan (from PR #140 Tests)

PR #140 includes test files that validate hook evaluation logic. These tests should be adapted for the connector architecture:

| PR #140 Test | Lines | Tests | Adaptation |
|-------------|-------|-------|-----------|
| `claude_code_hook_test.go` | 194 | Observe mode (allow+context), Action mode (block response), Disabled (bypass), Component scan targets | Move to `connector/claudecode_test.go`, test `HandleHookEvent()` interface |
| `codex_hook_test.go` | 202 | Observe mode, Action mode, Disabled, Component scan targets | Move to `connector/codex_test.go`, test `HandleHookEvent()` interface |

**Additional tests to write**:
- Registry: `Get()` returns correct connector, `GetAll()` resolves list, unknown name returns error
- Setup/Teardown: env files, hook scripts, backup files created/removed per connector
- Settings.json patching: hooks added, idempotent re-setup, teardown restores original
- OTel: metrics recorded with correct per-agent labels, spans emitted with correct attributes
- Mode resolution: inherit → global, per-agent override, default observe
- Auth: gateway token, master key, loopback, reject unauthorized
- Config backward compat: singular `connector: openclaw` treated as `connectors: ["openclaw"]`
- Proxy `resolveConnector`: correct format → connector mapping

---

## 23. What This Spec Does NOT Cover

These are explicitly out of scope — no changes needed:

- **Inspection engine** (rule matching, CodeGuard, LLM-based scanning logic)
- **Provider resolution** (inferProviderFromURL, splitModel, inferProvider, providers.json)
- **Bifrost SDK** (provider routing, auth headers, format translation, streaming)
- **Audit logging** (audit store, sinks, JSONL, webhooks)
- **OPA policy engine** (evaluate, reload, firewall rules)
- **PII redaction** (redaction package, reveal header)
- **Watcher subsystem** (file watcher, enforcer, quarantine)
- **External Go plugins** (deferred — can add `DiscoverPlugins()` later)
