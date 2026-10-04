# MyAgent — Native macOS Agent App with Hermes Backend

> Design spec for renaming Motive → MyAgent and replacing OpenCode with Hermes
> as the agent backend, fully integrated with DefenseClaw IT Governed mode.

## Status: Design

---

## 1. Overview

**MyAgent** is a native macOS menu-bar application (forked from [Motive](https://github.com/geezerrrr/motive))
that provides a Spotlight-like command interface for an AI agent. The agent runs
in the background, executes tasks autonomously, and surfaces native macOS popups
when it needs approval.

**Key change**: Replace OpenCode (Go binary) with Hermes (Python agent) as the
backend agent framework. Hermes is already installed and configured by DefenseClaw's
IT Governed mode, with hardened Docker sandbox, MCP tools, and guardrails.

### Architecture

```
MyAgent (macOS SwiftUI app)
  │
  │  Option+Space → command bar
  │  Native popups for approvals
  │
  ├── spawns → Hermes Agent (Python, already installed by defenseclaw setup it-governed)
  │               │
  │               ├── LLM calls → LiteLLM:4001 (DefenseClaw gateway)
  │               │                  ├── Semantic Router → best model
  │               │                  └── Circuit API (gpt-5-5, o3, claude-sonnet-4-6, etc.)
  │               │
  │               ├── MCP tools → LiteLLM:4001/mcp/ (gateway MCP)
  │               │                  ├── Jira/Confluence (98 tools)
  │               │                  ├── Outlook/Calendar (9 tools)
  │               │                  └── (extensible)
  │               │
  │               ├── Terminal → Docker sandbox (hardened, no host access)
  │               │
  │               └── DefenseClaw hooks → guardrail inspection
  │
  └── reads → ~/.defenseclaw/.env (gateway token, auto-configured)
```

### What stays from Motive
- SwiftUI menu-bar app shell
- Command bar (Option+Space hotkey)
- Drawer UI (conversation view)
- Native macOS permission popups
- Trust levels (Careful/Balanced/YOLO)
- Settings window structure
- Skill browser
- Scheduled tasks
- Design system (Aurora colors, typography)

### What changes
- Branding: Motive → **MyAgent**
- Agent backend: OpenCode (Go) → **Hermes** (Python)
- Default provider: Claude → **DefenseClaw** (LiteLLM:4001)
- API key: Keychain → auto-read from `~/.defenseclaw/.env`
- Config dir: `~/.motive/` → `~/.myagent/`
- Skills dir: Motive skills → Hermes skills (`~/.hermes/skills/`)
- Bundle ID: `com.velvet.motive` → `com.cisco.myagent`

---

## 2. Hermes Integration Protocol

### 2.1 How Motive talks to OpenCode (current)

```
Motive → spawn `opencode serve --port 0` → parse stdout for port
Motive → REST POST /session → create session
Motive → REST POST /session/{id}/prompt → send user message
Motive ← SSE /session/{id}/events → stream events
```

**SSE Event Types** (from SSEEventParser):
- `text.delta` — streaming text chunk
- `tool.call` — tool invocation (name, args)
- `tool.result` — tool output
- `permission.request` — needs user approval
- `question` — agent asks user a question
- `usage` — token usage stats
- `session.complete` — turn finished
- `error` — error occurred

### 2.2 How MyAgent will talk to Hermes (proposed)

**Option A: Hermes HTTP API (recommended)**

Hermes has a built-in HTTP API (`hermes serve`) that exposes:
```
POST /v1/chat/completions  — OpenAI-compatible chat
POST /v1/runs              — agent runs with tool calling
GET  /v1/runs/{id}/events  — SSE event stream
POST /v1/runs/{id}/reply   — reply to agent question
```

```
MyAgent → spawn `hermes serve --port 0` → parse stdout for port
MyAgent → REST POST /v1/runs → create agent run
MyAgent → REST POST /v1/runs/{id}/reply → answer questions
MyAgent ← SSE /v1/runs/{id}/events → stream events
```

**Event mapping** (OpenCode → Hermes):

| OpenCode Event | Hermes Event | Notes |
|---------------|-------------|-------|
| `text.delta` | `response.output_text.delta` | Streaming text |
| `tool.call` | `response.function_call` | Tool invocation |
| `tool.result` | `response.function_call_output` | Tool result |
| `permission.request` | Hook PreToolUse response | Via DefenseClaw hooks |
| `question` | `response.requires_action` | Agent needs input |
| `usage` | `response.usage` | Token counts |
| `session.complete` | `response.completed` | Turn finished |
| `error` | `response.failed` | Error |

**Option B: Direct process communication**

Hermes also supports stdio communication (like how it works in terminal mode):
```
MyAgent → spawn `hermes --cli --non-interactive`
MyAgent → write JSON to stdin
MyAgent ← read JSON from stdout
```

This is simpler but less structured than the HTTP API.

**Recommendation**: Option A (HTTP API) because:
- Hermes `serve` mode is designed for programmatic access
- SSE streaming maps cleanly to Motive's existing SSE parser
- REST endpoints map to Motive's existing REST client
- Session management is built into Hermes serve mode

### 2.3 Permission/Approval Flow

Current (Motive + OpenCode):
```
OpenCode → SSE permission.request → Motive shows native popup → user clicks Allow/Deny
→ Motive → REST POST /permission/{id}/reply → OpenCode continues/stops
```

Proposed (MyAgent + Hermes + DefenseClaw):
```
Hermes → PreToolUse hook → DefenseClaw gateway (port 18970)
  → Guardrail inspection (regex + rules)
  → If CRITICAL: auto-block (Hermes gets block response)
  → If HIGH + HILT enabled: pause execution
    → MyAgent shows native popup → user clicks Allow/Deny
    → MyAgent → REST POST to DefenseClaw → Hermes continues/stops
  → If safe: auto-allow
```

**Key insight**: DefenseClaw guardrails handle the security policy.
MyAgent only needs to show popups for HILT (human-in-the-loop) cases,
not for every tool call. This is more efficient than OpenCode's approach
where every tool call needs explicit permission.

---

## 3. Renaming Plan

### 3.1 Brand Assets
- App name: **MyAgent**
- Bundle ID: `com.cisco.myagent`
- Menu bar icon: Shield with agent indicator (reuse DefenseClaw shield + status dot)
- Window title: "MyAgent"
- Settings → Provider: "DefenseClaw" as default
- Footer: "Powered by DefenseClaw + Hermes"

### 3.2 Code Changes

| File/Area | Change |
|-----------|--------|
| `Motive.xcodeproj` | Rename target, bundle ID, product name |
| `Info.plist` | CFBundleName, CFBundleDisplayName → MyAgent |
| `ConfigManager.swift` | Default provider → .defenseclaw |
| `ProviderConfigStore.swift` | DefenseClaw base URL default |
| `ConfigManager+Provider.swift` | Auto-read gateway token from .env |
| `ConfigManager+Environment.swift` | Add DefenseClaw env vars |
| `OpenCodeServer.swift` | → `HermesServer.swift` — spawn hermes serve |
| `OpenCodeBridge.swift` | → `HermesBridge.swift` — REST/SSE client |
| `OpenCodeConfigGenerator.swift` | → `HermesConfigGenerator.swift` |
| `SSEEventParser.swift` | Map Hermes event types |
| `EnvironmentBuilder.swift` | Pass DefenseClaw env vars to Hermes |
| All UI strings | "Motive" → "MyAgent", "OpenCode" → "Hermes" |
| Skills.bundle | Keep Motive skills + add DefenseClaw-specific skills |
| `~/.motive/` | → `~/.myagent/` config directory |

### 3.3 Files to Add
- `HermesServer.swift` — Hermes process lifecycle
- `HermesBridge.swift` — REST/SSE communication
- `HermesConfigGenerator.swift` — writes hermes config
- `DefenseClawIntegration.swift` — reads .env, checks gateway health

---

## 4. IT Governed Mode Integration

### 4.1 Auto-Discovery

When MyAgent launches, it checks:
1. Is DefenseClaw installed? (`~/.defenseclaw/config.yaml` exists?)
2. Is IT Governed mode active? (`deployment_mode: it_governed`)
3. Is the gateway running? (health check `http://127.0.0.1:18970/health`)
4. Is Hermes installed? (`which hermes` or `~/.local/bin/hermes`)

If all checks pass → auto-configure:
- Provider: DefenseClaw
- Base URL: `http://127.0.0.1:4001/v1`
- API key: from `~/.defenseclaw/.env`
- Model: `default` (SR routes)
- Trust level: from DefenseClaw guardrail mode (observe=Balanced, action=Careful)

### 4.2 Gateway Health in Menu Bar

The menu bar icon reflects DefenseClaw gateway health:
- 🟢 Green dot: gateway healthy, Hermes running
- 🟡 Yellow dot: gateway degraded (SR down or MCP timeout)
- 🔴 Red dot: gateway offline
- ⚪ Gray: DefenseClaw not installed

### 4.3 MCP Tools in UI

MyAgent's skill browser shows MCP tools from DefenseClaw:
- Fetches tool list from `http://127.0.0.1:4001/mcp/` (tools/list)
- Groups by MCP server (Confluence, Outlook, etc.)
- Shows tool descriptions and input schemas
- User can enable/disable individual tools

---

## 5. Implementation Phases

### Phase 1: Rename (1 day)
- Motive → MyAgent branding across all files
- Bundle ID, Info.plist, window titles, strings
- Keep OpenCode backend temporarily

### Phase 2: DefenseClaw Provider (0.5 day)
- Add DefenseClaw provider (already done in this session)
- Auto-read gateway token
- Set as default provider
- Test LLM calls through LiteLLM

### Phase 3: Hermes Backend (3-5 days)
- Write `HermesServer.swift` (process lifecycle)
- Write `HermesBridge.swift` (REST/SSE client)
- Map Hermes events to MyAgent event model
- Write `HermesConfigGenerator.swift`
- Remove OpenCode dependency
- Test agent execution end-to-end

### Phase 4: DefenseClaw Integration (1-2 days)
- Gateway health monitoring
- Auto-discovery of IT Governed mode
- MCP tool browser
- Trust level sync with guardrail mode
- Permission popup integration with DefenseClaw HILT

### Phase 5: Polish (1-2 days)
- App icon / menu bar icon
- Onboarding flow for DefenseClaw setup
- Error states when gateway is down
- Localization updates
- Testing on clean machine

**Total estimate: 7-10 days**

---

## 6. Deployment

### 6.1 Distribution

MyAgent is distributed as part of DefenseClaw's IT Governed setup:

```bash
defenseclaw setup it-governed --yes
# Installs: Hermes + hardened Docker + hooks + guardrails + MyAgent.app
```

The `it-governed` provisioner:
1. Installs Hermes (if not present)
2. Builds MyAgent.app from source (or downloads pre-built DMG)
3. Places in `/Applications/MyAgent.app`
4. Registers launch-at-login via SMAppService

### 6.2 Update Flow

MyAgent checks for updates from the DefenseClaw release channel:
- Release artifacts: `cisco-aispg/defenseclaw/releases`
- Update check: periodic (configurable, default daily)
- Update mechanism: download DMG, prompt user to replace

---

## 7. Security Considerations

| Concern | Mitigation |
|---------|-----------|
| API keys in memory | Keychain storage for provider keys; gateway token read from .env |
| Hermes sandbox escape | Docker sandbox hardening (no host FS, no network, caps dropped) |
| MCP tool abuse | DefenseClaw guardrails inspect all tool calls |
| Prompt injection | Regex rules (246) + sandbox-escape rules (5 CRITICAL) |
| Config tampering | Immutable file flags (chflags uchg) after setup |
| Token expiry | MyAgent monitors gateway health; shows error when JWT expires |

---

## 8. Open Questions

1. **Hermes `serve` mode availability**: Does the current Hermes version support
   `hermes serve --port 0`? If not, we need to use stdio communication or the
   Hermes gateway HTTP API.

2. **Browser automation**: Motive bundles `browser-use-sidecar` for browser
   automation. Should MyAgent include this? (It runs outside Docker sandbox.)

3. **Memory plugin**: Motive has a TypeScript memory plugin. Should MyAgent use
   Hermes's built-in memory system instead?

4. **Multi-agent**: Motive supports agent switching. Should MyAgent expose
   multiple Hermes profiles?

5. **Windows/Linux**: Motive is macOS-only. Should we plan a web-based fallback
   (the MyAgent web UI at `services/ui/`) for other platforms?
