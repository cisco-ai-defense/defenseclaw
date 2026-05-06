# DefenseClaw macOS App — Design Spec

> **Status:** PROPOSAL (0% implemented)

## Overview

A native macOS application that serves as an **agent cockpit with integrated governance** — unifying OpenClaw (the AI agent) and DefenseClaw (the governance layer) into a single UI. The agent is the hero; governance is woven into every interaction.

## Decisions

| Decision | Choice |
|----------|--------|
| Purpose | Agent cockpit with integrated governance |
| Scope | DefenseClaw + OpenClaw unified interface |
| Backend lifecycle | macOS LaunchAgent for sidecar + app-managed agent sessions |
| Agent interaction | Multi-session orchestrator (chat, observe tool calls, intervene) |
| Layout | Tab bar (one session visible at a time) + governance sidebar |
| Communication | Pure HTTP REST + WebSocket (no FFI, no cgo, no XPC) |
| Implementations | 3 versions: SwiftUI, Tauri+React, AppKit+SwiftUI hybrid |

## Architecture

### Communication Protocol

All 3 app versions share the same communication layer — no direct Go/Python FFI.

```
┌─────────────────────────────────────────────┐
│  macOS App (any version)                    │
│                                             │
│  ┌─────────────┐   ┌──────────────────┐    │
│  │ REST Client  │   │ WebSocket Client │    │
│  │ (sidecar API)│   │ (OpenClaw GW)    │    │
│  └──────┬──────┘   └────────┬─────────┘    │
│         │                    │              │
│  ┌──────┴────────────────────┴──────────┐   │
│  │        Service Layer (shared)        │   │
│  │  - SidecarService (30+ endpoints)    │   │
│  │  - AgentSessionService (WS v3)      │   │
│  │  - ProcessRunner (Python CLI)       │   │
│  │  - LaunchAgentManager               │   │
│  └──────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
         │                    │
    localhost:18790      ws://host:port
         │                    │
   DefenseClaw           OpenClaw
   Sidecar               Gateway
```

### Sidecar REST API (existing, no backend changes needed)

| Endpoint | Purpose |
|---|---|
| `GET /health` | Subsystem health (gateway, watcher, guardrail, sandbox...) |
| `GET /status` | Overall sidecar status |
| `GET /alerts` | Governance alerts feed |
| `GET /skills` | Installed skills with block/allow status |
| `GET /mcps` | MCP servers with status |
| `POST /enforce/block` | Block a skill/MCP |
| `POST /enforce/allow` | Allow a skill/MCP |
| `POST /v1/skill/scan` | Trigger on-demand scan |
| `GET /v1/guardrail/config` | Guardrail mode/settings |
| `PATCH /v1/guardrail/config` | Change guardrail mode |
| `POST /v1/guardrail/evaluate` | Evaluate content against guardrail |
| `GET /enforce/blocked` | List blocked items |
| `GET /enforce/allowed` | List allowed items |
| `GET /tools/catalog` | Available tools catalog |
| `POST /policy/reload` | Reload OPA policies |
| `POST /policy/evaluate` | Evaluate admission policy |
| `POST /audit/event` | Log audit event |

### OpenClaw WebSocket v3

Device auth handshake → bidirectional JSON events:
- Tool call requests/responses
- Chat messages (user → agent, agent → user)
- Session lifecycle (start, stop, error)
- Skill install/uninstall events

### Backend Lifecycle

- **DefenseClaw sidecar**: managed via macOS LaunchAgent (persists across app restarts, protects agent even when UI is closed)
- **OpenClaw agent sessions**: started/stopped from within the app per-tab
- **Python CLI**: invoked via `Process`/shell for setup and on-demand scan commands

## Folder Structure

```
apps/
  shared/                    # Shared Swift package (SPM) — used by App A and C
    Package.swift
    Sources/DefenseClawKit/
      SidecarClient.swift    # REST client for all 30+ endpoints
      AgentSession.swift     # WebSocket v3 client
      ProcessRunner.swift    # Shell out to Python CLI (init, setup, scan, doctor)
      LaunchAgentManager.swift
      ConfigManager.swift    # Read/write ~/.defenseclaw/config.yaml
      Models/
        Alert.swift
        Skill.swift
        Plugin.swift
        MCPServer.swift
        ToolEntry.swift
        HealthSnapshot.swift
        ToolEvent.swift
        ChatMessage.swift
        SessionConfig.swift
        PolicyModels.swift   # AdmissionInput/Output, FirewallInput/Output, etc.
        ScanResult.swift     # Finding, ScanResult, severity enums
        ConfigModels.swift   # Full Config struct matching config.yaml schema
  swiftui-app/              # App A: Pure SwiftUI
  tauri-app/                # App B: Tauri + React/TypeScript
  appkit-app/               # App C: AppKit + SwiftUI hybrid
```

---

## App A: Pure SwiftUI

**Target**: macOS 14+ (Sonoma), Swift 5.9+

### Structure

```
apps/swiftui-app/
  DefenseClaw/
    DefenseClawApp.swift          # @main, WindowGroup + MenuBarExtra
    Views/
      MainWindow.swift            # Tab bar + content area + governance sidebar
      SessionTab/
        SessionTabView.swift      # Single session: chat + tool stream + governance
        ChatView.swift            # Message list + input field
        ToolStreamView.swift      # Real-time tool call feed with status badges
        GovernanceSidebar.swift   # Alerts, guardrail status, block/allow controls
      NewSessionSheet.swift       # Workspace picker + agent config
      SettingsView.swift          # Config, LaunchAgent toggle, sidecar status
    ViewModels/
      AppViewModel.swift          # Manages sessions array, active tab, sidecar connection
      SessionViewModel.swift      # Per-session: chat history, tool events, governance state
    MenuBar/
      MenuBarView.swift           # MenuBarExtra: status dot, alert count, quick actions
    Package.swift                 # Depends on shared DefenseClawKit
```

### Key SwiftUI APIs

- `TabView` with `.tabViewStyle(.automatic)` for session tabs
- `NavigationSplitView` for chat/tools (main) + governance (sidebar)
- `MenuBarExtra` for ambient menu bar status
- `SMAppService` for LaunchAgent install/uninstall
- async/await `URLSession` for REST + `URLSessionWebSocketTask` for WS
- `@Observable` (macOS 14+) for view models

### Data Flow

```
SidecarClient (polling /health, /alerts every 5s)
       │
       ▼
AppViewModel (@Observable)
  ├── sidecarHealth: HealthSnapshot
  ├── sessions: [SessionViewModel]
  └── activeSessionIndex: Int
           │
           ▼
     SessionViewModel (@Observable)
       ├── messages: [ChatMessage]        ← from WebSocket
       ├── toolEvents: [ToolEvent]        ← from WebSocket
       ├── alerts: [Alert]                ← from REST /alerts
       ├── skills: [Skill]               ← from REST /skills
       └── guardrailMode: String          ← from REST /v1/guardrail/config
```

---

## App B: Tauri + React/TypeScript

**Target**: Tauri v2, React 18, TypeScript 5, Vite

### Structure

```
apps/tauri-app/
  src-tauri/
    src/
      main.rs                     # Tauri entry point
      commands.rs                 # Tauri commands (invoke from JS)
      launchagent.rs              # LaunchAgent plist management
    tauri.conf.json               # Window config, permissions
    Cargo.toml
  src/
    App.tsx                       # Root: tab bar + router
    components/
      TabBar/
        TabBar.tsx                # Session tabs + new session button
        TabItem.tsx               # Single tab with status indicator
      Session/
        SessionView.tsx           # Main session layout: chat + tools + governance
        ChatPanel.tsx             # Message list + input
        ToolStream.tsx            # Tool call feed with severity badges
        GovernanceSidebar.tsx     # Alerts, guardrail, block/allow
      MenuBar/
        TrayMenu.tsx              # System tray status (Tauri tray API)
      Settings/
        SettingsDialog.tsx        # Config, LaunchAgent, sidecar health
    services/
      sidecar-client.ts          # fetch() wrapper for REST API
      agent-session.ts           # WebSocket v3 client
      process-runner.ts          # Tauri shell commands for Python CLI
    hooks/
      useSession.ts              # Per-session state (chat, tools, governance)
      useSidecar.ts              # Sidecar health polling
      useWebSocket.ts            # WS connection with reconnect
    types/
      index.ts                   # Alert, Skill, MCP, Health, ToolEvent types
    package.json
    vite.config.ts
    tsconfig.json
```

### Key Tauri Features

- `tauri::command` for LaunchAgent management and Process spawning (Rust side)
- System tray API for menu bar status icon + popup menu
- `window.fetch()` for sidecar REST (no CORS — Tauri allows localhost)
- Native `WebSocket` for OpenClaw gateway
- ~10MB binary (vs ~150MB Electron — uses system WebView)

> **Note:** The `services/` and `hooks/` directories in the Tauri app are the TypeScript equivalent of the shared `DefenseClawKit` Swift package. They implement the same REST/WS client logic in a different language because Tauri's frontend is web-based and cannot consume Swift packages.

### Data Flow

```
sidecar-client.ts (fetch /health, /alerts every 5s)
       │
       ▼
useSidecar() hook (React state)
  └── health, alerts, skills, mcps

useWebSocket() hook (WS v3 connection)
       │
       ▼
useSession() hook (per tab)
  ├── messages: ChatMessage[]
  ├── toolEvents: ToolEvent[]
  └── governance: { alerts, guardrailMode, skills }
```

---

## App C: AppKit + SwiftUI Hybrid

**Target**: macOS 14+, Swift 5.9+

### Structure

```
apps/appkit-app/
  DefenseClawAppKit/
    main.swift                        # NSApplicationMain
    AppDelegate.swift                 # NSApplicationDelegate, menu bar setup
    WindowManagement/
      MainWindowController.swift      # NSWindowController — custom title bar + tab strip
      TabStripView.swift              # Custom AppKit tab bar (drag-reorder, close buttons)
      TabStripItem.swift              # Single tab: title, status dot, close button
    Views/                            # SwiftUI content (hosted via NSHostingView)
      SessionContentView.swift        # NSHostingView wrapper for SwiftUI session
      ChatView.swift                  # SwiftUI: message list + input
      ToolStreamView.swift            # SwiftUI: tool call feed
      GovernanceSidebarView.swift     # SwiftUI: alerts, guardrail, block/allow
      NewSessionSheet.swift           # SwiftUI: workspace picker
      SettingsView.swift              # SwiftUI: config panel
    MenuBar/
      StatusBarController.swift       # NSStatusItem + NSPopover for menu bar
      StatusBarPopover.swift          # SwiftUI view inside NSPopover
    ViewModels/
      AppViewModel.swift              # Same @Observable pattern as App A
      SessionViewModel.swift          # Per-session state
    Package.swift                     # Depends on shared DefenseClawKit
```

### AppKit vs SwiftUI Split

| Layer | Technology | Reason |
|-------|-----------|--------|
| Window frame, title bar | AppKit | Custom tab strip with drag-reorder, close buttons, status dots |
| Tab management | AppKit | Programmatic tab add/remove/reorder with animation |
| Menu bar icon | AppKit (`NSStatusItem`) | Custom popover sizing and positioning |
| Chat, tools, governance | SwiftUI (via `NSHostingView`) | Declarative, reactive data binding |

### Data Flow

Identical to App A — same `@Observable` view models, same `DefenseClawKit` client. The only difference is the hosting layer:

```
AppDelegate
  └── MainWindowController (AppKit)
        ├── TabStripView (AppKit) — manages tab UI
        │     └── tabs: [TabStripItem] — bound to AppViewModel.sessions
        └── contentView: NSHostingView (bridges to SwiftUI)
              └── SessionContentView
                    ├── ChatView
                    ├── ToolStreamView
                    └── GovernanceSidebarView
```

---

## UI Layout (all versions)

```
┌─────────────────────────────────────────────────────────┐
│  [Agent 1: ~/project-a]  [Agent 2: ~/project-b]  [+]   │  ← Tab bar
├───────────────────────────────────┬─────────────────────┤
│                                   │   GOVERNANCE        │
│   CHAT                            │                     │
│   ┌─────────────────────────┐     │   ● Guardrail: on   │
│   │ > Deploy the auth svc   │     │   ● Sandbox: running│
│   │                         │     │   ▲ 2 warnings      │
│   │ Running kubectl apply...│     │   ■ 1 blocked       │
│   └─────────────────────────┘     │                     │
│                                   │   ─────────────     │
│   TOOL STREAM                     │   SKILLS (3)        │
│   ┌─────────────────────────┐     │   ✓ web-search      │
│   │ ✓ read_file  2ms        │     │   ✓ code-exec       │
│   │ ✓ edit_file  5ms        │     │   ✗ data-exfil      │
│   │ ▲ bash       warned     │     │                     │
│   │ ✗ curl       blocked    │     │   MCP SERVERS (2)   │
│   └─────────────────────────┘     │   ✓ github          │
│                                   │   ✓ filesystem      │
│   [message input...]              │                     │
├───────────────────────────────────┴─────────────────────┤
│  ● Sidecar: healthy  ● Guardrail: active  ▲ 2 alerts   │  ← Status bar
└─────────────────────────────────────────────────────────┘

  Menu bar: [🛡] ← click for popover with global status
```

---

## Complete CLI Command Coverage

The app must expose every CLI command through its UI. Commands map to app features as follows.

### First-Run & Setup (replaces `defenseclaw init` + `defenseclaw setup *`)

The app includes a **Setup Wizard** that launches on first run (or from Settings). It replaces:

| CLI Command | App equivalent |
|---|---|
| `defenseclaw init` | First-launch wizard: creates `~/.defenseclaw/`, writes `config.yaml`, initializes SQLite audit DB |
| `setup skill-scanner` | Settings > Scanners > Skill Scanner (binary path, LLM, behavioral, policy, VirusTotal) |
| `setup mcp-scanner` | Settings > Scanners > MCP Scanner (binary path, analyzers, prompts/resources/instructions) |
| `setup gateway` | Settings > Gateway (host, port, token, auto-approve, watcher config) |
| `setup guardrail` | Settings > Guardrail (enable/disable, mode observe/action, model, API key, scanner mode, judge) |
| `setup splunk` | Settings > Integrations > Splunk (HEC endpoint, token, index, source, TLS, batch) |
| `sandbox init` | Settings > Sandbox > Initialize (OpenShell binary, install, configure) |
| `sandbox setup` | Settings > Sandbox > Configure (standalone mode, systemd units, network policy) |

### Skill Management (replaces `defenseclaw skill *`)

| CLI Command | App equivalent |
|---|---|
| `skill scan <path>` | Skills tab > Scan button (or drag-drop path) → calls `POST /v1/skill/scan` |
| `skill list` | Skills tab > list view → calls `GET /skills` |
| `skill block <name>` | Skills tab > right-click > Block → calls `POST /enforce/block` |
| `skill allow <name>` | Skills tab > right-click > Allow → calls `POST /enforce/allow` |
| `skill unblock <name>` | Skills tab > right-click > Unblock |
| `skill unallow <name>` | Skills tab > right-click > Remove from allow list |
| `skill quarantine <name>` | Skills tab > right-click > Quarantine |
| `skill restore <name>` | Skills tab > Quarantine view > Restore |
| `skill disable <name>` | Skills tab > right-click > Disable (runtime) → calls `POST /skill/disable` |
| `skill enable <name>` | Skills tab > right-click > Enable (runtime) → calls `POST /skill/enable` |
| `skill fetch <url>` | Skills tab > Fetch Skill sheet (URL input) → calls `POST /v1/skill/fetch` |
| `skill deploy <name>` | Skills tab > right-click > Deploy |

### Plugin Management (replaces `defenseclaw plugin *`)

| CLI Command | App equivalent |
|---|---|
| `plugin scan <path>` | Plugins tab > Scan button |
| `plugin list` | Plugins tab > list view |
| `plugin block/allow/unblock/unallow` | Plugins tab > right-click context menu |
| `plugin quarantine/restore` | Plugins tab > right-click > Quarantine/Restore |
| `plugin disable/enable` | Plugins tab > right-click > Disable/Enable → calls `POST /plugin/disable`, `/plugin/enable` |
| `plugin fetch/deploy` | Plugins tab > Fetch/Deploy sheets |

### MCP Server Management (replaces `defenseclaw mcp *`)

| CLI Command | App equivalent |
|---|---|
| `mcp list` | MCP tab > list view → calls `GET /mcps` |
| `mcp scan <url>` | MCP tab > Scan button → calls `POST /v1/mcp/scan` |
| `mcp set <name> <url>` | MCP tab > Add Server sheet (name + URL/command) |
| `mcp unset <name>` | MCP tab > right-click > Remove |
| `mcp block/allow` | MCP tab > right-click > Block/Allow |

### Tool Management (replaces `defenseclaw tool *`)

| CLI Command | App equivalent |
|---|---|
| `tool inspect <name>` | Tools tab > select tool > Inspect panel → calls `POST /api/v1/inspect/tool` |
| `tool scan <name>` | Tools tab > Scan button → calls `POST /api/v1/scan/code` |
| `tool block <name>` | Tools tab > right-click > Block |
| `tool list` | Tools tab > list view → calls `GET /tools/catalog` |
| `tool catalog` | Tools tab > full catalog view |

### Policy Management (replaces `defenseclaw policy *` in both CLIs)

| CLI Command | App equivalent |
|---|---|
| `policy validate` | Policy tab > Validate button (compile-check Rego) |
| `policy show` | Policy tab > data.json viewer (formatted JSON) |
| `policy evaluate` | Policy tab > Dry Run panel (target type/name, severity → verdict) |
| `policy evaluate-firewall` | Policy tab > Firewall Test panel (destination, port, protocol → action) |
| `policy reload` | Policy tab > Reload button → calls `POST /policy/reload` |
| `policy domains` | Policy tab > Firewall Domains view (allowed/blocked lists) |
| `policy list` (Python) | Policy tab > Block/Allow lists view |
| `policy edit` (Python) | Policy tab > Edit data.json (with save + reload) |
| `policy apply` (Python) | Policy tab > Apply policy template (default/strict/permissive) |
| `policy reset` (Python) | Policy tab > Reset to defaults |
| `policy test` (Python) | Policy tab > Run Rego tests |
| `sandbox policy diff` | Policy tab > Sandbox Coverage view (discovered vs. covered endpoints) |

### Scanning (replaces `defenseclaw scan *` + `aibom *` + `codeguard *`)

| CLI Command | App equivalent |
|---|---|
| `scan code <path>` | Scan tab > CodeGuard panel (file/directory picker → results) |
| `aibom scan` | Scan tab > AIBOM panel (AI Bill of Materials inventory) |
| `codeguard install-skill` | Settings > CodeGuard > Install Skill button |

### Monitoring & Diagnostics (replaces `status`, `alerts`, `doctor`)

| CLI Command | App equivalent |
|---|---|
| `status` | Status bar (always visible) + Settings > Status panel |
| `alerts` | Governance sidebar > Alerts section (real-time feed) |
| `doctor` | Settings > Diagnostics (checks scanner binaries, config, DB, connectivity) |

### Sandbox Management (replaces `defenseclaw-gateway sandbox *`)

| CLI Command | App equivalent |
|---|---|
| `sandbox start` | Sandbox panel > Start button (via `Process` → `systemctl`) |
| `sandbox stop` | Sandbox panel > Stop button |
| `sandbox restart` | Sandbox panel > Restart button |
| `sandbox status` | Sandbox panel > Health view (systemd unit status) |
| `sandbox exec` | Sandbox panel > Run Command sheet (input → exec as sandbox user) |
| `sandbox shell` | N/A — terminal-only, not suitable for GUI. Link to "Open Terminal" instead. |

### Daemon Management (replaces `defenseclaw-gateway start/stop/restart`)

| CLI Command | App equivalent |
|---|---|
| `start` | Handled by LaunchAgent (auto on boot). Settings > toggle "Run on login" |
| `stop` | App quit → LaunchAgent keeps running. Settings > Stop Sidecar button |
| `restart` | Settings > Restart Sidecar button |

### Configuration Editor (replaces `~/.defenseclaw/config.yaml` manual editing)

The Settings view provides a **full config editor** covering every config section:

| Config section | Settings panel |
|---|---|
| `claw.mode` / `home_dir` / `config_file` | General > Claw Mode (openclaw / nemoclaw / etc.) |
| `gateway.*` (host, port, token, auto_approve, api_port, api_bind) | Gateway > Connection |
| `gateway.watcher.*` (enabled, skill.enabled, skill.take_action, skill.dirs) | Gateway > Watcher |
| `guardrail.*` (enabled, mode, model, model_name, port, host, scanner_mode, api_key_env, block_message) | Guardrail > Settings |
| `guardrail.judge.*` (model, provider, threshold) | Guardrail > LLM Judge |
| `scanners.skill_scanner.*` (binary, use_llm, behavioral, meta, trigger, virustotal, aidefense, policy, lenient, consensus) | Scanners > Skill Scanner |
| `scanners.mcp_scanner.*` (binary, analyzers, prompts, resources, instructions) | Scanners > MCP Scanner |
| `scanners.plugin_scanner` | Scanners > Plugin Scanner |
| `scanners.codeguard` | Scanners > CodeGuard Rules Dir |
| `inspect_llm.*` (provider, model, api_key, api_key_env, base_url, timeout, max_retries) | Scanners > Inspect LLM |
| `cisco_ai_defense.*` (endpoint, api_key, api_key_env, timeout_ms, enabled_rules) | Integrations > Cisco AI Defense |
| `openshell.*` (binary, policy_dir, mode, version, host_networking) | Sandbox > OpenShell |
| `watch.*` (debounce_ms, auto_block, allow_list_bypass_scan) | Watcher > Behavior |
| `splunk.*` (hec_endpoint, hec_token, index, source, sourcetype, verify_tls, batch_size, flush_interval) | Integrations > Splunk |
| `otel.*` (enabled, endpoint) | Integrations > OpenTelemetry |
| `skill_actions.*` (critical/high/medium/low/info → file/runtime/install) | Enforcement > Skill Actions |
| `mcp_actions.*` (critical/high/medium/low/info → file/runtime/install) | Enforcement > MCP Actions |
| `plugin_actions.*` (critical/high/medium/low/info → file/runtime/install) | Enforcement > Plugin Actions |
| `data_dir`, `audit_db`, `quarantine_dir`, `policy_dir` | General > Paths |

---

## Updated UI Layout (all versions)

The app has 3 navigation levels:

1. **Tab bar** (top) — agent sessions
2. **Main area** — chat + tool stream (per session)
3. **Governance sidebar** (right, collapsible) — alerts, skills, MCPs, plugins, tools

Plus a **top-level navigation** for non-session views:

```
┌─────────────────────────────────────────────────────────┐
│  [Sessions ▼]  [Scan]  [Policy]  [Settings]             │  ← Navigation bar
├─────────────────────────────────────────────────────────┤
│  [Agent 1: ~/project-a]  [Agent 2: ~/project-b]  [+]   │  ← Session tabs
├───────────────────────────────────┬─────────────────────┤
│                                   │   GOVERNANCE        │
│   CHAT                            │                     │
│   ┌─────────────────────────┐     │   [Alerts] [Skills] │
│   │ > Deploy the auth svc   │     │   [MCPs] [Plugins]  │
│   │                         │     │   [Tools]           │
│   │ Running kubectl apply...│     │                     │
│   └─────────────────────────┘     │   ● Guardrail: on   │
│                                   │   ● Sandbox: running│
│   TOOL STREAM                     │   ▲ 2 warnings      │
│   ┌─────────────────────────┐     │   ■ 1 blocked       │
│   │ ✓ read_file  2ms        │     │                     │
│   │ ✓ edit_file  5ms        │     │   ─────────────     │
│   │ ▲ bash       warned     │     │   SKILLS (3)        │
│   │ ✗ curl       blocked    │     │   ✓ web-search  [▶] │
│   └─────────────────────────┘     │   ✓ code-exec   [▶] │
│                                   │   ✗ data-exfil  [■] │
│   [message input...]              │                     │
├───────────────────────────────────┴─────────────────────┤
│  ● Sidecar  ● Guardrail  ● Sandbox  ▲ 2 alerts         │  ← Status bar
└─────────────────────────────────────────────────────────┘

  Menu bar: [🛡] ← click for popover with global status

Non-session views (via navigation bar):
  Scan    → CodeGuard + AIBOM + on-demand skill/MCP/plugin scan
  Policy  → OPA policy viewer/editor, dry-run, firewall domains, sandbox diff
  Settings → Full config editor, setup wizards, diagnostics, LaunchAgent
```

---

## Native Chat Interface

The chat interface is the hero of the app. It must match the OpenClaw browser UI at `localhost:18789` — a streaming chat with real-time thinking visibility and tool call cards inline.

### Message Types

The chat renders 5 distinct message types, each with its own visual treatment:

```
┌─────────────────────────────────────────────────────────┐
│  USER MESSAGE                                           │
│  ┌─────────────────────────────────────────────────┐    │
│  │ Deploy the auth service to production            │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  THINKING (collapsible, dimmed)           ▼ 1.2s        │
│  ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┐    │
│  │ I need to check the current deployment state    │    │
│  │ first, then apply the auth.yaml manifest...     │    │
│  └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┘    │
│                                                         │
│  TOOL CALL (inline card)                                │
│  ┌──────────────────────────────────────────────────┐   │
│  │ ⚙ shell                                    ✓ 2s │   │
│  │ kubectl get pods -n auth                         │   │
│  │ ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄  │   │
│  │ NAME              READY   STATUS    AGE          │   │
│  │ auth-svc-7b9f4    1/1     Running   3d           │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│  APPROVAL REQUEST (action required)                     │
│  ┌──────────────────────────────────────────────────┐   │
│  │ ⚠ Approval needed                                │   │
│  │ kubectl apply -f auth.yaml                       │   │
│  │                                                   │   │
│  │           [Approve]  [Deny]                       │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│  ASSISTANT MESSAGE (streaming, markdown)                │
│  ┌─────────────────────────────────────────────────┐    │
│  │ The auth service is deployed. The pod is running │    │
│  │ with 1/1 containers ready. I applied the new     │    │
│  │ manifest and verified the rollout.         ▌      │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  GUARDRAIL BADGE (inline, when triggered)               │
│  ┌──────────────────────────────────────────────────┐   │
│  │ 🛡 Guardrail: blocked — prompt injection detected │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Streaming

The chat supports real-time token streaming from the LLM:

| Source | Protocol | How it works |
|--------|----------|--------------|
| Agent text responses | WebSocket v3 `session.message` events | Tokens arrive as content deltas; append to current assistant bubble in real-time |
| LLM completions (via guardrail proxy) | SSE (`text/event-stream`) | OpenAI-compatible `data: {"choices":[{"delta":{"content":"..."}}]}` chunks; proxy at `localhost:4000` |
| Tool call streaming | WebSocket v3 `tool_call` + `tool_result` events | Tool card appears on `tool_call`, output populates on `tool_result` |

**Streaming UX:**
- Cursor (blinking `▌`) at the end of the streaming text
- Tokens render immediately as they arrive — no buffering
- Markdown is rendered incrementally (headings, code blocks, lists render as soon as the delimiter is complete)
- "Stop generating" button appears during streaming (sends cancel/abort)
- Scroll anchors to bottom during streaming; user scroll-up pauses auto-scroll

### Thinking / Reasoning Panel

When the agent's LLM uses extended thinking (Anthropic `thinking` content blocks, or OpenAI reasoning tokens), the UI shows what the agent is "thinking" before it responds:

**How thinking data arrives:**
- Anthropic models: SSE events with `content_block_start` where `type: "thinking"`, followed by `content_block_delta` with `type: "thinking_delta"` and `thinking` text
- OpenAI models: streaming chunks may include reasoning tokens (model-dependent)
- The guardrail proxy passes these through as-is in the SSE stream

**Thinking UX:**
- A collapsible "Thinking..." section appears above the assistant response
- During thinking: animated ellipsis or spinner + live text streaming inside a dimmed/muted container
- Thinking text uses a distinct style: lighter font color (`secondary` label), dashed border, monospace or italic
- After thinking completes: section auto-collapses to a single line showing "Thinking — 1.2s" with a disclosure triangle to expand
- Thinking content is NOT editable or copyable by default (it's internal reasoning)
- If the model doesn't emit thinking tokens, the section simply doesn't appear

```
Thinking states:

[Active]     ⟳ Thinking...
             │ I need to check the deployment state
             │ first. Let me look at the pods in the
             │ auth namespace and then apply the▌

[Collapsed]  ▶ Thinking — 1.2s

[Expanded]   ▼ Thinking — 1.2s
             │ I need to check the deployment state
             │ first. Let me look at the pods in the
             │ auth namespace and then apply the new
             │ manifest. I should verify the rollout
             │ status afterward.
```

### Tool Call Cards

Tool calls render as inline cards within the chat flow (matching OpenClaw's browser UI):

| Tool call status | Visual |
|-----------------|--------|
| `pending` | Spinner + tool name + args preview (dimmed) |
| `running` | Animated border + tool name + args |
| `completed` (exit 0) | Green checkmark `✓` + tool name + elapsed time + collapsible output |
| `completed` (exit != 0) | Red X `✗` + tool name + error output |
| `warned` (guardrail) | Yellow triangle `▲` + tool name + warning reason |
| `blocked` (guardrail/policy) | Red shield `🛡` + tool name + block reason + "was blocked by DefenseClaw" |

**Card interactions:**
- Click to expand/collapse output
- Output uses monospace font, syntax-highlighted for code
- Long output is truncated with "Show more" link
- Right-click: Copy output, Copy command, Re-run, Inspect in Tools tab

### Exec Approval Requests

When `exec.approval.requested` arrives via WebSocket:

1. An approval card appears inline in the chat (see mockup above)
2. Shows the command to be executed (`rawCommand` or `commandPreview`)
3. Shows the working directory (`cwd`)
4. Two action buttons: **Approve** (green) and **Deny** (red)
5. If `gateway.auto_approve_safe` is true, safe commands show "Auto-approved" badge instead
6. Dangerous commands (matching the pattern list in `router.go`) show a red warning banner
7. Clicking Approve/Deny sends `exec.approval.resolve` RPC via WebSocket
8. Card updates to show the decision with timestamp

### Chat Input

The input area at the bottom of the chat:

```
┌─────────────────────────────────────────────────────────┐
│  / for commands    [📎]  Type a message...    [↑ Send]  │
└─────────────────────────────────────────────────────────┘
```

- **Multiline**: Shift+Enter for newline, Enter to send
- **Slash commands**: `/scan`, `/block`, `/allow` (registered via plugin SDK) — autocomplete dropdown
- **File attach**: drag-drop or click attachment icon to reference files
- **History**: Up arrow to recall previous messages
- **Markdown preview**: optional live preview toggle for complex messages

### Chat Message Data Model

Shared across all 3 app versions:

```swift
// In DefenseClawKit/Models/ChatMessage.swift

enum MessageRole: String, Codable {
    case user, assistant, system, tool
}

enum MessageContentBlock: Identifiable {
    case text(String)
    case thinking(id: String, text: String, durationMs: Int?)
    case toolCall(id: String, tool: String, args: String, status: ToolCallStatus, output: String?, elapsed: TimeInterval?)
    case approvalRequest(id: String, command: String, cwd: String, isDangerous: Bool, decision: ApprovalDecision?)
    case guardrailBadge(severity: String, action: String, reason: String)
}

enum ToolCallStatus: String {
    case pending, running, completed, failed, warned, blocked
}

enum ApprovalDecision: String {
    case approved, denied, autoApproved
}

struct ChatMessage: Identifiable {
    let id: UUID
    let role: MessageRole
    var blocks: [MessageContentBlock]  // A message can have multiple blocks
    let timestamp: Date
    var isStreaming: Bool              // True while tokens are still arriving
}
```

For the Tauri app (TypeScript equivalent):

```typescript
// In services/types/chat.ts

type MessageRole = 'user' | 'assistant' | 'system' | 'tool';

type ContentBlock =
  | { type: 'text'; text: string }
  | { type: 'thinking'; id: string; text: string; durationMs?: number }
  | { type: 'tool_call'; id: string; tool: string; args: string; status: ToolCallStatus; output?: string; elapsedMs?: number }
  | { type: 'approval_request'; id: string; command: string; cwd: string; isDangerous: boolean; decision?: 'approved' | 'denied' | 'auto_approved' }
  | { type: 'guardrail_badge'; severity: string; action: string; reason: string };

type ToolCallStatus = 'pending' | 'running' | 'completed' | 'failed' | 'warned' | 'blocked';

interface ChatMessage {
  id: string;
  role: MessageRole;
  blocks: ContentBlock[];
  timestamp: number;
  isStreaming: boolean;
}
```

### Event-to-UI Mapping

How WebSocket v3 and SSE events map to chat UI updates:

| Event | Source | UI Action |
|-------|--------|-----------|
| `session.message` (user) | WebSocket | Append user message bubble |
| `session.message` (assistant) | WebSocket | Start new assistant bubble, begin streaming |
| SSE `content_block_start` type=`thinking` | Guardrail proxy SSE | Show thinking section (active, streaming) |
| SSE `content_block_delta` type=`thinking_delta` | Guardrail proxy SSE | Append text to thinking section |
| SSE `content_block_stop` (thinking) | Guardrail proxy SSE | Collapse thinking, show duration |
| SSE `content_block_delta` type=`text_delta` | Guardrail proxy SSE | Append token to assistant bubble |
| SSE `data: [DONE]` | Guardrail proxy SSE | End streaming, remove cursor |
| `tool_call` | WebSocket | Insert tool card (pending/running) into chat |
| `tool_result` | WebSocket | Update tool card with output + status |
| `exec.approval.requested` | WebSocket | Insert approval card with Approve/Deny buttons |
| Guardrail block (mid-stream) | Guardrail proxy truncates stream | Show guardrail badge, end streaming |
| Guardrail block (pre-call) | Sidecar blocks before forward | Show guardrail badge instead of response |

---

## Scope Boundaries

- **No backend changes** — all 3 apps are pure clients of existing REST API + Python CLI via Process
- **macOS only** — Tauri version could be extended to Linux later but v1 is macOS-focused
- **No agent protocol changes** — uses existing WebSocket v3 and REST endpoints
- **Python CLI via Process** — setup/scan/init commands shell out to `defenseclaw` Python CLI
- **LaunchAgent, not LaunchDaemon** — runs as user, no root required
- **macOS 14+ minimum** — for `@Observable`, `MenuBarExtra`, `SMAppService`
- **Sandbox shell excluded** — interactive terminal not suitable for GUI; provide "Open Terminal" link instead
- **Config changes write YAML** — Settings editor writes `~/.defenseclaw/config.yaml` directly, then triggers sidecar reload

## What Each Version Demonstrates

| Version | Strength |
|---------|----------|
| **A (SwiftUI)** | Fastest to build, smallest codebase, most idiomatic macOS |
| **B (Tauri)** | Cross-platform potential, web tech reuse, smallest binary |
| **C (AppKit)** | Maximum native control, draggable tabs, custom window chrome |
