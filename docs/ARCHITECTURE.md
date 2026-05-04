# Architecture

DefenseClaw is a governance layer for OpenClaw. It orchestrates scanning,
enforcement, and auditing across existing tools without replacing any component.

## System Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DefenseClaw System                             │
│                                                                             │
│  ┌──────────────────────┐     ┌──────────────────────────────────────────┐  │
│  │  CLI (Python)        │     │  Plugins / Hooks (JS/TS)                │   │
│  │                      │     │                                         │   │
│  │  skill-scanner       │     │  OpenClaw plugin (api.on, commands)     │   │
│  │  mcp-scanner         │     │  before_tool_call → gateway inspect     │   │
│  │  plugin              │     │  /scan, /block, /allow slash cmds       │   │
│  │  aibom               │     │                                         │   │
│  │  codeguard           │     │                                         │   │
│  │  [custom scanners]   │     │                                         │   │
│  │  Writes scan results │     │                                         │   │
│  │  directly to DB      │     │                                         │   │
│  └──────────┬───────────┘     └───────────────────┬─────────────────────┘   │
│             │ REST API                            │ REST API                │
│             │                                     │                         │
│             ▼                                     ▼                         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                  DefenseClaw Gateway (Go)                           │    │
│  │                                                                     │    │
│  │  ┌───────────┐ ┌───────────┐ ┌──────────┐ ┌─────────────────┐       │    │
│  │  │ REST API  │ │ Audit /   │ │ Policy   │ │ OpenClaw WS     │       │    │
│  │  │ Server    │ │ SIEM      │ │ Engine   │ │ Client          │       │    │
│  │  │           │ │ Emitter   │ │          │ │                 │       │    │
│  │  │ Accepts   │ │           │ │ Block /  │ │ WS protocol v3  │       │    │
│  │  │ requests  │ │ Splunk    │ │ Allow /  │ │ Subscribes to   │       │    │
│  │  │ from CLI  │ │ HEC, CSV  │ │ Scan     │ │ all events,     │       │    │
│  │  │ & plugins │ │ export    │ │ gate     │ │ sends commands  │       │    │
│  │  └───────────┘ └───────────┘ └──────────┘ └────────┬────────┘       │    │
│  │                                                     │               │    │
│  │  ┌────────────────────────────────────────────┐     │               │    │
│  │  │  Inspection Engine (4-stage pipeline)        │     │              │    │
│  │  │  /api/v1/inspect/tool                      │     │               │    │
│  │  │  1. Regex (113 rules, 6 categories)        │     │               │    │
│  │  │  2. Cisco AI Defense (12 cloud rules)      │     │               │    │
│  │  │  3. LLM Judge (injection/PII/tool-inj)     │     │               │    │
│  │  │  4. OPA policy (7 Rego files)              │     │               │    │
│  │  │  + CodeGuard for write/edit tools          │     │               │    │
│  │  │  Verdict: allow / alert / block            │     │               │    │
│  │  └────────────────────────────────────────────┘     │               │    │
│  │                                                     │               │    │
│  │  ┌──────────────────┐  ┌──────────────┐             │               │    │
│  │  │  SQLite DB       │  │  Guardrail   │             │               │    │
│  │  │                  │  │  Proxy       │             │               │    │
│  │  │  Audit events    │  │              │             │               │    │
│  │  │  Scan results    │  │  Runs        │             │               │    │
│  │  │  Block/allow     │  │  guardrail   │             │               │    │
│  │  │  Skill inventory │  │  proxy       │             │               │    │
│  │  └──────────────────┘  └──────┬───────┘             │               │    │
│  └──────────────────────────────┼────────────────────┼─────────────────┘    │
│                                 │                    │                      │
│             ┌───────────────────┘                    │ WS (events           │
│             │ runs                                   │  + RPC)              │
│             ▼                                        │                      │
│  ┌──────────────────────────────────┐                │                      │
│  │  Guardrail Proxy (port 4000)    │                 │                      │
│  │                                  │                │                      │
│  │  ┌────────────────────────────┐  │                │                      │
│  │  │  DefenseClaw Guardrail     │  │                │                      │
│  │  │  (built-in Go)             │  │                │                      │
│  │  │                            │  │                │                      │
│  │  │  pre_call:  prompt scan    │  │                │                      │
│  │  │  post_call: response scan  │  │                │                      │
│  │  │    + tool call logging     │  │                │                      │
│  │  │  streaming: chunk inspect  │  │                │                      │
│  │  │  mode: observe | action    │  │                │                      │
│  │  └────────────────────────────┘  │                │                      │
│  └──────────┬───────────────────────┘                │                      │
│             │ proxied LLM API calls                  │                      │
│             ▼                                        │                      │
│  ┌──────────────────────┐                            │                      │
│  │  LLM Provider        │                            │                      │
│  │  (Anthropic, OpenAI, │                            │                      │
│  │   Google, etc.)      │                            │                      │
│  └──────────────────────┘                            │                      │
│                                                      ▼                      │
│  ┌───────────────────────────────────────────────────┴───────────────────┐  │
│  │                      OpenClaw Gateway                                 │  │
│  │                                                                       │  │
│  │   Events emitted:                  Commands accepted:                 │  │
│  │     tool_call / tool_result          exec.approval.resolve            │  │
│  │     exec.approval.requested          skills.update (enable/disable)   │  │
│  │     session.tool / agent             config.get / config.patch        │  │
│  │     session.message                  tools.catalog / skills.status    │  │
│  │                                      sessions.list / subscribe        │  │
│  │                                                                       │  │
│  │   LLM traffic routed through guardrail proxy via fetch interceptor    │  │
│  │   plugin (patches globalThis.fetch — no openclaw.json model changes) │  │
│  └──────────────────────────┬─────────────────────────────────────────────┘ │
│                              │                                              │
│                              ▼                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                   NVIDIA OpenShell Sandbox                          │    │
│  │                                                                     │    │
│  │   OpenClaw runtime executes inside sandbox                          │    │
│  │   Kernel-level isolation: filesystem, network, process              │    │
│  │   Policy YAML controls permissions                                  │    │
│  │                                                                     │    │
│  │   ┌────────────────────────────────────────────┐                    │    │
│  │   │  OpenClaw Agent Runtime                    │                    │    │
│  │   │    Skills, MCP servers, LLM interactions   │                    │    │
│  │   └────────────────────────────────────────────┘                    │    │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│                              ┌──────────────────┐                           │
│                              │  SIEM / SOAR      │                          │
│                              │  (Splunk, etc.)   │                          │
│                              └──────────────────┘                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

### 1. CLI (Python)

The CLI is the operator-facing tool for running security scans and managing
policy. It shells out to Python scanner CLIs and writes results directly to
the shared SQLite database.

| Responsibility | Detail |
|----------------|--------|
| Run scanners | `skill scanner`, `mcp scanner`, `plugin scanner`, `aibom`, CodeGuard |
| Write to DB | Scan results, AIBOM inventory, block/allow list edits |
| Communicate with gateway | REST API calls to trigger enforcement actions, emit audit events to SIEM, and apply actions to OpenClaw |
| Output formats | Human-readable (default), JSON (`--json`), table |

### 2. Plugins / Hooks (JS/TS)

The OpenClaw plugin registers a `before_tool_call` hook and three slash
commands. It connects to the gateway over REST to report activity and
request enforcement.

| Responsibility | Detail |
|----------------|--------|
| Tool call interception | `api.on("before_tool_call")` — sends tool details to gateway for policy check before execution |
| Slash commands | `/scan`, `/block`, `/allow` — operator actions from chat |
| Communicate with gateway | REST API calls to trigger scans, manage block/allow lists |

### 3. DefenseClaw Gateway (Go)

The gateway is the central daemon that ties everything together. It is the
only component with direct access to all subsystems.

| Responsibility | Detail |
|----------------|--------|
| REST API server (`:18970`) | Accepts requests from CLI and plugins; CSRF-protected, localhost-bound |
| Guardrail proxy (`:4000`) | HTTP reverse proxy that inspects all LLM traffic; rate-limited (100/s, burst 200) |
| OpenClaw WebSocket client | Connects via protocol v3, HMAC-SHA256 challenge-response auth, sequence tracking |
| Event router | Dispatches WebSocket events (`tool_call`, `tool_result`, `exec.approval.requested`, `session.message`, `agent`) with judge semaphore (cap 16) |
| Command dispatch | Sends RPC commands to OpenClaw: `exec.approval.resolve`, `skills.update`, `config.get`, `config.patch`, `tools.catalog`, `sessions.list` |
| Enforcement engine | Manages block/allow lists in SQLite (`internal/enforce/`) — separate from OPA |
| OPA policy engine | Runs Rego policies for admission, guardrail verdicts, firewall, audit, sandbox, skill-actions — compiled once via `sync.Once` |
| Inspection pipeline | 4-stage detection: (1) regex patterns → (2) Cisco AI Defense cloud scanner → (3) LLM judge → (4) OPA verdict aggregation |
| Audit / SIEM | Logs all events to SQLite (WAL), rotating JSONL (50MB via lumberjack), Splunk HEC, OpenTelemetry |
| Webhook dispatch | Pushes enforcement events to Slack (Block Kit), PagerDuty (Events v2), Webex, generic HMAC-SHA256 with severity/event filtering and retry |
| Firewall | Kernel-level network filtering (iptables on Linux, pfctl on macOS) |
| Watcher | File system monitoring for skill installation/removal events |
| Inventory | Tracks installed skills/MCP servers (AIBOM) |
| Daemon control | PID file management, process lifecycle (start/stop/restart), lumberjack log rotation |
| Telemetry | OpenTelemetry tracing and metrics (spans for tools, approvals, LLM calls, guardrail stages, agent lifecycle) |
| TUI dashboard | 13-panel Bubbletea terminal UI (Overview, Alerts, Skills, MCPs, Plugins, Inventory, Policy, Logs, Audit, Activity, Tools, Setup, First Run) |
| PII redaction | Two-layer redaction: `<redacted len=N sha=8hex>` — sink layer always redacts regardless of reveal flag |
| Hot reload | `guardrail_runtime.json` checked every 5s; updates mode and blockMessage under RWMutex |

### 4. SQLite Database

Single shared database used by CLI (direct write), gateway (read/write),
and plugins (read/write via gateway REST API).

| Table | Writers | Readers |
|-------|---------|---------|
| Scan results | CLI | Gateway, plugins, TUI |
| Block/allow lists | CLI | Gateway (admission gate) |
| Skill inventory (AIBOM) | CLI | Gateway, plugins, TUI |

### 5. LLM Guardrail (Fetch Interceptor + Go Proxy)

The guardrail intercepts all LLM traffic between OpenClaw and upstream
providers. A TypeScript fetch interceptor plugin patches `globalThis.fetch`
inside OpenClaw's Node.js process, routing all outbound LLM calls through
the Go guardrail reverse proxy regardless of which provider the user selects.

| Responsibility | Detail |
|----------------|--------|
| Universal interception | Fetch interceptor patches `globalThis.fetch` + `https.request`, covering 20+ providers via Bifrost SDK (v1.5.2) |
| 4-stage inspection | (1) 113 regex rules across 6 categories → (2) Cisco AI Defense cloud scanner (12 rules) → (3) LLM Judge (Claude Sonnet, reentrancy-guarded) → (4) OPA policy verdict aggregation |
| Detection strategies | `regex_only` (fastest), `regex_judge` (default — regex triages, judge verifies ambiguous), `judge_first` (most accurate, highest cost) |
| Provider routing | Bifrost SDK routes to correct provider based on model format (`provider/model-name`) and API key prefix inference. Tenant-isolated: each `(provider, sha256(key), baseURL)` gets dedicated client |
| Streaming inspection | Buffers first 8KB for tool call detection; `toolCallAccumulator` merges delta fragments; mid-stream inspection every 500 bytes; can terminate stream on CRITICAL finding |
| Auth separation | `X-AI-Auth` header carries the real provider key; `X-DC-Auth` carries the DefenseClaw sidecar token |
| Observe mode | Logs findings with colored output, never blocks (default, recommended to start) |
| Action mode | Blocks prompts/responses that match security policies by raising exceptions |
| Transparent proxy | No agent code changes required — the interceptor is invisible to OpenClaw |
| Concurrency | RWMutexes (`rtMu`, `engineMu`, `spanMu`, `cfgMu`), judge semaphore (cap 16), rate limiter (100/s burst 200), connection pool (20 idle, 10/host) |

**How it connects:**

1. `defenseclaw setup guardrail` registers the plugin in `openclaw.json`
2. On OpenClaw start, the fetch interceptor activates and patches `globalThis.fetch`
3. All outbound LLM calls are routed through `localhost:4000` with auth headers injected
4. The Go proxy inspects traffic, then forwards to the real upstream provider

See `docs/GUARDRAIL.md` for the full data flow.

## Data Flow

### Scan and Enforcement Flow

```
                CLI (scan)                    Plugin (hook)
                    │                              │
                    │ 1. Run scanner                │ 1. OpenClaw event fires
                    │ 2. Write results to DB        │
                    │                              │
                    ▼                              ▼
              ┌──────────────────────────────────────┐
              │           Gateway REST API            │
              │                                      │
              │  3. Log audit event                  │
              │  4. Forward to SIEM (if configured)  │
              │  5. Dispatch to webhooks (if config) │
              │  6. Evaluate policy (if action req)  │
              │  7. Send command to OpenClaw via WS   │
              └──────────────────────────────────────┘
                              │
                              ▼
                    OpenClaw Gateway (WS)
                              │
                              ▼
                  Action applied (e.g. skill
                  disabled, approval denied,
                  config patched)
```

### LLM Traffic Inspection Flow

```
  OpenClaw Agent       Fetch Interceptor       Guardrail Proxy        LLM Provider
       │              (in-process plugin)     (localhost:4000)      (any provider)
       │                      │                      │                    │
       │  1. fetch(provider)  │                      │                    │
       ├─────────────────────►│                      │                    │
       │                      │                      │                    │
       │               2. Redirect to localhost      │                    │
       │                  + X-AI-Auth (provider key) │                    │
       │                  + X-DC-Target-URL           │                    │
       │                      ├─────────────────────►│                    │
       │                      │                      │                    │
       │                      │  3. pre_call scan    │                    │
       │                      │     (injection,      │                    │
       │                      │      secrets, PII)   │                    │
       │                      │                      │                    │
       │                      │  [action: block]     │                    │
       │                      │                      │                    │
       │                      │                      │  4. Forward        │
       │                      │                      ├───────────────────►│
       │                      │                      │◄───────────────────┤
       │                      │                      │                    │
       │                      │  5. post_call scan   │                    │
       │                      │     (leaked secrets, │                    │
       │                      │      tool anomalies) │                    │
       │                      │                      │                    │
       │  6. Response         │◄─────────────────────┤                    │
       │◄─────────────────────┤                      │                    │
       │                      │                      │                    │
```

### Admission Gate

```
Block list? ──YES──▶ reject, log to DB, audit event to SIEM, alert
     │
     NO
     │
Allow list? ──YES──▶ skip scan, install, log to DB, audit event
     │
     NO
     │
   Scan
     │
  CLEAN ───────────▶ install, log to DB
     │
  HIGH/CRITICAL ───▶ reject, log to DB, audit event to SIEM, alert,
     │                 send skills.update(enabled=false) via gateway
  MEDIUM/LOW ──────▶ install with warning, log to DB, audit event
```

## Connector Architecture

DefenseClaw supports four agent frameworks via its pluggable connector system
(`internal/gateway/connector/`). Each connector adapts the sidecar to a specific
agent runtime's authentication, routing, and hook mechanisms.

### Built-in Connectors

| Connector | Framework | ToolInspectionMode | SubprocessPolicy | Hook Events |
|-----------|-----------|-------------------|-----------------|-------------|
| `openclaw` | OpenClaw | Both | Sandbox | Plugin-based (fetch interceptor) |
| `claudecode` | Claude Code | Both | Sandbox | 26 shell hook events |
| `codex` | Codex | Both | Sandbox | 5 shell hook events |
| `zeptoclaw` | ZeptoClaw | Both | Sandbox | Proxy-side response-scan only |

### Connector Interface

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
    SetCredentials(gatewayToken, masterKey string)
    VerifyClean(opts SetupOpts) error
}
```

**Optional interfaces**: `HookEndpoint`, `AllowedHostsProvider`, `ComponentScanner`,
`StopScanner`, `AgentPathProvider`, `EnvRequirementsProvider`, `HookScriptOwner`,
`ProviderProbe` (gateway refuses to start with 0 usable providers unless `AllowEmptyProviders` set).

### Connector Registry

`Registry` (`connector/registry.go`) prevents plugin name collisions with built-in connectors.
`NewDefaultRegistry()` pre-loads all four built-ins. Plugin connectors loaded via
`DiscoverPlugins(dir)` from `~/.defenseclaw/plugins/*.so`.

### Proxy Routing (per-connector /c/ prefix)

Each connector's Setup configures the agent to use a connector-prefixed URL:
```
Claude Code  → ANTHROPIC_BASE_URL=http://proxy:4000/c/claudecode
Codex        → OPENAI_BASE_URL=http://proxy:4000/c/codex
ZeptoClaw    → api_base: http://proxy:4000/c/zeptoclaw
OpenClaw     → Fetch interceptor sets X-DC-Target-URL header (no prefix)
```

The proxy strips `/c/<name>/`, identifies the connector, calls `Route()` for
signal extraction, then forwards to the resolved upstream.

### Configuration

```yaml
claw:
  mode: openclaw            # or: claudecode, codex, zeptoclaw
  home_dir: ""              # override auto-detected home (e.g. ~/.openclaw)

guardrail:
  connectors: [claudecode]  # multi-connector list (overrides claw.mode for proxy)
```

All skill and MCP directory resolution, watcher paths, scan targets, and install
candidate lookups derive from the active claw mode. The connector registry
resolves implementation by name.

### OpenClaw Skill Resolution Order

| Priority | Path | Source |
|----------|------|--------|
| 1 | `~/.openclaw/workspace/skills/` | Workspace/project-specific skills |
| 2 | Custom `skills_dir` from `~/.openclaw/openclaw.json` | User-configured custom path |
| 3 | `~/.openclaw/skills/` | Global user-installed skills |

## Component Communication Summary

```
┌─────────┐    REST     ┌──────────────┐    WS (v3)    ┌──────────────┐
│   CLI   │───────────▶│  DefenseClaw │──────────────▶│   OpenClaw   │
│ (Python)│            │   Gateway    │               │   Gateway    │
└─────────┘            │   (Go)       │◀──────────────│              │
                        │              │  events        └──────┬───────┘
┌─────────┐    REST     │  ┌────────┐  │                       │
│ Plugins │───────────▶│  │Inspect │  │───────▶  SIEM          │ LLM API calls
│ (JS/TS) │            │  │Engine  │  │                       │ (OpenAI format)
└─────────┘            │  └────────┘  │◀──────▶  SQLite DB    │
                        │              │                       ▼
┌─────────┐   Hooks     │  ┌────────┐  │               ┌──────────────┐
│ Claude  │───────────▶│  │Connec- │  │               │ LLM Provider │
│ Code /  │  (shell)    │  │tor Reg │  │               └──────────────┘
│ Codex   │            │  └────────┘  │
└─────────┘            │              │
                        │   runs       │               ┌──────────────┐
                        │   ──────────────────────────▶│  Guardrail   │
                        └──────────────┘               │  Proxy       │
                                                       │  + Guardrail │
                                                       └──────┬───────┘
                                                              │
                                                              ▼
                                                       LLM Provider
                                                    (Anthropic, OpenAI…)
```

## Internal Packages (Go Gateway)

The Go gateway is organized into 19 internal packages:

| Package | Purpose |
|---------|---------|
| `gateway/` | Core: GuardrailProxy (`:4000`), APIServer (`:18970`), WebSocket Client, Event Router, Inspection Engine, LLM Judge, Cisco AI Defense client, Bifrost provider integration |
| `audit/` | SQLite WAL store — 8 tables, 5s busy timeout |
| `cli/` | Go CLI (Cobra commands for gateway, policy, etc.) |
| `config/` | Full config schema with LLM resolution, hot-reload support |
| `daemon/` | PID file management, process lifecycle, lumberjack log rotation |
| `enforce/` | Block/allow list PolicyEngine (SQLite JSON actions) — distinct from OPA. SkillEnforcer/PluginEnforcer (quarantine), MCPEnforcer (endpoint blocking) |
| `firewall/` | Kernel-level network filtering (iptables/pfctl). Compiler interface, `RulesHash` drift detection (SHA-256, 12-char hex), `Observe` subsystem (lsof + skill domain scanning) |
| `gatewaylog/` | Structured JSONL event writer with fanout callbacks (rotating, 50MB) |
| `guardrail/` | RulePack loading, JudgeYAML definitions, LRU-cached suppressions |
| `inventory/` | Installed skills/MCP server tracking (AIBOM) |
| `notify/` | Cross-platform desktop notifications (osascript on macOS, notify-send on Linux, stderr fallback) for watchdog alerts |
| `policy/` | OPA engine — 7 Rego files (admission, guardrail, firewall, audit, skill_actions, sandbox, openshell), compiled once via `sync.Once` |
| `redaction/` | Two-layer PII redaction: `<redacted len=N sha=8hex>`, ForSink variants always redact |
| `sandbox/` | NVIDIA OpenShell sandbox policy enforcement |
| `scanner/` | 9 built-in scanner implementations: ClawShield (injection, malware, PII, secrets, vuln), CodeGuard, MCP scanner, Skill scanner, Plugin scanner. Common `Scanner` interface |
| `telemetry/` | OpenTelemetry: `guardrail/{stage}` and `guardrail.{phase}` span hierarchy, `inspect/{tool}` spans, 20+ metric instruments (verdicts, judge latency, cache hits, sink delivery, stream lifecycle) |
| `tui/` | 13-panel Bubbletea dashboard (Lipgloss + Bubbles); 201 TUI command entries |
| `watcher/` | File system monitoring (fsnotify) with 500ms debounce, three-phase admission gate (pre-scan OPA → scan → post-scan OPA), periodic rescan (60-min default) with 8-type drift detection, policy file watching (2s poll) |

## Multi-Turn Injection Detection

The event router maintains a `ContextTracker` (`internal/gateway/context_tracker.go`)
that buffers per-session conversation history and detects multi-turn prompt
injection attacks — where an attacker spreads malicious instructions across
several user messages to evade single-turn pattern matching.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `maxTurns` | 10 | Messages retained per session (FIFO ring buffer) |
| `maxSessions` | 200 | Total sessions tracked (LRU eviction when exceeded) |
| `sessionTTL` | 30 min | Idle sessions are evicted after this period |
| `staleSweepFrequency` | every 50 writes | Amortized sweep cost — no dedicated goroutine |

**Detection flow:**

1. Every `session.tool` / `session.message` event records the user turn via
   `ContextTracker.Record(sessionKey, role, content)`.
2. On each exec approval request, the router calls
   `HasRepeatedInjection(sessionKey, threshold=3)`.
3. `HasRepeatedInjection` scans all buffered user turns against the active
   regex pattern set (honoring rule pack overrides). If 3+ turns contain
   injection-like patterns, the request is denied automatically.
4. The context buffer is also passed to the `GuardrailInspector` via
   `RecentMessages()` so the LLM judge can evaluate multi-turn context.

**Eviction strategy:** LRU by `LastSeen` timestamp. When `maxSessions` is
exceeded, the oldest 25% of sessions are pruned in O(n log n) via a
snapshot-and-sort pass. TTL-based eviction runs every 50 `Record` calls.

## Security Notification Queue

The guardrail proxy maintains a `NotificationQueue` (`internal/gateway/notifications.go`)
that injects security enforcement alerts into LLM conversations as system
messages, ensuring the AI informs the user about blocked or quarantined
components.

**How it works:**

1. When the watcher detects and enforces a blocked skill/MCP/plugin, it pushes
   a `SecurityNotification` to the queue with: subject type, skill name,
   severity, finding count, actions taken, and reason.
2. Each notification has a 2-minute TTL. The queue is capped at 50 entries.
3. Before every LLM request, the proxy calls `FormatSystemMessage()` which
   returns a formatted `[DEFENSECLAW SECURITY ENFORCEMENT]` block containing
   all active (unexpired) notifications.
4. This message is prepended to the LLM request as a system message, instructing
   the model to proactively inform the user about the enforcement action.
5. Notifications are not drained on read — every session sees them until expiry.

## Audit Bridge

The `auditBridge` (`internal/gateway/audit_bridge.go`) translates audit events
from the SQLite store into the structured JSONL gateway log, providing a
single correlated observability stream.

- Registered as a callback on `audit.Logger` — fires on every persisted event.
- Translates audit actions into `gatewaylog.EventLifecycle` with subsystem
  inference (scanner, watcher, gateway, api, sinks, telemetry, enforcement).
- Skips actions that already have dedicated structured emissions on the hot
  path (`guardrail-verdict`, `llm-judge-response`) to avoid duplicate rows.
- Stateless: relies on `audit.sanitizeEvent` for PII redaction — forwards
  text verbatim without re-running detection.

## Plugin Scanner Registry

The `plugins/` package provides an extensible scanner plugin system:

- **`Scanner` interface** (`plugins/plugin.go`): `Name()`, `Version()`,
  `SupportedTargets()`, `Scan(ctx, target) (*ScanResult, error)`.
- **`Registry`** (`plugins/registry.go`): discovers plugins from filesystem
  directories by looking for `plugin.yaml` manifests in subdirectories.
- **Custom scanners**: implement the `Scanner` interface as a Go binary.
  See `plugins/examples/custom-scanner/main.go` for a working example.
- **Integration**: the TUI Plugins panel shows installed plugins with
  status and install/remove/quarantine actions.

## Built-in Scanner Catalog

The `internal/scanner/` package provides 9 scanner implementations sharing a
common `Scanner` interface (`Name()`, `Version()`, `SupportedTargets()`,
`Scan(ctx, target)`):

| Scanner | File | Targets | Detection Method |
|---------|------|---------|-----------------|
| ClawShield Injection | `clawshield_injection.go` | skill, code | 3-tier: regex patterns, base64 + entropy analysis, Unicode analysis |
| ClawShield Malware | `clawshield_malware.go` | skill, code | Magic bytes (ELF/PE/Mach-O/Java/WASM), reverse shells, cryptominers, C2 signatures, high-entropy blobs, zip-slip |
| ClawShield PII | `clawshield_pii.go` | skill, code | 10 categories: credit cards (Luhn), SSN, email, phone, IPv4, DOB, passport, driver's license, bank account, medical ID |
| ClawShield Secrets | `clawshield_secrets.go` | skill, code | 13+ providers: AWS, GCP, Azure, GitHub, GitLab, Slack, Stripe, Twilio, SendGrid, NPM, PyPI, private keys, JWT, bearer tokens |
| ClawShield Vuln | `clawshield_vuln.go` | skill, code | SQL injection, SSRF, path traversal, command injection, XSS |
| CodeGuard | `codeguard.go` | code | 10 built-in rules + custom YAML rules from `~/.defenseclaw/codeguard-rules/`. Hardcoded credentials, unsafe exec, network, deserialization, weak crypto |
| MCP Scanner | `mcp.go` | mcp | Shells out to `cisco-ai-mcp-scanner` CLI. Config: `Analyzers`, `ScanPrompts`, `ScanResources`, `ScanInstructions`. Env: `MCP_SCANNER_*` |
| Skill Scanner | `skill.go` | skill | Shells out to `cisco-ai-skill-scanner` CLI. Modes: LLM, behavioral, meta, trigger, VirusTotal, AI Defense. Env: `SKILL_SCANNER_*` |
| Plugin Scanner | `plugin.go` | plugin | Shells out to `defenseclaw plugin scan` or direct binary. Config: `Policy`, `Profile` |

Scanners are instantiated directly by constructors — there is no centralized
registry in this package. The watcher selects the scanner by install type;
the guardrail proxy uses the ClawShield and CodeGuard scanners for inline
inspection.

## Enforcement Engine

The `internal/enforce/` package provides three enforcers for post-admission
actions:

| Enforcer | Action | Mechanism |
|----------|--------|-----------|
| `SkillEnforcer` | `Quarantine(path)` | Moves skill to `<quarantine>/skills/`, removes original. `Restore()` reverses. `IsQuarantined()` checks status |
| `MCPEnforcer` | `BlockEndpoint(url)` | Adds URL to sandbox policy deny list. `AllowEndpoint()` reverses |
| `PluginEnforcer` | `Quarantine(path)` | Same as SkillEnforcer but for `<quarantine>/plugins/` |

This is separate from the OPA policy engine — it manages SQLite-backed
block/allow lists and filesystem quarantine operations.

## Firewall Subsystem

The `internal/firewall/` package provides kernel-level network filtering:

**Compiler interface:**

| Method | Purpose |
|--------|---------|
| `Platform()` | Returns platform name (`pf` or `iptables`) |
| `Compile(cfg)` | Generates firewall rules from `FirewallConfig` |
| `ValidateArg(arg)` | Validates a rule argument |
| `ApplyCommand(path)` | Returns the shell command to apply rules |
| `RemoveCommand()` | Returns the shell command to remove rules |

**Drift detection:** `RulesHash(rules)` returns a 12-character hex SHA-256
fingerprint of the active ruleset (comments excluded). `GetStatus()` queries
the running firewall and returns rule count, anchor name, active state, and
last-checked timestamp.

**Observation:** `Observe(ctx, skillDirs)` discovers active network
connections via `lsof`, scans skill source files for URL patterns (`.py`,
`.js`, `.go`, `.yaml`, `.json`, `.env`), and proposes a deny-by-default
config with an allowlist. `findWouldBlock()` shows what existing connections
would be blocked.

**Config defaults:** Anchor name `com.defenseclaw`, default action `allow` or
`deny`, only `outbound` direction supported. Pre-populated allowlist includes
Anthropic, OpenAI, GitHub, and other known LLM provider domains.

## Dual Policy Engines

DefenseClaw has two distinct policy evaluation systems — do not confuse them:

| Engine | Package | Purpose | Data source |
|--------|---------|---------|-------------|
| **Enforcement Engine** | `internal/enforce/` | Block/allow list gate: checks SQLite `actions` table for explicit block/allow entries | SQLite JSON actions |
| **OPA Policy Engine** | `internal/policy/` | Rego-based policy evaluation for admission, guardrail verdicts, firewall rules, sandbox controls | 7 `.rego` files in `policies/rego/` |

The enforcement engine runs first (static block/allow lookup), and if the item is not explicitly listed, the OPA engine evaluates the appropriate Rego policy.

### OPA Admission Methods

| Method | Policy path | Returns |
|--------|------------|---------|
| `EvaluateAdmission()` | `data.defenseclaw.admission` | verdict, reason, file_action, install_action, runtime_action |
| `EvaluateGuardrail()` | `data.defenseclaw.guardrail` | action (allow/alert/block), severity, reason |
| `EvaluateSkillActions()` | `data.defenseclaw.skill_actions` | runtime_action, file_action, install_action, should_block |
| `EvaluateFirewall()` | `data.defenseclaw.firewall` | firewall rules output |
| `EvaluateSandbox()` | `data.defenseclaw.sandbox` | sandbox policy output |
| `EvaluateAudit()` | `data.defenseclaw.audit` | audit policy output |

### OPA Fallback Profile

When the OPA engine fails to load or evaluate, admission falls back to
`EvaluateAdmissionFallback()` using a `FallbackProfile` loaded from the
policy directory:

- `AllowListBypassScan` — allow-listed items skip scanning entirely
- `ScanOnInstall` — whether to scan on install events
- `Actions` — maps severity (CRITICAL/HIGH/MEDIUM/LOW/INFO) to per-surface
  actions (runtime, file, install)
- `ScannerOverrides` — per-target-type severity overrides (MCP and plugin
  scanners may have different thresholds than skill scanners)
- `FirstPartyAllow` — built-in allowlist for DefenseClaw's own plugins/skills
  with path provenance matching

## Inspection Pipeline Detail

The guardrail proxy runs a 4-stage inspection pipeline on every LLM request (pre-call and post-call):

```
Stage 1: Regex Rules (microseconds)
  113 compiled patterns across 6 categories:
    secretRules, commandRules, sensitivePathRules,
    c2Rules, cognitiveFileRules, trustExploitRules
  Output: RuleFinding{RuleID, Severity, Confidence, Evidence}
         │
         ▼
Stage 2: Cisco AI Defense (cloud, ~3s)
  POST to us.api.inspect.aidefense.security.cisco.com
  12 default rules (Prompt Injection, Jailbreak, PII, etc.)
  Retry logic: 400 "already configured" → retry without rules
         │
         ▼
Stage 3: LLM Judge (optional, model-dependent)
  Three detection strategies:
    regex_only  → skip judge entirely
    regex_judge → judge verifies ambiguous regex findings only
    judge_first → judge runs primary, regex as safety net
  Judge types: injection, pii, tool-injection
  Reentrancy guard: judgeCtxKey prevents infinite recursion
  Suppression engine: LRU regex cache (1024), NANP phone heuristic
         │
         ▼
Stage 4: OPA Policy (guardrail.rego)
  Aggregates max severity across all scanners
  block_threshold: HIGH (rank 3)
  alert_threshold: MEDIUM (rank 2)
  Observe mode: downgrades block → alert
  Output: final verdict (allow / alert / block)
```

## Watcher Subsystem Detail

The `internal/watcher/` package monitors skill, MCP, and plugin directories
for installation events and runs a multi-phase admission gate.

### Event Processing

File system events from fsnotify are debounced via a pending map
(`path → first-seen timestamp`). Default debounce: 500ms (configurable via
`watch.debounce_ms`; values ≤ 0 fall back to 500ms). Events are classified
by install type:

| Type | Classification |
|------|---------------|
| `skill` | Default for paths under skill directories |
| `plugin` | Paths under plugin directories |
| `mcp` | Enumerated from `openclaw.json` during rescan |

### Three-Phase Admission Gate

```
Phase 1: Pre-scan OPA
  ├── Build block/allow lists from SQLite
  ├── Load fallback profile from policy directory
  ├── Evaluate pre-scan policy (OPA or fallback)
  └── Verdict: blocked | rejected | allowed (skip scan) | scan (continue)
         │
Phase 2: Scanning (5-minute timeout)
  ├── Select scanner by install type
  │   ├── Skill → SkillScannerFromLLM
  │   ├── MCP → MCPScannerFromLLM
  │   └── Plugin → PluginScanner
  └── Per-scanner LLM config overrides via cfg.ResolveLLM()
         │
Phase 3: Post-scan OPA
  ├── Add scan findings to policy input (ScanResultInput)
  ├── Re-evaluate with findings (OPA or fallback)
  └── Apply enforcement: file_action, install_action, runtime_action
```

### Periodic Rescan and Drift Detection

When `watch.rescan_enabled` is `true` (default), a rescan loop runs
immediately on startup and then every `watch.rescan_interval_min` minutes
(default: 60). Each cycle:

1. Enumerates all installed targets (skill/plugin child directories + MCP
   servers from `openclaw.json`).
2. Takes a `TargetSnapshot` per target: content SHA-256 hash, dependency
   file hashes (13 patterns: `requirements.txt`, `package.json`, `go.mod`,
   etc.), config file hashes (10 patterns: `skill.yaml`, `.env`, etc.),
   and extracted network endpoints.
3. Compares against the stored baseline to produce drift deltas.

Network endpoint extraction scans code files (`.py`, `.js`, `.ts`, `.go`,
`.rb`, `.java`, `.rs`, `.php`, `.sh`) up to 512 KB per file, filtering
localhost/example.com/0.0.0.0 prefixes. Directories `.git`, `node_modules`,
`__pycache__`, `.venv`, `venv` are skipped.

MCP servers have a special snapshot path: no filesystem walk — the snapshot
is synthesized from the `openclaw.json` entry with a config hash and URL
endpoint.

### Policy File Watching

`watchPolicyListsAndYAML` runs independently on a 2-second polling interval,
monitoring:

- `{datadir}/block_list.yaml` and `allow_list.yaml`
- All `.yaml`, `.yml`, `.json`, `.rego` files in the policy directory

Changes are detected by SHA-256 hash comparison. On change, the watcher
records an `audit.ActionPolicyReload` event and bumps the version generation
via `version.BumpGeneration()`.

## Telemetry Span and Metric Hierarchy

### Span Names

| Span | Pattern | Attributes |
|------|---------|-----------|
| Stage-level guardrail | `guardrail/{stage}` | `defenseclaw.guardrail.{stage, direction, model, action, severity, reason, latency_ms}` |
| Phase-level guardrail | `guardrail.{phase}` | `defenseclaw.guardrail.{phase, action, severity, latency_ms}` |
| Tool inspection | `inspect/{tool}` | `defenseclaw.inspect.{tool, action, severity, latency_ms}` |
| Sidecar startup | `defenseclaw/startup` | `defenseclaw.event = "sidecar_start"` |

Guardrail phases: `regex`, `cisco_ai_defense`, `judge.pii`,
`judge.prompt_injection`, `opa`, `finalize`.

### Metric Instruments

| Metric | Type | Labels |
|--------|------|--------|
| `defenseclaw.gateway.verdicts` | Counter | verdict.stage, verdict.action, verdict.severity, policy_id, destination_app |
| `defenseclaw.gateway.judge.invocations` | Counter | judge.kind, judge.action, judge.severity |
| `defenseclaw.gateway.judge.latency` | Histogram | judge.kind |
| `defenseclaw.gateway.judge.errors` | Counter | judge.kind, judge.reason (provider \| parse) |
| `defenseclaw.guardrail.evaluations` | Counter | guardrail.scanner, guardrail.action_taken |
| `defenseclaw.guardrail.latency` | Histogram | guardrail.scanner |
| `defenseclaw.guardrail.judge.latency` | Histogram | gen_ai.request.model, judge.kind |
| `defenseclaw.guardrail.cache.hits` | Counter | scanner, verdict, ttl_bucket |
| `defenseclaw.guardrail.cache.misses` | Counter | scanner, verdict, ttl_bucket |
| `defenseclaw.redaction.applied` | Counter | detector, field |
| `defenseclaw.egress.events` | Counter | branch (known \| shape \| passthrough), decision (allow \| block), source (go \| ts) |
| `defenseclaw.audit.sink.batches.delivered` | Counter | sink, kind, status_code, retry_count |
| `defenseclaw.audit.sink.batches.dropped` | Counter | sink, kind, status_code, retry_count |
| `defenseclaw.audit.sink.queue.depth` | Gauge | sink.kind, sink.name |
| `defenseclaw.audit.sink.circuit.state` | Gauge | sink.kind, sink.name (0=closed, 1=open, 2=half-open) |
| `defenseclaw.audit.sink.delivery.latency` | Histogram | sink, kind, status_code, retry_count |
| `defenseclaw.stream.lifecycle` | Counter | http.route, transition (open \| close), outcome |
| `defenseclaw.stream.bytes_sent` | Counter | http.route, outcome |
| `defenseclaw.stream.duration_ms` | Histogram | http.route, outcome |
| `defenseclaw.schema.violations` | Counter | event_type, code |
