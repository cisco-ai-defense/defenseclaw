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
│  │  │  Inspection Engine (Tool & CodeGuard)       │     │              │    │
│  │  │  /api/v1/inspect/tool                      │     │               │    │
│  │  │  Block list → engine → CodeGuard           │     │               │    │
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
│  │   LLM traffic routed through guardrail proxy via openclaw.json        │  │
│  │   provider config (baseUrl → http://localhost:4000)                   │  │
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
| REST API server | Accepts requests from CLI and plugins |
| OpenClaw WebSocket client | Connects via protocol v3, device-key auth, challenge-response |
| Event subscription | Subscribes to all OpenClaw gateway events (`tool_call`, `tool_result`, `exec.approval.requested`, etc.) |
| Command dispatch | Sends RPC commands to OpenClaw: `exec.approval.resolve`, `skills.update`, `config.patch` |
| Policy engine | Runs admission gate: block list → allow list → scan → verdict |
| LLM guardrail management | Runs guardrail proxy; restarts on crash |
| Audit / SIEM | Logs all events to SQLite, forwards to Splunk HEC (batch or real-time) |
| DB access | Full read/write to SQLite — scan results, block/allow lists, inventory |

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
| Universal interception | Fetch interceptor covers all 7 providers (Anthropic, OpenAI, Azure, Gemini, OpenRouter, Ollama, Bedrock) |
| Prompt inspection | Scans every prompt for injection attacks, secrets, PII, data exfiltration patterns before it reaches the LLM |
| Response inspection | Scans every LLM response for leaked secrets, tool call anomalies |
| Multi-provider routing | Proxy routes to the correct upstream based on `X-DC-Target-URL` header set by the interceptor |
| Auth separation | `X-AI-Auth` header carries the real provider key; `Authorization` carries the DefenseClaw gateway key |
| Observe mode | Logs findings with colored output, never blocks (default, recommended to start) |
| Action mode | Blocks prompts/responses that match security policies by raising exceptions |
| Transparent proxy | No agent code changes required — the interceptor is invisible to OpenClaw |

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
              │  5. Evaluate policy (if action req)  │
              │  6. Send command to OpenClaw via WS   │
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

## Claw Mode

DefenseClaw supports multiple agent frameworks ("claw modes"). Currently only
**OpenClaw** is supported; additional frameworks will be added soon. The active
mode is set in `~/.defenseclaw/config.yaml`:

```yaml
claw:
  mode: openclaw
  home_dir: ""            # override auto-detected home (e.g. ~/.openclaw)
```

All skill and MCP directory resolution, watcher paths, scan targets, and install
candidate lookups derive from the active claw mode. Adding a new framework
requires only a new case in `internal/config/claw.go`.

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
