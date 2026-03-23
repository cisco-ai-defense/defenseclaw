# Architecture

DefenseClaw is a governance layer for OpenClaw. It orchestrates scanning,
enforcement, and auditing across existing tools without replacing any component.

## System Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           DefenseClaw System                                │
│                                                                              │
│  ┌─────────────────────┐       ┌─────────────────────────────────────────┐  │
│  │   CLI (Python)       │       │   Plugins / Hooks (JS/TS)              │  │
│  │                      │       │                                         │  │
│  │  skill-scanner       │       │  OpenClaw plugin lifecycle hooks        │  │
│  │  mcp-scanner         │       │  registerService, registerCommand       │  │
│  │  aibom               │       │  api.on("gateway_start"), etc.          │  │
│  │  codeguard            │       │                                         │  │
│  │  [custom scanners]   │       │  Registers hooks in OpenClaw for:       │  │
│  │                      │       │    - skill install/uninstall             │  │
│  │  Writes scan results │       │    - MCP server connect/disconnect      │  │
│  │  directly to DB      │       │    - gateway start/stop                 │  │
│  └──────────┬───────────┘       └──────────────┬──────────────────────────┘  │
│             │ REST API                          │ REST API                    │
│             │                                   │                            │
│             ▼                                   ▼                            │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │                  Orchestrator (Go daemon)                            │    │
│  │                                                                      │    │
│  │  ┌────────────┐  ┌────────────┐  ┌──────────┐  ┌────────────────┐   │    │
│  │  │  REST API   │  │  Audit /   │  │ Policy   │  │  OpenClaw WS   │   │    │
│  │  │  Server     │  │  SIEM      │  │ Engine   │  │  Client        │   │    │
│  │  │            │  │  Emitter   │  │          │  │                │   │    │
│  │  │ Accepts    │  │            │  │ Block /  │  │ Connects via   │   │    │
│  │  │ requests   │  │ Splunk HEC │  │ Allow /  │  │ WS protocol v3 │   │    │
│  │  │ from CLI   │  │ JSON/CSV   │  │ Scan     │  │                │   │    │
│  │  │ & plugins  │  │ export     │  │ gate     │  │ Subscribes to  │   │    │
│  │  └────────────┘  └────────────┘  └──────────┘  │ all events,    │   │    │
│  │                                                 │ sends commands │   │    │
│  │  ┌──────────────────────┐                       └───────┬────────┘   │    │
│  │  │  SQLite DB            │                               │           │    │
│  │  │                      │                               │           │    │
│  │  │  Audit events        │                               │           │    │
│  │  │  Scan results        │                               │           │    │
│  │  │  Block/allow lists   │                               │           │    │
│  │  │  Skill inventory     │                               │           │    │
│  │  └──────────────────────┘                               │           │    │
│  └──────────────────────────────────────────────────────────┼───────────┘    │
│                                                             │                │
│             ┌───────────────────────────────────────────────┘                │
│             │ WebSocket (events + RPC commands)                              │
│             ▼                                                                │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │                      OpenClaw Gateway                                │    │
│  │                                                                      │    │
│  │   Events emitted:                  Commands accepted:                │    │
│  │     tool_call                        exec.approval.resolve           │    │
│  │     tool_result                      skills.update (enable/disable)  │    │
│  │     exec.approval.requested          config.patch                    │    │
│  │     skill.install / uninstall        [future: mcp.disconnect]        │    │
│  │     mcp.connect / disconnect                                         │    │
│  └──────────────────────────┬───────────────────────────────────────────┘    │
│                              │                                               │
│                              ▼                                               │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │                   NVIDIA OpenShell Sandbox                           │    │
│  │                                                                      │    │
│  │   OpenClaw runtime executes inside sandbox                           │    │
│  │   Kernel-level isolation: filesystem, network, process               │    │
│  │   Policy YAML controls permissions                                   │    │
│  │                                                                      │    │
│  │   ┌────────────────────────────────────────────┐                     │    │
│  │   │  OpenClaw Agent Runtime                    │                     │    │
│  │   │    Skills, MCP servers, LLM interactions   │                     │    │
│  │   └────────────────────────────────────────────┘                     │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│                              ┌──────────────────┐                            │
│                              │  SIEM / SOAR      │                            │
│                              │  (Splunk, etc.)   │                            │
│                              └──────────────────┘                            │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

### 1. CLI (Python)

The CLI is the operator-facing tool for running security scans and managing
policy. It shells out to Python scanner CLIs and writes results directly to
the shared SQLite database.

| Responsibility | Detail |
|----------------|--------|
| Run scanners | `skill-scanner`, `mcp-scanner`, `aibom`, CodeGuard, custom plugins |
| Write to DB | Scan results, AIBOM inventory, block/allow list edits |
| Communicate with orchestrator | REST API calls to trigger enforcement actions, emit audit events to SIEM, and apply actions to OpenClaw |
| Output formats | Human-readable (default), JSON (`--json`), table |

### 2. Plugins / Hooks (JS/TS)

Plugins run inside the OpenClaw plugin lifecycle. They register hooks for
OpenClaw events and connect to the orchestrator over REST to report activity
and request enforcement.

| Responsibility | Detail |
|----------------|--------|
| Hook into OpenClaw events | `gateway_start`, skill install/uninstall, MCP connect/disconnect |
| Background services | Filesystem watcher, continuous scan, real-time alerting |
| Slash commands | `/scan`, `/block`, `/allow` — operator actions from chat |
| Communicate with orchestrator | REST API calls to send audit events to SIEM, read/write DB |

### 3. Orchestrator (Go daemon)

The orchestrator (previously "gateway sidecar") is the central daemon that
ties everything together. It is the only component with direct access to all
subsystems.

| Responsibility | Detail |
|----------------|--------|
| REST API server | Accepts requests from CLI and plugins |
| OpenClaw WebSocket client | Connects via protocol v3, device-key auth, challenge-response |
| Event subscription | Subscribes to all OpenClaw gateway events (`tool_call`, `tool_result`, `exec.approval.requested`, etc.) |
| Command dispatch | Sends RPC commands to OpenClaw: `exec.approval.resolve`, `skills.update`, `config.patch` |
| Policy engine | Runs admission gate: block list → allow list → scan → verdict |
| Audit / SIEM | Logs all events to SQLite, forwards to Splunk HEC (batch or real-time) |
| DB access | Full read/write to SQLite — audit events, scan results, block/allow lists, inventory |

### 4. SQLite Database

Single shared database used by CLI (direct write), orchestrator (read/write),
and plugins (read/write via orchestrator REST API).

| Table | Writers | Readers |
|-------|---------|---------|
| Audit events | CLI, orchestrator | Orchestrator, plugins, TUI, export |
| Scan results | CLI | Orchestrator, plugins, TUI |
| Block/allow lists | CLI | Orchestrator (admission gate) |
| Skill inventory (AIBOM) | CLI | Orchestrator, plugins, TUI |

## Data Flow

```
                CLI (scan)                    Plugin (hook)
                    │                              │
                    │ 1. Run scanner                │ 1. OpenClaw event fires
                    │ 2. Write results to DB        │
                    │                              │
                    ▼                              ▼
              ┌──────────────────────────────────────┐
              │          Orchestrator REST API        │
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
     │                 send skills.update(enabled=false) via orchestrator
  MEDIUM/LOW ──────▶ install with warning, log to DB, audit event
```

## Open Design Questions

### 1. OpenShell Sandbox — Actions & Access Control

OpenClaw runs inside NVIDIA's OpenShell sandbox on DGX Spark. The sandbox
provides kernel-level isolation (filesystem, network, process). DefenseClaw
writes the sandbox policy YAML; OpenShell enforces it.

**Questions to resolve:**

- **Granularity of sandbox policy:** Can individual skills be granted
  different filesystem/network scopes within a single OpenShell session, or is
  the policy session-wide? This determines whether DefenseClaw can enforce
  per-skill least-privilege or only coarse allow/deny at the sandbox level.

- **Runtime policy updates:** Can the OpenShell policy be hot-reloaded while
  OpenClaw is running, or does a policy change require a session restart?
  This affects how quickly a block action takes effect (target: <2 seconds).

- **Network egress control:** Can OpenShell restrict outbound network access
  per-domain or per-port? If so, DefenseClaw can enforce network allowlists
  for MCP servers (e.g., only permit connections to approved API endpoints).

- **Filesystem scope:** Can OpenShell restrict which directories a skill's
  subprocess can read/write? This would allow DefenseClaw to sandbox untrusted
  skills to their own directory tree.

- **Process execution control:** Can OpenShell restrict which binaries a skill
  can spawn? This would let DefenseClaw prevent skills from invoking
  interpreters (`python`, `node`, `bash -c`) outside of approved tool paths.

- **macOS degraded mode:** OpenShell is not available on macOS. What subset of
  access control can be replicated without kernel-level enforcement? Options
  include filesystem watchers + process monitoring (best-effort), or
  accepting that macOS is scan-only with no runtime enforcement.

### 2. Runtime Firewall — Message Inspection

All messages flowing through OpenClaw need to be inspected for prompt
injection, data exfiltration, and tool misuse. This could be implemented as
an OpenClaw plugin hook, inside the orchestrator, or as a combination.

**Questions to resolve:**

- **Hook vs. orchestrator vs. hybrid:** A plugin hook has access to the
  message before the LLM processes it (pre-LLM) and after (post-LLM),
  but adds latency to the chat loop. The orchestrator already receives
  `tool_call` and `tool_result` events via WebSocket, but these arrive
  after-the-fact. A hybrid approach could use hooks for blocking
  (pre-execution) and the orchestrator for async analysis + alerting.

- **Prompt injection detection:** Where does the classifier run? Options:
  (a) lightweight regex/heuristic in the hook for low-latency blocking,
  (b) call out to Cisco AI Defense cloud API for ML-based detection,
  (c) local model inference on DGX Spark. Trade-offs: latency vs. accuracy
  vs. offline capability.

- **Data exfiltration detection:** What signals indicate exfiltration?
  Candidates: (a) tool_call args containing file paths outside workspace,
  (b) outbound HTTP requests to non-allowlisted domains (needs OpenShell
  network telemetry or proxy), (c) large data payloads in tool results,
  (d) base64-encoded content in messages. Where is the policy defined —
  in DefenseClaw config or in OpenShell policy YAML?

- **Tool call inspection:** The orchestrator already pattern-matches
  dangerous commands (`curl`, `wget`, `rm -rf /`, etc.) in the
  `EventRouter`. Should this be extended to a full tool-call policy engine
  that can: (a) allowlist specific tools per skill, (b) restrict tool
  arguments (e.g., `shell` tool can only run commands matching a pattern),
  (c) rate-limit tool calls per skill/session? And should this policy be
  enforced pre-execution (via `exec.approval.requested` hook) or
  post-execution (via `tool_result` analysis)?

- **Blocking vs. alerting:** Which inspection results should block execution
  (synchronous, in the critical path) vs. alert only (asynchronous, logged
  to SIEM)? Blocking adds latency and risks false positives interrupting
  legitimate work. Alerting allows forensic review but doesn't prevent harm.

- **Latency budget:** What is the acceptable added latency per message for
  runtime inspection? The `exec.approval.requested` path already has a
  synchronous gate — adding inspection there must complete within the
  approval timeout window.

## Cross-Platform Behavior

| Capability | DGX Spark (full) | macOS (degraded) |
|------------|-------------------|-------------------|
| CLI scanners | All | All |
| Orchestrator daemon | Full | Full |
| Plugins / hooks | Full | Full |
| Block/allow lists | Full enforcement | Lists maintained, no sandbox enforcement |
| Quarantine | Files moved + sandbox policy | Files moved only |
| OpenShell sandbox | Active | Not available |
| Network enforcement | Via OpenShell | Not enforced |
| Runtime firewall | Full (hook + orchestrator) | Orchestrator-only (no sandbox telemetry) |
| Audit log + SIEM | Full | Full |

## Claw Mode

DefenseClaw supports multiple agent frameworks ("claw modes"). The active mode
is set in `~/.defenseclaw/config.yaml`:

```yaml
claw:
  mode: openclaw          # openclaw | nemoclaw | opencode | claudecode (future)
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
│   CLI   │───────────▶│              │──────────────▶│   OpenClaw   │
│ (Python)│            │ Orchestrator │               │   Gateway    │
└─────────┘            │   (Go)       │◀──────────────│              │
                        │              │  events        └──────────────┘
┌─────────┐    REST     │              │
│ Plugins │───────────▶│              │───────▶  SIEM (Splunk HEC)
│ (JS/TS) │            │              │
└─────────┘            │              │
                        │              │◀──────▶  SQLite DB
                        └──────────────┘
```
