# Sandbox Scanning: Skill & MCP Scanning Inside OpenShell

> **Status:** PROPOSAL (designed, not implemented)

## Problem

When OpenClaw runs inside an OpenShell sandbox, the host-side Go sidecar's
filesystem watcher (`fsnotify`) cannot see files inside the sandbox. Skills and
MCP servers installed by the agent go completely undetected — no scan, no block
list check, no audit trail.

## Two Operating Modes

DefenseClaw must support two mutually exclusive deployment topologies. The
scanning and enforcement path differs depending on which mode is active.

### Host Mode (no sandbox)

```
┌─── Host ──────────────────────────────────────────────────┐
│                                                            │
│  OpenClaw Gateway (ws://127.0.0.1:18789)                   │
│    └── DefenseClaw Plugin                                  │
│         └── before_tool_call → REST → sidecar inspect API  │
│                                                            │
│  DefenseClaw Sidecar                                       │
│    ├── fsnotify watcher (skill/MCP dirs)                   │
│    ├── skill-scanner CLI (shell out)                       │
│    ├── block/allow lists (SQLite)                          │
│    ├── enforcement (skills.update RPC)                     │
│    ├── audit store (SQLite)                                │
│    └── REST API (127.0.0.1:18790)                          │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

**How it works today:**
1. Go sidecar watches `~/.openclaw/skills/` via `fsnotify`
2. New directory → shell out to `skill-scanner` → evaluate → log → enforce
3. Plugin intercepts tool calls via `before_tool_call` → REST to sidecar
4. All communication is localhost HTTP

**Gap (fixed in this work):** The `before_tool_call` hook does not check the
block list. A blocked skill's tools could execute in the race window between
detection and `skills.update` disable. Fix: plugin syncs block list from
sidecar REST API and checks it in the hook.

### Sandbox Mode (OpenShell)

```
┌─── OpenShell Sandbox ─────────────────────────────────────┐
│                                                            │
│  OpenClaw Gateway (ws://127.0.0.1:18789)                   │
│    └── DefenseClaw Plugin                                  │
│         ├── install-watcher service (fs.watch)             │
│         ├── skill-scanner CLI (shell out, pip installed)   │
│         ├── scanMCPServer (in-process TS)                  │
│         ├── cached block/allow lists                       │
│         ├── before_tool_call → block list check            │
│         └── gateway methods ──────────────────┐            │
│                              WebSocket        │            │
└──────────────────────────────────┼────────────┘────────────┘
                                   │
                         port forward 18789
                                   │
┌─── Host ─────────────────────────┼─────────────────────────┐
│                                  │                         │
│  DefenseClaw Sidecar             │                         │
│    ├── sandbox scan poller ──────┘ (calls gateway methods) │
│    ├── block/allow list push                               │
│    ├── enforcement (skills.update RPC, via same WS)        │
│    ├── audit store (SQLite)                                │
│    └── REST API (127.0.0.1:18790)                          │
│                                                            │
│  Go watcher: DISABLED (cannot see sandbox filesystem)      │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

**Key differences from host mode:**
- Plugin does the filesystem watching (not the Go sidecar)
- Plugin does the scanning (shells out to `skill-scanner` inside sandbox)
- Plugin cannot reach sidecar REST API (network isolation)
- All plugin↔sidecar communication uses gateway methods over WebSocket
- Sidecar polls for results instead of pushing

## Mode Detection

**Plugin side** — checks environment at startup:
- File `/etc/openshell-tls/ca-bundle.pem` exists → sandbox mode
- Env var `OPENSHELL_SANDBOX` is set → sandbox mode
- Otherwise → host mode

**Sidecar side** — reads config:
- `openshell.enabled: true` + `openshell.sandbox_name` set → sandbox mode
- Otherwise → host mode

## Communication Protocol

### Gateway Methods (sandbox mode only)

Two gateway methods registered by the plugin, called by the sidecar over
the existing WebSocket connection:

#### `defenseclaw.scan.poll`

Sidecar calls this every 5 seconds. Plugin returns any queued scan results
and clears the queue.

**Request params:** `{}` (empty)

**Response payload:**
```json
{
  "results": [
    {
      "type": "skill",
      "name": "evil-skill",
      "path": "/sandbox/.openclaw/skills/evil-skill",
      "verdict": "rejected",
      "reason": "2 finding(s) at HIGH or above (max: CRITICAL)",
      "timestamp": "2026-03-26T10:00:00Z",
      "scan_result": {
        "scanner": "skill-scanner",
        "target": "/sandbox/.openclaw/skills/evil-skill",
        "findings": [...]
      }
    }
  ]
}
```

#### `defenseclaw.blocklist.sync`

Sidecar calls this on connect and whenever block/allow lists change.
Pushes the full lists to the plugin.

**Request params:**
```json
{
  "blocked": [
    { "target_type": "skill", "target_name": "evil-skill", "reason": "malicious" }
  ],
  "allowed": [
    { "target_type": "skill", "target_name": "trusted-skill", "reason": "vetted" }
  ]
}
```

**Response payload:** `{ "ok": true, "cached": 3 }`

### Block List in `before_tool_call` (both modes)

The `before_tool_call` hook gains a block list check. When a tool call
arrives, the plugin resolves which skill/MCP provides it and checks the
cached block list. If blocked, the tool call is cancelled immediately
via `event.cancel()`.

**Host mode:** Block list synced from sidecar REST API (`GET /enforce/blocked`)
on startup and periodically (every 30s).

**Sandbox mode:** Block list synced via `defenseclaw.blocklist.sync` gateway
method (pushed by sidecar on connect and on changes).

## End-to-End Flow (Sandbox Mode)

```
1. User (via Telegram) asks agent to install a skill
2. OpenClaw agent runs skill install → files written to ~/.openclaw/skills/foo/
3. Plugin's fs.watch fires on new directory
4. Plugin debounces (500ms), then shells out to `skill-scanner` CLI
5. skill-scanner returns JSON findings
6. Plugin evaluates: check cached block list → check cached allow list → severity threshold
7. Result queued in memory (AdmissionResult + ScanResult)
8. ──── within 5 seconds ────
9. Sidecar calls defenseclaw.scan.poll via gateway RPC
10. Plugin returns queued result, clears queue
11. Sidecar logs to audit store (SQLite on host)
12. If verdict = blocked/rejected AND take_action = true:
    a. Sidecar calls skills.update RPC → OpenClaw disables the skill
    b. Sidecar logs enforcement action
13. TUI on host shows new alert
14. If the skill's tool is called before disable completes:
    a. before_tool_call hook checks cached block list → event.cancel()
```

## `defenseclaw sandbox setup` Command

A single CLI command that automates all sandbox plumbing:

```
defenseclaw sandbox setup <sandbox-name>
```

### What It Does

| Step | Action | How |
|------|--------|-----|
| 1 | Port forwarding | `openshell forward start 18789 <sandbox>` |
| 2 | Extract gateway token | `openshell sandbox connect` → read `~/.openclaw/openclaw.json` → extract `gateway.auth.token` |
| 3 | Configure sidecar | Write token + sandbox name to `~/.defenseclaw/config.yaml` |
| 4 | Install `defenseclaw` CLI in sandbox | `openshell sandbox connect` → `pip install defenseclaw` |
| 5 | Copy plugin to sandbox | Copy `extensions/defenseclaw/dist/` → sandbox `~/.openclaw/extensions/defenseclaw/` |
| 6 | Restart OpenClaw | Signal OpenClaw inside sandbox to reload plugins |

### Config Changes

After setup, `~/.defenseclaw/config.yaml` gains:

```yaml
gateway:
  token: "<extracted-from-sandbox>"
  watcher:
    enabled: false  # host watcher disabled in sandbox mode

openshell:
  enabled: true
  sandbox_name: "dc-test"
  sandbox_scan_poll_interval_s: 5
```

## Files Changed

### Plugin (TypeScript)

| File | Type | Description |
|------|------|-------------|
| `src/mode.ts` | NEW | `isSandbox()` detection, exports mode constants |
| `src/services/install-watcher.ts` | NEW | Background service: `fs.watch` on skill/MCP dirs, scan, queue |
| `src/services/sandbox-bridge.ts` | NEW | Gateway method handlers + result queue |
| `src/index.ts` | MODIFY | Register service + methods (sandbox), block list check in hook (both) |

### Sidecar (Go)

| File | Type | Description |
|------|------|-------------|
| `internal/gateway/sandbox_scan.go` | NEW | Poll goroutine, blocklist push, result processing |
| `internal/gateway/rpc.go` | MODIFY | Add `ScanPoll()` and `BlocklistSync()` RPC methods |
| `internal/gateway/sidecar.go` | MODIFY | Add goroutine 5 for sandbox poller (when openshell.enabled) |
| `internal/config/config.go` | MODIFY | Add `sandbox_name` and `sandbox_scan_poll_interval_s` to OpenShellConfig |

### CLI (Go)

| File | Type | Description |
|------|------|-------------|
| `internal/cli/sandbox_setup.go` | NEW | `defenseclaw sandbox setup` command implementation |
| `internal/cli/root.go` | MODIFY | Register sandbox subcommand |

### Sandbox Package (Go)

| File | Type | Description |
|------|------|-------------|
| `internal/sandbox/openshell.go` | MODIFY | Add `ForwardPort()`, `RunInSandbox()`, `CopyToSandbox()`, `ReadFileFromSandbox()` methods |

## Prerequisites

Inside the sandbox (handled by `defenseclaw sandbox setup`):
- `pip install defenseclaw` (provides `skill-scanner` + `mcp-scanner`)
- Plugin copied to `~/.openclaw/extensions/defenseclaw/`

## Not In Scope

- LLM guardrail/proxy inside sandbox (network isolation problem, separate effort)
- Auto-creating the sandbox (user runs `openshell sandbox create`)
- Plugin auto-update mechanism
