# OpenShell Standalone Sandbox — Design Document

> **Status:** PROPOSAL (designed, not implemented)

## Overview

This document describes how DefenseClaw integrates with `openshell-sandbox`
in **standalone mode** — a Linux supervisor that wraps OpenClaw in kernel-level
isolation (Landlock, seccomp, network namespace) without Docker or Kubernetes.

The key insight: the sandbox shares the host filesystem (Landlock restricts
paths, it doesn't create an overlay) and uses a veth pair for networking.
This means most of DefenseClaw's existing architecture works unchanged.
The sidecar, LiteLLM, and all enforcement stay on the host.

## Sandbox Model

```bash
openshell-sandbox --policy-rules policy.rego --policy-data policy.yaml -- openclaw
```

### Isolation layers

| Layer | Mechanism | What it restricts |
|---|---|---|
| Filesystem | Landlock | OpenClaw and descendants can only access paths listed in `read_only` and `read_write` in the policy. The host sidecar is a separate process — Landlock does not apply to it. |
| Syscalls | seccomp | Dangerous syscalls are blocked for the child process tree. |
| Network | Network namespace + veth pair | Sandbox gets its own IP (e.g. `10.200.0.2`). Host reachable at gateway IP (e.g. `10.200.0.1`). Internal proxy + iptables rules inside namespace control outbound traffic. |
| Privileges | Unprivileged user | OpenClaw runs without root. |

### Key properties

- **Filesystem is shared.** OpenClaw writes to `~/.openclaw/skills/` on the
  host filesystem (Landlock permits it). The host sidecar reads the same
  paths. No separate mount namespace, no overlay filesystem.

- **Network is isolated but routable.** The veth pair gives bidirectional
  connectivity between host and sandbox via bridge IPs. No port forwarding
  needed.

- **Process isolation is one-way.** Landlock and seccomp only affect the
  child process tree (OpenClaw). The host-side sidecar is unrestricted.

## Deployment Topology

```
┌─ Host (10.200.0.1) ─────────────────────────────────────────┐
│                                                               │
│  defenseclaw sidecar (Go binary)                              │
│    ├── Gateway client: WebSocket → 10.200.0.2:18789           │
│    ├── fsnotify watcher: skill + MCP dirs on host filesystem  │
│    ├── REST API: 127.0.0.1:18790                              │
│    ├── LiteLLM supervisor: spawns + monitors LiteLLM          │
│    └── SQLite audit DB: ~/.defenseclaw/defenseclaw.db         │
│                                                               │
│  LiteLLM proxy (Python, child of sidecar)                     │
│    ├── Listens on 0.0.0.0:4000                                │
│    ├── defenseclaw_guardrail.py (pre/during/post call)        │
│    ├── Forwards to LLM provider (unrestricted outbound)       │
│    └── Reports telemetry to sidecar at 127.0.0.1:18790        │
│                                                               │
│ ─── veth pair ─────────────────────────────────────────────── │
│                                                               │
│  ┌─ Sandbox (10.200.0.2) ────────────────────────────────┐   │
│  │                                                        │   │
│  │  openshell-sandbox (supervisor)                        │   │
│  │    └── openclaw (child, :18789)                        │   │
│  │          ├── TS plugin (loaded by OpenClaw)             │   │
│  │          ├── Skills (grandchild processes)              │   │
│  │          └── MCP servers (grandchild processes)         │   │
│  │                                                        │   │
│  │  Landlock: restricts filesystem paths                  │   │
│  │  seccomp: blocks dangerous syscalls                    │   │
│  │  iptables + proxy: controls outbound network           │   │
│  └────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────┘
```

## Connection Map

| From | To | Address | Purpose |
|---|---|---|---|
| Sidecar gateway client | OpenClaw gateway | `10.200.0.2:18789` | WebSocket RPC, session events, tool events, approval requests |
| OpenClaw | LiteLLM proxy | `10.200.0.1:4000` | All LLM API calls (configured in `openclaw.json`) |
| LiteLLM | LLM provider | `api.anthropic.com:443` etc. | Forward scanned requests (host has unrestricted outbound) |
| LiteLLM guardrail | Sidecar REST API | `127.0.0.1:18790` | Telemetry events + OPA policy evaluation (both on host) |
| LiteLLM guardrail | Cisco AI Defense | `us.api.inspect.aidefense...:443` | Cloud-based content scanning (optional, from host) |

## How Each Requirement Is Met

### 1. Skill install scanning

**Status: works unchanged.**

Skill directories (`~/.openclaw/skills/`, workspace skills, `extraDirs`) are
on the host filesystem. OpenClaw writes to them (Landlock's `read_write`
permits it). The sidecar's fsnotify watcher runs on the host — same
filesystem, same inotify kernel subsystem, no Landlock restriction.

Detection is instant. On detection, the watcher runs the admission gate:

```
Block list? → YES → reject, log, alert, DisableSkill via WebSocket
  NO → Allow list? → YES → skip scan, log
    NO → Scan (shell out to skill-scanner)
      CLEAN → log
      HIGH/CRITICAL → reject, log, alert, DisableSkill via WebSocket
      MEDIUM/LOW → log warning
```

`DisableSkill` sends a `skills.update` RPC to `10.200.0.2:18789` — the only
change is the gateway IP in config, not in code.

### 2. MCP server scanning

**Status: works unchanged.**

MCP directories (`~/.openclaw/mcp-servers/`, `~/.openclaw/mcps/`) are on
the host filesystem. Same fsnotify watcher, same admission gate.

### 3. LLM guardrails (prompt + response scanning)

**Status: works with one config change.**

LiteLLM runs on the host as a child process of the sidecar. The guardrail
module (`defenseclaw_guardrail.py`) scans every prompt and response using
local pattern matching and optionally Cisco AI Defense cloud scanning.

OpenClaw inside the sandbox reaches LiteLLM at `10.200.0.1:4000` across the
veth pair. The `openclaw.json` is patched with:

```json
{
  "models": {
    "providers": {
      "litellm": {
        "baseUrl": "http://10.200.0.1:4000"
      }
    }
  }
}
```

**The guardrail is mandatory.** The sandbox's iptables block direct access to
LLM providers (`api.anthropic.com`, `api.openai.com`, etc.). The only allowed
outbound path to an LLM is through the host-side LiteLLM proxy. A malicious
skill cannot bypass it — the network namespace enforces this.

This is stronger than host mode, where nothing prevents a skill from calling
the provider directly.

### 4. Tool call and exec approval interception

**Status: works unchanged.**

The sidecar connects to the OpenClaw gateway via WebSocket at
`10.200.0.2:18789`, subscribes to sessions, and receives:

- `session.tool` events — logged, checked against dangerous patterns
- `exec.approval.requested` events — dangerous commands denied, safe
  commands auto-approved (when `auto_approve` is enabled)
- `tool_call` / `tool_result` events — logged to audit, traced via OTel

### 5. Audit logging and SIEM

**Status: works unchanged.**

SQLite audit DB lives on the host (`~/.defenseclaw/defenseclaw.db`).
All events (skill installs, tool calls, guardrail verdicts, approvals)
are logged. Splunk HEC forwarding and OTel export work as-is.

### 6. TUI and CLI

**Status: works unchanged.**

The TUI and `defenseclaw status` query the sidecar's REST API on
`127.0.0.1:18790`. Both run on the host. No change.

## Required Changes

### Config changes (2 values)

**`~/.defenseclaw/config.yaml`:**

```yaml
gateway:
  host: "10.200.0.2"   # sandbox bridge IP (default: 127.0.0.1)
```

**`~/.openclaw/openclaw.json`** (patched by `defenseclaw setup guardrail`):

```json
"baseUrl": "http://10.200.0.1:4000"
```

### Code changes

**`cli/defenseclaw/guardrail.py` — `patch_openclaw_config()`:**

The function currently hardcodes `localhost` for the LiteLLM baseUrl:

```python
"baseUrl": f"http://localhost:{litellm_port}"
```

Change to accept a configurable host:

```python
"baseUrl": f"http://{litellm_host}:{litellm_port}"
```

Where `litellm_host` defaults to `localhost` and is set to the host bridge
IP (e.g. `10.200.0.1`) in standalone sandbox mode.

**`internal/gateway/litellm.go` — bind address:**

LiteLLM must listen on an address reachable from the sandbox. If it currently
binds to `127.0.0.1`, it needs to bind to  the host bridge IP
so the sandbox can reach it across the veth. Check the `--host` flag passed
to litellm.

### Sandbox network policy

The Rego policy data (`policy.yaml`) must allow:

```yaml
network:
  outbound:
    - host: 10.200.0.1
      port: 4000
      comment: "LiteLLM guardrail proxy on host"
    # Do NOT allow direct LLM provider access — forces traffic through guardrail
```

The sandbox should NOT have outbound access to LLM provider endpoints
(`api.anthropic.com`, `api.openai.com`, etc.). This makes the guardrail
mandatory at the network level.

### Sandbox Landlock policy

The Landlock policy must grant `read_write` to skill and MCP directories
so OpenClaw can install them:

```yaml
filesystem:
  read_write:
    - ~/.openclaw/skills
    - ~/.openclaw/workspace/skills
    - ~/.openclaw/mcp-servers
    - ~/.openclaw/mcps
```

These are the same paths the sidecar's fsnotify watcher monitors.

## What Is NOT Needed

| Component | Why it's unnecessary |
|---|---|
| `SandboxScanner` (sidecar goroutine 5) | fsnotify works — same host filesystem |
| `defenseclaw.scan.poll` RPC | No polling needed — fsnotify gives instant detection |
| `defenseclaw.blocklist.sync` RPC | Sidecar manages block/allow lists directly on host |
| Port forwarding (`openshell forward`) | veth pair provides direct IP routing |
| `defenseclaw sandbox setup` command | No container to bootstrap — everything is on the host filesystem |
| Copying LiteLLM/guardrail into sandbox | Same filesystem — they're already installed on the host |
| Launch wrapper script for LiteLLM | LiteLLM runs on the host, not in the namespace |
| TS plugin install watcher | Redundant — host fsnotify handles skill/MCP detection |
| `DEFENSECLAW_API_HOST` env var | LiteLLM and sidecar are both on the host — `127.0.0.1` works |

## Gap: Runtime Policy Updates

DefenseClaw currently modifies OpenShell policies via `openshell policy set`.
In standalone mode, the policy is Rego + YAML files loaded at startup.

If DefenseClaw blocks a new MCP endpoint at runtime and wants to update the
network policy:

1. Modify `policy.yaml` on disk (the sidecar has host filesystem access)
2. Signal `openshell-sandbox` to reload (e.g. `SIGHUP`)

**If `openshell-sandbox` supports hot-reload:** DefenseClaw writes the
policy file and sends the signal. This can be added as a method on the
`OpenShell` struct.

**If it does not:** Network policy changes require a sandbox restart. But
enforcement still works — the admission gate blocks the skill/MCP at the
OpenClaw gateway level via `DisableSkill`. The network policy is
defense-in-depth, not the only enforcement layer.

## Security Properties

| Property | How it's achieved |
|---|---|
| Guardrail is mandatory | Sandbox iptables block direct LLM provider access; only host LiteLLM is reachable |
| Guardrail is tamper-proof | LiteLLM runs on the host, outside Landlock/seccomp/namespace — agent can't touch it |
| Audit is tamper-proof | SQLite DB on host, outside sandbox — agent can't corrupt it |
| Skill blocking is instant | fsnotify on host filesystem, no polling delay |
| Dangerous commands are blocked | Sidecar receives exec approval events via WebSocket, denies dangerous patterns |
| Network exfiltration is blocked | Sandbox iptables default-deny outbound; only approved endpoints allowed |

## Comparison to Other Modes

| | Host mode (no sandbox) | Standalone sandbox | Container sandbox (Docker/k8s) |
|---|---|---|---|
| Filesystem isolation | None | Landlock (path-level) | Full (overlay/mount namespace) |
| Network isolation | None | veth + iptables | Container network |
| fsnotify watcher | Works | Works (same filesystem) | Broken (different mount namespace) |
| Guardrail bypass possible | Yes (direct provider calls) | No (iptables block direct access) | Depends on network policy |
| Polling needed | No | No | Yes (SandboxScanner) |
| Port forwarding needed | No | No (veth) | Yes |
| Sidecar code changes | Baseline | Minimal (1 config, 1 code) | Significant (sandbox setup, polling, plugin proxy) |
