# Sandbox Architecture

## What It Is

Standalone sandbox mode runs OpenClaw inside an NVIDIA OpenShell sandbox
with DefenseClaw governance. The sandbox provides OS-level isolation
(Linux namespaces, Landlock, seccomp) while DefenseClaw adds scanning,
policy enforcement, and audit logging on top.

## Components

```
systemd
  ├── openshell-sandbox.service        ← runs as root, drops to sandbox user
  │     └── start-sandbox.sh
  │           └── openshell-sandbox    ← NVIDIA binary, creates namespaces
  │                 └── openclaw       ← agent runtime (inside sandbox)
  │
  └── defenseclaw-sandbox.target       ← groups services for start/stop
```

The **DefenseClaw gateway sidecar** (`defenseclaw-gateway run`) is the Go
process that connects to the sandbox over WebSocket, watches for new
skills/plugins via fsnotify, serves the REST API, and optionally runs the
guardrail proxy. It runs independently — not as a child of the sandbox.

## How They Talk

```
┌─────────────────────────┐          ┌─────────────────────────┐
│   Sandbox (10.200.0.2)  │  veth    │     Host (10.200.0.1)   │
│                         │◄────────►│                         │
│  OpenClaw :18789 (WS)   │          │  Sidecar REST :18970    │
│  DefenseClaw plugin     │          │  Guardrail proxy :4000  │
│  CodeGuard skill        │          │  SQLite audit DB        │
└─────────────────────────┘          └─────────────────────────┘
```

- **WebSocket (port 18789):** Sidecar connects to OpenClaw's gateway inside
  the sandbox. Authenticated via Ed25519 device key, pre-paired during setup.
- **REST API (port 18970):** CLI commands (`defenseclaw skill list`, `status`,
  etc.) hit the sidecar's API on the host side.
- **Guardrail proxy (port 4000):** All LLM traffic from inside the sandbox
  routes through this proxy for inspection before reaching the provider.

## Network Isolation

The sandbox runs in its own network namespace with a veth pair:

| Address | Side |
|---|---|
| `10.200.0.1` | Host |
| `10.200.0.2` | Sandbox |

Outbound traffic from the sandbox is forced through OpenShell's HTTP CONNECT
proxy at `10.200.0.1:3128`. DNS is restricted to configured nameservers
(default: `8.8.8.8`, `1.1.1.1`) via iptables rules injected by
`post-sandbox.sh`.

## DNS

The sandbox network namespace has no DNS resolver by default. OpenShell
blocks all traffic except connections through its proxy, which means UDP
port 53 queries to external resolvers are silently dropped. This breaks
any application that resolves hostnames before connecting (e.g., Node.js
uses `getaddrinfo()` rather than delegating DNS to the proxy).

To fix this without running a DNS forwarder process:

1. **Custom resolv.conf** — `defenseclaw setup sandbox` generates
   `sandbox-resolv.conf` with the configured nameservers (default:
   `8.8.8.8`, `1.1.1.1`). On each start, `start-sandbox.sh` uses
   `unshare --mount` to bind-mount this file over `/etc/resolv.conf`
   inside the sandbox. The host's resolv.conf is never modified.

2. **iptables allow rules** — `post-sandbox.sh` injects UDP 53 allow
   rules scoped to only those specific nameservers (not a blanket UDP 53
   allow). This limits DNS exfiltration to abusing the configured resolvers.

Nameservers are configurable: `--dns 10.0.0.2,10.0.0.3` for internal
resolvers, or `--dns host` to mirror the host's `/etc/resolv.conf`.

## Host-Side iptables Rules

In addition to the in-namespace DNS rules, `post-sandbox.sh` injects
rules on the host side when host networking is enabled:

| Rule | Purpose |
|---|---|
| `MASQUERADE` on `10.200.0.0/24` UDP 53 | Routes DNS responses back to the sandbox IP. Without this, replies from external nameservers have no return path into the namespace. |
| `route_localnet=1` | Allows DNAT from localhost to non-loopback addresses, required for UI forwarding. |
| `DNAT` localhost:18789 → 10.200.0.2:18789 | Forwards the OpenClaw UI port so it's accessible from `localhost` on the host without SSH tunneling. |
| `MASQUERADE` on 10.200.0.2:18789 | Ensures return traffic from the DNAT'd UI connection routes correctly. |

When guardrail is enabled, additional rules allow the sandbox to reach the
sidecar API (port 18970) and guardrail proxy (port 4000) on the host IP.

All these rules are cleaned up by `cleanup-sandbox.sh` on service stop and
re-injected on every start. Use `--no-host-networking` to skip them entirely
(OpenShell manages networking internally in that case).

## Security Layers

| Layer | Provides |
|---|---|
| Linux namespaces | Process, network, mount isolation |
| Landlock LSM | Filesystem access control |
| seccomp-BPF | System call filtering |
| OpenShell OPA policy | Per-connection network policy (destination, binary, L7) |
| DefenseClaw guardrail | LLM request/response inspection |
| DefenseClaw admission gate | Skill/plugin scanning before installation |
| CodeGuard skill | Runtime code execution monitoring |

## What Each Component Does

**OpenShell sandbox** — Kernel-level containment. Creates namespaces, applies
Landlock/seccomp profiles, evaluates OPA policy on every outbound connection.

**DefenseClaw sidecar** — Governance. Watches skill/plugin directories,
runs the admission gate (block → allow → scan), disables risky skills/plugins,
logs everything to SQLite, optionally forwards to Splunk.

**DefenseClaw plugin** — Runs inside the sandbox as an OpenClaw extension.
Intercepts `before_tool_call` events, provides `/scan`, `/block`, `/allow`
slash commands, routes LLM traffic through the guardrail proxy.

**CodeGuard skill** — Installed as a skill inside the sandbox. Monitors
code execution patterns at runtime.
