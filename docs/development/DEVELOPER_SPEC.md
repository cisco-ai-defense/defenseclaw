# DefenseClaw — Developer Spec

> **Status:** V1 SHIPPED — Core governance features (scanning, block/allow, guardrail,
> audit, TUI) are implemented. V2/V3 roadmap items remain planned.

## What It Is

DefenseClaw is the enterprise governance layer for OpenClaw. It wraps Cisco AI Defense scanners and NVIDIA OpenShell into a CLI that a developer can deploy in under five minutes, and a TUI that security operators use to manage alerts, block/allow lists, and enforcement — without touching YAML or JSON.

DefenseClaw does not replace OpenShell. It extends it with admission control, alert management, and enterprise integrations.

---

## V1 Scope (What Ships)

V1 does three things well:

1. **Scan everything before it runs** — skills, MCP servers, A2A agents, code, AI dependencies
2. **Block or allow with lists** — operator-managed block/allow lists for skills and MCP servers
3. **Surface alerts in a TUI** — scan findings, policy violations, and enforcement actions in a terminal dashboard

Everything else (multi-zone execution, universal connectors, SIEM adapters, approval queues) is roadmap. V1 is a CLI + TUI that makes a claw safe to deploy.

---

## Install and Deploy

```bash
# Install
curl -sSf https://get.defenseclaw.dev | sh

# Initialize (creates sandbox, loads scanners, generates default policy)
defenseclaw init

# Start the claw inside the secured sandbox
defenseclaw start

# Open the TUI dashboard
defenseclaw tui
```

That's it. Four commands from zero to a governed claw.

---

## CLI Reference

### Setup

| Command | What It Does |
|---------|-------------|
| `defenseclaw init` | Detect environment, create OpenShell sandbox, load scanners, generate policy |
| `defenseclaw start` | Launch OpenClaw inside the sandbox |
| `defenseclaw stop` | Graceful shutdown |
| `defenseclaw status` | One-line health check: agent, sandbox, skills, alerts |
| `defenseclaw tui` | Open the interactive terminal dashboard |

### Scanning

| Command | What It Does |
|---------|-------------|
| `defenseclaw scan skill <path>` | Run skill-scanner on a skill directory |
| `defenseclaw scan mcp <server>` | Run mcp-scanner on an MCP server |
| `defenseclaw scan a2a <agent-card>` | Run a2a-scanner on an agent card |
| `defenseclaw scan code <path>` | Run CodeGuard + static analysis on code |
| `defenseclaw scan all` | Full scan of all installed skills, MCP servers, and code |
| `defenseclaw inventory` | Generate AIBOM for the entire claw environment |

### Skills

| Command | What It Does |
|---------|-------------|
| `defenseclaw skill install <n>` | Scan → enforce block/allow list → install if clean |
| `defenseclaw skill list` | Installed skills with status (clean / blocked / warning) |
| `defenseclaw skill block <n>` | Add skill to block list — immediately disabled |
| `defenseclaw skill allow <n>` | Add skill to allow list — skip future scan blocks |
| `defenseclaw skill remove <n>` | Uninstall and revoke permissions |

### MCP Servers

| Command | What It Does |
|---------|-------------|
| `defenseclaw mcp list` | All registered MCP servers with scan status |
| `defenseclaw mcp scan <server>` | Scan a specific MCP server |
| `defenseclaw mcp block <server>` | Block an MCP server — agent can no longer call its tools |
| `defenseclaw mcp allow <server>` | Allow a previously blocked MCP server |
| `defenseclaw mcp remove <server>` | Deregister and block |

### Alerts

| Command | What It Does |
|---------|-------------|
| `defenseclaw alerts` | List all active alerts |
| `defenseclaw alerts --severity high` | Filter by severity |
| `defenseclaw alerts detail <id>` | Full finding details |
| `defenseclaw alerts dismiss <id> --reason "..."` | Dismiss with reason (logged) |
| `defenseclaw alerts export --format json` | Export for SIEM ingestion |

### Policy

| Command | What It Does |
|---------|-------------|
| `defenseclaw policy show` | View current sandbox + enforcement policy |
| `defenseclaw policy edit` | Open in editor, hot-reloads on save |
| `defenseclaw policy tighten` | Re-derive minimum permissions from installed assets |

### Audit

| Command | What It Does |
|---------|-------------|
| `defenseclaw audit log` | Full event history |
| `defenseclaw audit report --output report.html` | Standalone security report |
| `defenseclaw inventory export --format spdx` | AIBOM export for compliance |

---

## Block/Allow List Enforcement

Block and allow lists are the primary enforcement mechanism in V1.

### Admission Gate Logic

```
Is it on the block list?
  → YES → Reject. Log. Alert.
  → NO  → Is it on the allow list?
            → YES → Skip scan, install. Log.
            → NO  → Scan it.
                     → CLEAN → Install. Log.
                     → HIGH/CRITICAL → Reject. Log. Alert.
                     → MEDIUM/LOW → Install with warning. Log. Alert.
```

### Runtime Enforcement

Blocking is enforced, not advisory:

- **Blocked skill**: Sandbox permissions revoked, files quarantined, agent invocation returns error
- **Blocked MCP server**: Endpoint removed from sandbox network allow-list, OpenShell denies all connections
- **Allow-listed items**: Installed without scan gate, still logged and inventoried

All actions take effect in under 2 seconds. No restart required.

---

## TUI Dashboard

`defenseclaw tui` opens a four-panel interactive terminal:

| Panel | Contents | Inline Actions |
|-------|----------|----------------|
| **Alerts** | Live findings from all scanners, color-coded by severity | Dismiss, block source, view detail |
| **Skills** | Installed skills with status badges | Block, allow, remove, rescan |
| **MCP Servers** | Registered servers with scan status | Block, allow, remove, rescan |
| **Status** | Agent health, sandbox state, counts, last scan | — |

### Keybindings

| Key | Action |
|-----|--------|
| `Tab` | Cycle panels |
| `↑/↓` | Navigate |
| `b` | Block selected |
| `a` | Allow selected |
| `d` | Dismiss alert |
| `r` | Rescan |
| `Enter` | View detail |
| `/` | Filter |
| `q` | Quit |

---

## Architecture (V1)

```
defenseclaw CLI / TUI
       |
       ├── Scan Engine
       |     ├── skill-scanner
       |     ├── mcp-scanner
       |     ├── a2a-scanner
       |     ├── aibom
       |     └── CodeGuard
       |
       ├── Enforcement Engine
       |     ├── Block/allow lists (YAML)
       |     ├── Sandbox policy writer
       |     └── Runtime disconnector
       |
       ├── Alert Store
       |     ├── Finding aggregator
       |     └── Export (JSON, SIEM)
       |
       └── NVIDIA OpenShell (enforcement substrate)
             ├── Kernel isolation
             ├── YAML policy (written by DefenseClaw)
             ├── Network allow-list (managed by DefenseClaw)
             └── OpenClaw agent
```

DefenseClaw **writes** the OpenShell policy. It doesn't fork or reimplement isolation.

---

## What V1 Does NOT Include

| Feature | Target |
|---------|--------|
| SIEM/SOAR adapters | V2 |
| Human-in-the-loop approval queues | V2 |
| IAM integration (Okta, Entra ID) | V2 |
| Multi-zone trust execution | V3 |
| Universal connector declarations | V3 |
| HA deployment | V3 |
| Forensic replay | V3 |

---

## User Story: 5-Minute Deploy

```bash
$ curl -sSf https://get.defenseclaw.dev | sh
  ✅ DefenseClaw installed

$ defenseclaw init
  → Environment: RTX 4090
  → OpenShell sandbox: ✅ ready
  → Scanners loaded: ✅ skill, mcp, a2a, aibom, CodeGuard
  → Default policy: ✅ applied

$ defenseclaw start
  → OpenClaw running in secure sandbox.

$ defenseclaw skill install @community/jira-triage
  → [scan] skill-scanner......... ✅ Clean
  → [scan] mcp-scanner........... ✅ Clean
  → [aibom] Manifest saved
  → [policy] +jira.atlassian.com added
  → Installed.

$ defenseclaw tui
```

---

## Success Metrics (V1)

- Zero to governed claw in under 5 minutes
- 100% of skills and MCP servers scanned before activation
- Block action enforced in under 2 seconds
- TUI refreshes within 5 seconds of new findings
- All actions logged with actor, timestamp, and reason
- Zero items bypass admission gate without scan or allow-list entry

---

## Build Order

1. `defenseclaw init` + `start` (OpenShell wrapper)
2. `defenseclaw scan` (wrap all five scanners)
3. `defenseclaw skill install` with scan gate + block/allow
4. `defenseclaw mcp` with scan gate + block/allow
5. Block/allow list storage + runtime enforcement
6. Alert store + `defenseclaw alerts`
7. `defenseclaw tui` (four-panel dashboard)
8. `defenseclaw audit` + export
