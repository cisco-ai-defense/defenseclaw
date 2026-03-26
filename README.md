```
     ____         __                       ____  _
    / __ \ ___   / /___   ___   ___  ___  / ___|| | __ _ __      __
   / / / // _ \ / // _ \ / _ \ / __|/ _ \| |    | |/ _` |\ \ /\ / /
  / /_/ //  __// //  __/| | | |\__ \  __/| |___ | | (_| | \ V  V /
 /_____/ \___//_/ \___/ |_| |_||___/\___| \____||_|\__,_|  \_/\_/

  ╔═══════════════════════════════════════════════════════════════╗
  ║  Cisco DefenseClaw — Security Governance for Agentic AI      ║
  ╚═══════════════════════════════════════════════════════════════╝
```

# DefenseClaw

**AI agents are powerful. Unchecked, they're dangerous.**

Large language model agents — like those built on [OpenClaw](https://github.com/nvidia/openclaw) — can install skills, call MCP servers, execute code, and reach the network. Every one of those actions is an attack surface. A single malicious skill can exfiltrate data. A compromised MCP server can inject hidden instructions. Generated code can contain hardcoded secrets or command injection.

**DefenseClaw is the enterprise governance layer for OpenClaw.** It sits between your AI agents and the infrastructure they run on, enforcing a simple principle: **nothing runs until it's scanned, and anything dangerous is blocked automatically.**

```
  Developer / Operator
         │
    ┌────▼─────────────────────┐
    │   DefenseClaw Gateway    │  scan ─► block ─► enforce ─► audit
    └────┬─────────────────────┘
         │
    ┌────▼─────────────────────┐
    │   NVIDIA OpenShell       │  kernel isolation + network policy
    │     └── OpenClaw Agent   │  skills, MCP servers, code
    └──────────────────────────┘
```

---

## Architecture

DefenseClaw is a **multi-component system** with three runtimes:

| Component | Language | Purpose |
|-----------|----------|---------|
| **Python CLI** | Python 3.11+ | User-facing CLI (`defenseclaw`), scanners, TUI dashboard, config |
| **Go Orchestrator** | Go 1.23+ | Background daemon, WebSocket gateway, connectors (watchdog, Splunk, OpenShell, firewall), OPA policy engine, REST API, SQLite audit store |
| **TypeScript Plugin** | TypeScript | Native OpenClaw plugin with in-process scanning, policy enforcement, slash commands |

```
┌─────────────────────────────────────────────────────┐
│                    Python CLI                        │
│  scan · block · allow · tui · audit · inventory      │
│               ↕ REST (localhost:18789)                │
├─────────────────────────────────────────────────────┤
│                 Go Orchestrator Daemon                │
│  Gateway WS ┊ Watchdog ┊ Splunk/OTLP ┊ OPA ┊ SQLite │
├─────────────────────────────────────────────────────┤
│              TypeScript OpenClaw Plugin               │
│  /scan · /block · /allow · native scanners           │
└─────────────────────────────────────────────────────┘
```

---

## Prerequisites

| Requirement | Version | Check |
|-------------|---------|-------|
| Python | 3.11+ | `python3 --version` |
| Go | 1.23+ | `go version` |
| Node.js | 20+ (plugin only) | `node --version` |
| [uv](https://docs.astral.sh/uv/) | latest | `uv --version` |
| Git | any | `git --version` |

---

## Quick Start (5 minutes)

### 1. Clone, build, and install

```bash
git clone https://github.com/defenseclaw/defenseclaw.git
cd defenseclaw

# Build and install everything (Python CLI + Go gateway + OpenClaw plugin)
make install

# Activate the Python environment
source .venv/bin/activate

# Initialize DefenseClaw
defenseclaw init

# Scan a skill
defenseclaw skill scan /path/to/skill

# Check status
defenseclaw status

# View alerts
defenseclaw alerts
```

### Running Tests

```bash
# All tests (Python + Go)
make test

# Individual
make cli-test       # Python CLI tests
make gateway-test   # Go gateway tests
```

### Deploy (Orchestrated)

```bash
# Scan → enforce → deploy (delegates to Go daemon)
defenseclaw deploy ./my-project/

# Skip the scan step
defenseclaw deploy ./my-project/ --skip-scan
```

### Scanner Plugins

```bash
# List discovered plugins from ~/.defenseclaw/plugins/
defenseclaw plugin list

# Run a custom scanner plugin
defenseclaw plugin scan custom-scanner ./my-skill/
```

See [Plugin Development](docs/PLUGINS.md) for how to write your own scanner.

---

## Go Orchestrator Daemon

The daemon is the central hub. Start it before using the CLI or plugin.

```bash
# Build
cd gateway && go build -o ../bin/gateway ./cmd/gateway && cd ..

# Run with default config (~/.defenseclaw/config.yaml)
./bin/gateway

# Run with custom config
./bin/gateway -config /path/to/config.yaml
```

### REST API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/status` | System status with connector health |
| POST | `/scan/result` | Submit scan results |
| POST | `/audit/event` | Log an audit event |
| GET | `/alerts` | List alerts (query: `limit`) |
| GET | `/skills` | List known skills |
| GET | `/mcps` | List known MCP servers |
| POST | `/enforce/block` | Add to block list |
| POST | `/enforce/allow` | Add to allow list |
| DELETE | `/enforce/block` | Remove from block list |
| DELETE | `/enforce/allow` | Remove from allow list |
| POST | `/policy/evaluate` | Evaluate OPA policy |
| GET | `/policy/domains` | List available policy domains |

### Connectors

The daemon runs five connectors:

| Connector | What it does |
|-----------|-------------|
| **Gateway** | WebSocket v3 client to OpenClaw gateway, device auth, event routing, RPC |
| **Watchdog** | Monitors skill/MCP directories via fsnotify, emits OTEL events on changes |
| **Splunk/OTLP** | Forwards audit logs to Splunk HEC and/or OTLP HTTP endpoint |
| **OpenShell** | Manages sandbox policy YAML, hot-reload (DGX Spark only) |
| **Firewall** | Generates pfctl (macOS) or iptables (Linux) rules from policy |

### Runtime Security (Cisco AI Defense)

The daemon includes a two-tier runtime inspection pipeline:

| Tier | Engine | Latency | What it detects |
|------|--------|---------|-----------------|
| 1 | Local regex patterns | <1ms | Dangerous tools, prompt injection, sensitive paths, exfiltration indicators, destructive commands |
| 2 | Cisco AI Defense Inspect API | ~200ms | ML-based prompt injection, security violations, content safety, custom rules |

Both tiers are invoked on `tool_call`, `exec.approval.requested`, and `tool_result` events from the OpenClaw WebSocket stream. When `ai_defense.blocking_mode` is enabled, HIGH/CRITICAL findings from exec approval requests automatically deny the approval.

The tool call policy engine adds per-skill restrictions (allowed/denied tools, argument patterns, rate limits, exfiltration detection) on top of the inspection tiers.

Set `AI_DEFENSE_API_KEY` in your environment to enable Tier 2.

---

## TypeScript OpenClaw Plugin

The plugin runs inside OpenClaw and provides native in-process scanning.

### Build

```bash
cd extensions/defenseclaw
npm install
npm run build
```

### Slash Commands

| Command | Usage | Description |
|---------|-------|-------------|
| `/scan` | `/scan <path> [skill\|plugin\|mcp]` | Scan a skill, plugin, or MCP config |
| `/block` | `/block <skill\|mcp\|plugin> <name> [reason]` | Block a target |
| `/allow` | `/allow <skill\|mcp\|plugin> <name> [reason]` | Allow a target |

### Lifecycle Hooks

- **`gateway_start`** — runs `defenseclaw scan --json` on boot
- **`skill_install`** — evaluates plugin via native scanner + OPA policy
- **`skill_uninstall`** — logs uninstall event
- **`mcp_connect`** — evaluates MCP server config via native scanner
- **`mcp_disconnect`** — logs disconnect event

---

## Configuration

All configuration lives in `~/.defenseclaw/config.yaml`. Create it with `defenseclaw setup`.

### Example config

```yaml
data_dir: ~/.defenseclaw
audit_db: ~/.defenseclaw/audit.db
quarantine_dir: ~/.defenseclaw/quarantine
plugin_dir: ~/.defenseclaw/plugins
policy_dir: ~/.defenseclaw/policies

claw:
  mode: openclaw

gateway:
  host: 127.0.0.1
  port: 18789
  token: ""                      # Set via OPENCLAW_GATEWAY_TOKEN env var
  device_key_file: ~/.defenseclaw/device.key
  auto_approve_safe: false
  reconnect_ms: 800
  max_reconnect_ms: 15000
  approval_timeout_s: 30

scanners:
  skill_scanner:
    binary: skill-scanner
    use_llm: false
  mcp_scanner: mcp-scanner
  aibom: cisco-aibom
  codeguard: ""                  # Built-in, no binary needed

watch:
  debounce_ms: 500
  auto_block: false

openshell:
  binary: openshell
  policy_dir: ~/.defenseclaw/policies

splunk:
  enabled: false
  hec_endpoint: https://your-splunk:8088/services/collector/event
  hec_token: ""                  # Set via DEFENSECLAW_SPLUNK_HEC_TOKEN env var
  index: defenseclaw
  source: defenseclaw
  sourcetype: _json
  verify_tls: true
  batch_size: 50
  flush_interval_s: 5

ai_defense:
  enabled: true
  api_url: https://us.api.inspect.aidefense.security.cisco.com/api/v1
  timeout_seconds: 10
  max_retries: 3
  blocking_mode: false            # Set true to block on HIGH/CRITICAL findings
  include_rules: []               # Optional rule filter

tool_policy:
  default_action: allow
  skills:
    untrusted-skill:
      allowed_tools: ["read_file", "list_dir"]
      denied_tools: ["shell", "exec"]
  exfiltration:
    max_payload_bytes: 1048576
    sensitive_paths: ["/etc/shadow", "~/.ssh"]

skill_actions:
  critical: block
  high: block
  medium: warn
  low: allow
  info: allow
```

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `OPENCLAW_GATEWAY_TOKEN` | Gateway authentication token |
| `AI_DEFENSE_API_KEY` | Cisco AI Defense Inspect API key |
| `DEFENSECLAW_SPLUNK_HEC_TOKEN` | Splunk HEC token |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector endpoint (e.g., `http://localhost:4318`) |
| `EDITOR` / `VISUAL` | Editor for `defenseclaw policy edit` |

---

## Scanner Dependencies

DefenseClaw wraps four open-source security scanners plus built-in analyzers:

| Scanner | Package | What It Detects |
|---------|---------|-----------------|
| [Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner) | `cisco-ai-skill-scanner` | Prompt injection, data exfiltration, malicious code in AI skills |
| [MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) | `cisco-ai-mcp-scanner` | Malicious MCP tools, hidden instructions, SSRF |
| [AI BOM](https://github.com/cisco-ai-defense/aibom) | `cisco-aibom` | AI framework inventory (models, agents, tools, prompts) |
| CodeGuard | Built-in | Hardcoded credentials, unsafe exec, SQLi, weak crypto, path traversal |
| ClawShield | Built-in | Prompt injection (multi-tier), PII detection, secret leakage, vulnerability patterns, malware indicators |

```bash
# Install external scanners
uv tool install cisco-ai-skill-scanner
uv tool install --python 3.13 cisco-ai-mcp-scanner
uv tool install --python 3.13 cisco-aibom
```

---

## Testing

### Run Python tests

```bash
# All tests
uv run pytest cli/tests/ -v

# With coverage
uv run pytest cli/tests/ -v --tb=short
```

### Run Go tests (orchestrator)

```bash
cd gateway
go test -race ./...
```

### Run TypeScript tests (plugin)

```bash
cd extensions/defenseclaw
npm install
npx vitest run
```

### Run all checks

```bash
# Python lint + tests
make py-check

# Go orchestrator
cd gateway && go test -race ./...

# TypeScript plugin
cd extensions/defenseclaw && npx vitest run
```

### Manual testing with a live OpenClaw instance

If you have OpenClaw running (e.g., on AWS Bedrock via SSM tunnel):

```bash
# 1. Port-forward OpenClaw gateway (in a separate terminal)
aws ssm start-session \
  --target <instance-id> \
  --region us-east-1 \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["18789"],"localPortNumber":["18789"]}'

# 2. Retrieve the gateway token
export OPENCLAW_GATEWAY_TOKEN=$(aws ssm get-parameter \
  --name /openclaw/openclaw-bedrock/gateway-token \
  --with-decryption --query Parameter.Value --output text)

# 3. Start the orchestrator daemon
./bin/gateway

# 4. Check connectivity
uv run defenseclaw status

# 5. Run scans against OpenClaw skills
uv run defenseclaw scan ~/.openclaw/workspace/skills/ --type skill
uv run defenseclaw scan ~/.openclaw/workspace/skills/ --type clawshield

# 6. Launch the dashboard
uv run defenseclaw tui
```

---

## Admission Gate

Every skill and MCP server goes through a six-path admission gate. The logic is
implemented as a Rego policy (`policies/rego/admission.rego`) evaluated by the
embedded OPA engine, making it fully customizable without code changes.

```
Block list? ─── YES ──► reject, log, alert
     │
     NO
     │
Allow list? ─── YES ──► skip scan, install, log
     │
     NO
     │
   Scan
     │
  CLEAN? ──── YES ──► install, log
     │
     NO
     │
  HIGH/CRITICAL? ─ YES ──► reject, log, alert
     │
     NO
     │
  MEDIUM/LOW ──────────► install with warning, log, alert
```

### Policy Customization

All governance policies are Rego files in `~/.defenseclaw/policies/` (copied from
`policies/rego/` during setup). The OPA engine hot-reloads policies when files
change — no daemon restart required. Operators can tune severity thresholds,
firewall allowlists, and audit retention by editing `data.json`, or add custom
Rego rules for advanced logic.

See [Policy Customization](docs/POLICIES.md) for the full reference.

---

## SIEM Integration (Splunk / OTLP)

### Splunk HEC

The Go daemon forwards audit events to Splunk in real time. Set `splunk.enabled: true` in config and provide the HEC endpoint + token.

```bash
export DEFENSECLAW_SPLUNK_HEC_TOKEN="your-hec-token"
```

For the local Splunk workflow, use the preset instead of editing the generic
Splunk block by hand:

```bash
defenseclaw setup splunk-local --non-interactive
```

That command uses the bundled local bridge runtime shipped with `DefenseClaw`
and aligns the sidecar with the local bridge contract:

- HEC endpoint `http://127.0.0.1:8088/services/collector/event`
- index `defenseclaw_local`
- source `defenseclaw`
- sourcetype `defenseclaw:json`

Recommended local flow:

1. Run `defenseclaw setup splunk-local --non-interactive`
2. Start the DefenseClaw sidecar
3. Open local Splunk with the URL and credentials printed by the setup command
4. Validate events in local Splunk

For advanced or debugging use, the manual bridge contract can still be used:

1. Run `defenseclaw setup splunk-local --non-interactive --no-bootstrap-bridge`
2. Start the bundled local bridge manually
3. Export `DEFENSECLAW_SPLUNK_HEC_TOKEN`
4. Start the DefenseClaw sidecar
5. Validate events in local Splunk

Events are batched (default 50) and flushed every 5 seconds. Each event includes OTEL-shaped fields with pre-computed Splunk CIM metadata for zero-transformation indexing.

### OTLP Export

The daemon also exports logs, spans, and metrics via OTLP HTTP to any compatible collector (Jaeger, Grafana, Datadog, etc.).

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4318"
```

### Audit Database Schema

The SQLite audit DB uses an OTEL-native schema:

| Table | Contents |
|-------|----------|
| `otel_logs` | All audit events with trace/span IDs, severity, attributes, Splunk CIM columns |
| `otel_spans` | Scan and enforcement traces |
| `otel_metrics` | Counters (scans, findings, decisions) and gauges (blocked/allowed counts) |
| `scan_results` | Scan metadata (scanner, target, duration, finding count) |
| `findings` | Individual findings (severity, title, location, remediation) |
| `block_list` | Blocked skills/MCPs with reasons |
| `allow_list` | Allowed skills/MCPs with reasons |

---

## Platform Support

| Capability | DGX Spark (Linux) | macOS |
|------------|-------------------|-------|
| Scanning (all scanners) | Full | Full |
| Block/allow lists | Full enforcement | Full enforcement |
| Quarantine | Files + sandbox policy | Files only |
| OpenShell sandbox | Active kernel isolation | Gracefully skipped |
| Network enforcement | Via OpenShell + iptables | pfctl rules generated |
| Filesystem watchdog | Full (fsnotify) | Full (fsnotify) |
| Audit log | Full (SQLite + OTEL) | Full (SQLite + OTEL) |
| TUI dashboard | Full | Full |
| Splunk HEC export | Full | Full |
| OTLP export | Full | Full |

---

## Project Structure

```
defenseclaw/
├── cli/defenseclaw/           # Python CLI (Click + Rich)
│   ├── commands/              #   Command definitions (one file per command)
│   ├── scanner/               #   Scanner wrappers
│   ├── enforce/               #   Policy engine, admission
│   ├── db.py                  #   SQLite audit store
│   ├── config.py              #   YAML config loader
│   ├── gateway.py             #   REST client to Go daemon
│   └── main.py                #   CLI entry point
├── cli/tests/                 # Python pytest suite
├── gateway/                   # Go orchestrator daemon
│   ├── cmd/gateway/           #   Entry point
│   └── internal/
│       ├── daemon/            #   Lifecycle orchestration
│       ├── api/               #   REST API server + handlers
│       ├── audit/             #   OTEL-native SQLite store
│       ├── connector/         #   Connector interface + registry
│       │   ├── gateway/       #   OpenClaw WebSocket v3 client
│       │   ├── watchdog/      #   fsnotify file watcher
│       │   ├── splunk/        #   Splunk HEC + OTLP exporter
│       │   ├── openshell/     #   Sandbox policy management
│       │   └── firewall/      #   pfctl/iptables rule compiler
│       ├── config/            #   YAML config + defaults
│       └── policy/            #   OPA policy engine
├── extensions/defenseclaw/    # TypeScript OpenClaw plugin
│   └── src/
│       ├── scanners/          #   Native plugin + MCP scanners
│       └── policy/            #   In-process policy enforcer
├── policies/                  # OPA Rego + YAML policy templates
├── Makefile                   # Build targets
├── pyproject.toml             # Python dependencies
└── gateway/go.mod             # Go dependencies
```

---

## Building from Source

```bash
# Build everything (Python CLI + Go gateway + OpenClaw plugin)
make build

# Or install everything (builds + copies binaries/plugin into place)
make install

# Individual components
make pycli       # Python CLI → .venv/bin/defenseclaw
make gateway     # Go gateway → ./defenseclaw-gateway
make plugin      # TS plugin  → extensions/defenseclaw/dist/

# Individual installs
make gateway-install   # → ~/.local/bin/defenseclaw-gateway
make plugin-install    # → ~/.openclaw/extensions/defenseclaw/
```

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Installation Guide](docs/INSTALL.md) | Step-by-step setup for DGX Spark and macOS |
| [Quick Start](docs/QUICKSTART.md) | 5-minute walkthrough of every command |
| [Architecture](docs/ARCHITECTURE.md) | System diagram, data flow, and component responsibilities |
| [TUI Guide](docs/TUI.md) | Dashboard usage, keybindings, navigation |
| [Policy Customization](docs/POLICIES.md) | OPA Rego policy reference and customization guide |
| [Plugin Development](docs/PLUGINS.md) | Custom scanner plugin interface |
| [Testing](docs/TESTING.md) | Multi-language test guide (Python, Go, TypeScript, Rego) |

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
