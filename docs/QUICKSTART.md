# Quick Start Guide

Get DefenseClaw running in under 5 minutes.

## Prerequisites

- **Python 3.10+** — for the CLI and scanner dependencies
- **[uv](https://docs.astral.sh/uv/)** (recommended) or pip
- **Go 1.22+** — only needed if building the Go binary

## Option A: Python CLI (Recommended)

The Python CLI uses the native `cisco-ai-skill-scanner` SDK directly — no subprocess overhead.

```bash
git clone https://github.com/defenseclaw/defenseclaw.git
cd defenseclaw

# Create virtual environment and install (using uv — recommended)
uv venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -e cli

# Or using standard pip
python3 -m venv .venv
source .venv/bin/activate
pip install -e cli

# Verify installation
defenseclaw --help
```

## Option B: Full Install (CLI + Gateway + Plugin)

Build and install all components from source.

```bash
git clone https://github.com/defenseclaw/defenseclaw.git
cd defenseclaw

# Build and install everything
make install

# Activate the Python environment
source .venv/bin/activate
```

To build individual components:

```bash
make pycli     # Python CLI only
make gateway   # Go gateway only
make plugin    # OpenClaw plugin only
```

## 2. Initialize

```bash
defenseclaw init
```

This creates `~/.defenseclaw/` with:
- `config.yaml` — scanner paths, policy settings
- `audit.db` — SQLite audit log
- `quarantine/` — blocked skill storage
- `plugins/` — custom scanner plugins
- `policies/` — OpenShell policy files

Scanner dependencies are installed automatically during init.
Use `--skip-install` to skip this step.

## 3. First Scan

```bash
# Scan a skill (Python CLI uses native SDK)
defenseclaw skill scan ./path/to/skill/

# Scan all skills in configured directories
defenseclaw skill scan all

# Scan an MCP server
defenseclaw mcp scan https://mcp-server.example.com

# Generate AI bill of materials
defenseclaw aibom .
```

## 4. Block/Allow Enforcement

```bash
# Block a skill
defenseclaw skill block malicious-skill --reason "exfil pattern"

# Block an MCP server
defenseclaw mcp block https://shady.example.com --reason "hidden instructions"

# View what's blocked/allowed
defenseclaw skill list
defenseclaw mcp list

# Allow a skill
defenseclaw skill allow trusted-skill --reason "manually verified"

# Allow an MCP server
defenseclaw mcp allow https://trusted.example.com
```

## 5. Audit Log

```bash
# View recent audit events
defenseclaw audit

# Show more events
defenseclaw audit -n 50
```

Every action (scan, block, allow, quarantine, init) is logged.

## 6. Terminal Dashboard (Go CLI only)

The TUI requires the Go binary. Build it first with `make build`.

```bash
# Launch the interactive TUI
./defenseclaw tui
```

The TUI has three tabs:
- **Alerts** — color-coded severity, dismiss with `d`, view detail with `enter`
- **Skills** — block/allow toggle with `b`/`a`, view detail with `enter`
- **MCP Servers** — block/allow toggle with `b`/`a`, view detail with `enter`

Navigation: `tab`/`shift-tab` between tabs, `j`/`k` or arrows to move, `r` to refresh, `q` to quit.

Auto-refreshes every 5 seconds from SQLite.

## 7. Deploy (Full Orchestrated Flow)

```bash
# Full deploy: init → scan → auto-block → policy → sandbox
defenseclaw deploy

# Deploy a specific target directory
defenseclaw deploy ./my-project/

# Skip init if already configured
defenseclaw deploy --skip-init
```

This runs all 5 steps automatically:
1. **Init** — ensures `~/.defenseclaw/` exists
2. **Scan** — runs skill-scanner, mcp-scanner, aibom, and CodeGuard
3. **Enforce** — auto-blocks anything HIGH/CRITICAL
4. **Policy** — generates OpenShell sandbox policy from scan results
5. **Sandbox** — starts OpenClaw in OpenShell (DGX Spark only)

## 8. Code Scanning (CodeGuard)

```bash
# Scan code for security issues
defenseclaw scan code ./path/to/code/
```

Built-in rules detect: hardcoded credentials, unsafe command execution,
SQL injection, unsafe deserialization, weak crypto, path traversal, and more.

## 9. Status & Lifecycle

```bash
# Check deployment health
defenseclaw status

# Re-scan all known targets, auto-block/unblock based on results
defenseclaw rescan

# View security alerts
defenseclaw alerts
defenseclaw alerts -n 50

# Stop the sandbox
defenseclaw stop
```

## 10. SIEM Integration (Splunk)

DefenseClaw can forward audit events to Splunk for enterprise visibility.

### Batch Export

```bash
# Export events as JSON
defenseclaw audit export -f json -o audit.json

# Export as CSV
defenseclaw audit export -f csv -o audit.csv

# Send to Splunk via HEC
DEFENSECLAW_SPLUNK_HEC_TOKEN=<your-token> defenseclaw audit export -f splunk -n 500
```

### Real-Time Forwarding

Add to `~/.defenseclaw/config.yaml`:

```yaml
splunk:
  hec_endpoint: https://your-splunk:8088/services/collector/event
  hec_token: ""
  index: defenseclaw
  source: defenseclaw
  sourcetype: _json
  verify_tls: false
  enabled: true
  batch_size: 50
  flush_interval_s: 5
```

Set the token via environment variable (recommended):

```bash
export DEFENSECLAW_SPLUNK_HEC_TOKEN="your-hec-token"
```

With `enabled: true`, every scan, block, allow, deploy, and quarantine event is
streamed to Splunk as it happens.

### Local Splunk preset

For the local bridge workflow, prefer the bundled local preset instead of
editing the generic Splunk config manually:

```bash
defenseclaw setup splunk-local --non-interactive
```

That preset starts the bundled local bridge runtime and aligns DefenseClaw with
the local bridge contract:

- HEC endpoint `http://127.0.0.1:8088/services/collector/event`
- index `defenseclaw_local`
- source `defenseclaw`
- sourcetype `defenseclaw:json`

Recommended local flow:

1. Run `defenseclaw setup splunk-local --non-interactive`
2. Start the DefenseClaw sidecar
3. Open local Splunk using the printed URL and credentials
4. Validate data in local Splunk

Manual bridge mode remains available for debugging:

1. Run `defenseclaw setup splunk-local --non-interactive --no-bootstrap-bridge`
2. Export `DEFENSECLAW_SPLUNK_HEC_TOKEN`
3. Start the DefenseClaw sidecar

## 11. Running Tests

```bash
# Python CLI tests
source .venv/bin/activate
python3 -m unittest discover -s cli/tests -v

# Go tests
make test
```

## 12. Next Steps

- `defenseclaw tui` — interactive terminal dashboard (Go CLI)
- See [CLI Reference](CLI.md) for all commands and flags.
- See [Architecture](ARCHITECTURE.md) for system design details.
