# Installation Guide

This guide covers two scenarios:

1. **You already have OpenClaw running** — add DefenseClaw to secure it
2. **Fresh install** — set up OpenClaw inside OpenShell, then add DefenseClaw

Instructions are provided for both **NVIDIA DGX Spark** (aarch64/Ubuntu) and **macOS** (Apple Silicon).

---

## Understanding the Stack

```
┌──────────────────────────────────┐
│  DefenseClaw (CLI + TUI)         │  ← You are installing this
│  Scans, block/allow, governance  │
└──────────┬───────────────────────┘
           │ orchestrates
┌──────────▼───────────────────────┐
│  NVIDIA OpenShell                │  ← Sandbox (DGX Spark only)
│  Kernel isolation, network policy│
└──────────┬───────────────────────┘
           │ runs inside
┌──────────▼───────────────────────┐
│  OpenClaw                        │  ← AI agent framework
│  Skills, MCP servers, agents     │
└──────────────────────────────────┘
```

- **OpenClaw** is the AI agent framework that runs skills and connects to MCP servers.
- **OpenShell** is the NVIDIA sandbox that isolates OpenClaw with kernel-level controls.
- **DefenseClaw** sits on top. It scans everything before it runs, enforces block/allow lists, writes OpenShell policy, and provides a terminal dashboard. It does **not** replace OpenShell — it orchestrates it.

On **macOS**, OpenShell is not available. DefenseClaw still works for scanning, block/allow lists, audit logging, and the TUI dashboard. Sandbox enforcement is gracefully skipped.

**For sandbox setup on Linux**, see [SANDBOX.md](SANDBOX.md) for full architecture, configuration, and troubleshooting.

## Splunk Terms And Scope For The Local Preset

If you enable the bundled local Splunk workflow through `DefenseClaw`, you are
representing that you have reviewed and accepted the then-current Splunk
General Terms, available at:

- https://www.splunk.com/en_us/legal/splunk-general-terms.html

If you have a separately negotiated agreement with Splunk that expressly
supersedes those terms, that agreement governs instead. Otherwise, by
accessing or using Splunk software through this workflow, you are agreeing to
the Splunk General Terms posted at the time of access and use and
acknowledging their applicability to the Splunk software.

If you do not agree to the Splunk General Terms, do not download, start,
access, or use the software.

Scope guardrails for the local Splunk preset:

- use it only for local, single-instance workflows
- the bundled runtime starts directly in Splunk Free mode from day 1
- in Splunk Free mode, alerting is disabled
- in Splunk Free mode, authentication and RBAC are removed, so the
  default bundled profile does not require local user credentials
- when you open Splunk Web in a browser, Splunk can briefly route through its
  account page before it auto-enters the app without asking for credentials
- to use full Splunk Enterprise features later, apply a valid Splunk
  Enterprise license
- for a higher indexing limit, a free Splunk Developer License with a 10 GB/day limit is available at [dev.splunk.com](https://dev.splunk.com)
- assume existing Splunk license limits still apply
- do not treat it as an endorsed path to multi-instance or long-term
  deployment
- do not assume a seamless upgrade or migration path from this setup
- do not assume all Splunk Enterprise capabilities are enabled in every license
  mode
- do not assume this local preset proxies or replaces a direct O11y
  integration

For more details on the Free-tier behavior and limits, see
[About Splunk Free](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configure-splunk-licenses/about-splunk-free).

---

## Building from Source

This section covers building DefenseClaw from the repository.

### Prerequisites

| Tool | Minimum | Check | Install |
|------|---------|-------|---------|
| Go | 1.26.2+ | `go version` | [go.dev/dl](https://go.dev/dl/) or `brew install go` |
| Python | 3.10+ (3.12 recommended) | `python3 --version` | System package manager or [python.org](https://python.org) |
| uv | latest | `uv --version` | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Node.js / npm | 18+ | `node --version` | [nodejs.org](https://nodejs.org) or `brew install node` |
| Git | any | `git --version` | System package manager |

Python 3.11+ is recommended if you need the MCP scanner
(`cisco-ai-mcp-scanner` has a `python_version >= "3.11"` gate).

### Clone and Build Everything

```bash
git clone https://github.com/defenseclaw/defenseclaw.git
cd defenseclaw

# Build all three components (does not install)
make build
```

`make build` produces:

| Component | Output |
|-----------|--------|
| Python CLI | `.venv/bin/defenseclaw` |
| Go gateway | `./defenseclaw-gateway` (current platform) |
| OpenClaw plugin | `extensions/defenseclaw/dist/` |

### Build and Install Everything

```bash
make install
```

`make install` builds all components and installs them to their
target locations:

| Component | Installed to |
|-----------|-------------|
| Python CLI | `.venv/bin/defenseclaw` (activate with `source .venv/bin/activate`) |
| Go gateway | `~/.local/bin/defenseclaw-gateway` |
| OpenClaw plugin | `~/.defenseclaw/extensions/defenseclaw/` |

On macOS the gateway binary is automatically ad-hoc codesigned.

After install, activate the Python environment and initialize:

```bash
source .venv/bin/activate
defenseclaw init
```

### Building Individual Components

```bash
# Python CLI only (creates .venv, installs editable)
make pycli

# Go gateway only (outputs ./defenseclaw-gateway)
make gateway

# OpenClaw TypeScript plugin only (outputs extensions/defenseclaw/dist/)
make plugin
```

Install individual components without rebuilding everything:

```bash
# Gateway → ~/.local/bin/defenseclaw-gateway (+ defenseclaw CLI)
make gateway-install

# Plugin → ~/.defenseclaw/extensions/defenseclaw/ (+ defenseclaw CLI)
make plugin-install
```

### Cross-Compilation

Build the Go gateway for a different platform:

```bash
# Linux amd64 (e.g., cloud VM)
make gateway-cross GOOS=linux GOARCH=amd64

# Linux arm64 (e.g., DGX Spark)
make gateway-cross GOOS=linux GOARCH=arm64

# macOS Intel
make gateway-cross GOOS=darwin GOARCH=amd64
```

Output binary is named `defenseclaw-{GOOS}-{GOARCH}`. Copy it to the
target machine:

```bash
scp defenseclaw-linux-arm64 spark:/tmp/defenseclaw-gateway
ssh spark 'sudo mv /tmp/defenseclaw-gateway /usr/local/bin/defenseclaw-gateway && sudo chmod +x /usr/local/bin/defenseclaw-gateway'
```

### Dev Install

For contributors and development workflows:

```bash
make dev-install
```

This runs `scripts/install-dev.sh`, which:

1. Creates a `.venv` with editable install + dev dependencies (ruff,
   pytest, pytest-cov)
2. Builds the Go gateway
3. Optionally installs the gateway binary to `~/.local/bin`
4. Installs `golangci-lint` and `opa` via `go install` if missing

Flags:

```bash
./scripts/install-dev.sh --check        # Dependency checks only
./scripts/install-dev.sh --skip-install  # Build but don't install to ~/.local/bin
./scripts/install-dev.sh --yes           # Non-interactive
```

Alternatively, install the Python CLI with dev dependencies directly:

```bash
make dev-pycli    # pycli + dev group (ruff, pytest)
source .venv/bin/activate
```

---

## Building Release Artifacts (`make dist`)

The `make dist` target builds all release artifacts for distribution.
Use this when preparing a release or testing the installer locally.

### Produce All Artifacts

```bash
make dist
```

This runs `dist-cli`, `dist-gateway`, `dist-plugin`, and
`dist-checksums` in sequence. Output goes to `dist/`:

```
dist/
├── defenseclaw-0.2.0-py3-none-any.whl       # Python CLI wheel
├── defenseclaw-gateway-linux-amd64           # Gateway binary (linux/amd64)
├── defenseclaw-gateway-linux-arm64           # Gateway binary (linux/arm64)
├── defenseclaw-gateway-darwin-amd64          # Gateway binary (macOS Intel)
├── defenseclaw-gateway-darwin-arm64          # Gateway binary (macOS Apple Silicon)
├── defenseclaw-plugin-0.2.0.tar.gz           # OpenClaw plugin tarball
└── checksums.txt                             # SHA-256 checksums
```

### Individual Dist Targets

```bash
make dist-cli       # Build Python wheel (bundles Rego policies, CodeGuard skill, policy data)
make dist-gateway   # Cross-compile gateway for all 4 platform/arch combos
make dist-plugin    # Build and tar the OpenClaw plugin with runtime deps
make dist-checksums # Generate SHA-256 checksums.txt
```

`dist-cli` bundles data files into the wheel before building:
Rego policies, `data.json`, YAML policy templates, and the CodeGuard skill.

### Install from Local Dist

Test the release artifacts locally using the install script:

```bash
./scripts/install.sh --local dist/
```

This installs the gateway binary, Python CLI wheel (into
`~/.defenseclaw/.venv`), and plugin without downloading anything.

### Upload to GitHub Release

```bash
gh release create v0.2.0 dist/*
```

### Clean Dist

```bash
make dist-clean   # Remove dist/ and bundled _data/
make clean        # Full clean (binaries, venv, node_modules, coverage)
```

### Curl-to-Bash Installer

End users can install a released version without cloning the repo:

```bash
curl -LsSf https://github.com/defenseclaw/defenseclaw/releases/latest/download/install.sh | bash
```

The installer detects the platform, downloads the correct gateway
binary + CLI wheel + plugin tarball, installs them, and prompts to run
`defenseclaw init --enable-guardrail`. Use `--yes` / `-y` to skip
confirmations.

Pin a specific version:

```bash
VERSION=0.2.0 curl -LsSf .../install.sh | bash
```

#### Picking an agent connector at install time

By default the installer integrates with **OpenClaw** (installs the
OpenClaw runtime and the DefenseClaw plugin). You can pick a different
connector — or skip connector setup entirely — with `--connector`:

```bash
# Codex (no OpenClaw, no plugin tarball; patches ~/.codex/config.toml + hooks)
curl -LsSf .../install.sh | bash -s -- --connector codex

# Claude Code (no OpenClaw; patches ~/.claude/settings.json hooks)
curl -LsSf .../install.sh | bash -s -- --connector claudecode

# ZeptoClaw (no OpenClaw; patches ~/.zeptoclaw/config.json)
curl -LsSf .../install.sh | bash -s -- --connector zeptoclaw

# Lay binaries only — pick a connector later
curl -LsSf .../install.sh | bash -s -- --connector none

# Shortcut for "skip OpenClaw" without naming another connector
curl -LsSf .../install.sh | bash -s -- --no-openclaw
```

Run interactively (without `--yes` and without `--connector`) and the
installer prompts which connector to use. The picked connector is
recorded at `~/.defenseclaw/picked_connector` so the CLI's `defenseclaw
setup` defaults to it on the next invocation.

---

## Setup Commands Reference

After building and running `defenseclaw init`, use the `setup`
subcommands to configure individual components. All `setup` commands
support `--non-interactive` for scripted use and `--verify` /
`--no-verify` to toggle post-setup connectivity checks.

### `defenseclaw init`

One-time initialization. Creates `~/.defenseclaw/`, installs scanner
dependencies, seeds config and audit database, copies Rego policies
and the CodeGuard skill, and starts the sidecar if the gateway binary
is on PATH.

```bash
defenseclaw init
```

| Flag | Description |
|------|-------------|
| `--skip-install` | Skip scanner dependency checks and package installs |
| `--enable-guardrail` | Run interactive guardrail setup (guardrail proxy + OpenClaw plugin) during init |

What init does, step by step:

1. Detects environment (DGX Spark vs macOS)
2. Creates `~/.defenseclaw/` directory tree
3. Copies Rego policies and `data.json` to `~/.defenseclaw/policies/`
4. Seeds the Splunk bridge directory (for `setup splunk --logs`)
5. Creates `config.yaml` and SQLite audit database
6. Checks that scanner CLIs (`skill-scanner`, `mcp-scanner`) are
   importable
7. Reads gateway defaults from OpenClaw config + generates device key
8. If `--enable-guardrail`: runs the full guardrail setup flow
   (guardrail proxy + OpenClaw plugin)
9. Installs the CodeGuard skill to `~/.openclaw/skills/codeguard/`
10. Starts `defenseclaw-gateway` if the binary exists on PATH

```bash
# Skip scanner installs (already have them)
defenseclaw init --skip-install

# Init + guardrail in one step (recommended for first install)
defenseclaw init --enable-guardrail
```

### `defenseclaw setup guardrail`

Configure the LLM guardrail that inspects prompts and completions
flowing through the guardrail proxy.

```bash
defenseclaw setup guardrail
```

| Flag | Description |
|------|-------------|
| `--mode MODE` | `observe` (log only) or `action` (block dangerous content) |
| `--scanner-mode MODE` | `local` (pattern matching) or `remote` (Cisco AI Defense API) |
| `--port PORT` | guardrail proxy port |
| `--block-message TEXT` | Custom message shown when content is blocked in action mode |
| `--cisco-endpoint URL` | Cisco AI Defense API endpoint |
| `--cisco-api-key-env VAR` | Env var name for Cisco API key |
| `--cisco-timeout-ms MS` | Cisco API timeout |
| `--restart` | Restart `defenseclaw-gateway` and monitor OpenClaw gateway after setup |
| `--disable` | Disable the guardrail and revert OpenClaw config |
| `--verify` / `--no-verify` | Run connectivity checks after setup |
| `--non-interactive` | Apply flags without prompts |

What guardrail setup does:

1. Configures the guardrail proxy
2. Configures proxy model routing
3. Installs the DefenseClaw OpenClaw plugin
4. Patches `openclaw.json` to route LLM calls through the proxy
5. Saves settings to `config.yaml` and API keys to `.env`
6. Writes `guardrail_runtime.json` for live mode toggling

```bash
# Non-interactive with specific mode
defenseclaw setup guardrail --mode action --scanner-mode local --non-interactive

# Disable and revert
defenseclaw setup guardrail --disable

# Disable and restart gateway
defenseclaw setup guardrail --disable --restart
```

### `defenseclaw setup skill-scanner`

Configure which analyzers the skill scanner uses when scanning skills.

```bash
defenseclaw setup skill-scanner
```

| Flag | Description |
|------|-------------|
| `--policy PRESET` | `strict`, `balanced`, or `permissive` |
| `--use-llm` | Enable LLM-based code analysis |
| `--use-behavioral` | Enable behavioral pattern analysis |
| `--enable-meta` | Enable meta-analyzer |
| `--use-trigger` | Enable trigger analyzer |
| `--use-virustotal` | Enable VirusTotal scanning |
| `--use-aidefense` | Enable Cisco AI Defense analyzer |
| `--llm-provider PROVIDER` | `anthropic` or `openai` |
| `--llm-model MODEL` | Model name for LLM analyzer |
| `--llm-consensus-runs N` | Number of LLM consensus runs (0 = disabled) |
| `--lenient` | Tolerate malformed skills |
| `--verify` / `--no-verify` | Run connectivity checks after setup |
| `--non-interactive` | Apply flags without prompts |

Interactive mode prompts for each analyzer, LLM provider/model/API
key, VirusTotal/Cisco API keys (saved to `~/.defenseclaw/.env`), and
a policy preset. On verify, runs a quick scanner check and reports any
connectivity issues.

```bash
# Quick strict setup
defenseclaw setup skill-scanner --policy strict --use-llm --llm-provider anthropic --non-interactive

# Permissive with no external APIs
defenseclaw setup skill-scanner --policy permissive --non-interactive
```

### `defenseclaw setup mcp-scanner`

Configure which analyzers the MCP scanner uses.

```bash
defenseclaw setup mcp-scanner
```

| Flag | Description |
|------|-------------|
| `--analyzers LIST` | Comma-separated analyzer list (e.g. `yara,api,llm,behavioral,readiness`) |
| `--llm-provider PROVIDER` | `anthropic` or `openai` |
| `--llm-model MODEL` | Model for LLM analyzer |
| `--scan-prompts` | Scan MCP server prompts |
| `--scan-resources` | Scan MCP server resources |
| `--scan-instructions` | Scan MCP server instructions |
| `--non-interactive` | Apply flags without prompts |

MCP server URLs are managed separately with `defenseclaw mcp set` /
`defenseclaw mcp unset`, not through this setup command.

```bash
defenseclaw setup mcp-scanner --analyzers yara,api,behavioral --non-interactive
```

### `defenseclaw setup gateway`

Configure the connection to the OpenClaw gateway (local or remote).

```bash
defenseclaw setup gateway
```

| Flag | Description |
|------|-------------|
| `--remote` | Configure for a remote gateway (interactive: SSM or manual token) |
| `--host HOST` | Gateway WebSocket host |
| `--port PORT` | Gateway WebSocket port |
| `--api-port PORT` | Sidecar REST API port |
| `--token TOKEN` | Auth token (saved to `.env` as `OPENCLAW_GATEWAY_TOKEN`) |
| `--ssm-param PARAM` | Fetch token from AWS SSM Parameter Store |
| `--ssm-region REGION` | AWS region for SSM |
| `--ssm-profile PROFILE` | AWS CLI profile for SSM |
| `--verify` / `--no-verify` | Run gateway and sidecar health checks after setup |
| `--non-interactive` | Apply flags without prompts; auto-detects token from OpenClaw config |

In local interactive mode, the setup can read the gateway token from
`openclaw.json` (`gateway.auth.token`) automatically.

```bash
# Local with explicit port
defenseclaw setup gateway --host 127.0.0.1 --api-port 18970 --non-interactive

# Remote with SSM token
defenseclaw setup gateway --remote --ssm-param /prod/openclaw/token --ssm-region us-west-2 --non-interactive
```

### `defenseclaw setup splunk`

Configure Splunk integration for audit export and observability.

```bash
defenseclaw setup splunk
```

| Flag | Description |
|------|-------------|
| `--o11y` | Enable Splunk Observability Cloud (OTLP traces + metrics) |
| `--logs` | Enable local Splunk via Docker (HEC) |
| `--enterprise` | Enable remote Splunk Enterprise via HEC endpoint + token |
| `--realm REALM` | Splunk O11y realm |
| `--access-token TOKEN` | Splunk O11y access token |
| `--hec-endpoint URL` | Remote Splunk Enterprise HEC endpoint |
| `--hec-token TOKEN` | Remote Splunk Enterprise HEC token |
| `--skip-test` | Skip the live HEC probe after remote Splunk Enterprise setup |
| `--app-name NAME` | Application name for traces |
| `--disable` | Disable integration(s); combine with `--o11y` / `--logs` / `--enterprise` to scope |
| `--non-interactive` | Requires at least `--o11y`, `--logs`, or `--enterprise` |

The `--logs` option requires Docker and sets up a local Splunk runtime with the
DefenseClaw Splunk bridge (`splunk-claw-bridge`). That runtime starts directly
in Splunk Free mode from day 1. In Splunk Free mode, alerting is disabled and
authentication is not required. To use full Splunk Enterprise features later,
apply a valid Splunk Enterprise license. For more details, see
https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configure-splunk-licenses/about-splunk-free

```bash
# Enable Splunk Observability Cloud
defenseclaw setup splunk --o11y --realm us1 --access-token $SPLUNK_TOKEN --non-interactive

# Enable remote Splunk Enterprise HEC
defenseclaw setup splunk --enterprise \
  --hec-endpoint https://splunk.example.com:8088/services/collector/event \
  --hec-token "$SPLUNK_HEC_TOKEN" \
  --index defenseclaw \
  --non-interactive

# Enable local Splunk logs (requires Docker)
defenseclaw setup splunk --logs --accept-splunk-license --non-interactive

# Disable both
defenseclaw setup splunk --disable
```

For `--enterprise`, the Splunk administrator must already have enabled HTTP
Event Collector, created an active HEC token, and allowed the configured index.
DefenseClaw stores the token in `~/.defenseclaw/.env` as
`DEFENSECLAW_SPLUNK_HEC_TOKEN` and writes only `token_env` to `config.yaml`.
Setup sends one best-effort HEC probe event after writing config so you can
see whether Splunk returns `200 OK`; use `--skip-test` to suppress that probe.

### `defenseclaw doctor`

Run diagnostic checks to verify that all DefenseClaw components are
healthy and properly configured.

```bash
defenseclaw doctor
```

Checks performed:

| Check | What it verifies |
|-------|------------------|
| Config file | `~/.defenseclaw/config.yaml` exists and is valid |
| Audit database | SQLite database is accessible |
| Scanner binaries | `skill-scanner` and `mcp-scanner` CLIs are on PATH |
| Sidecar health | `GET /health` to the sidecar; reports gateway, watcher, and guardrail sub-states |
| OpenClaw gateway | `GET /health` to the OpenClaw gateway (if configured) |
| Guardrail proxy | guardrail proxy health check (if guardrail is enabled) |
| LLM API key | Probe Anthropic or OpenAI API (if LLM analyzer is configured) |
| Cisco AI Defense | Endpoint health check (if remote scanner mode is enabled) |
| VirusTotal | API connectivity check (if VirusTotal is enabled) |
| Splunk HEC | HEC endpoint check (if Splunk is enabled) |

Output uses colored PASS/FAIL/WARN/SKIP indicators. Exits with code 1
if any check fails.

```bash
# Run all checks
defenseclaw doctor
```

Other setup commands run a subset of these checks when `--verify` is
enabled (the default). If verification fails, the output suggests
running `defenseclaw doctor` for the full report.

---

## Upgrading

### Upgrading from 0.2.0 to 0.3.0

Release 0.2.0 does not include the `defenseclaw upgrade` CLI command. Use the
standalone upgrade shell script instead:

```bash
# Upgrade to 0.3.0 (downloads from GitHub Releases)
curl -sSfL https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/main/scripts/upgrade.sh \
  | bash -s -- --version 0.3.0
```

Or, if you have the repository cloned:

```bash
./scripts/upgrade.sh --version 0.3.0
```

Add `--yes` to skip the confirmation prompt.

The script will:

1. Verify release artifacts exist on GitHub before touching anything
2. Download the gateway binary and Python CLI wheel to a temp directory
3. Back up `~/.defenseclaw/` config files and `~/.openclaw/openclaw.json`
4. Stop the gateway, install the new artifacts, run migrations
5. Restart the gateway and verify health

After this upgrade completes, the `defenseclaw upgrade` CLI command becomes
available for all future upgrades.

#### 0.3.0 migration: legacy model provider cleanup

The 0.2.0 guardrail setup redirected LLM traffic by writing provider and model
entries directly into `~/.openclaw/openclaw.json`:

- `models.providers.defenseclaw` and/or `models.providers.litellm` — proxy
  provider definitions that routed calls through the guardrail
- `agents.defaults.model.primary` set to `defenseclaw/<model>` or
  `litellm/<model>` — forced all agent calls through the proxy provider

In 0.3.0, routing is handled transparently by a fetch interceptor in the
OpenClaw plugin, so these entries are no longer needed.

The migration uses a **pristine-backup restore** strategy. When DefenseClaw's
guardrail was first enabled, it captured a one-time snapshot of the original
`openclaw.json` (before any DefenseClaw modifications). The migration:

1. Restores `openclaw.json` from that pristine backup — removing all
   DefenseClaw-injected entries in one clean step
2. Re-applies only the minimal plugin registration that 0.3.0 needs
   (`plugins.allow`, `plugins.entries`, `plugins.load.paths`)
3. Saves a `.pre-0.3.0-migration` backup of the current file before
   overwriting, for safety

If no pristine backup exists (e.g. guardrail was never enabled, or the backup
was deleted), the migration falls back to **surgical removal**: it deletes
`models.providers.defenseclaw` / `models.providers.litellm` and strips the
proxy prefix from `agents.defaults.model.primary`.

If none of these legacy entries exist, the migration is a no-op.

### Upgrading from 0.3.0 and later

Starting with 0.3.0, use the built-in CLI command:

```bash
# Upgrade to the latest release
defenseclaw upgrade

# Upgrade to a specific version
defenseclaw upgrade --version 0.4.0

# Skip confirmation prompt
defenseclaw upgrade --yes
```

The CLI command performs the same steps as the shell script: pre-flight
artifact verification, config backup, stop-install-migrate-restart, and
health polling. See the [CLI Reference](CLI.md#upgrade) for full flag
documentation.

### What gets upgraded

| Component | Updated by upgrade | Notes |
|-----------|-------------------|-------|
| Gateway binary (`defenseclaw-gateway`) | Yes | Replaced from release tarball |
| Python CLI (`defenseclaw`) | Yes | Replaced from release wheel |
| OpenClaw plugin | No | Plugin is release-specific; installed by `install.sh` only |
| Config files | Preserved | Backed up before upgrade, migrations patch if needed |
| Policies | Preserved | Backed up; not overwritten |

### Rollback

If an upgrade fails or causes issues, restore from the timestamped backup:

```bash
# Backups are saved to ~/.defenseclaw/backups/upgrade-<timestamp>/
ls ~/.defenseclaw/backups/

# Restore config files
cp ~/.defenseclaw/backups/upgrade-20260429T120000/config.yaml ~/.defenseclaw/
cp ~/.defenseclaw/backups/upgrade-20260429T120000/openclaw.json ~/.openclaw/

# Downgrade to the previous version
defenseclaw upgrade --version 0.2.0
# Or use the shell script if the CLI is broken:
curl -sSfL https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/main/scripts/upgrade.sh \
  | bash -s -- --version 0.2.0
```

---

## Troubleshooting

### "defenseclaw: command not found"

The binary is not on your PATH. Either:

```bash
# Add to PATH
export PATH=$PATH:/usr/local/bin

# Or run directly
./defenseclaw
```

### "failed to load config — run 'defenseclaw init' first"

You haven't initialized yet:

```bash
defenseclaw init
```

### Scanners not found

If `defenseclaw status` shows scanners as "not found":

```bash
# Re-run init to install them
defenseclaw init

# Or install manually
uv tool install cisco-ai-skill-scanner
uv tool install --python 3.13 cisco-ai-mcp-scanner
uv tool install --python 3.13 cisco-aibom
```

Make sure `uv` tool binaries are on your PATH:

```bash
export PATH=$PATH:$HOME/.local/bin
```

### "OpenShell not available" on DGX Spark

OpenShell is not installed or not on PATH:

```bash
which openshell
# If not found, install it per NVIDIA documentation
```

### "OpenShell not available" on macOS

This is expected. OpenShell is Linux-only. DefenseClaw gracefully degrades: scanning, block/allow lists, audit logging, and the TUI all work without it.

### Permission denied writing policy

DefenseClaw tries to write sandbox policy to `/etc/openshell/policies/`. If that fails (permissions), it falls back to `~/.defenseclaw/policies/`. Both locations work. On DGX Spark, you can fix this with:

```bash
sudo mkdir -p /etc/openshell/policies
sudo chown $USER /etc/openshell/policies
```

---

## Directory Layout

After installation, your system has:

```
~/.defenseclaw/
├── config.yaml          # DefenseClaw configuration (includes claw mode)
├── audit.db             # SQLite audit log + scan results + block/allow lists
├── quarantine/          # Blocked skill files (moved here on block)
│   └── skills/
├── plugins/             # Custom scanner plugins (iteration 5)
├── policies/            # Sandbox policy files (fallback location)
└── codeguard-rules/     # CodeGuard security rules

~/.openclaw/             # OpenClaw home (default, configurable via claw.home_dir)
├── openclaw.json        # OpenClaw config — custom skills_dir read by DefenseClaw
├── config.yaml
├── workspace/
│   └── skills/          # Workspace/project-specific skills (priority 1)
├── skills/              # Global user-installed skills (priority 3)
├── mcp-servers/         # MCP server configs
└── mcps/                # MCP server configs (alt)

/etc/openshell/policies/ # OpenShell policy directory (DGX Spark, if writable)
└── defenseclaw-policy.yaml
```

DefenseClaw reads from the claw home directory (e.g. `~/.openclaw/`) but never modifies it directly. It writes sandbox policy to OpenShell and manages its own state in `~/.defenseclaw/`.

### Claw Mode Configuration

DefenseClaw supports multiple agent frameworks. Set the active mode in `~/.defenseclaw/config.yaml`:

```yaml
claw:
  mode: openclaw        # openclaw | zeptoclaw | claudecode | codex
  home_dir: ""          # auto-detected; override to use a custom path
```

The claw mode determines which skill and MCP directories are watched, scanned, and used for install resolution. Adding a new framework only requires a new case in the config resolver.
