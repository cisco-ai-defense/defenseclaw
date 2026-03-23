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

---

## Part A: Adding DefenseClaw to an Existing OpenClaw Deployment

Use this if OpenClaw is already running on your system.

### DGX Spark (aarch64 / Ubuntu)

#### Prerequisites

| Requirement | Check |
|-------------|-------|
| OpenClaw running | `openclaw status` or check your agent process |
| Python 3.11+ | `python3 --version` |
| Go 1.22+ (build from source) | `go version` |
| Git | `git --version` |

#### Step 1: Build DefenseClaw

```bash
# Clone the repository
git clone https://github.com/defenseclaw/defenseclaw.git
cd defenseclaw

# Build for linux/arm64
make build-linux-arm64

# Install the binary
sudo cp defenseclaw-linux-arm64 /usr/local/bin/defenseclaw
sudo chmod +x /usr/local/bin/defenseclaw

# Verify
defenseclaw --help
```

If you are cross-compiling from a different machine (e.g., your Mac):

```bash
make build-linux-arm64
scp defenseclaw-linux-arm64 your-spark:/tmp/defenseclaw
# Then on the Spark:
sudo mv /tmp/defenseclaw /usr/local/bin/defenseclaw
sudo chmod +x /usr/local/bin/defenseclaw
```

#### Step 2: Initialize

```bash
defenseclaw init
```

This creates `~/.defenseclaw/` and installs the Python scanner dependencies automatically. You will see output for each scanner as it installs.

Expected output:

```
[init] Environment: dgx-spark
[init] Creating /home/you/.defenseclaw/
[init] Installing scanner dependencies...
  Installing cisco-ai-skill-scanner... done
  Installing cisco-ai-mcp-scanner... done
  Installing cisco-aibom... done
[init] Scanners ready.
[init] SQLite audit database created.
[init] DefenseClaw initialized.
```

If you want to skip scanner installation (they're already installed):

```bash
defenseclaw init --skip-install
```

#### Step 3: Scan your existing environment

```bash
# Scan all skills in your OpenClaw skills directory
defenseclaw scan skill /path/to/your/openclaw/skills/my-skill/

# Scan an MCP server your agent connects to
defenseclaw scan mcp https://your-mcp-server.example.com

# Scan code for security issues
defenseclaw scan code /path/to/your/project/

# Run all scanners at once against a directory
defenseclaw scan /path/to/your/openclaw/
```

#### Step 4: Deploy with full enforcement

```bash
defenseclaw deploy /path/to/your/openclaw/
```

This runs the complete flow:
1. Ensures init is complete
2. Scans all skills, MCP servers, code, and AI dependencies
3. Auto-blocks anything with HIGH or CRITICAL findings
4. Generates an OpenShell sandbox policy from the results
5. Starts OpenClaw inside the OpenShell sandbox

Check status at any time:

```bash
defenseclaw status
```

#### Step 5: Open the dashboard

```bash
defenseclaw tui
```

Navigate with `tab` between panels, `j`/`k` to move through lists, `b` to block, `a` to allow, `d` to dismiss alerts, `q` to quit.

---

### macOS (Apple Silicon)

On macOS, DefenseClaw works for scanning, governance, and audit. Sandbox enforcement is skipped because OpenShell is not available on macOS.

#### Prerequisites

| Requirement | Check |
|-------------|-------|
| OpenClaw running | Your agent process or dev server |
| Python 3.11+ | `python3 --version` |
| Go 1.22+ (build from source) | `go version` |
| Git | `git --version` |

Install Go if needed:

```bash
brew install go
```

#### Step 1: Build DefenseClaw

```bash
git clone https://github.com/defenseclaw/defenseclaw.git
cd defenseclaw

# Build for Apple Silicon
make build

# Install
sudo cp defenseclaw /usr/local/bin/
sudo chmod +x /usr/local/bin/defenseclaw

# Verify
defenseclaw --help
```

#### Step 2: Initialize

```bash
defenseclaw init
```

Expected output on macOS:

```
[init] Environment: macos
[init] Creating /Users/you/.defenseclaw/
[init] Installing scanner dependencies...
  Installing cisco-ai-skill-scanner... done
  Installing cisco-ai-mcp-scanner... done
  Installing cisco-aibom... done
[init] Scanners ready.
[init] SQLite audit database created.
[init] DefenseClaw initialized.
```

#### Step 3: Scan your environment

```bash
# Scan a skill
defenseclaw scan skill ./path/to/skill/

# Scan an MCP server
defenseclaw scan mcp https://your-mcp-server.example.com

# Scan code
defenseclaw scan code ./your-project/

# Generate AI bill of materials
defenseclaw scan aibom .
```

#### Step 4: Deploy

```bash
defenseclaw deploy ./your-project/
```

On macOS, the sandbox step prints:

```
Step 5/5: Starting sandbox...
  OpenShell not available on macOS — sandbox enforcement skipped
```

Everything else works: scanning, auto-blocking, policy generation, audit logging.

#### Step 5: Manage and monitor

```bash
# Check status
defenseclaw status

# View alerts
defenseclaw alerts

# Open the TUI dashboard
defenseclaw tui

# Block a risky skill
defenseclaw block skill ./risky-skill --reason "data exfiltration pattern"

# View block/allow lists
defenseclaw list blocked
defenseclaw list allowed
```

---

## Part B: Fresh Install — OpenClaw + OpenShell + DefenseClaw

Use this if you are starting from scratch.

### DGX Spark (aarch64 / Ubuntu)

#### Step 1: Install OpenShell

OpenShell is NVIDIA's sandbox for isolating AI agent workloads. Install it from the NVIDIA container toolkit:

```bash
# Add the NVIDIA container toolkit repository
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | \
  sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg

curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
  sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
  sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list

sudo apt-get update

# Install OpenShell
sudo apt-get install -y nvidia-openshell

# Verify
openshell --version
```

> **Note:** The exact installation steps may vary depending on your DGX Spark
> software version. Refer to the
> [NVIDIA OpenShell documentation](https://docs.nvidia.com/openshell/) for the
> latest instructions specific to your system.

#### Step 2: Install OpenClaw

OpenClaw is the AI agent framework. Install it inside the OpenShell sandbox environment:

```bash
# Install OpenClaw
pip install openclaw

# Or from source
git clone https://github.com/nvidia/openclaw.git
cd openclaw
pip install -e .

# Verify
openclaw --version
```

> **Note:** Consult the
> [OpenClaw documentation](https://github.com/nvidia/openclaw) for the latest
> installation instructions, configuration options, and supported models.

#### Step 3: Configure OpenClaw

Create your OpenClaw configuration:

```bash
mkdir -p ~/.openclaw

cat > ~/.openclaw/config.yaml << 'YAML'
agent:
  name: my-agent
  model: nvidia/llama-3.1-nemotron-70b-instruct

skills_dir: ~/.openclaw/skills
mcp_servers: []
YAML
```

Install skills your agent needs:

```bash
mkdir -p ~/.openclaw/skills
# Copy or install your skills into this directory
```

#### Step 4: Install DefenseClaw

```bash
git clone https://github.com/defenseclaw/defenseclaw.git
cd defenseclaw
make build-linux-arm64
sudo cp defenseclaw-linux-arm64 /usr/local/bin/defenseclaw
sudo chmod +x /usr/local/bin/defenseclaw
```

#### Step 5: Initialize DefenseClaw

```bash
defenseclaw init
```

This detects your DGX Spark environment, installs scanner dependencies, and creates the configuration.

#### Step 6: Deploy with DefenseClaw

Instead of starting OpenClaw manually, let DefenseClaw orchestrate the entire launch:

```bash
defenseclaw deploy ~/.openclaw/
```

This:
1. Scans all skills, MCP servers, code, and AI dependencies
2. Auto-blocks anything HIGH/CRITICAL
3. Generates an OpenShell sandbox policy that restricts network access and file permissions to only what your agent needs
4. Starts OpenClaw inside the OpenShell sandbox with the generated policy

#### Step 7: Verify

```bash
# Check everything is running
defenseclaw status

# Output should show:
#   Environment:  dgx-spark
#   Sandbox:      running
#   Scanners:     all installed
#   Blocked:      any auto-blocked items
#   Active alerts: count of findings

# Open the dashboard
defenseclaw tui
```

#### Step 8: Ongoing operations

```bash
# Re-scan everything after adding new skills
defenseclaw rescan

# View audit trail
defenseclaw audit

# Stop the sandbox
defenseclaw stop
```

---

### macOS (Apple Silicon) — Development Setup

macOS is ideal for developing and testing skills locally before deploying to DGX Spark. OpenShell is not available on macOS, so there is no sandbox enforcement, but scanning, governance, and the TUI all work.

#### Step 1: Install OpenClaw

```bash
# Using pip
pip install openclaw

# Or using uv
uv pip install openclaw

# Verify
openclaw --version
```

> **Note:** Refer to the [OpenClaw documentation](https://github.com/nvidia/openclaw)
> for macOS-specific setup, model configuration, and any additional dependencies.

#### Step 2: Configure OpenClaw

```bash
mkdir -p ~/.openclaw

cat > ~/.openclaw/config.yaml << 'YAML'
agent:
  name: dev-agent
  model: nvidia/llama-3.1-nemotron-70b-instruct

skills_dir: ~/.openclaw/skills
mcp_servers: []
YAML
```

#### Step 3: Install DefenseClaw

```bash
# Install Go if needed
brew install go

# Build
git clone https://github.com/defenseclaw/defenseclaw.git
cd defenseclaw
make build
sudo cp defenseclaw /usr/local/bin/
sudo chmod +x /usr/local/bin/defenseclaw
```

#### Step 4: Initialize and deploy

```bash
# Initialize (installs scanner dependencies)
defenseclaw init

# Deploy (scans, enforces, skips sandbox on macOS)
defenseclaw deploy ~/.openclaw/
```

Expected macOS output:

```
Step 5/5: Starting sandbox...
  OpenShell not available on macOS — sandbox enforcement skipped
```

#### Step 5: Develop safely

```bash
# Scan a skill you're developing
defenseclaw scan skill ./my-new-skill/

# Scan your code for security issues
defenseclaw scan code ./my-project/

# Check what's blocked
defenseclaw list blocked

# Open the dashboard
defenseclaw tui
```

#### Step 6: Move to DGX Spark

When you're ready to deploy to production:

```bash
# On your Mac: cross-compile for DGX Spark
make build-linux-arm64

# Copy binary and your skill to the Spark
scp defenseclaw-linux-arm64 spark:/usr/local/bin/defenseclaw
scp -r ./my-new-skill/ spark:~/.openclaw/skills/

# On the Spark: deploy with full sandbox enforcement
ssh spark
defenseclaw deploy ~/.openclaw/
```

---

## Upgrading OpenClaw

When a new version of OpenClaw is released, use DefenseClaw to safely upgrade.

### DGX Spark

```bash
# Stop the current sandbox
defenseclaw stop

# Upgrade OpenClaw
pip install --upgrade openclaw

# Re-scan everything with the new version
defenseclaw rescan

# Re-deploy with the updated OpenClaw
defenseclaw deploy ~/.openclaw/

# Verify
defenseclaw status
```

### macOS

```bash
# Upgrade OpenClaw
pip install --upgrade openclaw

# Re-scan
defenseclaw rescan

# Re-deploy
defenseclaw deploy ~/.openclaw/
```

---

## Upgrading DefenseClaw

```bash
cd defenseclaw
git pull origin main

# DGX Spark
make build-linux-arm64
sudo cp defenseclaw-linux-arm64 /usr/local/bin/defenseclaw

# macOS
make build
sudo cp defenseclaw /usr/local/bin/defenseclaw

# Verify
defenseclaw --version
```

Your `~/.defenseclaw/` data directory (config, audit log, block/allow lists) is preserved across upgrades.

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
  mode: openclaw        # openclaw (default) | nemoclaw | opencode | claudecode (future)
  home_dir: ""          # auto-detected; override to use a custom path
```

The claw mode determines which skill and MCP directories are watched, scanned, and used for install resolution. Adding a new framework only requires a new case in the config resolver.
