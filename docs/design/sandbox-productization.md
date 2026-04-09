# Sandbox Productization Plan

## Overview

This document covers everything required to ship DefenseClaw's OpenShell
standalone sandbox integration as a production feature. It spans build,
packaging, installation, initialization, runtime, and the security hardening
items identified in `sandbox-security-analysis.md`.

### Current state

Today the sandbox integration works but requires manual steps:

- Manually download and extract `openshell-sandbox` from NVIDIA's container
- Manually create a `sandbox` Linux user
- Manually write OpenShell policy files (Rego + YAML)
- Manually configure OpenClaw inside the sandbox (config, plugin, ownership)
- Manually inject iptables rules to punch holes for sidecar access
- Manually pair the DefenseClaw device with OpenClaw

All of this needs to be automated into the existing CLI lifecycle:
`defenseclaw init` → `defenseclaw setup sandbox` → `defenseclaw sandbox start`.

### Scope: single sandbox

This plan supports **one sandbox instance per host**. A single
`openshell-sandbox` process running a single OpenClaw instance under a
single `sandbox` user. Multiple sandboxes on the same host (e.g.,
separate dev/prod instances with different policies) are out of scope
for v1. Supporting multiple sandboxes would require parameterizing
the user, home directory, veth IPs, systemd unit names, and config
paths — deferred to a future release if there's demand.

### Sandbox user and paths

The `sandbox` user is the user that OpenClaw runs as inside the sandbox.
`openshell-sandbox` runs as root and drops privileges to this user before
exec'ing OpenClaw. The user interacts with OpenClaw (onboarding, channel
login, skill management) via `sandbox exec` which enters the sandbox
namespace as this user.

The sandbox home directory defaults to `/home/sandbox` and is
configurable via `openshell.sandbox_home` in `~/.defenseclaw/config.yaml`.
All paths in launcher scripts and systemd units are generated with the
configured value — no `$HOME` or `~` expansion at runtime.

```yaml
# ~/.defenseclaw/config.yaml
openshell:
  mode: standalone
  sandbox_home: /home/sandbox   # default, configurable
```

Directory layout at the sandbox home:

```
/home/sandbox/                    # openshell.sandbox_home
  .openclaw/
    openclaw.json                 # SHARED (user + DefenseClaw patch)
    agents/                       # USER-OWNED
    extensions/
      defenseclaw/                # DEFENSECLAW-OWNED
      */                          # USER-OWNED
    skills/                       # USER-OWNED
    workspace/                    # USER-OWNED
    gateway.json                  # USER-OWNED
    devices.json                  # USER-OWNED
  .defenseclaw/
    config.yaml                   # DEFENSECLAW-OWNED (sandbox-side sidecar addr)
    plugin-verify.pub             # DEFENSECLAW-OWNED
```

When sandbox mode is active, `defenseclaw setup sandbox` sets:

```yaml
claw:
  home_dir: /home/sandbox/.openclaw
  config_file: /home/sandbox/.openclaw/openclaw.json
```

This makes **all existing code** (`guardrail.py:patch_openclaw_config()`,
`codeguard_skill.py:_enable_codeguard_in_openclaw()`, `config.py:skill_dirs()`,
etc.) automatically target the sandbox user's OpenClaw config and
directories. No changes needed to guardrail or codeguard patching code —
they already use `app.cfg.claw.config_file` and `app.cfg.claw_home_dir()`.

When sandbox mode is disabled (`--disable`), the values revert to:

```yaml
claw:
  home_dir: ~/.openclaw
  config_file: ~/.openclaw/openclaw.json
```

---

## Root and Privilege Requirements

Sandbox mode requires root for specific operations. This section
consolidates every privilege requirement so operators know exactly what
needs elevated access and why.

### What runs as root

| Process / Operation | Why root is needed | When it runs |
|---|---|---|
| `openshell-sandbox` | Creates network namespaces (`CAP_SYS_ADMIN`), sets up veth pairs and routes (`CAP_NET_ADMIN`), drops privileges to `sandbox` user internally | Every sandbox start (systemd service) |
| `start-sandbox.sh` | `unshare --mount` to create a private mount namespace for DNS resolv.conf bind-mount | Every sandbox start (ExecStart) |
| `pre-sandbox.sh` | Cleans orphan network namespaces (`ip netns delete`), stale veth interfaces (`ip link delete`), stale lock files | Every sandbox start (ExecStartPre) |
| `post-sandbox.sh` | Injects iptables rules into the sandbox namespace via `ip netns exec` + `iptables` | Every sandbox start (ExecStartPost) |
| `cleanup-sandbox.sh` | Cleans orphan namespaces and veth interfaces after unclean shutdown | Every sandbox stop (ExecStopPost) |
| `defenseclaw init --sandbox` | Creates the `sandbox` system user (`useradd`), sets file ownership (`chown`) | One-time setup |
| `defenseclaw setup sandbox` | Installs systemd unit files to `/etc/systemd/system/`, installs launcher scripts to `/usr/local/lib/defenseclaw/`, sets plugin ownership to `root:root`, sets sandbox config ownership to `sandbox:sandbox` | One-time setup (re-runnable) |
| `systemctl start/stop/restart` | Managing systemd services | Administrative operations |
| `sandbox exec --netns` / `sandbox shell --netns` | Uses `ip netns exec` to enter the sandbox namespace (troubleshooting only) | On-demand administrative operations |

### What does NOT run as root

| Process | Runs as | Notes |
|---|---|---|
| `defenseclaw-gateway` (sidecar) | Unprivileged user | systemd unit has `NoNewPrivileges=true`, `ProtectSystem=strict`. Connects to sandbox via WebSocket over the veth pair. No namespace or iptables access. |
| LiteLLM proxy | Unprivileged (child of sidecar) | Runs on the host, binds to port 4000 (unprivileged). |
| OpenClaw (inside sandbox) | `sandbox` user | Privilege-dropped by `openshell-sandbox` before exec. |
| DefenseClaw plugin (inside sandbox) | `sandbox` user | Loaded by OpenClaw, inherits its UID. |

### Capability breakdown

If deploying without full root (e.g., using Linux capabilities instead),
the minimum capabilities required by `openshell-sandbox.service` are:

| Capability | Used for |
|---|---|
| `CAP_SYS_ADMIN` | Creating network namespaces (`unshare`), mount namespaces |
| `CAP_NET_ADMIN` | veth pair setup, IP address assignment, route configuration, iptables rule injection |
| `CAP_SETUID` / `CAP_SETGID` | Dropping privileges to the `sandbox` user |
| `CAP_DAC_OVERRIDE` | Writing to `<sandbox_home>/` directories owned by `sandbox` user (during setup only) |

The sidecar (`defenseclaw-gateway.service`) requires **no capabilities**.
It runs as a normal unprivileged user.

### Principle

All privileged operations are confined to the sandbox service and its
lifecycle scripts. The sidecar is fully unprivileged at runtime. This
separation means a vulnerability in the sidecar (e.g., in its REST API)
cannot be leveraged to modify the sandbox's namespace, iptables rules,
or host filesystem.

---

## Phase 1: OpenShell Binary Acquisition

### Problem

`openshell-sandbox` is a Rust binary from NVIDIA's open-source repository.
DefenseClaw cannot vendor or rebuild it — it must be fetched as a prebuilt
artifact or built from source as part of our CI.

### Install methods

NVIDIA provides two official install methods. We use their installer
with a pinned version for reproducibility.

**Method A: Binary installer (recommended for servers)**

```bash
# Latest
curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh

# Pinned version (what DefenseClaw uses)
OPENSHELL_VERSION=0.6.2 curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh
```

**Method B: PyPI via uv (alternative)**

```bash
# Latest
uv tool install -U openshell

# Pinned version
uv tool install openshell==0.6.2
```

Both methods install the `openshell-sandbox` binary to the user's PATH.

### Implementation

#### 1.1 Version pinning

Add to `internal/config/defaults.go`:

```go
OpenShellVersion: "0.6.2",  // pinned, tested compatible version
```

Store in config as `openshell.version`. DefenseClaw pins to a tested
version to avoid breakage from upstream changes. The version can be
overridden via `--openshell-version` for users who need a different
release.

**Update process:** When NVIDIA releases a new version, test it
against the sandbox integration test suite (Phase 8.2), then update
the pinned version in `defaults.go`.

#### 1.2 Install wrapper

`defenseclaw init --sandbox` checks for `openshell-sandbox` on PATH.
If missing, it offers to install using NVIDIA's installer:

```
openshell-sandbox not found on PATH.

Install now? [Y/n]
  Method: NVIDIA binary installer (curl)
  Version: 0.6.2 (pinned)
```

If the user accepts, run:

```bash
OPENSHELL_VERSION=<pinned> curl -LsSf \
  https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh
```

If `uv` is available and `curl` is not, fall back to:

```bash
uv tool install openshell==<pinned>
```

#### 1.3 Go verification

```go
// internal/sandbox/install.go
func VerifyOpenShellBinary(path string) (string, error)  // returns version string
func CheckVersionCompatibility(installed, required string) error
```

`VerifyOpenShellBinary` runs `openshell-sandbox --version` and parses
the output. `CheckVersionCompatibility` warns if the installed version
differs from the pinned version (non-fatal — the user may have a valid
reason to use a different version).

#### 1.4 CI integration

The standard CI pipeline does not install or test openshell-sandbox
(no privileged runners). The pinned version is verified manually as
part of the sandbox integration test suite (Phase 8.2).

---

## Phase 2: Build & Packaging

### 2.1 Binary naming — FUTURE

Currently goreleaser builds the binary as `defenseclaw` while the Makefile
and docs call it `defenseclaw-gateway`. This is a naming inconsistency but
not blocking. Defer to a future release to avoid breaking existing installs.

### 2.2 Plugin bundling

The OpenClaw plugin (`extensions/defenseclaw/`) is currently built separately
via `npm run build` and installed via `make plugin-install`. For production:

Add a Makefile target that produces a self-contained tarball:

```makefile
plugin-bundle:
    cd extensions/defenseclaw && npm ci && npm run build
    tar czf dist/defenseclaw-plugin.tar.gz \
        -C extensions/defenseclaw \
        package.json openclaw.plugin.json dist/ \
        node_modules/js-yaml node_modules/argparse
```

Include this tarball in goreleaser archives for Linux targets.

### 2.3 Guardrail module bundling

`guardrails/defenseclaw_guardrail.py` must be included in:
- The Python package (already in `pyproject.toml` package data)
- The goreleaser archive (new — so `defenseclaw init` can extract it)

Add to `.goreleaser.yaml`:

```yaml
archives:
  - files:
      - guardrails/defenseclaw_guardrail.py
      - policies/**/*
      - extensions/defenseclaw-plugin.tar.gz
```

### 2.4 Policy templates

Bundle OpenShell-specific policy templates:

```
policies/
  openshell/
    default.rego          # base Rego rules for openshell-sandbox
    default-data.yaml     # default network + filesystem policy
    strict-data.yaml      # locked-down variant (included, not applied by default)
    permissive-data.yaml  # development variant
```

These are DefenseClaw-authored policies that work with `openshell-sandbox`'s
policy engine. They replace the manually crafted files from testing.

**All endpoints in the generated policy YAML must include `tls: skip`.**
The openshell-sandbox proxy performs TLS interception (MITM) by default
using an ephemeral CA generated at startup. Node.js rejects the proxy's
certificate with `UnknownCA` even though `NODE_EXTRA_CA_CERTS` is set,
because the CA is regenerated on every sandbox restart and the injected
env vars don't reliably propagate through all execution paths. Setting
`tls: skip` per-endpoint makes the proxy pass through TLS without
interception, which is the correct behavior for DefenseClaw — we perform
our own inspection at the guardrail layer, not at the network proxy layer.

Example endpoint with `tls: skip`:

```yaml
network_policies:
  allow_telegram:
    binaries:
    - path: /**
    endpoints:
    - host: "**.telegram.org"
      ports:
      - 443
      tls: skip
```

#### Cisco AI Defense Inspection API

The Cisco AI Defense Inspection API
(`us.api.inspect.aidefense.security.cisco.com`) does **NOT** need to be
in the sandbox network policy. The call chain is:

```
Sandbox (OpenClaw) → LiteLLM (host) → guardrail Python (host) → Cisco AI Defense API
```

The guardrail module runs as a child process of LiteLLM, which is a
child process of the sidecar — all on the host side. The Cisco API
call originates from the host's network stack, not the sandbox. Only
LLM provider endpoints (OpenAI, Anthropic, etc.) need to be in the
sandbox policy if OpenClaw calls them directly, but in the standard
DefenseClaw setup, LLM traffic is routed through LiteLLM on the host
(`http://10.200.0.1:4000`), so those don't need sandbox policy entries
either.

The sandbox policy only needs entries for services that OpenClaw's
Node.js process connects to directly from inside the sandbox:
- Channel APIs (Telegram, Slack, Discord) — OpenClaw polls these
- npm registry — if OpenClaw installs packages at runtime
- Any custom skill/MCP endpoints the user configures

#### Default vs strict policy templates

**`default-data.yaml`** — applied by `defenseclaw init --sandbox`:

Broad wildcards for common services. Suitable for most deployments.

```yaml
network_policies:
  allow_defenseclaw_sidecar:
    binaries:
    - path: /**
    endpoints:
    - host: "10.200.0.1"
      ports: [18970, 4000]

  allow_channels:
    binaries:
    - path: /**
    endpoints:
    - host: "**.telegram.org"
      ports: [443]
      tls: skip
    - host: "**.slack.com"
      ports: [443]
      tls: skip
    - host: "hooks.slack.com"
      ports: [443]
      tls: skip
    - host: "**.discord.com"
      ports: [443]
      tls: skip
    - host: "gateway.discord.gg"
      ports: [443]
      tls: skip

  allow_npm_registry:
    binaries:
    - path: /**
    endpoints:
    - host: "registry.npmjs.org"
      ports: [443]
      tls: skip

  # NOTE: Direct LLM API access (OpenAI, Anthropic, etc.) is intentionally
  # NOT included. All LLM traffic must flow through LiteLLM on the host
  # (10.200.0.1:4000), which is already allowed above. This makes the
  # guardrail mandatory at the network level — a compromised skill cannot
  # bypass content scanning by calling the provider directly.
  #
  # If a deployment requires direct LLM access (bypassing guardrails),
  # the operator must add the endpoints explicitly with full awareness
  # of the security trade-off.
```

**`strict-data.yaml`** — included but NOT applied by default. For
security-conscious deployments that want minimal attack surface.
Users select it via `defenseclaw setup sandbox --policy strict`.

```yaml
network_policies:
  allow_defenseclaw_sidecar:
    binaries:
    - path: /**
    endpoints:
    - host: "10.200.0.1"
      ports: [18970, 4000]

  # No channel APIs — user must explicitly add the ones they need.
  # No npm registry — no runtime package installs.
  # No direct LLM APIs — all LLM traffic goes through LiteLLM
  #   on the host (10.200.0.1:4000), which is already allowed above.
```

The strict template only allows the sidecar connection. Everything
else must be explicitly added by the user. This is the right choice
for deployments where:
- LLM traffic is exclusively routed through LiteLLM (no direct calls)
- Channels are not used (or the user adds only what they need)
- No runtime npm installs are expected

To add an endpoint to the strict policy, edit the active policy file
and restart:

```bash
# Edit policy
vi <data_dir>/openshell-policy.yaml

# Check what OpenClaw needs
defenseclaw-gateway sandbox policy diff

# Apply
defenseclaw-gateway sandbox restart
```

### 2.5 Cross-compilation matrix

No changes needed — DefenseClaw is pure Go (modernc.org/sqlite, no CGo).
The sandbox feature is Linux-only; on macOS/Windows, `defenseclaw init`
skips sandbox setup and prints a message.

---

## Phase 3: Installation

### 3.1 `scripts/install.sh` — unified Linux server installer

The current `install.sh` only downloads the Go gateway binary. It needs to
become the single entry point for Linux server deployments, installing
everything a user needs before running `defenseclaw init`.

#### Current behavior

```
1. Download defenseclaw binary from GitHub Releases
2. Install to /usr/local/bin/
3. Print "Run defenseclaw init"
```

#### Target behavior

```bash
curl -sSfL https://raw.githubusercontent.com/defenseclaw/defenseclaw/main/scripts/install.sh | bash
# or with options:
curl ... | bash -s -- --sandbox    # also install openshell-sandbox
```

Steps:

```
1. Detect OS (linux/darwin) and arch (amd64/arm64)
2. Download defenseclaw release archive from GitHub Releases
3. Extract and install:
   a. defenseclaw-gateway binary → /usr/local/bin/
   b. Plugin tarball → ~/.defenseclaw/extensions/defenseclaw/
   c. Guardrail module → ~/.defenseclaw/guardrails/
   d. Policy templates → ~/.defenseclaw/policies/
4. Install Python CLI:
   a. Check for python3 and pip
   b. pip install from the bundled wheel or editable source:
        pip install ./defenseclaw-cli-*.whl
      (PyPI publishing is future — for now the CLI is built from source
       via `make pycli` or included as a wheel in the release archive)
   c. Install scanner dependencies: pip install skill-scanner mcp-scanner
5. If --sandbox flag (Linux only):
   a. Install openshell-sandbox via NVIDIA's installer (pinned version):
        OPENSHELL_VERSION=<pinned> curl -LsSf .../install.sh | sh
      Or via uv if curl is unavailable:
        uv tool install openshell==<pinned>
6. Verify installation:
   a. defenseclaw --version (Python CLI)
   b. defenseclaw-gateway --version (Go sidecar)
   c. openshell-sandbox --version (if --sandbox)
7. Print next steps:
   - Without --sandbox: "Run defenseclaw init"
   - With --sandbox: "Run defenseclaw init --sandbox"
```

#### Flags

| Flag | Description |
|------|-------------|
| `--sandbox` | Also install `openshell-sandbox` (Linux only) |
| `--no-python` | Skip Python CLI + scanner install |
| `--version VERSION` | Install specific version (default: latest) |
| `--prefix DIR` | Install binaries to DIR instead of /usr/local/bin |

#### Error handling

- macOS + `--sandbox`: print "Sandbox mode requires Linux" and exit
- Python not found: print warning, skip Python CLI, suggest manual install
- openshell-sandbox download fails: print error, continue without it,
  tell user they can install later with `defenseclaw sandbox install`
- No root access: use `~/.local/bin` as fallback, warn about PATH

### 3.2 Homebrew formula — FUTURE

Homebrew works on both macOS and Linux, but is primarily a developer
workstation tool. The existing Homebrew tap serves the **host-only**
(no sandbox) use case — developers on Mac or Linux desktops installing
DefenseClaw alongside OpenClaw.

For the **sandbox** use case (Linux servers), `scripts/install.sh` is
the primary distribution channel. Homebrew formula changes are deferred.

### 3.3 System packages (.deb/.rpm) — FUTURE

If/when we add system packages:
- `defenseclaw-gateway` binary to `/usr/local/bin/`
- Plugin to `/usr/share/defenseclaw/extensions/`
- Policies to `/usr/share/defenseclaw/policies/`
- Guardrail module to `/usr/share/defenseclaw/guardrails/`
- `openshell-sandbox` as a Recommends/Suggests dependency

### 3.4 End-to-end install flow (Linux server with sandbox)

For reference, the full install-to-running flow after productization:

```bash
# Step 1: Install everything
curl -sSfL .../install.sh | bash -s -- --sandbox

# Step 2: Initialize (creates user, config, DB, policies, plugin staging)
defenseclaw init --sandbox

# Step 3: Configure sandbox networking and guardrail
defenseclaw setup sandbox --sandbox-ip 10.200.0.2 --host-ip 10.200.0.1
defenseclaw setup guardrail --mode observe --non-interactive

# Step 4: Start (independent systemd services)
sudo systemctl start defenseclaw-sandbox.target
# or: defenseclaw-gateway sandbox start (convenience wrapper)

# Step 5: User configures OpenClaw (interactive — via GUI, TUI, CLI, or chat)
defenseclaw-gateway sandbox exec -- openclaw channels login --channel telegram
defenseclaw-gateway sandbox exec -- openclaw onboard
# Or connect to the GUI/TUI and do it there.

# Step 6: Restart sandbox (user changes persist automatically)
sudo systemctl restart openshell-sandbox.service
# Sidecar stays up, detects disconnect, reconnects automatically.
# Channels, skills, agents, sessions — all still there.
```

Compare to today's manual process (11+ steps with manual file editing,
user creation, iptables injection, and device pairing).

---

## Phase 4: Initialization (`defenseclaw init`)

### 4.1 Current behavior

`cmd_init.py` creates `~/.defenseclaw/`, seeds the SQLite DB, copies Rego
policies, optionally installs scanners and LiteLLM extras.

### 4.2 New: `--sandbox` flag

```
defenseclaw init --sandbox
```

Additional steps when `--sandbox` is passed:

```
1. Check Linux (fail on macOS/Windows with clear message)
2. Check openshell-sandbox binary exists (offer to install if missing)
3. Create sandbox system user:
     groupadd -r sandbox 2>/dev/null
     useradd -r -g sandbox -d /home/sandbox -m -s /bin/bash sandbox
4. Create sandbox home directories:
     /home/sandbox/.openclaw/
     /home/sandbox/.openclaw/extensions/
     /home/sandbox/.defenseclaw/
5. Install DefenseClaw plugin into sandbox home:
     cp -r <data_dir>/extensions/defenseclaw /home/sandbox/.openclaw/extensions/
     chown -R root:root /home/sandbox/.openclaw/extensions/defenseclaw
   NOTE: Only the defenseclaw plugin is managed here. Channel plugins
   (telegram, slack, etc.) are installed by the user via OpenClaw's
   own flows (openclaw channels login, GUI, TUI, or chat). See 7.7.
6. Copy default OpenShell policy files:
     cp policies/openshell/default.rego → <data_dir>/openshell-policy.rego
     cp policies/openshell/default-data.yaml → <data_dir>/openshell-policy.yaml
7. Print summary and next steps:
     "Run: defenseclaw setup sandbox --sandbox-ip ... --host-ip ..."
```

Init creates the user and directory skeleton. All configuration (config
patching, systemd units, policy generation with correct IPs/ports, device
pairing) is done by `defenseclaw setup sandbox` (Phase 5), which is
re-runnable.

### 4.3 Idempotency

All init steps must be idempotent. Running `defenseclaw init --sandbox` twice
should not create duplicate users or overwrite customized policies.

---

## Phase 5: Sandbox Setup (`defenseclaw setup sandbox`)

### 5.1 Current behavior

`cmd_setup.py` has a `setup sandbox` subcommand that sets config values
(`openshell.mode`, `gateway.host`, `guardrail.host`) and prints manual
next steps.

### 5.2 Enhanced behavior

`defenseclaw setup sandbox` should become a full orchestration command:

```
defenseclaw setup sandbox \
  --sandbox-ip 10.200.0.2 \
  --host-ip 10.200.0.1 \
  [--openclaw-port 18789] \
  [--policy strict|default|permissive] \
  [--dns 8.8.8.8,1.1.1.1]
```

Steps:

```
1. Validate prerequisites:
   - Linux OS
   - openshell-sandbox binary on PATH
   - sandbox user exists
   - OpenClaw installed (node, openclaw binary)

2. Configure DefenseClaw:
   - openshell.mode = standalone
   - openshell.sandbox_home = /home/sandbox (or --sandbox-home)
   - gateway.host = sandbox-ip
   - gateway.tls = false
   - gateway.api_bind = host-ip
   - guardrail.host = host-ip
   - claw.home_dir = <sandbox_home>/.openclaw
   - claw.config_file = <sandbox_home>/.openclaw/openclaw.json
   Setting claw.home_dir and claw.config_file makes all existing
   code (guardrail patching, codeguard skill install, skill/MCP dir
   resolution) automatically target the sandbox user's OpenClaw
   config and directories. No changes to guardrail.py or
   codeguard_skill.py needed.

3. Generate OpenShell policy:
   - Load template from <data_dir>/policies/openshell/
   - Inject correct ports (gateway.port=18789, gateway.api_port=18970,
     guardrail.port=4000)
   - Inject host/sandbox IPs
   - Write to <data_dir>/openshell-policy.yaml

4. Generate gateway auth token:
   - Generate a random 32-byte token (secrets.token_urlsafe)
   - Store in <data_dir>/config.yaml as gateway.token

5. Pre-pair the sidecar device (see 6.6):
   - Shell out to defenseclaw-gateway to load/generate device key
     and compute device ID, or read <data_dir>/device.key directly
   - Inject the device as pre-approved into the sandbox's
     <sandbox_home>/.openclaw/devices.json (see 6.6)

6. Patch sandbox-side OpenClaw config:
   - Patch <sandbox_home>/.openclaw/openclaw.json with gateway.* fields
     (see 7.7 — gateway.port, gateway.mode, gateway.bind, gateway.token)
   - Update defenseclaw plugin (copy if newer version — see 7.7)
   - Set ownership (root:root for plugin, sandbox:sandbox for config)
   - Create <sandbox_home>/.defenseclaw/config.yaml (sidecar address)
   This is Python code in cmd_setup.py, using the same read-modify-
   write pattern as guardrail.py. NOT Go code.

7. Run setup guardrail (if guardrail enabled):
   - Calls existing `_enable_guardrail()` flow which uses
     cfg.claw.config_file (now pointing at sandbox's openclaw.json)
   - Sets baseUrl to http://{host-ip}:{guardrail-port}
   - Do NOT put LiteLLM master key in sandbox config (see Phase 7)

8. Generate DNS resolv.conf:
   - Write <data_dir>/sandbox-resolv.conf with configured nameservers
   - Default: 8.8.8.8, 1.1.1.1 (override via --dns flag)

9. Generate systemd unit files and launcher scripts (see Phase 6.2, 6.3)
   - All paths hardcoded from openshell.sandbox_home and data_dir
   - Install to /etc/systemd/system/ and /usr/local/lib/defenseclaw/

10. Save config and print summary
```

Note: no `--openclaw-token` flag. The gateway auth token is auto-generated
and injected into both sides during setup. The user never sees or manages
it. The sidecar's device key (Ed25519 keypair for challenge-response auth)
is also auto-generated. Secrets stay off the command line.

### 5.3 `defenseclaw setup sandbox --disable`

Reverts to host mode:

```
1. Restore gateway.* fields in sandbox's openclaw.json (see 7.7)
2. Revert claw.home_dir → ~/.openclaw
3. Revert claw.config_file → ~/.openclaw/openclaw.json
4. Set openshell.mode = "" (empty)
5. Set gateway.host = 127.0.0.1, guardrail.host = localhost
6. Save config
7. Optionally: stop systemd services, remove unit files
```

The sandbox user and home directory are NOT deleted — the user may
want to re-enable sandbox mode later without losing OpenClaw state.

---

## Phase 6: Runtime

### 6.1 Architecture: independent processes

The sandbox and the sidecar are **independent processes** managed by
**systemd**, not by each other. Neither is the parent of the other.

```
systemd
  ├── openshell-sandbox.service   (runs as root — needs CAP_SYS_ADMIN)
  │     └── start-sandbox.sh      (bind-mount resolv.conf, exec sandbox)
  │           └── openshell-sandbox
  │                 └── openclaw  (child, privilege-dropped to sandbox user)
  │
  ├── defenseclaw-gateway.service (runs as defenseclaw user or root)
  │     └── defenseclaw-gateway run
  │           ├── Gateway client: WebSocket → sandbox IP
  │           ├── fsnotify watcher
  │           ├── REST API
  │           └── LiteLLM supervisor
  │
  └── defenseclaw-sandbox.target  (groups both for convenience)
```

**Why not parent-child?** If the sidecar supervised the sandbox:
- A sidecar restart (upgrade, crash, config change) kills the sandbox,
  disconnecting all OpenClaw users and destroying the network namespace.
- A sidecar OOM-kill sends SIGKILL (uncatchable) — the sandbox may not
  get a clean shutdown signal.

With independent processes:
- Sidecar restarts don't affect the sandbox. The sidecar reconnects via
  WebSocket when it comes back up.
- Sandbox restarts don't affect the sidecar. The sidecar detects the
  WebSocket disconnect, logs it, and retries with backoff.
- Each process has its own restart policy, resource limits, and logs.

### 6.2 systemd unit files

Generated by `defenseclaw setup sandbox` and installed to
`/etc/systemd/system/` (requires root).

#### `openshell-sandbox.service`

```ini
[Unit]
Description=OpenShell Sandbox (DefenseClaw-managed)
Documentation=https://github.com/defenseclaw/defenseclaw
After=network.target

[Service]
Type=exec
ExecStartPre=/usr/local/lib/defenseclaw/pre-sandbox.sh
ExecStart=/usr/local/lib/defenseclaw/start-sandbox.sh
ExecStartPost=/usr/local/lib/defenseclaw/post-sandbox.sh
ExecStopPost=/usr/local/lib/defenseclaw/cleanup-sandbox.sh

Restart=on-failure
RestartSec=5
RestartMaxDelaySec=60

StandardOutput=journal
StandardError=journal
SyslogIdentifier=openshell-sandbox

# openshell-sandbox needs root for namespace creation
# It drops privileges to the sandbox user internally

[Install]
WantedBy=defenseclaw-sandbox.target
```

#### `defenseclaw-gateway.service`

All paths are hardcoded at generation time by `defenseclaw setup sandbox`.

```ini
[Unit]
Description=DefenseClaw Gateway Sidecar
Documentation=https://github.com/defenseclaw/defenseclaw
After=openshell-sandbox.service
Wants=openshell-sandbox.service

[Service]
Type=exec
ExecStart=/usr/local/bin/defenseclaw-gateway run

Restart=on-failure
RestartSec=3
RestartMaxDelaySec=30

StandardOutput=journal
StandardError=journal
SyslogIdentifier=defenseclaw-gateway

# Sidecar does not need root
NoNewPrivileges=true
ProtectSystem=strict
# Paths injected by `defenseclaw setup sandbox` — absolute, no %h
#
# ReadWritePaths: host-side DefenseClaw data dir (SQLite DB, config,
#   device key, policy files, litellm config)
# ReadOnlyPaths: sandbox's OpenClaw dir (fsnotify watcher needs to
#   read skill dirs, MCP dirs, extensions, openclaw.json)
ReadWritePaths=/home/admin/.defenseclaw
ReadOnlyPaths=/home/sandbox/.openclaw
ReadOnlyPaths=/home/sandbox/.openclaw/skills
ReadOnlyPaths=/home/sandbox/.openclaw/workspace/skills
ReadOnlyPaths=/home/sandbox/.openclaw/extensions
ReadOnlyPaths=/home/sandbox/.openclaw/mcps

[Install]
WantedBy=defenseclaw-sandbox.target
```

The actual paths are injected from `data_dir` and `openshell.sandbox_home`
at generation time.

#### `defenseclaw-sandbox.target`

```ini
[Unit]
Description=DefenseClaw Sandbox (sandbox + sidecar)
Wants=openshell-sandbox.service defenseclaw-gateway.service

[Install]
WantedBy=multi-user.target
```

### 6.3 Launcher scripts

These scripts handle the namespace plumbing that doesn't fit cleanly
in systemd unit directives. Generated by `defenseclaw setup sandbox`
and installed to `/usr/local/lib/defenseclaw/`.

#### `pre-sandbox.sh` — pre-launch cleanup (ExecStartPre)

Runs as root before the sandbox starts. Cleans stale artifacts from
a previous unclean shutdown (see 7.7).

All paths are hardcoded at generation time by `defenseclaw setup sandbox`
using the configured `openshell.sandbox_home` and `data_dir`. No `$HOME`
or `~` expansion at runtime.

```bash
#!/bin/bash
set -euo pipefail

# Paths injected by `defenseclaw setup sandbox` — do not use $HOME
SANDBOX_HOME="/home/sandbox"
DEFENSECLAW_DIR="/home/admin/.defenseclaw"

# Clean orphan network namespaces from previous run
for ns in $(ip netns list 2>/dev/null | grep openshell | awk '{print $1}'); do
    ip netns delete "$ns" 2>/dev/null && echo "Cleaned orphan namespace: $ns"
done

# Clean stale veth interfaces
for veth in $(ip link show 2>/dev/null | grep -oP 'veth-h-\S+(?=@)'); do
    ip link delete "$veth" 2>/dev/null && echo "Cleaned stale veth: $veth"
done

# Clean stale lock files (only if sandbox is not running)
find "$SANDBOX_HOME/.openclaw/agents/" -name "*.lock" -delete 2>/dev/null || true

# Clean stale PID file (verify PID is not running AND is openshell-sandbox)
if [ -f "$SANDBOX_HOME/.openclaw/gateway.pid" ]; then
    pid=$(cat "$SANDBOX_HOME/.openclaw/gateway.pid")
    if ! (kill -0 "$pid" 2>/dev/null && \
          grep -q openshell "/proc/$pid/cmdline" 2>/dev/null); then
        rm -f "$SANDBOX_HOME/.openclaw/gateway.pid"
        echo "Cleaned stale PID file (pid=$pid)"
    fi
fi
```

#### `start-sandbox.sh` — sandbox launch (ExecStart)

Runs as root. Creates a private mount namespace for DNS resolution
(see 7.6), then execs openshell-sandbox. The mount namespace is
inherited by all child processes and destroyed when the process tree
exits. The host's `/etc/resolv.conf` is never modified.

All paths are hardcoded at generation time — no `$HOME` expansion.

```bash
#!/bin/bash
set -euo pipefail

# Paths injected by `defenseclaw setup sandbox`
DEFENSECLAW_DIR="/home/admin/.defenseclaw"
RESOLV_FILE="$DEFENSECLAW_DIR/sandbox-resolv.conf"
POLICY_REGO="$DEFENSECLAW_DIR/openshell-policy.rego"
POLICY_DATA="$DEFENSECLAW_DIR/openshell-policy.yaml"
SANDBOX_HOME="/home/sandbox"

exec unshare --mount -- bash -c '
    mount --bind '"$RESOLV_FILE"' /etc/resolv.conf
    exec openshell-sandbox \
        --policy-rules '"$POLICY_REGO"' \
        --policy-data '"$POLICY_DATA"' \
        --log-level info \
        --timeout 0 \
        -w '"$SANDBOX_HOME"' \
        -- '"$SANDBOX_HOME"'/start-openclaw.sh
'
```

#### `start-openclaw.sh` — OpenClaw wrapper (runs inside sandbox)

Runs inside the sandbox as the sandbox user (after privilege drop).
Handles sandbox-side environment setup before exec'ing OpenClaw:

```bash
#!/bin/bash
set -euo pipefail

# Bypass proxy for host veth IP (direct connectivity via veth pair)
export NO_PROXY="10.200.0.1${NO_PROXY:+,$NO_PROXY}"

exec openclaw gateway run
```

#### `cleanup-sandbox.sh` — post-stop cleanup (ExecStopPost)

Runs after the sandbox exits (clean or unclean):

```bash
#!/bin/bash
# openshell-sandbox cleans up its own namespace, iptables, and veth on
# clean shutdown. This script handles anything left over from unclean exits.

for ns in $(ip netns list 2>/dev/null | grep openshell | awk '{print $1}'); do
    ip netns delete "$ns" 2>/dev/null && echo "Cleaned orphan namespace: $ns"
done

for veth in $(ip link show 2>/dev/null | grep -oP 'veth-h-\S+(?=@)'); do
    ip link delete "$veth" 2>/dev/null && echo "Cleaned stale veth: $veth"
done
```

#### DNS resolv.conf — created by `defenseclaw setup sandbox`

The resolv.conf file is written once during setup and bind-mounted into
the sandbox on every start (see 7.6 for details):

```bash
# <data_dir>/sandbox-resolv.conf (e.g. /home/admin/.defenseclaw/sandbox-resolv.conf)
nameserver 8.8.8.8
nameserver 1.1.1.1
```

### 6.4 CLI convenience commands

While systemd is the primary management interface, the gateway binary
provides convenience wrappers:

#### `defenseclaw-gateway sandbox start`

```
1. Verify openshell.mode == "standalone"
2. Run: systemctl start defenseclaw-sandbox.target
3. Wait for OpenClaw health check (http://sandbox-ip:port/health)
4. Run policy diff check (see 7.7) — warn if endpoints are uncovered
5. Print status summary
```

#### `defenseclaw-gateway sandbox stop`

```
1. Run: systemctl stop defenseclaw-sandbox.target
2. Print confirmation
```

#### `defenseclaw-gateway sandbox restart`

```
1. systemctl restart openshell-sandbox.service
   (sidecar detects disconnect + reconnects automatically)
2. Wait for health check
3. Print status
```

Note: restarting the sandbox does NOT restart the sidecar. The sidecar
detects the WebSocket disconnect, retries with backoff, and reconnects
when the sandbox comes back. This is the key benefit of independent
processes — policy changes (which require a sandbox restart) don't
bounce the sidecar.

#### `defenseclaw-gateway sandbox status`

```
1. Parse systemctl status for both units (active, PID, uptime, memory)
2. Sidecar /health endpoint (includes sandbox subsystem — see below)
3. OpenClaw health (HTTP GET to sandbox IP)
4. Policy diff summary (warn if endpoints are uncovered)
```

#### Sandbox health subsystem

When `openshell.mode == "standalone"`, the sidecar registers a `Sandbox`
subsystem in `SidecarHealth` alongside the existing six (Gateway, Watcher,
API, Guardrail, Telemetry, Splunk). This is an additive, non-breaking
change — the new field appears in `/health` JSON only when sandbox mode
is enabled.

```go
// Addition to HealthSnapshot (internal/gateway/health.go)
Sandbox SubsystemHealth `json:"sandbox,omitempty"`
```

State transitions:

| State | Meaning |
|---|---|
| `disabled` | `openshell.mode` is not `"standalone"` (field omitted from JSON via `omitempty`) |
| `starting` | Sidecar is attempting initial WebSocket connection to sandbox |
| `running` | WebSocket connected, OpenClaw health check passing |
| `reconnecting` | WebSocket disconnected, retrying with backoff |
| `error` | OpenClaw health check failing despite WebSocket connection |

The sidecar updates the sandbox health state as part of its existing
WebSocket connection lifecycle — no new goroutine or polling needed.
The `Details` map includes `sandbox_ip`, `openclaw_port`, and
`last_health_check`.

#### `defenseclaw-gateway sandbox exec -- <command>`

Runs a command as the `sandbox` user on the host. The filesystem is
shared (Landlock restricts paths, doesn't create an overlay), so the
command reads/writes `<sandbox_home>/.openclaw/` directly.

```
sudo -u sandbox <command>
```

This is the primary mode. It works for all config and credential
commands (`openclaw channels login`, `openclaw onboard`, editing
config, installing skills). The host has full internet access and
DNS, so Telegram auth flows, npm installs, etc. work without
needing the sandbox's iptables holes.

Commands that need to reach the running OpenClaw gateway (e.g.,
`openclaw status`, `openclaw gateway call ...`) work because
`openclaw.json` has `gateway.bind: "lan"` — the gateway listens
on `0.0.0.0:18789` inside the namespace, reachable from the host
at `10.200.0.2:18789` via the veth pair.

All changes persist in `<sandbox_home>/` and survive sandbox restarts.

#### `defenseclaw-gateway sandbox exec --netns -- <command>`

Falls back to running inside the sandbox's network namespace. Use
this for troubleshooting the sandbox network (testing DNS, checking
iptables rules, verifying connectivity from the sandbox's perspective).

```
1. Find the sandbox network namespace:
     NS=$(ip netns list | grep openshell | awk '{print $1}' | head -1)
2. Run inside the namespace as the sandbox user:
     ip netns exec "$NS" sudo -u sandbox <command>
```

Requires root. Only enters the network namespace (not the mount
namespace), so the command sees the host's `/etc/resolv.conf` rather
than the sandbox's bind-mounted version. For full DNS fidelity,
use `sandbox shell --netns` and manually check
`<data_dir>/sandbox-resolv.conf`.

#### `defenseclaw-gateway sandbox shell`

```
defenseclaw-gateway sandbox exec -- bash
```

Interactive shell as the `sandbox` user. Runs on the host (default)
or inside the namespace (`--netns`).

### 6.5 Post-launch iptables injection

After the sandbox's network namespace is created, iptables rules must be
injected to allow the sandbox to reach host services. This runs as part
of the **sandbox service** (not the sidecar), via `ExecStartPost=` in
the systemd unit. Since `openshell-sandbox.service` runs as root, the
post-launch script also runs as root — no privilege escalation needed.

Add to `openshell-sandbox.service`:

```ini
ExecStartPost=/usr/local/lib/defenseclaw/post-sandbox.sh
```

#### `post-sandbox.sh`

```bash
#!/bin/bash
set -euo pipefail

# Paths injected by `defenseclaw setup sandbox`
DEFENSECLAW_DIR="/home/admin/.defenseclaw"
HOST_IP="10.200.0.1"
API_PORT=18970
GUARDRAIL_PORT=4000

# Wait for veth pair creation (openshell-sandbox needs a moment to set up
# the network namespace). Timeout after 30 seconds.
for i in $(seq 1 30); do
    if ip addr show | grep -q "$HOST_IP"; then
        break
    fi
    sleep 1
done

if ! ip addr show | grep -q "$HOST_IP"; then
    echo "ERROR: veth pair not created after 30s" >&2
    exit 1
fi

# Find the sandbox network namespace
NS=$(ip netns list 2>/dev/null | grep openshell | awk '{print $1}' | head -1)
if [ -z "$NS" ]; then
    echo "ERROR: sandbox namespace not found" >&2
    exit 1
fi

# Inject iptables rules into sandbox namespace
# NOTE: these are required until proxy integration (7.1) is done
# DNS: only allow the specific nameservers from sandbox-resolv.conf
for ns in $(grep '^nameserver' "$DEFENSECLAW_DIR/sandbox-resolv.conf" | awk '{print $2}'); do
    ip netns exec "$NS" iptables -I OUTPUT 1 -p udp -d "$ns" --dport 53 -j ACCEPT
done

ip netns exec "$NS" iptables -I OUTPUT 1 -p tcp -d "$HOST_IP" --dport "$API_PORT" -j ACCEPT
ip netns exec "$NS" iptables -I OUTPUT 1 -p tcp -d "$HOST_IP" --dport "$GUARDRAIL_PORT" -j ACCEPT

echo "Injected iptables rules into namespace $NS"
```

**Why not in the sidecar?** The sidecar is an unprivileged process
(`NoNewPrivileges=true` in its systemd unit). iptables injection
requires root or `CAP_NET_ADMIN`. By running it in the sandbox
service's `ExecStartPost=`, we keep the sidecar fully unprivileged
and avoid giving it any namespace or network capabilities.

**On sandbox restart:** systemd stops the sandbox (destroying the
namespace and all its iptables rules), then starts it again.
`ExecStartPost=` re-runs automatically, re-injecting the rules.

### 6.6 Device pairing

OpenClaw requires device pairing for WebSocket connections. DefenseClaw
supports two modes, controlled by the `gateway.auto_pair` config field:

| `gateway.auto_pair` | Behavior |
|---|---|
| `true` (default) | `defenseclaw setup sandbox` pre-injects the sidecar's device key into the sandbox's `devices.json`. The sidecar connects immediately on first start — no manual approval step. |
| `false` | The device key is NOT pre-injected. The operator must manually approve the sidecar's pairing request via OpenClaw's UI, CLI, or chat the first time. |

In both modes, the pairing is **persistent**. Once paired (whether
pre-injected or manually approved), the device entry lives in
`<sandbox_home>/.openclaw/devices.json` on the host filesystem. It
survives sandbox restarts. Pairing is a one-time event, not repeated
on every start.

#### Pre-pairing (auto_pair=true, default)

`defenseclaw setup sandbox` (Phase 5.2, step 5):

```
1. Load or generate the sidecar's Ed25519 device key
   (<data_dir>/device.key — same key used by LoadOrCreateIdentity)
2. Compute the device ID (fingerprint of the public key)
3. Merge the device into <sandbox_home>/.openclaw/devices.json:
   - Read existing devices.json (preserve any manually paired devices)
   - Append or update the entry matching this device ID:
     {
       "deviceId": "<fingerprint>",
       "publicKey": "<base64url-encoded-public-key>",
       "name": "defenseclaw-sidecar",
       "status": "approved",
       "approvedAt": "<ISO-8601-timestamp>"
     }
   - Write back, preserving all other entries
4. Set ownership: sandbox:sandbox (OpenClaw needs to read it)
```

When the sidecar connects via WebSocket, OpenClaw recognizes the device
key and accepts the connection immediately — no pairing request, no
approval flow, no nsenter.

#### Manual pairing (auto_pair=false)

For environments that require explicit approval of all device
connections:

```bash
defenseclaw setup sandbox --no-auto-pair
```

On first sidecar start, the sidecar connects and receives `NOT_PAIRED`.
It logs a message with the device ID and waits. The operator approves
via OpenClaw:

```bash
defenseclaw-gateway sandbox exec -- \
  openclaw gateway call device.pair.approve --params '{"requestId":"..."}'
```

Or via OpenClaw's GUI/TUI. Once approved, the pairing is persisted in
`<sandbox_home>/.openclaw/devices.json` and subsequent restarts connect
immediately.

#### Why pre-pairing is the default

- **No root needed by the sidecar at runtime.** The sidecar connects
  via WebSocket as an unprivileged process.
- **No race condition.** The device is already approved when the sandbox
  starts. No window where the sidecar is rejected and must retry.
- **Auditable.** The device was paired during a deliberate setup step.
  The audit log records the setup event.

#### Re-keying

If the device key is rotated (`rm <data_dir>/device.key`), re-run
`defenseclaw setup sandbox` to inject the new key into `devices.json`.
The old device entry is replaced (matched by device ID).

---

## Phase 7: Security Hardening

These items come from `sandbox-security-analysis.md`. Each one should be
a tracked work item.

### 7.1 Proxy integration (eliminate iptables bypass)

**Priority: P2 (future improvement)**

The current production architecture uses iptables rules injected via
`ExecStartPost=` (Phase 6.5) to allow the sandbox to reach the sidecar
API, LiteLLM, and DNS. This is acceptable for production because:

- The rules are scoped to specific host:port pairs, not blanket allows
- The sidecar API is bound to the veth IP (7.5), not 0.0.0.0
- The sidecar API has authentication (7.2)
- The iptables rules are injected by a root-owned systemd script, not
  by the sidecar

A future improvement is to integrate with OpenShell's internal proxy
to eliminate iptables rules entirely:

```
Sandbox → OpenShell proxy (3128) → DefenseClaw proxy (host) → internet
```

This requires OpenShell to support configuring an upstream proxy
(`--upstream-proxy` or similar). If/when NVIDIA adds this, DefenseClaw
can start an HTTP CONNECT proxy on the host and route all sandbox
traffic through it. This is a cleaner architecture but not a security
blocker — the current iptables approach is production-grade.

### 7.2 Sidecar API authentication

**Priority: P0**

Replace the `X-DefenseClaw-Client` header with real authentication:

```
Option A: Shared secret (simple)
  - defenseclaw setup sandbox generates a random token
  - Stored in <sandbox_home>/.defenseclaw/config.yaml (sandbox side)
  - Stored in <data_dir>/config.yaml (host side)
  - Plugin sends token in Authorization header
  - Sidecar validates on every request

Option B: mTLS (stronger)
  - defenseclaw setup sandbox generates a CA, server cert, client cert
  - Server cert for sidecar API (host)
  - Client cert for plugin (sandbox)
  - Stored in <data_dir>/tls/ (CA + server) and
    <sandbox_home>/.defenseclaw/tls/ (client)
  - Standard Go net/http TLS client auth
```

Recommendation: Start with Option A (shared secret). It's sufficient for
a local veth pair and matches OpenClaw's own token-based auth model. Add
mTLS as an option for hardened deployments.

### 7.3 Remove LiteLLM master key from sandbox

**Status: Will not implement.**

The LiteLLM master key stays in the sandbox. The existing guardrail
pipeline already intercepts and inspects all LLM traffic via the
sidecar WebSocket, so adding a separate HTTP reverse-proxy endpoint
would duplicate routing without meaningful security gain. The sandbox
network policy restricts outbound traffic to the configured LiteLLM
host only; the key cannot be exfiltrated to arbitrary endpoints.

### 7.4 Plugin signing

**Priority: P2**

Replace the `chown root:root` ownership hack:

```
1. defenseclaw setup sandbox generates an Ed25519 keypair
   - Private key: <data_dir>/plugin-signing.key (mode 0600)
   - Public key: <sandbox_home>/.defenseclaw/plugin-verify.pub

2. make plugin-install signs the plugin:
   - Compute SHA-256 of dist/index.js
   - Sign with private key
   - Write signature to dist/index.js.sig

3. Plugin loader in OpenClaw (or DefenseClaw wrapper) verifies:
   - Read public key from <sandbox_home>/.defenseclaw/plugin-verify.pub
   - Verify dist/index.js.sig against dist/index.js
   - Reject if signature is missing or invalid
```

This requires either:
- OpenClaw to support a plugin verification hook (feature request)
- DefenseClaw to wrap the plugin loading (shim that verifies then loads)

### 7.5 API bind to veth IP only

**Priority: P0 (quick fix)**

Change the default `api_bind` for standalone mode from `0.0.0.0` to
the host veth IP:

```go
// internal/gateway/sidecar.go
bind := "127.0.0.1"
if s.cfg.Gateway.APIBind != "" {
    bind = s.cfg.Gateway.APIBind
} else if s.cfg.OpenShell.IsStandalone() {
    bind = s.cfg.Gateway.Host  // Use the sandbox IP? No — use host IP
    // Need a config field for the host-side veth IP
}
```

Better: `defenseclaw setup sandbox --host-ip 10.200.0.1` already stores
this in `guardrail.host`. Use that as the default API bind in standalone
mode.

### 7.6 DNS resolution in the sandbox

**Priority: P0**

The openshell-sandbox network namespace has no DNS resolver. The sandbox
inherits the host's `/etc/resolv.conf` (pointing at Docker's or the host's
DNS server), but the sandbox namespace's iptables rules block all traffic
except connections to the proxy at `10.200.0.1:3128`. DNS queries (UDP
port 53) to external resolvers are silently dropped.

This breaks any Node.js application inside the sandbox, because Node.js
resolves hostnames via `getaddrinfo()` before connecting — unlike `curl -x`
which delegates DNS to the proxy via HTTP CONNECT.

**Impact**: Without DNS, OpenClaw cannot initialize Telegram (or any
external channel), cannot fetch model pricing, and cannot reach any
hostname-based service. LiteLLM at `http://10.200.0.1:4000` works only
because it's an IP address, not a hostname.

#### Solution: DNS passthrough with bind-mount

No DNS forwarder process (dnsmasq, socat, embedded Go) is needed.
Instead, the sandbox gets its own `/etc/resolv.conf` pointing at
public DNS resolvers, and iptables rules allow UDP 53 outbound.

**Two pieces:**

1. **Bind-mount** — `start-sandbox.sh` (see Phase 6.3) creates a
   private mount namespace via `unshare --mount` and bind-mounts
   `<data_dir>/sandbox-resolv.conf` over `/etc/resolv.conf`.
   The host's resolv.conf is never modified. The mount namespace is
   inherited by all child processes and destroyed when the sandbox
   process tree exits.

2. **iptables allow rule** — `post-sandbox.sh` (Phase 6.5) injects
   UDP 53 allow rules scoped to the specific nameservers listed in
   `sandbox-resolv.conf` (not a blanket UDP 53 allow).

#### Setup

`defenseclaw setup sandbox` creates the resolv.conf file:

```bash
# <data_dir>/sandbox-resolv.conf
nameserver 8.8.8.8
nameserver 1.1.1.1
```

The nameservers default to `8.8.8.8` and `1.1.1.1` (Google and
Cloudflare public DNS). Operators can override via:

```bash
defenseclaw setup sandbox --dns 10.0.0.2,10.0.0.3
```

Using the host's upstream resolver (parsed from the host's
`/etc/resolv.conf` before the bind mount) is also supported:

```bash
defenseclaw setup sandbox --dns host
```

#### Trade-off: DNS exfiltration

UDP 53 is only allowed to the specific nameservers configured in
`sandbox-resolv.conf` (default: `8.8.8.8`, `1.1.1.1`). A compromised
process cannot send DNS queries to arbitrary servers, which limits
DNS tunneling to abusing the configured resolvers. This is a minor
residual risk:

- The sandbox already allows HTTPS to several endpoints (channels, npm).
  HTTPS exfiltration is far more efficient than DNS tunneling.
- DNS exfiltration via public resolvers is low-bandwidth and noisy —
  detectable via DNS query logging if needed.

If DNS exfiltration is a concern for a specific deployment, operators can
point `--dns` at an internal resolver with query logging enabled.

### 7.7 Sandbox state persistence

**Priority: P0**

The sandbox runs inside an `openshell-sandbox` process that creates Linux
namespaces (network, mount). When the sandbox stops and restarts, the
network namespace is destroyed and recreated — but the filesystem at
`<sandbox_home>/` is persistent on the host. This means user state
survives restarts *by default*, but only if DefenseClaw doesn't clobber it.

#### Design principle: DefenseClaw never automates OpenClaw user flows

Users must be able to interact with OpenClaw directly — via the GUI,
TUI, CLI, or by chatting with the agent — to run onboarding, configure
channels (`openclaw channels login`), manage skills, pair devices, etc.
DefenseClaw must not replicate, wrap, or automate any of these flows.
DefenseClaw only manages its own config, its own plugin, network policy,
and guardrail setup.

#### State ownership model

(Paths relative to `openshell.sandbox_home`, default `/home/sandbox`)

```
<sandbox_home>/
  .openclaw/
    openclaw.json          ← SHARED (user + DefenseClaw patch)
    agents/                ← USER-OWNED (OpenClaw manages entirely)
    extensions/
      defenseclaw/         ← DEFENSECLAW-OWNED (we install + update)
      telegram/            ← USER-OWNED (installed by openclaw channels login)
      */                   ← USER-OWNED
    skills/                ← USER-OWNED
    workspace/             ← USER-OWNED
    gateway.json           ← USER-OWNED (OpenClaw gateway state)
    devices.json           ← USER-OWNED (OpenClaw pairing state)
  .defenseclaw/
    config.yaml            ← DEFENSECLAW-OWNED
    plugin-verify.pub      ← DEFENSECLAW-OWNED
```

Rules:
- **DEFENSECLAW-OWNED** files may be overwritten on setup/start
- **USER-OWNED** files are never touched by DefenseClaw
- **SHARED** files use patch/merge semantics (see below)

#### `openclaw.json` patch and restore

DefenseClaw already patches `openclaw.json` via existing code:

- **`guardrail.py:patch_openclaw_config()`** — sets `models.providers.litellm`,
  `agents.defaults.model.primary`, appends `"defenseclaw"` to `plugins.allow`
- **`guardrail.py:restore_openclaw_config()`** — removes the above
- **`codeguard_skill.py:_enable_codeguard_in_openclaw()`** — sets
  `skills.entries.codeguard = {enabled: true}`

This existing code is unchanged. The sandbox setup adds **only the
gateway-specific fields** on top, using the same read-modify-write
pattern.

#### Sandbox-specific fields (new code)

These fields are set by `defenseclaw setup sandbox` and restored by
`defenseclaw setup sandbox --disable`. They configure OpenClaw's
gateway to be reachable from the host via the veth pair.

| JSON path | Patch operation | Value | Why |
|---|---|---|---|
| `gateway.mode` | **set key** | `"local"` | OpenClaw gateway runs in local mode (no cloud gateway). |
| `gateway.port` | **set key** | configured port (e.g., `18789`) | OpenClaw gateway listens on this port inside the sandbox. |
| `gateway.bind` | **set key** | `"lan"` | Binds to `0.0.0.0` instead of `127.0.0.1`. Required because the sidecar connects from the host via the veth pair IP — localhost inside the namespace is not reachable from the host. |
| `gateway.token` | **set key** | auto-generated token | Auth token for WebSocket connections. Auto-generated during setup (Phase 5.2 step 4). |

Restore (on `--disable`):

| JSON path | Restore operation |
|---|---|
| `gateway.mode` | **delete key** (revert to OpenClaw default) |
| `gateway.port` | **delete key** |
| `gateway.bind` | **delete key** |
| `gateway.token` | **delete key** |

#### Existing fields (no code changes)

For reference, these are already handled by existing code and are
**not modified** by the sandbox work:

| JSON path | Managed by | Operation |
|---|---|---|
| `models.providers.litellm` | `guardrail.py:patch_openclaw_config()` | replace key |
| `agents.defaults.model.primary` | `guardrail.py:patch_openclaw_config()` | overwrite scalar |
| `plugins.allow[]` | `guardrail.py:patch_openclaw_config()` | append `"defenseclaw"` |
| `skills.entries.codeguard` | `codeguard_skill.py` | set if not already enabled |

The guardrail patching runs separately via `defenseclaw setup guardrail`.
In sandbox mode, the only difference is that `litellm_host` is set to
the host bridge IP (e.g., `10.200.0.1`) instead of `localhost` — this
is already supported by the existing `litellm_host` parameter.

#### What is never touched

Everything else in `openclaw.json` is user-owned:

- `channels.*` — user-configured (Telegram, Slack, Discord, etc.)
- `models.providers.*` (other than `litellm`) — user-configured
- `plugins.allow[]` (other than `"defenseclaw"`) — user-configured
- `agents.*` (other than `agents.defaults.model.primary`) — user-configured
- `mcp.*` — user-configured (read-only by DefenseClaw for inventory)
- `skills.*` (other than `skills.entries.codeguard`) — user-configured
- All other top-level keys — user-configured

#### Implementation

The sandbox-specific gateway patching is in **Python** (`cmd_setup.py`),
because `defenseclaw setup sandbox` is a Python CLI command. It uses the
same read-modify-write JSON pattern as `guardrail.py`.

```python
# cli/defenseclaw/commands/cmd_setup.py (in setup_sandbox)

def _patch_openclaw_gateway(openclaw_config: str, port: int, token: str) -> bool:
    """Patch gateway.* fields into openclaw.json for sandbox mode."""
    path = os.path.expanduser(openclaw_config)
    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False

    gw = cfg.setdefault("gateway", {})
    gw["mode"] = "local"
    gw["port"] = port
    gw["bind"] = "lan"
    gw["token"] = token

    with open(path, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return True


def _restore_openclaw_gateway(openclaw_config: str) -> bool:
    """Remove gateway.* fields from openclaw.json."""
    path = os.path.expanduser(openclaw_config)
    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False

    gw = cfg.get("gateway", {})
    for key in ("mode", "port", "bind", "token"):
        gw.pop(key, None)

    with open(path, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return True
```

#### Existing Go sandbox code (`internal/sandbox/`)

The existing Go code in `internal/sandbox/network_policy.go` handles
**runtime** policy manipulation by the sidecar (Go binary):

- `ParseOpenShellPolicy` — parses OpenShell YAML policy
- `RemoveEndpointsByHost` — removes a blocked MCP server's network
  access from the policy at runtime
- `HasEndpointForHost` — checks if a host is covered by policy
- `ParseMCPEndpoint` — extracts host:port from MCP endpoint URLs
- `StripPolicyHeader` — strips metadata from `openshell policy get` output

This code is properly in Go because it runs inside the sidecar process
when the watcher detects and blocks an MCP server. It is NOT setup code
and is not modified by this plan.

#### Stale runtime artifact cleanup

When a sandbox exits uncleanly (kill -9, host reboot, OOM), it can leave
behind artifacts that prevent the next startup from succeeding:

| Artifact | Location | Impact |
|----------|----------|--------|
| Orphan network namespaces | `ip netns list` | New sandbox can't create its namespace |
| Stale veth interfaces | `veth-h-*` on host | Route confusion — traffic goes to wrong namespace |
| Session lock files | `.openclaw/agents/*/sessions/*.lock` | `session file locked (timeout 10000ms)` |
| Gateway PID file | `.openclaw/gateway.pid` | Port-in-use or stale process detection |
| SQLite WAL/SHM | `.openclaw/**/*.db-wal`, `*.db-shm` | Usually harmless (auto-recovered), but can block if corrupted |

This cleanup runs via `pre-sandbox.sh` (ExecStartPre) before every
sandbox start:

```
1. Check if the previous sandbox process is actually running:
   - Read PID from gateway.pid
   - Verify PID is alive (kill -0) AND /proc/$PID/cmdline contains
     "openshell" (guards against PID reuse by an unrelated process)
   - If both checks pass, the sandbox is still running — skip cleanup
2. If not running, clean up:
   a. Delete all orphan network namespaces (ip netns delete)
   b. Delete stale veth-h-* interfaces
   c. Remove all .lock files under <sandbox_home>/.openclaw/agents/
   d. Remove gateway.pid if present
   e. Leave .db-wal/.db-shm (SQLite recovers these automatically)
3. Log each removed artifact
```

#### DefenseClaw plugin updates

When DefenseClaw is upgraded, the plugin at
`<sandbox_home>/.openclaw/extensions/defenseclaw/` may need updating.
On `sandbox start`:

```
1. Compare version of installed plugin vs bundled plugin
   (read package.json version from both locations)
2. If bundled is newer:
   a. Back up existing to extensions/defenseclaw.bak/
   b. Copy bundled version in
   c. Set ownership (root:root)
   d. Log the upgrade
3. If same version, skip
```

#### Network policy diff detection

OpenShell network policy is only applied when the sandbox starts. When
the user adds a channel (e.g., Telegram) or configures a new LLM
provider via OpenClaw's UI/CLI/chat, the OpenShell policy may not cover
the new endpoints. The sandbox must be restarted with an updated policy.

DefenseClaw does NOT auto-modify the policy. Instead, it provides a
diff tool that shows what's missing, and the user updates the policy
file manually.

**Default policy template**: Ships with broad wildcards for well-known
services (OpenAI, Anthropic, Google, Telegram, Slack, Discord). All
endpoints include `tls: skip`. This covers the common case without
any user intervention.

**Policy diff command**:

```bash
defenseclaw-gateway sandbox policy diff
```

This command:

```
1. Read <sandbox_home>/.openclaw/openclaw.json (via cfg.claw.config_file)
2. Extract endpoints required by configured channels and providers:
   - channels.telegram → *.telegram.org:443
   - models.providers.*.baseUrl → parse host:port
   - Any other channel type → known endpoint map
3. Read active policy <data_dir>/openshell-policy.yaml
4. Compare: for each required endpoint, check if a matching
   network_policy entry exists (exact host or wildcard match)
5. Print diff:

   Policy coverage:
     ✓ **.telegram.org:443        (allow_channels)
     ✓ **.slack.com:443           (allow_channels)
     ✗ gateway.discord.gg:443    (not in policy)
     ✗ mcp.example.com:8443      (not in policy)

   2 endpoints missing from active policy.
   Edit <data_dir>/openshell-policy.yaml and run:
     sudo systemctl restart openshell-sandbox.service
```

**Known endpoint map** (built into DefenseClaw):

```go
// internal/sandbox/endpoints.go
var knownChannelEndpoints = map[string][]Endpoint{
    "telegram": {{Host: "**.telegram.org", Port: 443}},
    "slack":    {{Host: "**.slack.com", Port: 443},
                 {Host: "hooks.slack.com", Port: 443}},
    "discord":  {{Host: "**.discord.com", Port: 443},
                 {Host: "gateway.discord.gg", Port: 443}},
}
```

This map is purely informational — it drives the diff output, not
the policy itself. The user is always in control of the policy file.

**Integration with `sandbox status`**: The `sandbox status` command
runs a lightweight version of the diff check and prints a warning if
there are uncovered endpoints, pointing the user to `sandbox policy diff`.

#### User-interactive sandbox access

Users run commands as the `sandbox` user on the host (see Phase 6.4):

```bash
defenseclaw-gateway sandbox exec -- openclaw channels login --channel telegram
defenseclaw-gateway sandbox exec -- openclaw status
defenseclaw-gateway sandbox shell   # interactive shell as sandbox user
```

These commands run via `sudo -u sandbox` on the host. The filesystem
is shared (Landlock restricts, doesn't overlay), so the command
reads/writes `<sandbox_home>/.openclaw/` directly. All changes
persist and survive sandbox restarts. For network troubleshooting,
use `--netns` to enter the sandbox's network namespace.

### 7.8 TLS override safety

**Priority: P2**

The `tls: false` override should require standalone mode to be active:

```go
func (g *GatewayConfig) RequiresTLS() bool {
    if g.TLS != nil {
        return *g.TLS
    }
    // In standalone mode, veth is point-to-point — TLS not needed
    // Outside standalone mode, non-loopback hosts require TLS
    switch g.Host {
    case "", "127.0.0.1", "localhost", "::1", "[::1]":
        return false
    default:
        return true
    }
}
```

When `openshell.mode == "standalone"`, auto-detect that TLS is not needed
for the veth pair IP, removing the need for an explicit `tls: false` at all.

---

## Phase 8: Testing

### 8.1 Unit tests

- `internal/sandbox/install_test.go` — binary download, checksum verification
- `internal/sandbox/standalone_test.go` — policy generation, command building
- `internal/sandbox/network_policy_test.go` — policy YAML parsing, endpoint matching
- `internal/gateway/sidecar_test.go` — api_bind behavior
- `internal/gateway/health_test.go` — sandbox subsystem health state transitions
- `internal/config/config_test.go` — standalone mode detection, TLS defaults, auto_pair

All unit tests run without privileged access. Policy generation,
config merging, health tracking, and command building are all testable
with mocks or temp directories.

### 8.2 Integration tests (CI)

Integration tests that exercise the full sandbox lifecycle require
Linux namespaces (privileged). These are **excluded from the standard
CI pipeline** and run only on a dedicated Linux host or manually.

Standard CI runs all unit tests, Go/Python/TS linting, and non-sandbox
integration tests:

```yaml
# .github/workflows/test.yml (existing, no changes needed)
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: make build
      - name: Test
        run: make test          # unit tests only, no privileged ops
      - name: Lint
        run: make lint
```

Sandbox-specific integration tests run on a self-hosted runner or
manually on a Linux VM:

```bash
# Manual sandbox integration test (requires root on Linux)
sudo make sandbox-test
# Tests:
# 1. defenseclaw init --sandbox (user creation, config, policy)
# 2. defenseclaw setup sandbox (full setup, systemd unit generation)
# 3. systemctl start defenseclaw-sandbox.target
# 4. sidecar connects to sandbox OpenClaw
# 5. tool inspection from sandbox network
# 6. guardrail LLM interception (mocked)
# 7. systemctl stop defenseclaw-sandbox.target + cleanup verification
```

### 8.3 Manual test checklist

```
□ Clean Linux host
□ defenseclaw init --sandbox completes without errors
□ defenseclaw setup sandbox configures all components
□ defenseclaw setup guardrail patches sandbox-side config
□ systemctl start defenseclaw-sandbox.target starts both services
□ OpenClaw healthy inside sandbox (GET /health via sandbox IP)
□ Sidecar /health shows sandbox subsystem as "running"
□ Device pre-paired (sidecar connects without manual approval)
□ Tool inspection works from sandbox (safe + dangerous)
□ LLM guardrail intercepts prompts (observe + action mode)
□ Watcher detects new skills in sandbox directories
□ User configures Telegram via sandbox exec (sudo -u sandbox openclaw channels login)
□ Telegram works end-to-end through sandbox
□ systemctl stop defenseclaw-sandbox.target cleans up cleanly
□ Re-start after stop works (idempotent, pairing persists)
□ User config survives restart (channels, skills, agents preserved)
□ openclaw.json not clobbered (user channels + DC plugin both present)
□ Stale artifacts cleaned on restart after kill -9 (locks, namespaces, veths)
□ sandbox policy diff detects missing endpoints after channel add
□ User edits policy + systemctl restart openshell-sandbox applies new policy
□ --no-auto-pair mode: manual pairing via sandbox exec works
```

---

## Phase 9: Documentation

### 9.1 User-facing docs

- `docs/SANDBOX.md` — end-to-end guide for sandbox mode
- `docs/QUICKSTART.md` — add sandbox quick-start section
- `docs/CONFIG_FILES.md` — document new config fields (`api_bind`,
  `openshell.version`, `openshell.sandbox_home`, `gateway.auto_pair`,
  standalone-mode defaults including `claw.home_dir` override)

### 9.2 Architecture docs

- Update `docs/design/openshell-standalone-sandbox.md` with production
  architecture (proxy chain, auth, no iptables bypass)
- Update `docs/design/sandbox-security-analysis.md` as hardening items
  are completed

---

## Implementation Order

| Priority | Item | Phase | Effort |
|----------|------|-------|--------|
| P0 | API bind to veth IP (not 0.0.0.0) | 7.5 | S |
| P0 | Sidecar API authentication (shared secret) | 7.2 | M |
| ~P0~ | ~Remove LiteLLM key from sandbox (sidecar LLM proxy)~ | ~7.3~ | ~Will not implement~ |
| P2 | Proxy integration (eliminate iptables bypass) | 7.1 | L |
| P0 | DNS passthrough with bind-mount | 7.6 | S |
| P0 | Sandbox state persistence (merge strategy + cleanup) | 7.7 | M |
| P1 | OpenShell binary download/install | 1 | M |
| P1 | `defenseclaw init --sandbox` automation | 4 | M |
| P1 | `defenseclaw setup sandbox` full orchestration (+ systemd units) | 5, 6 | L |
| P1 | systemd unit files + launcher scripts | 6.2, 6.3 | M |
| P1 | CLI convenience wrappers (`sandbox start/stop/status/exec`) | 6.4 | M |
| P1 | Post-launch iptables injection (sandbox ExecStartPost) | 6.5 | S |
| P1 | Device pairing (pre-pair default + manual option) | 6.6 | S |
| P1 | Sandbox health subsystem in /health | 6.4 | S |
| P1 | Policy templates (Rego + YAML, `tls: skip` on all endpoints) | 2.4 | M |
| P1 | Plugin + guardrail bundling in releases | 2.2, 2.3 | M |
| P2 | Plugin signing | 7.4 | M |
| P1 | Network policy diff tool (`sandbox policy diff`) | 7.7 | M |
| P1 | `sandbox exec` / `sandbox shell` (host-mode + `--netns` fallback) | 6.4 | S |
| P1 | install.sh unified installer | 3.1 | M |
| P2 | TLS override safety | 7.8 | S |
| Future | goreleaser binary rename | 2.1 | S |
| Future | Homebrew formula updates | 3.2 | S |
| P2 | CI: sandbox integration tests (manual/self-hosted, not standard CI) | 8.2 | L |
| P2 | Documentation | 9 | M |

**S** = small (< 1 day), **M** = medium (1–3 days), **L** = large (3–5 days)

Total estimated effort: ~6–8 weeks for one engineer, or ~3–4 weeks with
two engineers splitting security hardening (P0) and CLI automation (P1).
