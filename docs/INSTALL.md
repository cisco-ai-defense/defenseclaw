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

### Windows support

On **Windows**, DefenseClaw is **hook-only**. The hook-based connectors —
Claude Code, Codex, Hermes, Cursor, Windsurf, Gemini CLI, Copilot CLI, and
OpenHands — are fully supported. Their hook decisions run **natively in the
`defenseclaw-gateway` binary** (the agent invokes `defenseclaw-gateway hook --connector <name>
--event <event>`), so Windows needs **no Git Bash, no `jq`, and no shell
shims** — there are zero external prerequisites beyond the binary itself.

The proxy connectors **OpenClaw** and **ZeptoClaw** are **not supported on
Windows**: they require the local guardrail proxy, which DefenseClaw does not
host there. They are hidden from the TUI/CLI connector pickers and rejected by
setup on Windows with a clear error. Use them on macOS or Linux instead.

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

Cosign is not a POSIX release-install prerequisite from `0.8.5` onward. The
release installer prefers an existing binary and otherwise authenticates a
pinned, temporary Cosign `2.6.3` against a hard-coded platform SHA-256. The
temporary verifier is never added to `PATH` or installed system-wide.

---

## Building from Source

This section covers developer builds from the repository. Source targets and
`scripts/install-dev.sh` are not an alternate upgrade mechanism: direct install
targets refuse to overwrite a release-managed installation or one owned by
another checkout before changing installed entry points or the gateway.
`make all` is the explicit developer-machine reinstall workflow. When the
installed CLI already points exactly into the current checkout, it may reclaim
markerless or prior-release source state and records a strict ownership marker
after rebuilding. That workflow can run the checkout's current migrations
against developer state and must not be used on a release-managed host. The
release-owned resolver is for release-managed layouts; it must not be presented
as recovery for a source venv.

### Prerequisites

| Tool | Minimum | Check | Install |
|------|---------|-------|---------|
| Go | 1.26.4+ | `go version` | [go.dev/dl](https://go.dev/dl/) or `brew install go` |
| Python | 3.10+ (3.12 recommended) | `python3 --version` | System package manager or [python.org](https://python.org) |
| uv | latest | `uv --version` | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Node.js / npm | 18+ | `node --version` | [nodejs.org](https://nodejs.org) or `brew install node` |
| Git | any | `git --version` | System package manager |

Python 3.11+ is recommended if you need the MCP scanner
(`cisco-ai-mcp-scanner` has a `python_version >= "3.11"` gate).

### Clone and Build Everything

```bash
git clone https://github.com/cisco-ai-defense/defenseclaw.git
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
target locations after the source-install ownership preflight:

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

The `make dist` target builds unsigned inputs for the protected release
workflow. It is useful for development inspection and release preparation, but
it is not a publishable or authenticated `0.8.4+` release candidate by itself.

### Produce All Artifacts

```bash
make dist
```

This runs `dist-cli`, `dist-gateway`, `dist-plugin`, `dist-sandbox`,
`dist-upgrade-manifest`, and `dist-checksums` in sequence. Output goes to `dist/`:

```
dist/
├── defenseclaw-0.8.4-py3-none-any.whl       # unsigned Python CLI input
├── defenseclaw-gateway-linux-amd64           # Gateway binary (linux/amd64)
├── defenseclaw-gateway-linux-arm64           # Gateway binary (linux/arm64)
├── defenseclaw-gateway-darwin-amd64          # Gateway binary (macOS Intel)
├── defenseclaw-gateway-darwin-arm64          # Gateway binary (macOS Apple Silicon)
├── defenseclaw-plugin-0.8.4.tar.gz           # OpenClaw plugin tarball
├── upgrade-manifest.json                     # reviewed transition policy
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

### Test Local Development or Release Assets

For a source-owned development installation, use the source workflow:

```bash
make install
```

Do not pass the unsigned output of `make dist` to `install.sh --local` or
`install.ps1 -Local` for `0.8.4+`. Those entry points require a complete
release-owned asset set: signed checksums and certificate, schema-2 manifest,
and protected `.dcwheel`/`.dcgateway` payloads. This refusal is intentional;
otherwise a local directory could bypass release provenance and bridge policy.

`--local` remains useful for testing a complete authenticated release-asset
directory. It is fresh-install-only and refuses any existing or partial
installation before dependency or artifact changes.

### Cut a GitHub Release

The manually dispatched `Release` GitHub Actions workflow is the only supported
way to cut a release. It validates the requested version, builds and signs all
artifacts, runs the native upgrade gates, and creates the remote tag and GitHub
release together only after protected release approval. This ordering keeps
Immutable Releases from stranding half-built assets.

Preferred — from the Actions UI:

```
Actions -> Release -> Run workflow -> version: 0.4.0
```

Or dispatch the same workflow with GitHub CLI:

```bash
gh workflow run release.yaml --ref main -f version=0.4.0
```

Do not create or push the tag yourself. The workflow must retain exclusive
ownership of that namespace until its tested candidate is approved and
published.

> The version MUST be bare `X.Y.Z` with no `v` prefix. `scripts/install.sh`,
> `scripts/upgrade.sh`, and `defenseclaw upgrade` all build URLs of the
> form `releases/download/X.Y.Z/...`, and the workflow rejects any tag
> that doesn't match `^[0-9]+\.[0-9]+\.[0-9]+$`.

Do NOT manually `gh release create` — it would create an empty Immutable
Release that the workflow can't attach assets to (this is what broke the
0.3.1 release).

### Clean Dist

```bash
make dist-clean   # Remove dist/ and bundled _data/
make clean        # Full clean (binaries, venv, node_modules, coverage)
```

### Curl-to-Bash Installer

End users can install a released version without cloning the repo:

```bash
VERSION=0.8.4
INSTALL_URL="https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/${VERSION}/scripts/install.sh"
curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash
```

The installer detects the platform, downloads the correct gateway
binary + CLI wheel + plugin tarball, installs them, and prompts to run
`defenseclaw init --enable-guardrail`. Use `--yes` / `-y` to skip
confirmations. The release installers are fresh-install-only. If the CLI,
gateway, or managed virtual environment already exists, they exit before
platform/dependency setup or artifact replacement. Use the authenticated
current release-owned `scripts/upgrade.sh` resolver for an existing POSIX
pre-bridge host. The signed `scripts/upgrade.ps1` surface is refusal-only
because this cut publishes no Windows runtime. A `0.8.3`-or-older built-in
`defenseclaw upgrade` safely refuses a hard-cut target but cannot perform the
required two-process bridge handoff retroactively.

Authenticated POSIX installs keep a private, mode-0700 same-filesystem custody
directory for inactive rollback objects. A durable mode-0600 in-progress marker
is present only while a fresh install may need recovery and is retired before a
successful install is reported. Consequently, retained custody from a healthy
completed install does not bypass the early existing-install refusal; missing,
malformed, or symlinked marker state also fails closed before dependency or
artifact work.

Pin a specific version:

```bash
VERSION=0.8.4
INSTALL_URL="https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/${VERSION}/scripts/install.sh"
curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash
```

#### Picking an agent connector at install time

By default the installer integrates with **OpenClaw** (installs the
OpenClaw runtime and the DefenseClaw plugin). You can pick a different
connector — or skip connector setup entirely — with `--connector`:

```bash
VERSION=0.8.4
INSTALL_URL="https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/${VERSION}/scripts/install.sh"

# Codex (no OpenClaw, no plugin tarball; patches ~/.codex/config.toml + hooks)
curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash -s -- --connector codex

# Claude Code (no OpenClaw; patches ~/.claude/settings.json hooks)
curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash -s -- --connector claudecode

# ZeptoClaw (no OpenClaw; patches ~/.zeptoclaw/config.json)
curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash -s -- --connector zeptoclaw

# Lay binaries only — pick a connector later
curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash -s -- --connector none

# Shortcut for "skip OpenClaw" without naming another connector
curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash -s -- --no-openclaw
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
dependencies, seeds config and audit database, copies Rego policies,
and starts the sidecar if the gateway binary is on PATH. CodeGuard
native skill/rule installation is explicit and opt-in.

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
9. Skips native CodeGuard skill/rule installation unless requested separately
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
6. Uses the gateway config watcher to apply supported `config.yaml` changes at runtime

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
| `--analyzers LIST` | Comma-separated analyzer list (default `auto`; explicit example: `yara,api,llm,behavioral,readiness`) |
| `--llm-provider PROVIDER` | `anthropic` or `openai` |
| `--llm-model MODEL` | Model for LLM analyzer |
| `--scan-prompts` | Scan MCP server prompts |
| `--scan-resources` | Scan MCP server resources |
| `--scan-instructions` | Scan MCP server instructions |
| `--non-interactive` | Apply flags without prompts |

MCP server URLs are managed separately with `defenseclaw mcp set` /
`defenseclaw mcp unset`, not through this setup command.

`auto` lets DefenseClaw choose the scanner plugin set supported by the
installed `cisco-ai-mcp-scanner` version and configured credentials. To opt out
of an analyzer, pass an explicit list that omits it; once you pass a list,
DefenseClaw uses that list as-is instead of adding missing analyzer names back.

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

Under `config_version: 8`, each selected Splunk pipeline becomes an independent
entry in `observability.destinations`: HEC is logs-only and Splunk O11y uses
OTLP capabilities. An enabled destination with no explicit `send`/`routes`
exports every bucket and signal that kind supports under the unredacted `none`
profile. Use `defenseclaw observability plan` to review the effective route and
select a redacting profile before exporting across a less-trusted boundary.

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

### Unsupported historical sources

Automatic upgrades are supported only from versions named in the candidate's
published-baseline matrix. Sources outside it—including assetless `0.7.0`,
pre-upgrader `0.2.x`, and historical `0.3.x` releases—have no tested in-place
path. The resolver fails closed before stopping services and prints the exact
tested source versions.

Support is platform-specific. POSIX release gates cover the reviewed global
matrix through `0.4.0`. Release `0.8.4` published no Windows gateway or
rollback binary, so this hard cut has no supported Windows source version; the
PowerShell resolver fails closed before stopping services. Global POSIX
coverage must not be treated as a Windows upgrade claim.

If the installed version is not in that list, remain on the current version and
contact support for a source-specific, state-aware recovery plan. Do not infer
an intermediate hop, uninstall the old runtime, copy release artifacts over it,
or use a fresh installer as an upgrader.

### Supported staged upgrades

Run the current release-owned resolver in latest mode. Do not add a version
override when crossing the bridge boundary:

For an installed release without a source checkout, use the authenticated
POSIX resolver-asset bootstrap in [CLI Reference](CLI.md#upgrade).
The local paths below are only the equivalent entry points from a checkout of
the current release:

```bash
./scripts/upgrade.sh --yes
```

Release `0.8.4` is the config-v7/runtime-v7 protocol bridge for the subsequent
observability-v8 hard cut. Run the current release-owned updater without
`--version` when crossing that boundary so its signed manifest can select and
health-check the bridge before a fresh controller starts the target phase.
Explicit targets that skip a required bridge fail before installed state is
changed. Release `0.8.4` and later require Cosign provenance verification;
`--allow-unverified` cannot override it. The current POSIX resolver prefers an
existing `cosign`, otherwise it downloads pinned Cosign `2.6.3` into an
owner-only temporary directory and authenticates its hard-coded platform
SHA-256 before execution. It does not install Cosign system-wide or modify
`PATH`. The frozen `0.8.4` built-in controller also cannot parse the truthful
hard-cut manifest because its Windows bridge matrix is empty. Every `0.8.4`
host must therefore use the current target-release POSIX resolver, regardless
of whether Cosign is already installed.

The supported staged path is the authenticated current-release
`defenseclaw-upgrade.sh` asset in latest mode (or the equivalent
`scripts/upgrade.sh` from a trusted current-release checkout). The signed
PowerShell resolver remains a preflight refusal surface only. An
already-published `0.8.3`-or-older
`defenseclaw upgrade` command cannot gain the new two-hop orchestration after
installation, so its signed protocol check deliberately refuses the hard cut
before stopping services. Some frozen versions then print an obsolete raw
network-to-shell hint that must not be executed; use the authenticated
release-owned resolver instead. This is a safe preflight refusal, not a partial
upgrade.

Before the first service stop, the resolver commits a private phase-one journal
covering the exact source CLI, gateway, configuration, migration cursor, policy,
connector, and OpenClaw state plus whether the source gateway was running. If
bridge installation, migration, start, or version-bound health fails—or the
resolver is killed—the next invocation restores and health-checks that exact
source before it detects versions or begins new upgrade work.

If a rollback-renamed inode can still receive writes through an open file
descriptor, the resolver does not delete it. It remains in a plan-scoped,
mode-0700 custody directory on the same filesystem as the original path, with
its location recorded privately in the backup's
`phase1-state/retained-quarantines.json`. Preserve the directory and index until
validation is complete, and inspect them before manual cleanup.

The bridge commits a private phase-two recovery journal and fixed mutator
lease before stopping services. Wheel, migration, bundle, and service child
processes inherit that lease, so an abrupt controller or host interruption
cannot race rollback.

Re-run that same resolver in latest mode, without a version override.
It waits for any surviving child, bootstraps the retained authenticated `0.8.4`
wheel without trusting a partial target install, restores exact bridge state,
proves bridge health, and only then retries.

Once the bridge is installed, its fresh CLI controller performs the target
phase: preflight artifact verification, config backup,
stop-install-migrate-restart, rollback on failure, and version-bound health
polling. The release-owned POSIX shell resolver coordinates the initial bridge
selection. See the [CLI Reference](CLI.md#upgrade) for the
complete path and flag behavior.

An installed `0.8.4` bridge must start the hard-cut target phase through the
authenticated target-release POSIX resolver. Its frozen built-in parser
requires a nonempty Windows bridge matrix and cannot parse the truthful target
manifest whose Windows matrix is empty. A `0.8.3`-or-older frozen controller
also must use the release-owned resolver described below and correctly refuses
to skip the bridge.

#### 0.3.0 migration: legacy model provider cleanup

This migration still runs when upgrading directly from 0.2.0 to 0.4.0 or newer.

The 0.2.0 guardrail setup redirected LLM traffic by writing provider and model
entries directly into `~/.openclaw/openclaw.json`:

- `models.providers.defenseclaw` and/or `models.providers.litellm` — proxy
  provider definitions that routed calls through the guardrail
- `agents.defaults.model.primary` set to `defenseclaw/<model>` or
  `litellm/<model>` — forced all agent calls through the proxy provider

In 0.3.0, routing is handled transparently by a fetch interceptor in the
OpenClaw plugin, so these entries are no longer needed.

The migration uses a **surgical live-file** strategy. A pristine snapshot may
exist from initial guardrail setup, but the migration never restores that
snapshot over the live `openclaw.json`. It deletes only
`models.providers.defenseclaw` /
`models.providers.litellm`, strips the old proxy prefix from
`agents.defaults.model.primary`, and preserves operator-added providers,
plugins, models, workspaces, and ordering. It saves a
`.pre-0.3.0-migration` backup before changing the live file.

If none of these legacy entries exist, the migration is a no-op.

### Upgrading artifact-backed releases

Every supported POSIX source uses the authenticated target-release resolver in
latest mode to cross the `0.8.5` hard cut. Before backup or service stop, it
authenticates and privately acquires the exact published `0.8.4` wheel and
gateway needed for rollback. A host already on `0.8.4` skips the first
installation hop. A `0.8.3`-or-older host is carried through the required
bridge and into the latest release as one transaction. Neither frozen built-in
controller can learn the complete truthful path retroactively.

```bash
# For `0.8.4` or any supported older POSIX source, run an authenticated
# target-release asset in latest mode
bash defenseclaw-upgrade.sh --yes

# Equivalent resolver entry point from an authenticated current-release checkout
./scripts/upgrade.sh --yes
```

Do not add `--version` to the resolver command. The complete
Sigstore and SHA-256 bootstrap is in the [CLI Reference](CLI.md#upgrade). The
target-release resolver performs authenticated rollback-artifact acquisition,
backup, migration, restart, and health checks for both already-bridged and
pre-bridge sources.

Do not replace the managed CLI wheel through `pip`, `uv`, or another package
manager, and do not copy the wheel or gateway archive over an existing
installation. Those operations cannot provide bridge selection, durable
rollback, or version-bound health verification. The local shell and PowerShell
installers are fresh-install-only and refuse existing managed state before
dependency setup or artifact replacement. Every supported existing POSIX host,
including one already on `0.8.4`, must use the target-release upgrade resolver.

For protocol-2 releases, the installable bytes are published only inside
manifest-bound `.dcwheel` and `.dcgateway` protected envelopes. Their payloads
are deliberately not ZIP, wheel, gzip, or executable bytes until a verified
release-owned resolver materializes them privately. The conventional `.whl`,
`.tar.gz`, and `.zip` asset names are signed refusal envelopes. Renaming,
extracting, or package-installing either form is not a supported manual path;
use the resolver so the bridge and rollback contract cannot be skipped.

#### 0.8.5 hard cut and the 0.8.4 bridge

An installed `0.8.3` or older controller must not install `0.8.5` directly.
The normal one-command path uses the authenticated resolver asset owned by the
target release. Follow the complete Sigstore and SHA-256 bootstrap in the
[CLI Reference](CLI.md#upgrade), or run `./scripts/upgrade.sh --yes` from an
authenticated checkout of that release. Do not stream an unauthenticated
network response into a shell.

Windows cannot cross this hard cut because the published `0.8.4` bridge has no
Windows gateway or rollback binary. The signed `scripts/upgrade.ps1` resolver
is retained only to refuse before stopping services and explain that no tested
path exists. Keep the current Windows installation unchanged.

An explicit `0.8.3 → 0.8.5` request is intentionally rejected before backup,
service stop, or installed-file mutation. Fresh installers also refuse to
overwrite an existing installation. No package-manager or manual artifact-copy
path may replace an existing hard-cut installation unless it invokes this same
resolver contract.

### What gets upgraded

| Component | Updated by upgrade | Notes |
|-----------|-------------------|-------|
| Gateway binary (`defenseclaw-gateway`) | Yes | Replaced from release tarball |
| Python CLI (`defenseclaw`) | Yes | Replaced from release wheel |
| OpenClaw plugin | No | Plugin is release-specific; installed by `install.sh` only |
| Config files | Preserved | Backed up before upgrade, migrations patch if needed |
| Policies | Preserved | Backed up; not overwritten |

### Rollback and interrupted recovery

The staged resolver automatically restores the prior source if the bridge phase
fails, or restores the authenticated `0.8.4` gateway, CLI, configuration,
environment, migration cursor, and managed bundle if the hard-cut phase fails.
Durable recovery journals make the same rollback resume before version/config
detection after a crash or reboot. Success is emitted only after a fresh,
version-bound health check.

Timestamped backups remain available for inspection and support escalation:

```bash
# Backups are saved to ~/.defenseclaw/backups/upgrade-<timestamp>/
# Inspect only; do not manually copy a backup over live state.
ls ~/.defenseclaw/backups/

# Re-run the release-owned resolver without a version override.
scripts/upgrade.sh
# Windows:
.\scripts\upgrade.ps1
```

`defenseclaw upgrade` and the release-owned resolvers refuse downgrades.
Do not copy an older wheel or gateway over an installation. If automatic
recovery remains incomplete, keep the backup and journal intact and contact
support for a state-aware recovery plan.

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
  mode: openclaw        # openclaw | zeptoclaw | claudecode | codex | hermes | cursor | windsurf | geminicli | copilot | openhands | antigravity | opencode | omnigent
  home_dir: ""          # auto-detected; override to use a custom path
```

The claw mode determines which skill and MCP directories are watched, scanned, and used for install resolution. Adding a new framework only requires a new case in the config resolver.
