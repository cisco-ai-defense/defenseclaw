# CLI Reference

DefenseClaw has two CLI binaries:

| Binary | Language | Install |
|--------|----------|---------|
| `defenseclaw` | Python (Click) | `make pycli` or `uv pip install -e .` |
| `defenseclaw-gateway` | Go (Cobra) | `make gateway` |

Use `<binary> --help` for any command.

---

## Python CLI (`defenseclaw`)

### Top-Level Commands

| Command | Description |
|---------|-------------|
| `init` | Create `~/.defenseclaw` config, SQLite audit database, install scanner deps |
| `quickstart` | Zero-prompt end-to-end setup with safe defaults |
| `status` | Show environment, scanner availability, enforcement counts, sidecar health |
| `alerts` | Show recent security alerts |
| `doctor` | Verify credentials, endpoints, and connectivity after setup |
| `version` | Show CLI/gateway/plugin versions and flag drift |
| `guardrail` | Toggle the LLM guardrail on or off |
| `keys` | Inspect and manage API keys |
| `config` | Inspect and validate configuration |
| `tui` | Launch Go-based terminal UI |
| `uninstall` | Reversible uninstall of DefenseClaw components |
| `reset` | Wipe `~/.defenseclaw` so quickstart starts clean |
| `audit` | Audit trail helpers |

### setup

| Command | Description |
|---------|-------------|
| `setup skill-scanner` | Configure skill-scanner analyzers, API keys, and policy |
| `setup mcp-scanner` | Configure MCP scanner analyzers |
| `setup gateway` | Configure gateway connection settings |
| `setup guardrail` | Configure LLM guardrail (mode, model, port, API key) |
| `setup splunk` | Configure Splunk O11y, local Splunk bridge, or remote Splunk Enterprise HEC |
| `setup observability` | Configure unified OTel + audit sinks |
| `setup local-observability` | Bundled Prom/Loki/Tempo/Grafana stack |
| `setup webhook` | Configure Slack/PagerDuty/Webex/generic notifiers |
| `setup provider` | Configure custom LLM providers (custom-providers.json overlay) |
| `setup migrate-llm` | Rewrite config to v5 unified LLM shape |

### skill

| Command | Description |
|---------|-------------|
| `skill list` | List all OpenClaw skills with scan severity and enforcement status |
| `skill scan <target>` | Scan a skill by name, path, or `all` for all configured skills |
| `skill install <name>` | Install via clawhub, scan, enforce block/allow list |
| `skill info <name>` | Show detailed skill metadata, scan results, and enforcement actions |
| `skill block <name>` | Add a skill to the block list |
| `skill allow <name>` | Add a skill to the allow list (removes from block list) |
| `skill unblock <name>` | Remove a skill from the block/allow list |
| `skill disable <name>` | Disable a skill at runtime via gateway RPC |
| `skill enable <name>` | Re-enable a previously disabled skill via gateway RPC |
| `skill quarantine <name>` | Move a skill's files to the quarantine area |
| `skill restore <name>` | Restore a quarantined skill to its original location |
| `skill search <query>` | Search ClawHub skill registry |
| `skill remove <name>` | Remove an installed skill |
| `skill list-installed` | List all installed skills |

### mcp

| Command | Description |
|---------|-------------|
| `mcp list` | List MCP servers with enforcement status |
| `mcp scan <url>` | Scan an MCP server endpoint |
| `mcp block <url>` | Add an MCP server to the block list |
| `mcp allow <url>` | Add an MCP server to the allow list |
| `mcp unblock <name>` | Remove MCP server from block/allow list |
| `mcp set <name> <command>` | Register an MCP server |
| `mcp unset <name>` | Unregister an MCP server |

### plugin

| Command | Description |
|---------|-------------|
| `plugin list` | List installed plugins |
| `plugin scan <name-or-path>` | Scan a plugin for security issues |
| `plugin install <name-or-path>` | Install a plugin from a local path |
| `plugin remove <name>` | Remove an installed plugin |
| `plugin block <name>` | Block a plugin |
| `plugin allow <name>` | Allow-list a plugin |
| `plugin unblock <name>` | Remove from block/allow list |
| `plugin disable <name>` | Disable a plugin at runtime |
| `plugin enable <name>` | Enable a previously disabled plugin |
| `plugin quarantine <name>` | Quarantine a plugin's files |
| `plugin restore <name>` | Restore a quarantined plugin |
| `plugin info <name>` | Show detailed plugin information |
| `plugin list-installed` | List all installed plugins |

### tool

| Command | Description |
|---------|-------------|
| `tool block <name>` | Block a tool (global or scoped with `--source`) |
| `tool allow <name>` | Allow a tool (skip scan gate) |
| `tool unblock <name>` | Remove a tool from the block/allow list |
| `tool list` | List tools in the block/allow list |
| `tool status <name>` | Show block/allow status of a tool |

### policy

| Command | Description |
|---------|-------------|
| `policy create <name>` | Create a new security policy |
| `policy list` | List all available policies (built-in and custom) |
| `policy show <name>` | Show details of a policy |
| `policy activate <name>` | Activate a policy (applies to config + OPA data.json) |
| `policy delete <name>` | Delete a custom policy |
| `policy validate` | Compile-check Rego modules and validate data.json |
| `policy test` | Run OPA Rego unit tests |
| `policy edit actions` | Edit severity-to-action mappings |
| `policy edit scanner` | Edit per-scanner action overrides |
| `policy edit guardrail` | Edit guardrail policy (thresholds, Cisco trust, patterns) |
| `policy edit firewall` | Edit firewall policy (domains, ports, blocklists) |

`policy activate <name>` updates the OPA-backed policy, but it does not switch
the active guardrail rule pack. If you also need `strict` / `default` /
`permissive` judge prompts and suppressions, point `guardrail.rule_pack_dir`
at the matching profile. See
[Guardrail Rule Packs & Suppressions](GUARDRAIL_RULE_PACKS.md).

### aibom

| Command | Description |
|---------|-------------|
| `aibom scan [path]` | Generate AI Bill of Materials for a project |

### codeguard

| Command | Description |
|---------|-------------|
| `codeguard install-skill` | Install the CodeGuard skill into the OpenClaw workspace |

### upgrade

| Command | Description |
|---------|-------------|
| `upgrade` | Upgrade DefenseClaw in-place with config backup and restore |

### sandbox

| Command | Description |
|---------|-------------|
| `sandbox init` | Initialize OpenShell sandbox (Linux only) |
| `sandbox setup` | Configure sandbox networking and policies |

See [SANDBOX.md](SANDBOX.md) for full sandbox setup guide.

---

## Go Gateway CLI (`defenseclaw-gateway`)

The Go binary runs the sidecar daemon and provides additional commands.

### Daemon

| Command | Description |
|---------|-------------|
| *(no subcommand)* | Run the sidecar in the foreground |
| `start` | Start the sidecar as a background daemon |
| `stop` | Stop the running daemon |
| `restart` | Restart the daemon |
| `status` | Show health of the running sidecar's subsystems |

### scan

| Command | Description |
|---------|-------------|
| `scan code <path>` | Scan source code with CodeGuard static analyzer |

### policy

| Command | Description |
|---------|-------------|
| `policy validate` | Compile-check Rego modules and validate data.json |
| `policy show` | Display current OPA data.json policy |
| `policy evaluate` | Dry-run admission policy for a given input |
| `policy evaluate-firewall` | Dry-run firewall policy for a given destination |
| `policy reload` | Tell the running sidecar to hot-reload OPA policies |
| `policy domains` | List firewall domain allowlist and blocklist |

### connector

| Command | Description |
|---------|-------------|
| `connector teardown` | Run active connector's Teardown procedure |
| `connector verify` | Verify connector left no residual state |
| `connector list-backups` | List pristine connector backups |

### watchdog

| Command | Description |
|---------|-------------|
| `watchdog` | Run watchdog in foreground |
| `watchdog start` | Start as background daemon |
| `watchdog stop` | Stop running watchdog daemon |
| `watchdog status` | Show watchdog daemon status |

### provenance

| Command | Description |
|---------|-------------|
| `provenance show` | Show schema_version, content_hash, generation, binary_version |

### tui

| Command | Description |
|---------|-------------|
| `tui` | Launch terminal UI directly |

### sandbox

| Command | Description |
|---------|-------------|
| `sandbox start` | Start sandbox and sidecar via systemd |
| `sandbox stop` | Stop sandbox and sidecar via systemd |
| `sandbox restart` | Restart sandbox (sidecar reconnects automatically) |
| `sandbox status` | Show sandbox and sidecar systemd status |
| `sandbox exec -- <command>` | Run a command as the sandbox user |
| `sandbox shell` | Open an interactive shell as the sandbox user |
| `sandbox policy` | Compare active sandbox policy against configured endpoints |

See [SANDBOX.md](SANDBOX.md) for full sandbox architecture, setup, and troubleshooting.

---

## Command Details

### init

```
defenseclaw init [flags]
```

Creates `~/.defenseclaw/`, default config, SQLite audit database,
and installs scanner dependencies (skill-scanner, mcp-scanner, cisco-aibom) via `uv`.

**Flags:**
- `--skip-install` — skip automatic scanner dependency installation

### quickstart

```
defenseclaw quickstart [flags]
```

Zero-prompt end-to-end setup that runs `init`, configures scanners, sets up
the guardrail, starts the gateway, and wires the connector — all with safe defaults.
Ideal for first-time users or CI environments.

**Flags:**
- `--mode` — enforcement mode: `observe` (log only) or `action` (block threats)
- `--scanner` — scanner mode: `local`, `remote`, or `both`
- `--with-judge` / `--no-judge` — enable or disable the LLM judge
- `--non-interactive` — never prompt, use defaults and flags only
- `--yes` — skip all confirmation prompts
- `--force` — overwrite existing configuration
- `--connector` — connector to wire: `openclaw`, `zeptoclaw`, `claudecode`, or `codex`
- `--skip-gateway` — do not start the gateway daemon after setup
- `--json-summary` — print a machine-readable JSON summary on completion

**Examples:**

```bash
# Fully non-interactive quickstart for CI
defenseclaw quickstart --non-interactive --yes --connector claudecode --mode observe

# Interactive quickstart with action mode
defenseclaw quickstart --mode action --with-judge
```

### version

```
defenseclaw version [flags]
```

Displays the installed versions of the Python CLI, Go gateway binary, and
OpenClaw plugin. Optionally flags version drift between components.

**Flags:**
- `--json` — output as JSON
- `--no-drift-exit` — do not exit non-zero when versions drift

### guardrail

```
defenseclaw guardrail <subcommand>
```

Toggle the LLM guardrail on or off and inspect its state.

| Subcommand | Description |
|------------|-------------|
| `status` | Show whether guardrail is enabled and which connector is active |
| `disable` | Disable guardrail |
| `enable` | Re-enable guardrail |

**Flags (disable/enable):**
- `--restart` / `--no-restart` — restart sidecar + connector after toggling
- `--yes` — skip confirmation prompt

**Examples:**

```bash
defenseclaw guardrail status
defenseclaw guardrail disable --restart --yes
defenseclaw guardrail enable --restart
```

### keys

```
defenseclaw keys <subcommand>
```

Inspect and manage API keys stored in `~/.defenseclaw/.env`.

| Subcommand | Description |
|------------|-------------|
| `list` | List all credentials |
| `set <env_name>` | Store a credential |
| `fill-missing` | Interactive prompt for required credentials |
| `check` | Exit 0 if all required keys set, non-zero otherwise |

**Flags (list):**
- `--json` — output as JSON
- `--show-values` — reveal credential values (default: masked)
- `--missing-only` — show only unset credentials

**Flags (set):**
- `--value` — pass value non-interactively (otherwise prompts)

**Flags (fill-missing):**
- `--yes` — accept defaults without prompting

**Examples:**

```bash
defenseclaw keys list --missing-only
defenseclaw keys set ANTHROPIC_API_KEY --value sk-ant-...
defenseclaw keys fill-missing --yes
defenseclaw keys check && echo "All keys configured"
```

### config

```
defenseclaw config <subcommand>
```

Inspect and validate DefenseClaw configuration.

| Subcommand | Description |
|------------|-------------|
| `validate` | Verify config file parses and references valid enums |
| `show` | Render resolved configuration, secrets masked |
| `path` | Print filesystem locations DefenseClaw uses |

**Flags (validate):**
- `--quiet` — suppress output on success, exit code only

**Flags (show):**
- `--format` — output format: `yaml` or `json`
- `--reveal` — show secret values unmasked

**Examples:**

```bash
defenseclaw config validate --quiet
defenseclaw config show --format json
defenseclaw config show --reveal
defenseclaw config path
```

### uninstall

```
defenseclaw uninstall [flags]
```

Reversible uninstall of DefenseClaw components. Stops the gateway, removes
binaries, and optionally removes configuration. Can preserve the OpenClaw
connector installation.

**Flags:**
- `--all` — remove everything (binaries + config + data)
- `--binaries` — remove only binaries, keep config
- `--keep-openclaw` — do not remove OpenClaw connector files
- `--dry-run` — show what would be removed without removing
- `--yes` — skip confirmation prompt

**Examples:**

```bash
defenseclaw uninstall --dry-run
defenseclaw uninstall --all --yes
defenseclaw uninstall --binaries --keep-openclaw
```

### reset

```
defenseclaw reset [flags]
```

Wipes `~/.defenseclaw/` so that `quickstart` or `init` starts from a clean state.
The gateway is stopped first if running.

**Flags:**
- `--yes` — skip confirmation prompt

### tui

```
defenseclaw tui
```

Launches the Go-based terminal UI (requires `defenseclaw-gateway` binary).
Provides a dashboard view of alerts, scanner status, and enforcement activity.

### audit

```
defenseclaw audit <subcommand>
```

Audit trail helpers for recording configuration and operator mutations.

| Subcommand | Description |
|------------|-------------|
| `log-activity` | Record a config/operator mutation |

**Flags (log-activity):**
- `--payload-file` — path to JSON file with activity payload

### setup skill-scanner

```
defenseclaw setup skill-scanner [flags]
```

Interactively configure how skill-scanner runs. Enables LLM analysis,
behavioral dataflow analysis, meta-analyzer filtering, VirusTotal, and Cisco AI Defense.

API keys are stored in `~/.defenseclaw/config.yaml` and injected as
environment variables when skill-scanner runs.

**Flags:**
- `--use-llm` — enable LLM analyzer
- `--use-behavioral` — enable behavioral analyzer
- `--enable-meta` — enable meta-analyzer (false positive filtering)
- `--use-trigger` — enable trigger analyzer
- `--use-virustotal` — enable VirusTotal binary scanner
- `--use-aidefense` — enable Cisco AI Defense analyzer
- `--llm-provider` — LLM provider (`anthropic` or `openai`)
- `--llm-model` — LLM model name
- `--llm-consensus-runs` — LLM consensus runs (0 = disabled)
- `--policy` — scan policy preset (`strict`, `balanced`, `permissive`)
- `--lenient` — tolerate malformed skills
- `--non-interactive` — use flags instead of prompts (for CI)

### setup guardrail

```
defenseclaw setup guardrail [flags]
```

Configure the LLM guardrail (guardrail proxy). See
[Guardrail Quick Start](GUARDRAIL_QUICKSTART.md) for a full walkthrough.

**Flags:**
- `--mode` — `observe` (log only) or `action` (block threats)
- `--scanner-mode` — `local`, `remote`, or `both`
- `--port` — guardrail proxy port (default: 4000)
- `--disable` — disable guardrail and revert openclaw.json
- `--restart` — restart sidecar + OpenClaw after configuration
- `--non-interactive` — use flags instead of prompts

### setup observability

```
defenseclaw setup observability [flags]
```

Configure unified OpenTelemetry and audit sinks. Sets up trace, metric, and
log exporters for the gateway and scanners.

### setup local-observability

```
defenseclaw setup local-observability [flags]
```

Deploy a bundled local observability stack (Prometheus, Loki, Tempo, Grafana)
for development and testing. Requires Docker.

### setup webhook

```
defenseclaw setup webhook [flags]
```

Configure webhook-based notifiers for security events. Supports Slack,
PagerDuty, Webex Teams, and generic HTTP endpoints.

### setup provider

```
defenseclaw setup provider [flags]
```

Configure custom LLM providers by writing a `custom-providers.json` overlay.
Use this to add non-default model endpoints or private deployments.

### setup migrate-llm

```
defenseclaw setup migrate-llm [flags]
```

Rewrite `config.yaml` to the v5 unified LLM configuration shape. Consolidates
legacy provider/model entries into the new schema.

**Flags:**
- `--dry-run` — show the migrated config without writing
- `--no-backup` — skip creating a backup before migration

### skill scan

```
defenseclaw skill scan <target> [flags]
```

Scans a skill by name, path, or `all` for all configured skills. Respects
block/allow lists — blocked skills are rejected, allowed skills skip scan.

**Flags:**
- `--json` — output scan results as JSON
- `--path` — override skill directory path
- `--remote` — run scan via the Go sidecar REST API

**Examples:**

```bash
defenseclaw skill scan web-search
defenseclaw skill scan ./my-skill --path ./my-skill
defenseclaw skill scan all
```

### skill install

```
defenseclaw skill install <name> [flags]
```

Installs a skill via clawhub, then scans and optionally enforces policy.
Follows the admission gate: block list -> allow list -> scan -> enforce.

**Flags:**
- `--force` — overwrite an existing skill
- `--action` — apply configured `skill_actions` policy based on scan severity

### skill block / allow / unblock

```
defenseclaw skill block <name> [--reason "..."]
defenseclaw skill allow <name> [--reason "..."]
defenseclaw skill unblock <name>
```

### skill disable / enable

```
defenseclaw skill disable <name> [--reason "..."]
defenseclaw skill enable <name>
```

Requires the sidecar to be running. Sends RPC to OpenClaw gateway.

### skill quarantine / restore

```
defenseclaw skill quarantine <name> [--reason "..."]
defenseclaw skill restore <name> [--path /override/path]
```

### skill search

```
defenseclaw skill search <query> [flags]
```

Search the ClawHub skill registry for available skills.

**Flags:**
- `--json` — output results as JSON

### skill remove

```
defenseclaw skill remove <name>
```

Remove an installed skill from the local workspace.

### skill list-installed

```
defenseclaw skill list-installed
```

List all locally installed skills with their versions and status.

### mcp scan

```
defenseclaw mcp scan <url> [--json]
```

### mcp set / unset

```
defenseclaw mcp set <name> <command>
defenseclaw mcp unset <name>
```

Register or unregister an MCP server by name and command.

### mcp unblock

```
defenseclaw mcp unblock <name>
```

Remove an MCP server from the block/allow list.

### plugin scan

```
defenseclaw plugin scan <name-or-path> [--json]
```

### plugin block / allow / unblock

```
defenseclaw plugin block <name> [--reason "..."]
defenseclaw plugin allow <name> [--reason "..."]
defenseclaw plugin unblock <name>
```

### plugin disable / enable

```
defenseclaw plugin disable <name> [--reason "..."]
defenseclaw plugin enable <name>
```

Disable or enable a plugin at runtime without removing it.

### plugin quarantine / restore

```
defenseclaw plugin quarantine <name> [--reason "..."]
defenseclaw plugin restore <name> [--path /override/path]
```

Quarantine moves a plugin's files to an isolated directory; restore returns them.

### plugin info

```
defenseclaw plugin info <name> [--json]
```

Show detailed plugin information including version, status, scan results,
and enforcement history.

### plugin list-installed

```
defenseclaw plugin list-installed
```

List all installed plugins with their versions and enforcement status.

### aibom scan

```
defenseclaw aibom scan [path] [--json] [--summary-only] [--categories "..."]
```

### status

```
defenseclaw status
```

Shows environment, data directory, scanner availability,
enforcement counts, activity summary, and sidecar status.

### alerts

```
defenseclaw alerts [-n limit]
```

Displays recent security alerts. Default limit: 25.

#### alerts acknowledge

```
defenseclaw alerts acknowledge [flags]
```

Mark alerts as acknowledged.

**Flags:**
- `--severity` — filter by severity: `all`, `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`

#### alerts dismiss

```
defenseclaw alerts dismiss [flags]
```

Dismiss alerts from the active view.

**Flags:**
- `--severity` — filter by severity: `all`, `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`

### upgrade

```
defenseclaw upgrade [flags]
```

Downloads the gateway binary and Python CLI wheel from a GitHub release,
runs version-specific migrations, and restarts services. No source checkout
or build toolchain required — your configuration is preserved.

> **Plugin installs are release-specific.** The OpenClaw plugin is installed
> by `install.sh` as part of the release that ships it (0.3.0+). `upgrade`
> does not touch the plugin.

**Upgrade steps:**

1. Create timestamped backup of `~/.defenseclaw/` and `openclaw.json` to `~/.defenseclaw/backups/upgrade-<timestamp>/`
2. Stop `defenseclaw-gateway`
3. Download and replace gateway binary from the GitHub release tarball
4. Download and replace Python CLI from the GitHub release wheel
5. Run version-specific migrations between the installed and new versions
6. Start `defenseclaw-gateway` and restart OpenClaw gateway

**Version-specific migrations** are defined in `cli/defenseclaw/migrations.py`
and run automatically even during same-version upgrades. Each migration is
keyed to the release it ships with. For example, the v0.3.0 migration removes
legacy `models.providers.defenseclaw`, `models.providers.litellm`, and
`agents.defaults.model.primary` prefixed entries from `openclaw.json` (written
by 0.2.0's guardrail setup) while preserving plugin registration.

**Flags:**
- `--yes`, `-y` — skip confirmation prompts
- `--version VERSION` — upgrade to a specific release (default: latest)

**Examples:**

```bash
# Upgrade to the latest release
defenseclaw upgrade --yes

# Upgrade to a specific release
defenseclaw upgrade --version 0.3.0 --yes
```

The equivalent shell script `scripts/upgrade.sh` accepts the same flags:

```bash
./scripts/upgrade.sh --yes
./scripts/upgrade.sh --version 0.3.0 --yes
VERSION=0.3.0 ./scripts/upgrade.sh --yes
```

### doctor

```
defenseclaw doctor [--json]
```

Runs connectivity and credential checks against all configured services
(sidecar, guardrail proxy, Cisco AI Defense, Splunk, scanners).

---

## Go Gateway Command Details

### connector teardown

```
defenseclaw-gateway connector teardown [flags]
```

Run the active connector's Teardown procedure. Cleans up connector state,
removes injected configuration, and restores original files.

**Flags:**
- `--connector` — specify connector to tear down (default: active connector)
- `--json` — output results as JSON
- `--data-dir` — override data directory path

### connector verify

```
defenseclaw-gateway connector verify [flags]
```

Verify the connector left no residual state after teardown.

**Exit codes:**
- `0` — clean, no residual state
- `1` — dirty, residual state detected
- `2` — unknown, verification could not complete

### connector list-backups

```
defenseclaw-gateway connector list-backups
```

List pristine connector backups stored during setup. These can be used
to restore connector files to their original state.

### watchdog

```
defenseclaw-gateway watchdog [flags]
```

Health monitoring daemon with desktop notifications. Continuously monitors
the gateway, scanners, and connector health.

| Subcommand | Description |
|------------|-------------|
| *(no subcommand)* | Run watchdog in foreground |
| `start` | Start as background daemon |
| `stop` | Stop running watchdog daemon |
| `status` | Show watchdog daemon status |

**Examples:**

```bash
# Run in foreground (for debugging)
defenseclaw-gateway watchdog

# Manage as a daemon
defenseclaw-gateway watchdog start
defenseclaw-gateway watchdog status
defenseclaw-gateway watchdog stop
```

### provenance show

```
defenseclaw-gateway provenance show
```

Display provenance metadata for the installed gateway binary and configuration:
- `schema_version` — configuration schema version
- `content_hash` — SHA-256 of the configuration file
- `generation` — configuration generation number
- `binary_version` — gateway binary version and build info

### tui (gateway)

```
defenseclaw-gateway tui
```

Launch the terminal UI directly from the gateway binary. Provides a real-time
dashboard for monitoring alerts, scanner activity, and enforcement state.
