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
| `status` | Show environment, scanner availability, enforcement counts, sidecar health |
| `alerts` | Show recent security alerts |
| `doctor` | Verify credentials, endpoints, and connectivity after setup |

### setup

| Command | Description |
|---------|-------------|
| `setup skill-scanner` | Configure skill-scanner analyzers, API keys, and policy |
| `setup mcp-scanner` | Configure MCP scanner analyzers |
| `setup gateway` | Configure gateway connection settings |
| `setup guardrail` | Configure LLM guardrail (mode, model, port, API key) |
| `setup splunk` | Configure Splunk HEC / OTLP / local bridge integration |

### skill

| Command | Description |
|---------|-------------|
| `skill list` | List all OpenClaw skills with scan severity and enforcement status |
| `skill scan <target>` | Scan a skill by name, path, or `all` for all configured skills |
| `skill install <name>` | Install via clawhub, scan, enforce block/allow list |
| `skill info <name>` | Show detailed skill metadata, scan results, and enforcement actions |
| `skill block <name>` | Add a skill to the block list |
| `skill allow <name>` | Add a skill to the allow list (removes from block list) |
| `skill disable <name>` | Disable a skill at runtime via gateway RPC |
| `skill enable <name>` | Re-enable a previously disabled skill via gateway RPC |
| `skill quarantine <name>` | Move a skill's files to the quarantine area |
| `skill restore <name>` | Restore a quarantined skill to its original location |

### mcp

| Command | Description |
|---------|-------------|
| `mcp list` | List MCP servers with enforcement status |
| `mcp scan <url>` | Scan an MCP server endpoint |
| `mcp block <url>` | Add an MCP server to the block list |
| `mcp allow <url>` | Add an MCP server to the allow list |

### plugin

| Command | Description |
|---------|-------------|
| `plugin list` | List installed plugins |
| `plugin scan <name-or-path>` | Scan a plugin for security issues |
| `plugin install <name-or-path>` | Install a plugin from a local path |
| `plugin remove <name>` | Remove an installed plugin |

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

### aibom

| Command | Description |
|---------|-------------|
| `aibom scan [path]` | Generate AI Bill of Materials for a project |

### codeguard

| Command | Description |
|---------|-------------|
| `codeguard install-skill` | Install the CodeGuard skill into the OpenClaw workspace |

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
Follows the admission gate: block list → allow list → scan → enforce.

**Flags:**
- `--force` — overwrite an existing skill
- `--action` — apply configured `skill_actions` policy based on scan severity

### skill block / allow

```
defenseclaw skill block <name> [--reason "..."]
defenseclaw skill allow <name> [--reason "..."]
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

### mcp scan

```
defenseclaw mcp scan <url> [--json]
```

### plugin scan

```
defenseclaw plugin scan <name-or-path> [--json]
```

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

### doctor

```
defenseclaw doctor [--json]
```

Runs connectivity and credential checks against all configured services
(sidecar, guardrail proxy, Cisco AI Defense, Splunk, scanners).
