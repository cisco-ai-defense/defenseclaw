# CLI Reference

All subcommands are registered on `defenseclaw`. Use `defenseclaw <command> --help` for flags and examples.

## Commands

| Command | Description |
|---------|-------------|
| `init` | Create `~/.defenseclaw` config, SQLite audit database, and install scanner dependencies |
| `setup skill-scanner` | Interactively configure skill-scanner analyzers, API keys, and policy |
| `deploy [path]` | Full orchestrated deploy: init → scan → block → policy → sandbox |
| `sidecar` | Show gateway sidecar info and startup instructions |
| `sidecar status` | Show health of the running sidecar's subsystems |
| `status` | Show environment, sandbox health, scanner availability, and enforcement counts |
| `alerts` | Show recent security alerts |

### skill

| Command | Description |
|---------|-------------|
| `skill list` | List all OpenClaw skills with scan severity and enforcement status |
| `skill scan <target>` | Scan a skill by name, path, or `all` for all configured skills |
| `skill install <name>` | Install via clawhub → scan → enforce block/allow list |
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
| `plugin install <name-or-path>` | Install a plugin from a local path or registry |
| `plugin remove <name>` | Remove an installed plugin |

### aibom

| Command | Description |
|---------|-------------|
| `aibom generate [path]` | Generate AI Bill of Materials for a project |

---

## init

```
defenseclaw init [flags]
```

Creates `~/.defenseclaw/`, default config, SQLite audit database,
and installs scanner dependencies (skill-scanner, mcp-scanner, cisco-aibom) via `uv`.

**Flags:**
- `--skip-install` — skip automatic scanner dependency installation

## setup skill-scanner

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

## deploy

```
defenseclaw deploy [path] [flags]
```

Full orchestrated deployment:
1. Initialize if needed
2. Run all scanners (skills + MCP + AIBOM)
3. Auto-block anything HIGH/CRITICAL
4. Generate OpenShell sandbox policy
5. Start sandbox
6. Print summary

**Flags:**
- `--skip-init` — skip initialization step

## skill list

```
defenseclaw skill list [flags]
```

Lists all OpenClaw skills with their latest scan severity, enforcement status,
and applied actions. Merges data from OpenClaw's skill registry with DefenseClaw's
audit database.

**Flags:**
- `--json` — output merged skill list as JSON

## skill scan

```
defenseclaw skill scan <target> [flags]
```

Scans a skill by name, path, or `all` for all configured skills. Respects
block/allow lists — blocked skills are rejected, allowed skills skip scan.

**Flags:**
- `--json` — output scan results as JSON
- `--path` — override skill directory path

**Examples:**

```bash
# Scan a skill by name (resolved via openclaw)
defenseclaw skill scan web-search

# Scan a skill by path
defenseclaw skill scan ./my-skill --path ./my-skill

# Scan all configured skills
defenseclaw skill scan all
```

## skill install

```
defenseclaw skill install <name> [flags]
```

Installs a skill via clawhub, then scans and optionally enforces policy.
Follows the admission gate: block list → allow list → scan → enforce.

**Flags:**
- `--force` — overwrite an existing skill
- `--action` — apply configured `skill_actions` policy based on scan severity (quarantine, disable, block)

## skill info

```
defenseclaw skill info <name> [flags]
```

Shows merged skill metadata from OpenClaw, latest scan results, and enforcement actions.

**Flags:**
- `--json` — output as JSON

## skill block

```
defenseclaw skill block <name> [flags]
```

Adds a skill to the install block list. Blocked skills are rejected by
`skill install` before any scan runs.

**Flags:**
- `--reason` — reason for blocking

## skill allow

```
defenseclaw skill allow <name> [flags]
```

Adds a skill to the allow list. Allow-listed skills skip the scan gate
during install. Also removes the skill from the block list.

**Flags:**
- `--reason` — reason for allowing

## skill disable

```
defenseclaw skill disable <name> [flags]
```

Disables a skill at runtime via OpenClaw gateway RPC. Prevents the agent
from using the skill's tools until re-enabled. Requires the sidecar to be running.

**Flags:**
- `--reason` — reason for disabling

## skill enable

```
defenseclaw skill enable <name>
```

Re-enables a previously disabled skill via gateway RPC.

## skill quarantine

```
defenseclaw skill quarantine <name> [flags]
```

Moves the skill's directory to `~/.defenseclaw/quarantine/skills/` and records
the action. Use `skill restore` to undo.

**Flags:**
- `--reason` — reason for quarantine

## skill restore

```
defenseclaw skill restore <name> [flags]
```

Restores a quarantined skill to its original location.

**Flags:**
- `--path` — override restore destination (defaults to original path)

## mcp list

```
defenseclaw mcp list
```

Lists MCP servers with their enforcement status (blocked, allowed), reason,
and last update time.

## mcp scan

```
defenseclaw mcp scan <url> [flags]
```

Scans an MCP server endpoint using cisco-ai-mcp-scanner.

**Flags:**
- `--json` — output results as JSON

## mcp block

```
defenseclaw mcp block <url> [flags]
```

Adds an MCP server to the block list.

**Flags:**
- `--reason` — reason for blocking

## mcp allow

```
defenseclaw mcp allow <url> [flags]
```

Adds an MCP server to the allow list.

**Flags:**
- `--reason` — reason for allowing

## plugin list

```
defenseclaw plugin list
```

Lists installed plugins from `~/.defenseclaw/plugins/`.

## plugin scan

```
defenseclaw plugin scan <name-or-path> [flags]
```

Scans a plugin directory for security issues. Checks for dangerous permissions,
install scripts, credential theft, obfuscation, supply chain risks, and more.

Accepts a plugin name (resolved from `~/.defenseclaw/plugins/`) or a direct path.

**Flags:**
- `--json` — output scan results as JSON

**Examples:**

```bash
# Scan an installed plugin by name
defenseclaw plugin scan my-plugin

# Scan a plugin directory
defenseclaw plugin scan /path/to/plugin
```

## plugin install

```
defenseclaw plugin install <name-or-path>
```

Installs a plugin from a local directory path. Copies the plugin directory
to `~/.defenseclaw/plugins/`.

## plugin remove

```
defenseclaw plugin remove <name>
```

Removes an installed plugin by name.

## aibom generate

```
defenseclaw aibom generate [path] [flags]
```

Generates an AI Bill of Materials for a project. Runs cisco-aibom to inventory
AI components, models, and dependencies.

**Flags:**
- `--json` — output results as JSON

**Examples:**

```bash
# Generate AIBOM for current directory
defenseclaw aibom generate

# Generate AIBOM for a specific project
defenseclaw aibom generate /path/to/project

# Output as JSON for pipeline integration
defenseclaw aibom generate --json
```

## sidecar

```
defenseclaw sidecar
```

Displays gateway sidecar configuration and startup instructions.
The sidecar daemon runs as a separate Go binary (`defenseclaw-go`).

## sidecar status

```
defenseclaw sidecar status
```

Queries the sidecar's REST API to display the health of all three subsystems:
gateway connection, skill watcher, and API server.

## status

```
defenseclaw status
```

Shows environment, data directory, sandbox state, scanner availability,
enforcement counts, activity summary, and sidecar status.

## alerts

```
defenseclaw alerts [-n limit]
```

Displays recent security alerts (events with severity CRITICAL, HIGH, MEDIUM, or LOW).

**Flags:**
- `-n, --limit` — number of alerts to show (default: 25)
