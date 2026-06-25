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
| `setup codex` / `setup claude-code` | Configure observability-only connector aliases |
| `setup hermes` / `setup cursor` / `setup windsurf` | Configure hook-first observability aliases |
| `setup geminicli` / `setup copilot` | Configure observability aliases with native OTel where supported |
| `setup splunk` | Configure Splunk O11y, local Splunk bridge, or remote Splunk Enterprise HEC |

### guardrail

Per-connector guardrail controls. Each verb prints the current value when run
bare and mutates it when given an argument. `--connector X` scopes the change
to one connector on a **multi-connector** install (writes
`guardrail.connectors.<name>` in `~/.defenseclaw/config.yaml`); omit it to set
the **global default** every connector inherits. On a single-connector install
`--connector` is rejected (only one posture exists). Proxy connectors
(OpenClaw, ZeptoClaw) are not valid `--connector` targets — multi-connector is
hook-only.

| Command | Description |
|---------|-------------|
| `guardrail status` | Read-only; **no `--connector` flag**. Shows the resolved guardrail posture (enabled, mode, fail mode, HILT, block message) as one per-connector block for EACH active connector — same layout whether one or N are wired |
| `guardrail enable [--connector X]` | Turn the guardrail on globally, or re-enable a single previously-disabled connector (restores its hooks, no re-prompt) |
| `guardrail disable [--connector X]` | Kill switch: global, or drop one connector from the active set and remove its hooks |
| `guardrail fail-mode [open\|closed] [--connector X] [--yes] [--restart/--no-restart]` | Show/set the response-layer hook fail mode (e.g. `guardrail fail-mode closed --connector codex`) |
| `guardrail hilt [on\|off] [--min-severity high\|medium\|low\|critical] [--connector X] [--yes] [--restart/--no-restart]` | Show/set human-in-the-loop approval policy |
| `guardrail block-message "<text>" [--connector X]` | Show/set the message shown to the agent when an action is blocked |

**Read fan-out vs. `--connector` writes.** On a multi-connector install the CLI
splits in two: **read / status / inventory** commands fan out to *all* active
connectors with one identical layout — `status`, `doctor`, `guardrail status`,
the bare `guardrail fail-mode` / `hilt` / `block-message` reads, and
`skill list` / `mcp list` / `plugin list`. **Mutating** guardrail verbs are
single-target via `--connector X` (default = the active connector); omit it to
set the global default. `guardrail status` is read-only and takes no
`--connector`. Scan commands (`skill scan --all`, `mcp scan --all`,
`aibom scan`) default to every active connector and narrow with a target or
`--connector`.

### agent

| Command | Description |
|---------|-------------|
| `agent discover [--refresh] [--json]` | Run local agent discovery and best-effort emit sanitized discovery telemetry |
| `agent usage [--refresh] [--json] [--detail] [--state STATE] [--category CAT] [--product NAME] [--show-gone] [--limit N]` | Show continuous AI visibility inventory from the sidecar. The default view groups signals by `(state, category, product, vendor, detector)` so wide-net detectors (e.g. `package_dependency` rolling up every `package.json`/`pyproject.toml`/`requirements.txt`) collapse into a single row with a count and sample basenames. `--detail` falls back to the per-signal view (with two-axis confidence and rich evidence columns when the gateway has them); `--state`/`--category`/`--product` filter the table; `gone` signals are hidden by default unless `--show-gone` (or `--state gone`) is passed; `--json` is the unfiltered raw payload for tooling. |
| `agent processes [--refresh] [--json] [--limit N]` | List AI processes the sidecar currently observes (PID, PPID, user, uptime, comm, vendor/product). Sourced from the `runtime` block on each process-detector signal. |
| `agent components [--refresh] [--json] [--ecosystem ECO] [--name NEEDLE] [--min-identity 0..1] [--min-presence 0..1] [--limit N]` | Show the deduped AI components/SDK rollup (one row per `(ecosystem, name)`) with versions, install counts, two-axis confidence (identity + presence) and the detector set. `--min-identity`/`--min-presence` filter on the Bayesian engine output for fast triage. |
| `agent components show NAME [--ecosystem ECO] [--json]` | Print every per-install location for one component: detector, state, workspace hash, basename, evidence quality, match kind, last-seen. Raw paths only surface when both `privacy.disable_redaction=true` and `ai_discovery.store_raw_local_paths=true`. |
| `agent components history NAME [--ecosystem ECO] [--limit N] [--json]` | Print the confidence trend (most-recent-first) for one component, sourced from the SQLite `ai_confidence_snapshots` history. |
| `agent confidence explain NAME [--ecosystem ECO] [--json]` | Print the per-evidence factor breakdown the engine used to compute identity + presence: detector, evidence id, match kind, quality, specificity/recency, likelihood ratio, log-odds delta, and the percentage-point shift each factor contributed. |
| `agent confidence policy show [--source merged\|default] [--json]` | Print the active confidence policy YAML. `merged` (default) is what the engine actually loaded; `default` is the embedded baseline so you can diff against your override. |
| `agent confidence policy default [--json]` | Print the embedded default policy — typically piped to `~/.defenseclaw/confidence_policy.yaml` as a starting point for an override. |
| `agent confidence policy validate PATH [--json]` | Dry-run a candidate policy file against the sidecar's loader + validator. Exits non-zero on failure with the same diagnostic the loader would print at boot. |
| `agent discovery enable [--mode] [--scan-roots] [--scan-interval-min N] [--process-interval-s N] [--max-files-per-scan N] [--max-file-bytes N] [--include-shell-history/--no-include-shell-history] [--include-package-manifests/--no-...] [--include-env-var-names/--no-...] [--include-network-domains/--no-...] [--emit-otel/--no-emit-otel] [--allow-workspace-signatures/--no-...] [--store-raw-local-paths/--no-...] [--restart/--no-restart] [--scan/--no-scan] [--yes]` | Flip `ai_discovery.enabled=true`, save config, bounce the gateway, and trigger a first scan in one step. Re-running on an already-enabled install with new tuning flags applies the diff and bounces the sidecar (audit logs as `ai_discovery-update`). |
| `agent discovery disable [--restart/--no-restart] [--yes]` | Flip `ai_discovery.enabled=false`, save config, and bounce the gateway so the service stops |
| `agent discovery setup [--restart/--no-restart] [--scan/--no-scan] [--yes]` | Walk an interactive wizard for every `ai_discovery.*` knob (mode, scan/process intervals, scan roots, file caps, detection sources, OTel, signature/path privacy). Each prompt defaults to the current config value so pressing Enter on every step is a no-op. |
| `agent discovery status [--json]` | Show on-disk + live AI discovery state and warn on drift between the two |
| `agent discovery scan [--json]` | Trigger one immediate AI discovery scan via the sidecar (`POST /api/v1/ai-usage/scan`) and render a one-line summary. Returns an actionable error when the sidecar is disabled (HTTP 503) pointing at `agent discovery enable`. |
| `agent signatures list \| validate \| install \| disable \| enable` | Manage AI discovery signature packs |

### skill

| Command | Description |
|---------|-------------|
| `skill list` | List active agent skills with scan severity and enforcement status |
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
| `mcp set <name> --command <cmd> [--connector X]` | Add/update an MCP server in the active connector config |
| `mcp unset <name> [--connector X]` | Remove an MCP server from the active connector config |
| `mcp block <url>` | Add an MCP server to the block list |
| `mcp allow <url>` | Add an MCP server to the allow list |

For `--connector opencode`, `mcp set` writes a command that OpenCode will
execute from `opencode.json`. DefenseClaw refuses commands that resolve
outside trusted install prefixes unless you add the directory to
`DEFENSECLAW_TRUSTED_BIN_PREFIXES` or pass `--force-untrusted-command` for
that one write.

### plugin

| Command | Description |
|---------|-------------|
| `plugin list` | List installed plugins |
| `plugin scan <name-or-path>` | Scan a plugin for security issues |
| `plugin install <name-or-path>` | Install a plugin from a local path |
| `plugin remove <name>` | Remove an installed plugin |

### registry

External skill / MCP catalog ingestion. See
[`docs/REGISTRIES.md`](./REGISTRIES.md) for the full pipeline.

| Command | Description |
|---------|-------------|
| `registry add <id>` | Register a new external catalog source (clawhub, smithery, skills_sh, http_yaml, http_json, git, file) |
| `registry edit <id>` | Update an existing source (only the flags you pass are changed) |
| `registry list` | List configured registry sources with cached `total (clean/warning/blocked)` entry counts |
| `registry show <id>` | Pretty-print one source plus its verdict summary |
| `registry remove <id>` | Delete a source and its on-disk cache |
| `registry test <id>` | Dry-run fetch + parse — no cache or asset_policy writes |
| `registry sync [<id>...] [--all]` | Fetch + scan + auto-promote clean entries into `asset_policy.{skill,mcp}.registry` |
| `registry entries <id> [--approved\|--rejected]` | Show cached entries (after sync); operator-override filters |
| `registry approve <id> <name> --type {skill\|mcp}` | Manually approve an entry |
| `registry reject <id> <name> --type {skill\|mcp}` | Manually reject an entry (sets status to `blocked`) |
| `registry require --type <t> --enabled/--disabled` | Toggle `asset_policy.<t>.registry_required` |
| `registry wizard` | Interactive add+sync convenience flow |
| `setup registry` | Wrapper for `registry wizard` so it shows up in `setup --help` |

All `registry` subcommands accept `--non-interactive` (skip prompts;
required flags must be present) and `--json` (stable machine-readable
output) so they're safe to call from the TUI and CI/CD pipelines.

### tool

| Command | Description |
|---------|-------------|
| `tool block <name> [--connector X] [--source S]` | Block a tool globally or for one connector |
| `tool allow <name> [--connector X] [--source S]` | Allow a tool globally or for one connector (runtime allow bypasses the scan gate for the matching connector scope) |
| `tool unblock <name> [--connector X]` | Remove a global or connector-scoped tool decision |
| `tool list [--connector X]` | List global decisions plus decisions that apply to a connector |
| `tool status <name> [--connector X]` | Show the effective block/allow status globally or for a connector |

`--connector` is the runtime enforcement scope. A scoped `tool block` or
`tool allow` applies only to calls attributed to that connector; omitting it
keeps the decision global. `--source` is audit/source metadata that records
where the decision came from, but it is not used as a runtime enforcement
selector.

Runtime allow semantics differ by lane. Hook/inspect calls still run CodeGuard
on allow-listed write tools before returning a clean allow. The sidecar stream
lane has no CodeGuard payload scanner, so a matching tool allow is a full scan
bypass on that lane.

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
| `codeguard status --connector <name> --target skill\|rule` | Inspect optional native CodeGuard assets |
| `codeguard install --connector <name> --target skill\|rule [--replace]` | Explicitly install a CodeGuard skill/rule asset |
| `codeguard install-skill` | Backward-compatible alias for `codeguard install --target skill` |

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
| `status` | Show health of the running sidecar's subsystems. On a multi-connector install it also renders a per-connector "Connector Mode" section from the `/status` endpoint's `connector_modes` array (one entry per active connector: `connector`, `mode`, `telemetry`, `proxy_intercept`). The `/status` payload also keeps the singular `connector_mode` field for the active connector as a back-compat alias. |

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
- `--allow-unverified` — unsafe override for releases whose checksum manifest
  is missing, unsigned, incomplete, or otherwise unverifiable

Signed releases can be upgraded on hosts without `cosign`; the command warns
and continues with SHA-256 checksum validation only. Install `cosign` to verify
Sigstore provenance in addition to checksums.

**Known recovery paths:**

| Installed version | Recommendation |
| --- | --- |
| `0.8.0` or `0.8.1` | These versions can require local `cosign` before the fixed wheel is installed. Install `cosign` first (`brew install cosign` on macOS) and then run plain `defenseclaw upgrade`, or use `defenseclaw upgrade --allow-unverified` only if you accept the reduced provenance check for that one bridge upgrade. |
| `0.7.x` | Upgrade directly to the latest release. Do not target `0.8.0`; that release had a broken migration-cache path. |
| `0.7.0` release tag | No downloadable release assets were published for this tag, so release-asset smoke cannot cover it. Upgrade from a locally installed `0.7.0` directly to the latest release. |
| `0.2.0` | This predates the `defenseclaw upgrade` command. Use the installer documented in `docs/INSTALL.md` to bridge to a modern release. |

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
