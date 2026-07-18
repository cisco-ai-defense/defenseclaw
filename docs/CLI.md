# CLI Reference

DefenseClaw has two CLI binaries:

| Binary | Language | Install |
|--------|----------|---------|
| `defenseclaw` | Python (Click) | Signed installer; `make pycli` only in an isolated contributor checkout |
| `defenseclaw-gateway` | Go (Cobra) | Signed installer; `make gateway` only in an isolated contributor checkout |

The `make` targets are contributor tooling, not operator installation or
upgrade paths. Do not point raw `pip`, `uv`, editable-install, or package-copy
commands at a release-managed host or its `~/.defenseclaw/.venv`; those tools
cannot select a bridge, retain rollback custody, or prove fresh-process health.
Use the signed fresh installer on a new host and the authenticated release-owned
resolver below on an existing host.

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
| `setup galileo [status\|test\|enable\|disable\|remove]` | Configure real-time Galileo Cloud/self-hosted OTLP traces; test uses the live gateway path by default |
| `setup observability add\|list\|enable\|disable\|remove\|test` | Manage config-v8 OTLP, Galileo, Splunk HEC, JSONL, HTTP JSONL, console, and Prometheus destinations |
| `observability plan` | Show the masked effective v8 collection, local SQLite, destination capability/routes, redaction, retention, and warning plan |
| `setup local-observability up\|down\|status` | Manage the bundled OTel Collector + Grafana stack |

Observability destination names are identities: a new `--name` appends a route;
reusing a name updates only that route. Use `setup observability list [--json]`
for target/kind/signal inventory and `--dry-run` before `add`. The TUI exposes
the runtime-loaded inventory under **Overview → Observability Destinations** and
the management wizard under **0 Setup → Observability / Galileo**.

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
| `agent usage [--refresh] [--json] [--detail] [--state STATE] [--category CAT] [--product NAME] [--component NAME] [--show-gone] [--by-detector] [--limit N]` | Show continuous AI visibility inventory from the sidecar. The default view groups repeated observations of the same product, SDK/component, or local model and rolls their categories/detectors into compact list columns. Local-model rows display model ID, installed/loaded status, and format when available. `--detail` falls back to per-signal rows; `--state`/`--category`/`--product` filter the table; `--component` also matches local model IDs by case-insensitive substring; `gone` signals are hidden unless `--show-gone` (or `--state gone`) is passed; `--by-detector` restores detector-level rows; `--json` is the unfiltered raw payload for tooling. |
| `agent processes [--refresh] [--json] [--limit N]` | List AI processes the sidecar currently observes (PID, PPID, user, uptime, comm, vendor/product). Sourced from the `runtime` block on each process-detector signal. |
| `agent components [--refresh] [--json] [--ecosystem ECO] [--name NEEDLE] [--min-identity 0..1] [--min-presence 0..1] [--limit N]` | Show the deduped AI components/SDK rollup (one row per `(ecosystem, name)`) with versions, install counts, two-axis confidence (identity + presence) and the detector set. `--min-identity`/`--min-presence` filter on the Bayesian engine output for fast triage. |
| `agent components show NAME [--ecosystem ECO] [--json]` | Print every per-install location for one component: detector, state, workspace hash, basename, evidence quality, match kind, last-seen. Exported raw paths depend on the v8 field-class/redaction profile selected for that destination. |
| `agent components history NAME [--ecosystem ECO] [--limit N] [--json]` | Print the confidence trend (most-recent-first) for one component, sourced from the SQLite `ai_confidence_snapshots` history. |
| `agent confidence explain NAME [--ecosystem ECO] [--json]` | Print the per-evidence factor breakdown the engine used to compute identity + presence: detector, evidence id, match kind, quality, specificity/recency, likelihood ratio, log-odds delta, and the percentage-point shift each factor contributed. |
| `agent confidence policy show [--source merged\|default] [--json]` | Print the active confidence policy YAML. `merged` (default) is what the engine actually loaded; `default` is the embedded baseline so you can diff against your override. |
| `agent confidence policy default [--json]` | Print the embedded default policy — typically piped to `~/.defenseclaw/confidence_policy.yaml` as a starting point for an override. |
| `agent confidence policy validate PATH [--json]` | Dry-run a candidate policy file against the sidecar's loader + validator. Exits non-zero on failure with the same diagnostic the loader would print at boot. |
| `agent discovery enable [--mode] [--scan-roots] [--scan-interval-min N] [--process-interval-s N] [--max-files-per-scan N] [--max-file-bytes N] [--include-shell-history/--no-include-shell-history] [--include-package-manifests/--no-...] [--include-env-var-names/--no-...] [--include-network-domains/--no-...] [--allow-workspace-signatures/--no-...] [--store-raw-local-paths/--no-...] [--restart/--no-restart] [--scan/--no-scan] [--yes]` | Flip `ai_discovery.enabled=true`, save config, bounce the gateway, and trigger a first scan in one step. Re-running on an already-enabled install with new tuning flags applies the diff and bounces the sidecar (recorded as `ai_discovery-update` in canonical local history). |
| `agent discovery disable [--restart/--no-restart] [--yes]` | Flip `ai_discovery.enabled=false`, save config, and bounce the gateway so the service stops |
| `agent discovery setup [--restart/--no-restart] [--scan/--no-scan] [--yes]` | Walk an interactive wizard for every current `ai_discovery.*` knob (mode, scan/process intervals, scan roots, file caps, detection sources, and signature/path privacy). Destination routing is owned separately by observability v8. Each prompt defaults to the current config value so pressing Enter on every step is a no-op. |
| `agent discovery status [--json]` | Show on-disk + live AI discovery state and warn on drift between the two |
| `agent discovery scan [--json]` | Trigger one immediate AI discovery scan via the sidecar (`POST /api/v1/ai-usage/scan`) and render a one-line summary. Returns an actionable error when the sidecar is disabled (HTTP 503) pointing at `agent discovery enable`. |
| `agent signatures list \| validate \| install \| disable \| enable` | Manage AI discovery signature packs |

Continuous scans classify installed or loaded local models as `local_model` and
place the dynamic identity under a dedicated `model` block rather than the
bounded product/component fields. For example:

```bash
defenseclaw agent usage --category local_model
defenseclaw agent usage --component Qwen3
defenseclaw agent usage --category local_model --detail
```

The built-in [Lemonade Server configuration](https://lemonade-server.ai/docs/guide/configuration/)
signature recognizes its binaries/processes, app/config metadata, environment
variable names, and loopback service on port `13305`. Bounded reads of the
documented [`/v1/models`](https://lemonade-server.ai/docs/api/openai/) metadata
list downloaded models; `/v1/health` reports loaded models. Filesystem discovery
also covers GGUF/GGML, MLX, safetensors, ONNX/ORT, Core ML, TFLite, Q4NX, Hugging Face
caches, and Ollama stores. It stats and groups model artifacts but never reads
model-binary contents; small Ollama manifest JSON is the bounded exception.
Inference and model-control API routes are never called.

The local usage API retains model IDs for operator display and filtering.
Outbound canonical records follow each v8 destination's field-class redaction
profile. Normal discovery sanitization omits extended model metadata, model
basenames, and path hashes while retaining an installation-scoped HMAC lifecycle
pseudonym. Raw paths additionally require
`ai_discovery.store_raw_local_paths=true` and a selected v8 projection that
preserves the `path` field class. Authenticated Lemonade discovery uses
only `LEMONADE_API_KEY` after the configured origin passes a credential-free
`/live` check; it never sends `LEMONADE_ADMIN_API_KEY`, and credentials are never
printed or emitted. The API pass
caps each decoded response at 1 MiB and each pass at 256 model items; bounded
per-source cursors continue through larger inventories on later passes.

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
| `status` | Show health of the running sidecar's subsystems. It renders a per-connector "Connector Mode" section from the `/status` endpoint's `connector_modes` array, including the direct/proxy data path, `policy_mode`, `enforcement_surface`, telemetry channels, and proxy interception state. The payload keeps the legacy `mode` data-path value and singular `connector_mode` alias for compatibility. |

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

Downloads and verifies the gateway binary and Python CLI wheel from a GitHub
release, backs up managed state, runs release-manifest migrations, restarts
services, and verifies gateway health. No source checkout or build toolchain
is required.

> **Plugin installs are release-specific.** The OpenClaw plugin is installed
> by `install.sh` as part of the release that ships it (0.3.0+). `upgrade`
> does not touch the plugin.

**Upgrade steps:**

1. Detect the installed version and verify the target release contract before stopping anything.
2. If the contract names a bridge, either select it from the reviewed baseline matrix or refuse with the exact supported path.
3. Create durable, private rollback custody for the complete managed state and its pre-upgrade running/stopped status.
4. Install and health-check the bridge, then start the target phase in a fresh bridge controller process.
5. Install the target, run release-required migrations through the durable migration cursor, and restart services.
6. Report success only after version-bound health checks pass; otherwise restore and verify the exact source state.

Crossing the observability-v8 hard cut requires the `0.8.4` bridge. The
release-owned POSIX shell resolver performs the supported one-command path:

```text
reviewed 0.8.3-or-older source
    -> 0.8.4 bridge
    -> fresh 0.8.4 controller
    -> 0.8.5 hard cut
```

An already-published `0.8.3`-or-older built-in CLI cannot be taught this
two-process orchestration retroactively. Its protocol check therefore refuses
a hard-cut latest release before stopping services. Some frozen releases print
an obsolete raw-network shell hint after that safe refusal; it must not be
executed. Use the authenticated resolver-asset bootstrap below instead. A
current resolver treats `--version` as the selected final release and still
inserts every manifest-required bridge; the option never authorizes a direct
hard-cut install. The immutable `0.8.5` resolver predates that repair and must
be invoked without `--version` and with no exported `VERSION` value.

POSIX rollback retains any plan-owned inode that might still receive a late
open-descriptor write. The payload is placed in a plan-scoped, mode-0700
same-filesystem custody directory; the timestamped backup records its path in
`phase1-state/retained-quarantines.json`. Do not remove either one until the
restored release and any retained evidence have been inspected.

A first-hop bridge failure similarly restores the exact old gateway, whole
managed CLI environment, migration-touched state, prior running state, and
version-bound health before the resolver returns nonzero. A hard-cut failure
restores and health-checks the retained `0.8.4` CLI, gateway, config,
environment, cursor, and managed bundle before reporting rollback.

**Version-specific migrations** are defined in `cli/defenseclaw/migrations.py`
and run while an authenticated upgrade advances across the release boundary
that owns them. An authenticated same-version request is a no-op: it does not
reinstall artifacts or run migrations. Each migration is keyed to the release
it ships with. For example, the v0.3.0 migration removes
legacy `models.providers.defenseclaw`, `models.providers.litellm`, and
`agents.defaults.model.primary` prefixed entries from `openclaw.json` (written
by 0.2.0's guardrail setup) while preserving plugin registration.

The upgrade runner applies the required configuration-v8 observability migration
through the same release cursor. It converts supported v7 `otel`, `audit_sinks`,
SQLite/JSONL/console, Galileo, and global redaction settings into one validated
`observability` graph, preserving narrower effective collection/routing/privacy
behavior and local Agent360 compatibility. It backs up and atomically replaces
the source, promotes inline observability secrets to locked environment
references, refreshes owned local dashboard assets without resetting volumes,
and then checks health. No separate plan/apply step is required. The v8 gateway
does not rewrite v7 configuration at startup or run both formats in parallel;
a required migration failure restores the source and does not start v8 against
the v7 file.

**Flags:**
- `--yes`, `-y` — skip confirmation prompts
- `--version VERSION` — select a specific final release; required bridges are
  still staged (default: latest)
- `--allow-unverified` — legacy-only unsafe override. It cannot bypass the
  signed manifest, checksum, bridge, or migration requirements for `0.8.4+`.

`0.8.4+` upgrades require Cosign and the exact release-workflow identity. The
current POSIX resolver and the `0.8.5+` built-in controller prefer an existing
`cosign`; if it is missing, they download pinned Cosign `2.6.3` into an
owner-only temporary directory, verify its hard-coded platform SHA-256 before
execution, use it once, and remove it. They do not install it globally or alter
`PATH`. Any verifier download, digest, or signature failure occurs before
service stop or installed mutation. The immutable `0.8.4` built-in controller
also cannot parse the truthful hard-cut manifest because its Windows bridge
matrix is empty. Use the current target-release POSIX resolver on every
`0.8.4` host, regardless of whether Cosign is already installed.

**Known recovery paths:**

| Installed version | Recommendation |
| --- | --- |
| `0.8.4` | Run the current target-release POSIX resolver without `--version`; it authenticates a temporary pinned Cosign when needed and privately acquires exact `0.8.4` rollback artifacts before backup, service stop, or target mutation. The frozen built-in command cannot parse the truthful hard-cut manifest with `platform_tested_source_versions.windows: []`, even when Cosign is already on `PATH`. |
| A POSIX source listed for its platform in `release/upgrade-baselines.json` | Run the current release-owned shell resolver without `--version`. It authenticates a temporary verifier if needed and performs `source → 0.8.4 → fresh controller → latest` as one command. |
| `0.8.0` or `0.8.1` | Use the current release-owned POSIX resolver without `--version`; no system-wide Cosign installation is required. Do not use `--allow-unverified`; strict bridge provenance cannot be bypassed. |
| Any Windows source | The `0.8.4` release contains no Windows gateway/rollback binary, so no Windows hard-cut path is published. The PowerShell resolver fails closed before stopping services. Keep the current installation unchanged. |
| A source outside the published matrix, including assetless `0.7.0`, `0.2.x`, or historical `0.3.x` releases | No tested in-place path is inferred. Remain on the current version and contact support for a source-specific, state-aware recovery plan. Do not uninstall, overwrite state, or force an intermediate hop. |
| Direct installer from `0.8.3 → 0.8.5` | Refused before service stop or installed mutation. Manual artifact copying is unsupported because it bypasses bridge selection and rollback. Use the release-owned resolver; selecting a final version there does not bypass the bridge. |

**Examples:**

The bootstrap intentionally uses `releases/latest/download` to locate the
current resolver rather than the `0.8.4` bridge's older resolver. That URL is
only a locator: the signed checksum identity, exact resolver digest,
completeness marker, and syntax check authenticate the bytes before execution.

```bash
# POSIX: one-command staged resolver (do not add --version)
(
  set -eu
  unset VERSION
  umask 077
  d="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-upgrade.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  cosign_bin="$(command -v cosign || true)"
  if [ -z "$cosign_bin" ]; then
    platform="$(uname -s | tr '[:upper:]' '[:lower:]')/$(uname -m)"
    case "$platform" in
      darwin/x86_64) cosign_asset=cosign-darwin-amd64; cosign_sha=5715d61dd00a9b6dcb344de14910b434145855b7f82690b94183c553ac1b68be ;;
      darwin/arm64) cosign_asset=cosign-darwin-arm64; cosign_sha=ff497a698f125f3130b04f000b2cb0dd163bcaf00b5e776ef536035e6d0b3f3e ;;
      linux/x86_64|linux/amd64) cosign_asset=cosign-linux-amd64; cosign_sha=7c78a7f2efc00088bd788a758db6e0928e79f3e0eb83eb5d3c499ed98da4c4f4 ;;
      linux/aarch64|linux/arm64) cosign_asset=cosign-linux-arm64; cosign_sha=b7c23659a50a59fd8eec44b87188e9062157d0c87796cac7b38727e5390c4917 ;;
      *) echo "Unsupported platform for automatic Cosign verification" >&2; exit 1 ;;
    esac
    cosign_bin="$d/$cosign_asset"
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --max-filesize 209715200 --output "$cosign_bin" \
      "https://github.com/sigstore/cosign/releases/download/v2.6.3/$cosign_asset"
    if command -v sha256sum >/dev/null; then
      cosign_actual="$(sha256sum "$cosign_bin" | awk '{print $1}')"
    else
      cosign_actual="$(shasum -a 256 "$cosign_bin" | awk '{print $1}')"
    fi
    [ "$cosign_actual" = "$cosign_sha" ]
    chmod 700 "$cosign_bin"
  fi
  for name in defenseclaw-upgrade.sh checksums.txt checksums.txt.sig checksums.txt.pem; do
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --output "$d/$name" \
      "https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/$name"
  done
  "$cosign_bin" verify-blob \
    --certificate "$d/checksums.txt.pem" \
    --signature "$d/checksums.txt.sig" \
    --certificate-identity \
      'https://github.com/cisco-ai-defense/defenseclaw/.github/workflows/release.yaml@refs/heads/main' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    "$d/checksums.txt"
  line="$(grep -E '^[0-9a-f]{64}  defenseclaw-upgrade[.]sh$' "$d/checksums.txt")"
  [ "$(printf '%s\n' "$line" | wc -l | tr -d ' ')" = 1 ]
  expected="${line%% *}"
  if command -v sha256sum >/dev/null; then
    actual="$(sha256sum "$d/defenseclaw-upgrade.sh" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "$d/defenseclaw-upgrade.sh" | awk '{print $1}')"
  fi
  [ "$actual" = "$expected" ]
  [ "$(tail -n 1 "$d/defenseclaw-upgrade.sh")" = \
    '# DefenseClaw upgrade resolver complete v1' ]
  bash -n "$d/defenseclaw-upgrade.sh"
  bash "$d/defenseclaw-upgrade.sh" --yes
)
```

> **Windows hard-cut unavailable:** `0.8.4` intentionally published no
> Windows gateway or rollback binary, so there is no authenticated Windows
> bridge into `0.8.5`. The signed PowerShell resolver is a fail-closed refusal
> surface only. Keep the existing Windows installation unchanged until a
> future release publishes and tests an explicit supported path.

From a checkout of the current release, invoke the resolver in latest mode:

```bash
./scripts/upgrade.sh --yes
./scripts/upgrade.sh --plan
```

The release wheel, gateway archive, and local installers are not independent
upgrade mechanisms. `install.sh --local` and `install.ps1 -Local` refuse an
existing installation before dependency or artifact changes. Package-manager
replacement of the managed wheel and manual copying of release artifacts are
unsupported because they bypass bridge selection, rollback custody, and
post-upgrade health checks; use the release-owned resolver instead.

Protocol-2 releases expose their authenticated installable payloads only as
manifest-bound `.dcwheel` and `.dcgateway` envelopes. Those files are not
directly consumable by package or archive tools; the release-owned resolver
decodes them into private conventional files only after signature and digest
verification. Conventional release filenames contain signed refusal text, so
manual artifact URLs fail closed instead of silently bypassing the bridge.

### doctor

```
defenseclaw doctor [--json]
```

Runs connectivity and credential checks against all configured services
(sidecar, guardrail proxy, Cisco AI Defense, Splunk, scanners).
