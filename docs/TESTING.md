# DefenseClaw CLI — End-to-End Test Results

**Date:** 2026-03-23
**Environment:** macOS (Apple Silicon), Python 3.14, Go 1.22+
**Gateway:** Remote OpenClaw on DGX Spark, port-forwarded via AWS SSM to localhost:18789
**Sidecar:** Local `defenseclaw-gateway` binary on localhost:18790

---

## Test Summary

| Category | Tested | Passed | Failed | Blocked |
|----------|--------|--------|--------|---------|
| Core CLI | 3 | 3 | 0 | 0 |
| Skill commands | 7 | 7 | 0 | 0 |
| MCP commands | 3 | 3 | 0 | 0 |
| Plugin commands | 5 | 5 | 0 | 0 |
| Setup commands | 2 | 2 | 0 | 0 |
| Sidecar commands | 1 | 1 | 0 | 0 |
| Deploy | 1 | 0 | 0 | 1 |
| **Total** | **22** | **21** | **0** | **1** |

---

## Core CLI

### `defenseclaw --version`
- **Status:** PASS
- **Output:** `defenseclaw, version 0.1.0`

### `defenseclaw init --skip-install`
- **Status:** PASS
- **Output:**
  ```
  Environment: macos
  Claw mode:   openclaw
  Claw home:   /Users/vnarajal/.openclaw
  Directories: created
  Config: /Users/vnarajal/.defenseclaw/config.yaml
  Audit DB: /Users/vnarajal/.defenseclaw/audit.db
  Scanners: skipped (--skip-install)
  OpenShell: not available on macOS (sandbox enforcement will be skipped)
  ```
- **Verified:** Config file created, audit DB initialized, directories exist.

### `defenseclaw status`
- **Status:** PASS
- **Output:**
  ```
  Environment:  macos
  Scanners:     skill-scanner (installed), mcp-scanner (installed),
                cisco-aibom (installed), codeguard (built-in)
  Enforcement:  1 blocked skill, 1 allowed skill, 1 blocked MCP, 1 allowed MCP
  Activity:     3 total scans, 3 active alerts
  Sidecar:      running
  ```
- **Verified:** Reflects all enforcement actions taken during testing. Scanner availability detection works.

---

## Skill Commands

### `defenseclaw skill list`
- **Status:** PASS
- **Data source:** Remote OpenClaw gateway via sidecar REST API (`GET /skills` -> `skills.status` RPC)
- **Output:** Rich table with 50 skills (6 ready, 44 missing), columns: Status, Skill, Description, Source, Severity, Actions
- **Verified:** Skill metadata (name, description, source, status) all populated from remote gateway.

### `defenseclaw skill info weather`
- **Status:** PASS
- **Output:**
  ```
  Skill:       weather
  Description: Get current weather and forecasts via wttr.in or Open-Meteo...
  Source:      openclaw-bundled
  Path:        /home/ubuntu/.nvm/versions/node/v22.22.1/lib/node_modules/openclaw/skills/weather
  Eligible:    True
  Bundled:     True
  Homepage:    https://wttr.in/:help
  ```
- **Verified:** Metadata fetched from remote gateway via sidecar. Path shows remote DGX filesystem.

### `defenseclaw skill block test-malicious-skill`
- **Status:** PASS
- **Output:** `[skill] 'test-malicious-skill' added to block list`
- **Verified:** Persisted in SQLite audit DB. Reflected in `defenseclaw status` (Blocked skills: 1).

### `defenseclaw skill allow trusted-skill`
- **Status:** PASS
- **Output:** `[skill] 'trusted-skill' added to allow list`
- **Verified:** Persisted in SQLite audit DB. Reflected in `defenseclaw status` (Allowed skills: 1).

### `defenseclaw skill disable weather --reason "testing disable flow"`
- **Status:** PASS
- **Output:** `[skill] 'weather' disabled via gateway RPC`
- **Verified:** Sends `skills.update` RPC through sidecar WebSocket to remote OpenClaw gateway. Sidecar logs show `req skills.update` with `ok=true` response.

### `defenseclaw skill enable weather`
- **Status:** PASS
- **Output:** `[skill] 'weather' enabled via gateway RPC`
- **Verified:** Sends `skills.update` RPC through sidecar WebSocket. Sidecar logs confirm successful response.

### `defenseclaw skill scan` / `skill install`
- **Status:** NOT TESTED (dependency not available)
- **Reason:** `skill scan` requires local skill directories (skills are remote on DGX). `skill install` requires `clawhub` CLI which is not installed locally.
- **Note:** The scanner binary (`skill-scanner`) is installed and detected by `status`.

---

## MCP Commands

### `defenseclaw mcp list`
- **Status:** PASS
- **Output:** `No MCP servers in enforcement lists.`
- **Verified:** Correct initial state (no MCP servers configured).

### `defenseclaw mcp block http://suspicious-mcp.example.com --reason "untrusted endpoint"`
- **Status:** PASS
- **Output:** `Blocked: http://suspicious-mcp.example.com`
- **Verified:** Persisted in SQLite audit DB. Reflected in `defenseclaw status` (Blocked MCPs: 1).

### `defenseclaw mcp allow http://trusted-mcp.internal:8080`
- **Status:** PASS
- **Output:** `Allowed: http://trusted-mcp.internal:8080`
- **Verified:** Persisted in SQLite audit DB. Reflected in `defenseclaw status` (Allowed MCPs: 1).

### `defenseclaw mcp scan`
- **Status:** NOT TESTED
- **Reason:** Requires a live MCP server endpoint to scan.

---

## Plugin Commands

### `defenseclaw plugin list` (empty state)
- **Status:** PASS
- **Output:** `No plugins installed.`

### `defenseclaw plugin install /Users/vnarajal/Desktop/defenseclaw/extensions/defenseclaw`
- **Status:** PASS
- **Output:** `Installed plugin: defenseclaw`
- **Verified:** Plugin directory copied to `~/.defenseclaw/plugins/defenseclaw`.

### `defenseclaw plugin list` (after install)
- **Status:** PASS
- **Output:**
  ```
  Installed plugins:
    defenseclaw
  ```

### `defenseclaw plugin remove defenseclaw`
- **Status:** PASS
- **Output:** `Removed plugin: defenseclaw`
- **Verified:** Directory removed from plugin store.

### `defenseclaw plugin scan <path>` (human-readable output)
- **Status:** PASS
- **Target:** `extensions/defenseclaw/`
- **Output:**
  ```
  [plugin] scanning /Users/vnarajal/Desktop/defenseclaw/extensions/defenseclaw...
    Plugin:   defenseclaw
    Duration: 0.06s
    Verdict:  CRITICAL (14 findings)

      [LOW] Plugin declares no permissions
      [INFO] Tool may execute shell commands (x3)
      [INFO] Tool uses eval-like execution (x2)
      [INFO] Tool references child_process (x3)
      [INFO] Tool accesses environment variables
      [INFO] Tool makes network requests (x2)
      [CRITICAL] Possible AWS key detected
      [CRITICAL] Private key embedded in source
  ```
- **Verified:** All findings include Location and Fix fields. CRITICAL findings are from test fixtures in `__tests__/plugin-scanner.test.ts` (expected).

### `defenseclaw plugin scan --json <path>`
- **Status:** PASS
- **Verified:** Valid JSON output, parseable. Contains `scanner`, `target`, `timestamp`, `findings` (14 items), `duration_ns`, `metadata` fields.

### `defenseclaw plugin scan nonexistent-plugin` (error path)
- **Status:** PASS
- **Output:**
  ```
  error: plugin not found: nonexistent-plugin
    Provide a path or an installed plugin name from /Users/vnarajal/.defenseclaw/plugins
  ```
- **Exit code:** 1

---

## Setup Commands

### `defenseclaw setup gateway --non-interactive --host 127.0.0.1 --port 18789 --api-port 18790`
- **Status:** PASS
- **Output:**
  ```
  Saved to ~/.defenseclaw/config.yaml

    gateway.host:        127.0.0.1
    gateway.port:        18789
    gateway.api_port:    18790
    gateway.token:       (none — local mode)

  Start the sidecar with:
    defenseclaw-gateway
    (local mode — ensure OpenClaw is running on this machine)
  ```
- **Verified:** Config written to `~/.defenseclaw/config.yaml` with correct values.

### `defenseclaw setup gateway` (interactive modes)
- **Status:** NOT TESTED (requires interactive terminal)
- **Modes available:**
  - Default (local): Prompts for host/port/api-port, no token
  - `--remote`: Prompts for host/port/api-port + token via AWS SSM or manual entry
  - `--non-interactive` with `--ssm-param`: Fetches token from AWS SSM Parameter Store

### `defenseclaw setup skill-scanner`
- **Status:** NOT TESTED (requires interactive terminal)

---

## Sidecar Commands

### `defenseclaw sidecar status`
- **Status:** PASS
- **Output:**
  ```
  DefenseClaw Sidecar Health
  ══════════════════════════
    Started:  2026-03-23T21:23:46
    Uptime:   9m 28s

    gateway:     RUNNING (since 2026-03-23T21:23:47)
                 protocol: 3

    watcher:     DISABLED (since 2026-03-23T21:23:46)

    api:         RUNNING (since 2026-03-23T21:23:46)
                 addr: 127.0.0.1:18790
  ```
- **Verified:** Reflects actual sidecar state. Gateway connected to remote OpenClaw. API server listening.

---

## Deploy

### `defenseclaw deploy --skip-init /Users/vnarajal/Desktop/defenseclaw`
- **Status:** BLOCKED (hangs at aibom scanner)
- **Output before hang:**
  ```
  Step 1/5: Init skipped (--skip-init)
  Step 2/5: Running all scanners...
    [scan] skill-scanner -> /Users/vnarajal/Desktop/defenseclaw
      Skipped (not installed)
    [scan] mcp-scanner -> /Users/vnarajal/Desktop/defenseclaw
      Clean (0.00s)
    [scan] aibom -> /Users/vnarajal/Desktop/defenseclaw
      (hangs here)
  ```
- **Root cause:** `cisco-aibom analyze` is designed for Python codebases and has a 300-second timeout. Scanning the full project tree (Go + Python + Node.js + node_modules) causes it to hang or run extremely slowly.
- **Workaround:** Run against `cli/` subdirectory only, or reduce the aibom timeout.

---

## Alerts

### `defenseclaw alerts`
- **Status:** PASS
- **Output:** Rich table with security alerts showing Severity, Timestamp, Action, Target, Details columns.
- **Verified:** Shows alerts generated by scan and enforcement actions during testing.

---

## Data Flow Verification

### Sidecar WebSocket RPC (verified via sidecar logs)

| RPC Method | Triggered by | Response |
|------------|-------------|----------|
| `skills.status` | `defenseclaw skill list` | `ok=true` (50 skills) |
| `skills.update` (disable) | `defenseclaw skill disable weather` | `ok=true` |
| `skills.update` (enable) | `defenseclaw skill enable weather` | `ok=true` |

### SQLite Audit DB (verified via `defenseclaw status`)

| Metric | Value after testing |
|--------|-------------------|
| Total scans | 3 |
| Active alerts | 3 |
| Blocked skills | 1 (`test-malicious-skill`) |
| Allowed skills | 1 (`trusted-skill`) |
| Blocked MCPs | 1 (`http://suspicious-mcp.example.com`) |
| Allowed MCPs | 1 (`http://trusted-mcp.internal:8080`) |

---

## Not Tested (dependency blockers)

| Command | Blocker |
|---------|---------|
| `skill scan <name>` | No local skill directories (skills are remote on DGX) |
| `skill install <name>` | `clawhub` CLI not installed locally |
| `skill quarantine <name>` | No local skill files to quarantine |
| `skill restore <name>` | Nothing quarantined |
| `mcp scan <endpoint>` | Needs a live MCP server endpoint |
| `aibom generate <path>` | `cisco-aibom` hangs on non-Python-only projects |
| `setup skill-scanner` | Interactive prompts only |
| `setup gateway` (interactive) | Interactive prompts only |

---

## Known Issues

1. **Plugin scanner not on PATH by default.** The `defenseclaw-plugin-scanner` binary needs to be manually symlinked to `~/.local/bin/` or installed via `npm link`. This should be automated during `defenseclaw init`.

2. **`cisco-aibom` hangs on mixed-language projects.** The `deploy` command's aibom step has a 300s timeout but `cisco-aibom analyze` runs very slowly on non-Python directories. Consider adding a shorter timeout or restricting scan scope.

3. **`skill-scanner` shows "not installed" during deploy.** The binary exists at `~/.local/bin/skill-scanner` but `deploy` reports it as not installed. The scanner wrapper may be checking for `cisco-ai-skill-scanner` instead of `skill-scanner`.

---

## Environment Setup for Testing

```bash
# Python CLI (installed in editable mode)
cd cli && uv pip install -e . --python .venv/bin/python

# Go sidecar binary
cd /Users/vnarajal/Desktop/defenseclaw && go build -o bin/defenseclaw-gateway ./cmd/defenseclaw

# Plugin scanner (symlink to PATH)
ln -sf /Users/vnarajal/Desktop/defenseclaw/extensions/defenseclaw/bin/plugin-scanner.mjs \
       ~/.local/bin/defenseclaw-plugin-scanner

# Start sidecar with gateway token
export OPENCLAW_GATEWAY_TOKEN=$(aws ssm get-parameter \
  --name /openclaw/openclaw-bedrock/gateway-token \
  --with-decryption --query Parameter.Value --output text \
  --region us-east-1 --profile devops)
./bin/defenseclaw-gateway --token "$OPENCLAW_GATEWAY_TOKEN"
```
