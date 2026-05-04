# Hook Event System

DefenseClaw uses hook events to intercept and inspect agent actions in real-time. Hook events are the primary mechanism for Claude Code and Codex connectors.

## Architecture

```
Agent (Claude Code/Codex)
    │
    ├─ Hook script triggered (shell)
    │       │
    │       ▼
    │   POST /api/v1/<connector>/hook
    │       │
    │       ▼
    │   Gateway evaluates event
    │       │
    │       ├─ Policy check (OPA)
    │       ├─ Content inspection
    │       ├─ PII redaction
    │       └─ Audit logging
    │       │
    │       ▼
    │   Response: allow / block / observe
    │
    ▼
Agent continues or halts
```

## Claude Code Hook Events

26 events registered in `~/.claude/settings.json` (source: `claudecode.go` hookGroups):

### Security-Critical (support blocking in action mode)

| Event | Trigger | Inspection | Timeout |
|-------|---------|------------|---------|
| `PreToolUse` | Before any tool execution | Tool policy, argument inspection, MCP asset detection | 30s |
| `UserPromptSubmit` | User sends a message | Injection detection, content inspection | 30s |
| `UserPromptExpansion` | Prompt expansion occurs | Content inspection | 30s |
| `PermissionRequest` | Agent requests elevated permissions | Permission policy evaluation, MCP asset detection | 30s |
| `SessionStart` | New conversation begins | Component scanning (skills, plugins, MCP) | 30s |

### Audit & Inspection (logged, content-inspected, blocking depends on mode)

| Event | Trigger | Purpose | Timeout |
|-------|---------|---------|---------|
| `PostToolUse` | After tool execution completes | Result inspection, MCP asset detection | 30s |
| `PostToolUseFailure` | Tool execution fails | Error tracking | 30s |
| `PostToolBatch` | Batch of tool calls completes | Aggregate audit, scan changed files | 90s |
| `PermissionDenied` | Permission was denied | Security audit | 30s |
| `SubagentStart` | Subagent spawned | Multi-agent tracking | 30s |
| `SubagentStop` | Subagent terminated | Multi-agent tracking, scan changed files | 90s |
| `Stop` | Session ends normally | CodeGuard scan of changed files | 90s |
| `StopFailure` | Session ends abnormally | Anomaly detection | 30s |
| `SessionEnd` | Session teardown | Session-end scanning | 60s |
| `InstructionsLoaded` | System instructions loaded | Instruction injection detection | 30s |
| `ConfigChange` | Runtime config modified | Config manipulation detection | 30s |
| `CwdChanged` | Working directory changed | Directory traversal tracking | 30s |
| `FileChanged` | File system modification | File mutation audit | 30s |
| `WorktreeRemove` | Git worktree removed | Cleanup tracking | 30s |
| `PreCompact` | Before context compaction | Context state capture | 30s |
| `PostCompact` | After context compaction | Context change audit | 30s |
| `TaskCreated` | Task created | Task lifecycle, content inspection | 30s |
| `TaskCompleted` | Task completed | Task lifecycle, content inspection | 30s |
| `TeammateIdle` | Multi-agent teammate idle | Coordination audit, content inspection | 30s |
| `Notification` | Informational notification | Low-priority audit | 30s |
| `Elicitation` | User interaction requested | Interaction tracking, content inspection | 30s |
| `ElicitationResult` | User interaction completed | Interaction tracking, content inspection | 30s |

## Codex Hook Events

5 events registered (source: `codex.go` hookGroups):

| Event | Trigger | Inspection | Timeout |
|-------|---------|------------|---------|
| `SessionStart` | New session begins | Component scanning | 30s |
| `UserPromptSubmit` | User sends prompt | Injection detection, content inspection | 30s |
| `PreToolUse` | Before tool execution | Tool policy, argument inspection, MCP asset detection | 30s |
| `PostToolUse` | After tool execution | Result inspection, MCP asset detection | 30s |
| `Stop` | Session ends | CodeGuard scan of changed files | 90s |

## Hook Script Location

Hook scripts are installed by `defenseclaw-gateway connector setup` into `~/.defenseclaw/hooks/`:

- Claude Code: `~/.defenseclaw/hooks/claude-code-hook.sh` (registered in `~/.claude/settings.json`)
- Codex: `~/.defenseclaw/hooks/codex-hook.sh` (registered in `~/.codex/config.toml`)
- Generic (all connectors): `inspect-tool.sh`, `inspect-request.sh`, `inspect-response.sh`, `inspect-tool-response.sh`

Scripts call the sidecar's hook endpoint with the event payload and return the verdict (allow/block) to the agent via exit code (0 = allow, 2 = block).

## Hook Hardening

Hook scripts include security hardening (`hooks/_hardening.sh`):
- `GIT_CONFIG_NOSYSTEM=1` — prevents git config injection
- Ephemeral `HOME` — isolates hook execution
- `ulimit` limits — resource constraints
- Allow-list regex — validates event payloads

## Configuration

```yaml
# config.yaml — per-connector hook behavior
claude_code:
  enabled: true
  scan_on_session_start: true
  fail_closed: false  # block if gateway unreachable

codex:
  enabled: true
  scan_on_session_start: true
```

## Guardrail Mode Behavior

| Mode | PreToolUse | UserPromptSubmit | Other Events |
|------|-----------|-----------------|--------------|
| `observe` | Log finding, allow (`WouldBlock=true`) | Log finding, allow | Audit only |
| `action` | Block if policy violated | Block if injection detected | Content inspection |

Mode is resolved per-connector: `guardrail.claude_code.mode` (or `guardrail.codex.mode`) falls back to `guardrail.mode` if set to `"inherit"` or empty.

## Hook Response Format

The gateway returns a JSON response to the hook script with the following structure:

```json
{
  "action": "allow|block|confirm|alert",
  "raw_action": "block",
  "severity": "HIGH",
  "reason": "Tool arguments contain injection pattern",
  "findings": ["CS-INJ-SQL-001"],
  "mode": "observe",
  "would_block": true,
  "claude_code_output": { ... }
}
```

**Hook-specific output** (Claude Code `PreToolUse` block):
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "reason": "Blocked by policy: injection detected"
  }
}
```

**Hook-specific output** (Codex `PermissionRequest` block):
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PermissionRequest",
    "decision": {"behavior": "deny", "message": "Blocked by DefenseClaw policy"}
  }
}
```

## MCP Asset Policy Integration

Hook events that involve tool calls are checked against MCP asset policies:

1. **MCP detection**: Tool name starts with `mcp__` or `mcp:`, or `MCPServerName` field is set
2. **Terminal MCP detection**: For bash/shell tools, content is checked for `mcp add`, `claude mcp add`, `codex mcp add` commands
3. **Policy lookup**: Detected MCP server checked against block/allow lists
4. **Verdict merge**: MCP policy verdict merged with content inspection verdict (highest severity wins)

Only `PreToolUse` and `PermissionRequest` events can enforce MCP blocks in action mode.

## Hook Fail Mode

Hook scripts support two fail modes (set via `DEFENSECLAW_FAIL_MODE` env var):

| Mode | Behavior on gateway unreachable |
|------|--------------------------------|
| `open` (default) | Allow the action, log failure to `~/.defenseclaw/logs/hook-failures.jsonl` |
| `closed` | Block the action (exit 2) |

The fail mode is configured per-connector via the `fail_closed` config field.
