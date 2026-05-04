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

28 events registered in `~/.claude/settings.json`:

### Security-Critical (support blocking in action mode)

| Event | Trigger | Inspection |
|-------|---------|------------|
| `PreToolUse` | Before any tool execution | Tool policy, argument inspection, sensitive path check |
| `UserPromptSubmit` | User sends a message | Injection detection, content inspection |
| `PermissionRequest` | Agent requests elevated permissions | Permission policy evaluation |
| `SessionStart` | New conversation begins | Component scanning (skills, plugins, MCP) |

### Audit-Only (logged but not blocked)

| Event | Trigger | Purpose |
|-------|---------|---------|
| `PostToolUse` | After tool execution completes | Result inspection, audit trail |
| `PostToolUseFailure` | Tool execution fails | Error tracking |
| `PostToolBatch` | Batch of tool calls completes | Aggregate audit |
| `PermissionDenied` | Permission was denied | Security audit |
| `SubagentStart` | Subagent spawned | Multi-agent tracking |
| `SubagentStop` | Subagent terminated | Multi-agent tracking |
| `Stop` | Session ends normally | CodeGuard scan of changed files |
| `StopFailure` | Session ends abnormally | Anomaly detection |
| `InstructionsLoaded` | System instructions loaded | Instruction injection detection |
| `ConfigChange` | Runtime config modified | Config manipulation detection |
| `CwdChanged` | Working directory changed | Directory traversal tracking |
| `FileChanged` | File system modification | File mutation audit |
| `WorktreeRemove` | Git worktree removed | Cleanup tracking |
| `PreCompact` | Before context compaction | Context state capture |
| `PostCompact` | After context compaction | Context change audit |
| `TaskCreated` | Task created | Task lifecycle |
| `TaskCompleted` | Task completed | Task lifecycle |
| `TeammateIdle` | Multi-agent teammate idle | Coordination audit |
| `Notification` | Informational notification | Low-priority audit |
| `Setup` | Session initialization | Bootstrap audit |
| `Elicitation` | User interaction requested | Interaction tracking |
| `ElicitationResult` | User interaction completed | Interaction tracking |

## Codex Hook Events

6 events registered:

| Event | Trigger | Inspection |
|-------|---------|------------|
| `SessionStart` | New session begins | Component scanning |
| `UserPromptSubmit` | User sends prompt | Injection detection |
| `PreToolUse` | Before tool execution | Tool policy, argument inspection |
| `PermissionRequest` | Permission escalation | Permission policy |
| `PostToolUse` | After tool execution | Result inspection |
| `Stop` | Session ends | CodeGuard scan of changed files |

## Hook Script Location

Hook scripts are installed by `defenseclaw-gateway connector setup`:

- Claude Code: `~/.claude/hooks/defenseclaw/`
- Codex: `~/.codex/hooks/defenseclaw/`

Scripts call the sidecar's hook endpoint with the event payload and return the verdict (allow/block) to the agent.

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
| `observe` | Log finding, allow | Log finding, allow | Audit only |
| `action` | Block if policy violated | Block if injection detected | Audit only |
