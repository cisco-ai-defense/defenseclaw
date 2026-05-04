# Connector Setup Guide

DefenseClaw supports multiple AI agent frameworks via its connector architecture. Each connector adapts the sidecar to a specific agent runtime.

## Supported Connectors

| Connector | Agent Framework | LLM Routing | Tool Inspection | Hook Events |
|-----------|----------------|-------------|-----------------|-------------|
| `openclaw` | OpenClaw | Fetch interceptor (X-DC-Target-URL header) | REST API (/api/v1/inspect/*) | N/A (WebSocket) |
| `claudecode` | Claude Code | ANTHROPIC_BASE_URL env var | Hook events (20+ types) | PreToolUse, PostToolUse, SessionStart, Stop, etc. |
| `codex` | Codex | OPENAI_BASE_URL env var | Hook events (6 types) | SessionStart, UserPromptSubmit, PreToolUse, PermissionRequest, PostToolUse, Stop |
| `zeptoclaw` | ZeptoClaw | api_base in config.json | Config hooks (before_tool, before_request, after_response) | N/A |

## Installation with a Connector

```bash
# Install with specific connector
curl -LsSf .../install.sh | bash -s -- --connector claudecode

# Or specify during init
defenseclaw init --connector codex
```

## Connector-Specific Configuration

### OpenClaw (default)

Config file: `~/.openclaw/openclaw.json`

OpenClaw uses a TypeScript plugin (`extensions/defenseclaw/`) that:
- Intercepts all HTTP/HTTPS fetch calls via `globalThis.fetch` patching
- Routes LLM traffic through the guardrail proxy on port 4000
- Injects correlation headers (X-DefenseClaw-Agent-Id, etc.)
- Communicates with the sidecar via REST API for tool inspection

```yaml
# config.yaml
claw:
  mode: openclaw
  home_dir: ~/.openclaw
  config_file: ~/.openclaw/openclaw.json
```

### Claude Code

Config file: `~/.claude/settings.json`

Claude Code uses shell-based hooks registered in the Claude Code settings file. The sidecar handles hook events via POST /api/v1/claude-code/hook.

**Registered Hook Events (28 types):**
- SessionStart, InstructionsLoaded, UserPromptSubmit
- PreToolUse, PostToolUse, PostToolUseFailure, PostToolBatch
- PermissionRequest, PermissionDenied
- SubagentStart, SubagentStop
- Stop, StopFailure
- ConfigChange, CwdChanged, FileChanged
- WorktreeRemove, PreCompact, PostCompact
- TaskCreated, TaskCompleted
- TeammateIdle, Notification
- Setup, Elicitation, ElicitationResult

```yaml
# config.yaml
claw:
  mode: claudecode
```

LLM routing: Sets `ANTHROPIC_BASE_URL=http://127.0.0.1:4000/c/claudecode`

### Codex

Config file: `.codex/config.json`

Codex uses hook scripts similar to Claude Code but with fewer event types.

**Registered Hook Events (6 types):**
- SessionStart, UserPromptSubmit, PreToolUse
- PermissionRequest, PostToolUse, Stop

```yaml
# config.yaml
claw:
  mode: codex
```

LLM routing: Sets `OPENAI_BASE_URL=http://127.0.0.1:4000/c/codex`

### ZeptoClaw

Config file: `~/.zeptoclaw/config.json`

ZeptoClaw patches its `api_base` configuration to route through the guardrail proxy.

```yaml
# config.yaml
claw:
  mode: zeptoclaw
```

LLM routing: Patches `api_base: http://127.0.0.1:4000/c/zeptoclaw` in config.json

## Proxy Routing

Each connector uses a `/c/<connector-name>` URL prefix so the proxy can identify the source:

```
Claude Code  → ANTHROPIC_BASE_URL=http://proxy:4000/c/claudecode
Codex        → OPENAI_BASE_URL=http://proxy:4000/c/codex
ZeptoClaw    → api_base: http://proxy:4000/c/zeptoclaw
OpenClaw     → Fetch interceptor sets X-DC-Target-URL header
```

The proxy strips the prefix, identifies the connector, and applies connector-specific signal extraction.

## Connector Lifecycle

```bash
# Setup (runs during init or setup)
defenseclaw-gateway connector setup --connector claudecode

# Teardown (removes config patches)
defenseclaw-gateway connector teardown --connector claudecode

# Verify clean state
defenseclaw-gateway connector verify --connector claudecode

# List pristine backups
defenseclaw-gateway connector list-backups
```

## Switching Connectors

```bash
# Disable current guardrail (tears down active connector)
defenseclaw guardrail disable --yes

# Change connector in config
# Then re-enable with new connector
defenseclaw guardrail enable --yes
```

## Multi-Connector Mode

DefenseClaw supports running multiple connectors simultaneously:

```yaml
# config.yaml
guardrail:
  connectors: [claudecode, codex]
```

Each connector operates independently with its own hook registration and LLM routing.
