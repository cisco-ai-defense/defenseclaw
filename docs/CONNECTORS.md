# Connector Setup Guide

DefenseClaw supports multiple AI agent frameworks via its connector architecture. Each connector adapts the sidecar to a specific agent runtime.

## Supported Connectors

| Connector | Agent Framework | LLM Routing | Tool Inspection | Hook Events | SubprocessPolicy |
|-----------|----------------|-------------|-----------------|-------------|-----------------|
| `openclaw` | OpenClaw | Fetch interceptor (X-DC-Target-URL header) | REST API (/api/v1/inspect/*) | N/A (plugin-based) | Sandbox |
| `claudecode` | Claude Code | ANTHROPIC_BASE_URL env var | Hook events (26 types) | SessionStart, PreToolUse, Stop, etc. | Sandbox |
| `codex` | Codex | OPENAI_BASE_URL env var | Hook events (5 types) | SessionStart, PreToolUse, PostToolUse, etc. | Sandbox |
| `zeptoclaw` | ZeptoClaw | api_base in config.json | Proxy-side response-scan | N/A (no vendor hooks by design) | Sandbox |

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

**Registered Hook Events (26 types):**
- SessionStart, InstructionsLoaded, UserPromptSubmit, UserPromptExpansion
- PreToolUse, PostToolUse, PostToolUseFailure, PostToolBatch
- PermissionRequest, PermissionDenied
- SubagentStart, SubagentStop
- Stop, StopFailure, SessionEnd
- ConfigChange, CwdChanged, FileChanged
- WorktreeRemove, PreCompact, PostCompact
- TaskCreated, TaskCompleted
- TeammateIdle, Notification
- Elicitation, ElicitationResult

```yaml
# config.yaml
claw:
  mode: claudecode
```

LLM routing: Sets `ANTHROPIC_BASE_URL=http://127.0.0.1:4000/c/claudecode`

### Codex

Config file: `~/.codex/config.toml`

Codex uses hook scripts similar to Claude Code but with fewer event types. Configuration is in TOML format with `[hooks]`, `[model_providers]`, and `[otel]` sections patched by setup.

**Registered Hook Events (5 types):**
- SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, Stop

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

## Authentication

Each connector implements `Authenticate(r *http.Request) bool` with connector-specific logic:

| Connector | Auth Method | Loopback Trust |
|-----------|-------------|----------------|
| OpenClaw | `X-DC-Auth` header or `Authorization: Bearer` (master key) | Trust if no token configured |
| Claude Code | `X-DC-Auth` header or `Authorization: Bearer` (master key) | Trust if no token configured |
| Codex | Loopback unconditionally allowed (native binary, no fetch interceptor) | Always trust loopback |
| ZeptoClaw | `X-DC-Auth` header, `Authorization: Bearer`, or provider API key match | Narrow loopback-allow on first boot only |

All token comparisons use constant-time comparison (`SecureTokenMatch`) to prevent timing attacks.

## Provider Probe

Each connector implements `ProviderProbe` — the gateway refuses to start with zero usable upstream providers unless `AllowEmptyProviders` is explicitly set:

| Connector | Probe Logic |
|-----------|-------------|
| OpenClaw | Returns 1 if gateway token or master key configured |
| Claude Code | Returns 1 if `ANTHROPIC_API_KEY` env or master key set |
| Codex | Counts providers with non-empty API key in config snapshot; falls back to `OPENAI_API_KEY` |
| ZeptoClaw | Counts providers with non-empty API key in config snapshot |

## Allowed Hosts

Each connector declares upstream hosts that should bypass firewall rules:

| Connector | Allowed Hosts |
|-----------|---------------|
| OpenClaw | `us.api.inspect.aidefense.security.cisco.com` |
| Claude Code | `claude.ai`, `docs.anthropic.com`, `console.anthropic.com`, `github.com`, `api.github.com`, `objects.githubusercontent.com` |
| Codex | `github.com`, `api.github.com`, `objects.githubusercontent.com`, `openai.com`, `platform.openai.com` |
| ZeptoClaw | `openrouter.ai`, `api.together.xyz` |

## Managed Backup System

Connector setup creates SHA256-tracked backups of all modified config files:

- **Location**: `~/.defenseclaw/connector_backups/<connector>/<logical_name>.json`
- **On Setup**: Original file bytes + SHA256 hash captured before patching
- **On Teardown**: If current file matches post-patch hash, pristine backup is restored
- **Drift detection**: If user edited the file after setup, teardown leaves it untouched

All config writes use `atomicWriteFile()` with advisory file locking (`withFileLock()`) to prevent corruption from concurrent access.

## CodeGuard Integration

Connectors that support component scanning install CodeGuard automatically during setup:

| Connector | CodeGuard Artifact | Install Location |
|-----------|-------------------|-----------------|
| Claude Code | `codeguard-security` plugin (from `cosai-oasis/project-codeguard`) | Installed via `claude plugin install` |
| Codex | `software-security` skill (cloned from GitHub) | `~/.codex/skills/software-security/` |

CodeGuard scans are triggered on `Stop` events (scan changed files since session start).

## ZeptoClaw Provider Routing

ZeptoClaw supports multiple upstream providers with model-prefix routing:

| Provider Prefix | Default Base URL |
|----------------|-----------------|
| `anthropic/` | `https://api.anthropic.com` |
| `openai/` | `https://api.openai.com/v1` |
| `openrouter/` | `https://openrouter.ai/api/v1` |
| `groq/` | `https://api.groq.com/openai/v1` |
| `deepseek/` | `https://api.deepseek.com` |
| `gemini/` | `https://generativelanguage.googleapis.com/v1beta` |
| `xai/` | `https://api.x.ai/v1` |
| `novita/` | `https://api.novita.ai/v3/openai` |

Model format: `"prefix/model-name"` (e.g., `"anthropic/claude-sonnet"`).
