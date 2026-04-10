# LLM Guardrail — Data Flow & Architecture

The LLM guardrail intercepts all traffic between agent frameworks and LLM
providers. It uses a **connector-based architecture** where each agent
framework (OpenClaw, ZeptoClaw, future frameworks) has a dedicated Connector
that translates its request format into a canonical `RoutingDecision` the
proxy core processes uniformly.

The Go guardrail reverse proxy (`internal/gateway/proxy.go`,
`internal/gateway/guardrail.go`) inspects every prompt and response without
requiring changes to agent code.

## Connector Architecture

```
                    +----------------------------------+
                    |   Agent Framework                |
                    |  (OpenClaw / ZeptoClaw / Future) |
                    +---------------+------------------+
                                    | HTTP POST
                                    v
                    +----------------------------------+
                    |   GuardrailProxy HTTP Server      |
                    +---------------+------------------+
                                    |
                           +--------v--------+
                           | ConnectorRouter  |
                           | (auto-detect)    |
                           +--------+--------+
                            /       |        \
                  +---------+ +-----+-----+ +----------+
                  | OpenClaw| | ZeptoClaw | | Generic  |
                  |Connector| | Connector | |Connector |
                  +---------+ +-----------+ +----------+
                         \        |        /
                          +-------v------+
                          |RoutingDecision|  (canonical form)
                          +-------+------+
                                  |
                  +---------------v----------------+
                  |         Proxy Core              |
                  | 1. Inspect input (rules/judge)  |
                  | 2. Resolve LLMProvider adapter   |
                  | 3. Forward to upstream          |
                  | 4. Inspect output               |
                  | 5. Return response              |
                  +--------------------------------+
```

**Detection order**: OpenClaw (has `X-DC-Target-URL`) → ZeptoClaw (has `X-ZC-Provider` or standard auth without `X-DC-Target-URL`) → Generic (fallback).

### Connector Interface

Each connector implements (`internal/gateway/connector/connector.go`):

| Method | Purpose |
|--------|---------|
| `Name()` | Canonical name for telemetry (`"openclaw"`, `"zeptoclaw"`, `"generic"`) |
| `Detect(r)` | Does this request belong to this connector? First match wins |
| `Authenticate(r)` | Is the request authorized? (token, master key, or loopback trust) |
| `Route(r, body)` | Produce a `RoutingDecision` with upstream URL, provider, API key, etc. |

### RoutingDecision (canonical form)

Every connector produces a `RoutingDecision` containing:
- `UpstreamURL` — full upstream URL (e.g. `https://api.openai.com/v1/chat/completions`)
- `ProviderName` — canonical name: `"openai"`, `"anthropic"`, `"azure"`, etc.
- `APIKey`, `AuthHeader`, `AuthScheme` — upstream auth details
- `Model`, `Stream`, `RawBody` — request metadata
- `PassthroughMode` — forward verbatim (provider-native paths like Anthropic `/v1/messages`)
- `ExtraUpstreamHeaders` — additional headers (e.g., `anthropic-version`)
- `ConnectorName` — source connector for telemetry attribution

## OpenClaw Connector

**File**: `internal/gateway/connector/openclaw.go`

Uses the TypeScript fetch interceptor plugin (running inside OpenClaw's
Node.js process) that patches `globalThis.fetch`, routing all outbound LLM
calls through `localhost:4000`.

### Why a Fetch Interceptor?

OpenClaw's `message_sending` plugin hook is broken (issue #26422) — outbound
messages never fire, making plugin-only interception impossible for LLM
responses. Additionally, configuring a single proxy provider in
`openclaw.json` only covers one model — switching to any other provider
bypasses the proxy entirely.

### Auth Design (three-header contract)

The interceptor sets three headers on every proxied request:

```
X-DC-Target-URL: https://api.anthropic.com  ← original upstream URL
X-AI-Auth:       Bearer sk-ant-*            ← real provider key (captured from SDK header)
X-DC-Auth:       Bearer <sidecar-token>     ← proxy authorization token
```

`X-AI-Auth` is extracted from whichever header the provider SDK uses:
- `Authorization: Bearer` — OpenAI, OpenRouter, Gemini compat
- `x-api-key` — Anthropic
- `api-key` — Azure OpenAI
- Query param `?key=` — Gemini native (passed through URL, not header)
- AWS SigV4 — Bedrock (multiple headers, pass-through)
- No auth — Ollama

| Aspect | Implementation |
|--------|---------------|
| **Detect** | `X-DC-Target-URL` header present |
| **Authenticate** | `X-DC-Auth` token → master key (`sk-dc-*`) → loopback trust → open proxy |
| **Route** | Extract `X-DC-Target-URL` → upstream URL, `X-AI-Auth` → API key, infer provider from URL domain via `providers.json`, SSRF check |

### Providers Covered

| Provider | Interception | Format |
|----------|-------------|--------|
| Anthropic | api.anthropic.com | /v1/messages (passthrough) |
| OpenAI | api.openai.com | /v1/chat/completions |
| OpenRouter | openrouter.ai | /api/v1/chat/completions |
| Azure OpenAI | *.openai.azure.com | /openai/v1/responses + /chat/completions |
| Gemini | generativelanguage.googleapis.com | OpenAI-compatible |
| Ollama | localhost:11434 | Pass-through (no key needed) |
| Bedrock | *.amazonaws.com | AWS SigV4 pass-through |

## ZeptoClaw Connector

**File**: `internal/gateway/connector/zeptoclaw.go`

Handles requests from ZeptoClaw, a Rust-based agent framework that sends
standard HTTP with no DefenseClaw-specific headers. ZeptoClaw's `api_base`
config is patched to redirect traffic through the proxy.

| Aspect | Implementation |
|--------|---------------|
| **Detect** | `X-ZC-Provider` header present, OR (`X-DC-Target-URL` absent AND standard auth header present) |
| **Authenticate** | `X-DC-Auth` token → master key → loopback trust → open proxy |
| **Route** | Resolve provider from `X-ZC-Provider` → model prefix inference → `provider/model` format. Upstream URL from `X-ZC-Upstream` → config map → embedded defaults table |

### Provider Inference from Model Name

```
"gpt-4o"                    → openai
"claude-sonnet-4-20250514"  → anthropic
"gemini-1.5-pro"            → gemini
"anthropic/claude-3-haiku"  → anthropic (explicit prefix)
"command-r-plus"            → cohere
"deepseek-chat"             → deepseek
```

### Upstream URL Resolution

Since ZeptoClaw replaces the real URL with `api_base: "http://127.0.0.1:4000"`,
the connector reconstructs the original upstream:

1. `X-ZC-Upstream` header (if ZeptoClaw sends it — optional)
2. Config `providers` map (populated by `defenseclaw setup guardrail --claw zeptoclaw`)
3. Embedded default table (`zeptoclaw_defaults.go` — 19 providers)

### Embedded Default Provider Table

Mirrored from ZeptoClaw's `PROVIDER_REGISTRY` — covers OpenAI, Anthropic,
OpenRouter, Groq, Gemini, Ollama, NVIDIA, DeepSeek, Azure, Bedrock, xAI,
and more. See `internal/gateway/connector/zeptoclaw_defaults.go`.

## Generic / Fallback Connector

**File**: `internal/gateway/connector/generic.go`

Same model-based provider inference as ZeptoClaw but with relaxed auth
(always authenticates). Serves as fallback for curl testing, future
frameworks, or any OpenAI-compatible client.

## Data Flow

### Connector Router Flow

```
 ┌──────────────┐     ┌─────────────────────┐     ┌────────────────────┐     ┌──────────────┐
 │  Agent        │     │  ConnectorRouter    │     │   Proxy Core       │     │  LLM Provider│
 │  Framework    │     │  (auto-detect)      │     │  (inspect+forward) │     │              │
 └──────┬───────┘     └──────────┬──────────┘     └──────────┬─────────┘     └──────┬───────┘
        │                        │                           │                      │
        │  POST /v1/chat/...     │                           │                      │
        ├───────────────────────►│                           │                      │
        │                        │                           │                      │
        │                  Detect: which connector?          │                      │
        │                  Authenticate: authorized?         │                      │
        │                  Route: → RoutingDecision          │                      │
        │                        │                           │                      │
        │                        ├──────────────────────────►│                      │
        │                        │                           │                      │
        │                        │            PRE-CALL scan  │                      │
        │                        │                           ├─────────────────────►│
        │                        │                           │◄─────────────────────┤
        │                        │            POST-CALL scan │                      │
        │                        │                           │                      │
        │  Response              │◄──────────────────────────┤                      │
        │◄───────────────────────┤                           │                      │
```

### OpenClaw Fetch Interceptor Flow

```
 ┌──────────────┐     ┌─────────────────────┐     ┌────────────────────┐     ┌──────────────┐
 │   OpenClaw    │     │  Fetch Interceptor  │     │   Guardrail Proxy  │     │  LLM Provider│
 │   Agent       │     │  (in-process plugin)│     │  (localhost:4000)  │     │              │
 └──────┬───────┘     └──────────┬──────────┘     └──────────┬─────────┘     └──────┬───────┘
        │                        │                           │                      │
        │  fetch(provider_url)   │                           │                      │
        ├───────────────────────►│                           │                      │
        │                        │                           │                      │
        │                        │  Redirects to localhost   │                      │
        │                        │  + adds X-AI-Auth header  │                      │
        │                        │  + adds X-DC-Target-URL   │                      │
        │                        ├──────────────────────────►│                      │
        │                        │                           │                      │
        │                        │     OpenClaw connector    │                      │
        │                        │     detects + routes      │                      │
        │                        │            PRE-CALL scan  │                      │
        │                        │                           ├─────────────────────►│
        │                        │                           │◄─────────────────────┤
        │                        │            POST-CALL scan │                      │
        │                        │                           │                      │
        │  Response              │◄──────────────────────────┤                      │
        │◄───────────────────────┤                           │                      │
```

### ZeptoClaw Flow

```
 ┌──────────────┐                ┌────────────────────┐     ┌──────────────┐
 │   ZeptoClaw   │                │   Guardrail Proxy  │     │  LLM Provider│
 │   Agent       │                │  (localhost:4000)  │     │              │
 └──────┬───────┘                └──────────┬─────────┘     └──────┬───────┘
        │                                   │                      │
        │  POST /v1/chat/completions        │                      │
        │  Authorization: Bearer sk-key     │                      │
        │  (api_base patched to proxy)      │                      │
        ├──────────────────────────────────►│                      │
        │                                   │                      │
        │                  ZeptoClaw connector detects              │
        │                  Infers provider from model name         │
        │                  Resolves upstream from config/defaults  │
        │                  → RoutingDecision                       │
        │                                   │                      │
        │                     PRE-CALL scan │                      │
        │                                   ├─────────────────────►│
        │                                   │◄─────────────────────┤
        │                    POST-CALL scan │                      │
        │                                   │                      │
        │  Response                         │                      │
        │◄──────────────────────────────────┤                      │
```

### Normal Request (observe mode, clean)

```
 ┌──────────────┐     ┌────────────────────────────────┐     ┌──────────────┐
 │   OpenClaw    │     │         Guardrail Proxy           │     │  Anthropic   │
 │   Agent       │     │       (localhost:4000)           │     │  API         │
 └──────┬───────┘     └──────────────┬─────────────────┘     └──────┬───────┘
        │                            │                              │
        │  POST /v1/chat/completions │                              │
        │  (OpenAI format)           │                              │
        ├───────────────────────────►│                              │
        │                            │                              │
        │               ┌───────────┴───────────┐                  │
        │               │  PRE-CALL guardrail    │                  │
        │               │                        │                  │
        │               │  1. Extract messages   │                  │
        │               │  2. Scan for:          │                  │
        │               │     - injection        │                  │
        │               │     - secrets/PII      │                  │
        │               │     - exfiltration     │                  │
        │               │  3. Verdict: CLEAN     │                  │
        │               │  4. Log to stdout      │                  │
        │               └───────────┬───────────┘                  │
        │                            │                              │
        │                            │  Forward (translated to      │
        │                            │  Anthropic Messages API)     │
        │                            ├─────────────────────────────►│
        │                            │                              │
        │                            │  Response                    │
        │                            │◄─────────────────────────────┤
        │                            │                              │
        │               ┌───────────┴───────────┐                  │
        │               │  POST-CALL guardrail   │                  │
        │               │                        │                  │
        │               │  1. Extract content    │                  │
        │               │  2. Extract tool calls │                  │
        │               │  3. Scan response      │                  │
        │               │  4. Verdict: CLEAN     │                  │
        │               │  5. Log to stdout      │                  │
        │               └───────────┬───────────┘                  │
        │                            │                              │
        │  Response (OpenAI format)  │                              │
        │◄───────────────────────────┤                              │
        │                            │                              │
```

### Flagged Request (action mode, blocked)

```
 ┌──────────────┐     ┌────────────────────────────────┐     ┌──────────────┐
 │   OpenClaw    │     │         Guardrail Proxy           │     │  Anthropic   │
 │   Agent       │     │       (localhost:4000)           │     │  API         │
 └──────┬───────┘     └──────────────┬─────────────────┘     └──────┬───────┘
        │                            │                              │
        │  POST /v1/chat/completions │                              │
        │  (contains "ignore all     │                              │
        │   previous instructions")  │                              │
        ├───────────────────────────►│                              │
        │                            │                              │
        │               ┌───────────┴───────────┐                  │
        │               │  PRE-CALL guardrail    │                  │
        │               │                        │                  │
        │               │  1. Scan messages      │                  │
        │               │  2. MATCH: injection   │                  │
        │               │  3. Verdict: HIGH      │                  │
        │               │  4. Mode = action      │                  │
        │               │  5. Set mock_response   │                  │
        │               └───────────┬───────────┘                  │
        │                            │                              │
        │                            │  (request never forwarded)   │
        │                            │                              │
        │  HTTP 200 / mock response  │                              │
        │  "I'm unable to process    │                              │
        │   this request..."         │                              │
        │◄───────────────────────────┤                              │
        │                            │                              │
```

### Flagged Response (observe mode, logged only)

```
 ┌──────────────┐     ┌────────────────────────────────┐     ┌──────────────┐
 │   OpenClaw    │     │         Guardrail Proxy           │     │  Anthropic   │
 │   Agent       │     │       (localhost:4000)           │     │  API         │
 └──────┬───────┘     └──────────────┬─────────────────┘     └──────┬───────┘
        │                            │                              │
        │  POST /v1/chat/completions │                              │
        ├───────────────────────────►│                              │
        │                            │                              │
        │               PRE-CALL: CLEAN (passes)                   │
        │                            │                              │
        │                            ├─────────────────────────────►│
        │                            │◄─────────────────────────────┤
        │                            │                              │
        │               ┌───────────┴───────────┐                  │
        │               │  POST-CALL guardrail   │                  │
        │               │                        │                  │
        │               │  1. Response contains  │                  │
        │               │     "sk-ant-api03-..." │                  │
        │               │  2. MATCH: secret      │                  │
        │               │  3. Verdict: MEDIUM    │                  │
        │               │  4. Mode = observe     │                  │
        │               │  5. Log warning only   │                  │
        │               │     (do not block)     │                  │
        │               └───────────┬───────────┘                  │
        │                            │                              │
        │  Response returned as-is   │                              │
        │◄───────────────────────────┤                              │
        │                            │                              │
```

## Component Ownership

```
┌─────────────────────────────────────────────────────────────────────┐
│                     DefenseClaw Orchestrator (Go)                    │
│                                                                     │
│  Owns:                                                              │
│  ├── guardrail proxy process (start, monitor health, restart)        │
│  ├── Config: guardrail.enabled, mode, port, connectors             │
│  ├── Builds ConnectorRouter from config (sidecar.go:buildConnectorRouter) │
│  ├── Loads guardrail.* from config; proxy hot-reloads mode from guardrail_runtime.json │
│  └── Health tracking: guardrail subsystem state                    │
│                                                                     │
│  Does NOT:                                                          │
│  ├── Inspect LLM content (the in-process Go proxy / GuardrailInspector does) │
│  └── Terminate LLM requests itself (the guardrail HTTP server does)  │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                 ConnectorRouter + Connectors (Go)                    │
│                 internal/gateway/connector/                          │
│                                                                     │
│  Owns:                                                              │
│  ├── Framework detection (ordered: OpenClaw → ZeptoClaw → Generic)  │
│  ├── Request authentication (token, master key, loopback trust)    │
│  ├── Routing decision (upstream URL, provider, API key, auth)       │
│  ├── Provider inference from URL domain (OpenClaw) or model name   │
│  │   (ZeptoClaw/Generic)                                            │
│  ├── Embedded default provider URL table (19 providers)            │
│  ├── SSRF protection (IsKnownProviderDomain)                       │
│  └── Telemetry attribution via ConnectorName                       │
│                                                                     │
│  Does NOT:                                                          │
│  ├── Inspect LLM content (proxy core handles inspection)           │
│  └── Forward requests (proxy core handles upstream communication)  │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                     Guardrail Proxy Core (Go)                       │
│                                                                     │
│  Owns:                                                              │
│  ├── Receives RoutingDecision from connector and processes it       │
│  ├── Protocol translation (OpenAI ↔ Anthropic/Google/etc.)         │
│  ├── Inspection pipeline + upstream LLM forwarding                 │
│  └── Falls back to legacy auth when no ConnectorRouter is set      │
│                                                                     │
│  Does NOT:                                                          │
│  ├── Load its own YAML (receives config from sidecar / NewGuardrailProxy) │
│  └── Manage its own lifecycle (supervised by orchestrator)          │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│         Guardrail inspection (Go, in-process with proxy)            │
│         internal/gateway/guardrail.go, internal/gateway/proxy.go     │
│                                                                     │
│  Owns:                                                              │
│  ├── Multi-scanner orchestrator (scanner_mode logic)               │
│  ├── Local pattern scanning (injection, secrets, exfil)            │
│  ├── Cisco AI Defense client (HTTP, in gateway package)             │
│  ├── Streaming response inspection (mid-stream + final assembly)   │
│  ├── OPA policy evaluation in-process (policy.Engine)              │
│  ├── Hot-reload (proxy reads guardrail_runtime.json with TTL)      │
│  ├── Block/allow decision per mode                                 │
│  └── Audit + OTel via proxy telemetry helpers                      │
│                                                                     │
│  Does NOT:                                                          │
│  ├── Run as a separate Python subprocess for inspection            │
│  └── Manage sidecar lifecycle (supervised by orchestrator)         │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                     DefenseClaw CLI (Python)                         │
│                                                                     │
│  Owns:                                                              │
│  ├── `defenseclaw init` — seeds config, policies, optional guardrail setup │
│  ├── `defenseclaw setup guardrail [--claw openclaw|zeptoclaw]`     │
│  │   OpenClaw: plugin install + openclaw.json patching             │
│  │   ZeptoClaw: api_base patching + provider config population     │
│  ├── `defenseclaw upgrade` — in-place upgrade with backup/restore  │
│  └── --disable: revert patched configs + uninstall plugins         │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                 Fetch Interceptor Plugin (TypeScript)                │
│                 (OpenClaw only)                                      │
│                                                                     │
│  Owns:                                                              │
│  ├── Patches globalThis.fetch inside OpenClaw's Node.js process    │
│  ├── Routes ALL outbound LLM calls through localhost:4000          │
│  ├── Captures provider auth from SDK headers (Authorization,      │
│  │   x-api-key, api-key) and forwards as X-AI-Auth               │
│  ├── Sends X-DC-Auth for proxy authorization (from sidecar config)│
│  ├── Adds X-DC-Target-URL header with original provider URL       │
│  └── Activates only when guardrail.enabled = true                  │
└─────────────────────────────────────────────────────────────────────┘
```

## Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| `observe` | Log all findings with severity and matched patterns. Never block. | Initial deployment, SOC monitoring, tuning false positives |
| `action` | Block prompts/responses that match HIGH/CRITICAL patterns. MEDIUM/LOW are logged only. | Production enforcement after tuning |

Mode is set in `~/.defenseclaw/config.yaml` (`guardrail.mode`) and passed into
`NewGuardrailProxy` when the sidecar starts the guardrail proxy; hot-reload
updates come from `guardrail_runtime.json`.

Mode can be changed at runtime via hot-reload (no restart required):

```bash
curl -X PATCH http://127.0.0.1:18790/v1/guardrail/config \
  -H 'Content-Type: application/json' \
  -H 'X-DefenseClaw-Client: cli' \
  -d '{"mode": "action"}'
```

The Go sidecar writes `~/.defenseclaw/guardrail_runtime.json` and the guardrail
proxy reads it with a 5-second TTL cache, applying changes without restart.

## Detection Patterns

### Prompt Inspection (pre-call)

| Category | Patterns | Severity |
|----------|----------|----------|
| Prompt injection | `ignore previous`, `ignore all instructions`, `disregard previous`, `you are now`, `act as`, `pretend you are`, `bypass`, `jailbreak`, `do anything now`, `dan mode` | HIGH |
| Data exfiltration | `/etc/passwd`, `/etc/shadow`, `base64 -d`, `exfiltrate`, `send to my server`, `curl http` | HIGH |
| Secrets in prompt | `sk-`, `sk-ant-`, `api_key=`, `-----begin rsa`, `aws_access_key`, `password=`, `bearer `, `ghp_`, `github_pat_` | MEDIUM |

### Response Inspection (post-call)

| Category | Patterns | Severity |
|----------|----------|----------|
| Leaked secrets | Same secret patterns as above | MEDIUM |
| Tool call logging | Function name + first 200 chars of arguments (logged, not blocked) | INFO |

## File Layout

```
cli/defenseclaw/
  guardrail.py                      # config generation, openclaw.json patching
  commands/cmd_setup.py             # `setup guardrail` command
  commands/cmd_init.py              # configures guardrail proxy + OpenClaw integration
  config.py                         # GuardrailConfig dataclass

internal/config/
  config.go                         # GuardrailConfig Go struct
  defaults.go                       # guardrail defaults

internal/gateway/
  guardrail.go                      # GuardrailInspector — local, Cisco, judge, OPA
  proxy.go                          # GuardrailProxy — reverse proxy + inspection hooks
  sidecar.go                        # runGuardrail() goroutine
  health.go                         # guardrail subsystem health tracking

~/.defenseclaw/                     # runtime (generated, not in repo)
  config.yaml                       # guardrail section

~/.openclaw/
  openclaw.json                     # patched: plugin registration only (no provider/model changes)
```

## Setup Flow

### OpenClaw Setup (default)

```
┌──────────────────────────────────────────────────────────────────┐
│  defenseclaw setup guardrail [--claw openclaw]                   │
│                                                                  │
│  Interactive wizard:                                             │
│  1. Enable guardrail? → yes                                     │
│  2. Mode? → observe (default) or action                         │
│  3. Port? → 4000 (default)                                      │
│                                                                  │
│  No model or API key prompts — the fetch interceptor handles    │
│  provider detection and key injection automatically.            │
│                                                                  │
│  Generates:                                                      │
│  ├── ~/.defenseclaw/config.yaml (guardrail section + connectors)│
│  ├── Sets connectors.openclaw.enabled = true                    │
│  └── Patches ~/.openclaw/openclaw.json                          │
│      ├── Registers defenseclaw in plugins.allow                 │
│      └── Enables plugin entry (fetch interceptor loads on start)│
└──────────────────────────────────────────────────────────────────┘

When OpenClaw starts, the fetch interceptor plugin activates and routes
all outbound LLM calls through the guardrail proxy — regardless of
which provider the user selects in the UI.
```

### ZeptoClaw Setup

```
┌──────────────────────────────────────────────────────────────────┐
│  defenseclaw setup guardrail --claw zeptoclaw                    │
│                                                                  │
│  1. Read ~/.zeptoclaw/config.json (discover providers)           │
│  2. Save original provider configs to                           │
│     ~/.defenseclaw/zeptoclaw_original_providers.json            │
│  3. Patch api_base for each provider to                         │
│     http://127.0.0.1:4000/v1                                   │
│  4. Write connector config to config.yaml:                       │
│     connectors.zeptoclaw.enabled = true                          │
│     connectors.zeptoclaw.providers = {provider → upstream map}  │
│  5. Restart ZeptoClaw (picks up new api_base)                   │
└──────────────────────────────────────────────────────────────────┘

No plugin install needed — ZeptoClaw uses api_base redirect, which is
simpler and less invasive than a fetch interceptor.
```

### Sidecar Startup (both connectors)

```
┌──────────────────────────────────────────────────────────────────┐
│  defenseclaw-gateway  (or: defenseclaw sidecar)                  │
│                                                                  │
│  Starts all subsystems:                                          │
│  1. Gateway WS connection loop                                   │
│  2. Skill/MCP watcher                                           │
│  3. REST API server                                              │
│  4. Builds ConnectorRouter from config:                          │
│     ├── If connectors.openclaw.enabled → add OpenClawConnector  │
│     ├── If connectors.zeptoclaw.enabled → add ZeptoClawConnector│
│     └── Always set GenericConnector as fallback                 │
│  5. Spawns guardrail proxy with ConnectorRouter (if enabled)    │
│     ├── Verifies guardrail settings in config.yaml              │
│     ├── Starts proxy with mode + scanner env vars               │
│     ├── Polls /health/liveliness until 200                      │
│     └── Restarts on crash (exponential backoff)                 │
└──────────────────────────────────────────────────────────────────┘
```

## Teardown

```
# OpenClaw teardown (default)
defenseclaw setup guardrail --disable
defenseclaw setup guardrail --claw openclaw --disable
  1. Remove defenseclaw plugin entries from openclaw.json
  2. Uninstall plugin from ~/.openclaw/extensions/defenseclaw/
  3. Set connectors.openclaw.enabled = false in config.yaml
  4. Restart OpenClaw gateway (fetch interceptor unloads)

# ZeptoClaw teardown
defenseclaw setup guardrail --claw zeptoclaw --disable
  1. Read ~/.defenseclaw/zeptoclaw_original_providers.json
  2. Restore original api_base values in ~/.zeptoclaw/config.json
  3. Set connectors.zeptoclaw.enabled = false in config.yaml
  4. Restart ZeptoClaw (restores direct provider access)
```

## Upgrade

```
defenseclaw upgrade [--yes] [--version VERSION]
  1. Back up ~/.defenseclaw/ and openclaw.json to timestamped directory
  2. Stop defenseclaw-gateway
  3. Download and replace gateway binary from GitHub release tarball
  4. Download and replace Python CLI from GitHub release wheel
  5. Run version-specific migrations (e.g. v0.3.0: remove legacy provider entries)
  6. Start defenseclaw-gateway and restart OpenClaw gateway
```

Migrations are keyed to the release they ship with and run automatically when
upgrading across version boundaries. The migration framework lives in
`cli/defenseclaw/migrations.py`.

> **Plugin installs are release-specific and not part of upgrade.**
> The OpenClaw plugin is installed by `install.sh` as part of the release
> that ships it (0.3.0+). Running `upgrade` does not touch the plugin.

The shell-based upgrade script (`scripts/upgrade.sh`) accepts the same flags:

```bash
# Upgrade to the latest release
./scripts/upgrade.sh

# Upgrade to a specific release
./scripts/upgrade.sh --version 0.3.0
VERSION=0.3.0 ./scripts/upgrade.sh

# Non-interactive
./scripts/upgrade.sh --yes
```

See [CLI Reference — upgrade](CLI.md#upgrade) for full options.

## Scanner Modes

The guardrail supports three scanner modes, configured via
`guardrail.scanner_mode` in `config.yaml` (loaded into the sidecar and passed
to `NewGuardrailProxy` / `GuardrailInspector`; hot-reload via `guardrail_runtime.json`):

| Mode | Behavior |
|------|----------|
| `local` (default) | Only local pattern matching — no network calls |
| `remote` | Only Cisco AI Defense cloud API |
| `both` | Local first; if clean, also run Cisco; if local flags, skip Cisco (saves latency + API cost) |

### Scanner Mode Data Flow (`both`)

```
                        ┌──────────────────────┐
                        │ GuardrailInspector.  │
                        │ Inspect()            │
                        └──────────┬───────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    │  Local pattern scan          │
                    └──────────────┬──────────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    │  Local flagged?              │
                    └──┬──────────────────────┬───┘
                    YES│                      │NO
                       │                      │
              Return   │        ┌─────────────┴─────────────┐
              local    │        │ Cisco AI Defense API call │
              verdict  │        └─────────────┬─────────────┘
                       │                      │
                       │        ┌─────────────┴─────────────┐
                       │        │ mergeVerdicts()           │
                       │        │ (higher severity)         │
                       │        └─────────────┬─────────────┘
                       │                      │
                    ┌──┴──────────────────────┴───┐
                    │ finalize() — OPA in-process │
                    │ (policy.Engine)           │
                    └──────────────┬────────────┘
                                   │
                            Final verdict
```

## Cisco AI Defense Integration

The guardrail integrates with Cisco AI Defense's Chat Inspection API
(`/api/v1/inspect/chat`) for ML-based detection of:

- Prompt injection attacks
- Jailbreak attempts
- Data exfiltration / leakage
- Privacy and compliance violations

Configuration in `config.yaml`:

```yaml
guardrail:
  scanner_mode: both
  cisco_ai_defense:
    endpoint: "https://us.api.inspect.aidefense.security.cisco.com"
    api_key_env: "CISCO_AI_DEFENSE_API_KEY"
    timeout_ms: 3000
    enabled_rules: []  # empty = send 8 default rules (Prompt Injection, Harassment, etc.)
```

The API key is **never hardcoded** — it is read from the environment
variable specified in `api_key_env`.

### Default Enabled Rules

When `enabled_rules` is empty (default), the client sends these 8 rules in
every API request:

1. Prompt Injection
2. Harassment
3. Hate Speech
4. Profanity
5. Sexual Content & Exploitation
6. Social Division & Polarization
7. Violence & Public Safety Threats
8. Code Detection

If the API key has pre-configured rules on the Cisco dashboard, the client
detects the `400 Bad Request` ("already has rules configured") and
automatically retries without the rules payload.

### Graceful Degradation

- If Cisco API is unreachable or times out → falls back to local-only
- If OPA policy engine fails to load or evaluate → uses merged scanner verdicts from `guardrail.go`
- If OPA policy has compile errors → uses built-in severity logic

## OPA Policy Evaluation

`GuardrailInspector` in `internal/gateway/guardrail.go` evaluates combined
scanner results through the OPA guardrail policy (`policies/rego/guardrail.rego`)
in-process via `policy.Engine.EvaluateGuardrail`, which decides the final verdict based on configurable:

- **Severity thresholds**: block on HIGH+, alert on MEDIUM+
- **Cisco trust level**: `full` (trust Cisco verdicts equally), `advisory`
  (downgrade Cisco-only blocks to alerts), `none` (ignore Cisco results)
- **Pattern lists**: configurable in `policies/rego/data.json` under
  `guardrail.patterns`

The HTTP endpoint `POST /v1/guardrail/evaluate` exposes the same evaluation
for external callers; the built-in proxy does not require it for normal operation.

## Component Ownership

```
┌─────────────────────────────────────────────────────────────────────┐
│                     DefenseClaw Orchestrator (Go)                    │
│                                                                     │
│  Owns:                                                              │
│  ├── guardrail proxy process (start, monitor health, restart)        │
│  ├── Config: guardrail.enabled, mode, scanner_mode, port, model    │
│  ├── Loads guardrail.* from config; proxy hot-reloads from guardrail_runtime.json │
│  ├── Health tracking: guardrail subsystem state                    │
│  ├── REST API: POST /v1/guardrail/evaluate (optional HTTP OPA)      │
│  └── OTel metrics: scanner attribution, latency, token counts      │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                     Guardrail Proxy (Go)                            │
│                                                                     │
│  Owns:                                                              │
│  ├── Model routing (config.yaml)                                   │
│  ├── API key management (reads from env var)                       │
│  ├── Protocol translation (OpenAI ↔ Anthropic/Google/etc.)         │
│  └── Inspection pipeline + upstream LLM forwarding                 │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│         Guardrail inspection (Go, in-process with proxy)            │
│         internal/gateway/guardrail.go, internal/gateway/proxy.go     │
│                                                                     │
│  Owns:                                                              │
│  ├── Multi-scanner orchestrator (scanner_mode logic)               │
│  ├── Local pattern scanning (injection, secrets, exfil)            │
│  ├── Cisco AI Defense client (HTTP, in gateway package)             │
│  ├── OPA policy evaluation in-process (policy.Engine)              │
│  ├── Verdict merging (mergeVerdicts, mergeWithJudge)               │
│  ├── Block/allow decision per mode                                 │
│  └── Structured logging + audit / OTel via proxy telemetry         │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                     DefenseClaw CLI (Python)                         │
│                                                                     │
│  Owns:                                                              │
│  ├── `defenseclaw init` — seeds config, policies, optional guardrail setup │
│  ├── `defenseclaw setup guardrail` — config wizard (plugin-only, no model changes) │
│  ├── `defenseclaw upgrade` — in-place upgrade with backup/restore  │
│  ├── openclaw.json patching (plugin registration only)             │
│  └── openclaw.json revert + plugin uninstall on --disable          │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                 Fetch Interceptor Plugin (TypeScript)                │
│                                                                     │
│  Owns:                                                              │
│  ├── Patches globalThis.fetch inside OpenClaw's Node.js process    │
│  ├── Routes ALL outbound LLM calls through localhost:4000          │
│  ├── Captures provider auth from SDK headers (Authorization,      │
│  │   x-api-key, api-key) and forwards as X-AI-Auth               │
│  ├── Sends X-DC-Auth for proxy authorization (from sidecar config)│
│  ├── Adds X-DC-Target-URL header with original provider URL       │
│  └── Activates only when guardrail.enabled = true                  │
└─────────────────────────────────────────────────────────────────────┘
```

## File Layout

```
policies/rego/
  guardrail.rego                    # OPA policy for LLM guardrail verdicts
  guardrail_test.rego               # OPA unit tests
  data.json                         # guardrail section: patterns, thresholds, Cisco trust

cli/defenseclaw/
  guardrail.py                      # config generation, openclaw.json patching, plugin lifecycle
  commands/cmd_setup.py             # `setup guardrail` command (plugin-only, no model changes)
  commands/cmd_upgrade.py           # `upgrade` command — file replacement + version migrations
  migrations.py                     # Version-specific migration framework (v0.3.0+)
  commands/cmd_init.py              # configures guardrail proxy + OpenClaw integration
  config.py                         # GuardrailConfig + CiscoAIDefenseConfig dataclasses
  paths.py                          # scripts_dir() for locating scripts in dev/wheel installs

internal/configs/
  providers.json                    # Shared provider config (domains, env keys) — single source of truth
  embed.go                          # Go embed for providers.json

extensions/defenseclaw/src/
  index.ts                          # Plugin entry — registers interceptor as plugin service
  fetch-interceptor.ts              # Patches globalThis.fetch, captures auth headers, routes to proxy
  sidecar-config.ts                 # Reads guardrail.port from config

internal/config/
  config.go                         # GuardrailConfig + CiscoAIDefenseConfig + ConnectorsConfig Go structs
  connectors.go                     # ConnectorsConfig, OpenClawConnectorConfig, ZeptoClawConnectorConfig

internal/policy/
  types.go                          # GuardrailInput / GuardrailOutput types
  engine.go                         # EvaluateGuardrail method

internal/gateway/
  connector/                        # Connector architecture (NEW)
    connector.go                    # Connector interface + RoutingDecision struct
    router.go                       # ConnectorRouter — ordered detection, first match wins
    openclaw.go                     # OpenClaw connector (X-DC-Target-URL + fetch interceptor)
    zeptoclaw.go                    # ZeptoClaw connector (model inference + api_base redirect)
    zeptoclaw_defaults.go           # Embedded default provider table (19 providers)
    generic.go                      # Generic fallback connector (curl, future frameworks)
    helpers.go                      # InferProviderFromURL, IsKnownProviderDomain, ExtractAPIKey, IsLoopback
  guardrail.go                      # GuardrailInspector — scanners + OPA finalize
  proxy.go                          # GuardrailProxy — connector-aware reverse proxy + inspection
  provider.go                       # Provider routing (splitModel, inferProvider)
  provider_openai.go                # OpenAI provider
  provider_anthropic.go             # Anthropic provider (passthrough /v1/messages)
  provider_azure.go                 # Azure OpenAI (Foundry→deployment URL, api-version)
  provider_gemini.go                # Gemini (native + OpenAI-compatible)
  provider_openrouter.go            # OpenRouter (attribution headers)
  api.go                            # POST /v1/guardrail/evaluate, /v1/guardrail/event
  sidecar.go                        # runGuardrail() + buildConnectorRouter()
  health.go                         # guardrail subsystem health tracking

scripts/
  upgrade.sh                        # Shell-based upgrade (mirrors `defenseclaw upgrade`)

~/.defenseclaw/                     # runtime (generated, not in repo)
  config.yaml                       # guardrail section (incl. connectors, scanner_mode, cisco_ai_defense)
  backups/                          # timestamped upgrade backups
```

## Per-Inspection Audit Events

Every guardrail verdict is written to the SQLite audit store via two
event types:

| Action | Trigger | Severity |
|--------|---------|----------|
| `guardrail-inspection` | `GuardrailProxy.recordTelemetry()` after inspection (`proxy.go`, `guardrail.go`) | From verdict |
| `guardrail-opa-inspection` | `POST /v1/guardrail/evaluate` handler when that HTTP API is used (`api.go`) | From OPA output |

These events are queryable via `defenseclaw audit list` and forwarded to
Splunk when the SIEM adapter is enabled.

## Streaming Response Inspection

The guardrail proxy (`internal/gateway/proxy.go`) inspects streaming LLM
responses in-process:

- Accumulates text as SSE chunks arrive
- Periodically runs a quick local pattern scan on the growing buffer
- In `action` mode, terminates the stream early if a high-severity threat is detected
- After the stream completes, runs the full multi-scanner inspection pipeline on assembled content

## Hot Reload

Mode and scanner_mode can be changed at runtime without restarting:

```bash
# Switch from observe to action mode
curl -X PATCH http://127.0.0.1:18790/v1/guardrail/config \
  -H 'Content-Type: application/json' \
  -H 'X-DefenseClaw-Client: cli' \
  -d '{"mode": "action", "scanner_mode": "both"}'

# Check current config
curl http://127.0.0.1:18790/v1/guardrail/config
```

The PATCH endpoint updates the in-memory config and writes
`guardrail_runtime.json`. The guardrail proxy reads this file with a
5-second TTL cache and applies updated `mode` and `scanner_mode` without
restart (including Cisco client enable/disable when scanner mode changes).

## Setup Wizard

`defenseclaw setup guardrail` prompts for:

1. Enable guardrail? (yes/no)
2. Mode (observe/action)
3. Scanner mode (local/remote/both)
4. Cisco AI Defense endpoint, API key env var, timeout (if remote/both)
5. Guardrail proxy port

The wizard no longer prompts for model selection or API keys — the fetch
interceptor captures provider auth headers set by OpenClaw's provider
SDKs and forwards them to the proxy automatically.

Non-interactive mode supports all options as flags:

```bash
defenseclaw setup guardrail \
  --mode action \
  --scanner-mode both \
  --cisco-endpoint https://us.api.inspect.aidefense.security.cisco.com \
  --cisco-api-key-env CISCO_AI_DEFENSE_API_KEY \
  --cisco-timeout-ms 3000 \
  --port 4000 \
  --non-interactive
```

## Future Extensions

- **Hot pattern reload**: Load pattern updates from `data.json` without
  restarting the guardrail process.
- **Approval queue**: Require human approval for blocked prompts in
  high-security environments.
