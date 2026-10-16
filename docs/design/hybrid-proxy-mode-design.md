# Design Document: Hybrid Proxy Mode — Semantic Routing, Responses API Bridge, and Multi-Connector LLM Proxy

**PR:** #999 (`feat/claudecode-hybrid-proxy-mode`)
**Author:** Engineering team
**Date:** 2026-10-15
**Status:** Implementation complete, in review

---

## 1. Problem Statement

DefenseClaw's connector architecture splits into two models:

- **Proxy connectors** (Codex, ClaudeCode): Route all LLM traffic through the
  DefenseClaw gateway, enabling real-time guardrail inspection of prompts and
  responses before they reach the LLM provider.
- **Hook-only connectors** (Cursor, Hermes, Devin, OpenHands, Amp, Copilot):
  Only intercept tool calls via filesystem/process hooks. LLM traffic goes
  directly from the agent to the provider, bypassing guardrail inspection.

This creates three gaps:

1. **No prompt/response inspection** for hook-only connectors — a jailbreak
   prompt or leaked credential in an LLM response is invisible to DefenseClaw.
2. **No model routing** — every agent uses its built-in provider. Operators
   cannot centrally control which models agents use or route traffic through
   a corporate gateway (e.g., Cisco AI Gateway).
3. **No Responses API support** — agents using OpenAI's Responses API (Codex)
   cannot work with providers that only support chat/completions (Azure,
   Bedrock, custom gateways).

## 2. Solution Overview

**Hybrid Proxy Mode** unifies LLM traffic routing across all 11 connectors
by adding three capabilities:

```
┌─────────────┐    ┌──────────────────────────────────────────────┐
│  AI Agent    │    │              DefenseClaw Gateway             │
│ (any of 11   │───▶│                                              │
│  connectors) │    │  ┌─────────────┐  ┌──────────────────────┐  │
│              │    │  │  Guardrail   │  │  Semantic Router     │  │
│              │    │  │  Pre-check   │──▶│  (MMBert classify)  │  │
│              │    │  └─────────────┘  └──────────────────────┘  │
│              │    │         │                    │               │
│              │    │         ▼                    ▼               │
│              │    │  ┌─────────────┐  ┌──────────────────────┐  │
│              │    │  │  Bifrost    │  │  Provider Selection  │  │
│              │    │  │  Bridge     │◀─│  (path_override,     │  │
│              │    │  │  (Responses │  │   extra_headers,     │  │
│              │    │  │   → chat)   │  │   extra_body)        │  │
│              │    │  └─────────────┘  └──────────────────────┘  │
│              │    │         │                                    │
│              │    │         ▼                                    │
│              │◀───│  ┌─────────────┐                            │
│              │    │  │  Guardrail   │                            │
│              │    │  │  Post-check  │                            │
│              │    │  └─────────────┘                            │
└─────────────┘    └──────────────────────────────────────────────┘
                              │
                              ▼
                   ┌──────────────────────┐
                   │   LLM Provider       │
                   │   (OpenAI, Azure,    │
                   │    Bedrock, Cisco    │
                   │    AI Gateway, etc.) │
                   └──────────────────────┘
```

### 2.1 Core Inspection Principle

> **Guardrail inspection happens at the earliest possible point. For
> connectors with hook support (`CanBlock=true`), inspection happens
> via hooks at the agent — the gateway does NOT duplicate it. For
> connectors without hooks, the gateway performs inspection on the
> proxy path. Semantic routing is orthogonal to inspection — it
> applies to ALL traffic when enabled, regardless of inspection mode.**

This means:
- **ClaudeCode, Codex, Kiro, Omnigent, Amp, Devin** → hooks inspect;
  gateway only routes (no gateway inspection).
- **Cursor, Hermes, OpenHands, OpenCode, Copilot** → gateway inspects
  AND routes (hooks unavailable).

### 2.2 Semantic Router

Classifies incoming requests by content to select the optimal LLM provider
and model. Runs for ALL connectors when `routing.enabled: true`, independent
of whether inspection happens via hooks or gateway.

### 2.3 Responses API Bridge (Bifrost)

Translates OpenAI Responses API (`/v1/responses`) to chat/completions for
providers that don't natively support the Responses API format.

### 2.4 Multi-Connector Proxy

Routes LLM traffic from all 11 connectors through the gateway. The gateway's
role depends on the connector:
- **Hook-capable**: Proxy for routing only (no inspection overhead).
- **Hook-less**: Proxy for routing AND inspection (full pipeline).

## 3. Detailed Design

### 3.1 Semantic Router

**Component:** `internal/gateway/model_router*.go`

#### 3.1.1 Architecture

The semantic router uses an external embedding-based classifier (MMBert via
vLLM) to classify the intent of each request and select an appropriate
model/provider.

```
Request → Extract last user message
       → POST /api/v1/classify/intent
       → Parse { recommended_model, confidence }
       → If confidence >= min_confidence:
            return ModelRouterDecision { provider, model, url, key }
       → Else:
            fall through to default model
```

#### 3.1.2 Data Structures

```go
// Input to the router
type ModelRouterInput struct {
    Messages    []ChatMessage
    Tools       []Tool
    Stream      bool
    User        string
    SessionID   string
}

// Output from the router
type ModelRouterDecision struct {
    Provider      string            // "openai", "azure", "bedrock", etc.
    TargetURL     string            // Full provider endpoint
    Model         string            // Model identifier
    APIKey        string            // Resolved credential
    ExtraHeaders  map[string]string // Per-model HTTP headers
    ExtraBody     map[string]string // Per-model body injection
    PathOverride  string            // Override API path
}
```

#### 3.1.3 Confidence Threshold

The router enforces a configurable `min_confidence` (default 0.6). When the
classifier returns a confidence below the threshold, the request falls through
to the first configured routing model (the default). This prevents
low-confidence misroutes from sending a coding question to a science model.

#### 3.1.4 Signal Configuration

Signals are defined in config.yaml with example phrases per intent:

```yaml
routing:
  signals:
    - name: coding
      examples:
        - "Write a Python function to sort a list"
        - "Fix this TypeScript compilation error"
        # ... 10 examples
    - name: architecture
      examples:
        - "Design a microservices architecture"
        - "What's the best database for this workload?"
```

### 3.2 Responses API Bridge (Bifrost)

**Component:** `internal/gateway/provider_bifrost.go`

#### 3.2.1 Protocol Translation

The Bifrost bridge translates between two API formats:

| Responses API (Input) | chat/completions (Output) |
|---|---|
| `{"input": [messages], "instructions": "..."}` | `{"messages": [...], "model": "...", "stream": true}` |
| `developer` role | `system` role (for strict providers) |
| SSE: `response.output_text.delta` | SSE: `choices[0].delta.content` |
| SSE: `response.completed` | SSE: `[DONE]` with aggregated content |

#### 3.2.2 SSE Event Format

**Delta event (streaming):**
```json
{
  "type": "response.output_text.delta",
  "output_index": 0,
  "content_index": 0,
  "delta": "partial text..."
}
```

**Completion event:**
```json
{
  "type": "response.completed",
  "response": {
    "id": "resp_...",
    "status": "completed",
    "output": [{"type": "message", "role": "assistant", "content": [...]}],
    "usage": {"input_tokens": 100, "output_tokens": 50}
  }
}
```

#### 3.2.3 Tenant Isolation

Each unique (provider, apiKey, baseURL) tuple gets a dedicated Bifrost client
instance. A `tenantKey` struct hashes credentials and endpoints so tenant A's
credentials never leak into tenant B's request.

```go
type tenantKey struct {
    provider string
    apiKey   string
    baseURL  string
    tls      bool
}
```

An LRU cache with 256-entry eviction cap prevents unbounded memory growth
on credential rotation.

### 3.3 Guardrail Integration

**Component:** `internal/gateway/proxy_guardrail_observability_v8.go`

#### 3.3.1 Inspection Pipeline

```
                    ┌─────────────────┐
  Request ─────────▶│  Pre-call       │──── BLOCK? ──▶ Return block SSE
                    │  InspectMidStream│                (Responses API format)
                    └────────┬────────┘
                             │ PASS
                             ▼
                    ┌─────────────────┐
                    │ Semantic Router  │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Bifrost Forward  │──── Stream chunks
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Post-call        │──── BLOCK? ──▶ Log finding
                    │ InspectResponse  │
                    └─────────────────┘
```

#### 3.3.2 Block Handling on Responses API Path

When pre-call inspection blocks a request, the handler returns a valid
Responses API SSE stream containing the block reason — not a JSON error
that Codex would silently ignore:

```
data: {"type":"response.output_text.delta","delta":"[BLOCKED] SEC-ANTHROPIC: API key detected in prompt"}

data: {"type":"response.completed","response":{"status":"incomplete","output":[...]}}
```

### 3.4 Custom Provider Support

**Component:** `internal/config/routing_validate.go`

Three new fields on `routing.models[]` enable any custom LLM provider
without code changes:

```yaml
routing:
  models:
  - name: claude-sonnet
    provider: azure
    model: claude-sonnet-4-6
    base_url: https://chat-ai.cisco.com/openai/deployments/claude-sonnet-4-6
    api_key_env: CISCO_AI_JWT
    path_override: /chat/completions
    extra_headers:
      api-key: <resolved from api_key_env>
    extra_body:
      user: '{"appkey":"..."}'
```

| Field | Purpose | Example |
|---|---|---|
| `path_override` | Override API path for non-standard endpoints | `/chat/completions` (no `/v1/` prefix) |
| `extra_headers` | Per-model HTTP headers | `api-key: <jwt>` for Azure |
| `extra_body` | Per-model request body injection | `user: {"appkey":"..."}` for Cisco |

### 3.5 Codex Integration (model_providers)

**Component:** CLI setup commands

Replaces the legacy `openai_base_url` redirect with the `model_providers`
extension mechanism in Codex's `codex.toml`:

```toml
model_provider = "defenseclaw"

[model_providers.defenseclaw]
base_url = "http://127.0.0.1:4000/c/codex"
wire_api = "responses"
supports_websockets = false

[model_providers.defenseclaw.auth]
command = "sh"
args = ["-c", "echo <gateway-token>"]
```

- `wire_api = "responses"` forces Codex to use Responses API format
- `supports_websockets = false` forces HTTP POST (no WebSocket upgrade)
- Gateway token is baked into config at setup time
- Cleanup path removes stale `model_providers.defenseclaw` on teardown

### 3.6 Connector Coverage

| # | Connector | Proxy Method | Notes |
|---|---|---|---|
| 1 | ClaudeCode | Native proxy | `ANTHROPIC_BASE_URL` → gateway |
| 2 | Codex | model_providers | Responses API over HTTP POST |
| 3 | Cursor | Hybrid proxy | `ANTHROPIC_BASE_URL` injection |
| 4 | Copilot | Hybrid proxy | Custom proxy endpoint |
| 5 | Hermes | Hybrid proxy | Hook + proxy fallback |
| 6 | OpenHands | Hybrid proxy | LLM base URL override |
| 7 | Devin | Hybrid proxy | Proxy URL injection |
| 8 | Amp | Hybrid proxy | Plugin-based routing |
| 9 | OpenCode | Hybrid proxy | Bridge plugin |
| 10 | Kiro | Native proxy | Direct proxy routing |
| 11 | Omnigent | Native proxy | Direct proxy routing |

## 4. Request Flow (End-to-End)

```
1. Agent sends LLM request to DefenseClaw gateway
   └── Connector extracts ConnectorSignals (model, API key, upstream)

2. Guardrail pre-call inspection
   └── InspectMidStream checks user prompt for policy violations
   └── If BLOCK: return Responses API SSE stream with block reason

3. Semantic routing (if routing.enabled)
   └── POST /api/v1/classify/intent with user message
   └── If confidence >= min_confidence: select routed model
   └── Else: use default model from routing.models[0]

4. Provider resolution
   └── Resolve Bifrost client for (provider, key, url) tuple
   └── Apply path_override, extra_headers, extra_body

5. Bifrost bridge (if Responses API → chat/completions)
   └── Parse Responses API input messages
   └── Convert developer→system role
   └── Call ChatCompletionStream
   └── Transform delta chunks to Responses API events

6. Upstream LLM call
   └── Forward to provider with resolved auth headers
   └── Stream SSE responses back

7. Guardrail post-call inspection
   └── Scan full assistant response for policy violations
   └── Log findings to audit pipeline

8. Return to agent
   └── Stream Responses API SSE events to the agent
```

## 5. Configuration Reference

### 5.1 Routing Configuration

```yaml
routing:
  enabled: true
  version: "0.3.0"
  port: 4000
  remote:
    endpoint: http://localhost:8080
    timeout_ms: 3000
  models:
    - name: claude-sonnet
      provider: azure
      model: claude-sonnet-4-6
      base_url: https://chat-ai.cisco.com/openai/deployments/claude-sonnet-4-6
      auth: api_key
      api_key_env: CISCO_AI_JWT
      path_override: /chat/completions
      extra_headers:
        api-key: "${CISCO_AI_JWT}"
      extra_body:
        user: '{"appkey":"my-app-key"}'
    - name: gpt-4o
      provider: openai
      model: gpt-4o
      auth: api_key
      api_key_env: OPENAI_API_KEY
  signals:
    - name: coding
      examples: ["Write a function...", "Fix this bug..."]
    - name: architecture
      examples: ["Design a system...", "Database choice..."]
  decisions:
    - signal: coding
      model: claude-sonnet
    - signal: architecture
      model: gpt-4o
```

### 5.2 Validation Rules

| Field | Constraint |
|---|---|
| `models[].name` | Non-empty, ≤128 bytes, unique |
| `models[].provider` | ≤4096 bytes |
| `models[].auth` | `passthrough`, `api_key`, or `none` |
| `models[].base_url` | Valid absolute URL with scheme |
| `remote.timeout_ms` | ≤5000ms |
| `version` | Semantic version string |

## 6. Security Considerations

### 6.1 Credential Isolation

- Tenant keys are hashed by (provider, apiKey, baseURL) — different
  tenants never share a Bifrost client instance.
- API keys resolved from env vars at request time, not cached in config.
- `extra_headers` values containing `${ENV_VAR}` are resolved at request
  time from the process environment.

### 6.2 Guardrail Enforcement

- Pre-call inspection runs BEFORE semantic routing — a blocked request
  never reaches the classifier or LLM provider.
- Post-call inspection runs on the FULL assembled response — not just
  individual SSE chunks.
- Block verdicts on Responses API path return valid SSE streams (not JSON
  errors) so agents process them correctly.

### 6.3 Semantic Router Trust Boundary

- The classifier receives only the last user message — not full
  conversation history, tool results, or system prompts.
- Low-confidence classifications fall through to the default model —
  preventing misrouting to an inappropriate model.
- The classifier runs locally (vLLM) — no external network call.

## 7. Observability

- Routing decisions logged with confidence score and selected model.
- Guardrail pre/post phases traced via OpenTelemetry spans.
- Bifrost bridge latency measured per-request.
- Semantic cache hit/miss rate tracked.
- Connector-level proxy routing metrics (which connectors use proxy).

## 8. Limitations and Future Work

### Current Limitations

1. **Confidence threshold is global** — cannot be per-signal.
2. **Semantic router requires running vLLM classifier** — adds infra
   dependency. Falls back gracefully to default model if unavailable.
3. **Responses API bridge is streaming-only** — no synchronous mode.
4. **Extra body injection is string-only** — no nested JSON objects.

### Phase 2 Plans

1. **AWS SigV4 auth** for Bedrock routing (currently passthrough only).
2. **Per-signal confidence thresholds** for fine-grained routing control.
3. **Semantic caching** — cache responses for semantically similar queries.
4. **Multi-turn context** — use conversation history for better routing.
5. **WebSocket support** for Codex (currently HTTP POST only).
