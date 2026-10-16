# Technical Specification: Hybrid Proxy Mode

**PR:** #999 (`feat/claudecode-hybrid-proxy-mode`)
**Version:** 1.0
**Date:** 2026-10-15
**Status:** In review

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Connector Classification](#2-connector-classification)
3. [Traffic Routing Rules](#3-traffic-routing-rules)
4. [Semantic Router](#4-semantic-router)
5. [Responses API Bridge](#5-responses-api-bridge)
6. [Guardrail Inspection Strategy](#6-guardrail-inspection-strategy)
7. [Custom Provider Integration](#7-custom-provider-integration)
8. [Configuration Schema](#8-configuration-schema)
9. [Request Flow Diagrams](#9-request-flow-diagrams)
10. [API Contracts](#10-api-contracts)
11. [Tenant Isolation](#11-tenant-isolation)
12. [Observability](#12-observability)
13. [Error Handling](#13-error-handling)
14. [Security Model](#14-security-model)
15. [Performance Budget](#15-performance-budget)
16. [Testing Strategy](#16-testing-strategy)
17. [Rollout Plan](#17-rollout-plan)

---

## 1. Executive Summary

Hybrid Proxy Mode routes LLM traffic from all 11 DefenseClaw connectors through
the gateway for two purposes:

1. **Semantic routing** — Select the optimal LLM provider/model based on request
   content (when `routing.enabled: true`).
2. **Guardrail inspection** — Inspect prompts and responses for policy violations
   (only for connectors that cannot perform inspection natively via hooks).

### Core Principle: Inspection at the Earliest Point

> **Traffic passing through the DefenseClaw gateway is forwarded for semantic
> routing ONLY when `routing.enabled: true`. Guardrail inspection of LLM
> prompts/responses happens through connector hooks for ALL connectors that
> support hooks. Gateway-level inspection applies ONLY to connectors that
> lack native hook inspection capability.**

This principle ensures:
- No redundant double-inspection (hook + gateway) for capable connectors.
- Minimum latency — hook inspection happens at the agent, not at the proxy.
- Connectors without hooks still get full guardrail coverage via the gateway.
- Semantic routing is orthogonal to inspection — it's a model-selection
  concern, not a security concern.

---

## 2. Connector Classification

### 2.1 Inspection Capability Matrix

| Connector | Has Hooks | CanBlock | Hook Inspection | Proxy Inspection | Semantic Routing |
|-----------|-----------|----------|-----------------|------------------|------------------|
| **ClaudeCode** | Yes | Yes | Pre-execution + response scan | **No** (hooks handle it) | Via proxy (if routing enabled) |
| **Codex** | Yes | Yes | Pre-execution + response scan | **No** (hooks handle it) | Via proxy (model_providers) |
| **Kiro** | Yes | Yes | Pre-execution + response scan | **No** (hooks handle it) | Via proxy (if routing enabled) |
| **Omnigent** | Yes | Yes | Pre-execution + response scan | **No** (hooks handle it) | Via proxy (if routing enabled) |
| **Amp** | Yes | Yes | Pre-execution + response scan | **No** (hooks handle it) | Via proxy (if routing enabled) |
| **Devin** | Yes | Yes | Pre-execution | **No** (hooks handle it) | Via proxy (if routing enabled) |
| **Cursor** | No | No | N/A | **Yes** (gateway inspects) | Via proxy (if routing enabled) |
| **Hermes** | No | No | N/A | **Yes** (gateway inspects) | Via proxy (if routing enabled) |
| **OpenHands** | No | No | N/A | **Yes** (gateway inspects) | Via proxy (if routing enabled) |
| **OpenCode** | No | No | N/A | **Yes** (gateway inspects) | Via proxy (if routing enabled) |
| **Copilot** | No | No | N/A | **Yes** (gateway inspects) | Via proxy (if routing enabled) |

### 2.2 Classification Logic

```go
type InspectionStrategy int

const (
    InspectViaHooks   InspectionStrategy = iota // Connector has CanBlock hooks
    InspectViaGateway                           // Connector lacks hooks; gateway inspects
)

func resolveInspectionStrategy(conn Connector, opts SetupOpts) InspectionStrategy {
    if hp, ok := conn.(HookCapabilityProvider); ok {
        caps := hp.HookCapabilities(opts)
        if caps.CanBlock {
            return InspectViaHooks
        }
    }
    return InspectViaGateway
}
```

The gateway queries the connector's `HookCapability` at setup time. If
`CanBlock == true`, the connector handles its own prompt/response inspection
through its hook lifecycle (pre_tool_call, pre_llm, after_llm events). The
gateway does NOT duplicate that inspection on the proxy path.

### 2.3 Data Flow Per Classification

**Hook-capable connectors (ClaudeCode, Codex, Kiro, Omnigent, Amp, Devin):**
```
Agent → [Hook: pre_llm inspection] → DefenseClaw Proxy → [Semantic Routing] → LLM Provider
     ← [Hook: after_llm inspection] ← DefenseClaw Proxy ← [Response] ←
```

**Hook-less connectors (Cursor, Hermes, OpenHands, OpenCode, Copilot):**
```
Agent → DefenseClaw Proxy → [Gateway: pre-call inspection] → [Semantic Routing] → LLM Provider
     ← DefenseClaw Proxy ← [Gateway: post-call inspection] ← [Response] ←
```

---

## 3. Traffic Routing Rules

### 3.1 Decision Matrix

```
                    routing.enabled = true          routing.enabled = false
                    ┌─────────────────────┐         ┌──────────────────────┐
Hook-capable        │ Route through proxy  │         │ Pass through proxy   │
connector           │ for MODEL SELECTION  │         │ (no routing, no      │
(ClaudeCode,        │ only.                │         │  gateway inspection)  │
 Codex, etc.)       │ No gateway           │         │ Hook inspection      │
                    │ inspection.          │         │ handles security.    │
                    │ Hooks handle         │         │                      │
                    │ inspection.          │         │                      │
                    └─────────────────────┘         └──────────────────────┘

                    ┌─────────────────────┐         ┌──────────────────────┐
Hook-less           │ Route through proxy  │         │ Pass through proxy   │
connector           │ for MODEL SELECTION  │         │ with GATEWAY         │
(Cursor, Hermes,    │ AND gateway          │         │ INSPECTION (pre +   │
 OpenHands, etc.)   │ inspection (pre +    │         │ post call).         │
                    │ post call).          │         │ No semantic routing. │
                    └─────────────────────┘         └──────────────────────┘
```

### 3.2 Decision Pseudocode

```go
func handleProxyRequest(w http.ResponseWriter, r *http.Request, conn Connector) {
    strategy := resolveInspectionStrategy(conn, setupOpts)

    // Step 1: Gateway inspection ONLY for hook-less connectors
    if strategy == InspectViaGateway {
        verdict := inspector.InspectMidStream(ctx, "request", prompt, messages, model, mode)
        if verdict.Action == Block {
            writeBlockSSE(w, verdict)
            return
        }
    }

    // Step 2: Semantic routing ONLY when enabled
    var decision *ModelRouterDecision
    if routingEnabled {
        decision = modelRouter.Route(ctx, input)
    }

    // Step 3: Forward to LLM provider
    response := bifrost.Forward(ctx, request, decision)

    // Step 4: Gateway post-call inspection ONLY for hook-less connectors
    if strategy == InspectViaGateway {
        verdict := inspector.InspectMidStream(ctx, "response", response, nil, model, mode)
        if verdict.Action == Block {
            logFinding(verdict)
        }
    }

    // Step 5: Return response to agent
    streamResponse(w, response)
}
```

### 3.3 Why Not Inspect Everything at the Gateway?

1. **Latency**: Hook inspection happens in-process at the agent (sub-ms).
   Gateway inspection adds a network round trip (~10-50ms).
2. **Redundancy**: Running the same guardrail rules twice (hook + gateway)
   wastes compute and can produce conflicting verdicts.
3. **False positives**: The hook sees the full agent context (tool history,
   session state). The gateway sees only the isolated HTTP request. Hooks
   produce fewer false positives because they have richer context.
4. **Architecture**: Hooks are the canonical inspection point. The gateway
   proxy is a fallback for connectors that can't support hooks, not a
   replacement.

---

## 4. Semantic Router

### 4.1 Purpose

Select the optimal LLM provider and model for each request based on the
content's semantic intent, independent of which connector sent it.

### 4.2 Architecture

```
                    ┌──────────────────────┐
  User message ────▶│  vLLM Classifier     │
                    │  (MMBert, local)     │
                    │                      │
                    │  POST /classify/     │
                    │       intent         │
                    │                      │
                    │  Returns:            │
                    │  {model, confidence} │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │  Confidence Check    │
                    │                      │
                    │  conf >= threshold?  │──── No ──▶ Use default model
                    │                      │
                    └──────────┬───────────┘
                               │ Yes
                    ┌──────────▼───────────┐
                    │  Resolve Backend     │
                    │                      │
                    │  model alias →       │
                    │  {provider, url,     │
                    │   key, headers}      │
                    └──────────────────────┘
```

### 4.3 Interface

```go
type ModelRouter interface {
    Route(ctx context.Context, input ModelRouterInput) *ModelRouterDecision
}

type ModelRouterInput struct {
    Messages    []ChatMessage          // Conversation history
    Tools       []Tool                 // Available tools
    Stream      bool                   // Streaming request?
    User        string                 // User identifier
    SessionID   string                 // Session identifier
    Connector   string                 // Source connector name
}

type ModelRouterDecision struct {
    Provider      string               // "openai", "azure", "bedrock", etc.
    TargetURL     string               // Full provider endpoint
    Model         string               // Model identifier (e.g., "claude-sonnet-4-6")
    APIKey        string               // Resolved credential
    ExtraHeaders  map[string]string    // Per-model HTTP headers
    ExtraBody     map[string]string    // Per-model body injection
    PathOverride  string               // Override API path (e.g., "/chat/completions")
    Confidence    float64              // Router confidence (0.0-1.0)
    Signal        string               // Matched intent signal name
}
```

### 4.4 Confidence Threshold

```yaml
routing:
  remote:
    min_confidence: 0.6    # Default threshold
```

| Confidence | Behavior |
|---|---|
| >= 0.6 | Use the routed model |
| < 0.6 | Fall through to `routing.models[0]` (default) |
| Classifier unreachable | Fall through to default (graceful degradation) |

### 4.5 Signal Definition

```yaml
routing:
  signals:
    - name: coding
      examples:
        - "Write a Python function to sort a list"
        - "Fix this TypeScript compilation error"
        - "Explain this regex pattern"
        - "Optimize this SQL query"
        - "Review this pull request"
        - "Write unit tests for this module"
        - "Refactor this class to use dependency injection"
        - "Debug this segfault in the C code"
        - "Convert this callback to async/await"
        - "Add error handling to this function"
    - name: architecture
      examples:
        - "Design a microservices architecture for this system"
        - "What's the best database for high-write workloads?"
        - "Should we use event sourcing or CRUD?"
        - "How should we handle distributed transactions?"
    - name: science
      examples:
        - "Explain quantum entanglement"
        - "Derive the Navier-Stokes equation"
    - name: math
      examples:
        - "Prove that sqrt(2) is irrational"
        - "Solve this differential equation"
  decisions:
    - signal: coding
      model: claude-sonnet        # Best for code generation
    - signal: architecture
      model: gpt-4o               # Best for system design
    - signal: science
      model: claude-sonnet        # Good at reasoning
    - signal: math
      model: gpt-4o              # Strong at formal math
```

---

## 5. Responses API Bridge (Bifrost)

### 5.1 Purpose

Bridge OpenAI Responses API format to chat/completions for providers that
don't support the Responses API natively (Azure, Bedrock, custom gateways).

### 5.2 Protocol Translation

#### Input (Responses API)
```json
{
  "model": "claude-sonnet-4-6",
  "input": [
    {"role": "user", "content": "Write a sort function"}
  ],
  "instructions": "You are a helpful assistant",
  "stream": true
}
```

#### Translated Output (chat/completions)
```json
{
  "model": "claude-sonnet-4-6",
  "messages": [
    {"role": "system", "content": "You are a helpful assistant"},
    {"role": "user", "content": "Write a sort function"}
  ],
  "stream": true
}
```

### 5.3 SSE Event Format

#### Streaming delta
```
data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"def sort"}
```

#### Completion event
```
data: {"type":"response.completed","response":{"id":"resp_abc123","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"def sort(lst):\n    return sorted(lst)"}]}],"usage":{"input_tokens":15,"output_tokens":12}}}
```

#### Block event (guardrail)
```
data: {"type":"response.output_text.delta","delta":"[BLOCKED] SEC-ANTHROPIC: API key detected in prompt"}

data: {"type":"response.completed","response":{"id":"resp_block","status":"incomplete","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"[BLOCKED] ..."}]}]}}
```

### 5.4 Role Mapping

| Responses API Role | chat/completions Role | Notes |
|---|---|---|
| `user` | `user` | Direct mapping |
| `assistant` | `assistant` | Direct mapping |
| `developer` | `system` | Converted for strict providers |
| `system` | `system` | Direct mapping |
| `instructions` field | Prepended as `system` message | First message in array |

### 5.5 Tenant Isolation

```go
type tenantKey struct {
    provider string
    apiKey   string
    baseURL  string
    tls      bool
}
```

Each unique `tenantKey` gets a dedicated Bifrost client. LRU cache with
256-entry cap prevents memory growth on credential rotation.

---

## 6. Guardrail Inspection Strategy

### 6.1 The Core Rule

```
IF connector.HookCapabilities().CanBlock == true:
    Inspection happens via hooks (pre_tool_call, pre_llm, after_llm)
    Gateway does NOT run guardrail inspection on the proxy path
    Gateway ONLY performs semantic routing (if enabled)

ELSE:
    Inspection happens at the gateway proxy (pre-call + post-call)
    Gateway runs full InspectMidStream on request AND response
    Gateway also performs semantic routing (if enabled)
```

### 6.2 Implementation

```go
func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) {
    conn := p.resolveConnector(r)
    caps := conn.HookCapabilities(p.opts)

    // Determine inspection strategy
    gatewayInspection := !caps.CanBlock

    // PRE-CALL: Only for hook-less connectors
    if gatewayInspection {
        verdict := p.inspector.InspectMidStream(ctx, "request", ...)
        if verdict.Blocked() {
            p.writeBlockResponse(w, verdict)
            return
        }
    }

    // SEMANTIC ROUTING: For all connectors when routing is enabled
    if p.routingEnabled {
        decision := p.modelRouter.Route(ctx, input)
        if decision != nil {
            applyRoutingDecision(r, decision)
        }
    }

    // FORWARD to provider
    resp := p.bifrost.Forward(ctx, r)

    // POST-CALL: Only for hook-less connectors
    if gatewayInspection {
        verdict := p.inspector.InspectMidStream(ctx, "response", resp, ...)
        if verdict.Blocked() {
            p.logFinding(verdict)
        }
    }

    p.streamResponse(w, resp)
}
```

### 6.3 Why This Split Matters

| Scenario | Hook-capable | Hook-less |
|---|---|---|
| User sends jailbreak prompt | Hook pre_llm blocks it at the agent | Gateway pre-call blocks it at the proxy |
| LLM leaks API key in response | Hook after_llm detects it at the agent | Gateway post-call detects it at the proxy |
| Semantic routing picks wrong model | No impact — hooks still inspect | No impact — gateway still inspects |
| Gateway is down | Hooks still work (fail-closed) | Agent cannot reach LLM (fail-closed) |
| Hook is tampered | Gateway does NOT compensate (separate concern) | N/A |

### 6.4 Conditional Inspection Config

```yaml
guardrail:
  proxy_mode: hybrid    # "hybrid" = conditional, "full" = always inspect
```

When `proxy_mode: full`, the gateway inspects ALL traffic regardless of
hook capability. This is a defense-in-depth override for high-security
deployments that accept the latency cost.

---

## 7. Custom Provider Integration

### 7.1 Three Configuration Fields

```yaml
routing:
  models:
    - name: cisco-claude
      provider: azure
      model: claude-sonnet-4-6
      base_url: https://chat-ai.cisco.com/openai/deployments/claude-sonnet-4-6
      api_key_env: CISCO_AI_JWT
      path_override: /chat/completions
      extra_headers:
        api-key: "${CISCO_AI_JWT}"
      extra_body:
        user: '{"appkey":"defenseclaw-prod"}'
```

### 7.2 Field Semantics

| Field | Type | Purpose | When Used |
|---|---|---|---|
| `path_override` | `string` | Override Bifrost's default `/v1/chat/completions` path | Providers without `/v1/` prefix (Cisco AI Gateway) |
| `extra_headers` | `map[string]string` | HTTP headers injected per-request | Provider-specific auth (`api-key` for Azure, `x-api-key` for Anthropic) |
| `extra_body` | `map[string]string` | JSON fields merged into request body | Provider-specific metadata (Cisco appkey, user tracking) |

### 7.3 Auth Header Resolution

The `effectiveProvider` from the routing decision determines which auth
header format to use:

| Provider | Auth Header |
|---|---|
| `openai` | `Authorization: Bearer <key>` |
| `azure` | `api-key: <key>` |
| `anthropic` | `x-api-key: <key>` |
| `bedrock` | AWS SigV4 (IAM credentials) |
| `vertex` | `Authorization: Bearer <service-account-token>` |

### 7.4 Environment Variable Resolution

`extra_headers` values containing `${ENV_VAR}` are resolved at request time:

```yaml
extra_headers:
  api-key: "${CISCO_AI_JWT}"    # Resolved from os.Getenv("CISCO_AI_JWT")
```

---

## 8. Configuration Schema

### 8.1 Full Schema

```yaml
routing:
  enabled: true                          # Master switch for semantic routing
  version: "0.3.0"                       # Schema version
  port: 4000                             # Proxy listen port

  remote:
    endpoint: http://localhost:8080       # vLLM classifier endpoint
    timeout_ms: 3000                     # Max classify latency (≤5000ms)
    min_confidence: 0.6                  # Minimum confidence to accept routing

  models:                                # Available backend models
    - name: claude-sonnet                # Alias (used in decisions)
      provider: azure                    # Provider type
      model: claude-sonnet-4-6           # Model identifier
      base_url: https://...              # Provider endpoint
      auth: api_key                      # Auth mode
      api_key_env: CISCO_AI_JWT          # Env var for credential
      path_override: /chat/completions   # API path override
      extra_headers:                     # Per-model HTTP headers
        api-key: "${CISCO_AI_JWT}"
      extra_body:                        # Per-model body fields
        user: '{"appkey":"prod"}'

  signals:                               # Intent definitions
    - name: coding
      examples: [...]                    # 10+ example phrases

  decisions:                             # Signal → model mapping
    - signal: coding
      model: claude-sonnet

guardrail:
  proxy_mode: hybrid                     # "hybrid" or "full"
```

### 8.2 Validation Rules

| Field | Constraint | Error |
|---|---|---|
| `models[].name` | Non-empty, ≤128 bytes, unique | `duplicate model name` |
| `models[].provider` | ≤4096 bytes | `provider too long` |
| `models[].auth` | `passthrough`, `api_key`, `none` | `unknown auth mode` |
| `models[].base_url` | Valid absolute URL | `invalid URL` |
| `models[].api_key_env` | Required when `auth=api_key` | `api_key_env required` |
| `remote.timeout_ms` | ≤5000ms | `timeout exceeds limit` |
| `remote.min_confidence` | 0.0–1.0 | `invalid confidence` |
| `signals[].examples` | ≥1 example | `signal needs examples` |
| `decisions[].model` | Must reference a defined model | `unknown model` |

---

## 9. Request Flow Diagrams

### 9.1 Hook-Capable Connector + Routing Enabled

```
ClaudeCode                   DefenseClaw Gateway           Cisco AI Gateway
    │                              │                              │
    │── LLM request ──────────────▶│                              │
    │                              │                              │
    │   (No gateway inspection     │── Classify intent ──▶ vLLM   │
    │    - hooks handle security)  │◀── {model, 0.85} ───        │
    │                              │                              │
    │                              │── Forward (path_override) ──▶│
    │                              │◀── Stream response ──────────│
    │                              │                              │
    │◀── Stream SSE ──────────────│                              │
    │                              │                              │
    │── [Hook: after_llm] ────────│                              │
    │   (response inspection       │                              │
    │    happens at agent)         │                              │
```

### 9.2 Hook-Less Connector + Routing Enabled

```
Cursor                       DefenseClaw Gateway           OpenAI
    │                              │                              │
    │── LLM request ──────────────▶│                              │
    │                              │                              │
    │                              │── PRE-CALL INSPECTION        │
    │                              │   InspectMidStream("request")│
    │                              │   → PASS                     │
    │                              │                              │
    │                              │── Classify intent ──▶ vLLM   │
    │                              │◀── {model, 0.72} ───        │
    │                              │                              │
    │                              │── Forward ──────────────────▶│
    │                              │◀── Stream response ──────────│
    │                              │                              │
    │                              │── POST-CALL INSPECTION       │
    │                              │   InspectMidStream("response")
    │                              │   → PASS                     │
    │                              │                              │
    │◀── Stream SSE ──────────────│                              │
```

### 9.3 Routing Disabled (All Connectors)

```
Any Connector                DefenseClaw Gateway           Original Provider
    │                              │                              │
    │── LLM request ──────────────▶│                              │
    │                              │                              │
    │   IF hook-less:              │                              │
    │   ├── PRE-CALL INSPECTION    │                              │
    │   │                          │                              │
    │                              │── Forward (no routing) ─────▶│
    │                              │◀── Stream response ──────────│
    │                              │                              │
    │   IF hook-less:              │                              │
    │   ├── POST-CALL INSPECTION   │                              │
    │                              │                              │
    │◀── Stream SSE ──────────────│                              │
```

---

## 10. API Contracts

### 10.1 Proxy Endpoints

| Method | Path | Format | Purpose |
|---|---|---|---|
| POST | `/v1/chat/completions` | chat/completions | Standard LLM proxy |
| POST | `/v1/responses` | Responses API | Codex/Responses API clients |
| POST | `/responses` | Responses API | Alias |
| POST | `/c/{connector}/v1/chat/completions` | chat/completions | Connector-scoped proxy |
| POST | `/c/{connector}/v1/responses` | Responses API | Connector-scoped Responses |

### 10.2 Internal APIs

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/classify/intent` | Semantic classifier (vLLM) |
| GET | `/api/v1/routing/health` | Router health check |

---

## 11. Tenant Isolation

Each proxy request is scoped to a tenant by:

1. **Credential isolation**: `tenantKey{provider, apiKey, baseURL}` hashes
   create per-tenant Bifrost clients.
2. **LRU eviction**: 256-entry cap prevents memory growth.
3. **No credential sharing**: Tenant A's API key never appears in tenant B's
   request, even under concurrent load.
4. **Request-scoped**: Auth headers resolved per-request from environment,
   not cached across requests.

---

## 12. Observability

| Metric | Type | Labels |
|---|---|---|
| `defenseclaw_proxy_requests_total` | Counter | connector, provider, model |
| `defenseclaw_proxy_latency_seconds` | Histogram | connector, provider |
| `defenseclaw_routing_decisions_total` | Counter | signal, model, confidence_bucket |
| `defenseclaw_routing_fallback_total` | Counter | reason (low_confidence, error) |
| `defenseclaw_guardrail_proxy_verdicts` | Counter | connector, direction, action |
| `defenseclaw_bifrost_bridge_latency` | Histogram | provider |

### Traces

- `proxy.forward` span: full request lifecycle
- `routing.classify` span: semantic router latency
- `guardrail.inspect` span: pre/post inspection
- `bifrost.bridge` span: Responses→chat translation

---

## 13. Error Handling

| Failure | Behavior |
|---|---|
| Semantic router unreachable | Fall through to default model (graceful) |
| Low confidence (< threshold) | Fall through to default model |
| Provider returns 5xx | Return 502 to agent with error detail |
| Guardrail inspection timeout | Fail-closed (block the request) |
| Bifrost bridge parse error | Return 400 with malformed-input detail |
| Credential env var unset | Return 500 at request time (not startup) |
| All models unavailable | Return 503 Service Unavailable |

---

## 14. Security Model

### 14.1 Threat Model

| Threat | Mitigation |
|---|---|
| Prompt injection | Pre-call guardrail inspection (hook or gateway) |
| Response data leakage | Post-call guardrail inspection |
| Model misrouting | Confidence threshold + default fallback |
| Credential leakage | Per-tenant isolation, env-var resolution |
| Classifier poisoning | Local vLLM (no external network call) |
| SSE injection | Strict JSON serialization of events |

### 14.2 Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│                  User Trust Boundary                     │
│  ┌───────────────┐   ┌────────────────────────────────┐ │
│  │  AI Agent     │   │  DefenseClaw Gateway           │ │
│  │  (Connector)  │──▶│  ┌──────────┐  ┌───────────┐  │ │
│  │               │   │  │ Guardrail │  │ Semantic   │  │ │
│  │               │   │  │ Inspector │  │ Router     │  │ │
│  │               │   │  └──────────┘  └───────────┘  │ │
│  └───────────────┘   └──────────┬─────────────────────┘ │
└─────────────────────────────────┼───────────────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │  Provider Trust Boundary    │
                    │  (OpenAI, Azure, Bedrock,  │
                    │   Cisco AI Gateway)         │
                    └────────────────────────────┘
```

---

## 15. Performance Budget

| Operation | Budget | Measured |
|---|---|---|
| Semantic routing (classify) | < 100ms | ~50ms (local vLLM) |
| Guardrail pre-call inspection | < 50ms | ~20ms |
| Bifrost bridge translation | < 5ms | ~2ms |
| SSE chunk forwarding | < 1ms/chunk | ~0.5ms/chunk |
| Total added latency (routing) | < 200ms | ~75ms |
| Total added latency (no routing) | < 50ms | ~20ms |

---

## 16. Testing Strategy

### 16.1 Unit Tests

- `model_router_test.go`: Confidence thresholds, fallback, signal matching
- `provider_bifrost_error_test.go`: Bifrost error handling
- `proxy_block_alert_test.go`: Block SSE format validation
- `routing_validate_test.go`: Config validation rules

### 16.2 Integration Tests

- `proxy_connector_requests_test.go`: Per-connector proxy routing
- `hook_loopback_noproxy_test.go`: Hook-capable connectors don't get proxy inspection
- `sidecar_fleet_client_id_test.go`: Client ID generation

### 16.3 E2E Tests

- Codex → gateway → Cisco AI Gateway round trip
- ClaudeCode → gateway → routing → Azure round trip
- Cursor → gateway → inspection → routing → OpenAI round trip
- Block verdict → Responses API SSE stream format

---

## 17. Rollout Plan

### Phase 1 (This PR)
- Semantic routing for all 11 connectors
- Responses API bridge via Bifrost
- Conditional inspection (hooks vs gateway)
- Custom provider support (path_override, extra_headers, extra_body)
- Codex model_providers integration

### Phase 2
- AWS SigV4 auth for Bedrock
- Per-signal confidence thresholds
- Semantic caching (cache responses for similar queries)
- Multi-turn conversation context for better routing
- WebSocket support for Codex

### Phase 3
- A/B testing between models
- Cost-aware routing (prefer cheaper models for simple queries)
- Latency-aware routing (prefer faster models under SLA pressure)
- User preference learning (personalized model selection)
