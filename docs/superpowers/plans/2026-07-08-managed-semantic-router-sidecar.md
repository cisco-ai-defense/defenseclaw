# Managed Semantic Router Sidecar — Technical Spec

**Goal:** Enable DefenseClaw to manage the vLLM Semantic Router as a single Docker container, using its classify/intent API for routing decisions while preserving Bifrost in the forwarding path for multi-provider format translation.

**Architecture:** DefenseClaw starts a single router container from the `ghcr.io/vllm-project/semantic-router/vllm-sr:v0.3.0` image. At boot, it translates its `routing:` config block into the SR's v0.3 canonical format, starts the container with the router binary directly (no Envoy, no storage backends), and registers a `RemoteRouterClient` that calls `POST /api/v1/classify/intent` for every request. The response contains `recommended_model` — DefenseClaw then forwards via Bifrost to the appropriate upstream.

**Tech Stack:** Go (DefenseClaw gateway), Docker (single container), vLLM Semantic Router v0.3 (router binary only), HTTP JSON for routing decisions, existing Bifrost SDK for upstream forwarding.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ~/.defenseclaw/config.yaml (single source of truth)                     │
│                                                                          │
│  routing:                                                                │
│    enabled: true                                                         │
│    models: [{name: reasoning, ...}, {name: code, ...}, {name: fast, ...}]│
│    signals: {keywords: [...]}                                            │
│    decisions: [{name: reasoning_route, ...}, ...]                        │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │ parsed at sidecar boot
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  DefenseClaw Gateway (sidecar.go)                                        │
│                                                                          │
│  Startup:                                                                │
│  1. Check Docker is available                                            │
│  2. Translate config → SR v0.3 YAML                                      │
│  3. docker run (single router container, port 8888)                      │
│  4. Health-check GET /health                                             │
│  5. Register RemoteRouterClient                                          │
│                                                                          │
│  Request flow:                                                           │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ User prompt                                                         │ │
│  │   → Pre-call guardrails (regex + judge + policy)                    │ │
│  │   → RemoteRouterClient.Route()                                      │ │
│  │       POST http://127.0.0.1:8888/api/v1/classify/intent             │ │
│  │       ← {recommended_model: "reasoning", routing_decision: "..."}   │ │
│  │   → Bifrost (format translation + auth + streaming)                 │ │
│  │       Uses recommended_model to select provider                     │ │
│  │       → Upstream LLM (Anthropic, OpenAI, Ollama, Bedrock, etc.)     │ │
│  │   → Post-call guardrails                                            │ │
│  │   → Response to user                                                │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│  Docker container: defenseclaw-semantic-router                            │
│  Image: ghcr.io/vllm-project/semantic-router/vllm-sr:v0.3.0              │
│  Entrypoint: /usr/local/bin/router (direct binary, no shell wrapper)     │
│  Port: 8888 (API server)                                                 │
│                                                                          │
│  Exposed endpoints:                                                      │
│  - GET  /health                    → {"status": "healthy"}               │
│  - GET  /ready                     → readiness + model status            │
│  - GET  /v1/models                 → available model list                │
│  - POST /api/v1/classify/intent    → routing decision (main API)         │
│  - POST /api/v1/classify/pii       → PII detection                       │
│  - POST /api/v1/classify/security  → jailbreak detection                 │
│  - POST /api/v1/classify/combined  → all-in-one classification           │
│                                                                          │
│  Capabilities:                                                           │
│  - 14 selection algorithms                                               │
│  - 17 signal types (keywords, embeddings, domain, complexity, etc.)      │
│  - Boolean decision trees (AND/OR/NOT)                                   │
│  - Runs on CPU only, no GPU required                                     │
└─────────────────────────────────────────────────────────────────────────┘
```

## Block Diagram: How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                         USER / AGENT                                  │
│                    (Claude Code, Hermes, Codex, etc.)                │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ LLM request
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    DEFENSECLAW GATEWAY                                │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  1. PRE-CALL GUARDRAILS                                      │    │
│  │     • Regex pattern matching                                 │    │
│  │     • LLM Judge (injection, PII, exfil)                      │    │
│  │     • OPA policy evaluation                                  │    │
│  │     → BLOCK if policy violation detected                     │    │
│  └──────────────────────────────┬──────────────────────────────┘    │
│                                 │ passed                             │
│                                 ▼                                    │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  2. SEMANTIC ROUTER (ModelRouter.Route)                       │    │
│  │                                                              │    │
│  │     RemoteRouterClient                                       │    │
│  │       │                                                      │    │
│  │       │  POST /api/v1/classify/intent                        │    │
│  │       │  {messages: [...]}                                   │    │
│  │       ▼                                                      │    │
│  │  ┌──────────────────────────────────┐                        │    │
│  │  │  Docker: defenseclaw-semantic-    │                        │    │
│  │  │         router (port 8888)       │                        │    │
│  │  │                                  │                        │    │
│  │  │  Signals: keyword match,         │                        │    │
│  │  │  embedding, domain, complexity   │                        │    │
│  │  │                                  │                        │    │
│  │  │  Decision: priority rules        │                        │    │
│  │  │  (AND/OR/NOT boolean tree)       │                        │    │
│  │  │                                  │                        │    │
│  │  │  Algorithm: static, elo,         │                        │    │
│  │  │  router-dc, automix, hybrid...   │                        │    │
│  │  └──────────────────┬───────────────┘                        │    │
│  │                     │                                        │    │
│  │       ← {recommended_model: "reasoning"}                     │    │
│  │                                                              │    │
│  └──────────────────────────────┬──────────────────────────────┘    │
│                                 │ model decided                      │
│                                 ▼                                    │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  3. BIFROST (Provider SDK)                                    │    │
│  │                                                              │    │
│  │     • Selects provider based on recommended_model            │    │
│  │     • Format translation:                                    │    │
│  │       OpenAI ↔ Anthropic ↔ Bedrock ↔ Gemini ↔ Ollama       │    │
│  │     • API key resolution (env vars, vaults)                  │    │
│  │     • Streaming (SSE chunked transfer)                       │    │
│  │     • Retry / failover                                       │    │
│  │                                                              │    │
│  └──────────────────────────────┬──────────────────────────────┘    │
│                                 │ formatted request                  │
│                                 ▼                                    │
│                    ┌────────────────────────┐                        │
│                    │    UPSTREAM LLM        │                        │
│                    │                        │                        │
│                    │  • api.anthropic.com   │                        │
│                    │  • api.openai.com      │                        │
│                    │  • Ollama localhost     │                        │
│                    │  • Bedrock             │                        │
│                    │  • Azure OpenAI        │                        │
│                    └────────────┬───────────┘                        │
│                                 │ response                           │
│                                 ▼                                    │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  4. POST-CALL GUARDRAILS                                      │    │
│  │     • Response inspection (PII, harmful content)             │    │
│  │     • Audit logging                                          │    │
│  │     • Telemetry (OTel spans, metrics)                        │    │
│  │     → BLOCK/REDACT if policy violation                       │    │
│  └──────────────────────────────┬──────────────────────────────┘    │
│                                 │                                    │
└─────────────────────────────────┼────────────────────────────────────┘
                                  │ response
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         USER / AGENT                                  │
└─────────────────────────────────────────────────────────────────────┘
```

### Integration Flow (Sequence)

```
    User          DefenseClaw        Semantic Router       Bifrost         LLM Provider
     │                │                    │                  │                │
     │─── prompt ────▶│                    │                  │                │
     │                │── guardrails ──┐   │                  │                │
     │                │                │   │                  │                │
     │                │◀── pass ───────┘   │                  │                │
     │                │                    │                  │                │
     │                │── classify/intent ─▶│                  │                │
     │                │                    │── evaluate ──┐   │                │
     │                │                    │  signals     │   │                │
     │                │                    │  decisions   │   │                │
     │                │                    │  algorithm   │   │                │
     │                │                    │◀─────────────┘   │                │
     │                │◀─ recommended_model─│                  │                │
     │                │                    │                  │                │
     │                │── forward(model) ──────────────────▶  │                │
     │                │                    │                  │── request ────▶│
     │                │                    │                  │◀── response ───│
     │                │◀───────────────────────────────────── │                │
     │                │                    │                  │                │
     │                │── post-guardrails ┐│                  │                │
     │                │◀──────────────────┘│                  │                │
     │◀── response ───│                    │                  │                │
     │                │                    │                  │                │
```

---

## Why Bifrost Is Still Required

The SR only answers **"which model should handle this?"** — it does NOT forward requests to backends.

| Concern | Semantic Router | Bifrost | DefenseClaw |
|---------|----------------|---------|-------------|
| Which model handles this request? | ✅ | — | — |
| Translate OpenAI ↔ Anthropic ↔ Bedrock ↔ Gemini format | — | ✅ | — |
| Resolve API keys | — | ✅ | ✅ |
| Handle streaming (SSE) | — | ✅ | — |
| Retry / failover | — | ✅ | — |
| Pre/post-call guardrails | — | — | ✅ |
| Audit logging, telemetry | — | — | ✅ |

---

## Routing Decision API

### `POST /api/v1/classify/intent`

**Request:**
```json
{
  "messages": [
    {"role": "user", "content": "analyze the tradeoffs between REST and gRPC"}
  ],
  "options": {"return_probabilities": true}
}
```

**Response:**
```json
{
  "recommended_model": "reasoning",
  "routing_decision": "reasoning_route",
  "matched_signals": {"keywords": ["complex_task"]},
  "classification": {"category": "reasoning_route", "confidence": 0.92},
  "decision_result": {"decision_name": "reasoning_route", "confidence": 0.92}
}
```

DefenseClaw uses `recommended_model` to override the Bifrost model selection. If the API is unavailable or returns no recommendation, the request falls through to the default provider.

---

## Config Schema (DefenseClaw config.yaml)

```yaml
routing:
  enabled: true
  version: "0.3.0"              # vllm-sr version (for pip install)
  port: 8888                    # API port the router listens on
  algorithm: hybrid             # global default selection algorithm

  # Optional: point to external SR instead of managed container
  remote:
    endpoint: ""                # e.g. http://sr-service:8080 (K8s/Docker)
    timeout_ms: 100

  models:
    - name: reasoning
      provider: anthropic
      model: claude-sonnet-4-6
      api_key_env: ANTHROPIC_API_KEY
      capabilities: [reasoning, analysis, long-context]
      cost_per_1k_tokens: 0.003
    - name: code
      provider: ollama
      model: qwen3:4b
      base_url: http://host.docker.internal:11434
      capabilities: [code, debugging]
      cost_per_1k_tokens: 0.0
    - name: fast
      provider: openai
      model: gpt-4o-mini
      api_key_env: OPENAI_API_KEY
      capabilities: [chat, simple-qa]
      cost_per_1k_tokens: 0.00015

  signals:
    keywords:
      - name: complex_task
        keywords: ["analyze", "compare", "synthesize", "step by step"]
        operator: OR
      - name: code_task
        keywords: ["code", "function", "debug", "implement"]
        operator: OR

  decisions:
    - name: reasoning_route
      priority: 100
      operator: AND
      conditions:
        - type: keyword
          name: complex_task
      model_refs: [reasoning]
    - name: code_route
      priority: 90
      operator: AND
      conditions:
        - type: keyword
          name: code_task
      model_refs: [code]
    - name: default_route
      priority: 10
      model_refs: [fast]
```

---

## Generated SR Config (v0.3 Canonical Format)

DefenseClaw translates the above into `~/.defenseclaw/semantic-router/config.yaml`:

```yaml
version: v0.3
listeners:
  - name: http-8888
    address: 0.0.0.0
    port: 8888
    timeout: 300s
providers:
  reasoning:
    provider: anthropic
    model: claude-sonnet-4-6
    capabilities: [reasoning, analysis, long-context]
    cost_per_1k_tokens: 0.003
  code:
    provider: ollama
    model: qwen3:4b
    base_url: http://host.docker.internal:11434
    capabilities: [code, debugging]
  fast:
    provider: openai
    model: gpt-4o-mini
    capabilities: [chat, simple-qa]
    cost_per_1k_tokens: 0.00015
routing:
  signals:
    keywords:
      - name: complex_task
        keywords: [analyze, compare, synthesize, step by step]
        operator: OR
      - name: code_task
        keywords: [code, function, debug, implement]
        operator: OR
  decisions:
    - name: reasoning_route
      description: Route to reasoning_route
      priority: 100
      rules:
        operator: AND
        conditions:
          - type: keyword
            name: complex_task
      modelRefs:
        - model: reasoning
    - name: code_route
      description: Route to code_route
      priority: 90
      rules:
        operator: AND
        conditions:
          - type: keyword
            name: code_task
      modelRefs:
        - model: code
    - name: default_route
      description: Route to default_route
      priority: 10
      rules:
        operator: AND
      modelRefs:
        - model: fast
```

---

## Component Implementation

### 1. Config Translator (`internal/routing/config_translate.go`)

Converts `config.RoutingConfig` → SR v0.3 canonical YAML:
- `version: v0.3` header
- `listeners[]` with port and timeout
- `providers{}` as named map (not array)
- `routing.signals` + `routing.decisions` (nested under routing, not top-level)
- Decisions use `rules{operator, conditions[]}` and `modelRefs[{model}]` format
- Atomic write (temp file + rename)

### 2. Lifecycle Manager (`internal/routing/lifecycle.go`)

Starts the router as a single Docker container:
```
docker run -d \
  --name defenseclaw-semantic-router \
  -v <config-dir>:/app/config \
  -p 8888:8888 \
  --entrypoint /usr/local/bin/router \
  ghcr.io/vllm-project/semantic-router/vllm-sr:v0.3.0 \
  -config=/app/config/config.yaml \
  -port=50051 \
  -enable-api=true \
  -api-port=8888
```

- Removes any existing container before starting
- Health checks via `GET /health` on configured port
- Stop via `docker rm -f`
- Single container (~10s startup), no Envoy/Redis/Postgres/Milvus

### 3. Remote Router Client (`internal/gateway/model_router_remote.go`)

Implements `ModelRouter` interface:
- `POST /api/v1/classify/intent` with messages
- Parses `recommended_model` from response
- Returns `ModelRouterDecision{Model: recommended_model}`
- 100ms default timeout, graceful nil-return on any error
- Connection pooling (10 idle connections)

### 4. Orchestrator (`internal/routing/orchestrator.go`)

Startup sequence:
1. Check Docker is available
2. Translate config to SR format
3. Start router container
4. Wait for health (60s timeout)
5. Return endpoint URL

### 5. Manager (`internal/routing/manager.go`)

Handles `pip install vllm-sr` for the CLI tool (used by setup command only, not by the container path). Checks if Docker is available.

### 6. CLI Command (`cli/defenseclaw/commands/cmd_setup.py`)

`defenseclaw setup routing --enable`:
1. Installs vllm-sr via pip (if not present)
2. Checks Docker is running
3. Saves config
4. Restarts gateway (which starts the container)

---

## Modes

| Mode | When | Behavior |
|------|------|----------|
| `managed` (default) | `routing.enabled: true` | DefenseClaw starts router container, manages lifecycle |
| `remote` | `routing.remote.endpoint` is set | DefenseClaw calls external SR instance (no container) |
| disabled | `routing.enabled: false` | Zero overhead, all requests go to default provider |

If the SR is unavailable (container crash, network error, timeout), the request falls through to the default provider — graceful degradation, not an error.

---

## What Runs (Minimal Footprint)

| Component | Required? | Notes |
|-----------|-----------|-------|
| **Router container** | Yes | Single container, ~200MB image, CPU only |
| Envoy | No | Not needed — we use classify API directly |
| Redis | No | Not needed for keyword-only routing |
| Postgres | No | Not needed for keyword-only routing |
| Milvus | No | Only needed if embedding signals enabled |
| Grafana/Prometheus/Jaeger | No | Observability lives in DefenseClaw |
| Dashboard | No | Config managed by DefenseClaw |
| Simulator | No | Dev/test only |

**Total: 1 container, ~10s startup, <5ms per routing decision.**

---

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Docker not running | Log error, routing disabled, gateway starts normally |
| Container fails to start | Log error, routing disabled |
| Container crashes | RemoteRouterClient gets error → nil → default provider |
| API timeout (>100ms) | nil → default provider |
| No routing decision returned | nil → default provider |
| Config validation fails | Refuse to write, keep previous |

---

## Tested End-to-End Results

```
$ curl /api/v1/classify/intent -d '{"messages":[{"role":"user","content":"analyze tradeoffs"}]}'
→ recommended_model: "reasoning", matched_signals: {keywords: ["complex_task"]}

$ curl /api/v1/classify/intent -d '{"messages":[{"role":"user","content":"implement fibonacci"}]}'
→ recommended_model: "code", matched_signals: {keywords: ["code_task"]}

$ curl /api/v1/classify/intent -d '{"messages":[{"role":"user","content":"what is 2+2"}]}'
→ recommended_model: "fast", matched_signals: {}
```

---

## File Structure

| File | Responsibility |
|------|----------------|
| `internal/routing/config_translate.go` | DefenseClaw config → SR v0.3 YAML |
| `internal/routing/config_translate_test.go` | Translation correctness tests |
| `internal/routing/lifecycle.go` | Docker container start/stop/health |
| `internal/routing/lifecycle_test.go` | Lifecycle logic tests |
| `internal/routing/orchestrator.go` | Full startup sequence orchestration |
| `internal/routing/manager.go` | pip install + Docker availability check |
| `internal/routing/manager_test.go` | Manager logic tests |
| `internal/gateway/model_router_remote.go` | RemoteRouterClient (classify/intent API) |
| `internal/gateway/model_router_remote_test.go` | Client tests (mock SR) |
| `internal/gateway/model_router_feedback.go` | Post-response feedback to SR |
| `internal/gateway/model_router_adapter.go` | NewRemoteModelRouter factory |
| `internal/gateway/sidecar.go` | Startup/shutdown wiring |
| `internal/config/config.go` | RoutingConfig types |
| `cli/defenseclaw/commands/cmd_setup.py` | setup routing CLI command |
| `cli/defenseclaw/config.py` | Python RoutingConfig model |
