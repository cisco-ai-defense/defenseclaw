# Managed Semantic Router Sidecar — Technical Spec

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable DefenseClaw to download, configure, and manage the vLLM Semantic Router as a local subprocess — providing all 14 selection algorithms and 17 signal types with zero user interaction with the SR binary directly. DefenseClaw owns the config, lifecycle, and API surface.

**Architecture:** DefenseClaw manages the semantic router binary the same way it manages `defenseclaw-gateway` (daemon lifecycle, PID tracking, log rotation, health checks). The user configures routing exclusively via `~/.defenseclaw/config.yaml`. At sidecar boot, DefenseClaw translates its `routing:` block into the SR's native config, starts the SR subprocess, and registers a `RemoteRouterClient` as the active `ModelRouter`. All LLM requests continue through Bifrost for provider translation, auth, and streaming — the SR only decides *which* model handles each request.

**Tech Stack:** Go (DefenseClaw gateway), vLLM Semantic Router binary (external, downloaded), HTTP JSON for router communication, existing Bifrost SDK for upstream forwarding.

## Global Constraints

- DefenseClaw is the single source of truth — users never edit SR config directly
- SR is a managed subprocess (like the gateway daemon): start, stop, health-check, log rotation
- Bifrost remains in the forwarding path for multi-provider format translation
- Fallback: if SR is unavailable, DefenseClaw falls through to default provider (zero disruption)
- Binary download: versioned, checksum-verified, platform-aware (darwin-arm64, darwin-amd64, linux-amd64, linux-arm64)
- SR listens on loopback only (127.0.0.1:8080), no auth needed (same trust model as guardrail proxy)
- Config hot-reload: when `routing:` block changes in config.yaml, DefenseClaw regenerates SR config and signals the SR to reload

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ~/.defenseclaw/config.yaml (single source of truth)                     │
│                                                                          │
│  routing:                                                                │
│    enabled: true                                                         │
│    algorithm: hybrid                                                     │
│    models: [...]                                                         │
│    signals: {...}                                                         │
│    decisions: [...]                                                       │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │ parsed at sidecar boot
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  DefenseClaw Gateway (sidecar.go Run)                                    │
│                                                                          │
│  1. Translate config.RoutingConfig → SR native YAML                      │
│     Write to ~/.defenseclaw/semantic-router/config.yaml                  │
│  2. Ensure SR binary exists (download if missing/outdated)               │
│  3. Start SR subprocess (managed lifecycle)                              │
│  4. Health-check SR on 127.0.0.1:8080/health                            │
│  5. Register RemoteRouterClient as ModelRouter                           │
│                                                                          │
│  Request flow:                                                           │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ User prompt                                                         │ │
│  │   → Pre-call guardrails (regex + judge + policy)                    │ │
│  │   → ModelRouter.Route(input)                                        │ │
│  │       → POST http://127.0.0.1:8080/v1/route                        │ │
│  │       ← {model, provider, base_url, reason}                        │ │
│  │   → Bifrost (format translation + auth + streaming)                 │ │
│  │       → Upstream LLM (Anthropic, OpenAI, Ollama, Bedrock, etc.)     │ │
│  │   → Post-call guardrails                                            │ │
│  │   → Response to user                                                │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│  Semantic Router subprocess (managed by DefenseClaw)                      │
│  Binary: ~/.defenseclaw/bin/semantic-router                               │
│  Config: ~/.defenseclaw/semantic-router/config.yaml                       │
│  Logs:   ~/.defenseclaw/semantic-router/router.log                        │
│  PID:    ~/.defenseclaw/semantic-router/router.pid                        │
│  Port:   127.0.0.1:8080                                                  │
│                                                                          │
│  Capabilities (all from vLLM SR):                                        │
│  - 14 selection algorithms                                               │
│  - 17 signal types (keywords, embeddings, domain, complexity, etc.)      │
│  - Boolean decision trees (AND/OR/NOT)                                   │
│  - Online learning (Elo, RL, KNN adapt from feedback)                    │
│  - Semantic caching                                                      │
│  - Built-in embedding inference (Candle/ONNX)                            │
└─────────────────────────────────────────────────────────────────────────┘
```

## Why Bifrost Is Still Required

| Concern | Semantic Router | Bifrost | DefenseClaw |
|---------|----------------|---------|-------------|
| Which model handles this request? | Yes | — | — |
| Translate OpenAI ↔ Anthropic ↔ Bedrock ↔ Gemini format | — | Yes | — |
| Resolve API keys (env vars, vaults, token resolvers) | — | Yes | Yes |
| Handle streaming (SSE, chunked transfer) | — | Yes | — |
| Retry / failover on provider errors | — | Yes | — |
| Pre/post-call guardrail inspection | — | — | Yes |
| Audit logging, telemetry, HILT | — | — | Yes |

**The SR answers "where?" — Bifrost handles "how to get there."**

Exception: when ALL models are behind the same OpenAI-compatible API (e.g., all Ollama), `rawForwardChatCompletion` (already exists) can bypass Bifrost. The router just swaps `base_url` + `model`.

---

## Config Schema (DefenseClaw config.yaml)

```yaml
routing:
  enabled: true                         # master switch
  version: "0.3.0"                      # desired SR binary version
  port: 8080                            # SR listen port (loopback only)
  algorithm: hybrid                     # global default algorithm

  # Embedding for signals (SR runs inference internally via Candle/ONNX,
  # or delegates to Ollama if configured)
  embedding:
    provider: ollama                    # ollama | internal (SR's built-in Candle)
    base_url: http://127.0.0.1:11434
    model: nomic-embed-text

  # LLM for classification signals (domain, complexity)
  llm_classifier:
    base_url: http://127.0.0.1:11434
    model: qwen3:4b

  # Model backends the router can choose from
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
      base_url: http://127.0.0.1:11434
      capabilities: [code, debugging, refactoring]
      cost_per_1k_tokens: 0.0
    - name: fast
      provider: openai
      model: gpt-4o-mini
      api_key_env: OPENAI_API_KEY
      capabilities: [chat, simple-qa]
      cost_per_1k_tokens: 0.00015

  # Signal configuration
  signals:
    keywords:
      - name: complex_task
        keywords: ["analyze", "compare", "synthesize", "step by step"]
        operator: OR
      - name: code_task
        keywords: ["code", "function", "debug", "implement"]
        operator: OR
    embedding:
      enabled: true
      threshold: 0.75
    domain:
      enabled: true
    complexity:
      enabled: true
    context_length:
      thresholds: [4096, 32768]
    # All other signals (language, pii, jailbreak, etc.) enabled by default

  # Decision rules with boolean tree conditions
  decisions:
    - name: complex_reasoning
      priority: 100
      conditions:
        operator: AND
        children:
          - signal: complex_task
          - signal: complexity
            min_confidence: 0.8
      model_refs: [reasoning]
      algorithm: router-dc

    - name: code_work
      priority: 90
      conditions:
        operator: OR
        children:
          - signal: code_task
          - signal: domain
            value: "code"
      model_refs: [code]
      algorithm: static

    - name: safe_default
      priority: 80
      conditions:
        operator: NOT
        children:
          - signal: jailbreak
      model_refs: [reasoning, code, fast]
      algorithm: hybrid

    - name: fallback
      priority: 10
      model_refs: [fast]
      algorithm: static
```

---

## SR Native Config (Generated by DefenseClaw)

DefenseClaw translates the above into the SR's own format and writes it to `~/.defenseclaw/semantic-router/config.yaml`. The user never sees or edits this file.

---

## Component Breakdown

### 1. SR Binary Manager (`internal/routing/manager.go`)

Responsibilities:
- Download SR binary from releases (versioned, checksummed)
- Platform detection (GOOS/GOARCH)
- Install to `~/.defenseclaw/bin/semantic-router`
- Version checking (upgrade when `routing.version` changes)
- Signature/checksum verification

Download URL pattern:
```
https://github.com/vllm-project/semantic-router/releases/download/v{version}/semantic-router-{os}-{arch}{.exe}
```

### 2. SR Lifecycle Manager (`internal/routing/lifecycle.go`)

Responsibilities:
- Start SR as detached subprocess (like `internal/daemon/`)
- PID file management (`~/.defenseclaw/semantic-router/router.pid`)
- Log rotation (`~/.defenseclaw/semantic-router/router.log`)
- Health check (GET `http://127.0.0.1:{port}/health`)
- Graceful shutdown (SIGTERM → SIGKILL after timeout)
- Restart on crash (watchdog-style)
- Context-aware: stops when gateway context is cancelled

### 3. Config Translator (`internal/routing/config_translate.go`)

Responsibilities:
- Convert `config.RoutingConfig` → SR native YAML format
- Write to `~/.defenseclaw/semantic-router/config.yaml`
- Signal to running SR to reload (POST `/v1/config/reload` or SIGHUP)
- Validate translated config before writing (fail-fast on bad config)

### 4. Remote Router Client (`internal/gateway/model_router_remote.go`)

Responsibilities:
- Implement `ModelRouter` interface
- POST to `http://127.0.0.1:{port}/v1/route` with request payload
- Parse response: `{backend_name, model, provider, base_url, api_key, reason}`
- Timeout handling (default 50ms, configurable)
- Graceful fallback: return nil on any error (gateway uses default path)
- Connection pooling (reuse HTTP connections)

Request/Response contract:
```json
// POST /v1/route
{
  "messages": [{"role": "user", "content": "analyze this code"}],
  "model": "requested-model",
  "stream": false,
  "session_id": "abc123",
  "user_id": "user@example.com"
}

// Response
{
  "backend": "reasoning",
  "model": "claude-sonnet-4-6",
  "provider": "anthropic",
  "base_url": "https://api.anthropic.com",
  "algorithm": "router-dc",
  "decision": "complex_reasoning",
  "confidence": 0.92,
  "reason": "embedding similarity 0.92 to 'reasoning and analysis' capability"
}
```

### 5. CLI Command (`internal/cli/setup_routing.go`)

```bash
defenseclaw setup routing --enable     # download binary, write config, start
defenseclaw setup routing --disable    # stop SR, remove from startup
defenseclaw setup routing --status     # show SR health, algorithm, signals
defenseclaw setup routing --upgrade    # download latest version
```

### 6. Feedback Loop (`internal/gateway/model_router_feedback.go`)

After each response:
- Record latency, token count, error status
- POST to SR's `/v1/feedback` endpoint so Elo/RL/KNN adapt
- Wired into the existing post-call path in `handleChatCompletion`

---

## Lifecycle Integration

### Startup sequence (in `sidecar.go Run()`)

```
1. Parse config.Routing
2. If !routing.Enabled → skip (zero overhead)
3. EnsureSRBinary(routing.Version) → download if missing/outdated
4. TranslateConfig(routing) → write SR native config
5. StartSR(port, configPath) → subprocess with PID tracking
6. WaitForHealth(port, timeout=5s) → poll /health
7. RegisterModelRouter(NewRemoteRouterClient(port, timeout))
8. Log: "[guardrail] semantic router enabled (v{version}, {algorithm})"
```

### Shutdown sequence

```
1. Gateway context cancelled
2. Send SIGTERM to SR process
3. Wait up to 5s for graceful exit
4. If still alive: SIGKILL
5. Remove PID file
```

### Hot-reload (config.yaml changes)

```
1. Config watcher detects routing: block change
2. TranslateConfig(newRouting) → write new SR config
3. POST /v1/config/reload to SR (or restart SR if reload unsupported)
4. Health-check new instance
5. Log: "[guardrail] semantic router config reloaded"
```

---

## File Structure

### New files to create

| File | Responsibility |
|------|----------------|
| `internal/routing/manager.go` | SR binary download, version check, platform detection |
| `internal/routing/manager_test.go` | Mock download, checksum verification |
| `internal/routing/lifecycle.go` | Start/stop/health-check/restart SR subprocess |
| `internal/routing/lifecycle_test.go` | Mock process lifecycle |
| `internal/routing/config_translate.go` | DefenseClaw config → SR native config YAML generation |
| `internal/routing/config_translate_test.go` | Translation correctness |
| `internal/gateway/model_router_remote.go` | RemoteRouterClient implementing ModelRouter |
| `internal/gateway/model_router_remote_test.go` | Mock SR API, timeout, fallback |
| `internal/gateway/model_router_feedback.go` | Post-response feedback to SR |
| `internal/cli/setup_routing.go` | CLI command: enable/disable/status/upgrade |

### Modified files

| File | Changes |
|------|---------|
| `internal/config/config.go` | Add `Mode`, `Version`, `Port`, `Embedding`, `LLMClassifier`, `Remote` fields to `RoutingConfig` |
| `internal/gateway/sidecar.go` | Add SR lifecycle startup/shutdown in `Run()` |
| `internal/gateway/model_router_adapter.go` | Construct `RemoteRouterClient` (managed or remote endpoint) |

---

## Error Handling & Observability

| Scenario | Behavior |
|----------|----------|
| SR binary download fails | Log error, routing disabled, gateway starts normally |
| SR fails to start | Log error, routing disabled, fall through to default |
| SR crashes mid-operation | RemoteRouterClient gets connection error → returns nil → default path |
| SR responds slowly (> timeout) | Request cancelled → nil → default path |
| SR returns unknown backend | Log warning, fall through to default |
| Config validation fails | Refuse to write bad config, keep previous |

Observability:
- `[routing] sr started (pid={pid}, version={ver}, port={port})`
- `[routing] sr stopped (reason={reason})`
- `[routing] route: decision={name} → backend={backend} model={model} latency={ms}ms`
- `[routing] sr unreachable: falling back to default provider`
- `X-Semantic-Router: routed` / `X-Semantic-Router-Reason: ...` response headers

---

## Testing Strategy

| Test type | What | How |
|-----------|------|-----|
| Unit | Config translation | Assert generated YAML matches expected structure |
| Unit | Remote client | httptest mock of SR API, verify request/response parsing |
| Unit | Lifecycle | Mock exec.Command, verify PID tracking, kill signals |
| Integration | Full flow | Start real SR binary (if available), route through it |
| E2E | End-to-end | Send curl to DefenseClaw → verify correct model selected |

---

## Deployment Options

| Environment | How SR runs |
|------------|------------|
| Developer laptop | Managed subprocess (default) |
| Docker Compose | Separate container, DefenseClaw connects via network |
| Kubernetes | Sidecar container in same pod |
| Enterprise (air-gapped) | Pre-install SR binary in image, skip download |

For Docker/K8s, `routing.mode: remote` + `routing.remote.endpoint` can point to an external SR instance instead of managing a subprocess.

---

## Estimated Effort

| Task | Effort |
|------|--------|
| SR binary manager (download, version, checksum) | 2 days |
| SR lifecycle manager (start/stop/health/restart) | 2 days |
| Config translator (DefenseClaw → SR native format) | 1 day |
| Remote router client + fallback | 1 day |
| Feedback loop integration | 0.5 day |
| CLI command (`setup routing`) | 1 day |
| Sidecar wiring (startup/shutdown) | 0.5 day |
| Config schema expansion | 0.5 day |
| Tests | 2 days |
| **Total** | **~10 days** |

---

## Modes (No Local Fallback)

When `routing.enabled: true`, DefenseClaw **always** uses the semantic router. There is no local keyword-only fallback mode.

| Mode | When | Behavior |
|------|------|----------|
| `managed` (default) | `routing.enabled: true` | DefenseClaw downloads SR binary, manages lifecycle, routes through it |
| `remote` | `routing.remote.endpoint` is set | DefenseClaw connects to an externally managed SR instance (Docker/K8s) |

If the SR is unavailable (crash, network error, timeout), the request **falls through to the default provider** (no routing override applied) — this is graceful degradation, not a "local routing mode". The user's configured `llm.model` or Bifrost default takes over until SR recovers.

### Migration

1. `routing.enabled: false` (or absent) — routing is off, zero overhead, all requests go to default provider
2. `routing.enabled: true` — SR is required; DefenseClaw downloads and starts it automatically
3. `routing.remote.endpoint: http://...` — uses external SR instead of managed subprocess
