## Semantic Model Routing for Codex and Claude Code

### What

Adds intelligent model routing to DefenseClaw — the proxy classifies each LLM request by intent (planning vs coding) and routes to the appropriate backend (cloud model for planning, local model for coding). Works with the existing SR v0.3 container and supports four signal types for classification.

### Why

- **Cost optimization**: Route simple coding tasks to free local models (Ollama) instead of expensive cloud APIs
- **Capability matching**: Planning/architecture queries go to powerful reasoning models, implementation tasks go to code-tuned models
- **Resilience**: Fallback chains — if primary backend is unreachable, automatically try the next

### Changes (15 files, +2150/-110 lines)

#### Signal Type System (config layer)
- **`internal/config/config.go`** — New structs: `RoutingEmbeddingSignal`, `RoutingDomainSignal`, `RoutingComplexitySignal`, `RoutingEmbeddingsConfig`. Extended `RoutingCondition` with `MinConfidence`. Added `Auth` field to `RoutingModelBackend` with `EffectiveAuth()` auto-inference.
- **`internal/config/routing_validate.go`** — Validation expanded from keyword-only to four condition types: `keyword`, `embedding`, `domain`, `complexity`. Cross-validation: embedding conditions require model paths, `min_confidence` range 0.0-1.0, signal name references checked per type.
- **`internal/config/routing_validate_test.go`** — Full round-trip test with all signal types, backward compatibility for keyword-only configs, embedding-without-model-paths rejection, min_confidence range check.
- **`schemas/config/v8/defenseclaw-config.schema.json`** — JSON Schema extended with `signals.embeddings[]`, `signals.domains[]`, `signals.complexity[]`, `routing.embeddings`, expanded condition type enum, `min_confidence`, `auth` enum on model backends.

#### SR Translation (config → container)
- **`internal/routing/config_translate.go`** — SR v0.3 YAML generation for all signal types. Fixed critical field name: `examples` → `candidates` (verified by probing SR container's `/api/v1/classify/intent` endpoint). Added `SREmbeddingSignal`, `SRDomainSignal`, `SRComplexitySignal` structs with `TranslateEmbedding`, `TranslateDomain`, `TranslateComplexity` input types.

#### Gateway Wiring (sidecar → proxy → router)
- **`internal/gateway/sidecar.go`** — `buildTranslateInput()` passes all signal types + embedding model paths to SR. `RoutingEnabled` wired on `SetupOpts` at all three construction sites. `buildModelRouterBackends()` passes `Auth` field. **Auto-generates default embedding/domain/complexity signals** when embedding models are present on disk. **Augments keyword-only decisions** with embedding OR conditions for semantic fallback.
- **`internal/gateway/connector/connector.go`** — Added `RoutingEnabled bool` to `SetupOpts`.
- **`internal/gateway/model_router.go`** — Added `Auth string` to `ModelRouterBackend`.
- **`internal/gateway/model_router_remote.go`** — Credential resolution switches on auth mode: `passthrough` (keep client's Authorization header), `api_key` (replace with env var), `none` (strip header). Applied to both SR-classified and local keyword fallback paths.

#### Proxy Traffic Handling
- **`internal/gateway/proxy.go`** — `extractResponsesAPIMessages()` parses Responses API `input[]` for routing classification. Client-auth passthrough in direct-provider hydration. Model patching skipped for passthrough auth. `handleModels` proxies to real upstream (ChatGPT format). `patchPreferWebsockets(false)` in `/models` response to force Codex HTTP fallback. `stripUnsupportedInputItems` on HTTP passthrough for non-ChatGPT backends. `bodyModified` tracking to preserve original zstd body for ChatGPT passthrough (encrypted content integrity).
- **`internal/gateway/proxy_websocket.go`** — **New file** (462 lines). WebSocket passthrough to ChatGPT. WS-to-HTTP bridge for backends without WS support (Ollama). WebSocket upgrade rejected when model router is active (forces HTTP fallback for routing). `stripUnsupportedInputItems()` removes `additional_tools` for non-ChatGPT backends. `patchModelInJSON()` rewrites model name in WS/HTTP frames. `extractTextFromContentParts()` parses Responses API content arrays.

#### Connector Setup
- **`internal/gateway/connector/codex.go`** — `openai_base_url` patched when `RoutingEnabled` (not just `HybridProxyMode`). Dropped `/v1` suffix for ChatGPT backend path alignment.
- **`internal/gateway/connector/claudecode.go`** — `ANTHROPIC_BEDROCK_BASE_URL` patched when `RoutingEnabled`. Enables Bedrock proxy mode for Claude Code routing.

#### CLI & TUI
- **`cli/defenseclaw/commands/cmd_setup.py`** — Interactive routing wizard (`--interactive` flag). Walks user through adding model backends, describing task types, auto-generating keyword signals with synonym expansion. Detects embedding model availability. Only enabled for codex, openclaw, hermes connectors.
- **`cli/defenseclaw/tui/panels/setup.py`** — `SEMANTIC_ROUTING` wizard in TUI setup panel with enable/disable toggle, model count display, connector selector.

### How Routing Works

```
Codex exec "implement fibonacci"
  → GET /models (proxy returns prefer_websockets: false)
  → WS upgrade rejected (501, routing active)
  → HTTP POST /responses (fallback)
  → Decompress zstd, extract user msg from input[]
  → SR classifies: "implement" → coding_intent → ollama-local
  → Strip additional_tools, patch model → qwen3:4b
  → Forward to http://127.0.0.1:11434/v1/responses
  → Stream response back to Codex

Codex exec "plan the architecture"
  → Same flow, but:
  → SR classifies: "plan" → planning_intent → chatgpt-default
  → Forward original zstd body to chatgpt.com (passthrough)
```

### SR v0.3 Signal Types

| Signal | How It Matches | Status |
|--------|---------------|--------|
| `keyword` | Case-insensitive substring, AND/OR operators | ✅ Working |
| `embedding` | MMBert semantic similarity via `candidates` field. Confidence 0.0-1.0. | ✅ Working (fixed `examples` → `candidates`) |
| `domain` | Category detection (kubernetes, docker, sql, etc.) | ✅ Config generated, SR parses |
| `complexity` | Message length, tool count, indicators | ✅ Config generated, SR parses |

### Auth Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| `passthrough` | Forward client's original Authorization header | Codex OAuth → ChatGPT |
| `api_key` | Replace with env var value | DGX, OpenRouter, etc. |
| `none` | Strip Authorization header | Ollama (keyless) |
| `aws_sigv4` | Rejected (Phase 2) | Claude Code → Bedrock |

### User Setup

```bash
# Option A: Interactive wizard
defenseclaw setup codex --mode observe --yes
defenseclaw setup routing --enable --interactive
DEFENSECLAW_CODEX_LOOPBACK_TRUST=1 defenseclaw-gateway

# Option B: TUI
defenseclaw  # Navigate to Setup → Semantic Routing

# Option C: Manual config.yaml edit
```

### Testing

- [x] `go test ./internal/config/` — all pass
- [x] `go test ./internal/routing/` — all pass
- [x] `codex exec "implement fibonacci"` → Ollama qwen3:4b
- [x] `codex exec "plan an API"` → ChatGPT passthrough
- [x] curl HTTP routing tests for both paths
- [x] SR embedding preload verified (8 candidates, 768 dimensions)
- [x] ChatGPT encrypted content integrity preserved (zstd body passthrough)
- [ ] `defenseclaw setup routing --enable --interactive` wizard flow
- [ ] TUI Semantic Routing panel
- [ ] Claude Code Bedrock→Ollama translation

### Known Limitations

1. **Codex WS adds ~15s startup delay** — WS rejected, Codex retries 5x before HTTP fallback. Subsequent requests in same session are fast.
2. **SR embedding with MMBert only** — Qwen3 model needed for batched embeddings. MMBert works for per-request classification.
3. **Claude Code routing untested E2E via Cursor** — Verified with curl; full Cursor integration needs testing with `ANTHROPIC_BEDROCK_BASE_URL` pointed at proxy.
4. **`aws_sigv4` auth not implemented** — Bedrock passthrough uses static bearer token, not SigV4 re-signing.
