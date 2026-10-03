# PR #999: Hybrid Proxy Mode — Semantic Routing, Responses API Bridge, and Multi-Connector LLM Proxy

## Summary

Adds semantic model routing and LLM traffic proxying across 11 of 14 connectors, with a Bifrost-based Responses API → chat/completions bridge that enables Codex (and any Responses API client) to work with providers that only support chat/completions — including custom providers like Cisco AI Gateway.

## Key Features

### 1. Responses API → Chat/Completions Bridge via Bifrost

New `handleResponsesAPI` handler on `/v1/responses` and `/responses` that:
- Parses Responses API `input[]` messages
- Runs the semantic router for model classification
- Converts `developer` role → `system` for strict providers
- Calls Bifrost's `ChatCompletionStream` with `path_override` from config
- Streams real-time SSE deltas back as Responses API events (`response.output_text.delta`)
- Emits `response.completed` with full content and usage tokens
- Falls through to the first configured routing model when no intent matches (confidence below threshold)

### 2. Guardrail Inspection on Responses API Path

- **Pre-call**: Inspects user input before sending to the LLM. Blocks with a Responses API SSE stream containing the block reason (not a JSON error that Codex would ignore)
- **Post-call**: Inspects the full assistant response after streaming completes
- Tested: `SEC-ANTHROPIC` rule blocks API keys in prompts → `CRITICAL/block` verdict

### 3. Semantic Router with Confidence Threshold

- Embedding-based intent classification via MMBert (4 signals: science, math, coding, architecture)
- `min_confidence` threshold enforcement — low-confidence matches (< 0.6) fall through to default model instead of routing to the wrong model
- Config-only signal definition with 10 example phrases per intent

### 4. Custom Provider Support (Config-Only)

Three new fields on `routing.models[]` enable any custom LLM provider without code changes:

```yaml
routing:
  models:
  - name: claude-sonnet
    provider: azure
    model: claude-sonnet-4-6
    base_url: https://chat-ai.cisco.com/openai/deployments/claude-sonnet-4-6
    api_key_env: CISCO_AI_JWT
    path_override: /chat/completions    # Override Bifrost's default /v1/ prefix
    extra_headers:                       # Custom HTTP headers per model
      api-key: <resolved from api_key_env>
    extra_body:                          # Custom request body fields per model
      user: '{"appkey":"..."}'
```

- `path_override`: Override API path for providers without `/v1/` prefix
- `extra_headers`: Per-model HTTP headers (wired through `ModelRouterDecision`)
- `extra_body`: Per-model request body injection (e.g. Cisco appkey)
- `effectiveProvider`: Uses routing decision's provider for auth header selection (`api-key` for Azure, `x-api-key` for Anthropic, `Authorization: Bearer` for OpenAI)

### 5. Codex `model_providers` Integration (OpenRouter Pattern)

Replaces the legacy `openai_base_url` redirect with the `model_providers` extension mechanism:

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

- Gateway token baked into config at setup time (no env var needed)
- `wire_api = "responses"` + `supports_websockets = false` forces HTTP POST
- `Authenticate()` accepts gateway token on `Authorization: Bearer` header
- Cleanup path removes stale `model_providers.defenseclaw` on teardown

### 6. LLM Proxy Routing for 11 Connectors

| Connector | Mechanism | Confidence |
|-----------|-----------|------------|
| **Codex** | `model_providers.defenseclaw` + Bifrost Responses API bridge | Proven (OpenRouter pattern) |
| **Claude Code** | `ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN` | Proven (OpenRouter pattern) |
| **OpenCode** | `opencode.json` provider + `auth.json` | Proven (OpenRouter pattern) |
| **Hermes** | `~/.hermes/.env` + proxy env file | Proven (OpenRouter pattern) |
| **ZeptoClaw** | `config.json` api_base patch | Proven (dedicated) |
| **OpenClaw** | Fetch interceptor plugin | Proven (dedicated) |
| **Cursor** | UI-only (prints setup instructions) | Partial |
| **Copilot** | Proxy env file | Best-effort |
| **OpenHands** | Proxy env file (`LLM_BASE_URL`) | Best-effort |
| **Devin** | Proxy env file | Best-effort |
| **Amp** | Proxy env file after plugin install | Best-effort |
| Kiro / OmniGent / Antigravity | Vendor-dependent | Not supported |

### 7. Proxy Fixes

- **Content-Length mismatch**: `len(forwardBody)` instead of `len(body)` for zstd passthrough
- **Stray `bodyModified`**: Removed unconditional flag that broke ChatGPT encrypted content
- **Routing telemetry**: `recordSemanticRoutingDecisionV8()` now emits on the passthrough path
- **`/models` endpoint**: Returns routing models with `prefer_websockets: false`
- **`/responses` → `/chat/completions`** path rewrite for Azure providers in passthrough

## Files Changed

### Gateway Core
- `internal/gateway/proxy.go` — `handleResponsesAPI`, `effectiveProvider`, `extra_headers`/`extra_body` injection, guardrail inspection, SSE block messages, `/responses` path rewrite
- `internal/gateway/provider_bifrost.go` — `ResponsesStreamRaw()`, `bifrostURLPathKey`, `pathOverride`, `extraBody` support
- `internal/gateway/model_router.go` — `ExtraHeaders`, `ExtraBody`, `PathOverride` on `ModelRouterBackend` and `ModelRouterDecision`
- `internal/gateway/model_router_remote.go` — `minConfidence` threshold enforcement, wiring `ExtraHeaders`/`ExtraBody`/`PathOverride`
- `internal/gateway/sidecar.go` — Wire new config fields into backend construction

### Connectors
- `internal/gateway/connector/codex.go` — `model_providers.defenseclaw` setup, `wire_api`/`supports_websockets`, gateway token auth on `Authorization: Bearer`
- `internal/gateway/connector/claudecode.go` — `ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN` (OpenRouter pattern), gateway token on Bearer
- `internal/gateway/connector/hook_only.go` — Proxy env files for Cursor, Copilot, Hermes, OpenHands, Devin; OpenCode provider config; `writeProxyEnvFile()` helper; Hermes native `.env`
- `internal/gateway/connector/connector.go` — `resolveGatewayTokenForProxyEnv()` helper

### Config
- `internal/config/config.go` — `ExtraHeaders`, `ExtraBody`, `PathOverride` on `RoutingModelBackend`
- `schemas/config/v8/defenseclaw-config.schema.json` — Schema validation for new fields

## Testing

Tested end-to-end:
- Codex → DefenseClaw → Cisco AI Gateway (5 models) with streaming SSE
- Semantic router classifies intent with embedding signals (MMBert)
- Confidence threshold (0.6) prevents misrouting general queries
- Guardrail blocks API keys in prompts (`SEC-ANTHROPIC` → `CRITICAL/block`)
- Block message returned as Responses API SSE (not JSON error)
- All 5 Cisco models respond through Bifrost bridge

```
Codex → DefenseClaw proxy (:4000)
  → Guardrail inspection (pre-call)
  → Semantic Router (MMBert embeddings, 4 intents)
  → Bifrost ChatCompletionStream (Responses→chat/completions bridge)
  → Cisco chat-ai.cisco.com (api-key + appkey via config)
  → SSE stream back as Responses API events
  → Guardrail inspection (post-call)
  → Codex displays response
```
