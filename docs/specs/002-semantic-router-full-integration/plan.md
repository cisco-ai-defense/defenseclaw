# Plan: Full vLLM Semantic Router Integration

## Scope

### In scope

- Expand `internal/config/config.go` RoutingConfig to full v0.3 schema (~40 types)
- Expand `internal/routing/config_translate.go` to emit complete v0.3 YAML
- Add config validation (`internal/routing/config_validate.go`)
- Expand classify request to pass session/user/tools/headers/metadata
- Expand classify response parsing to handle plugin outputs
- Handle cached responses, system prompts, RAG context, compression, header mutations
- Pass reasoning_effort and lora_name through to Bifrost
- Enrich feedback with decision name, cost, TTFT/TPOT
- Hot config reload via SR management API
- ML model catalog download and management
- CLI commands: `routing replay`, `routing status`, `setup routing --install-models`
- Kubernetes sidecar deployment support
- Batch classification API support
- Router learning configuration

### Out of scope

- Building a custom SR dashboard UI in DefenseClaw
- Reimplementing any SR algorithm logic in Go
- Running SR's Envoy proxy mode (DC uses classify API directly)
- SR's fleet-sim traffic simulation tool
- SR's training pipeline for fine-tuning classifiers
- Multi-SR-instance load balancing (single instance per DC sidecar)
- SR's gRPC ExtProc integration (Envoy-specific)

## Dependencies

### Internal

- `feature/semantic-router` branch — existing integration (ModelRouter interface,
  RemoteRouterClient, Lifecycle, Orchestrator, config_translate)
- Bifrost SDK — for passing reasoning params and LoRA to upstream providers
- Config watcher — for triggering hot reloads
- Audit store — for logging routing decisions

### External

- vLLM Semantic Router v0.3 Docker image (`ghcr.io/vllm-project/semantic-router/vllm-sr:v0.3`)
- vLLM SR ML model catalog (Hugging Face: `LLM-Semantic-Router/`)
- Docker runtime (for managed mode)
- Optional: Redis/Valkey, Milvus, Postgres (for persistence features)

## Implementation Phases

### Phase 1: Config Expansion (~1 week)

**Goal:** SR evaluates all signals and algorithms server-side. DC just writes richer config.

1. Define all config types in `internal/config/config.go`
2. Expand `config_translate.go` to emit full v0.3 YAML
3. Add `config_validate.go` for cross-reference validation
4. Expand `buildTranslateInput()` in sidecar.go
5. Update Python `cli/defenseclaw/config.py` RoutingConfig
6. Add model catalog volume mount to Lifecycle.Start()
7. Add `setup routing --install-models` CLI command

**Validation:** Generate config, start SR with it, verify SR accepts it.

### Phase 2: Rich Context Passing (~3 days)

**Goal:** SR has full request context for session/user/conversation signals.

1. Expand `ModelRouterInput` struct with session, user, tools, headers, metadata
2. Expand `classifyRequest` in RemoteRouterClient with new fields
3. Extract session_id, user_id from connector auth headers in proxy.go
4. Pass guardrail signals (jailbreak_score, pii, severity) as metadata
5. Add configurable header passthrough list to RoutingConfig

**Validation:** Verify SR's reask/conversation/authz signals fire with context.

### Phase 3: Rich Response Consumption (~1 week)

**Goal:** DC leverages all SR plugin outputs.

1. Expand `classifyResponse` struct with plugin_outputs
2. Expand `ModelRouterDecision` with system_prompt, reasoning_effort, rag_context, etc.
3. Handle cached_response → serve directly (path already exists)
4. Inject system_prompt into messages before Bifrost
5. Inject RAG context (system_prompt mode, tool_role mode, or inline)
6. Handle compressed_prompt (replace messages with compressed version)
7. Apply header_mutations to response
8. Pass reasoning_effort + lora_name through Bifrost to provider
9. Log warnings from SR

**Validation:** E2E test each plugin output path.

### Phase 4: Operational Integration (~1 week)

**Goal:** Production-grade operational features.

1. Enrich RouterFeedback with decision name, cost, TTFT/TPOT, satisfaction
2. Implement hot config reload (watch → translate → POST /config)
3. Add `defenseclaw routing replay` CLI command
4. Add `defenseclaw routing status` CLI command (models loaded, health, decisions/sec)
5. Add Kubernetes sidecar support (generate container spec)
6. Add batch classification support for prefetch scenarios
7. Configure router learning system (adaptation, protection, state store)
8. Add routing degradation detection and audit events

**Validation:** Hot reload without restart, replay shows decisions, K8s deploys.

## Rollout Plan

### Stage 1: Feature flag (default off)

All new config fields are optional. Existing `routing.enabled: true` with just
`keywords` continues to work exactly as before. New features activate only when
configured.

### Stage 2: Progressive config expansion

Users can adopt features incrementally:
1. Start with keywords only (current behavior)
2. Add embeddings + complexity (requires model catalog)
3. Add plugins (response_cache, system_prompt)
4. Add learning + session awareness
5. Add external stores (Redis, Milvus) for persistence

### Stage 3: Image versioning

- Default image: `vllm-sr:v0.3` (no models, small, fast start)
- Models image: `vllm-sr:v0.3-models` (includes classifier catalog)
- Custom image: user builds with their own models/KBs

### Backward Compatibility

- Existing configs with only `routing.models`, `routing.signals.keywords`,
  `routing.decisions` continue to work unchanged
- New fields are all optional with zero-value defaults
- SR container version pinned in config (user controls upgrade)
- Config translator handles old-format → new-format gracefully

## Observability Plan

### Logs

| Event | Level | Fields |
|-------|-------|--------|
| Routing decision made | INFO | `decision`, `model`, `confidence`, `matched_signals`, `latency_ms` |
| Cache hit served | INFO | `decision`, `cache_type` (exact/semantic), `ttl_remaining` |
| System prompt injected | DEBUG | `decision`, `prompt_length` |
| RAG context injected | DEBUG | `decision`, `num_documents`, `injection_mode` |
| Prompt compressed | INFO | `decision`, `original_tokens`, `compressed_tokens`, `ratio` |
| Config hot reloaded | INFO | `changed_sections` |
| SR health degraded | WARN | `last_healthy`, `duration_unhealthy` |
| SR health recovered | INFO | `downtime_duration` |
| Model catalog downloaded | INFO | `models_count`, `total_size_mb` |
| Routing fallback (SR error) | WARN | `error`, `fallback_to` |

### Metrics (OTel)

| Metric | Type | Labels |
|--------|------|--------|
| `defenseclaw.routing.decisions_total` | Counter | `decision`, `model`, `algorithm` |
| `defenseclaw.routing.latency_ms` | Histogram | `decision`, `outcome` (routed/fallback/cached) |
| `defenseclaw.routing.cache_hits_total` | Counter | `cache_type` (exact/semantic) |
| `defenseclaw.routing.signals_matched` | Counter | `signal_type`, `signal_name` |
| `defenseclaw.routing.feedback_sent_total` | Counter | `success` |
| `defenseclaw.routing.sr_health` | Gauge | (0=down, 1=healthy) |
| `defenseclaw.routing.model_cost_usd` | Counter | `model`, `decision` |
| `defenseclaw.routing.compression_ratio` | Histogram | `decision` |

### Traces

| Span | Parent | Attributes |
|------|--------|------------|
| `routing.classify` | `guardrail.proxy.request` | `sr.decision`, `sr.model`, `sr.confidence`, `sr.algorithm` |
| `routing.apply_decision` | `guardrail.proxy.request` | `cache_hit`, `system_prompt_injected`, `rag_injected` |
| `routing.feedback` | `guardrail.proxy.request` | `model`, `latency_ms`, `tokens` |

## Security Plan

### Auth/Authz

- SR management API (POST /config, GET /replay) is bound to `127.0.0.1` only —
  not exposed to the network. DC calls it over localhost.
- User identity (user_id, user_groups) forwarded to SR comes from the already-
  authenticated connector headers — no additional auth layer needed.
- SR's internal authz signals evaluate role bindings but do not enforce access
  control — they only influence model selection.

### Data handling

- **Prompt content**: Sent to SR over localhost (same machine). SR processes
  in-memory, no persistent storage unless router_replay or response_cache plugins
  are enabled.
- **API keys**: Never sent to SR. DC resolves API keys after SR selects the model.
  SR only sees model names, not credentials.
- **PII in routing**: SR's PII classifier can detect PII in prompts (for routing
  decisions), but the actual redaction/blocking remains in DC's guardrail pipeline.
- **Model catalog**: Downloaded from Hugging Face over HTTPS. Checksum verified.
  Stored in `~/.defenseclaw/routing-models/`.

### Multi-tenancy

- SR operates per-sidecar (one instance per DC gateway). Tenant isolation is
  maintained by DC's existing connector/tenant separation.
- Session state (if Redis configured) uses tenant-scoped key prefixes.
- Router learning state is scoped to the conversation (session_id), not shared
  across tenants.

### Container security

- SR container runs as non-root user
- Read-only filesystem except for /tmp and /app/data
- No network access except localhost (DC communicates over mapped port)
- Health check endpoint does not expose sensitive information
