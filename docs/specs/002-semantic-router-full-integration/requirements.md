# Requirements: Full vLLM Semantic Router Integration

## Context

DefenseClaw's `feature/semantic-router` branch integrates the vLLM Semantic Router
(SR) as a managed sidecar for intelligent model routing. The current integration is
minimal — it sends messages to `POST /api/v1/classify/intent` and receives a
`recommended_model` string. This utilizes approximately 5% of SR's capabilities.

The vLLM Semantic Router v0.3 ("Themis") offers 17+ signal types, 16+ selection
algorithms, 12+ plugins, session-aware learning, semantic caching, RAG pipelines,
hallucination detection, and a full ML model catalog. This spec covers expanding the
integration to leverage the full SR feature set while preserving DefenseClaw's
existing guardrail pipeline architecture.

**Key constraint:** SR is config-driven — most features activate by writing a richer
v0.3 config YAML. The integration strategy prioritizes config expansion (80% of value)
over code changes.

**Branch:** `feature/semantic-router`
**SR version:** v0.3 (Themis release, 2026-06-05)
**SR repo:** github.com/vllm-project/semantic-router

## EARS Requirements

### Phase 1: Config Expansion

- REQ-01: The system shall support configuring all 17 SR signal types (keywords,
  embeddings, domain, complexity, context, structure, modality, language, pii,
  jailbreak, fact_check, user_feedbacks, reasks, preferences, conversation, events,
  metadata, role_bindings, kb, classifiers) in `~/.defenseclaw/config.yaml`.

- REQ-02: The system shall support configuring all SR selection algorithms (static,
  elo, router_dc, automix, hybrid, confidence, ratings, remom, fusion, workflows,
  latency_aware, multi_factor, prompt, knn, kmeans, svm, mlp) with their
  algorithm-specific parameters in decision rules.

- REQ-03: The system shall support configuring SR plugins (response_cache,
  context_compression, rag, memory, tools, tool_selection, hallucination, image_gen,
  system_prompt, header_mutation, response_jailbreak, fast_response, request_params,
  router_replay) per decision rule.

- REQ-04: The system shall translate the full DefenseClaw routing config into SR v0.3
  canonical YAML format, including: listeners, providers with model cards (pricing,
  quality_score, capabilities, LoRA, backend_refs), routing signals, routing
  decisions with algorithm params and plugins, projections, recipes, entrypoints,
  and global settings.

- REQ-05: The system shall support configuring model cards with param_size,
  context_window_size, quality_score, capabilities, modality, tags, LoRA adapters,
  pricing (prompt_per_1m, completion_per_1m, cached_input_per_1m), and weighted
  backend_refs with health checks.

- REQ-06: The system shall support SR's global configuration including model_catalog
  (embedded ML classifiers), modules (prompt_compression, prompt_guard, domain
  classifier, PII classifier, hallucination_mitigation, feedback_detector,
  modality_detector), and services (response_api, observability, authz, ratelimit).

- REQ-07: When `routing.enabled: true` and ML models are configured, the system
  shall mount the model catalog directory into the SR container so that embedded
  classifiers (jailbreak, domain, PII, fact-check, hallucination, feedback,
  modality) are available.

- REQ-08: The system shall support SR's projection system (partitions, scores with
  weighted_sum, and threshold_band mappings) for computing derived routing signals
  from combinations of base signals.

- REQ-09: The system shall support SR's recipe system, allowing named routing
  configurations that can be referenced as virtual model names via entrypoints.

### Phase 2: Rich Context Passing

- REQ-10: When routing a request, the system shall pass the full conversation
  history (all messages including tool results), tool definitions, and stream flag
  to the SR classify endpoint.

- REQ-11: When routing a request, the system shall pass session identity
  (session_id, conversation_id) to SR so that session telemetry, reask detection,
  and conversation signals can operate correctly.

- REQ-12: When routing a request, the system shall pass user identity (user_id,
  user_groups) from connector authentication headers to SR so that authz/role_binding
  signals and per-user rate limiting can operate.

- REQ-13: When routing a request, the system shall pass request metadata headers
  (configurable list) to SR so that metadata signals (e.g., consent headers,
  tenant info) can be evaluated.

- REQ-14: When routing a request, the system shall pass DefenseClaw guardrail
  signals (jailbreak_score, pii_detected, severity) as metadata so SR can use them
  as additional routing inputs without re-computing.

### Phase 3: Rich Response Consumption

- REQ-15: When SR returns a cached_response in the classify response, the system
  shall serve it directly to the client with `X-Semantic-Router: cache-hit` header,
  bypassing Bifrost forwarding entirely.

- REQ-16: When SR returns a system_prompt in the classify response, the system
  shall prepend it to the messages array before forwarding to the upstream provider
  via Bifrost.

- REQ-17: When SR returns reasoning_effort and use_reasoning in the classify
  response, the system shall pass these parameters through Bifrost to the upstream
  provider (as provider-specific parameters: `thinking` for Anthropic,
  `reasoning_effort` for OpenAI, etc.).

- REQ-18: When SR returns header_mutations in the classify response, the system
  shall apply add/update/delete mutations to the response headers sent to the client.

- REQ-19: When SR returns rag_context (retrieved documents) in the classify response,
  the system shall inject them into the request using the configured injection_mode
  (system_prompt, tool_role, or inline) before forwarding to Bifrost.

- REQ-20: When SR returns compressed_prompt in the classify response, the system
  shall use the compressed version instead of the original messages when forwarding
  to the upstream provider.

- REQ-21: When SR returns warnings in the classify response, the system shall log
  them at WARN level and include them in the audit trail.

- REQ-22: When SR returns lora_name in the classify response, the system shall
  include it in the Bifrost request parameters for providers that support LoRA
  adapter selection.

### Phase 4: Operational Integration

- REQ-23: The system shall send enriched feedback to SR's `/v1/feedback` endpoint
  after each response completes, including: model used, decision name, latency_ms,
  tokens (prompt + completion), success/failure, and optional user satisfaction
  signal when available.

- REQ-24: When routing config changes are detected via the config watcher, the
  system shall call SR's `POST /config` management API for hot reload instead of
  restarting the container.

- REQ-25: The system shall expose SR's router replay data via `defenseclaw routing
  replay` CLI command, querying SR's replay API for recent routing decisions.

- REQ-26: The system shall support downloading and managing SR's ML model catalog
  via `defenseclaw setup routing --install-models` command.

- REQ-27: Where Kubernetes deployment is configured, the system shall support
  deploying SR as a Kubernetes sidecar container (instead of Docker-run) using the
  existing Helm chart patterns.

- REQ-28: The system shall support SR's batch classification API
  (`POST /api/v1/classify/batch`) for scenarios where multiple requests can be
  classified in a single round-trip.

- REQ-29: If SR's health check fails for more than 30 seconds after being
  previously healthy, the system shall emit a `routing.degraded` audit event and
  continue operating with default provider fallback.

- REQ-30: The system shall support SR's router learning system, including:
  adaptation mode (observe/apply/bypass per route), protection settings
  (stability_weight, switch_margin), and state store configuration (Redis/Valkey).

### Non-Functional

- REQ-31: The routing decision latency overhead shall not exceed 50ms at p95 for
  keyword/embedding signals, and 200ms at p95 for ML classifier signals.

- REQ-32: The system shall gracefully degrade (return nil → use default provider)
  for any SR failure, ensuring zero impact on request success rate.

- REQ-33: The SR container memory footprint shall not exceed 2GB with the full ML
  model catalog loaded (CPU inference mode).

- REQ-34: The config translation shall be validated at startup — if the generated
  SR config is invalid, the system shall refuse to start routing and log the
  validation error, falling back to default provider.

## Acceptance Criteria

- AC-01: A config with all 17 signal types translates to valid SR v0.3 YAML that SR
  accepts without error (REQ-01, REQ-04).
- AC-02: A config with algorithm-specific parameters (e.g., automix with
  verification_threshold, confidence with hybrid_weights) produces correct SR config
  and SR routes requests accordingly (REQ-02).
- AC-03: Plugin configurations (response_cache, system_prompt, rag) in DC config
  appear in the translated SR config and SR applies them (REQ-03).
- AC-04: Model cards with pricing, quality_score, and LoRA translate correctly and
  SR uses them in cost-aware algorithms (REQ-05).
- AC-05: Session_id and user_id passed in classify request enable SR's reask
  detection and authz signals (REQ-11, REQ-12).
- AC-06: When SR returns a cached response, the client receives it in <5ms without
  an upstream call (REQ-15).
- AC-07: System prompts injected by SR appear in the messages sent to the upstream
  provider (REQ-16).
- AC-08: Hot config reload via management API updates SR routing without container
  restart (REQ-24).
- AC-09: `defenseclaw routing replay` shows recent routing decisions with matched
  signals and selected model (REQ-25).
- AC-10: When SR is unreachable, requests succeed via default provider within
  100ms timeout (REQ-32).

## Traceability

| REQ | Architecture Section | Acceptance Criteria |
|-----|---------------------|---------------------|
| REQ-01 | docs/design/2026-07-08-managed-semantic-router-sidecar.md | AC-01 |
| REQ-02 | internal/routing/config_translate.go | AC-02 |
| REQ-03 | internal/routing/config_translate.go | AC-03 |
| REQ-04 | internal/routing/config_translate.go | AC-01 |
| REQ-05 | internal/config/config.go | AC-04 |
| REQ-10 | internal/gateway/model_router_remote.go | AC-05 |
| REQ-11 | internal/gateway/model_router_remote.go | AC-05 |
| REQ-15 | internal/gateway/proxy.go | AC-06 |
| REQ-16 | internal/gateway/proxy.go | AC-07 |
| REQ-24 | internal/gateway/sidecar.go | AC-08 |
| REQ-25 | cli/defenseclaw/commands/ | AC-09 |
| REQ-32 | internal/gateway/model_router_remote.go | AC-10 |
