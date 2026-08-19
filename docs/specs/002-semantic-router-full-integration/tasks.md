# Tasks: Full vLLM Semantic Router Integration

## Tasks

### Phase 1: Config Expansion (REQ-01 through REQ-09)

1. [ ] **Define signal config types** — Add all 17 signal type structs to
   `internal/config/config.go`: RoutingEmbeddingSignal, RoutingDomainSignal,
   RoutingComplexitySignal, RoutingContextSignal, RoutingStructureSignal,
   RoutingModalitySignal, RoutingLanguageSignal, RoutingPIISignal,
   RoutingJailbreakSignal, RoutingFactCheckSignal, RoutingUserFeedbackSignal,
   RoutingReaskSignal, RoutingPreferenceSignal, RoutingConversationSignal,
   RoutingEventSignal, RoutingMetadataSignal, RoutingRoleBindingSignal,
   RoutingKBSignal, RoutingClassifierSignal. (REQ-01)

2. [ ] **Define algorithm config types** — Add algorithm-specific param structs:
   ConfidenceAlgorithmCfg, AutomixAlgorithmCfg, HybridAlgorithmCfg,
   RouterDCAlgorithmCfg, RemomAlgorithmCfg, FusionAlgorithmCfg,
   WorkflowsAlgorithmCfg, LatencyAwareAlgorithmCfg, MultiFactorAlgorithmCfg,
   PromptAlgorithmCfg, RatingsAlgorithmCfg. Expand RoutingAlgorithmConfig to hold
   type-discriminated params. (REQ-02)

3. [ ] **Define plugin config types** — Add RoutingPluginConfig (type + configuration
   map) and typed configs: ResponseCachePluginCfg, ContextCompressionPluginCfg,
   RAGPluginCfg, MemoryPluginCfg, ToolsPluginCfg, ToolSelectionPluginCfg,
   HallucinationPluginCfg, ImageGenPluginCfg, SystemPromptPluginCfg,
   HeaderMutationPluginCfg, ResponseJailbreakPluginCfg, FastResponsePluginCfg,
   RequestParamsPluginCfg, RouterReplayPluginCfg. (REQ-03)

4. [ ] **Expand model config types** — Add to RoutingModelBackend: ReasoningFamily,
   ParamSize, ContextWindowSize, QualityScore, Modality, Tags, LoRAs (name +
   description), Pricing (prompt_per_1m, completion_per_1m, cached_input_per_1m,
   cache_write_per_1m, currency), BackendRefs (endpoint, protocol, weight, type,
   health_check_path, health_check_interval), ExternalModelIDs. (REQ-05)

5. [ ] **Define global config types** — Add RoutingGlobalConfig with:
   RouterConfig (strategy, auto_model_name, learning, skip_processing, streamed_body),
   ServicesConfig (api, response_api, observability, authz, ratelimit, management_api,
   router_replay), StoresConfig (response_cache, memory, vector_store),
   ModelCatalogConfig (embeddings, system classifiers, external models, KBs, modules),
   IntegrationsConfig (tools, looper). (REQ-06)

6. [ ] **Define projection, recipe, entrypoint types** — Add
   RoutingProjectionsConfig (partitions, scores, mappings),
   RoutingRecipe (name, description, routing block),
   RoutingEntrypoint (model_names, recipe). (REQ-08, REQ-09)

7. [ ] **Expand config translator — signals** — Update `Translate()` in
   `internal/routing/config_translate.go` to emit all signal types into the v0.3
   YAML `routing.signals` block. Each signal type has its own YAML structure per
   SR's schema. (REQ-04)

8. [ ] **Expand config translator — decisions** — Update `Translate()` to emit
   full decision rules including: nested AND/OR/NOT conditions, algorithm blocks
   with type-specific params, plugin configurations, adaptations, emits, tier,
   output_contract, annotations, candidateIterations. (REQ-04)

9. [ ] **Expand config translator — providers** — Update `Translate()` to emit
   full provider/model definitions including: pricing, quality_score, capabilities,
   modality, LoRA, backend_refs with health checks, external_model_ids,
   reasoning_family. (REQ-04, REQ-05)

10. [ ] **Expand config translator — global + stores** — Update `Translate()` to
    emit the `global:` block including: router settings, services, stores
    (response_cache with Milvus/Redis config, memory, vector_store),
    model_catalog (system models, embedding config), modules (prompt_compression,
    prompt_guard, classifiers). (REQ-06)

11. [ ] **Expand config translator — projections, recipes, entrypoints** — Emit
    projections (partitions, scores, mappings), recipes, and entrypoints into v0.3
    YAML. (REQ-08, REQ-09)

12. [ ] **Add config validator** — Create `internal/routing/config_validate.go`:
    validate that all model names in decision.modelRefs exist in models[],
    all signal names in conditions exist in signals config, algorithm params are
    valid for the type, plugin configs pass basic schema checks. Return structured
    validation errors. (REQ-34)

13. [ ] **Add model catalog manager** — Create `internal/routing/models.go`:
    download SR model catalog from Hugging Face registry, verify checksums, store
    in `~/.defenseclaw/routing-models/`, support incremental updates. (REQ-07, REQ-26)

14. [ ] **Update Lifecycle to mount models** — Modify `lifecycle.go` Start() to
    add `-v models_dir:/app/models` volume mount when model_catalog is configured.
    Increase health timeout to 180s when models need loading. (REQ-07)

15. [ ] **Add setup routing --install-models CLI** — Add `--install-models` flag
    to Python CLI setup routing command. Downloads model catalog, shows progress,
    verifies integrity. (REQ-26)

16. [ ] **Update Python RoutingConfig** — Expand `cli/defenseclaw/config.py`
    RoutingConfig dataclass to parse all new config fields from YAML. Used by
    Python CLI commands and config validation. (REQ-01)

### Phase 2: Rich Context Passing (REQ-10 through REQ-14)

17. [ ] **Expand ModelRouterInput** — Add fields: Tools []interface{}, SessionID,
    ConversationID, UserID, UserGroups []string, Headers map[string]string,
    Metadata map[string]interface{}, RequestModel string. (REQ-10, REQ-11, REQ-12,
    REQ-13, REQ-14)

18. [ ] **Expand classifyRequest struct** — Add JSON fields: model, tools,
    session_id, user_id, user_groups, headers, metadata, options. Update Route()
    to populate from ModelRouterInput. (REQ-10)

19. [ ] **Extract identity in proxy** — In proxy.go handleRequest(), extract
    session_id (from X-Session-ID or X-Conversation-ID header), user_id
    (from connector auth), user_groups (from X-User-Groups header) and populate
    ModelRouterInput. Add configurable header passthrough list. (REQ-11, REQ-12,
    REQ-13)

20. [ ] **Pass guardrail signals as metadata** — After pre-call guardrails,
    populate ModelRouterInput.Metadata with dc_jailbreak_score, dc_pii_detected,
    dc_severity. SR can use these as metadata signals without re-computing. (REQ-14)

21. [ ] **Add routing context config** — Add `routing.context` config section:
    `session_headers` (list of header names for session_id extraction),
    `user_headers` (for user_id), `passthrough_headers` (forwarded to SR as
    headers map). (REQ-13)

### Phase 3: Rich Response Consumption (REQ-15 through REQ-22)

22. [ ] **Expand classifyResponse struct** — Add fields: plugin_outputs
    (cached_response, system_prompt, reasoning_effort, use_reasoning, lora_name,
    header_mutations, rag_context, compressed_prompt, tools_filtered, tools_blocked),
    warnings, session_telemetry. (REQ-15-22)

23. [ ] **Expand ModelRouterDecision** — Add fields: SystemPrompt, ReasoningEffort,
    UseReasoning, LoRAName, HeaderMutations, RAGContext, CompressedMessages,
    ToolsFiltered, Warnings, DecisionName, Algorithm, MatchedSignals. (REQ-15-22)

24. [ ] **Handle cached response** — In proxy.go, when decision.CacheHit is true
    and decision.CachedResponse is non-nil, serve directly (this path already
    exists — verify it works with SR's response format). Add
    `X-Semantic-Router-Decision` header. (REQ-15)

25. [ ] **Inject system prompt** — In proxy.go, when decision.SystemPrompt != "",
    prepend a system message to req.Messages before Bifrost forward. If a system
    message already exists, append SR's prompt to it. (REQ-16)

26. [ ] **Inject RAG context** — In proxy.go, when decision.RAGContext is non-nil,
    inject retrieved documents based on configured injection_mode:
    - "system_prompt": append to system message
    - "tool_role": add as tool result messages
    - "inline": insert before last user message
    (REQ-19)

27. [ ] **Handle compressed prompt** — In proxy.go, when decision.CompressedMessages
    is non-nil, replace req.Messages with the compressed version. Log compression
    ratio. (REQ-20)

28. [ ] **Apply header mutations** — After response is received from upstream,
    apply decision.HeaderMutations: add new headers, update existing, delete
    specified. Always add `X-Semantic-Router: routed` and
    `X-Semantic-Router-Decision: <name>`. (REQ-18)

29. [ ] **Pass reasoning params to Bifrost** — When decision.ReasoningEffort != ""
    or decision.UseReasoning is set, add provider-specific parameters to the
    upstream request body: `thinking.budget_tokens` for Anthropic,
    `reasoning_effort` for OpenAI, `enable_thinking` for Qwen. Map through Bifrost's
    extra_body or ExtraContent mechanism. (REQ-17)

30. [ ] **Pass LoRA name** — When decision.LoRAName != "", include it in the
    request to providers that support adapter selection (Ollama: model suffix,
    vLLM: adapter_name param). (REQ-22)

31. [ ] **Log warnings** — When decision.Warnings is non-empty, log each at WARN
    level with routing decision context. Include in audit event. (REQ-21)

### Phase 4: Operational Integration (REQ-23 through REQ-30)

32. [ ] **Enrich feedback** — Expand RouterFeedback.Record() parameters: add
    decision_name, prompt_tokens, completion_tokens, cost_usd, ttft_ms, tpot_ms.
    Update feedbackEntry struct and send() to include these fields. (REQ-23)

33. [ ] **Implement hot config reload** — Create `internal/routing/reload.go`:
    watch for routing config changes (from config watcher callback), re-translate,
    POST new config to SR's `/config` endpoint. On SR rejection, log error and
    keep previous config. (REQ-24)

34. [ ] **Add routing replay CLI** — Add `defenseclaw routing replay` command:
    calls SR's `GET /replay` API, formats and displays recent routing decisions
    (timestamp, request summary, matched signals, decision, model, latency).
    Support `--limit` and `--decision` filters. (REQ-25)

35. [ ] **Add routing status CLI** — Add `defenseclaw routing status` command:
    shows SR health, loaded models, signals configured, decisions/sec, cache hit
    rate, learning state. Calls GET /health, GET /v1/models, GET /metrics. (REQ-25)

36. [ ] **Add Kubernetes sidecar support** — Create `internal/routing/k8s.go`:
    generate K8s container spec (image, ports, volumes, resources, health probes)
    that can be injected as a sidecar. Support `routing.container.deploy_mode: k8s`
    config. (REQ-27)

37. [ ] **Add batch classification** — Create BatchRoute() method on
    RemoteRouterClient: accepts []ModelRouterInput, calls
    `POST /api/v1/classify/batch`, returns []ModelRouterDecision. Wire into
    scenarios where multiple requests are queued (future use). (REQ-28)

38. [ ] **Add health degradation detection** — In RemoteRouterClient, track
    consecutive health failures. After 30s of failures (previously healthy), emit
    `routing.degraded` audit event. On recovery, emit `routing.recovered`. (REQ-29)

39. [ ] **Configure router learning** — Add learning config to translator:
    emit `global.router.learning` block with adaptation (enabled, strategy,
    candidate_set), protection (scope, identity headers, tuning params), and
    state_store (backend, ttl, Redis config). (REQ-30)

40. [ ] **Spec updates + CONTEXT.md** — Update this spec with implementation
    notes, add entry to CONTEXT.md.

## Test Plan

### Unit Tests

| Test | File | Purpose |
|------|------|---------|
| Config types marshal/unmarshal | `internal/config/config_test.go` | All new types parse from YAML correctly |
| Signal translation | `internal/routing/config_translate_test.go` | Each signal type produces correct v0.3 YAML |
| Algorithm translation | `internal/routing/config_translate_test.go` | Each algorithm type emits correct params |
| Plugin translation | `internal/routing/config_translate_test.go` | Plugin configs emit correctly |
| Config validation | `internal/routing/config_validate_test.go` | Invalid refs caught, valid configs pass |
| Classify request building | `internal/gateway/model_router_remote_test.go` | Rich context populates all fields |
| Response parsing | `internal/gateway/model_router_remote_test.go` | All plugin outputs parse correctly |
| System prompt injection | `internal/gateway/proxy_test.go` | Prompt prepended correctly |
| RAG injection modes | `internal/gateway/proxy_test.go` | All 3 modes (system, tool_role, inline) work |
| Header mutations | `internal/gateway/proxy_test.go` | Add/update/delete applied correctly |
| Compression replacement | `internal/gateway/proxy_test.go` | Messages replaced when compressed |
| Feedback enrichment | `internal/gateway/model_router_feedback_test.go` | All new fields included |
| Hot reload | `internal/routing/reload_test.go` | Config change triggers POST to SR |
| Health degradation | `internal/gateway/model_router_remote_test.go` | Degraded event after 30s |
| Batch classify | `internal/gateway/model_router_remote_test.go` | Multiple inputs → multiple decisions |

### Integration Tests

| Test | Purpose |
|------|---------|
| Full config → SR accepts | Generate full v0.3 config, start SR container, verify no startup errors |
| Keyword routing E2E | Send request with keyword match, verify correct model selected |
| Embedding routing E2E | Configure embedding signal, verify similarity-based routing |
| Cache hit E2E | Enable response_cache, send duplicate request, verify cache hit |
| System prompt E2E | Configure system_prompt plugin, verify prompt in upstream request |
| Hot reload E2E | Change config, verify SR picks up new rules without restart |
| Fallback on SR failure | Kill SR container, verify requests succeed with default model |
| Session continuity | Send multi-turn conversation, verify session signals fire |

### Performance Tests

| Test | Target |
|------|--------|
| Classify latency (keywords only) | < 10ms p95 |
| Classify latency (embeddings + domain) | < 50ms p95 |
| Classify latency (full ML classifiers) | < 200ms p95 |
| SR cold start (no models) | < 15s |
| SR cold start (full model catalog) | < 60s |
| SR memory usage (full catalog) | < 2GB |
| Config translation time | < 100ms for max-size config |
| Hot reload time | < 500ms from file change to active |
