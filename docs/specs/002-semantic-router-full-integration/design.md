# Design: Full vLLM Semantic Router Integration

## Summary

Expand DefenseClaw's semantic router integration from a minimal classify-only client
(5% utilization) to a full-featured routing layer that leverages SR's complete signal
evaluation engine, algorithm library, plugin system, and operational APIs. The
integration preserves DefenseClaw's existing guardrail pipeline — SR slots in between
pre-call guardrails and Bifrost forwarding, same as today, but with dramatically
richer configuration, context passing, and response handling.

## Architecture

### System Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│  ~/.defenseclaw/config.yaml                                                  │
│                                                                              │
│  routing:                                                                    │
│    enabled: true                                                             │
│    version: "v0.3"                                                           │
│    container:                                                                │
│      image: ghcr.io/vllm-project/semantic-router/vllm-sr:v0.3-models        │
│      models_dir: ~/.defenseclaw/routing-models/                              │
│      gpu: false                                                              │
│    remote:                                                                   │
│      endpoint: ""  # or http://shared-sr:8080 for remote mode               │
│    models: [...]                                                             │
│    signals: {keywords, embeddings, domain, complexity, context, structure,   │
│              modality, language, pii, jailbreak, fact_check, user_feedbacks,  │
│              reasks, preferences, conversation, events, metadata,            │
│              role_bindings, kb, classifiers}                                  │
│    projections: {partitions, scores, mappings}                               │
│    decisions: [{rules, modelRefs, algorithm, plugins, adaptations, emits}]   │
│    global: {model_catalog, modules, services, learning, stores}              │
│    recipes: [...]                                                            │
│    entrypoints: [...]                                                        │
└────────────────────────────────┬────────────────────────────────────────────┘
                                 │ parsed at boot
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  DefenseClaw Gateway (sidecar.go)                                            │
│                                                                              │
│  Boot sequence:                                                              │
│  1. Parse routing config                                                     │
│  2. Validate config (schema + cross-references)                              │
│  3. Check Docker/K8s availability                                            │
│  4. TranslateAndWrite() → full v0.3 YAML                                    │
│  5. Start SR container (mount config + models)                               │
│  6. Health check (GET /health, up to 3min for model loading)                 │
│  7. RegisterModelRouter(NewRemoteModelRouter(...))                           │
│  8. Start RouterFeedback goroutine                                           │
│  9. Start config watcher (hot reload via POST /config)                       │
│                                                                              │
│  Request pipeline:                                                           │
│  ┌──────────────────────────────────────────────────────────────────┐       │
│  │ 1. AUTHENTICATE (connector / token / master-key)                  │       │
│  │                                                                    │       │
│  │ 2. PRE-CALL GUARDRAILS                                            │       │
│  │    → severity, jailbreak_score, pii_detected                      │       │
│  │                                                                    │       │
│  │ 3. SEMANTIC MODEL ROUTER (ModelRouter.Route)                       │       │
│  │    ┌────────────────────────────────────────────────────────┐     │       │
│  │    │ Build ClassifyRequest:                                  │     │       │
│  │    │   messages (full conversation)                          │     │       │
│  │    │   tools (definitions)                                   │     │       │
│  │    │   model (requested or "auto")                           │     │       │
│  │    │   session_id, user_id, user_groups                      │     │       │
│  │    │   headers (configurable passthrough)                    │     │       │
│  │    │   metadata (guardrail signals + custom)                 │     │       │
│  │    │                                                         │     │       │
│  │    │ POST /api/v1/classify/intent → SR                       │     │       │
│  │    │                                                         │     │       │
│  │    │ Parse ClassifyResponse:                                 │     │       │
│  │    │   recommended_model, routing_decision                   │     │       │
│  │    │   cached_response (serve directly if present)           │     │       │
│  │    │   system_prompt (inject into messages)                  │     │       │
│  │    │   reasoning_effort, use_reasoning                       │     │       │
│  │    │   header_mutations (apply to response)                  │     │       │
│  │    │   rag_context (inject into messages)                    │     │       │
│  │    │   compressed_prompt (replace messages)                  │     │       │
│  │    │   lora_name (pass to provider)                          │     │       │
│  │    │   warnings (log)                                        │     │       │
│  │    └────────────────────────────────────────────────────────┘     │       │
│  │                                                                    │       │
│  │ 4. APPLY ROUTING DECISION                                         │       │
│  │    - Cache hit? → return immediately                              │       │
│  │    - Inject system_prompt, RAG context, compressed prompt         │       │
│  │    - Override model, target_url, api_key                          │       │
│  │    - Set reasoning params                                         │       │
│  │                                                                    │       │
│  │ 5. BIFROST FORWARD                                                │       │
│  │    → upstream LLM (with overridden model/params)                  │       │
│  │                                                                    │       │
│  │ 6. POST-CALL GUARDRAILS + FEEDBACK                                │       │
│  │    - Apply header mutations to response                           │       │
│  │    - RouterFeedback.Record(enriched telemetry)                    │       │
│  └──────────────────────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  Docker/K8s: defenseclaw-semantic-router                                     │
│  Image: ghcr.io/vllm-project/semantic-router/vllm-sr:v0.3-models            │
│                                                                              │
│  Volumes:                                                                    │
│  - /app/config/config.yaml (translated from DC config)                       │
│  - /app/models/ (ML model catalog)                                           │
│  - /app/knowledge_bases/ (KB data for kb signals)                            │
│                                                                              │
│  ML Models (CPU, ~1.5GB total):                                              │
│  - mmbert32k-jailbreak-detector-merged (prompt guard)                        │
│  - mmbert32k-intent-classifier-merged (domain)                               │
│  - mmbert32k-pii-detector-merged (PII)                                       │
│  - mmbert32k-factcheck-classifier-merged (fact check)                        │
│  - mom-halugate-detector (hallucination)                                     │
│  - mom-halugate-explainer (hallucination explanation)                        │
│  - mmbert32k-feedback-detector-merged (user feedback)                        │
│  - mmbert32k-modality-router-merged (modality)                               │
│  - mom-embedding-pro (semantic embeddings, 768d)                             │
│  - mom-embedding-light (lightweight embeddings, 384d)                        │
│                                                                              │
│  Optional Backends:                                                          │
│  - Redis/Valkey (session state, response cache, learning state)              │
│  - Milvus (semantic cache vectors, memory store)                             │
│                                                                              │
│  APIs:                                                                       │
│  - POST /api/v1/classify/intent (main routing)                               │
│  - POST /api/v1/classify/batch (batch routing)                               │
│  - POST /api/v1/classify/pii (PII detection)                                 │
│  - POST /api/v1/classify/security (jailbreak)                                │
│  - POST /api/v1/classify/combined (all-in-one)                               │
│  - GET  /health, /ready, /v1/models                                          │
│  - POST /v1/feedback (learning)                                              │
│  - GET/POST /config (management)                                             │
│  - GET /replay (decision replay)                                             │
│  - GET /metrics (Prometheus)                                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Components Modified

| Component | File(s) | Change |
|-----------|---------|--------|
| Config types | `internal/config/routing_types.go` | Expand `RoutingConfig` to full v0.3 schema (~40 new types) |
| Config translator | `internal/routing/config_translate_v2.go` | Emit full v0.3 YAML (signals, algorithms, plugins, global, recipes) |
| Config validator | `internal/routing/config_validate.go` | NEW: validate cross-references, model names, signal names |
| Router interface | `internal/gateway/model_router.go` | Expand `ModelRouterInput` and `ModelRouterDecision` |
| Remote client | `internal/gateway/model_router_remote.go` | Expand request/response types, pass rich context |
| Proxy integration | `internal/gateway/proxy.go` | Handle cache hits, system prompts, RAG, compression, headers |
| Feedback sender | `internal/gateway/model_router_feedback.go` | Enrich feedback with decision name, satisfaction signals |
| Sidecar boot | `internal/gateway/sidecar.go` | Mount models, config watcher, hot reload |
| Lifecycle | `internal/routing/lifecycle.go` | Add models volume mount, health timeout for model loading |
| Orchestrator | `internal/routing/orchestrator.go` | Add model download step, config validation |
| Manager | `internal/routing/manager.go` | Add model catalog download/update |
| Python config | `cli/defenseclaw/config.py` | Expand `RoutingConfig` dataclass |
| CLI routing | `cli/defenseclaw/commands/cmd_setup.py` | Add `--install-models`, status, replay commands |

### Components Added

| Component | File(s) | Purpose |
|-----------|---------|---------|
| Config validator | `internal/routing/config_validate.go` | Schema + cross-reference validation |
| Model manager | `internal/routing/models.go` | Download, verify, update ML model catalog |
| Hot reloader | `internal/routing/reload.go` | Watch config changes, POST to SR /config |
| Replay client | `internal/routing/replay.go` | Query SR replay API |
| K8s deployer | `internal/routing/k8s.go` | Generate sidecar container spec for K8s |

### Data Flow: Classify Request

```text
GuardrailProxy.handleRequest()
    │
    ├─ Pre-call guardrails complete
    │   → jailbreak_score, pii_detected, severity
    │
    ▼
RemoteRouterClient.Route(ctx, input)
    │
    ├─ Build classifyRequest:
    │   {
    │     messages: [{role, content}...],  // full conversation
    │     model: "auto",                    // or specific model
    │     tools: [{type, function}...],     // tool definitions
    │     stream: true/false,
    │     session_id: "sess-abc",
    │     user_id: "user-123",
    │     user_groups: ["premium"],
    │     headers: {"x-tenant": "acme"},
    │     metadata: {
    │       "dc_jailbreak_score": 0.12,
    │       "dc_pii_detected": false,
    │       "dc_severity": "LOW",
    │       "consent": "granted"
    │     }
    │   }
    │
    ├─ POST /api/v1/classify/intent → SR container
    │
    ├─ SR internally evaluates:
    │   - 17+ signal types against config
    │   - Decision tree (priority-ordered rules)
    │   - Selected algorithm (e.g., confidence escalation)
    │   - Plugins (cache lookup, RAG retrieval, compression)
    │
    ▼
Parse classifyResponse:
    {
      recommended_model: "reasoning",
      routing_decision: "cs_hard_route",
      classification: {category: "computer science", confidence: 0.94},
      matched_signals: {complexity: "hard", domain: "cs", keyword: "code_task"},
      decision_result: {decision_name: "cs_hard_route", confidence: 0.94},
      // Plugin outputs:
      cached_response: null,                    // or {body, headers, status}
      system_prompt: "You are an expert...",    // or ""
      reasoning_effort: "high",                 // or ""
      use_reasoning: true,
      header_mutations: {add: [{name: "X-Route", value: "reasoning"}]},
      rag_context: [{content: "...", source: "docs/..."}],
      compressed_prompt: null,                  // or {messages: [...]}
      lora_name: "computer-science-expert",     // or ""
      warnings: []
    }
```

### Data Flow: Hot Config Reload

```text
Config file watcher detects change
    │
    ▼
Parse new RoutingConfig
    │
    ├─ Validate (config_validate.go)
    │   - All model names referenced in decisions exist
    │   - All signal names referenced in conditions exist
    │   - Algorithm params are valid for type
    │   - Plugin configs pass schema validation
    │
    ├─ TranslateAndWrite() → new SR YAML
    │
    ▼
POST /config (SR management API)
    │
    ├─ SR validates internally
    ├─ SR hot-reloads routing rules
    │
    ▼
Log "routing config reloaded" event
```

## Interfaces

### Expanded Classify Request (DC → SR)

```json
{
  "messages": [
    {"role": "system", "content": "..."},
    {"role": "user", "content": "analyze the tradeoffs between..."}
  ],
  "model": "auto",
  "tools": [
    {"type": "function", "function": {"name": "search", "description": "..."}}
  ],
  "stream": false,
  "session_id": "sess-abc123",
  "user_id": "user-456",
  "user_groups": ["premium", "engineering"],
  "headers": {
    "x-tenant-id": "acme-corp",
    "x-session-id": "sess-abc123",
    "x-conversation-id": "conv-789"
  },
  "metadata": {
    "dc_jailbreak_score": 0.05,
    "dc_pii_detected": false,
    "dc_severity": "NONE",
    "dc_connector": "claude-code",
    "consent": "granted"
  },
  "options": {
    "return_probabilities": true,
    "include_plugin_outputs": true
  }
}
```

### Expanded Classify Response (SR → DC)

```json
{
  "recommended_model": "qwen3-32b",
  "routing_decision": "cs_hard_route",
  "classification": {
    "category": "computer science",
    "confidence": 0.94
  },
  "matched_signals": {
    "domain": {"name": "computer science", "confidence": 0.94},
    "complexity": {"name": "needs_reasoning", "level": "hard", "confidence": 0.88},
    "keyword": {"name": "code_task", "matched": ["analyze", "tradeoffs"]},
    "conversation": {"name": "has_tools", "matched": true}
  },
  "decision_result": {
    "decision_name": "cs_hard_route",
    "confidence": 0.94,
    "algorithm": "confidence",
    "tier": 1
  },
  "plugin_outputs": {
    "cached_response": null,
    "system_prompt": "You are a senior software architect specializing in distributed systems.",
    "reasoning_effort": "high",
    "use_reasoning": true,
    "lora_name": "computer-science-expert",
    "header_mutations": {
      "add": [{"name": "X-Route-Decision", "value": "cs_hard_route"}],
      "update": [],
      "delete": []
    },
    "rag_context": [
      {
        "content": "Architecture decision record: we chose event sourcing because...",
        "source": "docs/adr/003-event-sourcing.md",
        "similarity": 0.87
      }
    ],
    "compressed_prompt": null,
    "tools_filtered": ["search"],
    "tools_blocked": ["exec_cmd"]
  },
  "warnings": [],
  "session_telemetry": {
    "last_model": "qwen3-8b",
    "turn_count": 4,
    "adaptation_active": true
  }
}
```

### Enriched Feedback (DC → SR)

```json
{
  "model": "qwen3-32b",
  "decision": "cs_hard_route",
  "latency_ms": 1245,
  "tokens": 892,
  "prompt_tokens": 156,
  "completion_tokens": 736,
  "success": true,
  "session_id": "sess-abc123",
  "user_id": "user-456",
  "stream": false,
  "cost_usd": 0.0037,
  "ttft_ms": 312,
  "tpot_ms": 45
}
```

### Management API (DC → SR)

| Method | Path | Purpose |
|--------|------|---------|
| POST | /config | Hot reload routing config |
| GET | /config | Read current active config |
| GET | /replay | Query recent routing decisions |
| GET | /replay/{id} | Get details of a specific decision |
| GET | /v1/models | List available models and status |
| GET | /metrics | Prometheus metrics |
| POST | /v1/feedback | Submit learning feedback |

## Data Model

### Config Types (internal/config/routing_types.go)

New/expanded types (abbreviated — full definitions in implementation):

```go
// Top-level routing config
type RoutingConfig struct {
    Enabled     bool
    Version     string                    // "v0.3"
    Container   RoutingContainerConfig
    Remote      RoutingRemoteConfig
    Models      []RoutingModelBackend     // EXPANDED: pricing, quality, lora, backends
    Signals     RoutingSignalConfig       // EXPANDED: all 17+ signal types
    Projections RoutingProjectionsConfig  // NEW
    Decisions   []RoutingDecisionRule     // EXPANDED: algorithm params, plugins, adaptations
    Global      RoutingGlobalConfig       // NEW: model_catalog, modules, services, learning
    Recipes     []RoutingRecipe           // NEW
    Entrypoints []RoutingEntrypoint       // NEW
}

// Expanded model definition
type RoutingModelBackend struct {
    Name              string
    Provider          string
    Model             string
    ReasoningFamily   string
    ParamSize         string
    ContextWindowSize int
    QualityScore      float64
    Capabilities      []string
    Modality          []string
    Tags              []string
    LoRAs             []RoutingLoRA
    Pricing           RoutingModelPricing
    BackendRefs       []RoutingBackendRef
    ExternalModelIDs  map[string]string
}

// All signal types
type RoutingSignalConfig struct {
    Keywords      []RoutingKeywordSignal
    Embeddings    []RoutingEmbeddingSignal     // NEW
    Domains       []RoutingDomainSignal        // NEW
    Complexity    []RoutingComplexitySignal    // NEW
    Context       []RoutingContextSignal       // NEW
    Structure     []RoutingStructureSignal     // NEW
    Modality      []RoutingModalitySignal      // NEW
    Language      []RoutingLanguageSignal      // NEW
    PII           []RoutingPIISignal           // NEW
    Jailbreak     []RoutingJailbreakSignal     // NEW
    FactCheck     []RoutingFactCheckSignal     // NEW
    UserFeedbacks []RoutingUserFeedbackSignal  // NEW
    Reasks        []RoutingReaskSignal         // NEW
    Preferences   []RoutingPreferenceSignal    // NEW
    Conversation  []RoutingConversationSignal  // NEW
    Events        []RoutingEventSignal         // NEW
    Metadata      []RoutingMetadataSignal      // NEW
    RoleBindings  []RoutingRoleBindingSignal   // NEW
    KB            []RoutingKBSignal            // NEW
    Classifiers   []RoutingClassifierSignal    // NEW
}

// Expanded decision with algorithm params and plugins
type RoutingDecisionRule struct {
    Name             string
    Description      string
    Priority         int
    Tier             int
    OutputContract   string
    Rules            RoutingRules              // EXPANDED: nested AND/OR/NOT
    ModelRefs        []RoutingModelRef         // EXPANDED: reasoning, lora, weight
    Algorithm        RoutingAlgorithmConfig    // EXPANDED: type-specific params
    Plugins          []RoutingPluginConfig     // NEW
    Adaptations      *RoutingAdaptationConfig  // NEW
    Emits            []RoutingEmitConfig       // NEW
    Annotations      map[string]string
}

// Algorithm with type-specific config
type RoutingAlgorithmConfig struct {
    Type         string                     // static, confidence, automix, hybrid, etc.
    OnError      string                     // fallback, skip, fail
    Confidence   *ConfidenceAlgorithmCfg
    Automix      *AutomixAlgorithmCfg
    Hybrid       *HybridAlgorithmCfg
    RouterDC     *RouterDCAlgorithmCfg
    Remom        *RemomAlgorithmCfg
    Fusion       *FusionAlgorithmCfg
    Workflows    *WorkflowsAlgorithmCfg
    LatencyAware *LatencyAwareAlgorithmCfg
    MultiFactor  *MultiFactorAlgorithmCfg
    Prompt       *PromptAlgorithmCfg
    Ratings      *RatingsAlgorithmCfg
}
```

## Integration Points

### With Existing DefenseClaw Components

| Component | Integration |
|-----------|-------------|
| Guardrail proxy | SR sits between pre-call guardrails and Bifrost (unchanged position) |
| Bifrost | Receives overridden model, reasoning params, LoRA from SR decision |
| Config watcher | Triggers hot reload to SR instead of container restart |
| Audit store | Logs routing decisions, matched signals, plugin actions |
| OTel telemetry | Emits routing spans with signal/algorithm/decision attributes |
| Connector auth | Extracts user_id, user_groups from connector headers for SR |
| TUI/CLI | Surfaces routing status, replay, model catalog management |

### With SR External Dependencies (Optional)

| Dependency | When Needed | Purpose |
|-----------|-------------|---------|
| Redis/Valkey | response_cache, learning, session state | Caching + state persistence |
| Milvus | semantic cache, memory store, vector store | Vector similarity search |
| Postgres | router_replay storage | Decision audit trail |

These are optional — SR works without them (in-memory fallbacks). DC can
configure them in `global.stores` when the operator wants persistence.

## Tradeoffs

### Config-driven vs. code-driven integration

**Decision:** Config-driven (expand translator) rather than reimplementing SR logic.

**Rationale:** SR has 100K+ lines of Go implementing signals, algorithms, and
plugins. Reimplementing any of it in DC would be:
- Maintenance burden (tracking SR releases)
- Bug-prone (subtle algorithm behavior)
- Slower to deliver (months vs. weeks)

**Trade-off:** DC depends on SR's config contract stability. v0.3 is a released,
documented format. Breaking changes would require translator updates.

### Single container vs. multi-container

**Decision:** Single router container + optional Redis/Milvus sidecars.

**Rationale:** The router binary handles all classification and routing. External
stores are only needed for persistence (caching, learning state). Most users will
start without them and add as needed.

### Embedded models vs. remote inference

**Decision:** CPU-only embedded models in the container by default.

**Rationale:** SR's classifiers (mmbert32k family) are small (~100-300MB each),
run fast on CPU (<10ms), and don't require GPU. Embedding them avoids network
calls and infrastructure complexity. GPU mode available for high-throughput
deployments via config.

### Graceful degradation

**Decision:** Every SR failure returns nil (use default provider).

**Rationale:** Routing is an optimization, not a requirement. A request that goes
to the "wrong" model still succeeds. SR unavailability must never cause request
failures.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| SR v0.3 config format changes | Low (released) | Medium | Pin SR image version, test translator against SR validation |
| Model catalog download size (~1.5GB) | Medium | Low | Lazy download on first `setup routing --install-models`, cache locally |
| SR container cold start with models | Medium | Low | 3-min health timeout already exists; pre-pull image |
| Memory pressure with full model catalog | Low | Medium | Document 2GB recommendation; models load on-demand per signal config |
| Plugin response format undocumented | Medium | Medium | Test against SR classify endpoint; use `options.include_plugin_outputs` |
| Redis/Milvus operational complexity | Medium | Low | Make them optional; in-memory defaults for simple deployments |
