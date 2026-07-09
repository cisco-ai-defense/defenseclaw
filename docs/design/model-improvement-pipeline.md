# Continuous Model Improvement Pipeline — Architecture

## End-to-End Block Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    RUNTIME (Always Running)                                   │
│                                                                                              │
│  ┌──────────┐     ┌───────────────────┐     ┌─────────────────┐     ┌──────────────────┐   │
│  │  User /  │     │   DEFENSECLAW     │     │   vLLM-SR       │     │   MODEL HOST     │   │
│  │  Agent   │────▶│   Gateway         │────▶│   (classify)    │     │   (llama.cpp)    │   │
│  │          │     │                   │     │                 │     │                  │   │
│  │ Claude   │     │ • Pre-guardrails  │     │ POST /api/v1/   │     │ Serves fine-     │   │
│  │ Hermes   │     │ • Hook intercept  │     │   classify/     │     │ tuned GGUF       │   │
│  │ Codex    │     │ • Audit logging   │     │   intent        │     │ models per       │   │
│  │ Cursor   │     │                   │     │                 │     │ category         │   │
│  └──────────┘     └─────────┬─────────┘     └────────┬────────┘     └────────▲─────────┘   │
│                             │                         │                       │             │
│                             │                         ▼                       │             │
│                             │              ┌──────────────────────┐           │             │
│                             │              │  Routing Decision    │           │             │
│                             │              │                      │           │             │
│                             │              │  "code" category     │           │             │
│                             │              │  → recommended_model │           │             │
│                             │              │    = "code-local"    │           │             │
│                             │              └──────────┬───────────┘           │             │
│                             │                         │                       │             │
│                             ▼                         ▼                       │             │
│                   ┌───────────────────────────────────────────────┐           │             │
│                   │              BIFROST                           │           │             │
│                   │                                               │           │             │
│                   │  IF model is "local" (promoted):              │           │             │
│                   │    → Forward to llama.cpp  ────────────────────────────────┘             │
│                   │                                               │                         │
│                   │  IF model is "frontier" (not yet promoted):   │                         │
│                   │    → Forward to Anthropic / OpenAI / etc.     │                         │
│                   │                                               │                         │
│                   └───────────────────────────────────────────────┘                         │
│                             │                                                               │
│                             ▼                                                               │
│                   ┌───────────────────┐     ┌────────────────────────────────┐              │
│                   │ Post-guardrails   │     │   OTel TRACE STORE             │              │
│                   │ • Response inspect│────▶│                                │              │
│                   │ • Audit log       │     │   Stores per request:          │              │
│                   │ • Telemetry       │     │   • user prompt                │              │
│                   └───────────────────┘     │   • model response             │              │
│                                             │   • routing decision           │              │
│                                             │   • category (from SR)         │              │
│                                             │   • latency, tokens            │              │
│                                             │   • model used                 │              │
│                                             └──────────────┬─────────────────┘              │
│                                                            │                                │
└────────────────────────────────────────────────────────────┼────────────────────────────────┘
                                                             │
                                                             │ OTel traces exported
                                                             ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                              OBSERVABILITY (Always Running)                                   │
│                                                                                              │
│  ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐                    │
│  │  Grafana Tempo   │     │   Prometheus     │     │   Grafana        │                    │
│  │  (trace store)   │     │   (metrics)      │     │   (dashboards)   │                    │
│  │                  │     │                  │     │                  │                    │
│  │  All LLM traces  │     │  • Requests/sec  │     │  Visualize:      │                    │
│  │  with categories │     │  • Latency p90   │     │  • Routes taken  │                    │
│  │  + responses     │     │  • Token usage   │     │  • Model quality │                    │
│  │                  │     │  • Error rates   │     │  • Cost savings  │                    │
│  └────────┬─────────┘     └──────────────────┘     └──────────────────┘                    │
│           │                                                                                  │
└───────────┼──────────────────────────────────────────────────────────────────────────────────┘
            │
            │ Query traces by category
            │ (e.g., "give me all 'code' category traces from last week")
            ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                         TRAINING PIPELINE (Periodic — weekly/triggered)                       │
│                                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐    │
│  │  STEP 1: DATA EXTRACTION                                                            │    │
│  │                                                                                      │    │
│  │  Query Tempo API:                                                                    │    │
│  │    "All traces where routing_decision = 'code_route' from last 7 days"              │    │
│  │                                                                                      │    │
│  │  Extract:                                                                            │    │
│  │    • prompt (user query)                                                             │    │
│  │    • chosen (frontier model response — the "gold standard")                         │    │
│  │    • rejected (local model response — if it existed, or generate one)               │    │
│  │                                                                                      │    │
│  │  Output: training_data_code.jsonl                                                    │    │
│  │    {"prompt": "implement quicksort", "chosen": "def quicksort...", "rejected": ...} │    │
│  └──────────────────────────────────────────────┬──────────────────────────────────────┘    │
│                                                  │                                           │
│                                                  ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐    │
│  │  STEP 2: UNSLOTH TRAINING                                                           │    │
│  │                                                                                      │    │
│  │  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐               │    │
│  │  │ Data Recipe     │────▶│ SFT (teach)     │────▶│ DPO/GRPO        │               │    │
│  │  │                 │     │                 │     │ (refine)        │               │    │
│  │  │ Auto-format     │     │ Train on        │     │ Preference      │               │    │
│  │  │ training data   │     │ frontier        │     │ optimization    │               │    │
│  │  │ from extracted  │     │ examples        │     │ vs frontier     │               │    │
│  │  │ traces          │     │                 │     │                 │               │    │
│  │  └─────────────────┘     └─────────────────┘     └────────┬────────┘               │    │
│  │                                                            │                        │    │
│  │  Base model: Qwen3.5-4B (or similar small model)           │                        │    │
│  │  Method: LoRA (memory-efficient)                           │                        │    │
│  │  Platform: Mac (DPO via mlx-lm-lora) or Cloud (GRPO)      │                        │    │
│  │  Time: 2-6 hours                                           │                        │    │
│  └────────────────────────────────────────────────────────────┼────────────────────────┘    │
│                                                               │                              │
│                                                               ▼                              │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐    │
│  │  STEP 3: EXPORT                                                                      │    │
│  │                                                                                      │    │
│  │  model.save_pretrained_gguf("code-v2.gguf", quantization="q4_k_m")                  │    │
│  │                                                                                      │    │
│  │  Output: ~/.defenseclaw/models/code-v2.gguf (~2.5 GB for 4B model)                  │    │
│  └──────────────────────────────────────────────┬──────────────────────────────────────┘    │
│                                                  │                                           │
│                                                  ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐    │
│  │  STEP 4: DEPLOY TO LLAMA.CPP                                                         │    │
│  │                                                                                      │    │
│  │  Copy GGUF to models directory                                                       │    │
│  │  Restart llama-server (or blue/green swap)                                           │    │
│  │                                                                                      │    │
│  │  llama-server --models-dir ~/.defenseclaw/models/ --models-max 3 --port 8090         │    │
│  │                                                                                      │    │
│  │  Verify: GET http://127.0.0.1:8090/health → 200 OK                                  │    │
│  └──────────────────────────────────────────────┬──────────────────────────────────────┘    │
│                                                  │                                           │
│                                                  ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐    │
│  │  STEP 5: EVALUATE                                                                    │    │
│  │                                                                                      │    │
│  │  Run held-out test set through BOTH:                                                 │    │
│  │    • Local model (llama.cpp)     → score_local                                      │    │
│  │    • Frontier model (Anthropic)  → score_frontier                                   │    │
│  │                                                                                      │    │
│  │  Scoring methods:                                                                    │    │
│  │    • LLM-as-judge (GPT-4 rates both outputs)                                       │    │
│  │    • Similarity (ROUGE/BERTScore vs frontier)                                       │    │
│  │    • Task-specific (code: does it compile? math: correct answer?)                   │    │
│  │                                                                                      │    │
│  │  Promotion threshold: score_local >= 90% of score_frontier                          │    │
│  └──────────────────────────────────────────────┬──────────────────────────────────────┘    │
│                                                  │                                           │
│                                                  ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐    │
│  │  STEP 6: PROMOTE OR ROLLBACK                                                         │    │
│  │                                                                                      │    │
│  │  IF score_local >= 90% of score_frontier:                                           │    │
│  │    ┌─────────────────────────────────────────────────────────────────┐              │    │
│  │    │  UPDATE vLLM-SR CONFIG:                                          │              │    │
│  │    │    "code" category → route to "code-local" (llama.cpp)          │              │    │
│  │    │    instead of → "code-frontier" (Anthropic)                     │              │    │
│  │    │                                                                  │              │    │
│  │    │  RESULT: All future "code" queries served locally               │              │    │
│  │    │    • $0 per query (vs $0.003/1K tokens on frontier)             │              │    │
│  │    │    • Lower latency (local vs API call)                          │              │    │
│  │    │    • Same quality (validated by eval)                           │              │    │
│  │    └─────────────────────────────────────────────────────────────────┘              │    │
│  │                                                                                      │    │
│  │  IF score_local < 90%:                                                              │    │
│  │    → Keep routing to frontier                                                        │    │
│  │    → Log: "model not ready, needs more training data"                               │    │
│  │    → Wait for next training cycle                                                    │    │
│  └─────────────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                              │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow Summary

```
┌────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   QUERY FLOW (per request, <100ms):                                        │
│                                                                             │
│   User ──▶ DefenseClaw ──▶ vLLM-SR ──▶ Bifrost ──▶ Model ──▶ User         │
│              (guard)      (classify)    (route)   (respond)                 │
│                │                                                            │
│                └──▶ OTel trace (async, non-blocking)                        │
│                                                                             │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   TRAINING FLOW (periodic, hours):                                          │
│                                                                             │
│   OTel ──▶ Extract ──▶ Unsloth ──▶ Export ──▶ Deploy ──▶ Eval ──▶ Promote │
│   (Tempo)   (ETL)     (SFT+DPO)   (GGUF)   (llama)    (judge)  (SR cfg) │
│                                                                             │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   FEEDBACK LOOP (continuous):                                               │
│                                                                             │
│   Local model serves "code" ──▶ OTel stores results                        │
│          │                              │                                   │
│          │   quality drops?             │                                   │
│          │◀─────────────────────────────┘                                   │
│          │                                                                  │
│          └──▶ Trigger retraining with new data                             │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

## Component Inventory

```
┌─────────────────────────────────────────────────────────────────┐
│  ALWAYS RUNNING (on your Mac)                                    │
│                                                                  │
│  ┌────────────────────┐  Port 18970 (API) / hooks               │
│  │ DefenseClaw Gateway │  Go binary, manages everything          │
│  └────────────────────┘                                          │
│                                                                  │
│  ┌────────────────────┐  Port 8888 (Docker container)            │
│  │ vLLM-SR Router     │  Routing decisions only                  │
│  └────────────────────┘                                          │
│                                                                  │
│  ┌────────────────────┐  Port 11434 (Docker/native)              │
│  │ Ollama             │  Current model host (existing)           │
│  └────────────────────┘                                          │
│                                                                  │
│  ┌────────────────────┐  Port 8090 (native binary)               │
│  │ llama.cpp server   │  Hosts fine-tuned models (new)           │
│  └────────────────────┘                                          │
│                                                                  │
│  ┌────────────────────┐  Port 3000/9090/3200                     │
│  │ Grafana + Tempo +  │  Trace storage + dashboards (new)        │
│  │ Prometheus         │                                          │
│  └────────────────────┘                                          │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│  PERIODIC (runs on demand or scheduled)                          │
│                                                                  │
│  ┌────────────────────┐  Python script                           │
│  │ Data Extractor     │  Queries Tempo, builds datasets          │
│  └────────────────────┘                                          │
│                                                                  │
│  ┌────────────────────┐  Python (mlx-lm-lora on Mac)            │
│  │ Unsloth / MLX      │  SFT + DPO training                     │
│  │ Training           │  Exports GGUF                            │
│  └────────────────────┘                                          │
│                                                                  │
│  ┌────────────────────┐  Python script                           │
│  │ Evaluator          │  Compares local vs frontier              │
│  └────────────────────┘                                          │
│                                                                  │
│  ┌────────────────────┐  Python/Go                               │
│  │ Promoter           │  Updates SR config + restarts            │
│  └────────────────────┘                                          │
└──────────────────────────────────────────────────────────────────┘
```

## Category-Based Model Progression

```
                        TIME →
                        
  Category: "code"
  ┌─────────────────────────────────────────────────────────────────────┐
  │                                                                      │
  │  Week 1-2:     All "code" → Anthropic (frontier)                    │
  │                OTel collects 1000+ code traces                       │
  │                                                                      │
  │  Week 3:       Train local model on code traces (SFT + DPO)         │
  │                Evaluate: local = 85% of frontier → NOT promoted      │
  │                                                                      │
  │  Week 4:       Retrain with 2000 traces + improved reward           │
  │                Evaluate: local = 92% of frontier → PROMOTED ✓       │
  │                                                                      │
  │  Week 5+:      All "code" → local model (llama.cpp)                 │
  │                Cost: $0 | Latency: 50ms (vs 500ms API call)         │
  │                Continue collecting traces for next improvement       │
  │                                                                      │
  └─────────────────────────────────────────────────────────────────────┘
  
  Category: "reasoning"
  ┌─────────────────────────────────────────────────────────────────────┐
  │                                                                      │
  │  Week 1-4:     All "reasoning" → Anthropic (frontier)               │
  │                Hard to match — may stay on frontier longer           │
  │                                                                      │
  │  Week 8:       Train: local = 78% → NOT promoted                    │
  │                                                                      │
  │  Week 12:      Train: local = 91% → PROMOTED ✓                     │
  │                                                                      │
  └─────────────────────────────────────────────────────────────────────┘
  
  Category: "simple-qa"
  ┌─────────────────────────────────────────────────────────────────────┐
  │                                                                      │
  │  Week 1:       All "simple" → GPT-4o-mini (cheap frontier)          │
  │                                                                      │
  │  Week 2:       Train 1.5B model → 95% quality → PROMOTED ✓         │
  │                Easiest category to replace locally                   │
  │                                                                      │
  └─────────────────────────────────────────────────────────────────────┘
```
