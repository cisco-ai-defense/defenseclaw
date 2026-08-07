# DefenseClaw Continuous Model Improvement Pipeline

## Technical Specification v1.0

**Document Version:** 1.0  
**Date:** 2026-07-09  
**Author:** DefenseClaw Engineering  
**Status:** Draft  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Architecture](#2-system-architecture)
3. [Data Flow Diagrams](#3-data-flow-diagrams)
4. [Component Specifications](#4-component-specifications)
5. [Tool Reference](#5-tool-reference)
6. [Configuration Reference](#6-configuration-reference)
7. [CLI Reference](#7-cli-reference)
8. [Error Handling](#8-error-handling)
9. [State Machine](#9-state-machine)
10. [File Layout](#10-file-layout)
11. [Implementation Modules](#11-implementation-modules)
12. [Estimated Effort](#12-estimated-effort)

---

## 1. Executive Summary

### 1.1 Purpose

DefenseClaw manages an automated pipeline that continuously improves local LLM models by learning from production traffic. User queries are classified by the semantic router, stored as training data, used to fine-tune local models, and promoted to serve traffic when they match frontier model quality.

### 1.2 Goals

| # | Goal | Metric |
|---|------|--------|
| G1 | Replace expensive frontier API calls with local models | Cost reduction per category |
| G2 | Maintain quality parity with frontier | ≥90% of frontier score (LLM-as-judge) |
| G3 | Zero manual intervention after setup | Auto-trigger, train, promote, rollback |
| G4 | Single source of truth | All config in `~/.defenseclaw/config.yaml` |
| G5 | Graceful degradation | Pipeline failure never impacts user requests |

### 1.3 Non-Goals

- Multi-GPU distributed training
- Pretraining from scratch
- Real-time training (batch only)
- Multi-node model serving
- Custom model architectures

### 1.4 Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Training trigger | Auto (threshold) + manual CLI | Hands-off by default, override when needed |
| Trace storage | Tempo (viz) + SQLite (training) | Best of both: dashboards + fast extraction |
| Training backend | User selects: Unsloth or mlx-lm-lora | Unsloth for CUDA GPUs, mlx-lm-lora for Mac |
| Algorithm | User selects per category | Different categories need different approaches |
| Base models | Curated list (Qwen, Llama, Phi, Gemma) | Tested + reliable, user picks per category |
| Model hosting | llama-server, always running, lazy-load | Instant inference on promotion, no cold start |
| Evaluation | LLM-as-judge | Most accurate for open-ended quality comparison |
| Promotion | Automatic if ratio ≥ threshold | Removes human bottleneck |
| Rollback | Auto (quality drop) + manual CLI | Safety net for production quality |

---

## 2. System Architecture

### 2.1 High-Level Block Diagram

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                           │
│                              DEFENSECLAW PLATFORM                                         │
│                                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                                                                                      │ │
│  │                         RUNTIME LAYER (per request)                                  │ │
│  │                                                                                      │ │
│  │  ┌─────────┐   ┌──────────────┐   ┌──────────┐   ┌─────────┐   ┌──────────────┐   │ │
│  │  │  USER   │──▶│  GUARDRAILS  │──▶│   SR     │──▶│ BIFROST │──▶│    MODEL     │   │ │
│  │  │  AGENT  │   │              │   │ classify │   │  route  │   │   (local or  │   │ │
│  │  │         │   │ • regex      │   │ /intent  │   │  + fwd  │   │   frontier)  │   │ │
│  │  │         │   │ • judge      │   │          │   │         │   │              │   │ │
│  │  │         │   │ • policy     │   │          │   │         │   │              │   │ │
│  │  └─────────┘   └──────────────┘   └────┬─────┘   └────┬────┘   └──────────────┘   │ │
│  │                                         │              │                            │ │
│  │                                         │              │    ┌───────────────────┐   │ │
│  │                                         │              ├───▶│ llama-server      │   │ │
│  │                                         │              │    │ (promoted local)  │   │ │
│  │                                         │              │    └───────────────────┘   │ │
│  │                                         │              │                            │ │
│  │                                         │              │    ┌───────────────────┐   │ │
│  │                                         │              └───▶│ Frontier API      │   │ │
│  │                                         │                   │ (Anthropic/OpenAI)│   │ │
│  │                                         │                   └───────────────────┘   │ │
│  │                                         ▼                                           │ │
│  │                                   ┌───────────────┐                                 │ │
│  │                                   │ TRACE CAPTURE │                                 │ │
│  │                                   │ (async, non-  │                                 │ │
│  │                                   │  blocking)    │                                 │ │
│  │                                   └───────┬───────┘                                 │ │
│  │                                           │                                         │ │
│  └───────────────────────────────────────────┼─────────────────────────────────────────┘ │
│                                              │                                           │
│                                              ▼                                           │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐   │
│  │                                                                                    │   │
│  │                           STORAGE LAYER                                           │   │
│  │                                                                                    │   │
│  │  ┌──────────────────────┐         ┌──────────────────────────────────────────┐    │   │
│  │  │  training-store.db   │         │  Grafana Tempo                            │    │   │
│  │  │  (SQLite)            │         │  (OTel trace visualization)               │    │   │
│  │  │                      │         │                                           │    │   │
│  │  │  • prompt            │         │  • Full request traces                    │    │   │
│  │  │  • response          │         │  • Routing decisions                      │    │   │
│  │  │  • category          │         │  • Latency histograms                     │    │   │
│  │  │  • model_used        │         │  • Category distribution                  │    │   │
│  │  │  • used_for_training │         │                                           │    │   │
│  │  └──────────┬───────────┘         └──────────────────────────────────────────┘    │   │
│  │             │                                                                      │   │
│  └─────────────┼────────────────────────────────────────────────────────────────────┘   │
│                │                                                                         │
│                │ threshold reached OR manual trigger                                     │
│                ▼                                                                         │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐   │
│  │                                                                                    │   │
│  │                    TRAINING PIPELINE LAYER (periodic)                              │   │
│  │                                                                                    │   │
│  │  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────┐   │   │
│  │  │ EXTRACT  │──▶│ DATASET  │──▶│  TRAIN   │──▶│  EXPORT  │──▶│   DEPLOY     │   │   │
│  │  │          │   │  BUILD   │   │          │   │          │   │              │   │   │
│  │  │ Query    │   │          │   │ Unsloth  │   │ → GGUF   │   │ Copy to      │   │   │
│  │  │ SQLite   │   │ Unsloth  │   │   OR     │   │ q4_k_m   │   │ models/      │   │   │
│  │  │ by       │   │ data-    │   │ mlx-lm-  │   │          │   │              │   │   │
│  │  │ category │   │ designer │   │ lora     │   │          │   │ llama-server │   │   │
│  │  │          │   │   OR     │   │          │   │          │   │ discovers    │   │   │
│  │  │          │   │ Direct   │   │ SFT/DPO/ │   │          │   │              │   │   │
│  │  │          │   │ JSONL    │   │ GRPO/ORPO│   │          │   │              │   │   │
│  │  └──────────┘   └──────────┘   └──────────┘   └──────────┘   └──────┬───────┘   │   │
│  │                                                                       │           │   │
│  │                                                                       ▼           │   │
│  │                                                              ┌──────────────────┐ │   │
│  │                                                              │    EVALUATE      │ │   │
│  │                                                              │                  │ │   │
│  │                                                              │ LLM-as-Judge:    │ │   │
│  │                                                              │ local vs frontier│ │   │
│  │                                                              │ on held-out set  │ │   │
│  │                                                              └────────┬─────────┘ │   │
│  │                                                                       │           │   │
│  │                                                              ┌────────┴─────────┐ │   │
│  │                                                              │                  │ │   │
│  │                                                         pass ▼             fail ▼ │   │
│  │                                                     ┌──────────────┐ ┌──────────┐ │   │
│  │                                                     │   PROMOTE    │ │  FAILED  │ │   │
│  │                                                     │              │ │          │ │   │
│  │                                                     │ Update SR    │ │ Log,     │ │   │
│  │                                                     │ config +     │ │ wait for │ │   │
│  │                                                     │ Bifrost      │ │ more data│ │   │
│  │                                                     │ routing      │ │          │ │   │
│  │                                                     └──────────────┘ └──────────┘ │   │
│  │                                                                                    │   │
│  └───────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                           │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Component Inventory

| Component | Type | Port | Language | Lifecycle |
|-----------|------|------|----------|-----------|
| DefenseClaw Gateway | Native binary | 18970 (API) | Go | Always running |
| Semantic Router | Docker container | 8888 | Go (vLLM SR) | Always running |
| llama-server | Native binary | 8090 | C++ | Always running, lazy-load |
| Training subprocess | Temporary process | — | Python | Runs during training only |
| Grafana | Docker container | 3000 | TypeScript | Always running |
| Tempo | Docker container | 3200/4318 | Go | Always running |
| Prometheus | Docker container | 9090 | Go | Always running |
| training-store.db | Embedded | — | SQLite | Part of gateway process |

---

## 3. Data Flow Diagrams

### 3.1 Runtime Data Flow (Every Request)

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                      │
│  REQUEST PATH (synchronous, <200ms total)                                           │
│                                                                                      │
│  User ─────▶ DefenseClaw Gateway                                                    │
│              │                                                                       │
│              ├─▶ [1] Pre-call Guardrails (regex + judge + policy)                    │
│              │       IF blocked → return error to user                               │
│              │       IF passed ↓                                                     │
│              │                                                                       │
│              ├─▶ [2] SR classify/intent (POST :8888/api/v1/classify/intent)          │
│              │       Returns: {category, recommended_model, matched_signals}         │
│              │                                                                       │
│              ├─▶ [3] Model Selection (Bifrost)                                       │
│              │       IF category is promoted → llama-server (:8090)                  │
│              │       ELSE → frontier API (Anthropic/OpenAI/Bedrock)                  │
│              │                                                                       │
│              ├─▶ [4] Post-call Guardrails (response inspection)                      │
│              │       IF blocked → return filtered response                           │
│              │       IF passed ↓                                                     │
│              │                                                                       │
│              └─▶ [5] Return response to user                                         │
│                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                      │
│  TRACE PATH (asynchronous, non-blocking)                                            │
│                                                                                      │
│  After step [5], in parallel:                                                        │
│                                                                                      │
│  ┌─▶ [A] Write to training-store.db (SQLite)                                        │
│  │       {category, prompt, response, model_used, latency, tokens}                  │
│  │                                                                                   │
│  └─▶ [B] Export OTel span to Tempo (via OTLP-HTTP)                                  │
│          {span attributes: dc.routing.category, dc.routing.decision, ...}           │
│                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Training Pipeline Flow (Periodic)

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                      │
│  TRIGGER                                                                             │
│                                                                                      │
│  ┌───────────────────┐         ┌─────────────────────────┐                          │
│  │  Auto-Trigger     │         │  Manual Trigger          │                          │
│  │                   │         │                          │                          │
│  │  Every 60s:       │         │  defenseclaw training    │                          │
│  │  check trace      │         │  run --category code     │                          │
│  │  count >= min     │         │                          │                          │
│  └────────┬──────────┘         └────────────┬────────────┘                          │
│           │                                  │                                       │
│           └──────────────┬───────────────────┘                                       │
│                          ▼                                                           │
│                                                                                      │
│  STAGE 1: EXTRACT                                                                    │
│  ─────────────────                                                                   │
│                                                                                      │
│  ┌──────────────────────────────────────────────────────┐                            │
│  │  Query training-store.db:                             │                            │
│  │                                                       │                            │
│  │  SELECT prompt, response, model_used                  │                            │
│  │  FROM training_traces                                 │                            │
│  │  WHERE category = 'code'                              │                            │
│  │    AND used_for_training = FALSE                      │                            │
│  │  ORDER BY timestamp DESC                              │                            │
│  │  LIMIT 1000                                           │                            │
│  │                                                       │                            │
│  │  Output: code_raw.jsonl (1000 traces)                 │                            │
│  │  Hold-out: 10% → code_eval.jsonl (100 traces)        │                            │
│  └──────────────────────────────────────────────────────┘                            │
│                          │                                                           │
│                          ▼                                                           │
│                                                                                      │
│  STAGE 2: BUILD DATASET                                                              │
│  ──────────────────────                                                              │
│                                                                                      │
│  ┌──────────────────────────────────────────────────────┐                            │
│  │                                                       │                            │
│  │  IF backend = unsloth:                                │                            │
│  │    Call data-designer Python API                      │                            │
│  │    • Read code_raw.jsonl as seed                      │                            │
│  │    • Generate rejected responses via local model      │                            │
│  │    • Score with LLM Judge                             │                            │
│  │    • Format as DPO/SFT dataset                        │                            │
│  │                                                       │                            │
│  │  IF backend = mlx-lm-lora:                            │                            │
│  │    Direct JSONL conversion (Go code):                 │                            │
│  │    • SFT: {"messages": [...]}                         │                            │
│  │    • DPO: {"prompt":, "chosen":, "rejected":}         │                            │
│  │                                                       │                            │
│  │  Output: code_train.jsonl                             │                            │
│  └──────────────────────────────────────────────────────┘                            │
│                          │                                                           │
│                          ▼                                                           │
│                                                                                      │
│  STAGE 3: TRAIN                                                                      │
│  ──────────────                                                                      │
│                                                                                      │
│  ┌──────────────────────────────────────────────────────┐                            │
│  │                                                       │                            │
│  │  DefenseClaw generates training script                │                            │
│  │  Executes as subprocess (Python)                      │                            │
│  │                                                       │                            │
│  │  IF backend = unsloth:                                │                            │
│  │    from unsloth import FastLanguageModel              │                            │
│  │    model = FastLanguageModel.from_pretrained(...)     │                            │
│  │    trainer = DPOTrainer(model, dataset, ...)          │                            │
│  │    trainer.train()                                    │                            │
│  │                                                       │                            │
│  │  IF backend = mlx-lm-lora:                            │                            │
│  │    $ mlx-lm-lora --train-mode dpo --model ... \      │                            │
│  │      --data code_train.jsonl --output ./output        │                            │
│  │                                                       │                            │
│  │  Duration: 2-6 hours (DPO), 24-36 hours (GRPO/Mac)   │                            │
│  │  Progress: parsed from stdout → training status       │                            │
│  └──────────────────────────────────────────────────────┘                            │
│                          │                                                           │
│                          ▼                                                           │
│                                                                                      │
│  STAGE 4: EXPORT                                                                     │
│  ──────────────                                                                      │
│                                                                                      │
│  ┌──────────────────────────────────────────────────────┐                            │
│  │                                                       │                            │
│  │  IF backend = unsloth:                                │                            │
│  │    model.save_pretrained_gguf(                        │                            │
│  │      "./output", tokenizer,                           │                            │
│  │      quantization_method="q4_k_m"                     │                            │
│  │    )                                                  │                            │
│  │                                                       │                            │
│  │  IF backend = mlx-lm-lora:                            │                            │
│  │    $ mlx-lm-lora --export-gguf \                      │                            │
│  │      --model ./output \                               │                            │
│  │      --output code-v2.gguf \                          │                            │
│  │      --quantize q4_k_m                                │                            │
│  │                                                       │                            │
│  │  Output: code-v2.gguf (~2.5 GB for 4B model)         │                            │
│  │  Duration: 5-10 minutes                               │                            │
│  └──────────────────────────────────────────────────────┘                            │
│                          │                                                           │
│                          ▼                                                           │
│                                                                                      │
│  STAGE 5: DEPLOY                                                                     │
│  ──────────────                                                                      │
│                                                                                      │
│  ┌──────────────────────────────────────────────────────┐                            │
│  │                                                       │                            │
│  │  1. Copy GGUF to ~/.defenseclaw/models/code-v2.gguf   │                            │
│  │  2. Update registry.json with version metadata        │                            │
│  │  3. llama-server auto-discovers (router mode)         │                            │
│  │     OR restart if replacing existing version          │                            │
│  │  4. Verify: GET :8090/health → 200                    │                            │
│  │                                                       │                            │
│  └──────────────────────────────────────────────────────┘                            │
│                          │                                                           │
│                          ▼                                                           │
│                                                                                      │
│  STAGE 6: EVALUATE                                                                   │
│  ────────────────                                                                    │
│                                                                                      │
│  ┌──────────────────────────────────────────────────────┐                            │
│  │                                                       │                            │
│  │  For each prompt in held-out eval set (50-100):       │                            │
│  │                                                       │                            │
│  │    response_local = POST llama-server(prompt)         │                            │
│  │    response_frontier = lookup from training-store.db  │                            │
│  │                                                       │                            │
│  │    judge_result = LLM_Judge(                          │                            │
│  │      prompt, response_local, response_frontier        │                            │
│  │    )                                                  │                            │
│  │    → {"score_a": 8.4, "score_b": 9.1}                │                            │
│  │                                                       │                            │
│  │  ratio = avg(score_a) / avg(score_b)                  │                            │
│  │        = 8.4 / 9.1 = 0.923                           │                            │
│  │                                                       │                            │
│  │  Decision: 0.923 >= 0.90 (threshold) → PROMOTE        │                            │
│  │                                                       │                            │
│  └──────────────────────────────────────────────────────┘                            │
│                          │                                                           │
│                     ┌────┴────┐                                                      │
│                pass ▼    fail ▼                                                      │
│                                                                                      │
│  STAGE 7a: PROMOTE              STAGE 7b: FAIL                                       │
│  ─────────────────              ───────────────                                      │
│                                                                                      │
│  ┌─────────────────────┐       ┌──────────────────────┐                             │
│  │                      │       │                       │                             │
│  │ 1. Update SR config: │       │ 1. Log: "ratio 0.85  │                             │
│  │    code → code-local │       │    below threshold"   │                             │
│  │                      │       │                       │                             │
│  │ 2. Update Bifrost:   │       │ 2. Keep routing to    │                             │
│  │    code-local →      │       │    frontier           │                             │
│  │    :8090             │       │                       │                             │
│  │                      │       │ 3. Wait for more      │                             │
│  │ 3. Record in         │       │    traces → retrain   │                             │
│  │    registry.json     │       │                       │                             │
│  │                      │       │ 4. Model stays in     │                             │
│  │ 4. Start quality     │       │    models/ dir        │                             │
│  │    monitoring        │       │                       │                             │
│  │                      │       └──────────────────────┘                             │
│  │ 5. Notify user       │                                                            │
│  │                      │                                                            │
│  └─────────────────────┘                                                            │
│                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Post-Promotion Quality Monitoring

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                      │
│  QUALITY MONITOR (runs continuously after promotion)                                 │
│                                                                                      │
│  Every N requests (monitor_interval, default 100):                                   │
│                                                                                      │
│  ┌──────────────────────────────────────────────────────────────────────────────┐    │
│  │                                                                               │    │
│  │  [1] Sample 5 random prompts from recent traces (served by local model)       │    │
│  │                                                                               │    │
│  │  [2] For each prompt:                                                         │    │
│  │        • Get response from local model (already stored in trace)              │    │
│  │        • Get response from frontier model (fresh API call)                    │    │
│  │        • Score with LLM Judge                                                 │    │
│  │                                                                               │    │
│  │  [3] Compute spot_ratio = avg(local_scores) / avg(frontier_scores)            │    │
│  │                                                                               │    │
│  │  [4] IF spot_ratio < (eval_threshold - 0.05):                                 │    │
│  │        → AUTO-ROLLBACK                                                        │    │
│  │        → Alert user                                                           │    │
│  │        → Log degradation event                                                │    │
│  │                                                                               │    │
│  │      ELSE:                                                                    │    │
│  │        → Continue serving locally                                             │    │
│  │        → Log spot-check result                                                │    │
│  │                                                                               │    │
│  └──────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                      │
│  ROLLBACK ACTION:                                                                    │
│                                                                                      │
│  ┌──────────────────────────────────────────────────────────────────────────────┐    │
│  │  1. Revert SR config: category → frontier model                              │    │
│  │  2. Revert Bifrost routing                                                    │    │
│  │  3. Mark version as "rolled_back" in registry                                 │    │
│  │  4. Desktop notification (if enabled)                                         │    │
│  │  5. Keep GGUF file (for debugging/retraining)                                 │    │
│  │  6. Reset trace counter (accumulate new data for next attempt)                │    │
│  └──────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.4 Category Lifecycle (Time-based View)

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                      │
│  CATEGORY: "code" — Lifecycle Over Time                                             │
│                                                                                      │
│  Week 1          Week 2          Week 3          Week 4          Week 5+             │
│  ──────          ──────          ──────          ──────          ──────              │
│                                                                                      │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────────┐       │
│  │COLLECTING│───▶│COLLECTING│───▶│ TRAINING│───▶│ PROMOTED│───▶│  MONITORING │       │
│  │ traces   │    │ traces   │    │ + EVAL  │    │         │    │             │       │
│  │          │    │          │    │         │    │         │    │  ┌───────┐  │       │
│  │ 0→250    │    │ 250→500  │    │ DPO on  │    │ Score:  │    │  │quality│  │       │
│  │ traces   │    │ traces   │    │ Qwen3.5 │    │ 0.92 ✓  │    │  │checks│  │       │
│  │          │    │ ✓ min_   │    │ 4B      │    │         │    │  │every  │  │       │
│  │ All →    │    │ traces   │    │         │    │ code →  │    │  │100 req│  │       │
│  │ frontier │    │ reached  │    │ 6 hours │    │ local   │    │  └───────┘  │       │
│  │          │    │          │    │         │    │         │    │             │       │
│  │ Cost:    │    │ AUTO-    │    │ Export  │    │ Cost:   │    │  IF drops:  │       │
│  │ $$$      │    │ TRIGGER  │    │ GGUF    │    │ $0      │    │  → rollback │       │
│  └─────────┘    └─────────┘    └─────────┘    └─────────┘    └─────────────┘       │
│                                                                                      │
│  Traces/day: ~100            Total: 500+         Savings: ~$15/day                   │
│                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Component Specifications

### 4.1 Trace Capture

**Purpose:** Store every LLM request + SR classification for future training.

**Trigger:** After each request completes (async, non-blocking).

**Storage:** `~/.defenseclaw/training-store.db` (SQLite)

**Schema:**
```sql
CREATE TABLE training_traces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    category TEXT NOT NULL,
    recommended_model TEXT,
    matched_signals TEXT,
    prompt TEXT NOT NULL,
    response TEXT NOT NULL,
    model_used TEXT NOT NULL,
    is_promoted_model BOOLEAN DEFAULT FALSE,
    latency_ms INTEGER,
    tokens_in INTEGER,
    tokens_out INTEGER,
    used_for_training BOOLEAN DEFAULT FALSE,
    training_run_id TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_category_unused ON training_traces(category, used_for_training);
CREATE INDEX idx_category_time ON training_traces(category, timestamp);
```

**Implementation:** Buffered channel (100 entries) + single writer goroutine. If channel full, drop silently.

### 4.2 Auto-Trigger

**Purpose:** Start training when enough data accumulates.

**Mechanism:** Goroutine checks every 60 seconds:
```
FOR each category WHERE auto_trigger = true:
  count = COUNT(*) WHERE category = X AND used_for_training = FALSE
  IF count >= min_traces AND state[X] == IDLE:
    start_pipeline(X)
```

### 4.3 Dataset Builder

**Purpose:** Transform raw traces into training-ready datasets.

**Backend = `unsloth`:** Calls `data-designer` Python API (generates rejected responses, applies LLM Judge scoring, formats output).

**Backend = `mlx-lm-lora`:** Direct JSONL conversion in Go (simple format mapping).

**Hold-out:** 10% reserved for evaluation (never trained on).

### 4.4 Training Runner

**Purpose:** Execute fine-tuning as a managed subprocess.

**Interface:** DefenseClaw generates a Python script, executes it, monitors stdout for progress, handles timeout (12h max).

**Supported algorithms:** SFT, DPO, GRPO, ORPO, SFT+DPO (two-stage).

### 4.5 Model Deployer

**Purpose:** Make trained GGUF available for inference.

**Mechanism:** Copy to models dir → llama-server auto-discovers (router mode) or restart for clean state.

### 4.6 Evaluator

**Purpose:** Score local model vs frontier using LLM-as-judge.

**Method:** Send both responses to judge model, get 1-10 scores, compute ratio.

**Minimum:** 50 eval prompts per run. Abort if fewer available.

### 4.7 Promoter

**Purpose:** Update routing to send category traffic to local model.

**Actions:** Update SR config + Bifrost routing + registry metadata + start quality monitor.

### 4.8 Quality Monitor

**Purpose:** Detect post-promotion quality degradation.

**Method:** Sample 5 prompts every N requests, score vs frontier, auto-rollback if drops.

---

## 5. Tool Reference

### 5.1 vLLM Semantic Router

| Property | Value |
|----------|-------|
| **Purpose** | Classify queries into routing categories |
| **Image** | `ghcr.io/vllm-project/semantic-router/vllm-sr:latest` |
| **Port** | 8888 |
| **API** | `POST /api/v1/classify/intent` |
| **Request** | `{"messages": [...], "options": {"return_probabilities": true}}` |
| **Response** | `{"recommended_model": "...", "routing_decision": "...", "matched_signals": {...}}` |
| **Health** | `GET /health` → `{"status": "healthy"}` |
| **Managed by** | DefenseClaw routing lifecycle (Docker container) |

### 5.2 Unsloth (Training Backend A)

| Property | Value |
|----------|-------|
| **Purpose** | Dataset creation + model training + GGUF export |
| **Install** | `pip install unsloth data-designer` |
| **Platform** | NVIDIA GPU (CUDA) required for GRPO; Mac supported for SFT/DPO via MLX |
| **Dataset API** | `data-designer` Python library (seed data → LLM generation → format) |
| **Training API** | `FastLanguageModel.from_pretrained()` + TRL trainers |
| **Export API** | `model.save_pretrained_gguf(dir, tokenizer, quantization_method="q4_k_m")` |
| **Algorithms** | SFT, DPO, GRPO, ORPO, PPO |
| **Memory (4B)** | ~6GB (SFT), ~10GB (DPO), ~20GB (GRPO) |
| **License** | Apache 2.0 (core), AGPL (Studio UI) |

### 5.3 mlx-lm-lora (Training Backend B)

| Property | Value |
|----------|-------|
| **Purpose** | Native Apple Silicon training |
| **Install** | `pip install -U mlx-lm-lora` |
| **Platform** | Apple Silicon Mac only (M1/M2/M3/M4) |
| **CLI** | `mlx-lm-lora --train-mode <algo> --model <repo> --data <file>` |
| **Export** | `mlx-lm-lora --export-gguf --model <dir> --output <file> --quantize q4_k_m` |
| **Algorithms** | SFT, DPO, ORPO, CPO, GRPO, Dr.GRPO, DAPO, PPO, Online DPO, XPO |
| **Memory (4B)** | ~8GB (DPO), ~20GB (GRPO) |
| **Speed (4B DPO)** | ~4-6 hours on M2 Max |
| **License** | MIT |

### 5.4 llama.cpp / llama-server (Model Hosting)

| Property | Value |
|----------|-------|
| **Purpose** | Serve fine-tuned GGUF models |
| **Install** | `brew install llama.cpp` or binary from GitHub releases |
| **Port** | 8090 (configurable) |
| **API** | OpenAI-compatible: `/v1/chat/completions`, `/v1/models`, `/health`, `/metrics` |
| **Mode** | Router mode (`--models-dir`) — auto-discovers GGUF files by name |
| **Lazy-load** | `--models-max N` — loads on first request, evicts LRU |
| **Streaming** | Full SSE streaming support |
| **Hardware** | Apple Metal, NVIDIA CUDA, AMD ROCm, Vulkan, CPU |
| **Binary size** | 5-30 MB |
| **License** | MIT |

### 5.5 Grafana + Tempo + Prometheus (Observability)

| Property | Value |
|----------|-------|
| **Purpose** | Trace visualization + metrics dashboards |
| **Install** | `defenseclaw setup local-observability` (Docker Compose) |
| **Grafana port** | 3000 |
| **Tempo port** | 3200 (query), 4318 (OTLP ingest) |
| **Prometheus port** | 9090 |
| **Span attributes** | `dc.routing.category`, `dc.routing.decision`, `dc.routing.recommended_model` |
| **Note** | For visualization only — training reads from SQLite, not Tempo |

### 5.6 data-designer (Dataset Builder)

| Property | Value |
|----------|-------|
| **Purpose** | Programmatic dataset creation with LLM generation + judging |
| **Install** | `pip install data-designer` (included with Unsloth) |
| **Input** | CSV, JSON, JSONL, Parquet, HuggingFace datasets |
| **Output** | Formatted JSONL (SFT, DPO, or custom schema) |
| **Features** | Seed sources, LLM text columns, LLM judge columns, schema transforms |
| **License** | Apache 2.0 |

### 5.7 Bifrost (Provider SDK)

| Property | Value |
|----------|-------|
| **Purpose** | Multi-provider format translation + auth + streaming |
| **Formats** | OpenAI ↔ Anthropic ↔ Bedrock ↔ Gemini ↔ Ollama |
| **Local model routing** | `model_name → http://127.0.0.1:8090/v1/chat/completions` (no translation needed) |
| **Frontier routing** | `model_name → api.anthropic.com/v1/messages` (translates format) |
| **Key** | When local model is promoted, Bifrost routes with zero translation overhead |

---

## 6. Configuration Reference

```yaml
training:
  enabled: true                         # master switch for entire pipeline
  backend: unsloth                      # unsloth | mlx-lm-lora
  models_dir: ~/.defenseclaw/models     # GGUF storage directory
  llama_server_port: 8090               # llama-server listen port
  training_timeout_hours: 12            # kill training if exceeds this
  trace_retention_days: 90              # auto-purge old traces

  # Curated base models (user picks per category)
  base_models:
    - id: Qwen3.5-4B
      hf_repo: unsloth/Qwen3.5-4B
      mlx_repo: mlx-community/Qwen3.5-4B-4bit
      size: 4B
    - id: Qwen3.5-1.5B
      hf_repo: unsloth/Qwen3.5-1.5B
      mlx_repo: mlx-community/Qwen3.5-1.5B-4bit
      size: 1.5B
    - id: Llama-3.2-3B
      hf_repo: unsloth/Llama-3.2-3B
      mlx_repo: mlx-community/Llama-3.2-3B-4bit
      size: 3B
    - id: Phi-4-mini
      hf_repo: unsloth/Phi-4-mini
      mlx_repo: mlx-community/Phi-4-mini-4bit
      size: 3.8B
    - id: Gemma-3-4B
      hf_repo: unsloth/Gemma-3-4B
      mlx_repo: mlx-community/Gemma-3-4B-4bit
      size: 4B

  # Per-category training configuration
  categories:
    - name: code                        # matches SR routing_decision
      base_model: Qwen3.5-4B            # from base_models list
      algorithm: dpo                    # sft | dpo | grpo | sft+dpo | orpo
      min_traces: 500                   # minimum before first training
      eval_threshold: 0.90              # promote if ratio >= this
      eval_prompts: 50                  # held-out test set size
      auto_trigger: true                # auto-train when min_traces reached
      monitor_interval: 100             # spot-check every N requests post-promotion

    - name: reasoning
      base_model: Qwen3.5-4B
      algorithm: sft+dpo
      min_traces: 1000
      eval_threshold: 0.92
      eval_prompts: 75
      auto_trigger: false               # manual only

    - name: simple-qa
      base_model: Qwen3.5-1.5B
      algorithm: sft
      min_traces: 300
      eval_threshold: 0.85
      eval_prompts: 50
      auto_trigger: true
      monitor_interval: 200
```

---

## 7. CLI Reference

### 7.1 Setup

```bash
defenseclaw training enable
# Interactive wizard:
#   1. Select backend (unsloth | mlx-lm-lora)
#   2. Install dependencies
#   3. Configure categories
#   4. Start llama-server
#   5. Enable trace capture

defenseclaw training disable
# Stops auto-triggers, keeps data and models
```

### 7.2 Status

```bash
defenseclaw training status
# Training Pipeline: enabled (backend: unsloth)
# llama-server: running (port 8090, 2 models loaded)
#
# Categories:
#   code:       847/500 traces ✓ | PROMOTED (v2, ratio=0.92)
#   reasoning:  234/1000 traces  | need 766 more
#   simple-qa:  1205/300 traces ✓| PROMOTED (v1, ratio=0.91)
```

### 7.3 Training Operations

```bash
defenseclaw training run --category code          # trigger training now
defenseclaw training run --category code --dry-run # show plan without executing
defenseclaw training eval --category code          # run eval only (no training)
defenseclaw training promote --category code --version v1  # force-promote
defenseclaw training rollback --category code      # revert to frontier
```

### 7.4 Data Management

```bash
defenseclaw training traces --category code                    # show trace stats
defenseclaw training traces --category code --export out.jsonl # export raw data
defenseclaw training traces --reset --category code            # mark all unused
```

### 7.5 Model Management

```bash
defenseclaw training models                       # list all versions
defenseclaw training models --delete code-v1      # remove old version
```

---

## 8. Error Handling

| Stage | Error | Behavior | Recovery |
|-------|-------|----------|----------|
| Trace capture | SQLite write fails | Log warning, don't block response | Retry next request |
| Auto-trigger | Training already running | Skip silently | Wait for current run |
| Extraction | Not enough traces | Abort, log count | Wait for more data |
| Dataset build | Subprocess fails | Log stderr, mark failed | Alert user, retry manual |
| Training | Out of memory | Kill, log OOM | Suggest smaller batch/model |
| Training | Subprocess crash | Log, mark failed | Keep checkpoint if available |
| Training | Timeout (>12h) | Kill subprocess | Alert user |
| Export | GGUF conversion fails | Log error, mark failed | Debug manually |
| Deploy | llama-server can't load | Log, don't promote | Restart llama-server |
| Eval | Judge API unavailable | Retry 3x with backoff | Abort if all fail |
| Eval | Below threshold | Don't promote (normal) | Wait for next cycle |
| Promotion | SR config update fails | Rollback config | Alert user |
| Post-promotion | Quality drops | Auto-rollback | Alert + retrain with new data |
| llama-server | Crashes | Watchdog restart (max 3) | During downtime → frontier |

---

## 9. State Machine

### Per-Category State Diagram

```
                    ┌─────────────┐
           ┌──────▶│    IDLE     │◀─────────────────────────────────┐
           │       └──────┬──────┘                                  │
           │              │                                         │
           │              │ threshold reached                       │
           │              │ OR manual trigger                       │
           │              ▼                                         │
           │       ┌──────────────┐                                 │
           │       │  EXTRACTING  │                                 │
           │       └──────┬───────┘                                 │
           │              │                                         │
           │              ▼                                         │
           │       ┌──────────────────┐                             │
           │       │ BUILDING_DATASET │                             │
           │       └──────┬───────────┘                             │
           │              │                                         │
           │              ▼                                         │
           │       ┌──────────────┐                                 │
           │       │   TRAINING   │──── timeout/crash ──────────────┤
           │       └──────┬───────┘                                 │
           │              │                                         │
           │              ▼                                         │
           │       ┌──────────────┐                                 │
           │       │  EXPORTING   │──── conversion fail ────────────┤
           │       └──────┬───────┘                                 │
           │              │                                         │
           │              ▼                                         │
           │       ┌──────────────┐                                 │
           │       │  DEPLOYING   │                                 │
           │       └──────┬───────┘                                 │
           │              │                                         │
           │              ▼                                         │
           │       ┌──────────────┐                                 │
           │       │  EVALUATING  │                                 │
           │       └──────┬───────┘                                 │
           │              │                                         │
           │         ┌────┴────┐                                    │
           │    pass ▼    fail ▼                                    │
           │  ┌──────────┐  ┌────────┐                             │
           │  │ PROMOTED │  │ FAILED │─────────────────────────────┘
           │  └────┬─────┘  └────────┘
           │       │
           │       │ quality monitor detects drop
           │       ▼
           │  ┌──────────────┐
           └──│ ROLLED_BACK  │
              └──────────────┘
```

**Concurrency rules:**
- One state per category at a time (mutex-protected)
- Multiple categories can be in different states concurrently
- State persisted in `registry.json` (survives restarts)

---

## 10. File Layout

```
~/.defenseclaw/
├── config.yaml                          # Single source of truth
├── training-store.db                    # SQLite (traces for training)
│
├── models/                              # GGUF model files
│   ├── registry.json                    # Version metadata + state
│   ├── code-v1.gguf                     # First trained version
│   ├── code-v2.gguf                     # Retrained (promoted)
│   └── simple-qa-v1.gguf               # Different category
│
├── training/                            # Training pipeline workspace
│   ├── datasets/                        # Generated datasets
│   │   ├── code_raw.jsonl               # Extracted raw traces
│   │   ├── code_train.jsonl             # Formatted for training
│   │   └── code_eval.jsonl              # Held-out eval set
│   ├── scripts/                         # Generated training scripts
│   │   └── train_code_v2.py             # Python script for current run
│   ├── output/                          # Training output (temporary)
│   │   └── code-v2/                     # Checkpoints + final model
│   └── logs/                            # Training subprocess logs
│       └── code_v2_2026-07-17.log       # Stdout/stderr capture
│
├── semantic-router/                     # SR config + container data
│   └── config.yaml                      # Generated SR config (v0.3)
│
└── bin/                                 # Managed binaries
    └── llama-server                     # (if not installed via brew)
```

---

## 11. Implementation Modules

| Module | Language | File | Responsibility |
|--------|----------|------|----------------|
| TraceCapture | Go | `internal/training/capture.go` | Async SQLite write after each request |
| AutoTrigger | Go | `internal/training/trigger.go` | Monitor counts, fire pipeline |
| DataExtractor | Go | `internal/training/extractor.go` | Query SQLite, export raw JSONL |
| DatasetBuilder | Go | `internal/training/dataset.go` | Call data-designer or build JSONL |
| TrainRunner | Go | `internal/training/runner.go` | Generate script, exec subprocess |
| Deployer | Go | `internal/training/deployer.go` | Copy GGUF, manage llama-server |
| Evaluator | Go | `internal/training/evaluator.go` | LLM-as-judge comparison scoring |
| Promoter | Go | `internal/training/promoter.go` | Update SR + Bifrost routing |
| QualityMonitor | Go | `internal/training/monitor.go` | Post-promotion spot-checks |
| ModelRegistry | Go | `internal/training/registry.go` | CRUD on registry.json |
| LlamaLifecycle | Go | `internal/training/llama.go` | Start/stop/health llama-server |
| Pipeline | Go | `internal/training/pipeline.go` | Orchestrate stages, state machine |
| Config | Go | `internal/config/training.go` | TrainingConfig struct |
| CLI | Python | `cli/defenseclaw/commands/cmd_training.py` | User-facing commands |

---

## 12. Estimated Effort

| Phase | Description | Time |
|-------|-------------|------|
| 1 | Trace capture + SQLite store | 2 days |
| 2 | Auto-trigger + state machine | 1 day |
| 3 | Dataset extraction + builder | 2 days |
| 4 | Training subprocess runner | 2 days |
| 5 | llama-server lifecycle | 1 day |
| 6 | Evaluator (LLM-as-judge) | 2 days |
| 7 | Promoter + rollback + monitor | 2 days |
| 8 | Model registry | 0.5 day |
| 9 | CLI commands | 1.5 days |
| 10 | Config types + integration | 1 day |
| 11 | End-to-end testing | 2 days |
| **Total** | | **~17 days** |

---

*End of Technical Specification*
