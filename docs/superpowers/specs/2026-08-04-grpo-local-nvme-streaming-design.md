# GRPO-Local: QLoRA GRPO with NVMe-Streamed Frozen Models

**Date:** 2026-08-04  
**Author:** Nikhil Ghodki  
**Status:** Design Complete  
**Target:** `internal/training/` (new `grpo-local` backend)

---

## Executive Summary

Add a new training backend (`grpo-local`) to DefenseClaw's continuous model improvement pipeline that implements Group Relative Policy Optimization (GRPO) with QLoRA, using NVMe-streamed frozen models for reference/reward computation. This enables reinforcement learning-based model training on consumer hardware with 8 GB RAM and no GPU.

**Key innovation:** Reference and reward models are streamed layer-by-layer from NVMe using O_DIRECT, reducing memory from ~32 GB (standard GRPO) to ~2.5 GB while maintaining identical training outcomes.

---

## Problem Statement

The existing training pipeline supports SFT (supervised fine-tuning) via Unsloth/mlx-lm-lora. SFT trains models to imitate frontier responses, but cannot discover novel solutions or optimize for verifiable outcomes (code correctness, format compliance, test execution).

GRPO enables the model to explore and learn from its own outputs, scored by deterministic reward functions. However, standard GRPO implementations (TRL GRPOTrainer) require GPU and 32+ GB RAM due to hosting policy + reference + reward models simultaneously.

**Goal:** Run GRPO on CPU-only hardware (8-16 GB RAM, fast NVMe) by streaming frozen models from disk.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Go Orchestrator (internal/training/grpo_runner.go)                      │
│                                                                          │
│  ┌──────────┐  ┌───────────┐  ┌───────────┐  ┌──────────────────────┐ │
│  │ Dataset  │→ │ Generation│→ │ Advantage │→ │ Loss + LoRA Update   │ │
│  │ Sampler  │  │ Scheduler │  │ Computer  │  │ (calls C lib)        │ │
│  └──────────┘  └─────┬─────┘  └───────────┘  └──────────────────────┘ │
│                       │                                                   │
└───────────────────────┼───────────────────────────────────────────────────┘
                        │ CGO calls
┌───────────────────────▼───────────────────────────────────────────────────┐
│  libgrpo_stream (C99, ~3000 lines)                                        │
│                                                                            │
│  ┌────────────────┐  ┌────────────────┐  ┌─────────────────────────────┐│
│  │ Policy Engine  │  │ Stream Engine  │  │ LoRA Engine                 ││
│  │ (Q4 in mmap)   │  │ (O_DIRECT)     │  │ (float32 adapters + Adam)  ││
│  │                │  │                │  │                             ││
│  │ • generate()   │  │ • ref_logprobs │  │ • forward_with_lora()      ││
│  │ • kv_cache     │  │ • reward_score │  │ • backward_lora()          ││
│  │ • sample_top_p │  │ • layer_buffer │  │ • adam_step()              ││
│  └────────────────┘  └────────────────┘  └─────────────────────────────┘│
│                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │ Kernel Library (shared by all engines)                               │ │
│  │ rmsnorm, matmul_q4, matmul_f32, silu, softmax, rope, gqa_attention │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────────┘
                        │
                        ▼ O_DIRECT pread / mmap
┌────────────────────────────────────────────────────────────────────────────┐
│  NVMe Storage (~/.defenseclaw/models/)                                      │
│  ├── policy.gguf          (1.5 GB, Q4_K_M, mmap'd for policy)             │
│  ├── reference.gguf       (1.5 GB, Q4_K_M, streamed layer-by-layer)       │
│  └── reward.gguf          (1.5 GB, Q4_K_M, streamed layer-by-layer)       │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Memory Modes (Auto-Detection)

The system detects available RAM at startup and selects a mode:

| Mode | Trigger | Policy | Reference | Reward | Total RAM |
|------|---------|--------|-----------|--------|-----------|
| **minimal** | < 6 GB free | mmap (Q4) | NVMe streamed | NVMe streamed | ~2.5 GB |
| **standard** | 6-12 GB free | mmap (Q4) | mmap resident | NVMe streamed | ~4.5 GB |
| **comfort** | > 12 GB free | mmap (Q4) | mmap resident | mmap resident | ~6.5 GB |

Auto-detection logic:
1. Query system free memory at GRPO pipeline start
2. Subtract policy model size + LoRA + KV cache + 1 GB headroom
3. Remaining budget determines frozen model placement
4. Priority: reference gets resident first (called more often for KL)

Override via config: `memory_mode: "minimal"` forces streaming regardless of available RAM.

**Platform fallback for O_DIRECT:**
- Linux: O_DIRECT with posix_memalign (full streaming performance)
- macOS: `fcntl(fd, F_NOCACHE, 1)` to bypass page cache (equivalent behavior)
- ARM64 Linux: pread + `posix_fadvise(SEQUENTIAL)` + `madvise(DONTNEED)`

---

## GRPO Training Loop

For each prompt in the dataset:

### Step 1: Generate (C: Policy Engine)
- Generate G completions autoregressively from policy + LoRA
- Capture per-token logprobs during generation (free — already computed)
- Policy is mmap'd, LoRA is in RAM → fast (50-140ms/token depending on model)

### Step 2: Score (Go: Reward Dispatcher)
- Dispatch to composable reward functions (rule-based, model-based, judge)
- Rule-based: exec, format, regex, contains, length, ground_truth, test_cases
- Model-based: stream reward.gguf layer-by-layer via C engine
- Judge: call existing evaluator.go HTTP endpoint

### Step 3: Advantage (Go: pure math)
- Group-relative normalization: `Â = (r - mean(r)) / std(r)`

### Step 4: Reference Logprobs (C: Stream Engine)
- Teacher-forced forward pass through reference.gguf
- Streamed layer-by-layer from NVMe (~1.2s per completion at 5 GB/s)
- Skipped entirely when `kl_coef=0`

### Step 5: Policy Logprobs (C: LoRA Engine)
- Forward through policy + LoRA (mmap'd, fast)
- Store activations at LoRA injection points for backward pass

### Step 6: Loss + Update (C: LoRA Engine)
- Compute clipped surrogate loss + KL penalty per token
- Backward through LoRA adapters only (frozen base has no gradients)
- Adam step on LoRA A and B matrices

### Step 7: Logging (Go)
- Report step, reward, loss, KL, clip fraction to stderr

---

## C Library: `libgrpo_stream`

### File Structure

```
internal/training/grpo_engine/
├── grpo.h              Public API (what Go calls via CGO)
├── kernels.c           Shared math kernels
├── policy.c            Policy engine: mmap'd forward, generate, KV cache
├── stream.c            Stream engine: O_DIRECT layer-by-layer forward
├── lora.c              LoRA engine: inject, backward, Adam optimizer
├── gguf.c              GGUF file parser
├── Makefile            Builds libgrpo_stream.a
└── testdata/
    ├── tiny_model.gguf 2-layer test model (~1 MB)
    └── fixtures/       Per-kernel golden outputs
```

### Public API

```c
// Lifecycle
GrpoCtx *grpo_init(GrpoConfig *cfg);
void     grpo_free(GrpoCtx *ctx);

// Generation (Policy Engine)
int      grpo_generate(GrpoCtx *ctx, const int *prompt, int prompt_len,
                       int *output, int max_len, float *logprobs_out,
                       float temp, float top_p);

// Logprob Computation
int      grpo_policy_logprobs(GrpoCtx *ctx, const int *tokens, int len, float *logprobs_out);
int      grpo_ref_logprobs(GrpoCtx *ctx, const int *tokens, int len, float *logprobs_out);
int      grpo_reward_forward(GrpoCtx *ctx, const int *tokens, int len, float *score_out);

// Training (LoRA Engine)
int      grpo_backward(GrpoCtx *ctx, const float *advantages,
                       const float *policy_logprobs, const float *old_logprobs,
                       const float *ref_logprobs, int G, int seq_len,
                       float clip_eps, float kl_coef);
int      grpo_adam_step(GrpoCtx *ctx, float lr, float beta1, float beta2, float eps, int step);

// Checkpointing
int      grpo_save_lora(GrpoCtx *ctx, const char *path);
int      grpo_load_lora(GrpoCtx *ctx, const char *path);

// Export
int      grpo_export_merged_gguf(GrpoCtx *ctx, const char *output_path);

// Diagnostics
GrpoStats grpo_stats(GrpoCtx *ctx);
```

### GrpoConfig

```c
typedef struct {
    const char *policy_gguf;       // Q4 GGUF for policy (mmap'd)
    const char *reference_gguf;    // Q4 GGUF for reference (streamed or mmap'd)
    const char *reward_gguf;       // Q4 GGUF for reward (streamed or mmap'd), NULL = skip
    int memory_mode;               // 0=minimal, 1=standard, 2=comfort
    int lora_rank;                 // default 16
    int lora_alpha;                // default 16
    const char *lora_targets;      // "q,k,v,o,gate,up,down"
    int max_seq_len;               // KV cache size (default 2048)
    int num_threads;               // OpenMP threads (default: nproc)
    int use_direct_io;             // 1=O_DIRECT, 0=fallback
    size_t layer_buffer_bytes;     // auto-sized from GGUF header
} GrpoConfig;
```

### Kernel Requirements

| Kernel | Purpose | Precision |
|--------|---------|-----------|
| `matmul_q4` | Q4 weight × float32 input | Double accumulator |
| `matmul_f32` | LoRA matrices (A, B) | Double accumulator |
| `rmsnorm` | Layer normalization | Double accumulator |
| `rope` | Rotary position embeddings | Float32 |
| `silu` | SiLU activation | Float32 |
| `softmax` | Numerically stable softmax | Float64 for max |
| `gqa_attention` | Grouped-query attention + causal mask | Float32 |
| `top_p_sample` | Nucleus sampling | Float32 |

All kernels have: scalar C99 reference, OpenMP parallel path, optional AVX2 path (bit-identical to scalar).

**Floating-point contract:** `-ffp-contract=off`, no `-ffast-math`. Ensures bit-identical results across scalar, OpenMP, and AVX2 code paths.

---

## LoRA Backward Pass

### What Gets Gradients

7 LoRA injection points per layer: q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj.

Frozen Q4 base weights: NO gradients (treated as constants in the computation graph).

### Memory for LoRA (3B model, rank=16)

| Item | Size |
|------|------|
| LoRA A+B matrices (36 layers × 7 targets) | ~72 MB |
| Adam state (m + v) | ~144 MB |
| Stored activations at injection points | ~158 MB |
| **Total trainable memory** | **~374 MB** |

### Backward Algorithm

For each LoRA injection point with stored input `x` and upstream gradient `dL/dy`:

```
h = x @ A                           [seq_len × rank]
dB = h^T @ dL/dy × (α/r)           [rank × out_dim]
dh = dL/dy @ B^T                    [seq_len × rank]
dA = x^T @ dh × (α/r)              [in_dim × rank]
```

Backward proceeds in reverse layer order. Only float32 LoRA matrices are updated.

### Loss Gradient Per Token

```
ratio = exp(logp_policy - logp_old)
clipped = clip(ratio, 1-ε, 1+ε)

if ratio×adv ≤ clipped×adv:
    dL/d(logp) = -ratio × advantage    (unclipped region)
else:
    dL/d(logp) = 0                      (clipped region, no gradient)

dL/d(logp) += -β                        (KL penalty gradient)
```

---

## Reward System

### Composable Reward Functions

```yaml
reward_funcs:
  - "exec:timeout=10,lang=python"    # weight=0.5
  - "test_cases:file=tests.json"     # weight=0.3
  - "length:max=1000"                # weight=0.2
```

Final reward = Σ(weight[i] × fn[i](completion))

### Supported Reward Types

| Type | Config | Returns | Memory |
|------|--------|---------|--------|
| `exec` | `exec:timeout=N,lang=L` | 0.0/0.5/1.0 (fail/partial/pass) | Zero |
| `format` | `format:json` or `format:yaml` | 0.0/1.0 | Zero |
| `regex` | `regex:pattern=P` | 0.0/1.0 | Zero |
| `contains` | `contains:required=a,b,c` | fraction found | Zero |
| `length` | `length:min=N,max=M` | 0.0-1.0 (linear penalty) | Zero |
| `ground_truth` | `ground_truth:field=F` | 0.0/1.0 (exact match) | Zero |
| `test_cases` | `test_cases:file=F` | fraction passed | Zero |
| `model` | `model:path=reward.gguf` | float score | ~75 MB (stream buffer) |
| `judge` | `judge:endpoint=E,model=M` | 1-10 normalized | Zero (HTTP call) |

---

## Checkpointing and Output

### LoRA Checkpoint Format (`.dclora`)

```
Header (64 bytes): magic, n_layers, rank, n_targets, dims, step, loss
Adam state: m[all_params], v[all_params]  (float32)
LoRA weights: per-layer per-target A and B matrices (float32)
```

Size for 3B model, rank=16: ~648 MB per checkpoint.

Saved every N steps (default 100). Training resumes from last checkpoint on interruption.

### Final Export

After training completes:
1. Merge LoRA into base: `W_final = dequant(W_base) + A@B × (α/r)`
2. Re-quantize merged weights to Q4_K_M
3. Write output GGUF (~1.7 GB for 3B model)
4. Return path to existing pipeline for evaluate → promote flow

---

## Integration with Existing Pipeline

### Pipeline Entry Point

In `pipeline.go`, when `backend="grpo-local"`:

```go
if cfg.Backend == "grpo-local" {
    grpoResult, err := RunGrpoLocal(ctx, GrpoLocalConfig{...})
    runResult = grpoResult
} else {
    runResult, err = Run(ctx, RunConfig{...})  // existing SFT path
}
```

### Reused Components (Unchanged)

| Component | How GRPO-local Uses It |
|-----------|----------------------|
| `store.go` | Traces still captured at runtime (unchanged) |
| `extractor.go` | Extracts prompts for GRPO dataset |
| `evaluator.go` | Post-training promotion evaluation |
| `registry.go` | Registers + promotes trained version |
| `trigger.go` | Auto-trigger fires grpo-local when algorithm=grpo |
| `llama.go` | Serves promoted merged GGUF |

### Config Extension

Added to `TrainingCategory`:

```go
GroupSize      int      // G (default 4)
MaxGenLength   int      // max tokens per completion (default 256)
ClipEpsilon    float64  // PPO clip (default 0.2)
KLCoef         float64  // β (default 0.0)
Temperature    float64  // generation temp (default 0.7)
LoRARank       int      // r (default 16)
LoRATargets    string   // "q,k,v,o,gate,up,down"
MemoryMode     string   // "auto", "minimal", "standard", "comfort"
RewardFuncs    []string // composable reward specs
ReferenceModel string   // GGUF path (empty = use policy as ref)
RewardModel    string   // GGUF path (empty = rule-based only)
```

---

## Example Configuration

```yaml
training:
  enabled: true
  backend: grpo-local
  models_dir: ~/.defenseclaw/models
  llama_server_port: 8090
  base_models:
    - id: qwen-3b
      hf_repo: Qwen/Qwen2.5-3B-Instruct
      size: 3B
  categories:
    - name: code_route
      base_model: qwen-3b
      algorithm: grpo
      min_traces: 500
      eval_threshold: 0.90
      auto_trigger: true
      group_size: 4
      max_gen_length: 256
      clip_epsilon: 0.2
      kl_coef: 0.0
      temperature: 0.7
      lora_rank: 16
      lora_targets: "q,k,v,o,gate,up,down"
      memory_mode: auto
      reward_funcs:
        - "exec:timeout=10,lang=python"
        - "format:json"
```

---

## Platform Support

| Platform | O_DIRECT | AVX2 | OpenMP | Status |
|----------|----------|------|--------|--------|
| Linux x86-64 | Yes | Yes | Yes | Full performance |
| Linux ARM64 | pread+fadvise | NEON (future) | Yes | Streaming via fallback |
| macOS x86-64 | F_NOCACHE | Yes | libomp | Near-full performance |
| macOS ARM64 | F_NOCACHE | No | libomp | Functional, no SIMD |

---

## Build System

C library built as static archive, linked via CGO:

```makefile
# internal/training/grpo_engine/Makefile
CC       ?= gcc
CFLAGS   = -O3 -std=c99 -ffp-contract=off -fPIC -fopenmp
libgrpo_stream.a: kernels.o policy.o stream.o lora.o gguf.o
	ar rcs $@ $^
```

**Build tag:** `grpo_engine` — users without a C compiler get a stub that returns an error. The existing SFT backends work without CGO.

---

## Testing Strategy

### Layer 1: C Kernel Fixtures
Per-kernel golden input/output from PyTorch reference. Tolerance: 1e-5.

### Layer 2: Go Integration Tests
Init, generate, logprobs, backward, Adam step, save/load, reward dispatch, checkpoint resume.

### Layer 3: End-to-End Oracle
Full GRPO loop on 2-layer tiny model (1 MB GGUF). Verifies reward increases over 10 steps. Runs in CI in ~10 seconds.

---

## Performance Estimates

For Qwen2.5-3B on 8-core CPU with NVMe:

| Step | Time per prompt | Notes |
|------|----------------|-------|
| Generate (G=4, 256 tokens) | ~50s | Bottleneck |
| Reward (rule-based) | <1s | In-process |
| Ref logprobs (streamed) | ~5s | 4 completions × 1.2s |
| Policy logprobs | ~3s | mmap'd, fast |
| Backward + Adam | ~5s | LoRA only |
| **Total per prompt** | **~64s** | |

**1000 prompts × 3 epochs: ~53 hours (2.2 days)**

Speed-up levers:
- G=2: halves generation time → ~35 hours
- max_len=128: halves generation → ~27 hours
- kl_coef=0: skips ref logprobs → ~48 hours
- All combined: **~15 hours (overnight)**

---

## Scope and Estimated Effort

| Component | Language | Lines (est.) | Weeks |
|-----------|----------|-------------|-------|
| `kernels.c` | C99 | ~800 | 2 |
| `policy.c` | C99 | ~600 | 1.5 |
| `stream.c` | C99 | ~400 | 1 |
| `lora.c` | C99 | ~700 | 1.5 |
| `gguf.c` | C99 | ~500 | 1 |
| `grpo_cgo.go` | Go | ~200 | 0.5 |
| `grpo_runner.go` | Go | ~400 | 1 |
| `grpo_reward.go` | Go | ~300 | 0.5 |
| `grpo_config.go` | Go | ~100 | 0.25 |
| Tests + fixtures | Go + C | ~800 | 1 |
| **Total** | | **~4800 lines** | **~6-8 weeks** |

---

## Novelty and Publication Potential

This system combines three existing ideas in a way nobody has published:
1. GRPO (DeepSeek, Feb 2024) — RL without a critic
2. QLoRA (Dettmers, May 2023) — 4-bit base + trainable adapters
3. O_DIRECT NVMe layer streaming for frozen model inference during training

The key insight is that GRPO's frozen models (reference + reward) have an identical access pattern to inference — sequential layer-by-layer forward passes with no backward pass. By streaming them from NVMe with a single reusable layer buffer, we eliminate 12+ GB of resident memory without changing the training outcome. This enables RL training on 8 GB hardware — a genuinely new capability that could be a paper contribution alongside the DefenseClaw chain-prevention paper.
