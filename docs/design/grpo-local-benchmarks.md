# GRPO-Local Performance Benchmarks

## Test Environment

- **CPU**: Apple M2 Pro (8 performance + 4 efficiency cores)
- **RAM**: 16 GB unified memory
- **Storage**: Internal NVMe SSD (sequential read ~5 GB/s)
- **OS**: macOS 14.x (F_NOCACHE mode, no O_DIRECT)

## Tiny Model Benchmarks (Structural Verification)

**Model**: `tiny_model.gguf` (2 layers, hidden=64, vocab=256, 116 KB)

| Operation | Time | Notes |
|-----------|------|-------|
| Engine init (grpo_init) | <1 ms | mmap + LoRA alloc |
| Generate (G=2, max_len=8) | <1 ms | 16 tokens total |
| Reward dispatch (2 rule-based) | <1 ms | In-process |
| Policy logprobs (G=2) | <1 ms | Teacher-forced |
| Backward + Adam step | <1 ms | LoRA rank=4 |
| Full E2E (5 steps) | **1.5 ms** | Complete GRPO loop |
| Checkpoint save | <1 ms | 1 KB file |
| GGUF merge + export | <1 ms | Tiny model |

**Verdict**: The engine infrastructure has negligible overhead. All latency on real models comes from matrix multiplications.

## Projected Performance (Real Models)

Based on the tiny model measurements and known matmul scaling characteristics:

### Per-Token Generation Latency (Single Token)

| Model | Hidden | Layers | Q4 Size | ms/token (est.) |
|-------|--------|--------|---------|-----------------|
| Qwen2.5-0.5B | 896 | 24 | 350 MB | ~15 ms |
| Qwen2.5-1.5B | 1536 | 28 | 900 MB | ~35 ms |
| Qwen2.5-3B | 2048 | 36 | 1.7 GB | ~55 ms |
| Llama-3.2-3B | 3072 | 28 | 1.8 GB | ~60 ms |
| Qwen2.5-7B | 3584 | 28 | 4.0 GB | ~120 ms |
| Llama-3.1-8B | 4096 | 32 | 4.5 GB | ~140 ms |
| Qwen2.5-14B | 5120 | 40 | 8.0 GB | ~230 ms |
| Qwen2.5-32B | 5120 | 64 | 18 GB | ~400 ms |

*Estimates based on: Q4 matmul throughput ~2 GFLOP/s per core, 8 cores, with memory bandwidth factored for mmap'd access.*

### Per-Prompt GRPO Time (G=4, max_len=256)

| Model | Generation | Reward | Ref Logprobs | Policy LP | Backward | **Total** |
|-------|-----------|--------|--------------|-----------|----------|-----------|
| Qwen2.5-0.5B | 15s | <1s | 2s (stream) | 1s | 2s | **~20s** |
| Qwen2.5-1.5B | 36s | <1s | 3s (stream) | 2s | 3s | **~44s** |
| Qwen2.5-3B | 56s | <1s | 5s (stream) | 3s | 5s | **~69s** |
| Qwen2.5-7B | 122s | <1s | 8s (stream) | 5s | 8s | **~143s** |
| Llama-3.1-8B | 143s | <1s | 10s (stream) | 6s | 10s | **~169s** |

### Full Training Run (1000 prompts × 3 epochs)

| Model | Per Prompt | Total (3 epochs) | Fits 8 GB? | Fits 16 GB? |
|-------|-----------|------------------|-----------|-------------|
| Qwen2.5-0.5B | ~20s | **17 hours** | ✓ | ✓ |
| Qwen2.5-1.5B | ~44s | **37 hours** | ✓ | ✓ |
| Qwen2.5-3B | ~69s | **57 hours (2.4 days)** | ✓ | ✓ |
| Qwen2.5-7B | ~143s | **119 hours (5 days)** | Streaming | ✓ |
| Llama-3.1-8B | ~169s | **141 hours (6 days)** | Streaming | ✓ |

### With Speed-Up Tricks

| Configuration | Qwen2.5-3B Time | Notes |
|--------------|----------------|-------|
| Baseline (G=4, len=256, 3 epochs) | 57 hours | Full spec |
| G=2 (halve generation) | 32 hours | Noisier advantages |
| G=4, len=128 (halve gen length) | 31 hours | Shorter outputs |
| G=2, len=128, 1 epoch | **8 hours** | Quick iteration |
| G=4, len=256, β=0 (no ref) | 48 hours | Skip ref streaming |
| All tricks (G=2, len=128, 1 epoch, β=0) | **7 hours** | Overnight |

## Memory Usage

### Minimal Mode (8 GB target)

| Component | Qwen2.5-3B | Notes |
|-----------|-----------|-------|
| Policy (mmap, Q4) | 1.7 GB | Resident via mmap |
| LoRA adapters (float32) | 72 MB | r=16, 7 targets × 36 layers |
| Adam state (m + v) | 144 MB | 2× LoRA size |
| KV cache | 32 MB | 2048 positions × 4 heads × 128 dim × 2 (K+V) |
| Activations stored | 158 MB | At LoRA injection points |
| Stream buffer (ref) | 75 MB | One layer at a time |
| Stream buffer (reward) | 75 MB | One layer at a time |
| Generation scratch | 50 MB | Logits + hidden state |
| **Total** | **~2.3 GB** | Well within 8 GB |

### Comfort Mode (16+ GB)

| Component | Qwen2.5-3B | Notes |
|-----------|-----------|-------|
| Policy (mmap, Q4) | 1.7 GB | Resident |
| Reference (mmap, Q4) | 1.7 GB | Resident (no streaming) |
| Reward (mmap, Q4) | 1.7 GB | Resident (no streaming) |
| LoRA + Adam + activations | 374 MB | Same as minimal |
| KV cache + scratch | 82 MB | Same |
| **Total** | **~5.6 GB** | Fast — no NVMe reads |

## I/O Throughput (Streaming Mode)

| Metric | Value |
|--------|-------|
| Layer size (3B model, Q4) | ~47 MB per layer |
| Layers per forward pass | 36 |
| Total I/O per teacher-forced forward | 1.7 GB |
| NVMe sequential read (M2 SSD) | ~5 GB/s |
| Time per streamed forward pass | ~340 ms |
| Per completion (4 completions × ref) | ~1.4 s |

## Comparison: GRPO-Local vs. Standard TRL (GPU)

| Metric | GRPO-Local (CPU, 8 GB) | TRL GRPOTrainer (1× A100) |
|--------|------------------------|---------------------------|
| Hardware cost | $0 (existing laptop) | ~$2/hour cloud GPU |
| Memory required | 2.3 GB | 40+ GB (GPU VRAM) |
| Training time (3B, 1000×3) | ~57 hours | ~2 hours |
| Cost per run | $0 | ~$4 (2h × $2/h) |
| 10 experimental runs | $0 | ~$40 |
| Overnight runs/week | 1 | limited by budget |
| Setup complexity | `defenseclaw setup training --enable` | CUDA, torch, vLLM, multi-GPU config |

**When GRPO-Local wins**: Rapid experimentation, no GPU access, privacy-sensitive data, always-on background training, edge deployment.

**When GPU wins**: Time-critical training, large models (>14B), large datasets, research requiring many runs.

## How to Run Benchmarks

```bash
# Build C library
make -C internal/training/grpo_engine clean all test

# Run Go E2E (tiny model, ~1ms)
CGO_ENABLED=1 go test -tags grpo_engine github.com/defenseclaw/defenseclaw/internal/training -run TestGrpoRunnerE2E -v

# Run with real model (download first)
huggingface-cli download Qwen/Qwen2.5-3B-Instruct-GGUF qwen2.5-3b-instruct-q4_k_m.gguf --local-dir ~/.defenseclaw/models/

# Manual training run
defenseclaw training run code_route --backend grpo-local --dry-run
defenseclaw training run code_route --backend grpo-local
```
