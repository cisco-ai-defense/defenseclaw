# GRPO Engine Enhancements — Design Spec

**Date:** 2026-08-05
**Scope:** 5 sequential tasks to bring the GRPO-Local C engine from prototype to publication-ready
**Target venue:** MLSys / OSDI (systems paper, 10-12 pages)

---

## Task 1: C-Native BPE Tokenizer

### Problem

`grpo_runner.go:tokensToString()` is a placeholder that returns token IDs as strings. Reward functions (`exec`, `format`, `regex`, `contains`, `ground_truth`) receive `"[1,2,3]"` instead of decoded text. The entire reward pipeline is non-functional on real models.

### Design

**New files:**
- `grpo_engine/tokenizer.c` (~400-500 lines)
- `grpo_engine/tokenizer.h` (public API)
- `grpo_engine/testdata/tokenizer_qwen3.json` (test fixture, stripped to first 1000 merges)

**Public API (added to grpo.h):**

```c
typedef struct GrpoTokenizer GrpoTokenizer;

/* Load a HuggingFace tokenizer.json file */
GrpoTokenizer *grpo_tokenizer_load(const char *path);
void            grpo_tokenizer_free(GrpoTokenizer *tok);

/* Encode text to token IDs. Returns number of tokens written. */
int grpo_tokenizer_encode(const GrpoTokenizer *tok, const char *text, int text_len,
                          int *output_ids, int max_tokens);

/* Decode token IDs to text. Returns number of bytes written (null-terminated). */
int grpo_tokenizer_decode(const GrpoTokenizer *tok, const int *ids, int n_ids,
                          char *output_buf, int buf_size);

/* Vocabulary size */
int grpo_tokenizer_vocab_size(const GrpoTokenizer *tok);
```

**Internal data structures:**

```c
struct GrpoTokenizer {
    /* Vocabulary: ID → byte sequence */
    char    **vocab;          /* vocab[token_id] = UTF-8 string */
    int      *vocab_len;      /* byte length of each vocab entry */
    int       vocab_size;

    /* Reverse lookup: byte sequence → ID (hash table) */
    struct TokenHashEntry *hash_table;
    int                    hash_capacity;

    /* BPE merge rules: ordered pairs */
    struct MergeRule *merges;   /* merges[priority] = {left_id, right_id, result_id} */
    int               n_merges;

    /* Special tokens */
    int bos_id;
    int eos_id;
    int pad_id;
};

struct MergeRule {
    int left;
    int right;
    int result;
};
```

**Encoding algorithm (byte-level BPE):**

1. Convert input text to byte sequence
2. Initialize token list: one token per byte (byte IDs 0-255 always in vocab)
3. Repeatedly find the highest-priority merge pair in the token list and merge
4. Stop when no more merges apply
5. Return final token ID sequence

**Parsing tokenizer.json:**

The file has this structure (relevant fields only):
```json
{
  "model": {
    "type": "BPE",
    "vocab": {"<token>": id, ...},
    "merges": ["token_a token_b", ...]
  },
  "added_tokens": [{"id": N, "content": "<|special|>", "special": true}],
  "decoder": {"type": "ByteLevel"}
}
```

We parse:
- `model.vocab` → build forward (string→id) and reverse (id→string) tables
- `model.merges` → build ordered merge priority list
- `added_tokens` → identify BOS/EOS/PAD IDs

JSON parsing: minimal inline parser (no dependency). Only need to handle string keys, integer values, string arrays, and nested objects. ~150 lines for a purpose-built parser that handles this specific schema.

**Integration with GrpoConfig:**

```c
typedef struct {
    const char *policy_gguf;
    const char *reference_gguf;
    const char *reward_gguf;
    const char *tokenizer_path;    /* NEW: path to tokenizer.json */
    /* ... rest unchanged ... */
} GrpoConfig;
```

**Integration with Go layer:**

```go
// grpo_runner.go — replace tokensToString
func (e *GrpoEngine) Detokenize(tokens []int) string {
    // CGO call to grpo_tokenizer_decode
}
```

The `RunGrpoLocal` function changes from:
```go
completionStr := tokensToString(completionTokens[g])
```
to:
```go
completionStr := engine.Detokenize(completionTokens[g])
```

**Testing:**
- Unit test: encode("Hello, world!") with Qwen3 tokenizer.json → known IDs
- Round-trip test: decode(encode(text)) == text for ASCII and UTF-8
- Reward integration test: encode a Python snippet, decode, pass to `rewardExec`

---

## Task 2: Benchmark Harness

### Problem

No empirical evidence that the C engine produces equivalent quality to TRL+Unsloth. Without benchmarks, the paper has no evaluation section.

### Design

**New directory structure:**
```
benchmarks/grpo/
├── README.md              # How to run benchmarks
├── run_all.py             # Master orchestrator
├── datasets/
│   ├── gsm8k_grpo.jsonl   # GSM8K formatted for GRPO (prompt + ground_truth)
│   └── humaneval_grpo.jsonl # HumanEval formatted for GRPO
├── baselines/
│   ├── trl_grpo.py        # TRL GRPOTrainer baseline
│   └── unsloth_grpo.py    # Unsloth GRPO baseline
├── grpo_local/
│   ├── prepare_dataset.py # Convert datasets to engine format (tokenized JSONL)
│   └── run_engine.py      # Invoke Go binary, collect metrics
├── evaluate/
│   ├── gsm8k_eval.py      # Evaluate GSM8K accuracy (extract boxed answers)
│   └── humaneval_eval.py  # Evaluate HumanEval pass@1 (sandbox execution)
└── results/
    └── .gitkeep
```

**Benchmark protocol:**

1. **Model:** Qwen3-1.7B (small enough for both CPU and GPU within reasonable time)
2. **Dataset:** 
   - GSM8K: 500 train prompts (GRPO), 200 eval prompts (accuracy measurement)
   - HumanEval: 164 problems (eval only after training on code prompts)
3. **Training config (identical across backends):**
   - Algorithm: GRPO
   - LoRA rank: 16, alpha: 16, targets: q,k,v,o,gate,up,down
   - Group size: 4
   - Max steps: 200 (enough to show convergence direction)
   - Learning rate: 1e-4
   - Clip epsilon: 0.2
   - KL coefficient: 0.0 (beta=0 for fair comparison, since TRL defaults to this)
4. **Reward functions:**
   - GSM8K: `ground_truth` (exact match on boxed answer)
   - HumanEval: `exec` (run code, check pass/fail)

**Metrics collected:**

| Metric | How measured |
|--------|-------------|
| Final accuracy (pass@1) | Run eval set through trained model, count correct |
| Reward curve | Mean reward per step (logged every 5 steps) |
| Wall-clock time | Total training time (seconds) |
| Peak RSS | `/proc/self/status` VmPeak (Linux) or `resource.getrusage` |
| Tokens/second (training) | Total tokens generated / total generation time |
| Peak VRAM (GPU baseline) | `nvidia-smi` peak memory |

**Output format:**

```json
{
  "system": "grpo-local",
  "model": "Qwen3-1.7B",
  "dataset": "gsm8k",
  "steps": 200,
  "accuracy_before": 0.12,
  "accuracy_after": 0.24,
  "reward_curve": [0.1, 0.15, 0.18, ...],
  "wall_clock_seconds": 3600,
  "peak_rss_mb": 4200,
  "peak_vram_mb": null,
  "tokens_per_second": 12.5
}
```

**Comparison chart generation:**

`run_all.py --plot` produces:
- Reward curve overlay (C engine vs TRL vs Unsloth)
- Bar chart: accuracy improvement, memory usage, training time
- Table: final numbers for the paper

---

## Task 3: O_DIRECT vs mmap Instrumentation

### Problem

We claim O_DIRECT streaming is better than mmap for the reference model, but have no measurements. The paper needs concrete numbers.

### Design

**Changes to `stream.c`:**

Add timing instrumentation (compile-time `#ifdef GRPO_BENCH_IO`):

```c
typedef struct {
    uint64_t bytes_read;
    uint64_t read_calls;
    uint64_t read_ns;         /* nanoseconds in pread() */
    uint64_t compute_ns;      /* nanoseconds in matmul */
    uint64_t peak_rss_kb;     /* peak resident set size */
    int      num_layers;
    int      use_direct_io;   /* 1=O_DIRECT, 0=mmap */
} StreamBenchStats;
```

**New benchmark function:**

```c
/* Runs the same reference logprob computation twice:
 * once with O_DIRECT layer streaming, once with full mmap.
 * Returns comparison stats. */
typedef struct {
    StreamBenchStats direct;
    StreamBenchStats mmap;
    float throughput_ratio;   /* direct/mmap */
    int64_t rss_savings_kb;   /* mmap_peak - direct_peak */
} StreamComparison;

StreamComparison stream_benchmark_comparison(const char *gguf_path,
                                            const int *tokens, int len);
```

**New mmap-mode StreamEngine variant:**

Currently `stream.c` always uses O_DIRECT + pread per layer. Add a second mode:
- `stream_open_mmap(path)` — mmap the entire file, then forward pass reads from mmap'd pointers
- This represents the "naive" approach (what you'd do without our optimization)
- Measures: RSS grows to full model size vs our O_DIRECT (one layer buffer)

**Go integration:**

```go
// New CLI command: defenseclaw grpo benchmark-io --model path/to/model.gguf
func benchmarkIO(modelPath string) {
    // Calls stream_benchmark_comparison via CGO
    // Prints table:
    // Mode        | Throughput | Peak RSS  | Time/layer
    // O_DIRECT    | 3.2 GB/s   | 52 MB     | 16ms
    // mmap        | 2.8 GB/s   | 4200 MB   | 14ms
    // Savings     | -12%       | 98.8%     | +14%
}
```

**What we're measuring (for the paper):**
1. Peak RSS: O_DIRECT should use ~50MB (one layer buffer) vs mmap using full model size (~2-4GB)
2. Throughput: O_DIRECT bypasses page cache (better on NVMe), mmap may benefit from OS readahead
3. Time-to-first-logprob: O_DIRECT has no startup cost, mmap has lazy fault cost
4. Steady-state per-layer time: should be similar once both are warm
5. Effect of memory pressure: when system RAM is constrained, mmap thrashes while O_DIRECT is stable

---

## Task 4: io_uring Support

### Problem

Current `stream.c` uses synchronous `pread()` — the CPU blocks during each layer read. With io_uring, we can overlap I/O for layer N+1 with computation on layer N.

### Design

**New file:** `grpo_engine/uring.c` (~200-250 lines)

**Architecture:**

```
Layer 0: [=== pread ===][=== compute ===]
Layer 1:                 [=== pread ===][=== compute ===]
Layer 2:                                 [=== pread ===][=== compute ===]

With io_uring (overlap):
Layer 0: [=== pread ===][=== compute ===]
Layer 1:                [=== pread ===  ][=== compute ===]
Layer 2:                                 [=== pread ===  ][=== compute ===]
                         ^ submitted while layer 0 computes
```

**API:**

```c
/* uring.h — Linux io_uring I/O backend */
#ifndef GRPO_URING_H
#define GRPO_URING_H

#ifdef __linux__
#include <stddef.h>
#include <stdint.h>

typedef struct UringReader UringReader;

/* Create a reader with a ring of depth entries (typically 2) */
UringReader *uring_open(const char *path, int depth, size_t buf_align);
void         uring_close(UringReader *ur);

/* Submit an async read. Returns immediately. */
int uring_submit_read(UringReader *ur, void *buf, size_t len, off_t offset);

/* Wait for the oldest submitted read to complete. Blocks until done. */
int uring_wait_completion(UringReader *ur);

/* Check if io_uring is available at runtime */
int uring_available(void);

#endif /* __linux__ */
#endif /* GRPO_URING_H */
```

**Integration with stream.c:**

```c
/* Modified layer processing loop (pseudo-code): */

// Submit read for layer 0
uring_submit_read(ur, buf_A, layer_info[0].total_size, layer_info[0].file_offset);

for (int L = 0; L < n_layers; L++) {
    // Wait for current layer's read to complete
    uring_wait_completion(ur);

    // Submit next layer's read (into alternate buffer) while we compute
    if (L + 1 < n_layers) {
        void *next_buf = (L % 2 == 0) ? buf_B : buf_A;
        uring_submit_read(ur, next_buf, layer_info[L+1].total_size, layer_info[L+1].file_offset);
    }

    // Compute on current layer (overlaps with next read)
    void *cur_buf = (L % 2 == 0) ? buf_A : buf_B;
    compute_layer(cur_buf, L, ...);
}
```

**Double-buffering:** Two aligned buffers (A and B), alternating. While computing on A, io_uring fills B with the next layer.

**Fallback:** On macOS or older Linux, silently falls back to synchronous pread (current behavior). Runtime detection via `__NR_io_uring_setup` syscall probe.

**Build integration:**

```makefile
# Detect io_uring availability
URING_OK := $(shell echo '#include <liburing.h>' | $(CC) -x c - -c -o /dev/null 2>/dev/null && echo 1)
ifeq ($(URING_OK),1)
  SRCS += uring.c
  CFLAGS += -DGRPO_HAS_URING
  LDFLAGS += -luring
endif
```

**Expected speedup:** If I/O is 40-60% of wall time (as measured in kimi-k3-in-c benchmarks), and we can overlap ~80% of it with compute, expected speedup is 20-35% on the reference model forward pass.

---

## Task 5: Research Paper

### Problem

The novelty exists but is undocumented. Without a paper, the innovations have no academic credit and no external validation.

### Design

**Paper structure (MLSys format, 10-12 pages):**

```
Title: "StreamGRPO: NVMe-Streaming Reinforcement Learning for Language Models
        on Commodity Hardware"

Authors: [Nikhil Ghodki, et al.] — Cisco AI Defense

Abstract (200 words):
  Problem: GRPO requires 2× model memory (policy + reference). GPU-dependent.
  Solution: Pure-C engine that streams reference from NVMe, KV-snapshot for
  group generation, LoRA-only backward on GGUF models.
  Result: [benchmarks from Task 2 and Task 3]
```

**Sections:**

1. **Introduction** (1.5 pages)
   - GRPO background (3 sentences)
   - Memory wall problem: policy + reference + optimizer = 3× model size
   - Our contribution: 3 systems techniques that reduce to 1.2× model size on CPU

2. **Background** (1 page)
   - GRPO algorithm (equations, cite DeepSeek 2024)
   - LoRA (cite Hu et al. 2021)
   - GGUF format (cite llama.cpp)
   - Colibri's O_DIRECT insight applied to inference (cite JustVugg 2026)

3. **System Design** (3 pages)
   - 3.1 Architecture overview (figure: Go orchestrator + C engine)
   - 3.2 NVMe-streaming reference model (O_DIRECT, one-layer buffer)
   - 3.3 KV-cache snapshot/restore for group generation
   - 3.4 LoRA-only backward through quantized weights
   - 3.5 GGUF-native training pipeline (no PyTorch dependency)

4. **Implementation** (2 pages)
   - 4.1 C engine internals (3097 lines, zero dependencies)
   - 4.2 Quantized forward pass (Q4/Q5/Q6/Q8 matmul kernels)
   - 4.3 io_uring double-buffered layer prefetch
   - 4.4 BPE tokenizer for reward evaluation
   - 4.5 Composable reward dispatch (format, exec, ground_truth)

5. **Evaluation** (3 pages)
   - 5.1 Experimental setup (hardware, models, datasets)
   - 5.2 Quality parity: GSM8K/HumanEval accuracy vs TRL+Unsloth
   - 5.3 Memory reduction: O_DIRECT streaming vs mmap baseline
   - 5.4 I/O performance: io_uring vs pread vs mmap
   - 5.5 End-to-end: wall-clock time, peak RSS, tokens/second
   - 5.6 Ablation: KV snapshot savings, LoRA rank sweep

6. **Related Work** (1 page)
   - TRL, OpenRLHF, veRL (GPU-native GRPO)
   - Unsloth (memory-efficient GPU training)
   - ZeRO-Infinity (NVMe offload for general training)
   - Colibri, kimi-k3-in-c (NVMe streaming for inference)
   - GPG, GTPO (algorithmic reference elimination)
   - llm.c (C-native pretraining)
   - QeRL (quantized RL)

7. **Limitations & Future Work** (0.5 page)
   - Speed: CPU-only is 50-100× slower than GPU
   - Tokenizer: currently requires separate tokenizer.json
   - Multi-GPU: not supported (single-machine focus)
   - Future: speculative PILOT-style prefetch for reference layers

8. **Conclusion** (0.5 page)

**Paper file:** `docs/papers/streamgrpo/`
- `paper.tex` (LaTeX, MLSys template)
- `figures/` (architecture diagram, benchmark charts, memory comparison)
- `tables/` (benchmark results)

**Key claims the paper must prove:**
1. Quality parity with TRL+Unsloth on GSM8K (within 2% accuracy)
2. 80%+ memory reduction for reference model (50MB vs 2-4GB)
3. Runs on 8GB RAM laptop (no GPU required)
4. First pure-C GRPO engine (novel systems contribution)

---

## Execution Order & Dependencies

```
Task 1 (Tokenizer) ──┐
                      ├──→ Task 2 (Benchmarks) ──→ Task 5 (Paper)
Task 3 (IO Bench) ───┘                              ↑
                                                     │
Task 4 (io_uring) ───────────────────────────────────┘
```

- Task 1 unblocks Task 2 (benchmarks need working rewards)
- Task 3 can run in parallel with Task 1 (independent)
- Task 4 can run in parallel with Task 2 (independent)
- Task 5 requires results from Tasks 2, 3, and 4

---

## Success Criteria

| Task | Done when |
|------|-----------|
| 1. Tokenizer | `make test` passes encode/decode round-trip; rewards produce real scores |
| 2. Benchmark | JSON results file shows accuracy delta; comparison chart generated |
| 3. IO Bench | Table printed showing RSS savings and throughput comparison |
| 4. io_uring | `stream.c` uses io_uring on Linux; benchmark shows speedup |
| 5. Paper | Complete LaTeX draft with all figures and tables filled in |

---

## Out of Scope

- Multi-GPU support
- Distributed training
- Supporting non-BPE tokenizers (SentencePiece unigram)
- Training models larger than 8B (out of scope for CPU-only claim)
- Submitting the paper (separate process)
