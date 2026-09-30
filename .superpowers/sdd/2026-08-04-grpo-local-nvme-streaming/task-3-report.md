## Task 3 Report: Policy Engine (mmap + Generation)

**Status:** ✅ Complete  
**Commit:** `5ebcdc76`  
**Build:** Success - libgrpo_stream.a built with no errors

---

### Implementation Summary

Replaced the stub `internal/training/grpo_engine/policy.c` with a complete Policy Engine implementation that provides mmap-based model loading and autoregressive generation with logprob capture.

### Components Implemented

#### 1. PolicyEngine Structure
- **Per-layer weight pointers:** Q, K, V, O projections + FFN gate/up/down weights (Q4_K)
- **Normalization weights:** Attention norm and FFN norm (F32)
- **Global tensors:** Token embeddings, output norm, LM head
- **KV cache:** Sized to `[max_seq_len × n_kv_heads × head_dim]`
- **Scratch buffers:** Hidden state, Q/K/V buffers, attention output, FFN intermediates, logits

#### 2. Model Loading (`policy_init`)
- Opens GGUF file and parses metadata via `gguf_open()`
- mmap's tensor data region with `MAP_SHARED` for efficient memory usage
- Resolves tensor pointers by name for all layers:
  - Attention projections: `blk.{l}.attn_{q,k,v,output}.weight`
  - FFN projections: `blk.{l}.ffn_{gate,up,down}.weight`
  - Normalization: `blk.{l}.{attn,ffn}_norm.weight`
- Handles both Q4_K quantized and F32 fallback tensors
- Allocates KV cache and scratch buffers

#### 3. Single-Token Forward Pass (`policy_forward_token`)
Implements one transformer layer with:
- **Token embedding lookup**
- **Per-layer processing:**
  - RMSNorm on hidden state
  - Q/K/V projection via `grpo_matmul_q4`
  - RoPE positional encoding on Q and K
  - KV cache update at current position
  - GQA attention via `grpo_gqa_attention`
  - Output projection
  - Residual connection
  - FFN RMSNorm
  - Gate and up projections with SiLU activation
  - Elementwise multiply: `gate * up`
  - Down projection
  - FFN residual connection
- **Final output:**
  - RMSNorm on final hidden state
  - LM head projection (Q4_K or F32) to vocabulary logits

#### 4. Autoregressive Generation (`policy_generate`)
- **Prefill phase:** Processes all prompt tokens sequentially
- **Generation loop:**
  - Computes softmax probabilities from logits
  - Applies temperature scaling
  - Samples next token via `grpo_top_p_sample`
  - Captures log-probability of sampled token
  - Feeds token back for next iteration
  - Stops on EOS token (ID=2) or max_len
- Returns total generated tokens

#### 5. Teacher-Forced Logprobs (`policy_logprobs`)
- Processes full token sequence without sampling
- Computes per-token logprobs for next token prediction
- Used for computing policy/reference logprobs during training

#### 6. Public Interface Functions
- `grpo_policy_init()` - Initialize policy engine from GGUF file
- `grpo_policy_free()` - Clean up resources
- `grpo_policy_generate_internal()` - Autoregressive generation
- `grpo_policy_logprobs_internal()` - Teacher-forced logprobs

These functions are ready for integration with the top-level `grpo_init()`, `grpo_generate()`, and `grpo_policy_logprobs()` API in a future task.

---

### Technical Details

**Memory Management:**
- Uses `mmap()` with `MAP_SHARED` for zero-copy tensor access
- All scratch buffers allocated once during init
- KV cache sized to max_seq_len (no dynamic reallocation)

**Numerical Stability:**
- Compiled with `-ffp-contract=off` (no FMA fusion)
- Uses double-precision accumulators in matmul kernels
- Log-probability computation with epsilon guard (`1e-10f`)

**Platform Compatibility:**
- Uses `_POSIX_C_SOURCE 200809L` for mmap/pread
- Standard C99 with no GNU extensions
- Compiles on Linux and macOS

**Kernel Integration:**
Uses all 8 math kernels from `kernels.c`:
1. `grpo_rmsnorm` - RMS normalization
2. `grpo_matmul_f32` - F32 matrix multiplication
3. `grpo_matmul_q4` - Q4_K dequantization + matmul
4. `grpo_silu` - SiLU activation
5. `grpo_rope` - Rotary positional encoding
6. `grpo_softmax` - Softmax normalization
7. `grpo_gqa_attention` - Grouped query attention
8. `grpo_top_p_sample` - Top-p (nucleus) sampling

---

### Build Output

```
make -C internal/training/grpo_engine clean all
rm -f *.o *.a test_runner
cc -O3 -std=c99 -ffp-contract=off -fPIC -Wall -Wextra -c gguf.c -o gguf.o
cc -O3 -std=c99 -ffp-contract=off -fPIC -Wall -Wextra -c kernels.c -o kernels.o
cc -O3 -std=c99 -ffp-contract=off -fPIC -Wall -Wextra -c policy.c -o policy.o
cc -O3 -std=c99 -ffp-contract=off -fPIC -Wall -Wextra -c stream.c -o stream.o
cc -O3 -std=c99 -ffp-contract=off -fPIC -Wall -Wextra -c lora.c -o lora.o
ar rcs libgrpo_stream.a gguf.o kernels.o policy.o stream.o lora.o
```

**Result:** ✅ Clean build, no errors, 1 pre-existing warning in gguf.c

---

### Next Steps

The policy engine is complete and ready for integration. The next task will wire these internal functions into the top-level GRPO API:
- `grpo_init()` will call `grpo_policy_init()`
- `grpo_generate()` will call `grpo_policy_generate_internal()`
- `grpo_policy_logprobs()` will call `grpo_policy_logprobs_internal()`

---

**Deliverables:**
- ✅ `internal/training/grpo_engine/policy.c` - 416 lines of production code
- ✅ Builds into `libgrpo_stream.a`
- ✅ Commit: `5ebcdc76` - feat(training): implement policy engine with mmap and autoregressive generation
- ✅ Report: `.superpowers/sdd/2026-08-04-grpo-local-nvme-streaming/task-3-report.md`

**Date:** 2026-08-04  
**Author:** Claude Sonnet 4.5
