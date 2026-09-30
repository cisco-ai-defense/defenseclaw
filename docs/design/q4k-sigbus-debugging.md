# Q4_K SIGBUS Debugging Guide

## Problem

On macOS ARM (Apple Silicon M2 Max), the `grpo_matmul_q4` function crashes with SIGBUS (exit 139) when compiled at any optimization level above `-O0`. This blocks Qwen3 models which use Q4_K format for projection weights.

## Root Cause (Confirmed)

Clang's auto-vectorizer at `-O1`+ generates aligned NEON loads (`ldr q0, [x8]`) from pointers into `mmap(MAP_SHARED)` memory. macOS ARM's VM subsystem cannot handle these vectorized accesses across page boundaries on mmap'd files, resulting in SIGBUS.

## What Works vs What Doesn't

| Config | Result | Why |
|--------|--------|-----|
| Q4_K matmul, `-O0` | ✓ Works | No auto-vectorization, scalar byte loads only |
| Q4_K matmul, `-O1` | ✗ SIGBUS | Clang strength-reduces loop into aligned loads |
| Q4_K matmul, `-O2`/`-O3` | ✗ SIGBUS | Same + more aggressive vectorization |
| Q8_0 matmul, `-O3` | ✓ Works | Has explicit NEON intrinsics (no auto-vec needed) |
| Q5_0 matmul, `-O3` | ✓ Works | Has explicit NEON intrinsics |
| Q6_K matmul, `-O3` | ✓ Works | Has explicit NEON intrinsics |
| Q4_K standalone test, `-O3` | ✓ Works | Inlining context differs from policy_forward_token |
| Q4_K inside policy_forward_token, any opt | ✗ SIGBUS | Optimizer context changes pointer access patterns |
| Linking libomp (even unused) | ✗ SIGBUS | libomp initialization corrupts signal handlers |

## Key Evidence

1. ASAN found NO memory errors (ran for 3 minutes at -O0 speed)
2. All tensor offsets are mathematically correct and in bounds
3. Direct byte reads from mmap'd Q4_K data succeed (test_offset.c)
4. Standalone `grpo_matmul_q4(out, x, q_data, 4096, 4096)` works at -O3
5. Same call from INSIDE `policy_forward_token` crashes at -O1+
6. Pure C binary at `-O0` generates valid tokens (315s for 2 tokens)

## Fix Approaches (Ranked by Likelihood of Success)

### Approach 1: `__attribute__((optnone))` on Q4_K only
```c
__attribute__((optnone))
void grpo_matmul_q4(float *out, const float *x, const void *W_packed, int rows, int in_dim) {
    // Same scalar code, but compiler won't optimize it
}
```
**Pros:** Simplest, guaranteed to work (O0 proven working), rest of file stays at O3.
**Cons:** Slow (~150s/token). But faster than current -O0 whole-file (315s/token) because other functions stay fast.
**Estimated speed:** ~80-100s/token (Q4_K scalar, everything else optimized).

### Approach 2: Copy mmap'd data to heap before matmul
```c
void grpo_matmul_q4(...) {
    // Copy the relevant weight slice to heap (aligned, safe for NEON)
    size_t row_bytes = blocks_per_row * Q4K_BLOCK_BYTES;
    uint8_t *W_local = aligned_alloc(64, row_bytes);  // heap = safe for NEON
    
    for (int r = 0; r < rows; r++) {
        memcpy(W_local, W + r * row_bytes, row_bytes);  // copy from mmap to heap
        // Now NEON can safely access W_local
        // ... NEON dequant + FMA ...
    }
    free(W_local);
}
```
**Pros:** Full NEON speed on Q4_K data, avoids mmap issue entirely.
**Cons:** Extra memcpy per row (2304 bytes × 4096 rows = 9.4 MB copied per matmul). At memory bandwidth this is ~2ms overhead — negligible vs compute.
**Estimated speed:** ~5-8 sec/token (same as Q8_0 NEON speed).

### Approach 3: `madvise(MADV_WILLNEED)` to pre-fault pages
```c
// Before the matmul loop, pre-fault all pages for this tensor
madvise((void*)row_data_start, total_tensor_bytes, MADV_WILLNEED);
```
**Pros:** Zero copy, pages become resident, NEON loads may succeed.
**Cons:** Might not fix it — SIGBUS could be from alignment, not page faults. Unproven.

### Approach 4: Use Q8_0 quantized Qwen3 GGUF
Download Qwen3-8B in Q8_0 format (8 GB instead of 4.9 GB). All tensors become Q8_0 which our NEON kernel handles perfectly.
**Pros:** Zero code changes, full speed, proven Q8_0 NEON kernel.
**Cons:** 60% larger file (8 GB vs 4.9 GB), might not exist on HuggingFace.

## Recommended Fix Order

1. **Try Approach 1 first** (5 min, guaranteed to work, proves end-to-end)
2. **Then implement Approach 2** (30 min, gives full NEON speed)
3. Approach 3 as experiment if 2 doesn't satisfy
4. Approach 4 as user-facing workaround

## Current State

- Branch: `feature/semantic-router-interface`
- Latest commit: `78f6a984` (kernels.c compiled at -O0)
- Makefile has `kernels.o` rule forcing `-O0`
- NEON Q4_K code exists but guarded by `#if defined(__ARM_NEON) && defined(GRPO_Q4K_NEON)` (never defined)
- All other kernels (Q8_0, Q5_0, Q6_K, F32) have working NEON at -O3

## Files to Modify

- `internal/training/grpo_engine/kernels.c` — the Q4_K matmul function
- `internal/training/grpo_engine/Makefile` — remove -O0 override once fixed

## Test Command

```bash
# Pure C test (fastest iteration):
cd internal/training/grpo_engine
make clean all
cc -O1 -std=c99 -ffp-contract=off -I. /tmp/test_qwen3_omp.c /tmp/omp_stub.o -L. -lgrpo_stream -lm -o /tmp/test_q4k
/tmp/test_q4k

# Expected output when fixed:
# Generated 2 tokens
#   Wall time: ~10 sec (with NEON)
#   token[0] = 105935
```

## Model file location
```
/tmp/qwen3-8b.gguf → symlink to ~/.ollama/models/blobs/sha256-a3de86...
```
