## Task 3: Policy Engine (mmap + Generation)

**Files:**
- Modify: `internal/training/grpo_engine/policy.c` (replace stub)

**Interfaces:**
- Consumes: `GgufFile` from Task 1, kernels from Task 2
- Produces: `policy_init()`, `policy_generate()`, `policy_logprobs()` (internal functions called by `grpo_init`/`grpo_generate`/`grpo_policy_logprobs`)

- [ ] **Step 1: Implement model loading via mmap + KV cache allocation**

The policy engine opens the GGUF file, mmap's the tensor data region, and pre-computes pointers to each layer's weight tensors. It allocates a KV cache sized to `max_seq_len`.

```c
/* policy.c — mmap'd policy forward pass and autoregressive generation */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "grpo.h"

typedef struct {
    /* Per-layer weight pointers (into mmap region) */
    const void *q_weight;   /* Q4_K packed */
    const void *k_weight;
    const void *v_weight;
    const void *o_weight;
    const void *gate_weight;
    const void *up_weight;
    const void *down_weight;
    const float *attn_norm; /* f32 norm weights */
    const float *ffn_norm;
} PolicyLayer;

typedef struct {
    GgufFile     gf;
    void        *mmap_base;
    size_t       mmap_size;
    PolicyLayer *layers;
    const float *embed;        /* token embedding table */
    const float *output_norm;  /* final RMS norm */
    const void  *output_weight; /* lm_head (may be Q4 or f32) */

    /* KV cache: [max_seq_len × n_kv_heads × head_dim] */
    float       *k_cache;
    float       *v_cache;
    int          max_seq_len;
    int          seq_pos;      /* current position in cache */

    /* Scratch buffers */
    float       *hidden;       /* [hidden_dim] */
    float       *logits;       /* [vocab_size] */
} PolicyEngine;
```

- [ ] **Step 2: Implement single-token forward pass**

A function that computes one transformer layer given the hidden state, using the mmap'd Q4 weights and the KV cache for attention.

- [ ] **Step 3: Implement `policy_generate` (autoregressive loop)**

```c
int policy_generate(PolicyEngine *pe, const int *prompt, int prompt_len,
                    int *output, int max_len, float *logprobs_out,
                    float temp, float top_p, unsigned int *rng) {
    pe->seq_pos = 0;
    int total_gen = 0;

    /* Prefill: process all prompt tokens */
    for (int i = 0; i < prompt_len; i++) {
        policy_forward_token(pe, prompt[i], pe->seq_pos);
        pe->seq_pos++;
    }

    /* Generate: sample and feed back */
    for (int i = 0; i < max_len; i++) {
        /* logits are in pe->logits after forward */
        /* Capture logprob of sampled token */
        float *probs = (float *)malloc(pe->gf.vocab_size * sizeof(float));
        memcpy(probs, pe->logits, pe->gf.vocab_size * sizeof(float));
        grpo_softmax(probs, (int)pe->gf.vocab_size);

        int token = grpo_top_p_sample(pe->logits, (int)pe->gf.vocab_size, temp, top_p, rng);
        output[i] = token;
        if (logprobs_out)
            logprobs_out[i] = logf(probs[token] + 1e-10f);
        free(probs);

        if (token == 2) break; /* EOS — common convention */
        total_gen++;

        /* Feed token back */
        policy_forward_token(pe, token, pe->seq_pos);
        pe->seq_pos++;
    }
    return total_gen;
}
```

- [ ] **Step 4: Implement `policy_logprobs` (teacher-forced forward for full sequence)**

This runs the full sequence through the model in one pass (no KV cache needed — all tokens processed at once) and returns per-token logprobs.

- [ ] **Step 5: Add policy tests to test_kernels.c (or separate test)**

Test that `policy_generate` produces valid token IDs and that logprobs are negative.

- [ ] **Step 6: Build and verify**

Run: `make -C internal/training/grpo_engine`
Expected: Compiles without errors.

- [ ] **Step 7: Commit**

```bash
git add internal/training/grpo_engine/policy.c
git commit -m "feat(training): implement policy engine with mmap and autoregressive generation"
```

---

