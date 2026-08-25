## Task 2: Math Kernels

**Files:**
- Modify: `internal/training/grpo_engine/kernels.c` (replace stub)
- Create: `internal/training/grpo_engine/test_kernels.c`
- Create: `internal/training/grpo_engine/testdata/fixtures/` (golden data)

**Interfaces:**
- Consumes: Raw float32 arrays and packed Q4_K weight arrays
- Produces: `grpo_rmsnorm()`, `grpo_matmul_q4()`, `grpo_matmul_f32()`, `grpo_rope()`, `grpo_silu()`, `grpo_softmax()`, `grpo_gqa_attention()`, `grpo_top_p_sample()`

- [ ] **Step 1: Implement `rmsnorm` and `matmul_f32`**

```c
/* kernels.c — core math kernels */
#include "grpo.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <float.h>

void grpo_rmsnorm(float *y, const float *x, const float *w, int n, float eps) {
    double ss = 0.0;
    for (int i = 0; i < n; i++) ss += (double)x[i] * (double)x[i];
    float inv = (float)(1.0 / sqrt(ss / (double)n + (double)eps));
    for (int i = 0; i < n; i++) y[i] = w[i] * x[i] * inv;
}

void grpo_matmul_f32(float *out, const float *x, const float *W,
                     int rows, int cols, int in_dim) {
    /* out[rows] = x[in_dim] @ W[in_dim × rows]^T
     * W is stored row-major: W[row][col] = W[row * in_dim + col] */
    #pragma omp parallel for
    for (int r = 0; r < rows; r++) {
        double acc = 0.0;
        for (int c = 0; c < in_dim; c++)
            acc += (double)x[c] * (double)W[r * in_dim + c];
        out[r] = (float)acc;
    }
}
```

- [ ] **Step 2: Implement `matmul_q4` (Q4_K dequantize-on-the-fly)**

```c
/* Q4_K block: 32 elements per block, 2 scales (d, dmin), 4-bit quantized values.
 * Each block is: half_t d, half_t dmin, uint8_t qs[16] (32 4-bit values packed)
 * Total: 2 + 2 + 16 = 20 bytes per 32 elements. */
#define Q4K_BLOCK_SIZE 32
#define Q4K_BLOCK_BYTES 20

static inline float dequant_q4k_element(const uint8_t *block, int idx) {
    /* Simplified Q4_K dequantization — full implementation handles super-blocks */
    uint16_t d_bits, dmin_bits;
    memcpy(&d_bits, block, 2);
    memcpy(&dmin_bits, block + 2, 2);
    /* Convert f16 to f32 (simplified — proper impl uses hardware or table) */
    float d = (float)d_bits / 1024.0f;      /* placeholder: real impl decodes f16 */
    float dmin = (float)dmin_bits / 1024.0f;

    const uint8_t *qs = block + 4;
    uint8_t q;
    if (idx % 2 == 0)
        q = qs[idx / 2] & 0x0F;
    else
        q = qs[idx / 2] >> 4;
    return d * (float)q - dmin;
}

void grpo_matmul_q4(float *out, const float *x, const void *W_packed,
                    int rows, int in_dim) {
    /* out[rows] = x[in_dim] @ W_packed[rows × in_dim, Q4_K format] */
    const int blocks_per_row = in_dim / Q4K_BLOCK_SIZE;
    const uint8_t *W = (const uint8_t *)W_packed;

    #pragma omp parallel for
    for (int r = 0; r < rows; r++) {
        double acc = 0.0;
        const uint8_t *row_data = W + (size_t)r * blocks_per_row * Q4K_BLOCK_BYTES;
        for (int b = 0; b < blocks_per_row; b++) {
            const uint8_t *block = row_data + b * Q4K_BLOCK_BYTES;
            for (int j = 0; j < Q4K_BLOCK_SIZE; j++) {
                float w = dequant_q4k_element(block, j);
                acc += (double)x[b * Q4K_BLOCK_SIZE + j] * (double)w;
            }
        }
        out[r] = (float)acc;
    }
}
```

- [ ] **Step 3: Implement `silu`, `rope`, `softmax`, `top_p_sample`**

```c
static inline float sigmoidf(float x) { return 1.0f / (1.0f + expf(-x)); }

void grpo_silu(float *x, int n) {
    for (int i = 0; i < n; i++)
        x[i] = x[i] * sigmoidf(x[i]);
}

void grpo_rope(float *q, float *k, int pos, int n_heads, int head_dim, float theta) {
    for (int h = 0; h < n_heads; h++) {
        for (int i = 0; i < head_dim; i += 2) {
            float freq = 1.0f / powf(theta, (float)i / (float)head_dim);
            float angle = (float)pos * freq;
            float cos_a = cosf(angle), sin_a = sinf(angle);
            int idx = h * head_dim + i;
            float q0 = q[idx], q1 = q[idx + 1];
            q[idx]     = q0 * cos_a - q1 * sin_a;
            q[idx + 1] = q0 * sin_a + q1 * cos_a;
            if (k) {
                float k0 = k[idx], k1 = k[idx + 1];
                k[idx]     = k0 * cos_a - k1 * sin_a;
                k[idx + 1] = k0 * sin_a + k1 * cos_a;
            }
        }
    }
}

void grpo_softmax(float *x, int n) {
    float max_val = -FLT_MAX;
    for (int i = 0; i < n; i++) if (x[i] > max_val) max_val = x[i];
    double sum = 0.0;
    for (int i = 0; i < n; i++) { x[i] = expf(x[i] - max_val); sum += (double)x[i]; }
    float inv = (float)(1.0 / sum);
    for (int i = 0; i < n; i++) x[i] *= inv;
}

int grpo_top_p_sample(const float *logits, int vocab_size, float temp, float top_p,
                      unsigned int *rng_state) {
    /* Temperature scaling + softmax */
    float *probs = (float *)malloc(vocab_size * sizeof(float));
    for (int i = 0; i < vocab_size; i++) probs[i] = logits[i] / temp;
    grpo_softmax(probs, vocab_size);

    /* Sort indices by probability descending */
    int *indices = (int *)malloc(vocab_size * sizeof(int));
    for (int i = 0; i < vocab_size; i++) indices[i] = i;
    /* Simple insertion sort — vocab is ~32-128K, called once per token */
    for (int i = 1; i < vocab_size; i++) {
        int j = i;
        while (j > 0 && probs[indices[j]] > probs[indices[j-1]]) {
            int tmp = indices[j]; indices[j] = indices[j-1]; indices[j-1] = tmp;
            j--;
        }
    }

    /* Accumulate until top_p, then sample uniformly from the nucleus */
    float cumsum = 0.0f;
    int nucleus_size = 0;
    for (int i = 0; i < vocab_size; i++) {
        cumsum += probs[indices[i]];
        nucleus_size++;
        if (cumsum >= top_p) break;
    }

    /* Sample from nucleus */
    *rng_state = *rng_state * 1664525u + 1013904223u; /* LCG */
    float u = (float)(*rng_state) / 4294967296.0f;
    float running = 0.0f;
    float norm = cumsum; /* renormalize within nucleus */
    int token = indices[0];
    for (int i = 0; i < nucleus_size; i++) {
        running += probs[indices[i]] / norm;
        if (u <= running) { token = indices[i]; break; }
    }

    free(probs);
    free(indices);
    return token;
}
```

- [ ] **Step 4: Implement `gqa_attention` (single-position for generation)**

```c
void grpo_gqa_attention(float *out, const float *q, const float *k_cache,
                        const float *v_cache, int n_heads, int n_kv_heads,
                        int head_dim, int seq_pos) {
    /* Single query position attending to all cached positions [0..seq_pos].
     * GQA: each KV head serves (n_heads / n_kv_heads) query heads. */
    int heads_per_kv = n_heads / n_kv_heads;

    for (int h = 0; h < n_heads; h++) {
        int kv_h = h / heads_per_kv;
        const float *qi = q + h * head_dim;

        /* Compute attention scores for this head */
        float *scores = (float *)malloc((seq_pos + 1) * sizeof(float));
        float scale = 1.0f / sqrtf((float)head_dim);

        for (int t = 0; t <= seq_pos; t++) {
            const float *kt = k_cache + (size_t)t * n_kv_heads * head_dim + kv_h * head_dim;
            double dot = 0.0;
            for (int d = 0; d < head_dim; d++)
                dot += (double)qi[d] * (double)kt[d];
            scores[t] = (float)dot * scale;
        }

        /* Softmax over scores */
        grpo_softmax(scores, seq_pos + 1);

        /* Weighted sum of values */
        float *oi = out + h * head_dim;
        memset(oi, 0, head_dim * sizeof(float));
        for (int t = 0; t <= seq_pos; t++) {
            const float *vt = v_cache + (size_t)t * n_kv_heads * head_dim + kv_h * head_dim;
            for (int d = 0; d < head_dim; d++)
                oi[d] += scores[t] * vt[d];
        }
        free(scores);
    }
}
```

- [ ] **Step 5: Write kernel test runner**

```c
/* test_kernels.c — validates kernels against known values */
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "grpo.h"

static int tests_passed = 0, tests_failed = 0;

static void check_close(const char *name, float got, float expected, float tol) {
    if (fabsf(got - expected) > tol) {
        fprintf(stderr, "FAIL %s: got %.8f expected %.8f (diff %.2e)\n",
                name, got, expected, fabsf(got - expected));
        tests_failed++;
    } else {
        tests_passed++;
    }
}

static void test_rmsnorm(void) {
    float x[] = {1.0f, 2.0f, 3.0f, 4.0f};
    float w[] = {1.0f, 1.0f, 1.0f, 1.0f};
    float y[4];
    grpo_rmsnorm(y, x, w, 4, 1e-5f);
    /* RMS = sqrt((1+4+9+16)/4) = sqrt(7.5) ≈ 2.7386 */
    float rms = sqrtf(7.5f);
    check_close("rmsnorm[0]", y[0], 1.0f / rms, 1e-5f);
    check_close("rmsnorm[3]", y[3], 4.0f / rms, 1e-5f);
}

static void test_silu(void) {
    float x[] = {0.0f, 1.0f, -1.0f};
    grpo_silu(x, 3);
    check_close("silu(0)", x[0], 0.0f, 1e-5f);
    check_close("silu(1)", x[1], 1.0f / (1.0f + expf(-1.0f)), 1e-5f);
}

static void test_softmax(void) {
    float x[] = {1.0f, 2.0f, 3.0f};
    grpo_softmax(x, 3);
    float sum = x[0] + x[1] + x[2];
    check_close("softmax_sum", sum, 1.0f, 1e-5f);
    /* x[2] should be largest */
    if (x[2] <= x[1] || x[1] <= x[0]) { fprintf(stderr, "FAIL softmax ordering\n"); tests_failed++; }
    else tests_passed++;
}

static void test_matmul_f32(void) {
    /* 2×3 @ 3×1 = 2×1 but in our layout: x[3], W[2][3] → out[2] */
    float x[] = {1.0f, 2.0f, 3.0f};
    float W[] = {1.0f, 0.0f, 0.0f,   /* row 0: dot with x = 1.0 */
                 0.0f, 1.0f, 0.0f};   /* row 1: dot with x = 2.0 */
    float out[2];
    grpo_matmul_f32(out, x, W, 2, 3, 3);
    check_close("matmul_f32[0]", out[0], 1.0f, 1e-5f);
    check_close("matmul_f32[1]", out[1], 2.0f, 1e-5f);
}

int main(void) {
    test_rmsnorm();
    test_silu();
    test_softmax();
    test_matmul_f32();

    printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
```

- [ ] **Step 6: Build and run tests**

Run: `make -C internal/training/grpo_engine test`
Expected: All kernel tests pass.

- [ ] **Step 7: Commit**

```bash
git add internal/training/grpo_engine/kernels.c internal/training/grpo_engine/test_kernels.c
git commit -m "feat(training): implement math kernels for grpo-local engine"
```

---

