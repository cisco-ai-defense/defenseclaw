93b47bba feat(training): implement math kernels for grpo-local engine
---STAT---
 internal/training/grpo_engine/grpo.h         |  12 ++
 internal/training/grpo_engine/kernels.c      | 228 ++++++++++++++++++++++++++-
 internal/training/grpo_engine/test_kernels.c | 151 ++++++++++++++++++
 3 files changed, 390 insertions(+), 1 deletion(-)
---DIFF---
diff --git a/internal/training/grpo_engine/grpo.h b/internal/training/grpo_engine/grpo.h
index 78b2e1f5..68bdeab3 100644
--- a/internal/training/grpo_engine/grpo.h
+++ b/internal/training/grpo_engine/grpo.h
@@ -92,11 +92,23 @@ int         grpo_reward_forward(GrpoCtx *ctx, const int *tokens, int len, float
 int         grpo_backward(GrpoCtx *ctx, const float *advantages,
                           const float *policy_logprobs, const float *old_logprobs,
                           const float *ref_logprobs, int G, int seq_len,
                           float clip_eps, float kl_coef);
 int         grpo_adam_step(GrpoCtx *ctx, float lr, float beta1, float beta2, float eps, int step);
 int         grpo_save_lora(GrpoCtx *ctx, const char *path);
 int         grpo_load_lora(GrpoCtx *ctx, const char *path);
 int         grpo_export_merged_gguf(GrpoCtx *ctx, const char *output_path);
 GrpoStats   grpo_stats(GrpoCtx *ctx);
 
+/* ─── Math Kernels ─── */
+void grpo_rmsnorm(float *y, const float *x, const float *w, int n, float eps);
+void grpo_matmul_f32(float *out, const float *x, const float *W, int rows, int cols, int in_dim);
+void grpo_matmul_q4(float *out, const float *x, const void *W_packed, int rows, int in_dim);
+void grpo_silu(float *x, int n);
+void grpo_rope(float *q, float *k, int pos, int n_heads, int head_dim, float theta);
+void grpo_softmax(float *x, int n);
+void grpo_gqa_attention(float *out, const float *q, const float *k_cache, const float *v_cache,
+                        int n_heads, int n_kv_heads, int head_dim, int seq_pos);
+int  grpo_top_p_sample(const float *logits, int vocab_size, float temp, float top_p,
+                       unsigned int *rng_state);
+
 #endif /* GRPO_H */
diff --git a/internal/training/grpo_engine/kernels.c b/internal/training/grpo_engine/kernels.c
index 26daea4a..ba54c8cd 100644
--- a/internal/training/grpo_engine/kernels.c
+++ b/internal/training/grpo_engine/kernels.c
@@ -1,2 +1,228 @@
-/* kernels.c stub */
+/* kernels.c — core math kernels for GRPO-Local engine */
 #include "grpo.h"
+#include <math.h>
+#include <stdlib.h>
+#include <string.h>
+#include <float.h>
+
+/* ─── RMS Normalization ─── */
+void grpo_rmsnorm(float *y, const float *x, const float *w, int n, float eps) {
+    double ss = 0.0;
+    for (int i = 0; i < n; i++) ss += (double)x[i] * (double)x[i];
+    float inv = (float)(1.0 / sqrt(ss / (double)n + (double)eps));
+    for (int i = 0; i < n; i++) y[i] = w[i] * x[i] * inv;
+}
+
+/* ─── Matrix Multiplication (F32) ─── */
+void grpo_matmul_f32(float *out, const float *x, const float *W,
+                     int rows, int cols, int in_dim) {
+    /* out[rows] = x[in_dim] @ W[in_dim × rows]^T
+     * W is stored row-major: W[row][col] = W[row * in_dim + col] */
+    (void)cols; /* unused in this signature */
+    #pragma omp parallel for
+    for (int r = 0; r < rows; r++) {
+        double acc = 0.0;
+        for (int c = 0; c < in_dim; c++)
+            acc += (double)x[c] * (double)W[r * in_dim + c];
+        out[r] = (float)acc;
+    }
+}
+
+/* ─── Q4_K Quantization Support ─── */
+#define Q4K_BLOCK_SIZE 32
+#define Q4K_BLOCK_BYTES 20
+
+/* Convert FP16 to FP32 (simplified implementation) */
+static inline float fp16_to_fp32(uint16_t h) {
+    uint32_t sign = (h >> 15) & 1;
+    uint32_t exp = (h >> 10) & 0x1F;
+    uint32_t mant = h & 0x3FF;
+
+    uint32_t f;
+    if (exp == 0) {
+        if (mant == 0) {
+            f = sign << 31;
+        } else {
+            /* subnormal */
+            exp = 127 - 14;
+            while ((mant & 0x400) == 0) {
+                mant <<= 1;
+                exp--;
+            }
+            mant &= 0x3FF;
+            f = (sign << 31) | (exp << 23) | (mant << 13);
+        }
+    } else if (exp == 0x1F) {
+        /* inf or nan */
+        f = (sign << 31) | (0xFF << 23) | (mant << 13);
+    } else {
+        /* normal */
+        f = (sign << 31) | ((exp + (127 - 15)) << 23) | (mant << 13);
+    }
+
+    float result;
+    memcpy(&result, &f, sizeof(float));
+    return result;
+}
+
+static inline float dequant_q4k_element(const uint8_t *block, int idx) {
+    /* Q4_K block: 2 bytes d (f16), 2 bytes dmin (f16), 16 bytes qs (32 4-bit values) */
+    uint16_t d_bits, dmin_bits;
+    memcpy(&d_bits, block, 2);
+    memcpy(&dmin_bits, block + 2, 2);
+
+    float d = fp16_to_fp32(d_bits);
+    float dmin = fp16_to_fp32(dmin_bits);
+
+    const uint8_t *qs = block + 4;
+    uint8_t q;
+    if (idx % 2 == 0)
+        q = qs[idx / 2] & 0x0F;
+    else
+        q = qs[idx / 2] >> 4;
+
+    return d * (float)q - dmin;
+}
+
+void grpo_matmul_q4(float *out, const float *x, const void *W_packed,
+                    int rows, int in_dim) {
+    /* out[rows] = x[in_dim] @ W_packed[rows × in_dim, Q4_K format] */
+    const int blocks_per_row = in_dim / Q4K_BLOCK_SIZE;
+    const uint8_t *W = (const uint8_t *)W_packed;
+
+    #pragma omp parallel for
+    for (int r = 0; r < rows; r++) {
+        double acc = 0.0;
+        const uint8_t *row_data = W + (size_t)r * blocks_per_row * Q4K_BLOCK_BYTES;
+        for (int b = 0; b < blocks_per_row; b++) {
+            const uint8_t *block = row_data + b * Q4K_BLOCK_BYTES;
+            for (int j = 0; j < Q4K_BLOCK_SIZE; j++) {
+                float w = dequant_q4k_element(block, j);
+                acc += (double)x[b * Q4K_BLOCK_SIZE + j] * (double)w;
+            }
+        }
+        out[r] = (float)acc;
+    }
+}
+
+/* ─── Activation Functions ─── */
+static inline float sigmoidf(float x) { return 1.0f / (1.0f + expf(-x)); }
+
+void grpo_silu(float *x, int n) {
+    for (int i = 0; i < n; i++)
+        x[i] = x[i] * sigmoidf(x[i]);
+}
+
+/* ─── RoPE (Rotary Position Embedding) ─── */
+void grpo_rope(float *q, float *k, int pos, int n_heads, int head_dim, float theta) {
+    for (int h = 0; h < n_heads; h++) {
+        for (int i = 0; i < head_dim; i += 2) {
+            float freq = 1.0f / powf(theta, (float)i / (float)head_dim);
+            float angle = (float)pos * freq;
+            float cos_a = cosf(angle), sin_a = sinf(angle);
+            int idx = h * head_dim + i;
+            float q0 = q[idx], q1 = q[idx + 1];
+            q[idx]     = q0 * cos_a - q1 * sin_a;
+            q[idx + 1] = q0 * sin_a + q1 * cos_a;
+            if (k) {
+                float k0 = k[idx], k1 = k[idx + 1];
+                k[idx]     = k0 * cos_a - k1 * sin_a;
+                k[idx + 1] = k0 * sin_a + k1 * cos_a;
+            }
+        }
+    }
+}
+
+/* ─── Softmax ─── */
+void grpo_softmax(float *x, int n) {
+    float max_val = -FLT_MAX;
+    for (int i = 0; i < n; i++) if (x[i] > max_val) max_val = x[i];
+    double sum = 0.0;
+    for (int i = 0; i < n; i++) { x[i] = expf(x[i] - max_val); sum += (double)x[i]; }
+    float inv = (float)(1.0 / sum);
+    for (int i = 0; i < n; i++) x[i] *= inv;
+}
+
+/* ─── Top-p Sampling ─── */
+int grpo_top_p_sample(const float *logits, int vocab_size, float temp, float top_p,
+                      unsigned int *rng_state) {
+    /* Temperature scaling + softmax */
+    float *probs = (float *)malloc(vocab_size * sizeof(float));
+    for (int i = 0; i < vocab_size; i++) probs[i] = logits[i] / temp;
+    grpo_softmax(probs, vocab_size);
+
+    /* Sort indices by probability descending */
+    int *indices = (int *)malloc(vocab_size * sizeof(int));
+    for (int i = 0; i < vocab_size; i++) indices[i] = i;
+    /* Simple insertion sort — vocab is ~32-128K, called once per token */
+    for (int i = 1; i < vocab_size; i++) {
+        int j = i;
+        while (j > 0 && probs[indices[j]] > probs[indices[j-1]]) {
+            int tmp = indices[j]; indices[j] = indices[j-1]; indices[j-1] = tmp;
+            j--;
+        }
+    }
+
+    /* Accumulate until top_p, then sample uniformly from the nucleus */
+    float cumsum = 0.0f;
+    int nucleus_size = 0;
+    for (int i = 0; i < vocab_size; i++) {
+        cumsum += probs[indices[i]];
+        nucleus_size++;
+        if (cumsum >= top_p) break;
+    }
+
+    /* Sample from nucleus */
+    *rng_state = *rng_state * 1664525u + 1013904223u; /* LCG */
+    float u = (float)(*rng_state) / 4294967296.0f;
+    float running = 0.0f;
+    float norm = cumsum; /* renormalize within nucleus */
+    int token = indices[0];
+    for (int i = 0; i < nucleus_size; i++) {
+        running += probs[indices[i]] / norm;
+        if (u <= running) { token = indices[i]; break; }
+    }
+
+    free(probs);
+    free(indices);
+    return token;
+}
+
+/* ─── GQA Attention ─── */
+void grpo_gqa_attention(float *out, const float *q, const float *k_cache,
+                        const float *v_cache, int n_heads, int n_kv_heads,
+                        int head_dim, int seq_pos) {
+    /* Single query position attending to all cached positions [0..seq_pos].
+     * GQA: each KV head serves (n_heads / n_kv_heads) query heads. */
+    int heads_per_kv = n_heads / n_kv_heads;
+
+    for (int h = 0; h < n_heads; h++) {
+        int kv_h = h / heads_per_kv;
+        const float *qi = q + h * head_dim;
+
+        /* Compute attention scores for this head */
+        float *scores = (float *)malloc((seq_pos + 1) * sizeof(float));
+        float scale = 1.0f / sqrtf((float)head_dim);
+
+        for (int t = 0; t <= seq_pos; t++) {
+            const float *kt = k_cache + (size_t)t * n_kv_heads * head_dim + kv_h * head_dim;
+            double dot = 0.0;
+            for (int d = 0; d < head_dim; d++)
+                dot += (double)qi[d] * (double)kt[d];
+            scores[t] = (float)dot * scale;
+        }
+
+        /* Softmax over scores */
+        grpo_softmax(scores, seq_pos + 1);
+
+        /* Weighted sum of values */
+        float *oi = out + h * head_dim;
+        memset(oi, 0, head_dim * sizeof(float));
+        for (int t = 0; t <= seq_pos; t++) {
+            const float *vt = v_cache + (size_t)t * n_kv_heads * head_dim + kv_h * head_dim;
+            for (int d = 0; d < head_dim; d++)
+                oi[d] += scores[t] * vt[d];
+        }
+        free(scores);
+    }
+}
diff --git a/internal/training/grpo_engine/test_kernels.c b/internal/training/grpo_engine/test_kernels.c
new file mode 100644
index 00000000..e1120e23
--- /dev/null
+++ b/internal/training/grpo_engine/test_kernels.c
@@ -0,0 +1,151 @@
+/* test_kernels.c — validates kernels against known values */
+#include <stdio.h>
+#include <stdlib.h>
+#include <math.h>
+#include "grpo.h"
+
+static int tests_passed = 0, tests_failed = 0;
+
+static void check_close(const char *name, float got, float expected, float tol) {
+    if (fabsf(got - expected) > tol) {
+        fprintf(stderr, "FAIL %s: got %.8f expected %.8f (diff %.2e)\n",
+                name, got, expected, fabsf(got - expected));
+        tests_failed++;
+    } else {
+        tests_passed++;
+    }
+}
+
+static void test_rmsnorm(void) {
+    printf("Testing rmsnorm...\n");
+    float x[] = {1.0f, 2.0f, 3.0f, 4.0f};
+    float w[] = {1.0f, 1.0f, 1.0f, 1.0f};
+    float y[4];
+    grpo_rmsnorm(y, x, w, 4, 1e-5f);
+    /* RMS = sqrt((1+4+9+16)/4) = sqrt(7.5) ≈ 2.7386 */
+    float rms = sqrtf(7.5f);
+    check_close("rmsnorm[0]", y[0], 1.0f / rms, 1e-5f);
+    check_close("rmsnorm[3]", y[3], 4.0f / rms, 1e-5f);
+}
+
+static void test_silu(void) {
+    printf("Testing silu...\n");
+    float x[] = {0.0f, 1.0f, -1.0f};
+    grpo_silu(x, 3);
+    check_close("silu(0)", x[0], 0.0f, 1e-5f);
+    float expected_1 = 1.0f / (1.0f + expf(-1.0f));
+    check_close("silu(1)", x[1], expected_1, 1e-5f);
+}
+
+static void test_softmax(void) {
+    printf("Testing softmax...\n");
+    float x[] = {1.0f, 2.0f, 3.0f};
+    grpo_softmax(x, 3);
+    float sum = x[0] + x[1] + x[2];
+    check_close("softmax_sum", sum, 1.0f, 1e-5f);
+    /* x[2] should be largest */
+    if (x[2] <= x[1] || x[1] <= x[0]) {
+        fprintf(stderr, "FAIL softmax ordering\n");
+        tests_failed++;
+    } else {
+        tests_passed++;
+    }
+}
+
+static void test_matmul_f32(void) {
+    printf("Testing matmul_f32...\n");
+    /* 2×3 @ 3×1 = 2×1 but in our layout: x[3], W[2][3] → out[2] */
+    float x[] = {1.0f, 2.0f, 3.0f};
+    float W[] = {1.0f, 0.0f, 0.0f,   /* row 0: dot with x = 1.0 */
+                 0.0f, 1.0f, 0.0f};   /* row 1: dot with x = 2.0 */
+    float out[2];
+    grpo_matmul_f32(out, x, W, 2, 3, 3);
+    check_close("matmul_f32[0]", out[0], 1.0f, 1e-5f);
+    check_close("matmul_f32[1]", out[1], 2.0f, 1e-5f);
+}
+
+static void test_top_p_sample(void) {
+    printf("Testing top_p_sample...\n");
+    /* Simple test: uniform logits, should sample from all tokens */
+    float logits[] = {1.0f, 1.0f, 1.0f, 1.0f};
+    unsigned int rng_state = 12345;
+    int token = grpo_top_p_sample(logits, 4, 1.0f, 1.0f, &rng_state);
+    /* Just check that it returns a valid token */
+    if (token < 0 || token >= 4) {
+        fprintf(stderr, "FAIL top_p_sample: returned invalid token %d\n", token);
+        tests_failed++;
+    } else {
+        tests_passed++;
+    }
+
+    /* Test with top_p = 0.5, should sample from top tokens */
+    float logits2[] = {0.0f, 1.0f, 2.0f, 3.0f};  /* increasing */
+    rng_state = 12345;
+    token = grpo_top_p_sample(logits2, 4, 1.0f, 0.5f, &rng_state);
+    /* With top_p=0.5, should likely sample token 3 (highest) */
+    if (token < 0 || token >= 4) {
+        fprintf(stderr, "FAIL top_p_sample (top_p=0.5): returned invalid token %d\n", token);
+        tests_failed++;
+    } else {
+        tests_passed++;
+    }
+}
+
+static void test_rope(void) {
+    printf("Testing rope...\n");
+    /* Simple test: verify that RoPE doesn't crash and preserves magnitude roughly */
+    float q[] = {1.0f, 0.0f, 1.0f, 0.0f};  /* 2 heads, head_dim=2 */
+    float k[] = {1.0f, 0.0f, 1.0f, 0.0f};
+    grpo_rope(q, k, 0, 2, 2, 10000.0f);
+
+    /* At pos=0, angle=0, so cos=1, sin=0 → should be unchanged */
+    check_close("rope_q[0]_pos0", q[0], 1.0f, 1e-5f);
+    check_close("rope_q[1]_pos0", q[1], 0.0f, 1e-5f);
+
+    /* Test at pos=1, should rotate */
+    float q2[] = {1.0f, 0.0f, 1.0f, 0.0f};
+    grpo_rope(q2, NULL, 1, 2, 2, 10000.0f);
+    /* Should be rotated, not equal to original */
+    float mag = sqrtf(q2[0]*q2[0] + q2[1]*q2[1]);
+    check_close("rope_magnitude", mag, 1.0f, 1e-4f);  /* magnitude preserved */
+}
+
+static void test_gqa_attention(void) {
+    printf("Testing gqa_attention...\n");
+    /* Simple test: 1 head, 1 kv_head, head_dim=2, seq_pos=1 */
+    float q[] = {1.0f, 0.0f};
+    float k_cache[] = {1.0f, 0.0f,   /* pos 0 */
+                       0.0f, 1.0f};  /* pos 1 */
+    float v_cache[] = {1.0f, 0.0f,   /* pos 0 */
+                       0.0f, 1.0f};  /* pos 1 */
+    float out[2];
+
+    grpo_gqa_attention(out, q, k_cache, v_cache, 1, 1, 2, 1);
+
+    /* Query [1,0] should attend more to k[0]=[1,0] than k[1]=[0,1]
+     * So output should be closer to v[0]=[1,0] */
+    if (out[0] <= 0.5f) {
+        fprintf(stderr, "FAIL gqa_attention: expected out[0] > 0.5, got %.3f\n", out[0]);
+        tests_failed++;
+    } else {
+        tests_passed++;
+    }
+}
+
+int main(void) {
+    printf("Running GRPO kernel tests...\n\n");
+
+    test_rmsnorm();
+    test_silu();
+    test_softmax();
+    test_matmul_f32();
+    test_top_p_sample();
+    test_rope();
+    test_gqa_attention();
+
+    printf("\n═══════════════════════════════════════\n");
+    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
+    printf("═══════════════════════════════════════\n");
+
+    return tests_failed > 0 ? 1 : 0;
+}
