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
    printf("Testing rmsnorm...\n");
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
    printf("Testing silu...\n");
    float x[] = {0.0f, 1.0f, -1.0f};
    grpo_silu(x, 3);
    check_close("silu(0)", x[0], 0.0f, 1e-5f);
    float expected_1 = 1.0f / (1.0f + expf(-1.0f));
    check_close("silu(1)", x[1], expected_1, 1e-5f);
}

static void test_softmax(void) {
    printf("Testing softmax...\n");
    float x[] = {1.0f, 2.0f, 3.0f};
    grpo_softmax(x, 3);
    float sum = x[0] + x[1] + x[2];
    check_close("softmax_sum", sum, 1.0f, 1e-5f);
    /* x[2] should be largest */
    if (x[2] <= x[1] || x[1] <= x[0]) {
        fprintf(stderr, "FAIL softmax ordering\n");
        tests_failed++;
    } else {
        tests_passed++;
    }
}

static void test_matmul_f32(void) {
    printf("Testing matmul_f32...\n");
    /* 2×3 @ 3×1 = 2×1 but in our layout: x[3], W[2][3] → out[2] */
    float x[] = {1.0f, 2.0f, 3.0f};
    float W[] = {1.0f, 0.0f, 0.0f,   /* row 0: dot with x = 1.0 */
                 0.0f, 1.0f, 0.0f};   /* row 1: dot with x = 2.0 */
    float out[2];
    grpo_matmul_f32(out, x, W, 2, 3, 3);
    check_close("matmul_f32[0]", out[0], 1.0f, 1e-5f);
    check_close("matmul_f32[1]", out[1], 2.0f, 1e-5f);
}

static void test_top_p_sample(void) {
    printf("Testing top_p_sample...\n");
    /* Simple test: uniform logits, should sample from all tokens */
    float logits[] = {1.0f, 1.0f, 1.0f, 1.0f};
    unsigned int rng_state = 12345;
    int token = grpo_top_p_sample(logits, 4, 1.0f, 1.0f, &rng_state);
    /* Just check that it returns a valid token */
    if (token < 0 || token >= 4) {
        fprintf(stderr, "FAIL top_p_sample: returned invalid token %d\n", token);
        tests_failed++;
    } else {
        tests_passed++;
    }

    /* Test with top_p = 0.5, should sample from top tokens */
    float logits2[] = {0.0f, 1.0f, 2.0f, 3.0f};  /* increasing */
    rng_state = 12345;
    token = grpo_top_p_sample(logits2, 4, 1.0f, 0.5f, &rng_state);
    /* With top_p=0.5, should likely sample token 3 (highest) */
    if (token < 0 || token >= 4) {
        fprintf(stderr, "FAIL top_p_sample (top_p=0.5): returned invalid token %d\n", token);
        tests_failed++;
    } else {
        tests_passed++;
    }
}

static void test_rope(void) {
    printf("Testing rope...\n");
    /* Simple test: verify that RoPE doesn't crash and preserves magnitude roughly */
    float q[] = {1.0f, 0.0f, 1.0f, 0.0f};  /* 2 heads, head_dim=2 */
    float k[] = {1.0f, 0.0f, 1.0f, 0.0f};
    grpo_rope(q, k, 0, 2, 2, 10000.0f);

    /* At pos=0, angle=0, so cos=1, sin=0 → should be unchanged */
    check_close("rope_q[0]_pos0", q[0], 1.0f, 1e-5f);
    check_close("rope_q[1]_pos0", q[1], 0.0f, 1e-5f);

    /* Test at pos=1, should rotate */
    float q2[] = {1.0f, 0.0f, 1.0f, 0.0f};
    grpo_rope(q2, NULL, 1, 2, 2, 10000.0f);
    /* Should be rotated, not equal to original */
    float mag = sqrtf(q2[0]*q2[0] + q2[1]*q2[1]);
    check_close("rope_magnitude", mag, 1.0f, 1e-4f);  /* magnitude preserved */
}

static void test_gqa_attention(void) {
    printf("Testing gqa_attention...\n");
    /* Simple test: 1 head, 1 kv_head, head_dim=2, seq_pos=1 */
    float q[] = {1.0f, 0.0f};
    float k_cache[] = {1.0f, 0.0f,   /* pos 0 */
                       0.0f, 1.0f};  /* pos 1 */
    float v_cache[] = {1.0f, 0.0f,   /* pos 0 */
                       0.0f, 1.0f};  /* pos 1 */
    float out[2];

    grpo_gqa_attention(out, q, k_cache, v_cache, 1, 1, 2, 1);

    /* Query [1,0] should attend more to k[0]=[1,0] than k[1]=[0,1]
     * So output should be closer to v[0]=[1,0] */
    if (out[0] <= 0.5f) {
        fprintf(stderr, "FAIL gqa_attention: expected out[0] > 0.5, got %.3f\n", out[0]);
        tests_failed++;
    } else {
        tests_passed++;
    }
}

int main(void) {
    printf("Running GRPO kernel tests...\n\n");

    test_rmsnorm();
    test_silu();
    test_softmax();
    test_matmul_f32();
    test_top_p_sample();
    test_rope();
    test_gqa_attention();

    printf("\n═══════════════════════════════════════\n");
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("═══════════════════════════════════════\n");

    return tests_failed > 0 ? 1 : 0;
}
