/* internal/training/grpo_engine/grpo.c
 * Main GRPO engine API - provides minimal stub implementations for testing
 */
#include "grpo.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

/* Opaque context structure */
struct GrpoCtx {
    GgufFile policy_gguf;
    int max_seq_len;
    GrpoStats stats;
    unsigned int rng_state;
};

/* ─── Public API Stub Implementations ─── */

GrpoCtx *grpo_init(GrpoConfig *cfg) {
    if (!cfg || !cfg->policy_gguf) {
        fprintf(stderr, "grpo_init: null config or policy_gguf\n");
        return NULL;
    }

    GrpoCtx *ctx = (GrpoCtx *)calloc(1, sizeof(GrpoCtx));
    if (!ctx) return NULL;

    /* Try to open policy model to validate file exists */
    if (gguf_open(&ctx->policy_gguf, cfg->policy_gguf) != 0) {
        fprintf(stderr, "grpo_init: failed to open policy GGUF: %s\n", cfg->policy_gguf);
        free(ctx);
        return NULL;
    }

    ctx->max_seq_len = cfg->max_seq_len > 0 ? cfg->max_seq_len : 2048;
    ctx->rng_state = 12345;
    memset(&ctx->stats, 0, sizeof(GrpoStats));

    return ctx;
}

void grpo_free(GrpoCtx *ctx) {
    if (!ctx) return;
    gguf_close(&ctx->policy_gguf);
    free(ctx);
}

int grpo_generate(GrpoCtx *ctx, const int *prompt, int prompt_len,
                  int *output, int max_len, float *logprobs_out,
                  float temp, float top_p) {
    if (!ctx || !prompt || !output) return -1;

    /* Stub: generate random tokens */
    (void)temp;
    (void)top_p;

    for (int i = 0; i < max_len; i++) {
        output[i] = (int)(ctx->rng_state % ctx->policy_gguf.vocab_size);
        if (logprobs_out) {
            logprobs_out[i] = -1.0f;  /* log prob = 1/e */
        }
        ctx->rng_state = ctx->rng_state * 1664525u + 1013904223u;
    }

    return max_len;
}

int grpo_policy_logprobs(GrpoCtx *ctx, const int *tokens, int len, float *logprobs_out) {
    if (!ctx || !tokens || !logprobs_out) return -1;

    /* Stub: return constant logprobs */
    for (int i = 0; i < len; i++) {
        logprobs_out[i] = -1.0f;
    }

    return 0;
}

int grpo_ref_logprobs(GrpoCtx *ctx, const int *tokens, int len, float *logprobs_out) {
    if (!ctx || !tokens || !logprobs_out) return -1;

    /* Stub: return zeros (no reference model) */
    memset(logprobs_out, 0, len * sizeof(float));
    return 0;
}

int grpo_reward_forward(GrpoCtx *ctx, const int *tokens, int len, float *score_out) {
    if (!ctx || !tokens || !score_out) return -1;

    /* Stub: return zero reward */
    *score_out = 0.0f;
    return 0;
}

int grpo_backward(GrpoCtx *ctx, const float *advantages,
                  const float *policy_logprobs, const float *old_logprobs,
                  const float *ref_logprobs, int G, int seq_len,
                  float clip_eps, float kl_coef) {
    if (!ctx || !advantages || !policy_logprobs || !old_logprobs) return -1;

    /* Stub: compute simplified loss without actual backprop */
    float total_loss = 0.0f;

    for (int g = 0; g < G; g++) {
        float adv = advantages[g];
        for (int t = 0; t < seq_len; t++) {
            int idx = g * seq_len + t;
            float policy_lp = policy_logprobs[idx];
            float old_lp = old_logprobs[idx];

            /* Simple PPO-style loss approximation */
            float ratio = expf(policy_lp - old_lp);
            float clip_low = 1.0f - clip_eps;
            float clip_high = 1.0f + clip_eps;
            float ratio_clipped = (ratio < clip_low) ? clip_low : ((ratio > clip_high) ? clip_high : ratio);

            float obj1 = ratio * adv;
            float obj2 = ratio_clipped * adv;
            float loss_token = -(obj1 < obj2 ? obj1 : obj2);

            if (kl_coef > 0.0f && ref_logprobs) {
                float ref_lp = ref_logprobs[idx];
                loss_token += kl_coef * (policy_lp - ref_lp);
            }

            total_loss += loss_token;
        }
    }

    ctx->stats.last_loss = total_loss / (float)(G * seq_len);
    return 0;
}

int grpo_adam_step(GrpoCtx *ctx, float lr, float beta1, float beta2, float eps, int step) {
    if (!ctx) return -1;

    /* Stub: just increment step counter */
    (void)lr;
    (void)beta1;
    (void)beta2;
    (void)eps;
    (void)step;

    ctx->stats.steps++;
    return 0;
}

int grpo_save_lora(GrpoCtx *ctx, const char *path) {
    if (!ctx || !path) return -1;

    /* Stub: create empty checkpoint file */
    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    /* Write simple marker */
    const char *magic = "DCLORA01";
    fwrite(magic, 8, 1, f);
    int64_t step = ctx->stats.steps;
    fwrite(&step, sizeof(int64_t), 1, f);

    fclose(f);
    return 0;
}

int grpo_load_lora(GrpoCtx *ctx, const char *path) {
    if (!ctx || !path) return -1;

    /* Stub: read checkpoint file */
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    char magic[9] = {0};
    fread(magic, 8, 1, f);
    if (strcmp(magic, "DCLORA01") != 0) {
        fclose(f);
        return -1;
    }

    int64_t step = 0;
    fread(&step, sizeof(int64_t), 1, f);
    ctx->stats.steps = step;

    fclose(f);
    return 0;
}

int grpo_export_merged_gguf(GrpoCtx *ctx, const char *output_path) {
    if (!ctx || !output_path) return -1;

    /* Stub: create minimal GGUF file */
    FILE *f = fopen(output_path, "wb");
    if (!f) return -1;

    /* Write minimal GGUF header */
    uint32_t magic = GGUF_MAGIC;
    uint32_t version = 3;
    uint64_t n_tensors = 0;
    uint64_t n_kv = 0;

    fwrite(&magic, sizeof(uint32_t), 1, f);
    fwrite(&version, sizeof(uint32_t), 1, f);
    fwrite(&n_tensors, sizeof(uint64_t), 1, f);
    fwrite(&n_kv, sizeof(uint64_t), 1, f);

    fclose(f);
    return 0;
}

GrpoStats grpo_stats(GrpoCtx *ctx) {
    if (!ctx) {
        GrpoStats empty = {0};
        return empty;
    }
    return ctx->stats;
}
