/* policy.c — mmap'd policy forward pass and autoregressive generation */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <math.h>

#include "grpo.h"

/* ─── Internal Policy Engine Structure ─── */

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
    float       *q_buf;        /* [n_heads × head_dim] */
    float       *k_buf;        /* [n_kv_heads × head_dim] */
    float       *v_buf;        /* [n_kv_heads × head_dim] */
    float       *attn_out;     /* [hidden_dim] */
    float       *ffn_gate;     /* [intermediate_dim] */
    float       *ffn_up;       /* [intermediate_dim] */
    float       *ffn_out;      /* [hidden_dim] */
    float       *logits;       /* [vocab_size] */
} PolicyEngine;

/* ─── Helper: Find and resolve tensor pointer ─── */
static const void *resolve_tensor_ptr(const GgufFile *gf, void *mmap_base,
                                      const char *name, GgufDtype expected_dtype) {
    GgufTensor *t = gguf_find_tensor(gf, name);
    if (!t) return NULL;
    if (t->dtype != expected_dtype && expected_dtype != GGUF_TYPE_F32) {
        /* Allow F32 fallback for Q4_K */
        if (!(expected_dtype == GGUF_TYPE_Q4_K && t->dtype == GGUF_TYPE_F32)) {
            fprintf(stderr, "policy: tensor %s has unexpected dtype %d (expected %d)\n",
                    name, t->dtype, expected_dtype);
            return NULL;
        }
    }
    return (const uint8_t *)mmap_base + t->offset;
}

/* ─── Policy Engine Initialization ─── */
static PolicyEngine *policy_init(const char *gguf_path, int max_seq_len) {
    PolicyEngine *pe = (PolicyEngine *)calloc(1, sizeof(PolicyEngine));
    if (!pe) return NULL;

    /* Open GGUF file */
    if (gguf_open(&pe->gf, gguf_path) != 0) {
        fprintf(stderr, "policy: failed to open %s\n", gguf_path);
        free(pe);
        return NULL;
    }

    /* mmap the tensor data region */
    struct stat st;
    if (fstat(pe->gf.fd, &st) != 0) {
        gguf_close(&pe->gf);
        free(pe);
        return NULL;
    }
    pe->mmap_size = (size_t)(st.st_size - pe->gf.data_offset);
    pe->mmap_base = mmap(NULL, pe->mmap_size, PROT_READ, MAP_SHARED,
                         pe->gf.fd, pe->gf.data_offset);
    if (pe->mmap_base == MAP_FAILED) {
        fprintf(stderr, "policy: mmap failed for %s\n", gguf_path);
        gguf_close(&pe->gf);
        free(pe);
        return NULL;
    }

    /* Resolve global tensors */
    pe->embed = (const float *)resolve_tensor_ptr(&pe->gf, pe->mmap_base,
                                                   "token_embd.weight", GGUF_TYPE_F32);
    pe->output_norm = (const float *)resolve_tensor_ptr(&pe->gf, pe->mmap_base,
                                                         "output_norm.weight", GGUF_TYPE_F32);
    pe->output_weight = resolve_tensor_ptr(&pe->gf, pe->mmap_base,
                                           "output.weight", GGUF_TYPE_Q4_K);
    if (!pe->output_weight) {
        /* Fallback to F32 */
        pe->output_weight = resolve_tensor_ptr(&pe->gf, pe->mmap_base,
                                               "output.weight", GGUF_TYPE_F32);
    }

    if (!pe->embed || !pe->output_norm || !pe->output_weight) {
        fprintf(stderr, "policy: missing global tensors\n");
        munmap(pe->mmap_base, pe->mmap_size);
        gguf_close(&pe->gf);
        free(pe);
        return NULL;
    }

    /* Resolve per-layer tensors */
    pe->layers = (PolicyLayer *)calloc((size_t)pe->gf.n_layers, sizeof(PolicyLayer));
    if (!pe->layers) {
        munmap(pe->mmap_base, pe->mmap_size);
        gguf_close(&pe->gf);
        free(pe);
        return NULL;
    }

    for (int l = 0; l < pe->gf.n_layers; l++) {
        char name[128];

        snprintf(name, sizeof(name), "blk.%d.attn_q.weight", l);
        pe->layers[l].q_weight = resolve_tensor_ptr(&pe->gf, pe->mmap_base, name, GGUF_TYPE_Q4_K);

        snprintf(name, sizeof(name), "blk.%d.attn_k.weight", l);
        pe->layers[l].k_weight = resolve_tensor_ptr(&pe->gf, pe->mmap_base, name, GGUF_TYPE_Q4_K);

        snprintf(name, sizeof(name), "blk.%d.attn_v.weight", l);
        pe->layers[l].v_weight = resolve_tensor_ptr(&pe->gf, pe->mmap_base, name, GGUF_TYPE_Q4_K);

        snprintf(name, sizeof(name), "blk.%d.attn_output.weight", l);
        pe->layers[l].o_weight = resolve_tensor_ptr(&pe->gf, pe->mmap_base, name, GGUF_TYPE_Q4_K);

        snprintf(name, sizeof(name), "blk.%d.ffn_gate.weight", l);
        pe->layers[l].gate_weight = resolve_tensor_ptr(&pe->gf, pe->mmap_base, name, GGUF_TYPE_Q4_K);

        snprintf(name, sizeof(name), "blk.%d.ffn_up.weight", l);
        pe->layers[l].up_weight = resolve_tensor_ptr(&pe->gf, pe->mmap_base, name, GGUF_TYPE_Q4_K);

        snprintf(name, sizeof(name), "blk.%d.ffn_down.weight", l);
        pe->layers[l].down_weight = resolve_tensor_ptr(&pe->gf, pe->mmap_base, name, GGUF_TYPE_Q4_K);

        snprintf(name, sizeof(name), "blk.%d.attn_norm.weight", l);
        pe->layers[l].attn_norm = (const float *)resolve_tensor_ptr(&pe->gf, pe->mmap_base,
                                                                     name, GGUF_TYPE_F32);

        snprintf(name, sizeof(name), "blk.%d.ffn_norm.weight", l);
        pe->layers[l].ffn_norm = (const float *)resolve_tensor_ptr(&pe->gf, pe->mmap_base,
                                                                    name, GGUF_TYPE_F32);

        if (!pe->layers[l].q_weight || !pe->layers[l].attn_norm || !pe->layers[l].ffn_norm) {
            fprintf(stderr, "policy: missing tensors for layer %d\n", l);
            free(pe->layers);
            munmap(pe->mmap_base, pe->mmap_size);
            gguf_close(&pe->gf);
            free(pe);
            return NULL;
        }
    }

    /* Allocate KV cache */
    pe->max_seq_len = max_seq_len;
    size_t kv_cache_size = (size_t)max_seq_len * (size_t)pe->gf.n_kv_heads * (size_t)pe->gf.head_dim;
    pe->k_cache = (float *)calloc(kv_cache_size, sizeof(float));
    pe->v_cache = (float *)calloc(kv_cache_size, sizeof(float));

    /* Allocate scratch buffers */
    pe->hidden = (float *)calloc((size_t)pe->gf.hidden_dim, sizeof(float));
    pe->q_buf = (float *)calloc((size_t)pe->gf.n_heads * (size_t)pe->gf.head_dim, sizeof(float));
    pe->k_buf = (float *)calloc((size_t)pe->gf.n_kv_heads * (size_t)pe->gf.head_dim, sizeof(float));
    pe->v_buf = (float *)calloc((size_t)pe->gf.n_kv_heads * (size_t)pe->gf.head_dim, sizeof(float));
    pe->attn_out = (float *)calloc((size_t)pe->gf.hidden_dim, sizeof(float));
    pe->ffn_gate = (float *)calloc((size_t)pe->gf.intermediate_dim, sizeof(float));
    pe->ffn_up = (float *)calloc((size_t)pe->gf.intermediate_dim, sizeof(float));
    pe->ffn_out = (float *)calloc((size_t)pe->gf.hidden_dim, sizeof(float));
    pe->logits = (float *)calloc((size_t)pe->gf.vocab_size, sizeof(float));

    if (!pe->k_cache || !pe->v_cache || !pe->hidden || !pe->logits) {
        fprintf(stderr, "policy: allocation failed\n");
        free(pe->k_cache);
        free(pe->v_cache);
        free(pe->hidden);
        free(pe->q_buf);
        free(pe->k_buf);
        free(pe->v_buf);
        free(pe->attn_out);
        free(pe->ffn_gate);
        free(pe->ffn_up);
        free(pe->ffn_out);
        free(pe->logits);
        free(pe->layers);
        munmap(pe->mmap_base, pe->mmap_size);
        gguf_close(&pe->gf);
        free(pe);
        return NULL;
    }

    pe->seq_pos = 0;
    return pe;
}

/* ─── Policy Engine Cleanup ─── */
static void policy_free(PolicyEngine *pe) {
    if (!pe) return;
    free(pe->k_cache);
    free(pe->v_cache);
    free(pe->hidden);
    free(pe->q_buf);
    free(pe->k_buf);
    free(pe->v_buf);
    free(pe->attn_out);
    free(pe->ffn_gate);
    free(pe->ffn_up);
    free(pe->ffn_out);
    free(pe->logits);
    free(pe->layers);
    if (pe->mmap_base != MAP_FAILED)
        munmap(pe->mmap_base, pe->mmap_size);
    gguf_close(&pe->gf);
    free(pe);
}

/* ─── Single-Token Forward Pass ─── */
static void policy_forward_token(PolicyEngine *pe, int token, int pos) {
    const int hidden_dim = (int)pe->gf.hidden_dim;
    const int intermediate_dim = (int)pe->gf.intermediate_dim;
    const int n_heads = (int)pe->gf.n_heads;
    const int n_kv_heads = (int)pe->gf.n_kv_heads;
    const int head_dim = (int)pe->gf.head_dim;
    const int vocab_size = (int)pe->gf.vocab_size;

    /* Embed token */
    const float *embed_row = pe->embed + (size_t)token * (size_t)hidden_dim;
    memcpy(pe->hidden, embed_row, (size_t)hidden_dim * sizeof(float));

    /* Run through transformer layers */
    for (int l = 0; l < pe->gf.n_layers; l++) {
        PolicyLayer *layer = &pe->layers[l];
        float *residual = (float *)malloc((size_t)hidden_dim * sizeof(float));
        memcpy(residual, pe->hidden, (size_t)hidden_dim * sizeof(float));

        /* Attention norm */
        grpo_rmsnorm(pe->hidden, residual, layer->attn_norm, hidden_dim, pe->gf.rms_eps);

        /* Q, K, V projections */
        grpo_matmul_q4(pe->q_buf, pe->hidden, layer->q_weight, n_heads * head_dim, hidden_dim);
        grpo_matmul_q4(pe->k_buf, pe->hidden, layer->k_weight, n_kv_heads * head_dim, hidden_dim);
        grpo_matmul_q4(pe->v_buf, pe->hidden, layer->v_weight, n_kv_heads * head_dim, hidden_dim);

        /* RoPE on Q and K */
        grpo_rope(pe->q_buf, pe->k_buf, pos, n_heads, head_dim, pe->gf.rope_theta);

        /* Store K, V in cache */
        size_t kv_offset = (size_t)pos * (size_t)n_kv_heads * (size_t)head_dim;
        memcpy(pe->k_cache + kv_offset, pe->k_buf, (size_t)n_kv_heads * (size_t)head_dim * sizeof(float));
        memcpy(pe->v_cache + kv_offset, pe->v_buf, (size_t)n_kv_heads * (size_t)head_dim * sizeof(float));

        /* GQA attention */
        grpo_gqa_attention(pe->attn_out, pe->q_buf, pe->k_cache, pe->v_cache,
                          n_heads, n_kv_heads, head_dim, pos);

        /* Output projection */
        grpo_matmul_q4(pe->hidden, pe->attn_out, layer->o_weight, hidden_dim, hidden_dim);

        /* Residual connection */
        for (int i = 0; i < hidden_dim; i++)
            pe->hidden[i] += residual[i];

        /* FFN */
        memcpy(residual, pe->hidden, (size_t)hidden_dim * sizeof(float));
        grpo_rmsnorm(pe->hidden, residual, layer->ffn_norm, hidden_dim, pe->gf.rms_eps);

        grpo_matmul_q4(pe->ffn_gate, pe->hidden, layer->gate_weight, intermediate_dim, hidden_dim);
        grpo_matmul_q4(pe->ffn_up, pe->hidden, layer->up_weight, intermediate_dim, hidden_dim);

        /* SiLU activation on gate and elementwise multiply with up */
        grpo_silu(pe->ffn_gate, intermediate_dim);
        for (int i = 0; i < intermediate_dim; i++)
            pe->ffn_gate[i] *= pe->ffn_up[i];

        /* Down projection */
        grpo_matmul_q4(pe->ffn_out, pe->ffn_gate, layer->down_weight, hidden_dim, intermediate_dim);

        /* Residual */
        for (int i = 0; i < hidden_dim; i++)
            pe->hidden[i] = residual[i] + pe->ffn_out[i];

        free(residual);
    }

    /* Final norm + output projection */
    grpo_rmsnorm(pe->hidden, pe->hidden, pe->output_norm, hidden_dim, pe->gf.rms_eps);

    /* Check if output weight is Q4_K or F32 */
    GgufTensor *out_tensor = gguf_find_tensor(&pe->gf, "output.weight");
    if (out_tensor && out_tensor->dtype == GGUF_TYPE_Q4_K) {
        grpo_matmul_q4(pe->logits, pe->hidden, pe->output_weight, vocab_size, hidden_dim);
    } else {
        grpo_matmul_f32(pe->logits, pe->hidden, (const float *)pe->output_weight,
                       vocab_size, vocab_size, hidden_dim);
    }
}

/* ─── Autoregressive Generation ─── */
static int policy_generate(PolicyEngine *pe, const int *prompt, int prompt_len,
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
        /* Compute probabilities for logprob capture */
        float *probs = (float *)malloc((size_t)pe->gf.vocab_size * sizeof(float));
        if (!probs) break;

        memcpy(probs, pe->logits, (size_t)pe->gf.vocab_size * sizeof(float));

        /* Apply temperature */
        if (temp != 1.0f) {
            for (int j = 0; j < pe->gf.vocab_size; j++)
                probs[j] /= temp;
        }

        grpo_softmax(probs, (int)pe->gf.vocab_size);

        /* Sample token */
        int token = grpo_top_p_sample(pe->logits, (int)pe->gf.vocab_size, temp, top_p, rng);
        output[i] = token;

        /* Capture logprob */
        if (logprobs_out)
            logprobs_out[i] = logf(probs[token] + 1e-10f);

        free(probs);

        /* Stop on EOS */
        if (token == 2) break; /* Common EOS token ID */
        total_gen++;

        /* Feed token back */
        policy_forward_token(pe, token, pe->seq_pos);
        pe->seq_pos++;

        if (pe->seq_pos >= pe->max_seq_len) break;
    }

    return total_gen;
}

/* ─── Teacher-Forced Logprobs ─── */
static int policy_logprobs(PolicyEngine *pe, const int *tokens, int len, float *logprobs_out) {
    pe->seq_pos = 0;

    for (int i = 0; i < len; i++) {
        policy_forward_token(pe, tokens[i], pe->seq_pos);
        pe->seq_pos++;

        /* Compute softmax probabilities */
        float *probs = (float *)malloc((size_t)pe->gf.vocab_size * sizeof(float));
        if (!probs) return -1;

        memcpy(probs, pe->logits, (size_t)pe->gf.vocab_size * sizeof(float));
        grpo_softmax(probs, (int)pe->gf.vocab_size);

        /* Get logprob of next token (if not last) */
        if (i + 1 < len) {
            int next_token = tokens[i + 1];
            logprobs_out[i] = logf(probs[next_token] + 1e-10f);
        }

        free(probs);
    }

    return 0;
}

/* ─── Public Interface (will be called by grpo_init/grpo_generate) ─── */

/* Note: These functions will be integrated into the main GRPO context in a later task.
 * For now, they are standalone and can be tested independently. */

PolicyEngine *grpo_policy_init(const char *gguf_path, int max_seq_len) {
    return policy_init(gguf_path, max_seq_len);
}

void grpo_policy_free(PolicyEngine *pe) {
    policy_free(pe);
}

int grpo_policy_generate_internal(PolicyEngine *pe, const int *prompt, int prompt_len,
                                  int *output, int max_len, float *logprobs_out,
                                  float temp, float top_p, unsigned int *rng) {
    return policy_generate(pe, prompt, prompt_len, output, max_len, logprobs_out, temp, top_p, rng);
}

int grpo_policy_logprobs_internal(PolicyEngine *pe, const int *tokens, int len, float *logprobs_out) {
    return policy_logprobs(pe, tokens, len, logprobs_out);
}
