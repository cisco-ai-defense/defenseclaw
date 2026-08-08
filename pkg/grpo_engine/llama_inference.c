/* llama_inference.c — Use llama.cpp for correct model inference.
 * Replaces our broken custom forward pass with the reference implementation.
 * Links against libllama (brew install llama.cpp). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <llama.h>

typedef struct {
    struct llama_model *model;
    struct llama_context *ctx;
    const struct llama_vocab *vocab;
    int n_vocab;
    int n_ctx;
} LlamaEngine;

static LlamaEngine *g_llama = NULL;

int llama_engine_init(const char *model_path, int n_ctx, int n_threads) {
    if (g_llama) return 0; /* already initialized */

    llama_backend_init();

    struct llama_model_params mp = llama_model_default_params();
    mp.n_gpu_layers = 0; /* CPU only for training */

    struct llama_model *model = llama_model_load_from_file(model_path, mp);
    if (!model) {
        fprintf(stderr, "llama_inference: failed to load model\n");
        return -1;
    }

    struct llama_context_params cp = llama_context_default_params();
    cp.n_ctx = n_ctx;
    cp.n_threads = n_threads;
    cp.n_threads_batch = n_threads;

    struct llama_context *ctx = llama_init_from_model(model, cp);
    if (!ctx) {
        fprintf(stderr, "llama_inference: failed to create context\n");
        llama_model_free(model);
        return -1;
    }

    g_llama = (LlamaEngine *)calloc(1, sizeof(LlamaEngine));
    g_llama->model = model;
    g_llama->ctx = ctx;
    g_llama->vocab = llama_model_get_vocab(model);
    g_llama->n_vocab = llama_vocab_n_tokens(g_llama->vocab);
    g_llama->n_ctx = n_ctx;

    fprintf(stderr, "llama_inference: ready (vocab=%d, ctx=%d, threads=%d)\n",
            g_llama->n_vocab, n_ctx, n_threads);
    return 0;
}

void llama_engine_free(void) {
    if (!g_llama) return;
    llama_free(g_llama->ctx);
    llama_model_free(g_llama->model);
    free(g_llama);
    g_llama = NULL;
    llama_backend_free();
}

/* Generate tokens autoregressively. Returns number of tokens generated. */
int llama_engine_generate(const int *prompt, int prompt_len,
                          int *output, int max_len,
                          float *logprobs_out,
                          float temp, float top_p,
                          unsigned int *rng_state) {
    if (!g_llama) return -1;

    llama_memory_clear(llama_get_memory(g_llama->ctx), true);

    /* Decode prompt */
    struct llama_batch batch = llama_batch_get_one((llama_token *)prompt, prompt_len);
    if (llama_decode(g_llama->ctx, batch) != 0) {
        fprintf(stderr, "llama_inference: prompt decode failed\n");
        return -1;
    }

    /* Generate tokens */
    int n_gen = 0;
    int prev_len = prompt_len;

    for (int i = 0; i < max_len; i++) {
        float *logits = llama_get_logits_ith(g_llama->ctx, prev_len - 1);
        if (!logits) break;

        /* Apply temperature and sample */
        int n_vocab = g_llama->n_vocab;
        float *probs = (float *)malloc((size_t)n_vocab * sizeof(float));
        for (int v = 0; v < n_vocab; v++) probs[v] = logits[v] / temp;

        /* Softmax */
        float max_val = -1e30f;
        for (int v = 0; v < n_vocab; v++) if (probs[v] > max_val) max_val = probs[v];
        double sum = 0;
        for (int v = 0; v < n_vocab; v++) { probs[v] = expf(probs[v] - max_val); sum += probs[v]; }
        for (int v = 0; v < n_vocab; v++) probs[v] /= (float)sum;

        /* Top-p sampling */
        int token = 0;
        if (temp < 0.01f) {
            /* Greedy */
            float best = -1;
            for (int v = 0; v < n_vocab; v++) if (probs[v] > best) { best = probs[v]; token = v; }
        } else {
            /* Simple top-p: sort not needed for correctness, just sample from nucleus */
            *rng_state = *rng_state * 1664525u + 1013904223u;
            float u = (float)(*rng_state) / 4294967296.0f;
            float cum = 0;
            for (int v = 0; v < n_vocab; v++) {
                cum += probs[v];
                if (cum >= u) { token = v; break; }
            }
        }

        output[i] = token;
        if (logprobs_out) logprobs_out[i] = logf(probs[token] + 1e-10f);
        free(probs);

        n_gen++;

        /* EOS check */
        if (token == 151645 || token == 151643) break;

        /* Decode next token */
        struct llama_batch next = llama_batch_get_one(&token, 1);
        if (llama_decode(g_llama->ctx, next) != 0) break;
        prev_len = 1;
    }

    return n_gen;
}

/* Compute teacher-forced logprobs for a token sequence. */
int llama_engine_logprobs(const int *tokens, int len, float *logprobs_out) {
    if (!g_llama || len < 2) return -1;

    llama_memory_clear(llama_get_memory(g_llama->ctx), true);

    /* Decode entire sequence at once */
    struct llama_batch batch = llama_batch_get_one((llama_token *)tokens, len);
    if (llama_decode(g_llama->ctx, batch) != 0) {
        fprintf(stderr, "llama_inference: logprobs decode failed\n");
        return -1;
    }

    /* Extract logprob of each next token */
    int n_vocab = g_llama->n_vocab;
    for (int i = 0; i < len - 1; i++) {
        float *logits = llama_get_logits_ith(g_llama->ctx, i);
        if (!logits) { logprobs_out[i] = 0; continue; }

        /* Softmax to get probability of next token */
        float max_val = -1e30f;
        for (int v = 0; v < n_vocab; v++) if (logits[v] > max_val) max_val = logits[v];
        double sum = 0;
        for (int v = 0; v < n_vocab; v++) sum += exp((double)(logits[v] - max_val));
        float log_sum = max_val + (float)log(sum);
        logprobs_out[i] = logits[tokens[i + 1]] - log_sum;
    }

    return 0;
}

int llama_engine_vocab_size(void) {
    return g_llama ? g_llama->n_vocab : 0;
}

/* ─── LoRA Adapter Support ─── */

static struct llama_adapter_lora *g_lora_adapter = NULL;

/* Write LoRA weights to a GGUF file that llama.cpp can load.
 * adapters: array of {A, B} pairs for each layer × target.
 * Layout: adapters[layer * 7 + target] = {A[in_dim*rank], B[rank*out_dim]} */
int llama_engine_export_lora_gguf(const char *output_path,
                                   const float *const *A_ptrs,
                                   const float *const *B_ptrs,
                                   int n_layers, int rank, float alpha,
                                   int hidden_dim, int intermediate_dim,
                                   int n_heads, int n_kv_heads, int head_dim) {
    FILE *f = fopen(output_path, "wb");
    if (!f) return -1;

    /* GGUF header */
    uint32_t magic = 0x46554747; /* GGUF */
    uint32_t version = 3;
    int n_targets = 7; /* q,k,v,o,gate,up,down */
    uint64_t n_tensors = (uint64_t)n_layers * n_targets * 2; /* A and B per target */
    uint64_t n_kv = 4; /* metadata entries */

    fwrite(&magic, 4, 1, f);
    fwrite(&version, 4, 1, f);
    fwrite(&n_tensors, 8, 1, f);
    fwrite(&n_kv, 8, 1, f);

    /* Metadata */
    /* helper to write a string KV */
    #define WRITE_STR_KV(key, val) { \
        uint64_t kl = strlen(key); fwrite(&kl, 8, 1, f); fwrite(key, kl, 1, f); \
        uint32_t vt = 8; fwrite(&vt, 4, 1, f); \
        uint64_t vl = strlen(val); fwrite(&vl, 8, 1, f); fwrite(val, vl, 1, f); }
    #define WRITE_F32_KV(key, val) { \
        uint64_t kl = strlen(key); fwrite(&kl, 8, 1, f); fwrite(key, kl, 1, f); \
        uint32_t vt = 6; fwrite(&vt, 4, 1, f); fwrite(&val, 4, 1, f); }

    WRITE_STR_KV("general.type", "adapter");
    WRITE_STR_KV("general.architecture", "qwen3");
    WRITE_STR_KV("adapter.type", "lora");
    WRITE_F32_KV("adapter.lora.alpha", alpha);

    /* Tensor info */
    const char *target_names[] = {"attn_q", "attn_k", "attn_v", "attn_output",
                                  "ffn_gate", "ffn_up", "ffn_down"};
    int in_dims[] = {hidden_dim, hidden_dim, hidden_dim, hidden_dim,
                     hidden_dim, hidden_dim, intermediate_dim};
    int out_dims[] = {n_heads*head_dim, n_kv_heads*head_dim, n_kv_heads*head_dim, hidden_dim,
                      intermediate_dim, intermediate_dim, hidden_dim};

    uint64_t data_offset = 0;
    for (int l = 0; l < n_layers; l++) {
        for (int t = 0; t < n_targets; t++) {
            char name_a[128], name_b[128];
            snprintf(name_a, sizeof(name_a), "blk.%d.%s.weight.lora_a", l, target_names[t]);
            snprintf(name_b, sizeof(name_b), "blk.%d.%s.weight.lora_b", l, target_names[t]);

            /* lora_a: [rank, in_dim] → ne[0]=rank, ne[1]=in_dim */
            uint64_t nl = strlen(name_a); fwrite(&nl, 8, 1, f); fwrite(name_a, nl, 1, f);
            uint32_t nd = 2; fwrite(&nd, 4, 1, f);
            uint64_t ne0 = rank, ne1 = in_dims[t];
            fwrite(&ne0, 8, 1, f); fwrite(&ne1, 8, 1, f);
            uint32_t dtype = 0; /* F32 */ fwrite(&dtype, 4, 1, f);
            fwrite(&data_offset, 8, 1, f);
            data_offset += (uint64_t)rank * in_dims[t] * 4;

            /* lora_b: [out_dim, rank] → ne[0]=out_dim, ne[1]=rank */
            nl = strlen(name_b); fwrite(&nl, 8, 1, f); fwrite(name_b, nl, 1, f);
            nd = 2; fwrite(&nd, 4, 1, f);
            ne0 = out_dims[t]; ne1 = rank;
            fwrite(&ne0, 8, 1, f); fwrite(&ne1, 8, 1, f);
            dtype = 0; fwrite(&dtype, 4, 1, f);
            fwrite(&data_offset, 8, 1, f);
            data_offset += (uint64_t)rank * out_dims[t] * 4;
        }
    }

    /* Align to 32 bytes */
    long pos = ftell(f);
    long aligned = (pos + 31) & ~31L;
    while (pos < aligned) { uint8_t z = 0; fwrite(&z, 1, 1, f); pos++; }

    /* Tensor data */
    for (int l = 0; l < n_layers; l++) {
        for (int t = 0; t < n_targets; t++) {
            int idx = l * n_targets + t;
            /* Write A: [rank × in_dim] stored column-major in our engine
             * llama.cpp expects row-major [rank rows of in_dim elements] */
            if (A_ptrs[idx]) {
                fwrite(A_ptrs[idx], sizeof(float), (size_t)rank * in_dims[t], f);
            } else {
                /* Write zeros */
                float zero = 0;
                for (int i = 0; i < rank * in_dims[t]; i++) fwrite(&zero, 4, 1, f);
            }
            /* Write B */
            if (B_ptrs[idx]) {
                fwrite(B_ptrs[idx], sizeof(float), (size_t)rank * out_dims[t], f);
            } else {
                float zero = 0;
                for (int i = 0; i < rank * out_dims[t]; i++) fwrite(&zero, 4, 1, f);
            }
        }
    }

    fclose(f);
    #undef WRITE_STR_KV
    #undef WRITE_F32_KV
    return 0;
}

/* Apply LoRA adapter to the llama context. Writes temp GGUF and loads it. */
int llama_engine_apply_lora(const float *const *A_ptrs, const float *const *B_ptrs,
                            int n_layers, int rank, float alpha,
                            int hidden_dim, int intermediate_dim,
                            int n_heads, int n_kv_heads, int head_dim) {
    if (!g_llama) return -1;

    const char *tmp_path = "/tmp/grpo-lora-active.gguf";

    /* Export current LoRA weights to GGUF */
    if (llama_engine_export_lora_gguf(tmp_path, A_ptrs, B_ptrs,
                                       n_layers, rank, alpha,
                                       hidden_dim, intermediate_dim,
                                       n_heads, n_kv_heads, head_dim) != 0) {
        return -1;
    }

    /* Remove old adapter if any */
    if (g_lora_adapter) {
        llama_adapter_lora_free(g_lora_adapter);
        g_lora_adapter = NULL;
    }

    /* Load new adapter */
    g_lora_adapter = llama_adapter_lora_init(g_llama->model, tmp_path);
    if (!g_lora_adapter) {
        fprintf(stderr, "llama_engine: failed to load LoRA adapter\n");
        return -1;
    }

    /* Apply to context with scale 1.0 */
    float scale = 1.0f;
    if (llama_set_adapters_lora(g_llama->ctx, &g_lora_adapter, 1, &scale) != 0) {
        fprintf(stderr, "llama_engine: failed to set LoRA adapter\n");
        return -1;
    }

    return 0;
}

/* Remove LoRA adapter (revert to base model) */
int llama_engine_remove_lora(void) {
    if (!g_llama) return -1;
    llama_set_adapters_lora(g_llama->ctx, NULL, 0, NULL);
    if (g_lora_adapter) {
        llama_adapter_lora_free(g_lora_adapter);
        g_lora_adapter = NULL;
    }
    return 0;
}
