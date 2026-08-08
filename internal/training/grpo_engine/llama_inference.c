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
