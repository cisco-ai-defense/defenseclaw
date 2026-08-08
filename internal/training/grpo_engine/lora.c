/* lora.c — LoRA adapter injection, backward pass, Adam optimizer */
#include "grpo.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TARGETS 7  /* q,k,v,o,gate,up,down */
#define DCLORA_MAGIC "DCLORA01"

typedef struct {
    float *A;     /* [in_dim × rank] */
    float *B;     /* [rank × out_dim] */
    float *dA;    /* gradient accumulator */
    float *dB;
    float *mA;    /* Adam first moment */
    float *mB;
    float *vA;    /* Adam second moment */
    float *vB;
    float *x_stored; /* stored input activation for backward */
    int    in_dim;
    int    out_dim;
} LoRAAdapter;

typedef struct {
    LoRAAdapter adapters[MAX_TARGETS]; /* per-target for one layer */
} LoRALayer;

typedef struct {
    LoRALayer *layers;
    int        n_layers;
    int        rank;
    int        alpha;
    float      scale;   /* alpha / rank */
    int        hidden_dim;
    int        intermediate_dim;
} LoRAEngine;

/* ─── Initialization ─── */
void lora_init(LoRAEngine *le, int n_layers, int rank, int alpha,
               int hidden_dim, int intermediate_dim, int n_heads, int n_kv_heads, int head_dim) {
    le->n_layers = n_layers;
    le->rank = rank;
    le->alpha = alpha;
    le->scale = (float)alpha / (float)rank;
    le->hidden_dim = hidden_dim;
    le->intermediate_dim = intermediate_dim;
    le->layers = (LoRALayer *)calloc(n_layers, sizeof(LoRALayer));

    for (int l = 0; l < n_layers; l++) {
        int dims[][2] = {
            {hidden_dim, hidden_dim},                /* q_proj */
            {hidden_dim, n_kv_heads * head_dim},     /* k_proj */
            {hidden_dim, n_kv_heads * head_dim},     /* v_proj */
            {hidden_dim, hidden_dim},                /* o_proj */
            {hidden_dim, intermediate_dim},           /* gate_proj */
            {hidden_dim, intermediate_dim},           /* up_proj */
            {intermediate_dim, hidden_dim},           /* down_proj */
        };
        for (int t = 0; t < MAX_TARGETS; t++) {
            LoRAAdapter *a = &le->layers[l].adapters[t];
            a->in_dim = dims[t][0];
            a->out_dim = dims[t][1];
            int a_size = a->in_dim * rank;
            int b_size = rank * a->out_dim;
            a->A  = (float *)calloc(a_size, sizeof(float));
            a->B  = (float *)calloc(b_size, sizeof(float));
            a->dA = (float *)calloc(a_size, sizeof(float));
            a->dB = (float *)calloc(b_size, sizeof(float));
            a->mA = (float *)calloc(a_size, sizeof(float));
            a->mB = (float *)calloc(b_size, sizeof(float));
            a->vA = (float *)calloc(a_size, sizeof(float));
            a->vB = (float *)calloc(b_size, sizeof(float));
            a->x_stored = NULL; /* allocated per forward pass */

            /* Kaiming init for A, small random for B.
             * Standard LoRA initializes B=0, but that creates a bootstrap problem
             * for GRPO: ratio=1 when LoRA contribution is zero, so no gradient flows.
             * Small random B (1e-4 scale) gives initial non-zero LoRA output,
             * allowing the first ratio != 1.0 and breaking the circular dependency. */
            float std_a = sqrtf(2.0f / (float)a->in_dim);
            for (int i = 0; i < a_size; i++)
                a->A[i] = std_a * ((float)rand() / RAND_MAX - 0.5f) * 2.0f;
            float std_b = 0.01f;  /* Must be large enough to perturb base model output */
            for (int i = 0; i < b_size; i++)
                a->B[i] = std_b * ((float)rand() / RAND_MAX - 0.5f) * 2.0f;
        }
    }
}

/* ─── Forward Injection ─── */
/* Add LoRA contribution: output += (x @ A) @ B × scale
 * Stores x for backward pass. */
void lora_forward_inject(LoRAAdapter *a, float *output, const float *x,
                         int seq_len, int rank, float scale) {
    /* Store input for backward */
    size_t x_bytes = (size_t)seq_len * a->in_dim * sizeof(float);
    a->x_stored = (float *)realloc(a->x_stored, x_bytes);
    memcpy(a->x_stored, x, x_bytes);

    /* h = x @ A  [seq_len × rank] */
    float *h = (float *)malloc(seq_len * rank * sizeof(float));
    for (int s = 0; s < seq_len; s++)
        grpo_matmul_f32(h + s * rank, x + s * a->in_dim, a->A, rank, a->in_dim, a->in_dim);

    /* output += h @ B × scale  [seq_len × out_dim] */
    for (int s = 0; s < seq_len; s++) {
        float *out_s = output + s * a->out_dim;
        for (int r = 0; r < a->out_dim; r++) {
            double acc = 0.0;
            for (int c = 0; c < rank; c++)
                acc += (double)h[s * rank + c] * (double)a->B[c * a->out_dim + r];
            out_s[r] += (float)acc * scale;
        }
    }
    free(h);
}

/* ─── Backward Pass ─── */
void lora_backward(LoRAAdapter *a, const float *dL_dy, int seq_len, int rank, float scale) {
    /* h = x_stored @ A */
    float *h = (float *)malloc(seq_len * rank * sizeof(float));
    for (int s = 0; s < seq_len; s++)
        grpo_matmul_f32(h + s * rank, a->x_stored + s * a->in_dim, a->A, rank, a->in_dim, a->in_dim);

    /* dB += h^T @ dL_dy × scale  [rank × out_dim] */
    for (int r = 0; r < rank; r++) {
        for (int o = 0; o < a->out_dim; o++) {
            double acc = 0.0;
            for (int s = 0; s < seq_len; s++)
                acc += (double)h[s * rank + r] * (double)dL_dy[s * a->out_dim + o];
            a->dB[r * a->out_dim + o] += (float)acc * scale;
        }
    }

    /* dh = dL_dy @ B^T  [seq_len × rank] */
    float *dh = (float *)malloc(seq_len * rank * sizeof(float));
    for (int s = 0; s < seq_len; s++) {
        for (int r = 0; r < rank; r++) {
            double acc = 0.0;
            for (int o = 0; o < a->out_dim; o++)
                acc += (double)dL_dy[s * a->out_dim + o] * (double)a->B[r * a->out_dim + o];
            dh[s * rank + r] = (float)acc;
        }
    }

    /* dA += x^T @ dh × scale  [in_dim × rank] */
    for (int i = 0; i < a->in_dim; i++) {
        for (int r = 0; r < rank; r++) {
            double acc = 0.0;
            for (int s = 0; s < seq_len; s++)
                acc += (double)a->x_stored[s * a->in_dim + i] * (double)dh[s * rank + r];
            a->dA[i * rank + r] += (float)acc * scale;
        }
    }

    free(h);
    free(dh);
}

/* ─── Adam Optimizer Step ─── */
void lora_adam_step(LoRAEngine *le, float lr, float beta1, float beta2, float eps, int step) {
    float bc1 = 1.0f - powf(beta1, (float)step);
    float bc2 = 1.0f - powf(beta2, (float)step);

    for (int l = 0; l < le->n_layers; l++) {
        for (int t = 0; t < MAX_TARGETS; t++) {
            LoRAAdapter *a = &le->layers[l].adapters[t];
            int a_size = a->in_dim * le->rank;
            int b_size = le->rank * a->out_dim;

            /* Update A */
            for (int i = 0; i < a_size; i++) {
                a->mA[i] = beta1 * a->mA[i] + (1.0f - beta1) * a->dA[i];
                a->vA[i] = beta2 * a->vA[i] + (1.0f - beta2) * a->dA[i] * a->dA[i];
                float m_hat = a->mA[i] / bc1;
                float v_hat = a->vA[i] / bc2;
                a->A[i] -= lr * m_hat / (sqrtf(v_hat) + eps);
            }

            /* Update B */
            for (int i = 0; i < b_size; i++) {
                a->mB[i] = beta1 * a->mB[i] + (1.0f - beta1) * a->dB[i];
                a->vB[i] = beta2 * a->vB[i] + (1.0f - beta2) * a->dB[i] * a->dB[i];
                float m_hat = a->mB[i] / bc1;
                float v_hat = a->vB[i] / bc2;
                a->B[i] -= lr * m_hat / (sqrtf(v_hat) + eps);
            }

            /* Zero gradients */
            memset(a->dA, 0, a_size * sizeof(float));
            memset(a->dB, 0, b_size * sizeof(float));
        }
    }
}

/* ─── Save Checkpoint ─── */
int lora_save(LoRAEngine *le, const char *path, int step, float loss) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    /* Header: 64 bytes */
    char header[64] = {0};
    memcpy(header, DCLORA_MAGIC, 8);
    *(uint32_t *)(header + 8) = (uint32_t)le->n_layers;
    *(uint32_t *)(header + 12) = (uint32_t)le->rank;
    *(uint32_t *)(header + 16) = MAX_TARGETS;
    *(uint32_t *)(header + 20) = (uint32_t)step;
    *(float *)(header + 24) = loss;
    *(uint32_t *)(header + 28) = (uint32_t)le->hidden_dim;
    *(uint32_t *)(header + 32) = (uint32_t)le->intermediate_dim;
    fwrite(header, 1, 64, f);

    /* Write all adapter weights + Adam state */
    for (int l = 0; l < le->n_layers; l++) {
        for (int t = 0; t < MAX_TARGETS; t++) {
            LoRAAdapter *a = &le->layers[l].adapters[t];
            int a_size = a->in_dim * le->rank;
            int b_size = le->rank * a->out_dim;
            fwrite(a->A, sizeof(float), a_size, f);
            fwrite(a->B, sizeof(float), b_size, f);
            fwrite(a->mA, sizeof(float), a_size, f);
            fwrite(a->mB, sizeof(float), b_size, f);
            fwrite(a->vA, sizeof(float), a_size, f);
            fwrite(a->vB, sizeof(float), b_size, f);
        }
    }
    fclose(f);
    return 0;
}

/* ─── Load Checkpoint ─── */
int lora_load(LoRAEngine *le, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    /* Read header */
    char header[64];
    if (fread(header, 1, 64, f) != 64) {
        fclose(f);
        return -1;
    }

    /* Validate magic */
    if (memcmp(header, DCLORA_MAGIC, 8) != 0) {
        fclose(f);
        return -1;
    }

    uint32_t n_layers = *(uint32_t *)(header + 8);
    uint32_t rank = *(uint32_t *)(header + 12);
    uint32_t n_targets = *(uint32_t *)(header + 16);

    /* Validate dimensions match */
    if ((int)n_layers != le->n_layers || (int)rank != le->rank || n_targets != MAX_TARGETS) {
        fclose(f);
        return -1;
    }

    /* Load all adapter weights + Adam state */
    for (int l = 0; l < le->n_layers; l++) {
        for (int t = 0; t < MAX_TARGETS; t++) {
            LoRAAdapter *a = &le->layers[l].adapters[t];
            int a_size = a->in_dim * le->rank;
            int b_size = le->rank * a->out_dim;

            if (fread(a->A, sizeof(float), a_size, f) != (size_t)a_size) goto error;
            if (fread(a->B, sizeof(float), b_size, f) != (size_t)b_size) goto error;
            if (fread(a->mA, sizeof(float), a_size, f) != (size_t)a_size) goto error;
            if (fread(a->mB, sizeof(float), b_size, f) != (size_t)b_size) goto error;
            if (fread(a->vA, sizeof(float), a_size, f) != (size_t)a_size) goto error;
            if (fread(a->vB, sizeof(float), b_size, f) != (size_t)b_size) goto error;
        }
    }

    fclose(f);
    return 0;

error:
    fclose(f);
    return -1;
}

/* ─── Export Merged GGUF ─── */
/* Merge LoRA into base weights: W_merged = dequant(W_q4) + A@B × scale
 * Re-quantize to Q4 and write GGUF.
 * NOTE: This is a placeholder implementation. Full GGUF writing requires
 * significant additional infrastructure (metadata, tensor packing, etc.) */
int lora_export_merged(LoRAEngine *le, GgufFile *base_gf, const char *output_path) {
    /* For now, return error - full implementation requires GGUF writer */
    (void)le;
    (void)base_gf;
    (void)output_path;
    fprintf(stderr, "lora_export_merged: not yet implemented\n");
    return -1;
}

/* ─── Free ─── */
void lora_free(LoRAEngine *le) {
    if (!le || !le->layers) return;

    for (int l = 0; l < le->n_layers; l++) {
        for (int t = 0; t < MAX_TARGETS; t++) {
            LoRAAdapter *a = &le->layers[l].adapters[t];
            free(a->A);
            free(a->B);
            free(a->dA);
            free(a->dB);
            free(a->mA);
            free(a->mB);
            free(a->vA);
            free(a->vB);
            free(a->x_stored);
        }
    }
    free(le->layers);
    le->layers = NULL;
}
