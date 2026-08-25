## Task 5: LoRA Engine (Forward Injection + Backward + Adam)

**Files:**
- Modify: `internal/training/grpo_engine/lora.c` (replace stub)

**Interfaces:**
- Consumes: Policy forward pass (Task 3), kernels (Task 2)
- Produces: `lora_init()`, `lora_forward_inject()`, `lora_backward()`, `lora_adam_step()`, `lora_save()`, `lora_load()`, `lora_export_merged()`

- [ ] **Step 1: Implement LoRA weight allocation and initialization**

```c
/* lora.c — LoRA adapter injection, backward pass, Adam optimizer */
#include "grpo.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TARGETS 7  /* q,k,v,o,gate,up,down */

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
} LoRAEngine;

void lora_init(LoRAEngine *le, int n_layers, int rank, int alpha,
               int hidden_dim, int intermediate_dim, int n_heads, int n_kv_heads, int head_dim) {
    le->n_layers = n_layers;
    le->rank = rank;
    le->alpha = alpha;
    le->scale = (float)alpha / (float)rank;
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

            /* Kaiming init for A, zeros for B */
            float std = sqrtf(2.0f / (float)a->in_dim);
            for (int i = 0; i < a_size; i++)
                a->A[i] = std * ((float)rand() / RAND_MAX - 0.5f) * 2.0f;
        }
    }
}
```

- [ ] **Step 2: Implement LoRA forward injection**

```c
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
```

- [ ] **Step 3: Implement LoRA backward pass**

```c
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
```

- [ ] **Step 4: Implement Adam optimizer step**

```c
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
```

- [ ] **Step 5: Implement save/load checkpoint (.dclora format)**

```c
#define DCLORA_MAGIC "DCLORA01"

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
```

- [ ] **Step 6: Build and verify**

Run: `make -C internal/training/grpo_engine`
Expected: Compiles without errors.

- [ ] **Step 7: Commit**

```bash
git add internal/training/grpo_engine/lora.c
git commit -m "feat(training): implement LoRA engine with forward injection, backward, Adam, and checkpointing"
```

---

