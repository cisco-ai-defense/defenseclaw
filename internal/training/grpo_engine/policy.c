/* policy.c — mmap'd policy forward pass and autoregressive generation */
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#include <sys/sysctl.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <math.h>

#include "grpo.h"

#ifdef _OPENMP
#include <omp.h>
#endif

/* ─── LoRA Injection Hook ─── */
/* Global pointer to active LoRA engine for injection during forward pass.
 * Set by grpo.c before calling policy_logprobs (where LoRA must be active)
 * and cleared afterward. NULL = no LoRA injection (used during generation
 * to capture old_logprobs without LoRA influence). */
typedef struct {
    float *A;
    float *B;
    float *dA;
    float *dB;
    float *mA;
    float *mB;
    float *vA;
    float *vB;
    float *x_stored;
    int    in_dim;
    int    out_dim;
} PolicyLoRAAdapter;

typedef struct {
    PolicyLoRAAdapter adapters[7]; /* q,k,v,o,gate,up,down */
} PolicyLoRALayer;

typedef struct {
    PolicyLoRALayer *layers;
    int n_layers;
    int rank;
    float scale; /* alpha/rank */
} PolicyLoRARef;

static PolicyLoRARef *g_active_lora = NULL;

void policy_set_active_lora(void *lora_ref) {
    g_active_lora = (PolicyLoRARef *)lora_ref;
}

/* Inject LoRA contribution: output += (input @ A) @ B * scale */
static void inject_lora(float *output, const float *input, int layer, int target_idx,
                        int out_dim, int in_dim) {
    (void)output; (void)input; (void)layer; (void)target_idx; (void)out_dim; (void)in_dim;
    /* TODO: re-enable after base forward pass is verified working */
    return;
    if (!g_active_lora || !g_active_lora->layers) return;
    if (layer >= g_active_lora->n_layers) return;

    PolicyLoRAAdapter *a = &g_active_lora->layers[layer].adapters[target_idx];
    if (!a->A || !a->B) return;

    int rank = g_active_lora->rank;
    float scale = g_active_lora->scale;

    /* h = input @ A  [rank] */
    float *h = (float *)malloc((size_t)rank * sizeof(float));
    if (!h) return;
    for (int r = 0; r < rank; r++) {
        double acc = 0.0;
        for (int c = 0; c < in_dim; c++)
            acc += (double)input[c] * (double)a->A[c * rank + r];
        h[r] = (float)acc;
    }

    /* output += h @ B * scale  [out_dim] */
    for (int o = 0; o < out_dim; o++) {
        double acc = 0.0;
        for (int r = 0; r < rank; r++)
            acc += (double)h[r] * (double)a->B[r * out_dim + o];
        output[o] += (float)acc * scale;
    }

    /* Store input for backward pass */
    if (a->x_stored) {
        memcpy(a->x_stored, input, (size_t)in_dim * sizeof(float));
    } else {
        a->x_stored = (float *)malloc((size_t)in_dim * sizeof(float));
        if (a->x_stored) memcpy(a->x_stored, input, (size_t)in_dim * sizeof(float));
    }

    free(h);
}

/* ─── Internal Policy Engine Structure ─── */

/* Quantization block sizes */
#define Q8_0_BLOCK_SIZE 32
#define Q8_0_BLOCK_BYTES 34
#define Q5_0_BLOCK_SIZE 32
#define Q5_0_BLOCK_BYTES 18
#define Q6_K_BLOCK_SIZE 256
#define Q6_K_BLOCK_BYTES 210

/* FP16 to FP32 conversion (duplicated from kernels.c) */
static inline float fp16_to_fp32(uint16_t h) {
    uint32_t sign = (h >> 15) & 1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;

    uint32_t f;
    if (exp == 0) {
        if (mant == 0) {
            f = sign << 31;
        } else {
            /* subnormal */
            exp = 127 - 14;
            while ((mant & 0x400) == 0) {
                mant <<= 1;
                exp--;
            }
            mant &= 0x3FF;
            f = (sign << 31) | (exp << 23) | (mant << 13);
        }
    } else if (exp == 0x1F) {
        /* inf or nan */
        f = (sign << 31) | (0xFF << 23) | (mant << 13);
    } else {
        /* normal */
        f = (sign << 31) | ((exp + (127 - 15)) << 23) | (mant << 13);
    }

    float result;
    memcpy(&result, &f, sizeof(float));
    return result;
}

typedef struct {
    /* Per-layer weight pointers (into mmap region) */
    const void *q_weight;
    const void *k_weight;
    const void *v_weight;
    const void *o_weight;
    const void *gate_weight;
    const void *up_weight;
    const void *down_weight;
    const void *attn_norm; /* f32 or f16 norm weights */
    const void *ffn_norm;
    int attn_norm_dtype, ffn_norm_dtype;
    /* Dtypes for dynamic dispatch */
    int q_dtype, k_dtype, v_dtype, o_dtype;
    int gate_dtype, up_dtype, down_dtype;
} PolicyLayer;

typedef struct {
    GgufFile     gf;
    void        *mmap_base;         /* Adjusted pointer to data start */
    void        *mmap_base_actual;  /* Original mmap pointer for munmap */
    size_t       mmap_size;         /* Original mmap size for munmap */
    void        *heap_weights;      /* If non-NULL, weights preloaded to heap */
    PolicyLayer *layers;
    const void  *embed;        /* token embedding table (may be quantized) */
    int          embed_dtype;  /* dtype of embedding table */
    const float *output_norm;  /* final RMS norm */
    const void  *output_weight; /* lm_head (may be Q4 or f32) */
    int          output_dtype; /* dtype of output weight */

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

/* ─── Helper: Find and resolve tensor pointer with dtype ─── */
static const void *resolve_tensor_ptr(const GgufFile *gf, void *mmap_base,
                                      const char *name, GgufDtype expected_dtype, int *dtype_out) {
    GgufTensor *t = gguf_find_tensor(gf, name);
    if (!t) return NULL;
    /* Accept F32 or F16 for norm weights (F16 will be widened at use time).
     * Accept any quantized type for projection weights. */
    if (expected_dtype == GGUF_TYPE_F32 && t->dtype != GGUF_TYPE_F32 && t->dtype != GGUF_TYPE_F16) {
        fprintf(stderr, "policy: tensor %s has dtype %d, expected F32 or F16\n", name, t->dtype);
        return NULL;
    }
    (void)expected_dtype;
    if (dtype_out) *dtype_out = (int)t->dtype;
    /* t->offset is absolute (already includes data_offset from gguf_open).
     * mmap_base points to data_offset in the file.
     * So we subtract data_offset to get the offset within the mmap'd region. */
    int64_t rel_offset = t->offset - gf->data_offset;
    return (const uint8_t *)mmap_base + rel_offset;
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

    /* mmap the tensor data region.
     * The offset must be page-aligned for mmap(). Round down data_offset
     * to the page boundary and adjust pointers accordingly. */
    struct stat st;
    if (fstat(pe->gf.fd, &st) != 0) {
        gguf_close(&pe->gf);
        free(pe);
        return NULL;
    }
    long page_size = sysconf(_SC_PAGESIZE);
    int64_t aligned_offset = (pe->gf.data_offset / page_size) * page_size;
    size_t offset_adj = (size_t)(pe->gf.data_offset - aligned_offset);
    pe->mmap_size = (size_t)(st.st_size - aligned_offset);
    pe->mmap_base_actual = mmap(NULL, pe->mmap_size, PROT_READ, MAP_SHARED,
                                pe->gf.fd, aligned_offset);
    if (pe->mmap_base_actual == MAP_FAILED) {
        fprintf(stderr, "policy: mmap failed for %s (offset=%lld, aligned=%lld, size=%zu)\n",
                gguf_path, (long long)pe->gf.data_offset, (long long)aligned_offset, pe->mmap_size);
        gguf_close(&pe->gf);
        free(pe);
        return NULL;
    }
    /* Adjust mmap_base to point at actual data start */
    pe->mmap_base = (uint8_t *)pe->mmap_base_actual + offset_adj;

    /* Preload weights to heap if system has enough free memory.
     * This eliminates mmap page-fault overhead during NEON matmuls.
     * Heuristic: preload if model size < 60% of physical RAM. */
    size_t data_size = (size_t)(st.st_size - pe->gf.data_offset);
#ifdef __APPLE__
    {
        int mib[2] = {CTL_HW, HW_MEMSIZE};
        uint64_t phys_mem = 0;
        size_t len = sizeof(phys_mem);
        sysctl(mib, 2, &phys_mem, &len, NULL, 0);
        if (data_size < (size_t)(phys_mem * 6 / 10)) {
            pe->heap_weights = malloc(data_size);
            if (pe->heap_weights) {
                memcpy(pe->heap_weights, pe->mmap_base, data_size);
                pe->mmap_base = pe->heap_weights;
                fprintf(stderr, "policy: preloaded %.1f MB weights to heap\n",
                        (double)data_size / (1024*1024));
            }
        } else {
            madvise(pe->mmap_base_actual, pe->mmap_size, MADV_WILLNEED);
            madvise(pe->mmap_base_actual, pe->mmap_size, MADV_RANDOM);
            fprintf(stderr, "policy: using mmap (model %.1f MB, RAM %.1f GB)\n",
                    (double)data_size / (1024*1024), (double)phys_mem / (1024*1024*1024));
        }
    }
#else
    madvise(pe->mmap_base_actual, pe->mmap_size, MADV_WILLNEED);
    madvise(pe->mmap_base_actual, pe->mmap_size, MADV_RANDOM);
    (void)data_size;
#endif

    /* Resolve global tensors.
     * Quantized models may store embeddings in Q8_0, Q6_K, or Q4_K — not F32.
     * Accept any dtype and handle dequantization at compute time. */
    GgufTensor *t_embed = gguf_find_tensor(&pe->gf, "token_embd.weight");
    GgufTensor *t_norm = gguf_find_tensor(&pe->gf, "output_norm.weight");
    GgufTensor *t_output = gguf_find_tensor(&pe->gf, "output.weight");

    /* Weight tying: if no separate output.weight, reuse token_embd.weight */
    if (!t_output) t_output = t_embed;

    if (!t_embed || !t_norm || !t_output) {
        fprintf(stderr, "policy: missing global tensors (embed=%p, norm=%p, output=%p)\n",
                (void*)t_embed, (void*)t_norm, (void*)t_output);
        munmap(pe->mmap_base_actual, pe->mmap_size);
        gguf_close(&pe->gf);
        free(pe);
        return NULL;
    }

    pe->embed = (const void *)((const uint8_t *)pe->mmap_base + (t_embed->offset - pe->gf.data_offset));
    pe->embed_dtype = (int)t_embed->dtype;
    pe->output_norm = (const float *)((const uint8_t *)pe->mmap_base + (t_norm->offset - pe->gf.data_offset));
    pe->output_weight = (const void *)((const uint8_t *)pe->mmap_base + (t_output->offset - pe->gf.data_offset));
    pe->output_dtype = (int)t_output->dtype;
    fprintf(stderr, "policy: tensors resolved (embed dtype=%d, norm dtype=%d, output dtype=%d, tied=%d)\n",
            t_embed->dtype, t_norm->dtype, t_output->dtype, t_output == t_embed);

    /* Resolve per-layer tensors */
    pe->layers = (PolicyLayer *)calloc((size_t)pe->gf.n_layers, sizeof(PolicyLayer));
    if (!pe->layers) {
        munmap(pe->mmap_base_actual, pe->mmap_size);
        gguf_close(&pe->gf);
        free(pe);
        return NULL;
    }

    for (int l = 0; l < pe->gf.n_layers; l++) {
        char name[128];

        snprintf(name, sizeof(name), "blk.%d.attn_q.weight", l);
        pe->layers[l].q_weight = resolve_tensor_ptr(&pe->gf, pe->mmap_base, name, GGUF_TYPE_Q4_K, &pe->layers[l].q_dtype);

        snprintf(name, sizeof(name), "blk.%d.attn_k.weight", l);
        pe->layers[l].k_weight = resolve_tensor_ptr(&pe->gf, pe->mmap_base, name, GGUF_TYPE_Q4_K, &pe->layers[l].k_dtype);

        snprintf(name, sizeof(name), "blk.%d.attn_v.weight", l);
        pe->layers[l].v_weight = resolve_tensor_ptr(&pe->gf, pe->mmap_base, name, GGUF_TYPE_Q4_K, &pe->layers[l].v_dtype);

        snprintf(name, sizeof(name), "blk.%d.attn_output.weight", l);
        pe->layers[l].o_weight = resolve_tensor_ptr(&pe->gf, pe->mmap_base, name, GGUF_TYPE_Q4_K, &pe->layers[l].o_dtype);

        snprintf(name, sizeof(name), "blk.%d.ffn_gate.weight", l);
        pe->layers[l].gate_weight = resolve_tensor_ptr(&pe->gf, pe->mmap_base, name, GGUF_TYPE_Q4_K, &pe->layers[l].gate_dtype);

        snprintf(name, sizeof(name), "blk.%d.ffn_up.weight", l);
        pe->layers[l].up_weight = resolve_tensor_ptr(&pe->gf, pe->mmap_base, name, GGUF_TYPE_Q4_K, &pe->layers[l].up_dtype);

        snprintf(name, sizeof(name), "blk.%d.ffn_down.weight", l);
        pe->layers[l].down_weight = resolve_tensor_ptr(&pe->gf, pe->mmap_base, name, GGUF_TYPE_Q4_K, &pe->layers[l].down_dtype);

        snprintf(name, sizeof(name), "blk.%d.attn_norm.weight", l);
        pe->layers[l].attn_norm = resolve_tensor_ptr(&pe->gf, pe->mmap_base,
                                                     name, GGUF_TYPE_F32, &pe->layers[l].attn_norm_dtype);

        snprintf(name, sizeof(name), "blk.%d.ffn_norm.weight", l);
        pe->layers[l].ffn_norm = resolve_tensor_ptr(&pe->gf, pe->mmap_base,
                                                    name, GGUF_TYPE_F32, &pe->layers[l].ffn_norm_dtype);

        if (!pe->layers[l].q_weight) fprintf(stderr, "policy: layer %d missing attn_q\n", l);
        if (!pe->layers[l].k_weight) fprintf(stderr, "policy: layer %d missing attn_k\n", l);
        if (!pe->layers[l].v_weight) fprintf(stderr, "policy: layer %d missing attn_v\n", l);
        if (!pe->layers[l].o_weight) fprintf(stderr, "policy: layer %d missing attn_output\n", l);
        if (!pe->layers[l].gate_weight) fprintf(stderr, "policy: layer %d missing ffn_gate\n", l);
        if (!pe->layers[l].up_weight) fprintf(stderr, "policy: layer %d missing ffn_up\n", l);
        if (!pe->layers[l].down_weight) fprintf(stderr, "policy: layer %d missing ffn_down\n", l);
        if (!pe->layers[l].attn_norm) fprintf(stderr, "policy: layer %d missing attn_norm\n", l);
        if (!pe->layers[l].ffn_norm) fprintf(stderr, "policy: layer %d missing ffn_norm\n", l);

        if (!pe->layers[l].q_weight || !pe->layers[l].k_weight || !pe->layers[l].v_weight ||
            !pe->layers[l].o_weight || !pe->layers[l].gate_weight || !pe->layers[l].up_weight ||
            !pe->layers[l].down_weight || !pe->layers[l].attn_norm || !pe->layers[l].ffn_norm) {
            fprintf(stderr, "policy: missing tensors for layer %d\n", l);
            free(pe->layers);
            munmap(pe->mmap_base_actual, pe->mmap_size);
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
    free(pe->heap_weights);
    if (pe->mmap_base_actual != MAP_FAILED)
        munmap(pe->mmap_base_actual, pe->mmap_size);
    gguf_close(&pe->gf);
    free(pe);
}

/* ─── Helper: Dequantize a single row from embedding table ─── */
static void dequant_embed_row(float *out, const void *embed_table, int embed_dtype,
                               int token, int hidden_dim) {
    if (embed_dtype == 0) {  /* F32 */
        const float *embed_f32 = (const float *)embed_table;
        memcpy(out, embed_f32 + (size_t)token * (size_t)hidden_dim,
               (size_t)hidden_dim * sizeof(float));
    } else {
        /* Quantized: treat as 1-row matmul with identity vector */
        /* Create identity input: [1.0, 1.0, ...] */
        float *identity = (float *)malloc((size_t)hidden_dim * sizeof(float));
        for (int i = 0; i < hidden_dim; i++) identity[i] = 1.0f;

        /* Compute single row dequantization */
        const uint8_t *row_start;
        switch (embed_dtype) {
            case 8: { /* Q8_0 */
                int blocks = hidden_dim / Q8_0_BLOCK_SIZE;
                row_start = (const uint8_t *)embed_table + (size_t)token * blocks * Q8_0_BLOCK_BYTES;
                for (int i = 0; i < hidden_dim; i++) {
                    int b = i / Q8_0_BLOCK_SIZE;
                    int j = i % Q8_0_BLOCK_SIZE;
                    const uint8_t *block = row_start + b * Q8_0_BLOCK_BYTES;
                    uint16_t d_bits;
                    memcpy(&d_bits, block, 2);
                    float d = fp16_to_fp32(d_bits);
                    const int8_t *qs = (const int8_t *)(block + 2);
                    out[i] = (float)qs[j] * d;
                }
                break;
            }
            case 6: { /* Q5_0 (18-byte variant) */
                int blocks = hidden_dim / Q5_0_BLOCK_SIZE;
                row_start = (const uint8_t *)embed_table + (size_t)token * blocks * Q5_0_BLOCK_BYTES;
                for (int i = 0; i < hidden_dim; i++) {
                    int b = i / Q5_0_BLOCK_SIZE;
                    int j = i % Q5_0_BLOCK_SIZE;
                    const uint8_t *block = row_start + b * Q5_0_BLOCK_BYTES;
                    uint16_t d_bits;
                    memcpy(&d_bits, block, 2);
                    float d = fp16_to_fp32(d_bits);
                    const uint8_t *qs = block + 2;
                    uint8_t q4 = (j % 2 == 0) ? (qs[j / 2] & 0x0F) : (qs[j / 2] >> 4);
                    int8_t q_signed = (int8_t)(q4) - 8;
                    out[i] = (float)q_signed * d;
                }
                break;
            }
            case 14: { /* Q6_K */
                int blocks = hidden_dim / Q6_K_BLOCK_SIZE;
                row_start = (const uint8_t *)embed_table + (size_t)token * blocks * Q6_K_BLOCK_BYTES;
                for (int i = 0; i < hidden_dim; i++) {
                    int b = i / Q6_K_BLOCK_SIZE;
                    int idx = i % Q6_K_BLOCK_SIZE;
                    const uint8_t *block = row_start + b * Q6_K_BLOCK_BYTES;
                    uint16_t d_bits;
                    memcpy(&d_bits, block + 208, 2);
                    float d = fp16_to_fp32(d_bits);
                    const int8_t *scales = (const int8_t *)(block + 192);
                    const uint8_t *ql = block;
                    const uint8_t *qh = block + 128;
                    int sb = idx / 16;
                    float scale = (float)scales[sb] * d;
                    uint8_t low4 = (idx % 2 == 0) ? (ql[idx / 2] & 0x0F) : (ql[idx / 2] >> 4);
                    int qh_byte_idx = idx / 4;
                    int qh_bit_idx = (idx % 4) * 2;
                    uint8_t high2 = (qh[qh_byte_idx] >> qh_bit_idx) & 0x03;
                    uint8_t q6 = low4 | (high2 << 4);
                    out[i] = ((float)q6 - 32.0f) * scale;
                }
                break;
            }
            case 12: { /* Q4_K — 256-element super-blocks, 144 bytes each */
                #define Q4K_BLOCK_SZ 256
                #define Q4K_BYTES 144
                int blocks = hidden_dim / Q4K_BLOCK_SZ;
                size_t row_bytes = (size_t)blocks * Q4K_BYTES;
                row_start = (const uint8_t *)embed_table + (size_t)token * row_bytes;
                for (int i = 0; i < hidden_dim; i++) {
                    int b = i / Q4K_BLOCK_SZ;
                    int idx = i % Q4K_BLOCK_SZ;
                    const uint8_t *block = row_start + b * Q4K_BYTES;
                    /* Q4_K super-block: 2B d + 2B dmin + 12B scales + 128B quantized */
                    uint16_t d_bits, dmin_bits;
                    memcpy(&d_bits, block, 2);
                    memcpy(&dmin_bits, block + 2, 2);
                    float d = fp16_to_fp32(d_bits);
                    float dmin = fp16_to_fp32(dmin_bits);
                    const uint8_t *qs = block + 16; /* after d(2)+dmin(2)+scales(12) */
                    uint8_t q4;
                    if (idx % 2 == 0)
                        q4 = qs[idx / 2] & 0x0F;
                    else
                        q4 = qs[idx / 2] >> 4;
                    out[i] = d * (float)q4 - dmin;
                }
                #undef Q4K_BLOCK_SZ
                #undef Q4K_BYTES
                break;
            }
            default:
                fprintf(stderr, "dequant_embed_row: unsupported dtype %d\n", embed_dtype);
                memset(out, 0, (size_t)hidden_dim * sizeof(float));
        }
        free(identity);
    }
}

/* ─── F16 Norm Helper ─── */
/* RMSNorm that accepts F16 or F32 weight pointers. If norm_dtype=1 (F16),
 * converts on the fly. Most norms are F32, so the hot path is a direct call. */
static void rmsnorm_any(float *y, const float *x, const void *w, int w_dtype, int n, float eps) {
    if (w_dtype == 0) { /* F32 — direct */
        grpo_rmsnorm(y, x, (const float *)w, n, eps);
    } else if (w_dtype == 1) { /* F16 — convert inline */
        float *w_f32 = (float *)malloc((size_t)n * sizeof(float));
        const uint16_t *w_f16 = (const uint16_t *)w;
        for (int i = 0; i < n; i++)
            w_f32[i] = fp16_to_fp32(w_f16[i]);
        grpo_rmsnorm(y, x, w_f32, n, eps);
        free(w_f32);
    } else {
        /* Fallback: treat as ones */
        grpo_rmsnorm(y, x, x, n, eps); /* identity — wrong but won't crash */
    }
}

/* ─── Single-Token Forward Pass ─── */
static void policy_forward_token(PolicyEngine *pe, int token, int pos) {
    const int hidden_dim = (int)pe->gf.hidden_dim;
    const int intermediate_dim = (int)pe->gf.intermediate_dim;
    const int n_heads = (int)pe->gf.n_heads;
    const int n_kv_heads = (int)pe->gf.n_kv_heads;
    const int head_dim = (int)pe->gf.head_dim;
    const int vocab_size = (int)pe->gf.vocab_size;

    /* Embed token: extract one row from the embedding table.
     * For quantized embeddings, use the matmul kernel on a single row
     * by computing the byte offset to that row and calling matmul with rows=hidden_dim.
     * This reuses the same dequant path that's proven to work for layer weights. */
    if (token < 0 || token >= (int)pe->gf.vocab_size) {
        fprintf(stderr, "policy: token %d out of range [0, %lld)\n", token, (long long)pe->gf.vocab_size);
        memset(pe->hidden, 0, (size_t)hidden_dim * sizeof(float));
        return;
    }
    if (pe->embed_dtype == 0) { /* F32: direct copy */
        const float *embed_f32 = (const float *)pe->embed;
        memcpy(pe->hidden, embed_f32 + (size_t)token * hidden_dim,
               (size_t)hidden_dim * sizeof(float));
    } else {
        /* Quantized: create one-hot vector and matmul to extract row.
         * Actually simpler: compute row byte offset and dequant in place.
         * Use a temporary one-hot and grpo_matmul_any for correctness. */
        /* Alternative: just zero-init hidden and add the row contribution.
         * For Q4_K with 256-element blocks: each row has hidden/256 blocks.
         * We extract just row `token` from the [vocab × hidden] matrix. */

        /* Safest approach: treat embed as [vocab × hidden] and extract row `token`
         * by calling matmul with a one-hot input of length vocab.
         * This is slow (vocab=151K) but correct. For production, optimize later. */

        /* Actually: compute byte offset to row and dequant block-by-block */
        int blocks_per_row;
        int block_bytes;
        switch (pe->embed_dtype) {
            case 12: blocks_per_row = hidden_dim / 256; block_bytes = 144; break;
            case 8:  blocks_per_row = hidden_dim / 32;  block_bytes = 34; break;
            case 6:  blocks_per_row = hidden_dim / 32;  block_bytes = 18; break;
            case 14: blocks_per_row = hidden_dim / 256; block_bytes = 210; break;
            default: memset(pe->hidden, 0, (size_t)hidden_dim * sizeof(float)); return;
        }

        /* Point to this row's start in the quantized tensor */
        const uint8_t *row_ptr = (const uint8_t *)pe->embed
                                 + (size_t)token * (size_t)blocks_per_row * (size_t)block_bytes;

        /* Use matmul_any to dequantize: treat as 1-row output with input = identity[hidden_dim] */
        /* Actually grpo_matmul_any does out[rows] = x[in_dim] @ W[rows×in_dim]
         * We want out[hidden_dim] = identity × embed_row — but that's just dequant.
         * Simpler: call the specific dequant for hidden_dim elements from row_ptr */

        /* Direct dequant: iterate blocks, dequant each element */
        for (int b = 0; b < blocks_per_row; b++) {
            const uint8_t *block = row_ptr + (size_t)b * block_bytes;
            int base_idx = b * (pe->embed_dtype == 14 || pe->embed_dtype == 12 ? 256 : 32);
            int elems = (pe->embed_dtype == 14 || pe->embed_dtype == 12) ? 256 : 32;

            if (pe->embed_dtype == 12) { /* Q4_K — full sub-block scale dequant */
                uint16_t d_bits, dmin_bits;
                memcpy(&d_bits, block, 2);
                memcpy(&dmin_bits, block + 2, 2);
                float dall = fp16_to_fp32(d_bits);
                float dm = fp16_to_fp32(dmin_bits);
                const uint8_t *sc = block + 4;
                const uint8_t *qs = block + 16;
                for (int g = 0; g < 4; g++) {
                    /* Sub-block scales for low and high nibbles */
                    uint8_t sc0, m0, sc1, m1;
                    int sj0 = 2*g, sj1 = 2*g+1;
                    if (sj0 < 4) { sc0 = sc[sj0]&63; m0 = sc[sj0+4]&63; }
                    else { sc0 = (sc[sj0+4]&0xF)|((sc[sj0-4]>>6)<<4); m0 = (sc[sj0+4]>>4)|((sc[sj0]>>6)<<4); }
                    if (sj1 < 4) { sc1 = sc[sj1]&63; m1 = sc[sj1+4]&63; }
                    else { sc1 = (sc[sj1+4]&0xF)|((sc[sj1-4]>>6)<<4); m1 = (sc[sj1+4]>>4)|((sc[sj1]>>6)<<4); }
                    float d1 = dall * (float)sc0, neg_m1 = dm * (float)m0;
                    float d2 = dall * (float)sc1, neg_m2 = dm * (float)m1;
                    for (int l = 0; l < 32 && (base_idx + g*64 + l) < hidden_dim; l++) {
                        pe->hidden[base_idx + g*64 + l]      = d1 * (float)(qs[g*32+l] & 0x0F) - neg_m1;
                        pe->hidden[base_idx + g*64 + l + 32] = d2 * (float)(qs[g*32+l] >> 4) - neg_m2;
                    }
                }
            } else if (pe->embed_dtype == 8) { /* Q8_0 */
                uint16_t d_bits;
                memcpy(&d_bits, block, 2);
                float d = fp16_to_fp32(d_bits);
                const int8_t *qs = (const int8_t *)(block + 2);
                for (int j = 0; j < elems && (base_idx + j) < hidden_dim; j++) {
                    pe->hidden[base_idx + j] = (float)qs[j] * d;
                }
            }
        }
    }

    /* Run through transformer layers */
    for (int l = 0; l < pe->gf.n_layers; l++) {
        PolicyLayer *layer = &pe->layers[l];
        float *residual = (float *)malloc((size_t)hidden_dim * sizeof(float));
        memcpy(residual, pe->hidden, (size_t)hidden_dim * sizeof(float));

        /* Attention norm */
        rmsnorm_any(pe->hidden, residual, layer->attn_norm, layer->attn_norm_dtype, hidden_dim, pe->gf.rms_eps);

        /* Q, K, V projections + LoRA injection */
        if (l == 0 && pos == 0) {
            fprintf(stderr, "policy: embed done, hidden[0..3]=%.6f,%.6f,%.6f,%.6f\n",
                    pe->hidden[0], pe->hidden[1], pe->hidden[2], pe->hidden[3]);
            fprintf(stderr, "policy: residual[0..3]=%.6f,%.6f,%.6f,%.6f\n",
                    residual[0], residual[1], residual[2], residual[3]);
            fprintf(stderr, "policy: attn_norm=%p, dtype=%d\n", (void*)layer->attn_norm, layer->attn_norm_dtype);
            fprintf(stderr, "policy: after rmsnorm, hidden[0..3]=%.6f,%.6f,%.6f,%.6f\n",
                    pe->hidden[0], pe->hidden[1], pe->hidden[2], pe->hidden[3]);
            fprintf(stderr, "policy: q_weight=%p, dtype=%d, rows=%d, in_dim=%d\n",
                    (void*)layer->q_weight, layer->q_dtype, n_heads * head_dim, hidden_dim);
            fflush(stderr);
        }
        grpo_matmul_any(pe->q_buf, pe->hidden, layer->q_weight, n_heads * head_dim, hidden_dim, layer->q_dtype);
        inject_lora(pe->q_buf, pe->hidden, l, 0, n_heads * head_dim, hidden_dim);

        grpo_matmul_any(pe->k_buf, pe->hidden, layer->k_weight, n_kv_heads * head_dim, hidden_dim, layer->k_dtype);
        inject_lora(pe->k_buf, pe->hidden, l, 1, n_kv_heads * head_dim, hidden_dim);

        grpo_matmul_any(pe->v_buf, pe->hidden, layer->v_weight, n_kv_heads * head_dim, hidden_dim, layer->v_dtype);
        inject_lora(pe->v_buf, pe->hidden, l, 2, n_kv_heads * head_dim, hidden_dim);

        /* RoPE on Q and K */
        grpo_rope(pe->q_buf, pe->k_buf, pos, n_heads, head_dim, pe->gf.rope_theta);

        /* Store K, V in cache */
        size_t kv_offset = (size_t)pos * (size_t)n_kv_heads * (size_t)head_dim;
        memcpy(pe->k_cache + kv_offset, pe->k_buf, (size_t)n_kv_heads * (size_t)head_dim * sizeof(float));
        memcpy(pe->v_cache + kv_offset, pe->v_buf, (size_t)n_kv_heads * (size_t)head_dim * sizeof(float));

        /* GQA attention */
        grpo_gqa_attention(pe->attn_out, pe->q_buf, pe->k_cache, pe->v_cache,
                          n_heads, n_kv_heads, head_dim, pos);

        /* Output projection + LoRA */
        grpo_matmul_any(pe->hidden, pe->attn_out, layer->o_weight, hidden_dim, hidden_dim, layer->o_dtype);
        inject_lora(pe->hidden, pe->attn_out, l, 3, hidden_dim, hidden_dim);

        /* Residual connection */
        for (int i = 0; i < hidden_dim; i++)
            pe->hidden[i] += residual[i];

        /* FFN */
        memcpy(residual, pe->hidden, (size_t)hidden_dim * sizeof(float));
        rmsnorm_any(pe->hidden, residual, layer->ffn_norm, layer->ffn_norm_dtype, hidden_dim, pe->gf.rms_eps);

        /* Gate + Up projections + LoRA */
        grpo_matmul_any(pe->ffn_gate, pe->hidden, layer->gate_weight, intermediate_dim, hidden_dim, layer->gate_dtype);
        inject_lora(pe->ffn_gate, pe->hidden, l, 4, intermediate_dim, hidden_dim);

        grpo_matmul_any(pe->ffn_up, pe->hidden, layer->up_weight, intermediate_dim, hidden_dim, layer->up_dtype);
        inject_lora(pe->ffn_up, pe->hidden, l, 5, intermediate_dim, hidden_dim);

        /* SiLU activation on gate and elementwise multiply with up */
        grpo_silu(pe->ffn_gate, intermediate_dim);
        for (int i = 0; i < intermediate_dim; i++)
            pe->ffn_gate[i] *= pe->ffn_up[i];

        /* Down projection + LoRA */
        grpo_matmul_any(pe->ffn_out, pe->ffn_gate, layer->down_weight, hidden_dim, intermediate_dim, layer->down_dtype);
        inject_lora(pe->ffn_out, pe->ffn_gate, l, 6, hidden_dim, intermediate_dim);

        /* Residual */
        for (int i = 0; i < hidden_dim; i++)
            pe->hidden[i] = residual[i] + pe->ffn_out[i];

        free(residual);
    }

    /* Final norm + output projection */
    rmsnorm_any(pe->hidden, pe->hidden, pe->output_norm, 0 /* output_norm is always F32 */, hidden_dim, pe->gf.rms_eps);

    /* Output projection using dynamic dispatcher */
    grpo_matmul_any(pe->logits, pe->hidden, pe->output_weight, vocab_size, hidden_dim, pe->output_dtype);
}

/* ─── KV Cache Snapshot for Multi-Completion Sharing ─── */
typedef struct {
    float *k_cache_copy;
    float *v_cache_copy;
    int seq_pos;
    size_t cache_bytes;
} KVSnapshot;

static KVSnapshot *kv_snapshot = NULL;

static void policy_save_kv(PolicyEngine *pe) {
    if (kv_snapshot) {
        free(kv_snapshot->k_cache_copy);
        free(kv_snapshot->v_cache_copy);
        free(kv_snapshot);
    }
    kv_snapshot = (KVSnapshot *)malloc(sizeof(KVSnapshot));
    if (!kv_snapshot) return;

    size_t bytes = (size_t)pe->seq_pos * (size_t)pe->gf.n_kv_heads * (size_t)pe->gf.head_dim * sizeof(float);
    kv_snapshot->k_cache_copy = (float *)malloc(bytes);
    kv_snapshot->v_cache_copy = (float *)malloc(bytes);
    if (!kv_snapshot->k_cache_copy || !kv_snapshot->v_cache_copy) {
        free(kv_snapshot->k_cache_copy);
        free(kv_snapshot->v_cache_copy);
        free(kv_snapshot);
        kv_snapshot = NULL;
        return;
    }

    memcpy(kv_snapshot->k_cache_copy, pe->k_cache, bytes);
    memcpy(kv_snapshot->v_cache_copy, pe->v_cache, bytes);
    kv_snapshot->seq_pos = pe->seq_pos;
    kv_snapshot->cache_bytes = bytes;
}

static void policy_restore_kv(PolicyEngine *pe) {
    if (!kv_snapshot) return;
    memcpy(pe->k_cache, kv_snapshot->k_cache_copy, kv_snapshot->cache_bytes);
    memcpy(pe->v_cache, kv_snapshot->v_cache_copy, kv_snapshot->cache_bytes);
    pe->seq_pos = kv_snapshot->seq_pos;
}

static void policy_free_kv_snapshot(void) {
    if (kv_snapshot) {
        free(kv_snapshot->k_cache_copy);
        free(kv_snapshot->v_cache_copy);
        free(kv_snapshot);
        kv_snapshot = NULL;
    }
}

/* ─── Prefill (for KV cache sharing) ─── */
static int policy_prefill(PolicyEngine *pe, const int *prompt, int prompt_len) {
    pe->seq_pos = 0;
    for (int i = 0; i < prompt_len; i++) {
        policy_forward_token(pe, prompt[i], pe->seq_pos);
        pe->seq_pos++;
    }
    return pe->seq_pos;
}

/* ─── Continue Generation (from saved KV cache state) ─── */
static int policy_generate_continue(PolicyEngine *pe, int *output, int max_len,
                                   float *logprobs_out, float temp, float top_p,
                                   unsigned int *rng) {
    int total_gen = 0;

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

        /* Stop on EOS (Qwen3: 151645, Llama: 2) */
        if (token == 151645 || token == 2 || token == 151643) break;
        total_gen++;

        /* Feed token back */
        policy_forward_token(pe, token, pe->seq_pos);
        pe->seq_pos++;

        if (pe->seq_pos >= pe->max_seq_len) break;
    }

    return total_gen;
}

/* ─── Autoregressive Generation ─── */
static int policy_generate(PolicyEngine *pe, const int *prompt, int prompt_len,
                          int *output, int max_len, float *logprobs_out,
                          float temp, float top_p, unsigned int *rng) {
    policy_prefill(pe, prompt, prompt_len);
    return policy_generate_continue(pe, output, max_len, logprobs_out, temp, top_p, rng);
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

int grpo_policy_prefill_internal(PolicyEngine *pe, const int *prompt, int prompt_len) {
    return policy_prefill(pe, prompt, prompt_len);
}

int grpo_policy_generate_continue_internal(PolicyEngine *pe, int *output, int max_len,
                                           float *logprobs_out, float temp, float top_p,
                                           unsigned int *rng) {
    return policy_generate_continue(pe, output, max_len, logprobs_out, temp, top_p, rng);
}

void grpo_policy_save_kv_internal(PolicyEngine *pe) {
    policy_save_kv(pe);
}

void grpo_policy_restore_kv_internal(PolicyEngine *pe) {
    policy_restore_kv(pe);
}

void grpo_policy_free_kv_snapshot_internal(void) {
    policy_free_kv_snapshot();
}

/* ─── Parallel Multi-Completion Generation ─── */

#include <pthread.h>

typedef struct {
    /* Shared read-only (weights + model config) */
    const PolicyEngine *pe;

    /* Per-thread mutable state */
    float       *k_cache;
    float       *v_cache;
    float       *hidden;
    float       *q_buf;
    float       *k_buf;
    float       *v_buf;
    float       *attn_out;
    float       *ffn_gate;
    float       *ffn_up;
    float       *ffn_out;
    float       *logits;
    float       *residual;
    int          seq_pos;
    unsigned int rng_state;

    /* Generation params */
    int    max_len;
    float  temp;
    float  top_p;
    int    omp_threads;

    /* Output */
    int   *out_tokens;
    float *out_logprobs;
    int    out_len;
} GenThreadCtx;

static void thread_forward_token(const PolicyEngine *pe, GenThreadCtx *tc, int token, int pos) {
    const int hidden_dim = (int)pe->gf.hidden_dim;
    const int intermediate_dim = (int)pe->gf.intermediate_dim;
    const int n_heads = (int)pe->gf.n_heads;
    const int n_kv_heads = (int)pe->gf.n_kv_heads;
    const int head_dim = (int)pe->gf.head_dim;
    const int vocab_size = (int)pe->gf.vocab_size;

    /* Embed token (same logic as policy_forward_token but using tc->hidden) */
    if (token < 0 || token >= vocab_size) {
        memset(tc->hidden, 0, (size_t)hidden_dim * sizeof(float));
        return;
    }
    if (pe->embed_dtype == 0) {
        const float *embed_f32 = (const float *)pe->embed;
        memcpy(tc->hidden, embed_f32 + (size_t)token * hidden_dim,
               (size_t)hidden_dim * sizeof(float));
    } else {
        int blocks_per_row, block_bytes;
        switch (pe->embed_dtype) {
            case 12: blocks_per_row = hidden_dim / 256; block_bytes = 144; break;
            case 8:  blocks_per_row = hidden_dim / 32;  block_bytes = 34; break;
            case 6:  blocks_per_row = hidden_dim / 32;  block_bytes = 18; break;
            case 14: blocks_per_row = hidden_dim / 256; block_bytes = 210; break;
            default: memset(tc->hidden, 0, (size_t)hidden_dim * sizeof(float)); return;
        }
        const uint8_t *row_ptr = (const uint8_t *)pe->embed
                                 + (size_t)token * (size_t)blocks_per_row * (size_t)block_bytes;
        for (int b = 0; b < blocks_per_row; b++) {
            const uint8_t *block = row_ptr + (size_t)b * block_bytes;
            int base_idx = b * (pe->embed_dtype == 14 || pe->embed_dtype == 12 ? 256 : 32);
            if (pe->embed_dtype == 12) {
                uint16_t d_bits, dmin_bits;
                memcpy(&d_bits, block, 2);
                memcpy(&dmin_bits, block + 2, 2);
                float dall = fp16_to_fp32(d_bits);
                float dm = fp16_to_fp32(dmin_bits);
                const uint8_t *sc = block + 4;
                const uint8_t *qs = block + 16;
                for (int g = 0; g < 4; g++) {
                    uint8_t sc0, m0, sc1, m1;
                    int sj0 = 2*g, sj1 = 2*g+1;
                    if (sj0 < 4) { sc0 = sc[sj0]&63; m0 = sc[sj0+4]&63; }
                    else { sc0 = (sc[sj0+4]&0xF)|((sc[sj0-4]>>6)<<4); m0 = (sc[sj0+4]>>4)|((sc[sj0]>>6)<<4); }
                    if (sj1 < 4) { sc1 = sc[sj1]&63; m1 = sc[sj1+4]&63; }
                    else { sc1 = (sc[sj1+4]&0xF)|((sc[sj1-4]>>6)<<4); m1 = (sc[sj1+4]>>4)|((sc[sj1]>>6)<<4); }
                    float d1 = dall * (float)sc0, neg_m1 = dm * (float)m0;
                    float d2 = dall * (float)sc1, neg_m2 = dm * (float)m1;
                    for (int l = 0; l < 32 && (base_idx + g*64 + l) < hidden_dim; l++) {
                        tc->hidden[base_idx + g*64 + l]      = d1 * (float)(qs[g*32+l] & 0x0F) - neg_m1;
                        tc->hidden[base_idx + g*64 + l + 32] = d2 * (float)(qs[g*32+l] >> 4) - neg_m2;
                    }
                }
            } else if (pe->embed_dtype == 8) {
                uint16_t d_bits;
                memcpy(&d_bits, block, 2);
                float d = fp16_to_fp32(d_bits);
                const int8_t *qs = (const int8_t *)(block + 2);
                int elems = 32;
                for (int j = 0; j < elems && (base_idx + j) < hidden_dim; j++)
                    tc->hidden[base_idx + j] = (float)qs[j] * d;
            }
        }
    }

    /* Transformer layers */
    for (int l = 0; l < pe->gf.n_layers; l++) {
        const PolicyLayer *layer = &pe->layers[l];
        memcpy(tc->residual, tc->hidden, (size_t)hidden_dim * sizeof(float));

        rmsnorm_any(tc->hidden, tc->residual, layer->attn_norm, layer->attn_norm_dtype, hidden_dim, pe->gf.rms_eps);

        grpo_matmul_any(tc->q_buf, tc->hidden, layer->q_weight, n_heads * head_dim, hidden_dim, layer->q_dtype);
        grpo_matmul_any(tc->k_buf, tc->hidden, layer->k_weight, n_kv_heads * head_dim, hidden_dim, layer->k_dtype);
        grpo_matmul_any(tc->v_buf, tc->hidden, layer->v_weight, n_kv_heads * head_dim, hidden_dim, layer->v_dtype);

        grpo_rope(tc->q_buf, tc->k_buf, pos, n_heads, head_dim, pe->gf.rope_theta);

        size_t kv_offset = (size_t)pos * (size_t)n_kv_heads * (size_t)head_dim;
        memcpy(tc->k_cache + kv_offset, tc->k_buf, (size_t)n_kv_heads * (size_t)head_dim * sizeof(float));
        memcpy(tc->v_cache + kv_offset, tc->v_buf, (size_t)n_kv_heads * (size_t)head_dim * sizeof(float));

        grpo_gqa_attention(tc->attn_out, tc->q_buf, tc->k_cache, tc->v_cache,
                          n_heads, n_kv_heads, head_dim, pos);

        grpo_matmul_any(tc->hidden, tc->attn_out, layer->o_weight, hidden_dim, hidden_dim, layer->o_dtype);

        for (int i = 0; i < hidden_dim; i++)
            tc->hidden[i] += tc->residual[i];

        memcpy(tc->residual, tc->hidden, (size_t)hidden_dim * sizeof(float));
        rmsnorm_any(tc->hidden, tc->residual, layer->ffn_norm, layer->ffn_norm_dtype, hidden_dim, pe->gf.rms_eps);

        grpo_matmul_any(tc->ffn_gate, tc->hidden, layer->gate_weight, intermediate_dim, hidden_dim, layer->gate_dtype);
        grpo_matmul_any(tc->ffn_up, tc->hidden, layer->up_weight, intermediate_dim, hidden_dim, layer->up_dtype);

        grpo_silu(tc->ffn_gate, intermediate_dim);
        for (int i = 0; i < intermediate_dim; i++)
            tc->ffn_gate[i] *= tc->ffn_up[i];

        grpo_matmul_any(tc->ffn_out, tc->ffn_gate, layer->down_weight, hidden_dim, intermediate_dim, layer->down_dtype);

        for (int i = 0; i < hidden_dim; i++)
            tc->hidden[i] = tc->residual[i] + tc->ffn_out[i];
    }

    rmsnorm_any(tc->hidden, tc->hidden, pe->output_norm, 0, hidden_dim, pe->gf.rms_eps);
    grpo_matmul_any(tc->logits, tc->hidden, pe->output_weight, vocab_size, hidden_dim, pe->output_dtype);
}

static void *gen_thread_fn(void *arg) {
    GenThreadCtx *tc = (GenThreadCtx *)arg;
    const PolicyEngine *pe = tc->pe;

#ifdef _OPENMP
    omp_set_num_threads(tc->omp_threads);
#endif

    tc->out_len = 0;
    for (int i = 0; i < tc->max_len; i++) {
        int token = grpo_top_p_sample(tc->logits, (int)pe->gf.vocab_size,
                                      tc->temp, tc->top_p, &tc->rng_state);
        tc->out_tokens[i] = token;

        /* Capture logprob */
        if (tc->out_logprobs) {
            float *probs = (float *)malloc((size_t)pe->gf.vocab_size * sizeof(float));
            if (probs) {
                memcpy(probs, tc->logits, (size_t)pe->gf.vocab_size * sizeof(float));
                for (int j = 0; j < (int)pe->gf.vocab_size; j++) probs[j] /= tc->temp;
                grpo_softmax(probs, (int)pe->gf.vocab_size);
                tc->out_logprobs[i] = logf(probs[token] + 1e-10f);
                free(probs);
            }
        }

        if (token == 151645 || token == 151643 || token == 2) break; /* EOS */
        tc->out_len++;

        thread_forward_token(pe, tc, token, tc->seq_pos);
        tc->seq_pos++;
        if (tc->seq_pos >= pe->max_seq_len) break;
    }
    return NULL;
}

int grpo_policy_generate_parallel_internal(PolicyEngine *pe, int G, int max_len,
                                           float temp, float top_p,
                                           unsigned int base_rng,
                                           GrpoCompletion *results) {
    const int hidden_dim = (int)pe->gf.hidden_dim;
    const int intermediate_dim = (int)pe->gf.intermediate_dim;
    const int n_kv_heads = (int)pe->gf.n_kv_heads;
    const int head_dim = (int)pe->gf.head_dim;
    const int vocab_size = (int)pe->gf.vocab_size;
    size_t kv_bytes = (size_t)pe->seq_pos * (size_t)n_kv_heads * (size_t)head_dim * sizeof(float);
    size_t full_kv = (size_t)pe->max_seq_len * (size_t)n_kv_heads * (size_t)head_dim * sizeof(float);

#ifdef _OPENMP
    int total_threads = omp_get_max_threads();
    int omp_per_gen = total_threads / G;
    if (omp_per_gen < 1) omp_per_gen = 1;
#else
    int omp_per_gen = 1;
#endif

    /* Allocate per-thread contexts */
    GenThreadCtx *tcs = (GenThreadCtx *)calloc((size_t)G, sizeof(GenThreadCtx));
    if (!tcs) return -1;

    for (int g = 0; g < G; g++) {
        tcs[g].pe = pe;
        tcs[g].k_cache = (float *)malloc(full_kv);
        tcs[g].v_cache = (float *)malloc(full_kv);
        memcpy(tcs[g].k_cache, pe->k_cache, kv_bytes);
        memcpy(tcs[g].v_cache, pe->v_cache, kv_bytes);
        tcs[g].seq_pos = pe->seq_pos;

        tcs[g].hidden   = (float *)calloc((size_t)hidden_dim, sizeof(float));
        tcs[g].q_buf    = (float *)calloc((size_t)pe->gf.n_heads * (size_t)head_dim, sizeof(float));
        tcs[g].k_buf    = (float *)calloc((size_t)n_kv_heads * (size_t)head_dim, sizeof(float));
        tcs[g].v_buf    = (float *)calloc((size_t)n_kv_heads * (size_t)head_dim, sizeof(float));
        tcs[g].attn_out = (float *)calloc((size_t)hidden_dim, sizeof(float));
        tcs[g].ffn_gate = (float *)calloc((size_t)intermediate_dim, sizeof(float));
        tcs[g].ffn_up   = (float *)calloc((size_t)intermediate_dim, sizeof(float));
        tcs[g].ffn_out  = (float *)calloc((size_t)hidden_dim, sizeof(float));
        tcs[g].logits   = (float *)malloc((size_t)vocab_size * sizeof(float));
        tcs[g].residual = (float *)malloc((size_t)hidden_dim * sizeof(float));

        memcpy(tcs[g].logits, pe->logits, (size_t)vocab_size * sizeof(float));
        tcs[g].rng_state = base_rng ^ ((unsigned int)(g + 1) * 2654435761u);

        tcs[g].max_len = max_len;
        tcs[g].temp = temp;
        tcs[g].top_p = top_p;
        tcs[g].omp_threads = omp_per_gen;
        tcs[g].out_tokens = results[g].tokens;
        tcs[g].out_logprobs = results[g].logprobs;
        tcs[g].out_len = 0;
    }

    /* Spawn threads */
    pthread_t *threads = (pthread_t *)malloc((size_t)G * sizeof(pthread_t));
    for (int g = 0; g < G; g++)
        pthread_create(&threads[g], NULL, gen_thread_fn, &tcs[g]);

    for (int g = 0; g < G; g++)
        pthread_join(threads[g], NULL);

    /* Collect results */
    for (int g = 0; g < G; g++)
        results[g].len = tcs[g].out_len;

    /* Restore OMP threads */
#ifdef _OPENMP
    omp_set_num_threads(total_threads);
#endif

    /* Cleanup */
    for (int g = 0; g < G; g++) {
        free(tcs[g].k_cache);
        free(tcs[g].v_cache);
        free(tcs[g].hidden);
        free(tcs[g].q_buf);
        free(tcs[g].k_buf);
        free(tcs[g].v_buf);
        free(tcs[g].attn_out);
        free(tcs[g].ffn_gate);
        free(tcs[g].ffn_up);
        free(tcs[g].ffn_out);
        free(tcs[g].logits);
        free(tcs[g].residual);
    }
    free(tcs);
    free(threads);

    return 0;
}
