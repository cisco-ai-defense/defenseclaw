/* stream.c — layer-by-layer streaming forward pass for frozen models
 *
 * Reads model weights layer-by-layer from NVMe using O_DIRECT (Linux) or F_NOCACHE (macOS)
 * to bypass page cache and avoid memory pressure. Performs teacher-forced forward passes
 * without keeping any layer's weights in memory after that layer is processed.
 *
 * Key design:
 * - ONE aligned buffer (4096-aligned for O_DIRECT) sized to largest layer
 * - pread() each layer's weights → compute → overwrite buffer next iteration
 * - No KV cache — teacher-forcing processes all tokens in parallel per layer
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <math.h>

#include "grpo.h"
#include "uring.h"

/* ─── Stream Engine Structure ─── */

typedef struct {
    /* Per-layer weight offsets within layer_buf */
    size_t q_offset, k_offset, v_offset, o_offset;
    size_t gate_offset, up_offset, down_offset;
    size_t attn_norm_offset, ffn_norm_offset;
    size_t total_size;  /* Total bytes for this layer */
    int64_t file_offset; /* Absolute file offset to start of layer data */
} LayerOffsets;

struct StreamEngine {
    GgufFile      gf;
    int           fd;           /* O_DIRECT fd (or regular fd on macOS) */
    char         *file_path;    /* path to GGUF file (for io_uring) */
    void         *layer_buf;    /* aligned buffer for one layer's weights */
    size_t        layer_buf_sz; /* size of largest layer */
    int           use_direct;
    LayerOffsets *layer_info;   /* array of n_layers */

    /* Global tensors (can be mmap'd separately since they're small) */
    const float  *embed;        /* token embedding table */
    const float  *output_norm;  /* final RMS norm */
    const void   *output_weight; /* lm_head (may be Q4 or f32) */
    GgufDtype     output_dtype;

    void         *embed_mmap;   /* separate mmap for embed + output */
    size_t        embed_mmap_sz;
};

/* ─── Helper: Aligned Buffer Allocation ─── */

static void *alloc_aligned(size_t size, size_t align) {
    void *ptr = NULL;
    if (posix_memalign(&ptr, align, size) != 0) return NULL;
    return ptr;
}

/* ─── Helper: Open File with O_DIRECT or F_NOCACHE ─── */

static int stream_open_file(struct StreamEngine *se, const char *path, int use_direct) {
    int flags = O_RDONLY;
#ifdef __linux__
    if (use_direct) flags |= O_DIRECT;
#endif
    se->fd = open(path, flags);
    if (se->fd < 0) {
        /* Fallback: try without O_DIRECT */
        se->fd = open(path, O_RDONLY);
        se->use_direct = 0;
        if (se->fd < 0) {
            fprintf(stderr, "stream: cannot open %s: %s\n", path, strerror(errno));
            return -1;
        }
    } else {
        se->use_direct = use_direct;
    }
#ifdef __APPLE__
    if (se->fd >= 0 && use_direct) {
        /* F_NOCACHE bypasses the unified buffer cache on macOS */
        /* F_NOCACHE is defined in sys/fcntl.h on macOS, value is 48 */
        #ifndef F_NOCACHE
        #define F_NOCACHE 48
        #endif
        if (fcntl(se->fd, F_NOCACHE, 1) == -1) {
            fprintf(stderr, "stream: F_NOCACHE failed, continuing anyway\n");
        }
    }
#endif
    return 0;
}

/* ─── Helper: Compute Layer Offsets from GGUF Tensor Table ─── */

static int compute_layer_offsets(struct StreamEngine *se) {
    /* Pre-compute which tensors belong to each layer and their byte ranges */
    se->layer_info = (LayerOffsets *)calloc((size_t)se->gf.n_layers, sizeof(LayerOffsets));
    if (!se->layer_info) return -1;

    size_t max_layer_size = 0;

    for (int l = 0; l < se->gf.n_layers; l++) {
        LayerOffsets *info = &se->layer_info[l];
        char name[128];
        size_t cur_offset = 0;
        int64_t min_file_offset = INT64_MAX;

        /* Find all tensors for this layer and compute offsets */

        /* Attention norm (F32) */
        snprintf(name, sizeof(name), "blk.%d.attn_norm.weight", l);
        GgufTensor *t = gguf_find_tensor(&se->gf, name);
        if (t) {
            info->attn_norm_offset = cur_offset;
            cur_offset += (size_t)t->nbytes;
            if (t->offset < min_file_offset) min_file_offset = t->offset;
        }

        /* FFN norm (F32) */
        snprintf(name, sizeof(name), "blk.%d.ffn_norm.weight", l);
        t = gguf_find_tensor(&se->gf, name);
        if (t) {
            info->ffn_norm_offset = cur_offset;
            cur_offset += (size_t)t->nbytes;
            if (t->offset < min_file_offset) min_file_offset = t->offset;
        }

        /* Q, K, V, O projections (Q4_K) */
        snprintf(name, sizeof(name), "blk.%d.attn_q.weight", l);
        t = gguf_find_tensor(&se->gf, name);
        if (t) {
            info->q_offset = cur_offset;
            cur_offset += (size_t)t->nbytes;
            if (t->offset < min_file_offset) min_file_offset = t->offset;
        }

        snprintf(name, sizeof(name), "blk.%d.attn_k.weight", l);
        t = gguf_find_tensor(&se->gf, name);
        if (t) {
            info->k_offset = cur_offset;
            cur_offset += (size_t)t->nbytes;
            if (t->offset < min_file_offset) min_file_offset = t->offset;
        }

        snprintf(name, sizeof(name), "blk.%d.attn_v.weight", l);
        t = gguf_find_tensor(&se->gf, name);
        if (t) {
            info->v_offset = cur_offset;
            cur_offset += (size_t)t->nbytes;
            if (t->offset < min_file_offset) min_file_offset = t->offset;
        }

        snprintf(name, sizeof(name), "blk.%d.attn_output.weight", l);
        t = gguf_find_tensor(&se->gf, name);
        if (t) {
            info->o_offset = cur_offset;
            cur_offset += (size_t)t->nbytes;
            if (t->offset < min_file_offset) min_file_offset = t->offset;
        }

        /* FFN gate, up, down (Q4_K) */
        snprintf(name, sizeof(name), "blk.%d.ffn_gate.weight", l);
        t = gguf_find_tensor(&se->gf, name);
        if (t) {
            info->gate_offset = cur_offset;
            cur_offset += (size_t)t->nbytes;
            if (t->offset < min_file_offset) min_file_offset = t->offset;
        }

        snprintf(name, sizeof(name), "blk.%d.ffn_up.weight", l);
        t = gguf_find_tensor(&se->gf, name);
        if (t) {
            info->up_offset = cur_offset;
            cur_offset += (size_t)t->nbytes;
            if (t->offset < min_file_offset) min_file_offset = t->offset;
        }

        snprintf(name, sizeof(name), "blk.%d.ffn_down.weight", l);
        t = gguf_find_tensor(&se->gf, name);
        if (t) {
            info->down_offset = cur_offset;
            cur_offset += (size_t)t->nbytes;
            if (t->offset < min_file_offset) min_file_offset = t->offset;
        }

        info->total_size = cur_offset;
        info->file_offset = min_file_offset;

        if (cur_offset > max_layer_size)
            max_layer_size = cur_offset;
    }

    /* Align buffer size to 4096 for O_DIRECT */
    se->layer_buf_sz = (max_layer_size + 4095) & ~4095UL;

    return 0;
}

/* ─── Helper: Load Global Tensors (Embed + Output) ─── */

static int load_global_tensors(struct StreamEngine *se) {
    /* Find embedding and output tensors */
    GgufTensor *embed_t = gguf_find_tensor(&se->gf, "token_embd.weight");
    GgufTensor *out_norm_t = gguf_find_tensor(&se->gf, "output_norm.weight");
    GgufTensor *out_t = gguf_find_tensor(&se->gf, "output.weight");

    if (!embed_t || !out_norm_t || !out_t) {
        fprintf(stderr, "stream: missing global tensors\n");
        return -1;
    }

    /* Determine mmap region (embed to output) */
    int64_t min_offset = embed_t->offset;
    int64_t max_offset = out_t->offset + out_t->nbytes;

    if (out_norm_t->offset < min_offset) min_offset = out_norm_t->offset;
    if (out_norm_t->offset + out_norm_t->nbytes > max_offset)
        max_offset = out_norm_t->offset + out_norm_t->nbytes;

    se->embed_mmap_sz = (size_t)(max_offset - min_offset);

    /* mmap this region */
    se->embed_mmap = mmap(NULL, se->embed_mmap_sz, PROT_READ, MAP_SHARED,
                         se->fd, min_offset);
    if (se->embed_mmap == MAP_FAILED) {
        fprintf(stderr, "stream: mmap failed for global tensors: %s\n", strerror(errno));
        return -1;
    }

    /* Resolve pointers into mmap */
    se->embed = (const float *)((uint8_t *)se->embed_mmap + (embed_t->offset - min_offset));
    se->output_norm = (const float *)((uint8_t *)se->embed_mmap + (out_norm_t->offset - min_offset));
    se->output_weight = (const void *)((uint8_t *)se->embed_mmap + (out_t->offset - min_offset));
    se->output_dtype = out_t->dtype;

    return 0;
}

/* ─── Helper: Apply Transformer Layer (Single Token or Batch) ─── */

static void apply_stream_layer(struct StreamEngine *se, float *hidden, int seq_len, int layer_idx) {
    const int hidden_dim = (int)se->gf.hidden_dim;
    const int intermediate_dim = (int)se->gf.intermediate_dim;
    const int n_heads = (int)se->gf.n_heads;
    const int n_kv_heads = (int)se->gf.n_kv_heads;
    const int head_dim = (int)se->gf.head_dim;

    LayerOffsets *info = &se->layer_info[layer_idx];

    /* Extract weight pointers from layer_buf */
    const float *attn_norm = (const float *)((uint8_t *)se->layer_buf + info->attn_norm_offset);
    const float *ffn_norm = (const float *)((uint8_t *)se->layer_buf + info->ffn_norm_offset);
    const void *q_weight = (const void *)((uint8_t *)se->layer_buf + info->q_offset);
    const void *k_weight = (const void *)((uint8_t *)se->layer_buf + info->k_offset);
    const void *v_weight = (const void *)((uint8_t *)se->layer_buf + info->v_offset);
    const void *o_weight = (const void *)((uint8_t *)se->layer_buf + info->o_offset);
    const void *gate_weight = (const void *)((uint8_t *)se->layer_buf + info->gate_offset);
    const void *up_weight = (const void *)((uint8_t *)se->layer_buf + info->up_offset);
    const void *down_weight = (const void *)((uint8_t *)se->layer_buf + info->down_offset);

    /* Allocate scratch buffers for this layer */
    float *residual = (float *)malloc((size_t)seq_len * (size_t)hidden_dim * sizeof(float));
    float *q_buf = (float *)malloc((size_t)seq_len * (size_t)n_heads * (size_t)head_dim * sizeof(float));
    float *k_buf = (float *)malloc((size_t)seq_len * (size_t)n_kv_heads * (size_t)head_dim * sizeof(float));
    float *v_buf = (float *)malloc((size_t)seq_len * (size_t)n_kv_heads * (size_t)head_dim * sizeof(float));
    float *attn_out = (float *)malloc((size_t)seq_len * (size_t)hidden_dim * sizeof(float));
    float *ffn_gate = (float *)malloc((size_t)seq_len * (size_t)intermediate_dim * sizeof(float));
    float *ffn_up = (float *)malloc((size_t)seq_len * (size_t)intermediate_dim * sizeof(float));
    float *ffn_out = (float *)malloc((size_t)seq_len * (size_t)hidden_dim * sizeof(float));

    if (!residual || !q_buf || !k_buf || !v_buf || !attn_out || !ffn_gate || !ffn_up || !ffn_out) {
        fprintf(stderr, "stream: allocation failed in layer %d\n", layer_idx);
        free(residual); free(q_buf); free(k_buf); free(v_buf);
        free(attn_out); free(ffn_gate); free(ffn_up); free(ffn_out);
        return;
    }

    /* Process each token in sequence (teacher-forcing: all tokens in parallel) */
    for (int pos = 0; pos < seq_len; pos++) {
        float *h = hidden + (size_t)pos * (size_t)hidden_dim;
        float *res = residual + (size_t)pos * (size_t)hidden_dim;

        /* Save residual */
        memcpy(res, h, (size_t)hidden_dim * sizeof(float));

        /* Attention norm */
        grpo_rmsnorm(h, res, attn_norm, hidden_dim, se->gf.rms_eps);

        /* Q, K, V projections */
        float *q = q_buf + (size_t)pos * (size_t)n_heads * (size_t)head_dim;
        float *k = k_buf + (size_t)pos * (size_t)n_kv_heads * (size_t)head_dim;
        float *v = v_buf + (size_t)pos * (size_t)n_kv_heads * (size_t)head_dim;

        grpo_matmul_q4(q, h, q_weight, n_heads * head_dim, hidden_dim);
        grpo_matmul_q4(k, h, k_weight, n_kv_heads * head_dim, hidden_dim);
        grpo_matmul_q4(v, h, v_weight, n_kv_heads * head_dim, hidden_dim);

        /* RoPE on Q and K */
        grpo_rope(q, k, pos, n_heads, head_dim, se->gf.rope_theta);
    }

    /* Self-attention (simplified: no KV cache, compute all-to-all attention) */
    /* For teacher-forcing, we process the full sequence at once */
    for (int pos = 0; pos < seq_len; pos++) {
        float *q = q_buf + (size_t)pos * (size_t)n_heads * (size_t)head_dim;
        float *out = attn_out + (size_t)pos * (size_t)hidden_dim;

        /* Simplified attention: use grpo_gqa_attention with full k_buf/v_buf as cache */
        grpo_gqa_attention(out, q, k_buf, v_buf, n_heads, n_kv_heads, head_dim, pos);
    }

    /* Output projection + residual */
    for (int pos = 0; pos < seq_len; pos++) {
        float *h = hidden + (size_t)pos * (size_t)hidden_dim;
        float *res = residual + (size_t)pos * (size_t)hidden_dim;
        float *attn = attn_out + (size_t)pos * (size_t)hidden_dim;

        grpo_matmul_q4(h, attn, o_weight, hidden_dim, hidden_dim);

        /* Residual connection */
        for (int i = 0; i < hidden_dim; i++)
            h[i] += res[i];
    }

    /* FFN */
    for (int pos = 0; pos < seq_len; pos++) {
        float *h = hidden + (size_t)pos * (size_t)hidden_dim;
        float *res = residual + (size_t)pos * (size_t)hidden_dim;

        /* Save new residual */
        memcpy(res, h, (size_t)hidden_dim * sizeof(float));

        /* FFN norm */
        grpo_rmsnorm(h, res, ffn_norm, hidden_dim, se->gf.rms_eps);

        float *gate = ffn_gate + (size_t)pos * (size_t)intermediate_dim;
        float *up = ffn_up + (size_t)pos * (size_t)intermediate_dim;
        float *out = ffn_out + (size_t)pos * (size_t)hidden_dim;

        /* Gate and up projections */
        grpo_matmul_q4(gate, h, gate_weight, intermediate_dim, hidden_dim);
        grpo_matmul_q4(up, h, up_weight, intermediate_dim, hidden_dim);

        /* SiLU activation on gate and elementwise multiply */
        grpo_silu(gate, intermediate_dim);
        for (int i = 0; i < intermediate_dim; i++)
            gate[i] *= up[i];

        /* Down projection */
        grpo_matmul_q4(out, gate, down_weight, hidden_dim, intermediate_dim);

        /* Residual */
        for (int i = 0; i < hidden_dim; i++)
            h[i] = res[i] + out[i];
    }

    free(residual); free(q_buf); free(k_buf); free(v_buf);
    free(attn_out); free(ffn_gate); free(ffn_up); free(ffn_out);
}

/* ─── Helper: Read Layer Data with O_DIRECT ─── */

static int read_layer_data(struct StreamEngine *se, int layer_idx) {
    LayerOffsets *info = &se->layer_info[layer_idx];

    /* For O_DIRECT, we need to read aligned chunks */
    /* Read from file_offset, size = total_size (rounded up to 4096) */
    size_t read_size = (info->total_size + 4095) & ~4095UL;
    if (read_size > se->layer_buf_sz)
        read_size = se->layer_buf_sz;

    ssize_t got = pread(se->fd, se->layer_buf, read_size, info->file_offset);
    if (got < 0) {
        fprintf(stderr, "stream: pread failed for layer %d: %s\n", layer_idx, strerror(errno));
        return -1;
    }

    /* Note: O_DIRECT requires reads to be sector-aligned. If the actual data is smaller,
     * we read more than needed but only use info->total_size bytes */

    return 0;
}

/* ─── Public API: Open Stream Engine ─── */

struct StreamEngine *stream_open(const char *gguf_path, int use_direct_io) {
    struct StreamEngine *se = (struct StreamEngine *)calloc(1, sizeof(struct StreamEngine));
    if (!se) return NULL;

    /* Open GGUF file */
    if (gguf_open(&se->gf, gguf_path) != 0) {
        fprintf(stderr, "stream: failed to open GGUF %s\n", gguf_path);
        free(se);
        return NULL;
    }

    /* Store file path for io_uring */
    se->file_path = strdup(gguf_path);
    if (!se->file_path) {
        gguf_close(&se->gf);
        free(se);
        return NULL;
    }

    /* Open with O_DIRECT or F_NOCACHE */
    if (stream_open_file(se, gguf_path, use_direct_io) != 0) {
        free(se->file_path);
        gguf_close(&se->gf);
        free(se);
        return NULL;
    }

    /* Compute layer offsets */
    if (compute_layer_offsets(se) != 0) {
        close(se->fd);
        gguf_close(&se->gf);
        free(se->file_path);
        free(se);
        return NULL;
    }

    /* Allocate aligned layer buffer */
    se->layer_buf = alloc_aligned(se->layer_buf_sz, 4096);
    if (!se->layer_buf) {
        fprintf(stderr, "stream: failed to allocate layer buffer (%zu bytes)\n", se->layer_buf_sz);
        free(se->layer_info);
        close(se->fd);
        gguf_close(&se->gf);
        free(se->file_path);
        free(se);
        return NULL;
    }

    /* Load global tensors (embed + output) */
    if (load_global_tensors(se) != 0) {
        free(se->layer_buf);
        free(se->layer_info);
        close(se->fd);
        gguf_close(&se->gf);
        free(se->file_path);
        free(se);
        return NULL;
    }

    return se;
}

/* ─── Public API: Stream Forward Logprobs ─── */

int stream_forward_logprobs(struct StreamEngine *se, const int *tokens, int len, float *logprobs_out) {
    if (!se || !tokens || !logprobs_out || len <= 0) return -1;

    const int hidden_dim = (int)se->gf.hidden_dim;
    const int vocab_size = (int)se->gf.vocab_size;

    /* Allocate hidden state for full sequence [len × hidden_dim] */
    float *hidden = (float *)calloc((size_t)len * (size_t)hidden_dim, sizeof(float));
    if (!hidden) {
        fprintf(stderr, "stream: failed to allocate hidden state\n");
        return -1;
    }

    /* Embed tokens */
    for (int i = 0; i < len; i++) {
        int token = tokens[i];
        if (token < 0 || token >= vocab_size) {
            fprintf(stderr, "stream: invalid token %d at position %d\n", token, i);
            free(hidden);
            return -1;
        }
        const float *embed_row = se->embed + (size_t)token * (size_t)hidden_dim;
        memcpy(hidden + (size_t)i * (size_t)hidden_dim, embed_row, (size_t)hidden_dim * sizeof(float));
    }

    /* Process each layer: read from disk, compute, discard weights */
#ifdef GRPO_HAS_URING
    UringReader *ur = NULL;
    void *buf_B = NULL;
    int n_layers = se->gf.n_layers;

    if (uring_available()) {
        ur = uring_open(se->file_path, 2, 4096);
        if (ur) {
            /* Allocate second buffer for double-buffering */
            buf_B = alloc_aligned(se->layer_buf_sz, 4096);
            if (!buf_B) { uring_close(ur); ur = NULL; }
        }
    }

    if (ur && buf_B) {
        /* Double-buffered io_uring path */
        void *bufs[2] = { se->layer_buf, buf_B };

        /* Submit first layer read */
        size_t read_size = (se->layer_info[0].total_size + 4095) & ~4095UL;
        if (read_size > se->layer_buf_sz) read_size = se->layer_buf_sz;

        /* Skip io_uring if first layer read_size is 0 */
        if (read_size == 0) {
            free(buf_B);
            uring_close(ur);
            ur = NULL;
        } else {
            uring_submit_read(ur, bufs[0], read_size, se->layer_info[0].file_offset);

            for (int L = 0; L < n_layers; L++) {
                /* Wait for current layer */
                if (uring_wait_completion(ur) < 0) {
                    fprintf(stderr, "stream: uring_wait_completion failed for layer %d\n", L);
                    free(buf_B);
                    uring_close(ur);
                    free(hidden);
                    return -1;
                }

                /* Submit next layer while we compute */
                if (L + 1 < n_layers) {
                    read_size = (se->layer_info[L + 1].total_size + 4095) & ~4095UL;
                    if (read_size > se->layer_buf_sz) read_size = se->layer_buf_sz;
                    if (read_size > 0) {
                        uring_submit_read(ur, bufs[(L + 1) % 2], read_size,
                                         se->layer_info[L + 1].file_offset);
                    }
                }

                /* Compute on current buffer */
                void *saved = se->layer_buf;
                se->layer_buf = bufs[L % 2];
                apply_stream_layer(se, hidden, len, L);
                se->layer_buf = saved;
            }

            free(buf_B);
            uring_close(ur);
        }
    }

    if (!ur) {
#endif
        /* Fallback: synchronous pread (existing behavior) */
        for (int l = 0; l < se->gf.n_layers; l++) {
            /* Read this layer's weights into layer_buf via pread */
            if (read_layer_data(se, l) != 0) {
                free(hidden);
                return -1;
            }

            /* Apply transformer layer using weights in layer_buf */
            apply_stream_layer(se, hidden, len, l);
            /* layer_buf is now free to be overwritten by next layer */
        }
#ifdef GRPO_HAS_URING
    }
#endif

    /* Apply final norm + output head → logits → logprobs */
    float *logits = (float *)malloc((size_t)vocab_size * sizeof(float));
    if (!logits) {
        free(hidden);
        return -1;
    }

    for (int pos = 0; pos < len; pos++) {
        float *h = hidden + (size_t)pos * (size_t)hidden_dim;

        /* Final RMS norm */
        grpo_rmsnorm(h, h, se->output_norm, hidden_dim, se->gf.rms_eps);

        /* Output projection */
        if (se->output_dtype == GGUF_TYPE_Q4_K) {
            grpo_matmul_q4(logits, h, se->output_weight, vocab_size, hidden_dim);
        } else {
            grpo_matmul_f32(logits, h, (const float *)se->output_weight,
                          vocab_size, vocab_size, hidden_dim);
        }

        /* Softmax */
        grpo_softmax(logits, vocab_size);

        /* Get logprob of next token (if not last position) */
        if (pos + 1 < len) {
            int next_token = tokens[pos + 1];
            logprobs_out[pos] = logf(logits[next_token] + 1e-10f);
        } else {
            /* Last token has no next token, set logprob to 0 */
            logprobs_out[pos] = 0.0f;
        }
    }

    free(logits);
    free(hidden);
    return 0;
}

/* ─── Public API: Close Stream Engine ─── */

void stream_close(struct StreamEngine *se) {
    if (!se) return;

    if (se->embed_mmap && se->embed_mmap != MAP_FAILED)
        munmap(se->embed_mmap, se->embed_mmap_sz);

    if (se->layer_buf)
        free(se->layer_buf);

    if (se->layer_info)
        free(se->layer_info);

    if (se->file_path)
        free(se->file_path);

    if (se->fd >= 0)
        close(se->fd);

    gguf_close(&se->gf);
    free(se);
}
