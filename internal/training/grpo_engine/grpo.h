/* internal/training/grpo_engine/grpo.h */
#ifndef GRPO_H
#define GRPO_H

#include <stdint.h>
#include <stddef.h>

/* ─── GGUF Types ─── */
#define GGUF_MAGIC 0x46554747  /* 'G','G','U','F' as little-endian u32 */

typedef enum {
    GGUF_TYPE_F32   = 0,
    GGUF_TYPE_F16   = 1,
    GGUF_TYPE_Q4_0  = 2,
    GGUF_TYPE_Q4_1  = 3,
    GGUF_TYPE_Q5_0  = 6,
    GGUF_TYPE_Q5_1  = 7,
    GGUF_TYPE_Q8_0  = 8,
    GGUF_TYPE_Q4_K  = 12,
    GGUF_TYPE_Q6_K  = 14,
} GgufDtype;

typedef struct {
    char       *name;
    int64_t     offset;    /* byte offset from data start */
    int64_t     nbytes;    /* total bytes */
    GgufDtype   dtype;
    int         n_dims;
    int64_t     dims[4];
} GgufTensor;

typedef struct {
    int           fd;
    int           version;
    int64_t       n_tensors;
    int64_t       data_offset;   /* byte offset where tensor data begins */
    GgufTensor   *tensors;       /* array of n_tensors */
    /* metadata cache */
    int64_t       n_layers;
    int64_t       hidden_dim;
    int64_t       intermediate_dim;
    int64_t       n_heads;
    int64_t       n_kv_heads;
    int64_t       head_dim;
    int64_t       vocab_size;
    float         rms_eps;
    float         rope_theta;
} GgufFile;

int         gguf_open(GgufFile *gf, const char *path);
void        gguf_close(GgufFile *gf);
GgufTensor *gguf_find_tensor(const GgufFile *gf, const char *name);
int64_t     gguf_metadata_int(const GgufFile *gf, const char *key);
const char *gguf_metadata_str(const GgufFile *gf, const char *key);

/* ─── Forward declarations for other modules ─── */
typedef struct GrpoCtx GrpoCtx;

typedef struct {
    const char *policy_gguf;
    const char *reference_gguf;
    const char *reward_gguf;
    int         memory_mode;       /* 0=minimal, 1=standard, 2=comfort */
    int         lora_rank;
    int         lora_alpha;
    const char *lora_targets;      /* "q,k,v,o,gate,up,down" */
    int         max_seq_len;
    int         num_threads;
    int         use_direct_io;
    size_t      layer_buffer_bytes;
} GrpoConfig;

typedef struct {
    int64_t  steps;
    double   total_gen_seconds;
    double   total_stream_seconds;
    double   total_backward_seconds;
    uint64_t bytes_streamed;
    float    last_loss;
    float    last_reward_mean;
} GrpoStats;

/* ─── Engine API ─── */
GrpoCtx    *grpo_init(GrpoConfig *cfg);
void        grpo_free(GrpoCtx *ctx);
int         grpo_generate(GrpoCtx *ctx, const int *prompt, int prompt_len,
                          int *output, int max_len, float *logprobs_out,
                          float temp, float top_p);
int         grpo_policy_logprobs(GrpoCtx *ctx, const int *tokens, int len, float *logprobs_out);
int         grpo_ref_logprobs(GrpoCtx *ctx, const int *tokens, int len, float *logprobs_out);
int         grpo_reward_forward(GrpoCtx *ctx, const int *tokens, int len, float *score_out);
int         grpo_backward(GrpoCtx *ctx, const float *advantages,
                          const float *policy_logprobs, const float *old_logprobs,
                          const float *ref_logprobs, int G, int seq_len,
                          float clip_eps, float kl_coef);
int         grpo_adam_step(GrpoCtx *ctx, float lr, float beta1, float beta2, float eps, int step);
int         grpo_save_lora(GrpoCtx *ctx, const char *path);
int         grpo_load_lora(GrpoCtx *ctx, const char *path);
int         grpo_export_merged_gguf(GrpoCtx *ctx, const char *output_path);
GrpoStats   grpo_stats(GrpoCtx *ctx);

/* ─── Math Kernels ─── */
void grpo_rmsnorm(float *y, const float *x, const float *w, int n, float eps);
void grpo_matmul_f32(float *out, const float *x, const float *W, int rows, int cols, int in_dim);
void grpo_matmul_q4(float *out, const float *x, const void *W_packed, int rows, int in_dim);
void grpo_silu(float *x, int n);
void grpo_rope(float *q, float *k, int pos, int n_heads, int head_dim, float theta);
void grpo_softmax(float *x, int n);
void grpo_gqa_attention(float *out, const float *q, const float *k_cache, const float *v_cache,
                        int n_heads, int n_kv_heads, int head_dim, int seq_pos);
int  grpo_top_p_sample(const float *logits, int vocab_size, float temp, float top_p,
                       unsigned int *rng_state);

/* ─── Stream Engine (O_DIRECT layer-by-layer forward) ─── */
/* Opaque handle - definition is in stream.c */
struct StreamEngine;

struct StreamEngine *stream_open(const char *gguf_path, int use_direct_io);
int                  stream_forward_logprobs(struct StreamEngine *se, const int *tokens, int len, float *logprobs_out);
void                 stream_close(struct StreamEngine *se);

#endif /* GRPO_H */
