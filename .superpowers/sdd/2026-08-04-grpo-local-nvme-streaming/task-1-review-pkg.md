98d9c2fd feat(training): add GGUF parser and C library scaffold for grpo-local
---STAT---
 internal/training/grpo_engine/Makefile  |  40 +++++++
 internal/training/grpo_engine/gguf.c    | 201 ++++++++++++++++++++++++++++++++
 internal/training/grpo_engine/grpo.h    | 102 ++++++++++++++++
 internal/training/grpo_engine/kernels.c |   2 +
 internal/training/grpo_engine/lora.c    |   2 +
 internal/training/grpo_engine/policy.c  |   2 +
 internal/training/grpo_engine/stream.c  |   2 +
 7 files changed, 351 insertions(+)
---DIFF---
diff --git a/internal/training/grpo_engine/Makefile b/internal/training/grpo_engine/Makefile
new file mode 100644
index 00000000..4a4ede0f
--- /dev/null
+++ b/internal/training/grpo_engine/Makefile
@@ -0,0 +1,40 @@
+# internal/training/grpo_engine/Makefile
+CC       ?= gcc
+CFLAGS   = -O3 -std=c99 -ffp-contract=off -fPIC -Wall -Wextra
+LDFLAGS  = -lm
+
+# OpenMP: detect availability
+OPENMP_OK := $(shell echo "int main(){return 0;}" | $(CC) -x c -fopenmp - -o /dev/null 2>/dev/null && echo 1)
+ifeq ($(OPENMP_OK),1)
+  CFLAGS += -fopenmp
+  LDFLAGS += -lgomp
+endif
+
+# AVX2: detect availability
+AVX2_OK := $(shell $(CC) -mavx2 -mfma -dM -E - < /dev/null 2>/dev/null | grep -c AVX2)
+ifeq ($(AVX2_OK),1)
+  CFLAGS += -mavx2 -mfma
+endif
+
+SRCS = gguf.c kernels.c policy.c stream.c lora.c
+OBJS = $(SRCS:.c=.o)
+
+.PHONY: all clean test portable
+
+all: libgrpo_stream.a
+
+libgrpo_stream.a: $(OBJS)
+	ar rcs $@ $^
+
+%.o: %.c grpo.h
+	$(CC) $(CFLAGS) -c $< -o $@
+
+portable:
+	$(MAKE) CFLAGS="-O2 -std=c99 -ffp-contract=off -fPIC -Wall"
+
+test: libgrpo_stream.a test_kernels.c
+	$(CC) $(CFLAGS) test_kernels.c -L. -lgrpo_stream $(LDFLAGS) -o test_runner
+	./test_runner
+
+clean:
+	rm -f *.o *.a test_runner
diff --git a/internal/training/grpo_engine/gguf.c b/internal/training/grpo_engine/gguf.c
new file mode 100644
index 00000000..ac2bd5cf
--- /dev/null
+++ b/internal/training/grpo_engine/gguf.c
@@ -0,0 +1,201 @@
+/* internal/training/grpo_engine/gguf.c
+ *
+ * Parses GGUF v3 format: header → metadata KV pairs → tensor info → tensor data.
+ * Reference: https://github.com/ggerganov/ggml/blob/master/docs/gguf.md
+ */
+#define _POSIX_C_SOURCE 200809L
+#include <fcntl.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <unistd.h>
+#include <sys/stat.h>
+
+#include "grpo.h"
+
+/* GGUF metadata value types */
+enum { GV_U8=0, GV_I8, GV_U16, GV_I16, GV_U32, GV_I32, GV_F32,
+       GV_BOOL, GV_STR, GV_ARR, GV_U64, GV_I64, GV_F64 };
+
+typedef struct {
+    const uint8_t *data;
+    size_t         size;
+    size_t         pos;
+} Reader;
+
+static int read_bytes(Reader *r, void *dst, size_t n) {
+    if (r->pos + n > r->size) return -1;
+    memcpy(dst, r->data + r->pos, n);
+    r->pos += n;
+    return 0;
+}
+static uint32_t read_u32(Reader *r) { uint32_t v; read_bytes(r, &v, 4); return v; }
+static uint64_t read_u64(Reader *r) { uint64_t v; read_bytes(r, &v, 8); return v; }
+static int64_t  read_i64(Reader *r) { int64_t v;  read_bytes(r, &v, 8); return v; }
+static float    read_f32(Reader *r) { float v;    read_bytes(r, &v, 4); return v; }
+
+static char *read_str(Reader *r) {
+    uint64_t len = read_u64(r);
+    if (r->pos + len > r->size) return NULL;
+    char *s = (char *)malloc(len + 1);
+    if (!s) return NULL;
+    memcpy(s, r->data + r->pos, len);
+    s[len] = 0;
+    r->pos += len;
+    return s;
+}
+
+static void skip_value(Reader *r, uint32_t vtype) {
+    switch (vtype) {
+        case GV_U8: case GV_I8: case GV_BOOL: r->pos += 1; break;
+        case GV_U16: case GV_I16: r->pos += 2; break;
+        case GV_U32: case GV_I32: case GV_F32: r->pos += 4; break;
+        case GV_U64: case GV_I64: case GV_F64: r->pos += 8; break;
+        case GV_STR: { uint64_t len = read_u64(r); r->pos += len; break; }
+        case GV_ARR: {
+            uint32_t atype = read_u32(r);
+            uint64_t alen = read_u64(r);
+            for (uint64_t i = 0; i < alen; i++) skip_value(r, atype);
+            break;
+        }
+    }
+}
+
+int gguf_open(GgufFile *gf, const char *path) {
+    memset(gf, 0, sizeof(*gf));
+    gf->fd = -1;
+
+    /* Read entire file for header parsing (GGUF headers are small, data is at the end) */
+    int fd = open(path, O_RDONLY);
+    if (fd < 0) { fprintf(stderr, "gguf: cannot open %s\n", path); return -1; }
+
+    struct stat st;
+    if (fstat(fd, &st) != 0) { close(fd); return -1; }
+
+    /* Read enough for header — at most 64 MB for metadata, rest is tensor data */
+    size_t header_budget = (st.st_size < 64*1024*1024) ? (size_t)st.st_size : 64*1024*1024;
+    uint8_t *buf = (uint8_t *)malloc(header_budget);
+    if (!buf) { close(fd); return -1; }
+    if (pread(fd, buf, header_budget, 0) != (ssize_t)header_budget) {
+        free(buf); close(fd); return -1;
+    }
+
+    Reader r = { .data = buf, .size = header_budget, .pos = 0 };
+
+    /* Magic + version */
+    uint32_t magic = read_u32(&r);
+    if (magic != GGUF_MAGIC) {
+        fprintf(stderr, "gguf: bad magic in %s\n", path);
+        free(buf); close(fd); return -1;
+    }
+    gf->version = (int)read_u32(&r);
+    gf->n_tensors = (int64_t)read_u64(&r);
+    int64_t n_kv = (int64_t)read_u64(&r);
+
+    /* Parse metadata KV */
+    gf->rms_eps = 1e-5f;
+    gf->rope_theta = 10000.0f;
+    for (int64_t i = 0; i < n_kv; i++) {
+        char *key = read_str(&r);
+        uint32_t vtype = read_u32(&r);
+
+        /* Extract architecture metadata we need */
+        if (key && vtype == GV_U64) {
+            int64_t val = (int64_t)read_u64(&r);
+            if (strstr(key, "block_count"))       gf->n_layers = val;
+            else if (strstr(key, "embedding_length")) gf->hidden_dim = val;
+            else if (strstr(key, "feed_forward_length")) gf->intermediate_dim = val;
+            else if (strstr(key, "head_count\""))  gf->n_heads = val;
+            else if (strstr(key, "head_count_kv")) gf->n_kv_heads = val;
+        } else if (key && vtype == GV_U32) {
+            uint32_t val = read_u32(&r);
+            if (strstr(key, "block_count"))       gf->n_layers = val;
+            else if (strstr(key, "embedding_length")) gf->hidden_dim = val;
+            else if (strstr(key, "feed_forward_length")) gf->intermediate_dim = val;
+            else if (strstr(key, "head_count\""))  gf->n_heads = val;
+            else if (strstr(key, "head_count_kv")) gf->n_kv_heads = val;
+            else if (strstr(key, "vocab_size"))   gf->vocab_size = val;
+        } else if (key && vtype == GV_F32) {
+            float val = read_f32(&r);
+            if (strstr(key, "rms_norm_eps"))   gf->rms_eps = val;
+            else if (strstr(key, "rope.freq_base")) gf->rope_theta = val;
+        } else {
+            skip_value(&r, vtype);
+        }
+        free(key);
+    }
+
+    if (gf->n_heads > 0 && gf->hidden_dim > 0)
+        gf->head_dim = gf->hidden_dim / gf->n_heads;
+    if (gf->n_kv_heads == 0) gf->n_kv_heads = gf->n_heads;
+
+    /* Parse tensor info */
+    gf->tensors = (GgufTensor *)calloc((size_t)gf->n_tensors, sizeof(GgufTensor));
+    if (!gf->tensors) { free(buf); close(fd); return -1; }
+
+    for (int64_t i = 0; i < gf->n_tensors; i++) {
+        gf->tensors[i].name = read_str(&r);
+        gf->tensors[i].n_dims = (int)read_u32(&r);
+        for (int d = 0; d < gf->tensors[i].n_dims; d++)
+            gf->tensors[i].dims[d] = (int64_t)read_u64(&r);
+        gf->tensors[i].dtype = (GgufDtype)read_u32(&r);
+        gf->tensors[i].offset = (int64_t)read_u64(&r);
+    }
+
+    /* Data starts at alignment boundary after header */
+    size_t align = 32; /* GGUF v3 default alignment */
+    gf->data_offset = (int64_t)((r.pos + align - 1) & ~(align - 1));
+
+    /* Adjust tensor offsets to be absolute file offsets */
+    for (int64_t i = 0; i < gf->n_tensors; i++)
+        gf->tensors[i].offset += gf->data_offset;
+
+    /* Compute nbytes per tensor from dtype and dims */
+    for (int64_t i = 0; i < gf->n_tensors; i++) {
+        int64_t numel = 1;
+        for (int d = 0; d < gf->tensors[i].n_dims; d++)
+            numel *= gf->tensors[i].dims[d];
+        switch (gf->tensors[i].dtype) {
+            case GGUF_TYPE_F32:  gf->tensors[i].nbytes = numel * 4; break;
+            case GGUF_TYPE_F16:  gf->tensors[i].nbytes = numel * 2; break;
+            case GGUF_TYPE_Q4_K: gf->tensors[i].nbytes = numel / 2 + (numel / 64) * 4; break;
+            case GGUF_TYPE_Q8_0: gf->tensors[i].nbytes = numel + (numel / 32) * 2; break;
+            default:             gf->tensors[i].nbytes = numel / 2; break;
+        }
+    }
+
+    gf->fd = fd;
+    free(buf);
+    return 0;
+}
+
+void gguf_close(GgufFile *gf) {
+    if (!gf) return;
+    if (gf->fd >= 0) close(gf->fd);
+    if (gf->tensors) {
+        for (int64_t i = 0; i < gf->n_tensors; i++)
+            free(gf->tensors[i].name);
+        free(gf->tensors);
+    }
+    memset(gf, 0, sizeof(*gf));
+    gf->fd = -1;
+}
+
+GgufTensor *gguf_find_tensor(const GgufFile *gf, const char *name) {
+    for (int64_t i = 0; i < gf->n_tensors; i++)
+        if (gf->tensors[i].name && strcmp(gf->tensors[i].name, name) == 0)
+            return &gf->tensors[i];
+    return NULL;
+}
+
+int64_t gguf_metadata_int(const GgufFile *gf, const char *key) {
+    (void)gf; (void)key;
+    /* Stub: metadata already cached in GgufFile struct during gguf_open */
+    return -1;
+}
+
+const char *gguf_metadata_str(const GgufFile *gf, const char *key) {
+    (void)gf; (void)key;
+    /* Stub: metadata already cached in GgufFile struct during gguf_open */
+    return NULL;
+}
diff --git a/internal/training/grpo_engine/grpo.h b/internal/training/grpo_engine/grpo.h
new file mode 100644
index 00000000..78b2e1f5
--- /dev/null
+++ b/internal/training/grpo_engine/grpo.h
@@ -0,0 +1,102 @@
+/* internal/training/grpo_engine/grpo.h */
+#ifndef GRPO_H
+#define GRPO_H
+
+#include <stdint.h>
+#include <stddef.h>
+
+/* ─── GGUF Types ─── */
+#define GGUF_MAGIC 0x46475547  /* "GGUF" little-endian */
+
+typedef enum {
+    GGUF_TYPE_F32   = 0,
+    GGUF_TYPE_F16   = 1,
+    GGUF_TYPE_Q4_0  = 2,
+    GGUF_TYPE_Q4_1  = 3,
+    GGUF_TYPE_Q5_0  = 6,
+    GGUF_TYPE_Q5_1  = 7,
+    GGUF_TYPE_Q8_0  = 8,
+    GGUF_TYPE_Q4_K  = 12,
+    GGUF_TYPE_Q6_K  = 14,
+} GgufDtype;
+
+typedef struct {
+    char       *name;
+    int64_t     offset;    /* byte offset from data start */
+    int64_t     nbytes;    /* total bytes */
+    GgufDtype   dtype;
+    int         n_dims;
+    int64_t     dims[4];
+} GgufTensor;
+
+typedef struct {
+    int           fd;
+    int           version;
+    int64_t       n_tensors;
+    int64_t       data_offset;   /* byte offset where tensor data begins */
+    GgufTensor   *tensors;       /* array of n_tensors */
+    /* metadata cache */
+    int64_t       n_layers;
+    int64_t       hidden_dim;
+    int64_t       intermediate_dim;
+    int64_t       n_heads;
+    int64_t       n_kv_heads;
+    int64_t       head_dim;
+    int64_t       vocab_size;
+    float         rms_eps;
+    float         rope_theta;
+} GgufFile;
+
+int         gguf_open(GgufFile *gf, const char *path);
+void        gguf_close(GgufFile *gf);
+GgufTensor *gguf_find_tensor(const GgufFile *gf, const char *name);
+int64_t     gguf_metadata_int(const GgufFile *gf, const char *key);
+const char *gguf_metadata_str(const GgufFile *gf, const char *key);
+
+/* ─── Forward declarations for other modules ─── */
+typedef struct GrpoCtx GrpoCtx;
+
+typedef struct {
+    const char *policy_gguf;
+    const char *reference_gguf;
+    const char *reward_gguf;
+    int         memory_mode;       /* 0=minimal, 1=standard, 2=comfort */
+    int         lora_rank;
+    int         lora_alpha;
+    const char *lora_targets;      /* "q,k,v,o,gate,up,down" */
+    int         max_seq_len;
+    int         num_threads;
+    int         use_direct_io;
+    size_t      layer_buffer_bytes;
+} GrpoConfig;
+
+typedef struct {
+    int64_t  steps;
+    double   total_gen_seconds;
+    double   total_stream_seconds;
+    double   total_backward_seconds;
+    uint64_t bytes_streamed;
+    float    last_loss;
+    float    last_reward_mean;
+} GrpoStats;
+
+/* ─── Engine API ─── */
+GrpoCtx    *grpo_init(GrpoConfig *cfg);
+void        grpo_free(GrpoCtx *ctx);
+int         grpo_generate(GrpoCtx *ctx, const int *prompt, int prompt_len,
+                          int *output, int max_len, float *logprobs_out,
+                          float temp, float top_p);
+int         grpo_policy_logprobs(GrpoCtx *ctx, const int *tokens, int len, float *logprobs_out);
+int         grpo_ref_logprobs(GrpoCtx *ctx, const int *tokens, int len, float *logprobs_out);
+int         grpo_reward_forward(GrpoCtx *ctx, const int *tokens, int len, float *score_out);
+int         grpo_backward(GrpoCtx *ctx, const float *advantages,
+                          const float *policy_logprobs, const float *old_logprobs,
+                          const float *ref_logprobs, int G, int seq_len,
+                          float clip_eps, float kl_coef);
+int         grpo_adam_step(GrpoCtx *ctx, float lr, float beta1, float beta2, float eps, int step);
+int         grpo_save_lora(GrpoCtx *ctx, const char *path);
+int         grpo_load_lora(GrpoCtx *ctx, const char *path);
+int         grpo_export_merged_gguf(GrpoCtx *ctx, const char *output_path);
+GrpoStats   grpo_stats(GrpoCtx *ctx);
+
+#endif /* GRPO_H */
diff --git a/internal/training/grpo_engine/kernels.c b/internal/training/grpo_engine/kernels.c
new file mode 100644
index 00000000..26daea4a
--- /dev/null
+++ b/internal/training/grpo_engine/kernels.c
@@ -0,0 +1,2 @@
+/* kernels.c stub */
+#include "grpo.h"
diff --git a/internal/training/grpo_engine/lora.c b/internal/training/grpo_engine/lora.c
new file mode 100644
index 00000000..f200abad
--- /dev/null
+++ b/internal/training/grpo_engine/lora.c
@@ -0,0 +1,2 @@
+/* lora.c stub */
+#include "grpo.h"
diff --git a/internal/training/grpo_engine/policy.c b/internal/training/grpo_engine/policy.c
new file mode 100644
index 00000000..e4609617
--- /dev/null
+++ b/internal/training/grpo_engine/policy.c
@@ -0,0 +1,2 @@
+/* policy.c stub */
+#include "grpo.h"
diff --git a/internal/training/grpo_engine/stream.c b/internal/training/grpo_engine/stream.c
new file mode 100644
index 00000000..c9de844f
--- /dev/null
+++ b/internal/training/grpo_engine/stream.c
@@ -0,0 +1,2 @@
+/* stream.c stub */
+#include "grpo.h"
