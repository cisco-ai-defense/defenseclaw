/* gguf.c
 *
 * Parses GGUF v3 format: header → metadata KV pairs → tensor info → tensor data.
 * Reference: https://github.com/ggerganov/ggml/blob/master/docs/gguf.md
 */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "grpo.h"

/* GGUF metadata value types */
enum { GV_U8=0, GV_I8, GV_U16, GV_I16, GV_U32, GV_I32, GV_F32,
       GV_BOOL, GV_STR, GV_ARR, GV_U64, GV_I64, GV_F64 };

typedef struct {
    const uint8_t *data;
    size_t         size;
    size_t         pos;
} Reader;

static int read_bytes(Reader *r, void *dst, size_t n) {
    if (r->pos + n > r->size) return -1;
    memcpy(dst, r->data + r->pos, n);
    r->pos += n;
    return 0;
}
static uint32_t read_u32(Reader *r) { uint32_t v = 0; read_bytes(r, &v, 4); return v; }
static uint64_t read_u64(Reader *r) { uint64_t v = 0; read_bytes(r, &v, 8); return v; }
static int64_t  read_i64(Reader *r) { int64_t v = 0;  read_bytes(r, &v, 8); return v; }
static float    read_f32(Reader *r) { float v = 0.0f;    read_bytes(r, &v, 4); return v; }

static char *read_str(Reader *r) {
    uint64_t len = read_u64(r);
    /* Guard against overflow: len could wrap r->pos beyond r->size */
    if (len > r->size || len > r->size - r->pos) return NULL;
    char *s = (char *)malloc(len + 1);
    if (!s) return NULL;
    memcpy(s, r->data + r->pos, len);
    s[len] = 0;
    r->pos += len;
    return s;
}

static void skip_value(Reader *r, uint32_t vtype) {
    switch (vtype) {
        case GV_U8: case GV_I8: case GV_BOOL: r->pos += 1; break;
        case GV_U16: case GV_I16: r->pos += 2; break;
        case GV_U32: case GV_I32: case GV_F32: r->pos += 4; break;
        case GV_U64: case GV_I64: case GV_F64: r->pos += 8; break;
        case GV_STR: { uint64_t len = read_u64(r); r->pos += len; break; }
        case GV_ARR: {
            uint32_t atype = read_u32(r);
            uint64_t alen = read_u64(r);
            for (uint64_t i = 0; i < alen; i++) {
                /* Guard against buffer overrun in recursive array skip */
                if (r->pos >= r->size) return;
                skip_value(r, atype);
            }
            break;
        }
    }
}

int gguf_open(GgufFile *gf, const char *path) {
    memset(gf, 0, sizeof(*gf));
    gf->fd = -1;

    /* Read entire file for header parsing (GGUF headers are small, data is at the end) */
    int fd = open(path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "gguf: cannot open %s\n", path); return -1; }

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }

    /* Read enough for header — at most 64 MB for metadata, rest is tensor data */
    size_t header_budget = (st.st_size < 64*1024*1024) ? (size_t)st.st_size : 64*1024*1024;
    uint8_t *buf = (uint8_t *)malloc(header_budget);
    if (!buf) { close(fd); return -1; }
    if (pread(fd, buf, header_budget, 0) != (ssize_t)header_budget) {
        free(buf); close(fd); return -1;
    }

    Reader r = { .data = buf, .size = header_budget, .pos = 0 };

    /* Magic + version */
    uint32_t magic = read_u32(&r);
    if (magic != GGUF_MAGIC) {
        fprintf(stderr, "gguf: bad magic in %s\n", path);
        free(buf); close(fd); return -1;
    }
    gf->version = (int)read_u32(&r);
    gf->n_tensors = (int64_t)read_u64(&r);
    int64_t n_kv = (int64_t)read_u64(&r);

    /* Parse metadata KV */
    gf->rms_eps = 1e-5f;
    gf->rope_theta = 10000.0f;
    for (int64_t i = 0; i < n_kv; i++) {
        char *key = read_str(&r);
        uint32_t vtype = read_u32(&r);

        /* Extract architecture metadata we need */
        if (key && vtype == GV_U64) {
            int64_t val = (int64_t)read_u64(&r);
            if (strstr(key, "block_count"))       gf->n_layers = val;
            else if (strstr(key, "embedding_length")) gf->hidden_dim = val;
            else if (strstr(key, "feed_forward_length")) gf->intermediate_dim = val;
            else if (strstr(key, "head_count_kv")) gf->n_kv_heads = val;
            else if (strstr(key, "head_count"))    gf->n_heads = val;
        } else if (key && vtype == GV_U32) {
            uint32_t val = read_u32(&r);
            if (strstr(key, "block_count"))       gf->n_layers = val;
            else if (strstr(key, "embedding_length")) gf->hidden_dim = val;
            else if (strstr(key, "feed_forward_length")) gf->intermediate_dim = val;
            else if (strstr(key, "head_count_kv")) gf->n_kv_heads = val;
            else if (strstr(key, "head_count"))    gf->n_heads = val;
            else if (strstr(key, "vocab_size"))   gf->vocab_size = val;
        } else if (key && vtype == GV_F32) {
            float val = read_f32(&r);
            if (strstr(key, "rms_norm_eps") || strstr(key, "rms_epsilon"))   gf->rms_eps = val;
            else if (strstr(key, "rope.freq_base")) gf->rope_theta = val;
        } else {
            /* Must skip value even if key read failed (NULL key) */
            skip_value(&r, vtype);
        }
        free(key); /* free(NULL) is safe */
    }

    if (gf->n_heads > 0 && gf->hidden_dim > 0)
        gf->head_dim = gf->hidden_dim / gf->n_heads;
    if (gf->n_kv_heads == 0) gf->n_kv_heads = gf->n_heads;

    fprintf(stderr, "gguf: rope_theta=%.1f, rms_eps=%.2e\n", gf->rope_theta, gf->rms_eps);

    /* Parse tensor info */
    gf->tensors = (GgufTensor *)calloc((size_t)gf->n_tensors, sizeof(GgufTensor));
    if (!gf->tensors) { free(buf); close(fd); return -1; }

    for (int64_t i = 0; i < gf->n_tensors; i++) {
        gf->tensors[i].name = read_str(&r);
        /* If name read fails, treat as parse error to avoid memory leak */
        if (!gf->tensors[i].name) {
            fprintf(stderr, "gguf: failed to read tensor name at index %lld\n", (long long)i);
            goto bad;
        }
        gf->tensors[i].n_dims = (int)read_u32(&r);
        for (int d = 0; d < gf->tensors[i].n_dims; d++)
            gf->tensors[i].dims[d] = (int64_t)read_u64(&r);
        gf->tensors[i].dtype = (GgufDtype)read_u32(&r);
        gf->tensors[i].offset = (int64_t)read_u64(&r);
    }

    /* Data starts at alignment boundary after header */
    size_t align = 32; /* GGUF v3 default alignment */
    gf->data_offset = (int64_t)((r.pos + align - 1) & ~(align - 1));

    /* Adjust tensor offsets to be absolute file offsets */
    for (int64_t i = 0; i < gf->n_tensors; i++)
        gf->tensors[i].offset += gf->data_offset;

    /* Compute nbytes per tensor from dtype and dims */
    for (int64_t i = 0; i < gf->n_tensors; i++) {
        int64_t numel = 1;
        for (int d = 0; d < gf->tensors[i].n_dims; d++) {
            /* Guard against integer overflow in tensor size calculation */
            if (numel > INT64_MAX / gf->tensors[i].dims[d]) {
                fprintf(stderr, "gguf: tensor %lld has overflowing dimensions\n", (long long)i);
                numel = INT64_MAX / 2; /* Cap to safe value */
                break;
            }
            numel *= gf->tensors[i].dims[d];
        }
        switch (gf->tensors[i].dtype) {
            case GGUF_TYPE_F32:  gf->tensors[i].nbytes = numel * 4; break;
            case GGUF_TYPE_F16:  gf->tensors[i].nbytes = numel * 2; break;
            case GGUF_TYPE_Q4_K: gf->tensors[i].nbytes = numel / 2 + (numel / 64) * 4; break;
            case GGUF_TYPE_Q8_0: gf->tensors[i].nbytes = numel + (numel / 32) * 2; break;
            default:             gf->tensors[i].nbytes = numel / 2; break;
        }
    }

    /* Infer vocab_size from token_embd.weight if not in metadata */
    if (gf->vocab_size == 0) {
        for (int64_t i = 0; i < gf->n_tensors; i++) {
            if (gf->tensors[i].name && strcmp(gf->tensors[i].name, "token_embd.weight") == 0) {
                if (gf->tensors[i].n_dims >= 2)
                    gf->vocab_size = gf->tensors[i].dims[1]; /* [hidden, vocab] */
                break;
            }
        }
    }

    gf->fd = fd;
    free(buf);
    return 0;

bad:
    /* Cleanup on parse error */
    if (gf->tensors) {
        for (int64_t j = 0; j < gf->n_tensors; j++)
            free(gf->tensors[j].name);
        free(gf->tensors);
        gf->tensors = NULL;
    }
    free(buf);
    close(fd);
    return -1;
}

void gguf_close(GgufFile *gf) {
    if (!gf) return;
    if (gf->fd >= 0) close(gf->fd);
    if (gf->tensors) {
        for (int64_t i = 0; i < gf->n_tensors; i++)
            free(gf->tensors[i].name);
        free(gf->tensors);
    }
    memset(gf, 0, sizeof(*gf));
    gf->fd = -1;
}

GgufTensor *gguf_find_tensor(const GgufFile *gf, const char *name) {
    for (int64_t i = 0; i < gf->n_tensors; i++)
        if (gf->tensors[i].name && strcmp(gf->tensors[i].name, name) == 0)
            return &gf->tensors[i];
    return NULL;
}

int64_t gguf_metadata_int(const GgufFile *gf, const char *key) {
    (void)gf; (void)key;
    /* Stub: metadata already cached in GgufFile struct during gguf_open */
    return -1;
}

const char *gguf_metadata_str(const GgufFile *gf, const char *key) {
    (void)gf; (void)key;
    /* Stub: metadata already cached in GgufFile struct during gguf_open */
    return NULL;
}
