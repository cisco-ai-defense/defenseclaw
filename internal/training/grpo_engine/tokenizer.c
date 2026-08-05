/* internal/training/grpo_engine/tokenizer.c */
#include "tokenizer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ─── Internal Structures ─── */

struct MergeRule {
    int left;
    int right;
    int result;
    int priority;  /* lower = higher priority (applied first) */
};

struct TokenHashEntry {
    char *key;
    int   key_len;
    int   id;
    struct TokenHashEntry *next;
};

struct GrpoTokenizer {
    char   **vocab;        /* vocab[id] = token string */
    int     *vocab_len;    /* byte lengths */
    int      vocab_size;

    struct TokenHashEntry **hash_table;
    int                     hash_capacity;

    struct MergeRule *merges;
    int               n_merges;

    int bos_id;
    int eos_id;
    int pad_id;
};

/* ─── Hash Table (FNV-1a) ─── */

static unsigned int hash_bytes(const char *data, int len) {
    unsigned int h = 2166136261u;
    for (int i = 0; i < len; i++) {
        h ^= (unsigned char)data[i];
        h *= 16777619u;
    }
    return h;
}

static void hash_insert(struct GrpoTokenizer *tok, const char *key, int key_len, int id) {
    unsigned int idx = hash_bytes(key, key_len) % (unsigned int)tok->hash_capacity;
    struct TokenHashEntry *entry = (struct TokenHashEntry *)malloc(sizeof(struct TokenHashEntry));
    if (!entry) return; /* Safe degradation: skip insertion if allocation fails */
    entry->key = (char *)malloc((size_t)key_len + 1);
    if (!entry->key) {
        free(entry);
        return; /* Safe degradation: skip insertion if key allocation fails */
    }
    memcpy(entry->key, key, (size_t)key_len);
    entry->key[key_len] = '\0';
    entry->key_len = key_len;
    entry->id = id;
    entry->next = tok->hash_table[idx];
    tok->hash_table[idx] = entry;
}

static int hash_lookup(const struct GrpoTokenizer *tok, const char *key, int key_len) {
    unsigned int idx = hash_bytes(key, key_len) % (unsigned int)tok->hash_capacity;
    struct TokenHashEntry *e = tok->hash_table[idx];
    while (e) {
        if (e->key_len == key_len && memcmp(e->key, key, (size_t)key_len) == 0)
            return e->id;
        e = e->next;
    }
    return -1;
}

/* ─── Minimal JSON Parser ─── */
/* Only parses the specific schema of tokenizer.json: model.vocab, model.merges, added_tokens */

static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)len + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)len, f);
    buf[rd] = '\0';
    if (out_len) *out_len = rd;
    fclose(f);
    return buf;
}

static const char *skip_ws(const char *p) {
    while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    return p;
}

/* Parse a JSON string (handling basic escapes). Returns pointer past closing quote. */
static const char *parse_string(const char *p, char *out, int max_len, int *out_len) {
    if (*p != '"') return NULL;
    p++;
    int len = 0;
    while (*p && *p != '"') {
        if (*p == '\\') {
            p++;
            char c = *p;
            if (c == 'n') c = '\n';
            else if (c == 't') c = '\t';
            else if (c == 'r') c = '\r';
            else if (c == '\\') c = '\\';
            else if (c == '"') c = '"';
            else if (c == '/') c = '/';
            else if (c == 'u') {
                /* Parse 4-hex-digit unicode escape */
                unsigned int cp = 0;
                for (int i = 0; i < 4 && p[1+i]; i++) {
                    char h = p[1+i];
                    cp <<= 4;
                    if (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                    else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                }
                p += 4;
                /* Encode as UTF-8 */
                if (cp < 0x80 && len < max_len) {
                    out[len++] = (char)cp;
                } else if (cp < 0x800 && len + 1 < max_len) {
                    out[len++] = (char)(0xC0 | (cp >> 6));
                    out[len++] = (char)(0x80 | (cp & 0x3F));
                } else if (cp < 0x10000 && len + 2 < max_len) {
                    out[len++] = (char)(0xE0 | (cp >> 12));
                    out[len++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                    out[len++] = (char)(0x80 | (cp & 0x3F));
                }
                p++;
                continue;
            }
            if (len < max_len) out[len++] = c;
        } else {
            if (len < max_len) out[len++] = *p;
        }
        p++;
    }
    if (*p == '"') p++;
    if (len < max_len) out[len] = '\0';
    if (out_len) *out_len = len;
    return p;
}

/* Skip a JSON value (string, number, object, array, bool, null) */
static const char *skip_value(const char *p) {
    p = skip_ws(p);
    if (*p == '"') {
        p++;
        while (*p && *p != '"') { if (*p == '\\') p++; p++; }
        if (*p == '"') p++;
    } else if (*p == '{') {
        int depth = 1; p++;
        while (*p && depth > 0) {
            if (*p == '{') depth++;
            else if (*p == '}') depth--;
            else if (*p == '"') { p++; while (*p && *p != '"') { if (*p == '\\') p++; p++; } }
            p++;
        }
    } else if (*p == '[') {
        int depth = 1; p++;
        while (*p && depth > 0) {
            if (*p == '[') depth++;
            else if (*p == ']') depth--;
            else if (*p == '"') { p++; while (*p && *p != '"') { if (*p == '\\') p++; p++; } }
            p++;
        }
    } else {
        while (*p && *p != ',' && *p != '}' && *p != ']') p++;
    }
    return p;
}

/* Parse integer from JSON */
static const char *parse_int(const char *p, int *out) {
    p = skip_ws(p);
    int neg = 0;
    if (*p == '-') { neg = 1; p++; }
    int val = 0;
    while (*p >= '0' && *p <= '9') { val = val * 10 + (*p - '0'); p++; }
    *out = neg ? -val : val;
    return p;
}

/* ─── Load Tokenizer ─── */

GrpoTokenizer *grpo_tokenizer_load(const char *path) {
    size_t file_len;
    char *json = read_file(path, &file_len);
    if (!json) {
        fprintf(stderr, "tokenizer: cannot read %s\n", path);
        return NULL;
    }

    GrpoTokenizer *tok = (GrpoTokenizer *)calloc(1, sizeof(GrpoTokenizer));
    tok->bos_id = -1;
    tok->eos_id = -1;
    tok->pad_id = -1;

    /* First pass: find max vocab ID to allocate arrays */
    int max_id = 0;
    int n_vocab_entries = 0;

    /* Find "vocab": { ... } section */
    const char *vocab_start = strstr(json, "\"vocab\"");
    if (!vocab_start) {
        free(json);
        grpo_tokenizer_free(tok);
        return NULL;
    }
    vocab_start = strchr(vocab_start, '{');
    if (!vocab_start) {
        free(json);
        grpo_tokenizer_free(tok);
        return NULL;
    }

    /* Count entries and find max ID */
    const char *p = vocab_start + 1;
    while (*p && *p != '}') {
        p = skip_ws(p);
        if (*p == '}') break;
        if (*p == ',') { p++; continue; }
        /* Skip key string */
        char key_buf[512];
        int key_len;
        p = parse_string(p, key_buf, 511, &key_len);
        if (!p) break;
        p = skip_ws(p);
        if (*p == ':') p++;
        int id;
        p = parse_int(p, &id);
        if (id > max_id) max_id = id;
        n_vocab_entries++;
        p = skip_ws(p);
        if (*p == ',') p++;
    }

    /* Allocate vocab arrays */
    tok->vocab_size = max_id + 1;
    tok->vocab = (char **)calloc((size_t)tok->vocab_size, sizeof(char *));
    tok->vocab_len = (int *)calloc((size_t)tok->vocab_size, sizeof(int));

    /* Hash table: 2x capacity for low collision rate */
    tok->hash_capacity = n_vocab_entries * 2;
    if (tok->hash_capacity < 512) tok->hash_capacity = 512;
    tok->hash_table = (struct TokenHashEntry **)calloc((size_t)tok->hash_capacity,
                                                       sizeof(struct TokenHashEntry *));

    /* Second pass: populate vocab */
    p = vocab_start + 1;
    while (*p && *p != '}') {
        p = skip_ws(p);
        if (*p == '}') break;
        if (*p == ',') { p++; continue; }
        char key_buf[512];
        int key_len;
        p = parse_string(p, key_buf, 511, &key_len);
        if (!p) break;
        p = skip_ws(p);
        if (*p == ':') p++;
        int id;
        p = parse_int(p, &id);
        if (id >= 0 && id < tok->vocab_size) {
            tok->vocab[id] = (char *)malloc((size_t)key_len + 1);
            memcpy(tok->vocab[id], key_buf, (size_t)key_len);
            tok->vocab[id][key_len] = '\0';
            tok->vocab_len[id] = key_len;
            hash_insert(tok, key_buf, key_len, id);
        }
        p = skip_ws(p);
        if (*p == ',') p++;
    }

    /* Parse merges */
    const char *merges_start = strstr(json, "\"merges\"");
    if (merges_start) {
        merges_start = strchr(merges_start, '[');
        if (merges_start) {
            /* Count merges */
            int n_merges = 0;
            const char *mp = merges_start + 1;
            while (*mp && *mp != ']') {
                mp = skip_ws(mp);
                if (*mp == '"') { n_merges++; mp = skip_value(mp); }
                else if (*mp == ',') mp++;
                else mp++;
            }

            tok->merges = (struct MergeRule *)calloc((size_t)n_merges, sizeof(struct MergeRule));
            tok->n_merges = 0;

            /* Parse each merge "left right" */
            mp = merges_start + 1;
            int priority = 0;
            while (*mp && *mp != ']') {
                mp = skip_ws(mp);
                if (*mp == ',') { mp++; continue; }
                if (*mp != '"') { mp++; continue; }

                char merge_str[512];
                int merge_len;
                mp = parse_string(mp, merge_str, 511, &merge_len);
                if (!mp) break;

                /* Split on space */
                char *space = strchr(merge_str, ' ');
                if (space) {
                    *space = '\0';
                    char *left_str = merge_str;
                    char *right_str = space + 1;
                    int left_len = (int)(space - merge_str);
                    int right_len = merge_len - left_len - 1;

                    int left_id = hash_lookup(tok, left_str, left_len);
                    int right_id = hash_lookup(tok, right_str, right_len);

                    /* The merged token is left+right concatenated */
                    char merged[1024];
                    memcpy(merged, left_str, (size_t)left_len);
                    memcpy(merged + left_len, right_str, (size_t)right_len);
                    int merged_len = left_len + right_len;
                    int result_id = hash_lookup(tok, merged, merged_len);

                    if (left_id >= 0 && right_id >= 0 && result_id >= 0) {
                        tok->merges[tok->n_merges].left = left_id;
                        tok->merges[tok->n_merges].right = right_id;
                        tok->merges[tok->n_merges].result = result_id;
                        tok->merges[tok->n_merges].priority = priority;
                        tok->n_merges++;
                    }
                }
                priority++;
            }
        }
    }

    /* Parse added_tokens for BOS/EOS/PAD */
    const char *added = strstr(json, "\"added_tokens\"");
    if (added) {
        added = strchr(added, '[');
        if (added) {
            const char *ap = added + 1;
            while (*ap && *ap != ']') {
                ap = skip_ws(ap);
                if (*ap == ',') { ap++; continue; }
                if (*ap != '{') { ap++; continue; }

                /* Find "id" and "content" in this object */
                const char *obj_end = ap;
                int depth = 1;
                obj_end++;
                while (*obj_end && depth > 0) {
                    if (*obj_end == '{') depth++;
                    else if (*obj_end == '}') depth--;
                    else if (*obj_end == '"') {
                        obj_end++;
                        while (*obj_end && *obj_end != '"') { if (*obj_end == '\\') obj_end++; obj_end++; }
                    }
                    obj_end++;
                }

                /* Search for "content" */
                const char *content_key = strstr(ap, "\"content\"");
                const char *id_key = strstr(ap, "\"id\"");
                if (content_key && content_key < obj_end && id_key && id_key < obj_end) {
                    /* Parse content */
                    const char *cp = content_key + 9;
                    cp = skip_ws(cp);
                    if (*cp == ':') cp++;
                    cp = skip_ws(cp);
                    char content[256];
                    int content_len;
                    parse_string(cp, content, 255, &content_len);

                    /* Parse id */
                    const char *ip = id_key + 4;
                    ip = skip_ws(ip);
                    if (*ip == ':') ip++;
                    int token_id;
                    parse_int(ip, &token_id);

                    /* Identify special tokens */
                    if (strstr(content, "endoftext") || strstr(content, "eos"))
                        tok->eos_id = token_id;
                    else if (strstr(content, "startoftext") || strstr(content, "bos"))
                        tok->bos_id = token_id;
                    else if (strstr(content, "pad"))
                        tok->pad_id = token_id;
                }
                ap = obj_end;
            }
        }
    }

    free(json);
    return tok;
}

void grpo_tokenizer_free(GrpoTokenizer *tok) {
    if (!tok) return;
    for (int i = 0; i < tok->vocab_size; i++) free(tok->vocab[i]);
    free(tok->vocab);
    free(tok->vocab_len);
    for (int i = 0; i < tok->hash_capacity; i++) {
        struct TokenHashEntry *e = tok->hash_table[i];
        while (e) {
            struct TokenHashEntry *next = e->next;
            free(e->key);
            free(e);
            e = next;
        }
    }
    free(tok->hash_table);
    free(tok->merges);
    free(tok);
}

int grpo_tokenizer_vocab_size(const GrpoTokenizer *tok) {
    return tok ? tok->vocab_size : 0;
}

/* ─── BPE Encode ─── */

int grpo_tokenizer_encode(const GrpoTokenizer *tok, const char *text, int text_len,
                          int *output_ids, int max_tokens) {
    if (!tok || !text || text_len <= 0) return 0;

    /* Initialize: one token per byte (byte-level BPE) */
    /* Each byte maps to its single-char token ID via hash lookup */
    int *ids = (int *)malloc((size_t)text_len * sizeof(int));
    int n = 0;
    for (int i = 0; i < text_len; i++) {
        char byte_str[2] = { text[i], '\0' };
        int id = hash_lookup(tok, byte_str, 1);
        if (id >= 0) {
            ids[n++] = id;
        }
        /* Skip unknown bytes silently — don't add invalid token IDs */
    }

    /* Apply merges in priority order */
    /* Iterative: scan for best (lowest priority) merge, apply, repeat */
    int changed = 1;
    while (changed) {
        changed = 0;
        int best_pos = -1;
        int best_priority = tok->n_merges; /* higher than any real priority */
        int best_result = -1;

        for (int i = 0; i < n - 1; i++) {
            /* Check if (ids[i], ids[i+1]) is a merge pair */
            for (int m = 0; m < tok->n_merges; m++) {
                if (tok->merges[m].priority >= best_priority) continue;
                if (tok->merges[m].left == ids[i] && tok->merges[m].right == ids[i + 1]) {
                    best_pos = i;
                    best_priority = tok->merges[m].priority;
                    best_result = tok->merges[m].result;
                    break; /* This pair found its best merge, move to next position */
                }
            }
        }

        if (best_pos >= 0) {
            ids[best_pos] = best_result;
            /* Shift remaining left */
            for (int i = best_pos + 1; i < n - 1; i++) {
                ids[i] = ids[i + 1];
            }
            n--;
            changed = 1;
        }
    }

    /* Copy result */
    int out_n = n < max_tokens ? n : max_tokens;
    memcpy(output_ids, ids, (size_t)out_n * sizeof(int));
    free(ids);
    return out_n;
}

/* ─── BPE Decode ─── */

int grpo_tokenizer_decode(const GrpoTokenizer *tok, const int *ids, int n_ids,
                          char *output_buf, int buf_size) {
    if (!tok || !ids || n_ids <= 0) return 0;

    int pos = 0;
    for (int i = 0; i < n_ids; i++) {
        int id = ids[i];
        if (id < 0 || id >= tok->vocab_size || !tok->vocab[id]) continue;
        int len = tok->vocab_len[id];
        if (pos + len >= buf_size) break;
        memcpy(output_buf + pos, tok->vocab[id], (size_t)len);
        pos += len;
    }
    if (pos < buf_size) output_buf[pos] = '\0';
    return pos;
}
