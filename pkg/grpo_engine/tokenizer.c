/* grpo_engine */
#include "tokenizer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

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

/* GPT-2 byte decoder: converts unicode codepoints back to raw bytes.
 * Ġ (U+0120) → space, Ċ (U+010A) → newline, etc. */
static int gpt2_byte_decode(const char *input, int input_len, char *output, int output_size) {
    int out_pos = 0;
    int i = 0;
    while (i < input_len && out_pos < output_size - 1) {
        unsigned char c = (unsigned char)input[i];
        uint32_t codepoint;
        int char_len;

        /* Decode UTF-8 to codepoint */
        if (c < 0x80) {
            codepoint = c; char_len = 1;
        } else if ((c & 0xE0) == 0xC0) {
            if (i + 1 >= input_len) break;
            codepoint = ((c & 0x1F) << 6) | (input[i+1] & 0x3F); char_len = 2;
        } else if ((c & 0xF0) == 0xE0) {
            if (i + 2 >= input_len) break;
            codepoint = ((c & 0x0F) << 12) | ((input[i+1] & 0x3F) << 6) | (input[i+2] & 0x3F); char_len = 3;
        } else {
            if (i + 3 >= input_len) break;
            codepoint = ((c & 0x07) << 18) | ((input[i+1] & 0x3F) << 12) | ((input[i+2] & 0x3F) << 6) | (input[i+3] & 0x3F); char_len = 4;
        }
        i += char_len;

        /* Map GPT-2 codepoint back to byte value */
        uint8_t byte_val;
        if (codepoint >= 0x21 && codepoint <= 0x7E) {
            byte_val = (uint8_t)codepoint; /* printable ASCII maps to itself */
        } else if (codepoint >= 0xA1 && codepoint <= 0xAC) {
            byte_val = (uint8_t)codepoint;
        } else if (codepoint >= 0xAE && codepoint <= 0xFF) {
            byte_val = (uint8_t)codepoint;
        } else if (codepoint >= 0x100 && codepoint <= 0x100 + 32) {
            /* Mapped bytes: 0x00-0x20 → U+0100-U+0120 */
            byte_val = (uint8_t)(codepoint - 0x100);
        } else if (codepoint >= 0x121 && codepoint <= 0x144) {
            /* Mapped bytes: remaining non-printable */
            /* 0x7F→U+0121, 0x80→U+0122, ..., 0xA0→U+0142, 0xAD→U+0143, 0x100+→... */
            /* Simplified: build reverse map for the remaining bytes */
            /* The GPT-2 mapping for non-printable/non-Latin1 bytes:
             * byte 0x7F → U+0121, 0x80→U+0122, ..., 0x9F→U+0141,
             * 0xA0→U+0142, 0xAD→U+0143 */
            static const uint8_t remap[] = {
                0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
                0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92,
                0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C,
                0x9D, 0x9E, 0x9F, 0xA0, 0xAD
            };
            int idx = (int)(codepoint - 0x121);
            byte_val = (idx >= 0 && idx < 35) ? remap[idx] : '?';
        } else {
            /* Unknown — write as UTF-8 directly */
            for (int k = 0; k < char_len && out_pos < output_size - 1; k++)
                output[out_pos++] = input[i - char_len + k];
            continue;
        }
        output[out_pos++] = (char)byte_val;
    }
    output[out_pos] = '\0';
    return out_pos;
}

int grpo_tokenizer_decode(const GrpoTokenizer *tok, const int *ids, int n_ids,
                          char *output_buf, int buf_size) {
    if (!tok || !ids || n_ids <= 0) return 0;

    /* First pass: concatenate raw BPE token strings */
    int raw_size = buf_size * 2;
    char *raw = (char *)malloc((size_t)raw_size);
    if (!raw) return 0;

    int pos = 0;
    for (int i = 0; i < n_ids; i++) {
        int id = ids[i];
        if (id < 0 || id >= tok->vocab_size || !tok->vocab[id]) continue;
        int len = tok->vocab_len[id];
        if (pos + len >= raw_size) break;
        memcpy(raw + pos, tok->vocab[id], (size_t)len);
        pos += len;
    }
    raw[pos] = '\0';

    /* Second pass: convert GPT-2 byte encoding to actual UTF-8 */
    int result = gpt2_byte_decode(raw, pos, output_buf, buf_size);
    free(raw);
    return result;
}

/* ─── Load Tokenizer from GGUF Metadata ─── */

static uint32_t gguf_read_u32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t gguf_read_u64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

GrpoTokenizer *grpo_tokenizer_load_gguf(const char *gguf_path) {
    int fd = open(gguf_path, O_RDONLY);
    if (fd < 0) return NULL;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return NULL; }

    /* Read header — need enough for metadata (tokens array can be large).
     * Qwen3-8B has ~151K tokens averaging ~6 bytes each = ~1 MB of token strings.
     * Read up to 128 MB to be safe. */
    size_t budget = (size_t)st.st_size;
    if (budget > 128 * 1024 * 1024) budget = 128 * 1024 * 1024;
    uint8_t *buf = (uint8_t *)malloc(budget);
    if (!buf) { close(fd); return NULL; }
    ssize_t rd = pread(fd, buf, budget, 0);
    close(fd);
    if (rd < 28) { free(buf); return NULL; }

    /* Parse GGUF header */
    size_t pos = 0;
    uint32_t magic = gguf_read_u32(buf + pos); pos += 4;
    if (magic != 0x46554747) { free(buf); return NULL; } /* 'GGUF' */
    pos += 4; /* version */
    pos += 8; /* n_tensors */
    uint64_t n_kv = gguf_read_u64(buf + pos); pos += 8;

    /* Scan metadata for tokenizer arrays */
    char **tokens_arr = NULL;
    int *tokens_len_arr = NULL;
    int64_t n_tokens = 0;
    int eos_id = -1, bos_id = -1, pad_id = -1;

    for (uint64_t i = 0; i < n_kv && pos < (size_t)rd - 4; i++) {
        /* Read key string */
        if (pos + 8 > (size_t)rd) break;
        uint64_t key_len = gguf_read_u64(buf + pos); pos += 8;
        if (pos + key_len > (size_t)rd) break;
        const char *key = (const char *)(buf + pos);
        pos += key_len;

        /* Read value type */
        if (pos + 4 > (size_t)rd) break;
        uint32_t vtype = gguf_read_u32(buf + pos); pos += 4;

        int is_tokens = (key_len == 21 && memcmp(key, "tokenizer.ggml.tokens", 21) == 0);
        int is_eos = (key_len >= 20 && key_len < 64 && memmem(key, key_len, "eos_token_id", 12) != NULL);
        int is_bos = (key_len >= 20 && key_len < 64 && memmem(key, key_len, "bos_token_id", 12) != NULL);
        int is_pad = (key_len >= 20 && key_len < 64 && memmem(key, key_len, "padding_token_id", 16) != NULL);

        if (is_eos && vtype == 4) { /* u32 */
            if (pos + 4 > (size_t)rd) break;
            eos_id = (int)gguf_read_u32(buf + pos); pos += 4;
        } else if (is_bos && vtype == 4) {
            if (pos + 4 > (size_t)rd) break;
            bos_id = (int)gguf_read_u32(buf + pos); pos += 4;
        } else if (is_pad && vtype == 4) {
            if (pos + 4 > (size_t)rd) break;
            pad_id = (int)gguf_read_u32(buf + pos); pos += 4;
        } else if (is_tokens && vtype == 9) { /* array */
            if (pos + 12 > (size_t)rd) break;
            uint32_t arr_type = gguf_read_u32(buf + pos); pos += 4;
            uint64_t arr_len = gguf_read_u64(buf + pos); pos += 8;
            if (arr_type != 8) { /* must be string array */
                /* Skip non-string array */
                for (uint64_t j = 0; j < arr_len && pos < (size_t)rd; j++) {
                    if (arr_type <= 1 || arr_type == 7) pos += 1;
                    else if (arr_type <= 3) pos += 2;
                    else if (arr_type <= 6) pos += 4;
                    else pos += 8;
                }
                continue;
            }
            n_tokens = (int64_t)arr_len;
            tokens_arr = (char **)calloc((size_t)n_tokens, sizeof(char *));
            tokens_len_arr = (int *)calloc((size_t)n_tokens, sizeof(int));
            if (!tokens_arr || !tokens_len_arr) break;

            for (int64_t j = 0; j < n_tokens && pos + 8 <= (size_t)rd; j++) {
                uint64_t slen = gguf_read_u64(buf + pos); pos += 8;
                if (pos + slen > (size_t)rd) { n_tokens = j; break; }
                tokens_arr[j] = (char *)malloc(slen + 1);
                if (tokens_arr[j]) {
                    memcpy(tokens_arr[j], buf + pos, slen);
                    tokens_arr[j][slen] = '\0';
                    tokens_len_arr[j] = (int)slen;
                }
                pos += slen;
            }
        } else {
            /* Skip other value types */
            switch (vtype) {
                case 0: case 1: case 7: pos += 1; break;
                case 2: case 3: pos += 2; break;
                case 4: case 5: case 6: pos += 4; break;
                case 10: case 11: case 12: pos += 8; break;
                case 8: { /* string */
                    if (pos + 8 > (size_t)rd) goto done;
                    uint64_t slen = gguf_read_u64(buf + pos); pos += 8;
                    pos += slen;
                    break;
                }
                case 9: { /* array */
                    if (pos + 12 > (size_t)rd) goto done;
                    uint32_t at = gguf_read_u32(buf + pos); pos += 4;
                    uint64_t al = gguf_read_u64(buf + pos); pos += 8;
                    for (uint64_t j = 0; j < al && pos < (size_t)rd; j++) {
                        if (at == 8) {
                            if (pos + 8 > (size_t)rd) goto done;
                            uint64_t sl = gguf_read_u64(buf + pos); pos += 8;
                            pos += sl;
                        } else if (at <= 1 || at == 7) pos += 1;
                        else if (at <= 3) pos += 2;
                        else if (at <= 6) pos += 4;
                        else pos += 8;
                    }
                    break;
                }
                default: goto done;
            }
        }
    }
done:
    free(buf);

    if (!tokens_arr || n_tokens == 0) {
        free(tokens_arr);
        free(tokens_len_arr);
        return NULL;
    }

    /* Build tokenizer from extracted vocab */
    GrpoTokenizer *tok = (GrpoTokenizer *)calloc(1, sizeof(GrpoTokenizer));
    tok->vocab_size = (int)n_tokens;
    tok->vocab = tokens_arr;
    tok->vocab_len = tokens_len_arr;
    tok->bos_id = bos_id;
    tok->eos_id = eos_id;
    tok->pad_id = pad_id;
    tok->hash_capacity = (int)n_tokens * 2;
    tok->hash_table = (struct TokenHashEntry **)calloc((size_t)tok->hash_capacity,
                                                       sizeof(struct TokenHashEntry *));
    for (int i = 0; i < tok->vocab_size; i++) {
        if (tok->vocab[i])
            hash_insert(tok, tok->vocab[i], tok->vocab_len[i], i);
    }

    fprintf(stderr, "tokenizer: loaded %d tokens from GGUF (eos=%d, bos=%d)\n",
            tok->vocab_size, tok->eos_id, tok->bos_id);
    return tok;
}
