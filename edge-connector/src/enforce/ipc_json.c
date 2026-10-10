#include "defenseclaw.h"
#include "platform.h"
#include <string.h>
#include <stdlib.h>

/*
 * Minimal JSON-RPC parser for fixed-schema tool call requests.
 * No external dependencies. Handles the exact schema expected:
 *
 * {"jsonrpc":"2.0","method":"evaluate","params":{
 *   "tool_name":"...", "tool_hash":"...", "capabilities":N,
 *   "destination":"...", "session_id":N, "direction":N, "content":"..."},"id":N}
 *
 * Strict validation: rejects anything that doesn't exactly match.
 * direction and content are optional (Phase 1B extension).
 */

static const char *skip_whitespace(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static const char *parse_string(const char *p, char *out, size_t max_len) {
    if (*p != '"') return NULL;
    p++;
    size_t i = 0;
    while (*p != '"' && *p != '\0' && i < max_len - 1) {
        if (*p == '\\') {
            p++;
            if (*p == '\0') return NULL;
            switch (*p) {
            case '"': case '\\': case '/':
                out[i++] = *p++;
                break;
            case 'n': out[i++] = '\n'; p++; break;
            case 't': out[i++] = '\t'; p++; break;
            case 'r': out[i++] = '\r'; p++; break;
            case 'b': out[i++] = '\b'; p++; break;
            case 'f': out[i++] = '\f'; p++; break;
            case 'u': out[i++] = '?'; p++; break; /* placeholder for \uXXXX */
            default:
                return NULL; /* reject invalid escape sequences */
            }
        } else {
            if ((unsigned char)*p < 0x20)
                return NULL; /* reject unescaped control characters */
            out[i++] = *p++;
        }
    }
    out[i] = '\0';
    if (*p != '"') return NULL;
    return p + 1;
}

static const char *parse_uint(const char *p, uint32_t *out) {
    if (*p < '0' || *p > '9') return NULL;
    *out = 0;
    while (*p >= '0' && *p <= '9') {
        uint32_t digit = (uint32_t)(*p - '0');
        if (*out > (UINT32_MAX - digit) / 10) {
            return NULL; /* overflow */
        }
        *out = (*out * 10) + digit;
        p++;
    }
    return p;
}

static int hex_to_byte(char hi, char lo) {
    int h, l;
    if (hi >= '0' && hi <= '9') h = hi - '0';
    else if (hi >= 'a' && hi <= 'f') h = hi - 'a' + 10;
    else if (hi >= 'A' && hi <= 'F') h = hi - 'A' + 10;
    else return -1;
    if (lo >= '0' && lo <= '9') l = lo - '0';
    else if (lo >= 'a' && lo <= 'f') l = lo - 'a' + 10;
    else if (lo >= 'A' && lo <= 'F') l = lo - 'A' + 10;
    else return -1;
    return (h << 4) | l;
}

int dclaw_ipc_parse_request(const char *json, size_t json_len,
                            dclaw_tool_request_t *out) {
    if (json_len > DCLAW_IPC_MAX_PAYLOAD) return -1;
    if (json[json_len] != '\0') return -1; /* must be NUL-terminated */

    memset(out, 0, sizeof(dclaw_tool_request_t));

    const char *p = skip_whitespace(json);
    if (*p != '{') return -1;
    p++;

    /* We need: method, params.tool_name, params.tool_hash, params.capabilities,
     * params.session_id, and optionally params.destination */
    bool got_tool_name = false, got_hash = false, got_caps = false, got_session = false;
    bool got_id = false;

    /* Simplified: scan for known keys in any order */
    char key_buf[32];
    char val_buf[256];

    while (*p != '\0' && *p != '}') {
        p = skip_whitespace(p);
        if (*p == ',') { p++; continue; }
        if (*p == '}') break;

        /* Parse key */
        const char *after_key = parse_string(p, key_buf, sizeof(key_buf));
        if (!after_key) return -1;
        p = skip_whitespace(after_key);
        if (*p != ':') return -1;
        p = skip_whitespace(p + 1);

        if (strcmp(key_buf, "params") == 0) {
            /* Nested object */
            if (*p != '{') return -1;
            p++;
            while (*p != '\0' && *p != '}') {
                p = skip_whitespace(p);
                if (*p == ',') { p++; continue; }
                if (*p == '}') break;

                const char *pk = parse_string(p, key_buf, sizeof(key_buf));
                if (!pk) return -1;
                p = skip_whitespace(pk);
                if (*p != ':') return -1;
                p = skip_whitespace(p + 1);

                if (strcmp(key_buf, "tool_name") == 0) {
                    p = parse_string(p, out->tool_name, DCLAW_TOOL_NAME_MAX);
                    if (!p) return -1;
                    got_tool_name = true;
                } else if (strcmp(key_buf, "tool_hash") == 0) {
                    p = parse_string(p, val_buf, sizeof(val_buf));
                    if (!p) return -1;
                    if (strlen(val_buf) != 64) return -1;
                    for (int i = 0; i < 32; i++) {
                        int b = hex_to_byte(val_buf[i*2], val_buf[i*2+1]);
                        if (b < 0) return -1;
                        out->tool_hash[i] = (uint8_t)b;
                    }
                    got_hash = true;
                } else if (strcmp(key_buf, "capabilities") == 0) {
                    uint32_t v;
                    p = parse_uint(p, &v);
                    if (!p || v > 0x7F) return -1;
                    out->cap_flags = (uint8_t)v;
                    got_caps = true;
                } else if (strcmp(key_buf, "session_id") == 0) {
                    uint32_t v;
                    p = parse_uint(p, &v);
                    if (!p || v > 65535) return -1;
                    out->session_id = (uint16_t)v;
                    got_session = true;
                } else if (strcmp(key_buf, "destination") == 0) {
                    p = parse_string(p, out->destination, DCLAW_DESTINATION_MAX);
                    if (!p) return -1;
                } else if (strcmp(key_buf, "direction") == 0) {
                    uint32_t v;
                    p = parse_uint(p, &v);
                    if (!p || v > 1) return -1;
                    out->direction = (uint8_t)v;
                } else if (strcmp(key_buf, "content") == 0) {
                    /* Copy content into owned buffer to avoid dangling pointer */
                    if (*p != '"') return -1;
                    const char *content_start = p + 1;
                    const char *scan = content_start;
                    while (*scan != '"' && *scan != '\0') {
                        if (*scan == '\\') {
                            if (*(scan + 1) == '\0') return -1;
                            scan += 2;
                            continue;
                        }
                        scan++;
                    }
                    if (*scan != '"') return -1;
                    uint16_t clen = (uint16_t)(scan - content_start);
                    if (clen > DCLAW_CONTENT_MAX - 1) clen = DCLAW_CONTENT_MAX - 1;
                    memcpy(out->content_buf, content_start, clen);
                    out->content_buf[clen] = '\0';

                    /* M-11 fix: Unescape JSON string escapes in the content buffer.
                     * Without this, escaped quotes (\") and backslashes (\\) are
                     * passed through literally, causing content inspection to miss
                     * patterns that span escape boundaries.
                     *
                     * M-2 fix: Also decode \uXXXX sequences so that Unicode-escaped
                     * keywords (e.g. password
                     * = "password") are normalized before content scanning.  Without
                     * this, an attacker can evade the keyword scanner by encoding
                     * sensitive strings as \uXXXX sequences. */
                    {
                        char *r = out->content_buf;
                        char *w = out->content_buf;
                        while (*r != '\0') {
                            if (r[0] == '\\' && r[1] == '"') {
                                *w++ = '"';
                                r += 2;
                            } else if (r[0] == '\\' && r[1] == '\\') {
                                *w++ = '\\';
                                r += 2;
                            /* CRT-2 fix: Decode standard JSON escape sequences
                             * that were previously passed through literally. */
                            } else if (r[0] == '\\' && r[1] == 'n') {
                                *w++ = '\n';
                                r += 2;
                            } else if (r[0] == '\\' && r[1] == 't') {
                                *w++ = '\t';
                                r += 2;
                            } else if (r[0] == '\\' && r[1] == 'r') {
                                *w++ = '\r';
                                r += 2;
                            } else if (r[0] == '\\' && r[1] == 'b') {
                                *w++ = '\b';
                                r += 2;
                            } else if (r[0] == '\\' && r[1] == 'f') {
                                *w++ = '\f';
                                r += 2;
                            } else if (r[0] == '\\' && r[1] == '/') {
                                *w++ = '/';
                                r += 2;
                            } else if (r[0] == '\\' && r[1] == 'u' &&
                                       r[2] != '\0' && r[3] != '\0' &&
                                       r[4] != '\0' && r[5] != '\0') {
                                /* Decode \uXXXX: parse 4 hex digits, emit UTF-8 */
                                int hi = hex_to_byte(r[2], r[3]);
                                int lo = hex_to_byte(r[4], r[5]);
                                if (hi >= 0 && lo >= 0) {
                                    uint16_t cp = (uint16_t)((hi << 8) | lo);
                                    if (cp < 0x80) {
                                        *w++ = (char)cp;
                                    } else if (cp < 0x800) {
                                        *w++ = (char)(0xC0 | (cp >> 6));
                                        *w++ = (char)(0x80 | (cp & 0x3F));
                                    } else {
                                        *w++ = (char)(0xE0 | (cp >> 12));
                                        *w++ = (char)(0x80 | ((cp >> 6) & 0x3F));
                                        *w++ = (char)(0x80 | (cp & 0x3F));
                                    }
                                    r += 6;
                                } else {
                                    /* Invalid hex digits — copy literally */
                                    *w++ = *r++;
                                }
                            } else {
                                *w++ = *r++;
                            }
                        }
                        *w = '\0';
                        clen = (uint16_t)(w - out->content_buf);
                    }

                    out->content = out->content_buf;
                    out->content_len = clen;
                    p = scan + 1;
                } else {
                    /* Skip unknown value - handle nested objects/arrays */
                    if (*p == '"') {
                        p = parse_string(p, val_buf, sizeof(val_buf));
                        if (!p) return -1;
                    } else {
                        /* H-4 fix: Add nesting depth limit to prevent stack
                         * exhaustion from deeply nested JSON payloads. */
                        int depth = 0;
                        int max_depth = 8;
                        do {
                            if (*p == '{' || *p == '[') { depth++; if (depth > max_depth) return -1; }
                            else if (*p == '}' || *p == ']') { if (depth == 0) break; depth--; }
                            else if (*p == '"') { p++; while (*p && *p != '"') { if (*p == '\\') p++; p++; } }
                            else if (depth == 0 && *p == ',') break;
                            if (*p) p++;
                        } while (*p && depth >= 0);
                    }
                }
            }
            if (*p == '}') p++;
        } else if (strcmp(key_buf, "id") == 0) {
            /* Parse JSON-RPC id field */
            uint32_t v;
            const char *after_id = parse_uint(p, &v);
            if (after_id) {
                out->request_id = (int32_t)v;
                got_id = true;
                p = after_id;
            } else {
                /* id could be a string or null — skip it */
                if (*p == '"') {
                    p = parse_string(p, val_buf, sizeof(val_buf));
                    if (!p) return -1;
                } else {
                    /* skip null or other literal */
                    while (*p && *p != ',' && *p != '}') p++;
                }
            }
        } else {
            /* Skip top-level values we don't need (jsonrpc, method) */
            if (*p == '"') {
                p = parse_string(p, val_buf, sizeof(val_buf));
                if (!p) return -1;
            } else {
                /* H-4 fix: Add nesting depth limit to prevent stack
                 * exhaustion from deeply nested JSON payloads. */
                int depth = 0;
                int max_depth = 8;
                do {
                    if (*p == '{' || *p == '[') { depth++; if (depth > max_depth) return -1; }
                    else if (*p == '}' || *p == ']') { if (depth == 0) break; depth--; }
                    else if (*p == '"') { p++; while (*p && *p != '"') { if (*p == '\\') p++; p++; } }
                    else if (depth == 0 && *p == ',') break;
                    if (*p) p++;
                } while (*p && depth >= 0);
            }
        }
    }

    if (!got_tool_name || !got_hash || !got_caps || !got_session) return -1;

    /* Default id to 1 for backward compatibility if not present */
    if (!got_id) out->request_id = 1;

    /* M-1 fix: Validate that the JSON-RPC "method" field is present and set
     * to "evaluate". Previously, a request without a "method" field was
     * accepted as long as tool_name, hash, caps, and session were present.
     * This allowed non-evaluate RPC calls to be processed. */
    {
        const char *m = json;
        bool found_method = false;
        while ((m = strstr(m, "\"method\"")) != NULL) {
            m += 8; /* skip "method" */
            while (*m == ' ' || *m == ':' || *m == '\t') m++;
            if (*m == '"') {
                char method_buf[32] = {0};
                const char *ms = m + 1;
                size_t mi = 0;
                while (*ms != '"' && *ms != '\0' && mi < sizeof(method_buf) - 1) {
                    method_buf[mi++] = *ms++;
                }
                method_buf[mi] = '\0';
                if (strcmp(method_buf, "evaluate") != 0) {
                    return -1; /* reject unknown methods */
                }
                found_method = true;
            }
            break;
        }
        if (!found_method) {
            return -1; /* M-1: reject requests without a method field */
        }
    }

    return 0;
}
