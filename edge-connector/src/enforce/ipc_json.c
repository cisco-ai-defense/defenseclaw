/*
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

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
            case 'u':
                if (p[1] && p[2] && p[3] && p[4]) {
                    out[i++] = '?';
                    p += 5; /* skip 'u' + 4 hex digits */
                } else {
                    return NULL;
                }
                break;
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
    bool got_id = false, got_method = false;

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
                    if (!p || v > 0xFF) return -1;
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
                    size_t raw_content_len = (size_t)(scan - content_start);
                    size_t raw_clen = raw_content_len;
                    if (raw_clen > DCLAW_CONTENT_MAX - 1) {
                        raw_clen = DCLAW_CONTENT_MAX - 1;
                        out->flags |= DCLAW_FLAG_CONTENT_TRUNCATED;
                    }
                    uint16_t clen = (uint16_t)raw_clen;
                    memcpy(out->content_buf, content_start, clen);
                    out->content_buf[clen] = '\0';

                    {
                        char *r = out->content_buf;
                        char *w = out->content_buf;
                        char *w_end = out->content_buf + DCLAW_CONTENT_MAX - 4;
                        while (*r != '\0' && w < w_end) {
                            if (r[0] == '\\' && r[1] == '"') {
                                *w++ = '"';
                                r += 2;
                            } else if (r[0] == '\\' && r[1] == '\\') {
                                *w++ = '\\';
                                r += 2;
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
                                int hi = hex_to_byte(r[2], r[3]);
                                int lo = hex_to_byte(r[4], r[5]);
                                if (hi >= 0 && lo >= 0) {
                                    uint16_t cp = (uint16_t)((hi << 8) | lo);
                                    if (cp == 0) {
                                        r += 6; /* reject NUL — skip without emitting */
                                    } else if (cp < 0x80) {
                                        *w++ = (char)cp;
                                        r += 6;
                                    } else if (cp < 0x800) {
                                        *w++ = (char)(0xC0 | (cp >> 6));
                                        *w++ = (char)(0x80 | (cp & 0x3F));
                                        r += 6;
                                    } else {
                                        *w++ = (char)(0xE0 | (cp >> 12));
                                        *w++ = (char)(0x80 | ((cp >> 6) & 0x3F));
                                        *w++ = (char)(0x80 | (cp & 0x3F));
                                        r += 6;
                                    }
                                } else {
                                    r += 6; /* invalid hex — skip entire \uXXXX sequence */
                                }
                            } else {
                                *w++ = *r++;
                            }
                        }
                        if (*r != '\0') {
                            out->flags |= DCLAW_FLAG_CONTENT_TRUNCATED;
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
                        int depth = 0;
                        int max_depth = 8;
                        do {
                            if (*p == '{' || *p == '[') { depth++; if (depth > max_depth) return -1; }
                            else if (*p == '}' || *p == ']') { if (depth == 0) break; depth--; }
                            else if (*p == '"') { p++; while (*p && *p != '"') { if (*p == '\\' && *(p+1)) p++; p++; } }
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
        } else if (strcmp(key_buf, "method") == 0) {
            /* Parse the "method" field during the main key scan
             * instead of using a post-hoc strstr search on raw JSON. strstr
             * can match "method" inside string values, leading to false
             * positives or bypasses. */
            char method_buf[32];
            p = parse_string(p, method_buf, sizeof(method_buf));
            if (!p) return -1;
            if (strcmp(method_buf, "evaluate") != 0) {
                return -1; /* reject unknown methods */
            }
            got_method = true;
        } else {
            /* Skip top-level values we don't need (jsonrpc, etc.) */
            if (*p == '"') {
                p = parse_string(p, val_buf, sizeof(val_buf));
                if (!p) return -1;
            } else {
                int depth = 0;
                int max_depth = 8;
                do {
                    if (*p == '{' || *p == '[') { depth++; if (depth > max_depth) return -1; }
                    else if (*p == '}' || *p == ']') { if (depth == 0) break; depth--; }
                    else if (*p == '"') { p++; while (*p && *p != '"') { if (*p == '\\' && *(p+1)) p++; p++; } }
                    else if (depth == 0 && *p == ',') break;
                    if (*p) p++;
                } while (*p && depth >= 0);
            }
        }
    }

    if (!got_tool_name || !got_hash || !got_caps || !got_session) return -1;

    /* Default id to 1 for backward compatibility if not present */
    if (!got_id) out->request_id = 1;

    /* Method validation is handled during the main key scan above (got_method
     * flag). Reject requests without a valid method field. */
    if (!got_method) {
        return -1; /* reject requests without "method":"evaluate" */
    }

    return 0;
}
