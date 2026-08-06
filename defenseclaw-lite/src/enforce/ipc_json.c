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
 *   "destination":"...", "session_id":N},"id":N}
 *
 * Strict validation: rejects anything that doesn't exactly match.
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
        }
        out[i++] = *p++;
    }
    out[i] = '\0';
    if (*p != '"') return NULL;
    return p + 1;
}

static const char *parse_uint(const char *p, uint32_t *out) {
    if (*p < '0' || *p > '9') return NULL;
    *out = 0;
    while (*p >= '0' && *p <= '9') {
        *out = (*out * 10) + (*p - '0');
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
                } else {
                    /* Skip unknown value */
                    if (*p == '"') {
                        p = parse_string(p, val_buf, sizeof(val_buf));
                        if (!p) return -1;
                    } else {
                        while (*p && *p != ',' && *p != '}') p++;
                    }
                }
            }
            if (*p == '}') p++;
        } else {
            /* Skip top-level values we don't need (jsonrpc, method, id) */
            if (*p == '"') {
                p = parse_string(p, val_buf, sizeof(val_buf));
                if (!p) return -1;
            } else {
                while (*p && *p != ',' && *p != '}') p++;
            }
        }
    }

    if (!got_tool_name || !got_hash || !got_caps || !got_session) return -1;
    return 0;
}
