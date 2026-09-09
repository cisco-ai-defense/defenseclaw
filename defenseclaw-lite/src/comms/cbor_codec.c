#include "defenseclaw.h"
#include "platform.h"
#include <string.h>

extern dclaw_state_t *dclaw_get_state(void);

/*
 * Minimal CBOR encoder/decoder for DefenseClaw Lite fixed-schema messages.
 * Implements only the CBOR types needed:
 *   - Unsigned integers (major type 0)
 *   - Byte strings (major type 2)
 *   - Text strings (major type 3)
 * No maps, arrays, or nested structures — all messages are flat sequences.
 */

/* === CBOR Encoder === */

static size_t cbor_encode_uint(uint8_t *buf, uint8_t major, uint64_t val) {
    uint8_t mt = (major << 5);
    if (val < 24) {
        buf[0] = mt | (uint8_t)val;
        return 1;
    } else if (val <= 0xFF) {
        buf[0] = mt | 24;
        buf[1] = (uint8_t)val;
        return 2;
    } else if (val <= 0xFFFF) {
        buf[0] = mt | 25;
        buf[1] = (uint8_t)(val >> 8);
        buf[2] = (uint8_t)val;
        return 3;
    } else if (val <= 0xFFFFFFFF) {
        buf[0] = mt | 26;
        buf[1] = (uint8_t)(val >> 24);
        buf[2] = (uint8_t)(val >> 16);
        buf[3] = (uint8_t)(val >> 8);
        buf[4] = (uint8_t)val;
        return 5;
    }
    buf[0] = mt | 27;
    buf[1] = (uint8_t)(val >> 56);
    buf[2] = (uint8_t)(val >> 48);
    buf[3] = (uint8_t)(val >> 40);
    buf[4] = (uint8_t)(val >> 32);
    buf[5] = (uint8_t)(val >> 24);
    buf[6] = (uint8_t)(val >> 16);
    buf[7] = (uint8_t)(val >> 8);
    buf[8] = (uint8_t)val;
    return 9;
}

static size_t cbor_encode_bytes(uint8_t *buf, const uint8_t *data, size_t len) {
    size_t hdr = cbor_encode_uint(buf, 2, len);
    memcpy(buf + hdr, data, len);
    return hdr + len;
}

static size_t cbor_encode_text(uint8_t *buf, const char *str) {
    size_t len = strlen(str);
    size_t hdr = cbor_encode_uint(buf, 3, len);
    memcpy(buf + hdr, str, len);
    return hdr + len;
}

/* === CBOR Decoder === */

__attribute__((unused))
static size_t cbor_decode_uint(const uint8_t *buf, size_t buf_len, uint64_t *val) {
    if (buf_len < 1) return 0;
    uint8_t additional = buf[0] & 0x1F;

    if (additional < 24) {
        *val = additional;
        return 1;
    } else if (additional == 24 && buf_len >= 2) {
        *val = buf[1];
        return 2;
    } else if (additional == 25 && buf_len >= 3) {
        *val = ((uint64_t)buf[1] << 8) | buf[2];
        return 3;
    } else if (additional == 26 && buf_len >= 5) {
        *val = ((uint64_t)buf[1] << 24) | ((uint64_t)buf[2] << 16) |
               ((uint64_t)buf[3] << 8) | buf[4];
        return 5;
    } else if (additional == 27 && buf_len >= 9) {
        *val = ((uint64_t)buf[1] << 56) | ((uint64_t)buf[2] << 48) |
               ((uint64_t)buf[3] << 40) | ((uint64_t)buf[4] << 32) |
               ((uint64_t)buf[5] << 24) | ((uint64_t)buf[6] << 16) |
               ((uint64_t)buf[7] << 8) | buf[8];
        return 9;
    }
    return 0; /* error */
}

/* === Heartbeat Encoder (32 bytes output) === */

int dclaw_cbor_encode_heartbeat(uint8_t *buf, size_t *out_len, size_t buf_size) {
    dclaw_state_t *s = dclaw_get_state();
    if (buf_size < 32) return -1;

    /* Heartbeat is a fixed 32-byte binary blob, not CBOR-wrapped for efficiency.
     * Wire format matches proposal §7.2 exactly. */
    size_t pos = 0;

    /* device_id (4 bytes, big-endian) */
    buf[pos++] = (uint8_t)(s->device.device_id >> 24);
    buf[pos++] = (uint8_t)(s->device.device_id >> 16);
    buf[pos++] = (uint8_t)(s->device.device_id >> 8);
    buf[pos++] = (uint8_t)(s->device.device_id);

    /* uptime_sec (4 bytes) */
    uint32_t uptime = hal_tick_ms() / 1000;
    buf[pos++] = (uint8_t)(uptime >> 24);
    buf[pos++] = (uint8_t)(uptime >> 16);
    buf[pos++] = (uint8_t)(uptime >> 8);
    buf[pos++] = (uint8_t)(uptime);

    /* policy_version (2 bytes) */
    buf[pos++] = (uint8_t)(s->device.policy_version >> 8);
    buf[pos++] = (uint8_t)(s->device.policy_version);

    /* fw_version (2 bytes) */
    buf[pos++] = (uint8_t)(s->device.fw_version >> 8);
    buf[pos++] = (uint8_t)(s->device.fw_version);

    /* denied_count, allowed_count, warned_count, escalated_count (2 bytes each = 8) */
    /* TODO: wire these from actual counters; using zeros for now */
    memset(buf + pos, 0, 8);
    pos += 8;

    /* cache_hit_pct (1 byte) */
    buf[pos++] = 0;

    /* session_count (1 byte) */
    uint8_t active = 0;
    for (int i = 0; i < DCLAW_MAX_SESSIONS; i++) {
        if (s->sessions[i].started_at != 0) active++;
    }
    buf[pos++] = active;

    /* audit_head_hmac (8 bytes) — last entry's hmac extended to 8 bytes */
    memset(buf + pos, 0, 8);
    if (s->audit_writer.count > 0) {
        memcpy(buf + pos, s->audit_writer.buffer[s->audit_writer.count - 1].hmac, 4);
    }
    pos += 8;

    /* flags (1 byte) */
    uint8_t flags = 0;
    if (!s->online) flags |= 0x20; /* OFFLINE_MODE */
    if (!s->clock.time_trusted) flags |= 0x02; /* POLICY_STALE (no time = stale) */
    buf[pos++] = flags;

    /* reserved (1 byte) */
    buf[pos++] = 0;

    *out_len = 32;
    return 0;
}

/* === Verdict Request Encoder === */

int dclaw_cbor_encode_verdict_request(const dclaw_tool_request_t *req,
                                      uint16_t request_id,
                                      uint8_t session_risk,
                                      uint8_t *buf, size_t *out_len,
                                      size_t buf_size) {
    if (buf_size < 256) return -1; /* Increased from 128 to accommodate content */
    size_t pos = 0;

    /* request_id: uint16 */
    pos += cbor_encode_uint(buf + pos, 0, request_id);

    /* sha256: 32 bytes */
    pos += cbor_encode_bytes(buf + pos, req->tool_hash, 32);

    /* tool_name: text string (up to 32 chars for wire efficiency) */
    char short_name[33];
    strncpy(short_name, req->tool_name, 32);
    short_name[32] = '\0';
    pos += cbor_encode_text(buf + pos, short_name);

    /* cap_flags: uint8 */
    pos += cbor_encode_uint(buf + pos, 0, req->cap_flags);

    /* session_risk: uint8 */
    pos += cbor_encode_uint(buf + pos, 0, session_risk);

    /* session_caps: uint8 (prior caps in session — simplified) */
    pos += cbor_encode_uint(buf + pos, 0, req->cap_flags);

    /* destination: optional text (only if non-empty) */
    if (req->destination[0] != '\0') {
        pos += cbor_encode_text(buf + pos, req->destination);
    } else {
        /* Empty string if no destination */
        pos += cbor_encode_text(buf + pos, "");
    }

    /* direction: uint8 */
    pos += cbor_encode_uint(buf + pos, 0, req->direction);

    /* content_scope: uint8 */
    pos += cbor_encode_uint(buf + pos, 0, req->content_scope);

    /* content: text string (truncated to DCLAW_ESCALATION_PAYLOAD_MAX if needed) */
    if (req->content != NULL && req->content_len > 0) {
        /* Truncate content to fit in escalation payload max (typically 256 bytes) */
        size_t max_content = DCLAW_ESCALATION_PAYLOAD_MAX;
        size_t content_to_send = req->content_len < max_content ? req->content_len : max_content;
        size_t hdr = cbor_encode_uint(buf + pos, 3, content_to_send);
        memcpy(buf + pos + hdr, req->content, content_to_send);
        pos += hdr + content_to_send;
    } else {
        /* Empty string if no content */
        pos += cbor_encode_text(buf + pos, "");
    }

    /* findings: uint8 (bitmask of categories found locally - placeholder for now) */
    pos += cbor_encode_uint(buf + pos, 0, 0);

    *out_len = pos;
    return 0;
}

/* === Verdict Response Decoder (16 bytes fixed, or extended with category/evidence) === */

int dclaw_cbor_decode_verdict_response(const uint8_t *buf, size_t len,
                                       uint16_t *request_id, uint8_t *action,
                                       uint8_t *severity, uint16_t *ttl,
                                       uint8_t *reason, uint8_t *flags,
                                       uint32_t *server_ts, uint8_t *hmac_tag) {
    if (len < 16) return -1;

    /* Fixed binary format, not CBOR — matching proposal §7.2 wire format:
     * [request_id:2][action:1][severity:1][ttl:2][reason:1][flags:1][server_ts:4][hmac:4] */
    *request_id = ((uint16_t)buf[0] << 8) | buf[1];
    *action = buf[2];
    *severity = buf[3];
    *ttl = ((uint16_t)buf[4] << 8) | buf[5];
    *reason = buf[6];
    *flags = buf[7];
    *server_ts = ((uint32_t)buf[8] << 24) | ((uint32_t)buf[9] << 16) |
                 ((uint32_t)buf[10] << 8) | buf[11];
    memcpy(hmac_tag, buf + 12, 4);

    return 0;
}

/* === Enriched Verdict Response Decoder (with category and evidence) === */

int dclaw_cbor_decode_verdict_response_enriched(const uint8_t *buf, size_t len,
                                                uint16_t *request_id, uint8_t *action,
                                                uint8_t *severity, uint16_t *ttl,
                                                uint8_t *reason, uint8_t *flags,
                                                uint32_t *server_ts, uint8_t *hmac_tag,
                                                uint8_t *category, char *evidence,
                                                size_t evidence_size) {
    /* First decode the standard 16-byte response */
    if (dclaw_cbor_decode_verdict_response(buf, len, request_id, action, severity,
                                           ttl, reason, flags, server_ts, hmac_tag) != 0) {
        return -1;
    }

    /* If there's additional data, try to extract category and evidence */
    *category = 0;
    if (evidence != NULL && evidence_size > 0) {
        evidence[0] = '\0';
    }

    if (len > 16) {
        size_t pos = 16;

        /* category: uint8 */
        if (pos < len) {
            uint64_t cat_val;
            size_t consumed = cbor_decode_uint(buf + pos, len - pos, &cat_val);
            if (consumed > 0) {
                *category = (uint8_t)cat_val;
                pos += consumed;
            }
        }

        /* evidence: byte string (max 64 bytes) */
        if (pos < len && evidence != NULL && evidence_size > 0) {
            /* Check if this is a byte string (major type 2) or text string (major type 3) */
            uint8_t major = (buf[pos] >> 5) & 0x07;
            if (major == 2 || major == 3) {
                uint64_t str_len;
                size_t hdr = cbor_decode_uint(buf + pos, len - pos, &str_len);
                if (hdr > 0 && pos + hdr + str_len <= len) {
                    size_t copy_len = str_len < (evidence_size - 1) ? str_len : (evidence_size - 1);
                    memcpy(evidence, buf + pos + hdr, copy_len);
                    evidence[copy_len] = '\0';
                }
            }
        }
    }

    return 0;
}
