#include "defenseclaw.h"
#include "platform.h"
#include <string.h>

extern dclaw_state_t *dclaw_get_state(void);

/*
 * Minimal CBOR encoder/decoder for Edge Connector fixed-schema messages.
 * Implements only the CBOR types needed:
 *   - Unsigned integers (major type 0)
 *   - Byte strings (major type 2)
 *   - Text strings (major type 3)
 * No maps, arrays, or nested structures — all messages are flat sequences.
 */

/* === CBOR Encoder === */

/* Returns the number of bytes needed to encode val, without writing. */
static size_t cbor_uint_size(uint64_t val) {
    if (val < 24) return 1;
    if (val <= 0xFF) return 2;
    if (val <= 0xFFFF) return 3;
    if (val <= 0xFFFFFFFF) return 5;
    return 9;
}

static size_t cbor_encode_uint_safe(uint8_t *buf, size_t remaining, uint8_t major, uint64_t val) {
    size_t needed = cbor_uint_size(val);
    if (needed > remaining) return 0;
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

static size_t cbor_encode_bytes_safe(uint8_t *buf, size_t remaining,
                                     const uint8_t *data, size_t len) {
    size_t hdr_size = cbor_uint_size(len);
    if (hdr_size + len > remaining) return 0;
    size_t hdr = cbor_encode_uint_safe(buf, remaining, 2, len);
    memcpy(buf + hdr, data, len);
    return hdr + len;
}

static size_t cbor_encode_text_safe(uint8_t *buf, size_t remaining, const char *str) {
    size_t len = strlen(str);
    size_t hdr_size = cbor_uint_size(len);
    if (hdr_size + len > remaining) return 0;
    size_t hdr = cbor_encode_uint_safe(buf, remaining, 3, len);
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

    /* uptime_sec (4 bytes, wire format truncated to 32-bit) */
    uint32_t uptime = (uint32_t)(hal_tick_ms() / 1000);
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

    /* denied_count (2 bytes) */
    uint16_t denied = (uint16_t)(s->eval_denied_count & 0xFFFF);
    buf[pos++] = (uint8_t)(denied >> 8);
    buf[pos++] = (uint8_t)(denied);
    /* allowed_count (2 bytes) */
    uint16_t allowed = (uint16_t)(s->eval_allowed_count & 0xFFFF);
    buf[pos++] = (uint8_t)(allowed >> 8);
    buf[pos++] = (uint8_t)(allowed);
    /* warned_count (2 bytes) */
    uint16_t warned = (uint16_t)(s->eval_warned_count & 0xFFFF);
    buf[pos++] = (uint8_t)(warned >> 8);
    buf[pos++] = (uint8_t)(warned);
    /* escalated_count (2 bytes) */
    uint16_t escalated = (uint16_t)(s->eval_escalated_count & 0xFFFF);
    buf[pos++] = (uint8_t)(escalated >> 8);
    buf[pos++] = (uint8_t)(escalated);

    /* cache_hit_pct (1 byte) — computed from actual cache stats */
    {
        uint8_t pct = 0;
        if (s->eval_count > 0) {
            /* M-5 fix: Cap at 100% to prevent overflow on counter wrap */
            uint32_t raw = 100U * s->eval_cache_hit_count / s->eval_count;
            pct = (uint8_t)(raw > 100 ? 100 : raw);
        }
        buf[pos++] = pct;
    }

    /* session_count (1 byte) */
    uint8_t active = 0;
    for (int i = 0; i < DCLAW_MAX_SESSIONS; i++) {
        if (s->sessions[i].started_at != 0) active++;
    }
    buf[pos++] = active;

    /* audit_head_hmac (8 bytes) — first 8 bytes of last entry's 16-byte HMAC */
    memset(buf + pos, 0, 8);
    if (s->audit_writer.count > 0) {
        memcpy(buf + pos, s->audit_writer.buffer[s->audit_writer.count - 1].hmac, 8);
    }
    pos += 8;

    /* flags (1 byte) */
    uint8_t flags = 0;
    if (!s->online) flags |= 0x20; /* OFFLINE_MODE */
    if (!s->clock.time_trusted) flags |= 0x02; /* POLICY_STALE (no time = stale) */
    /* P2-19 fix: Include rollback flag 0x08 when a canary rollback occurred.
     * The flag is set here but NOT cleared — clearing happens in
     * mqtt_client.c after the heartbeat publish succeeds.  This ensures the
     * flag is retried on the next heartbeat if the publish fails. */
    if (s->rollback_pending) {
        flags |= 0x08; /* CANARY_ROLLBACK */
    }
    buf[pos++] = flags;

    /* capabilities (1 byte) — device capability bitmap */
    buf[pos++] = s->device.capabilities;

    *out_len = 32;
    return 0;
}

/* === Verdict Request Encoder === */

int dclaw_cbor_encode_verdict_request(const dclaw_tool_request_t *req,
                                      uint16_t request_id,
                                      uint8_t session_risk,
                                      uint8_t *buf, size_t *out_len,
                                      size_t buf_size) {
    size_t pos = 0;
    size_t n;

#define CBOR_CHECK(expr) do { n = (expr); if (n == 0) return -1; pos += n; } while(0)

    /* request_id: uint16 */
    CBOR_CHECK(cbor_encode_uint_safe(buf + pos, buf_size - pos, 0, request_id));

    /* sha256: 32 bytes */
    CBOR_CHECK(cbor_encode_bytes_safe(buf + pos, buf_size - pos, req->tool_hash, 32));

    /* tool_name: text string (up to 32 chars for wire efficiency) */
    char short_name[33];
    memset(short_name, 0, sizeof(short_name)); /* safety: zero buffer before strncpy */
    strncpy(short_name, req->tool_name, 32);
    short_name[32] = '\0'; /* explicit NUL-termination after strncpy */
    CBOR_CHECK(cbor_encode_text_safe(buf + pos, buf_size - pos, short_name));

    /* cap_flags: uint8 */
    CBOR_CHECK(cbor_encode_uint_safe(buf + pos, buf_size - pos, 0, req->cap_flags));

    /* session_risk: uint8 */
    CBOR_CHECK(cbor_encode_uint_safe(buf + pos, buf_size - pos, 0, session_risk));

    /* session_caps: uint8 (prior caps in session — simplified) */
    CBOR_CHECK(cbor_encode_uint_safe(buf + pos, buf_size - pos, 0, req->cap_flags));

    /* destination: optional text (only if non-empty) */
    if (req->destination[0] != '\0') {
        CBOR_CHECK(cbor_encode_text_safe(buf + pos, buf_size - pos, req->destination));
    } else {
        /* Empty string if no destination */
        CBOR_CHECK(cbor_encode_text_safe(buf + pos, buf_size - pos, ""));
    }

    /* direction: uint8 */
    CBOR_CHECK(cbor_encode_uint_safe(buf + pos, buf_size - pos, 0, req->direction));

    /* content_scope: uint8 */
    CBOR_CHECK(cbor_encode_uint_safe(buf + pos, buf_size - pos, 0, req->content_scope));

    /* content: text string (truncated to DCLAW_ESCALATION_PAYLOAD_MAX if needed) */
    if (req->content != NULL && req->content_len > 0) {
        /* Truncate content to fit in escalation payload max (typically 256 bytes) */
        size_t max_content = DCLAW_ESCALATION_PAYLOAD_MAX;
        size_t content_to_send = req->content_len < max_content ? req->content_len : max_content;
        size_t remaining = buf_size - pos;
        size_t hdr_size = cbor_uint_size(content_to_send);
        if (hdr_size + content_to_send > remaining) return -1;
        size_t hdr = cbor_encode_uint_safe(buf + pos, remaining, 3, content_to_send);
        if (hdr == 0) return -1;
        memcpy(buf + pos + hdr, req->content, content_to_send);
        pos += hdr + content_to_send;
    } else {
        /* Empty string if no content */
        CBOR_CHECK(cbor_encode_text_safe(buf + pos, buf_size - pos, ""));
    }

    /* findings: uint8 (bitmask of categories found locally - placeholder for now) */
    CBOR_CHECK(cbor_encode_uint_safe(buf + pos, buf_size - pos, 0, 0));

#undef CBOR_CHECK

    *out_len = pos;
    return 0;
}

/* === Verdict Response Decoder (16 bytes fixed, or extended with category/evidence) === */

int dclaw_cbor_decode_verdict_response(const uint8_t *buf, size_t len,
                                       uint16_t *request_id, uint8_t *action,
                                       uint8_t *severity, uint16_t *ttl,
                                       uint8_t *reason, uint8_t *flags,
                                       uint32_t *server_ts, uint8_t *hmac_tag) {
    if (len < 28) return -1;

    /* Fixed binary format: [request_id:2][action:1][severity:1][ttl:2][reason:1][flags:1][server_ts:4][hmac:16] */
    *request_id = ((uint16_t)buf[0] << 8) | buf[1];
    *action = buf[2];
    *severity = buf[3];
    *ttl = ((uint16_t)buf[4] << 8) | buf[5];
    *reason = buf[6];
    *flags = buf[7];
    *server_ts = ((uint32_t)buf[8] << 24) | ((uint32_t)buf[9] << 16) |
                 ((uint32_t)buf[10] << 8) | buf[11];
    memcpy(hmac_tag, buf + 12, 16);

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
    /* First decode the standard 28-byte response */
    if (dclaw_cbor_decode_verdict_response(buf, len, request_id, action, severity,
                                           ttl, reason, flags, server_ts, hmac_tag) != 0) {
        return -1;
    }

    /* If there's additional data, try to extract category and evidence */
    *category = 0;
    if (evidence != NULL && evidence_size > 0) {
        evidence[0] = '\0';
    }

    if (len > 28) {
        size_t pos = 28;

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
