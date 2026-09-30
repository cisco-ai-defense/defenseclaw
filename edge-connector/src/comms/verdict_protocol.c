#include "defenseclaw.h"
#include "platform.h"
#include <string.h>

/*
 * Verdict request/response protocol handler.
 * Implements:
 * - Session-scoped HMAC tag verification (REQ-27)
 * - Pending verdict deduplication (REQ-28)
 * - Clock synchronization from server_ts (REQ-25, REQ-26)
 * - REVOKE_PRIOR flag handling
 */

extern dclaw_state_t *dclaw_get_state(void);
extern void dclaw_cache_store(const uint8_t *tool_hash, dclaw_action_t action,
                              dclaw_severity_t severity);
extern void dclaw_cache_invalidate(const uint8_t *tool_hash);
extern const char *dclaw_mqtt_get_session_id(void);
extern int dclaw_audit_write(dclaw_action_t action, dclaw_reason_t reason,
                             uint16_t target_hash, uint16_t session_id);
extern int dclaw_cbor_decode_verdict_response(const uint8_t *buf, size_t len,
                                              uint16_t *request_id, uint8_t *action,
                                              uint8_t *severity, uint16_t *ttl,
                                              uint8_t *reason, uint8_t *flags,
                                              uint32_t *server_ts, uint8_t *hmac_tag);

/*
 * Verdict HMAC computation.
 * When DCLAW_HAS_MBEDTLS=1: real HMAC-SHA256 truncated to 4 bytes.
 * When DCLAW_HAS_MBEDTLS=0: FNV-1a stub for dev builds only.
 */
#if !defined(DCLAW_HAS_MBEDTLS) || DCLAW_HAS_MBEDTLS == 0

#pragma message "Verdict HMAC uses FNV-1a stub — DO NOT USE IN PRODUCTION"

static void compute_verdict_hmac(const uint8_t *device_key, size_t key_len,
                                 const char *session_id,
                                 uint16_t request_id, uint8_t action,
                                 const uint8_t *tool_hash,
                                 uint8_t *out_4bytes) {
    /* FNV-1a stub: deterministic 4-byte output for dev/test only */
    uint32_t h = 0x811c9dc5;
    for (size_t i = 0; i < key_len; i++) {
        h ^= device_key[i];
        h *= 0x01000193;
    }
    for (const char *p = session_id; *p; p++) {
        h ^= (uint8_t)*p;
        h *= 0x01000193;
    }
    h ^= (request_id & 0xFF);
    h *= 0x01000193;
    h ^= (request_id >> 8);
    h *= 0x01000193;
    h ^= action;
    h *= 0x01000193;
    for (int i = 0; i < 8; i++) {
        h ^= tool_hash[i];
        h *= 0x01000193;
    }
    memcpy(out_4bytes, &h, 4);
}

#else /* DCLAW_HAS_MBEDTLS == 1 */

#include <mbedtls/md.h>

static void compute_verdict_hmac(const uint8_t *device_key, size_t key_len,
                                 const char *session_id,
                                 uint16_t request_id, uint8_t action,
                                 const uint8_t *tool_hash,
                                 uint8_t *out_4bytes) {
    /*
     * Real HMAC-SHA256 truncated to 4 bytes.
     * Input: HMAC-SHA256(device_key, session_id || request_id || action || tool_hash[0:8])
     */
    uint8_t hmac_full[32];
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md_info, 1 /* HMAC */);
    mbedtls_md_hmac_starts(&ctx, device_key, key_len);

    /* Feed: session_id (NUL-terminated string) */
    mbedtls_md_hmac_update(&ctx, (const uint8_t *)session_id, strlen(session_id));

    /* Feed: request_id (2 bytes, little-endian) */
    uint8_t rid[2] = { (uint8_t)(request_id & 0xFF), (uint8_t)(request_id >> 8) };
    mbedtls_md_hmac_update(&ctx, rid, 2);

    /* Feed: action (1 byte) */
    mbedtls_md_hmac_update(&ctx, &action, 1);

    /* Feed: tool_hash[0:8] */
    mbedtls_md_hmac_update(&ctx, tool_hash, 8);

    mbedtls_md_hmac_finish(&ctx, hmac_full);
    mbedtls_md_free(&ctx);

    /* Truncate to 4 bytes */
    memcpy(out_4bytes, hmac_full, 4);
}

#endif /* DCLAW_HAS_MBEDTLS */

/* Constant-time comparison to prevent timing side-channels */
static bool ct_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

/* Device key loaded once from HAL secure element */
static uint8_t s_device_key[32];
static size_t  s_device_key_len = 0;
static bool    s_device_key_loaded = false;

static const uint8_t *get_device_key(size_t *out_key_len) {
    if (!s_device_key_loaded) {
        s_device_key_len = 0;
        if (hal_load_device_key(s_device_key, &s_device_key_len, sizeof(s_device_key)) != 0) {
            /* Fallback: zero key — this will cause HMAC mismatches, which is safer
             * than using a hardcoded key */
            memset(s_device_key, 0, sizeof(s_device_key));
            s_device_key_len = 16;
        }
        s_device_key_loaded = true;
    }
    *out_key_len = s_device_key_len;
    return s_device_key;
}

/* Register a pending verdict request */
int dclaw_verdict_register_pending(uint16_t request_id, const uint8_t *tool_hash) {
    dclaw_state_t *s = dclaw_get_state();

    for (int i = 0; i < DCLAW_PENDING_SLOTS; i++) {
        if (!s->pending[i].resolved && s->pending[i].request_id == 0) {
            s->pending[i].request_id = request_id;
            s->pending[i].resolved = false;
            s->pending[i].resolved_at = 0;
            (void)tool_hash; /* stored externally for HMAC verification */
            return i;
        }
    }
    return -1; /* No free slots */
}

/* Process a received verdict response */
int dclaw_verdict_handle_response(const uint8_t *resp_buf, size_t resp_len,
                                  const uint8_t *pending_tool_hash) {
    if (resp_len != 16) return -1;

    dclaw_state_t *s = dclaw_get_state();

    /* Decode the 16-byte response */
    uint16_t request_id, ttl;
    uint8_t action, severity, reason, flags;
    uint32_t server_ts;
    uint8_t received_hmac[4];

    int rc = dclaw_cbor_decode_verdict_response(resp_buf, resp_len,
                                                &request_id, &action, &severity,
                                                &ttl, &reason, &flags,
                                                &server_ts, received_hmac);
    if (rc != 0) return -1;

    /* REQ-28: Deduplication — check if already resolved */
    bool found = false;
    for (int i = 0; i < DCLAW_PENDING_SLOTS; i++) {
        if (s->pending[i].request_id == request_id) {
            if (s->pending[i].resolved) {
                return 0; /* Duplicate — silently discard */
            }
            found = true;
            s->pending[i].resolved = true;
            s->pending[i].resolved_at = hal_tick_ms();
            break;
        }
    }
    if (!found) return -1; /* Unknown request_id */

    /* REQ-27: Verify HMAC tag */
    uint8_t expected_hmac[4];
    size_t key_len;
    const uint8_t *device_key = get_device_key(&key_len);
    const char *session_id = dclaw_mqtt_get_session_id();

    compute_verdict_hmac(device_key, key_len, session_id,
                         request_id, action, pending_tool_hash, expected_hmac);

    if (!ct_compare(received_hmac, expected_hmac, 4)) {
        /* REQ-29: HMAC verification failed */
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT,
                          (uint16_t)(pending_tool_hash[0] | (pending_tool_hash[1] << 8)),
                          0);
        return -1;
    }

    /* REQ-25: Update clock from server_ts */
    if (server_ts > 0) {
        s->clock.cloud_epoch = server_ts;
        s->clock.ticks_at_sync = hal_tick_ms();
        s->clock.time_trusted = true;
    }

    /* Handle REVOKE_PRIOR flag (bit 0) */
    if (flags & 0x01) {
        dclaw_cache_invalidate(pending_tool_hash);
    }

    /* Cache the verdict */
    dclaw_cache_store(pending_tool_hash, (dclaw_action_t)action,
                      (dclaw_severity_t)severity);

    /* Audit the decision */
    dclaw_audit_write((dclaw_action_t)action, (dclaw_reason_t)reason,
                      (uint16_t)(pending_tool_hash[0] | (pending_tool_hash[1] << 8)),
                      0);

    return 0;
}

/* Compute HMAC for outbound use (e.g., for testing/verification) */
void dclaw_verdict_compute_expected_hmac(uint16_t request_id, uint8_t action,
                                         const uint8_t *tool_hash,
                                         uint8_t *out_hmac_4bytes) {
    size_t key_len;
    const uint8_t *device_key = get_device_key(&key_len);
    const char *session_id = dclaw_mqtt_get_session_id();
    compute_verdict_hmac(device_key, key_len, session_id,
                         request_id, action, tool_hash, out_hmac_4bytes);
}
