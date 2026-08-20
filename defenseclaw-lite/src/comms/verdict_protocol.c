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

/* Simple HMAC-SHA256 stub (replace with mbedtls_md_hmac in production).
 * Uses FNV-1a as a placeholder that gives deterministic 4-byte output. */
static void compute_verdict_hmac(const uint8_t *device_key, size_t key_len,
                                 const char *session_id,
                                 uint16_t request_id, uint8_t action,
                                 const uint8_t *tool_hash,
                                 uint8_t *out_4bytes) {
    /* HKDF step: session_key = hash(device_key || session_id) */
    uint32_t h = 0x811c9dc5;
    for (size_t i = 0; i < key_len; i++) {
        h ^= device_key[i];
        h *= 0x01000193;
    }
    for (const char *p = session_id; *p; p++) {
        h ^= (uint8_t)*p;
        h *= 0x01000193;
    }

    /* HMAC step: hash(session_key || request_id || action || tool_hash[0:8]) */
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
    /* In production: device_key would be loaded from secure element.
     * For Phase 1 dev: use a placeholder key. */
    uint8_t device_key[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    const char *session_id = dclaw_mqtt_get_session_id();

    compute_verdict_hmac(device_key, sizeof(device_key), session_id,
                         request_id, action, pending_tool_hash, expected_hmac);

    if (memcmp(received_hmac, expected_hmac, 4) != 0) {
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
    uint8_t device_key[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    const char *session_id = dclaw_mqtt_get_session_id();
    compute_verdict_hmac(device_key, sizeof(device_key), session_id,
                         request_id, action, tool_hash, out_hmac_4bytes);
}
