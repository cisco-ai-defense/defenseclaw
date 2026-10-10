#include "defenseclaw.h"
#include "platform.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

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
extern dclaw_retroactive_block_fn dclaw_get_retroactive_callback(void);
extern int dclaw_cbor_decode_verdict_response(const uint8_t *buf, size_t len,
                                              uint16_t *request_id, uint8_t *action,
                                              uint8_t *severity, uint16_t *ttl,
                                              uint8_t *reason, uint8_t *flags,
                                              uint32_t *server_ts, uint8_t *hmac_tag);

/*
 * Verdict HMAC computation.
 * When DCLAW_HAS_MBEDTLS=1: HMAC-SHA256 via mbedtls_md, truncated to 16 bytes.
 * Otherwise: built-in HMAC-SHA256 (no external library), truncated to 16 bytes.
 */
#if defined(DCLAW_HAS_MBEDTLS) && DCLAW_HAS_MBEDTLS == 1

/* mbedTLS path — real HMAC-SHA256 via mbedtls_md */

#include <mbedtls/md.h>

static void compute_verdict_hmac(const uint8_t *device_key, size_t key_len,
                                 const char *session_id,
                                 uint16_t request_id, uint8_t action,
                                 uint8_t severity, uint16_t ttl,
                                 uint8_t reason, uint8_t flags,
                                 uint32_t server_ts,
                                 const uint8_t *tool_hash,
                                 uint8_t *out_16bytes) {
    /*
     * BLK-1 fix: HMAC-SHA256 truncated to 16 bytes, covering ALL verdict fields.
     * Input: HMAC-SHA256(device_key, session_id || request_id || action ||
     *        severity || ttl || reason || flags || server_ts || tool_hash[0:32])
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

    /* NEW-6: Feed severity (1 byte) */
    mbedtls_md_hmac_update(&ctx, &severity, 1);

    /* NEW-6: Feed ttl (2 bytes, little-endian) */
    uint8_t ttl_le[2] = { (uint8_t)(ttl & 0xFF), (uint8_t)(ttl >> 8) };
    mbedtls_md_hmac_update(&ctx, ttl_le, 2);

    /* NEW-6: Feed reason (1 byte) */
    mbedtls_md_hmac_update(&ctx, &reason, 1);

    /* NEW-6: Feed flags (1 byte) */
    mbedtls_md_hmac_update(&ctx, &flags, 1);

    /* NEW-6: Feed server_ts (4 bytes, little-endian) */
    uint8_t ts_le[4] = {
        (uint8_t)(server_ts & 0xFF),
        (uint8_t)((server_ts >> 8) & 0xFF),
        (uint8_t)((server_ts >> 16) & 0xFF),
        (uint8_t)((server_ts >> 24) & 0xFF)
    };
    mbedtls_md_hmac_update(&ctx, ts_le, 4);

    /* Feed: tool_hash[0:32] */
    mbedtls_md_hmac_update(&ctx, tool_hash, 32);

    /* B-1 fix: Include boot_nonce so verdict HMACs are unique per boot.
     * Prevents cross-reboot verdict replay. */
    mbedtls_md_hmac_update(&ctx, dclaw_get_state()->boot_nonce, 16);

    mbedtls_md_hmac_finish(&ctx, hmac_full);
    mbedtls_md_free(&ctx);

    memcpy(out_16bytes, hmac_full, 16);
    dclaw_secure_zero(hmac_full, sizeof(hmac_full));
}

#else /* Built-in HMAC-SHA256 — no external library required */

#include "hmac_sha256.h"

static void compute_verdict_hmac(const uint8_t *device_key, size_t key_len,
                                 const char *session_id,
                                 uint16_t request_id, uint8_t action,
                                 uint8_t severity, uint16_t ttl,
                                 uint8_t reason, uint8_t flags,
                                 uint32_t server_ts,
                                 const uint8_t *tool_hash,
                                 uint8_t *out_16bytes) {
    /*
     * BLK-1 fix: HMAC-SHA256 truncated to 16 bytes, covering ALL verdict fields.
     * Input: HMAC-SHA256(device_key, session_id || request_id || action ||
     *        severity || ttl || reason || flags || server_ts || tool_hash[0:32])
     * Matches the mbedTLS path semantics exactly.
     */
    uint8_t hmac_full[32];
    uint8_t msg[280]; /* session_id + 2 + 1 + 1 + 2 + 1 + 1 + 4 + 32 + 16 = ~92 bytes max */
    size_t msg_len = 0;

    /* Feed: session_id (NUL-terminated string, excluding NUL) */
    size_t sid_len = strlen(session_id);
    memcpy(msg + msg_len, session_id, sid_len);
    msg_len += sid_len;

    /* Feed: request_id (2 bytes, little-endian) */
    msg[msg_len++] = (uint8_t)(request_id & 0xFF);
    msg[msg_len++] = (uint8_t)(request_id >> 8);

    /* Feed: action (1 byte) */
    msg[msg_len++] = action;

    /* NEW-6: Feed severity (1 byte) */
    msg[msg_len++] = severity;

    /* NEW-6: Feed ttl (2 bytes, little-endian) */
    msg[msg_len++] = (uint8_t)(ttl & 0xFF);
    msg[msg_len++] = (uint8_t)(ttl >> 8);

    /* NEW-6: Feed reason (1 byte) */
    msg[msg_len++] = reason;

    /* NEW-6: Feed flags (1 byte) */
    msg[msg_len++] = flags;

    /* NEW-6: Feed server_ts (4 bytes, little-endian) */
    msg[msg_len++] = (uint8_t)(server_ts & 0xFF);
    msg[msg_len++] = (uint8_t)((server_ts >> 8) & 0xFF);
    msg[msg_len++] = (uint8_t)((server_ts >> 16) & 0xFF);
    msg[msg_len++] = (uint8_t)((server_ts >> 24) & 0xFF);

    /* Feed: tool_hash[0:32] */
    memcpy(msg + msg_len, tool_hash, 32);
    msg_len += 32;

    /* B-1 fix: Include boot_nonce (16 bytes) */
    memcpy(msg + msg_len, dclaw_get_state()->boot_nonce, 16);
    msg_len += 16;

    dclaw_hmac_sha256(device_key, key_len, msg, msg_len, hmac_full);

    /* BLK-1: Truncate to 16 bytes (was 4) */
    memcpy(out_16bytes, hmac_full, 16);
    dclaw_secure_zero(hmac_full, sizeof(hmac_full));
    dclaw_secure_zero(msg, sizeof(msg));
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
static bool    s_device_key_provisioned = false;

/*
 * Strict hex character to nibble conversion.
 * Returns 0-15 on success, -1 for any non-hex character (including
 * whitespace, signs, and control characters).
 */
static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/*
 * Parse a hex-encoded string into a byte buffer with strict validation.
 * Rejects keys containing whitespace, signs, or any non-[0-9a-fA-F] chars.
 * Returns 0 on success, -1 on invalid input.
 */
static int hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/*
 * Try to load the device key from a file path (raw 32 bytes).
 * Returns 0 on success.
 */
static int load_key_from_file(const char *path, uint8_t *key, size_t *key_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, key, 32);
    close(fd);
    if (n != 32) return -1;
    *key_len = 32;
    return 0;
}

static const uint8_t *get_device_key(size_t *out_key_len) {
    if (!s_device_key_loaded) {
        s_device_key_len = 0;
        s_device_key_provisioned = false;

        bool loaded = false;

        /* Priority 1: DCLAW_DEVICE_KEY environment variable (hex-encoded, 64 chars = 32 bytes) */
        const char *env_key = getenv("DCLAW_DEVICE_KEY");
        if (env_key && env_key[0] != '\0') {
            if (hex_decode(env_key, s_device_key, 32) == 0) {
                s_device_key_len = 32;
                loaded = true;
                /* Best-effort scrub: overwrites the getenv() pointer in the C
                 * runtime, but /proc/PID/environ (a snapshot at exec) is NOT
                 * cleared. Use file-based key provisioning in production. */
                {
                    char *ev = getenv("DCLAW_DEVICE_KEY");
                    if (ev) {
                        volatile char *p = (volatile char *)ev;
                        while (*p) { *p++ = '0'; }
                    }
                }
            } else {
                fprintf(stderr, "[DCLAW] WARNING: DCLAW_DEVICE_KEY set but invalid (need 64 hex chars)\n");
            }
        }

        /* Priority 2: /etc/defenseclaw/device.key (raw 32-byte binary) */
        if (!loaded) {
            if (load_key_from_file("/etc/defenseclaw/device.key", s_device_key, &s_device_key_len) == 0) {
                loaded = true;
            }
        }

        /* Priority 3: HAL secure element (existing path: /etc/edge-connector/device.key) */
        if (!loaded) {
            if (hal_load_device_key(s_device_key, &s_device_key_len, sizeof(s_device_key)) == 0) {
                loaded = true;
            }
        }

        if (!loaded) {
#if DCLAW_DEV_MODE
            /* Fallback: 32-byte zero key (Comment 32 fix).
             * Must match the Go side (bridge.go) which uses make([]byte, 32).
             * Only permitted in dev mode (DCLAW_DEV_MODE=ON). */
            fprintf(stderr, "[DCLAW] WARNING: No device key found, using zero key (dev mode only).\n");
            memset(s_device_key, 0, sizeof(s_device_key));
            s_device_key_len = 32;
#else
            /* CRT-3 fix: In production mode (DCLAW_DEV_MODE=OFF), refuse to
             * fall back to a zero key. A zero key is a well-known constant that
             * any attacker can use to forge HMAC signatures. Return an empty
             * key so that verdict responses are rejected at the HMAC check. */
            fprintf(stderr, "[DCLAW] ERROR: No device key provisioned and DCLAW_DEV_MODE=OFF. "
                    "Set DCLAW_DEVICE_KEY or provision /etc/defenseclaw/device.key.\n");
            memset(s_device_key, 0, sizeof(s_device_key));
            s_device_key_len = 0;
#endif
        }

        /* Check that the loaded key is not all zeros */
        if (loaded) {
            bool all_zero = true;
            for (size_t i = 0; i < s_device_key_len; i++) {
                if (s_device_key[i] != 0) { all_zero = false; break; }
            }
            if (!all_zero) {
                s_device_key_provisioned = true;
            }
        }

        s_device_key_loaded = true;
    }
    *out_key_len = s_device_key_len;
    return s_device_key;
}

/* Set device key for testing. Allows tests to provision a non-zero key
 * so that verdict HMAC verification succeeds. */
void dclaw_verdict_set_device_key(const uint8_t *key, size_t key_len) {
    if (key_len > sizeof(s_device_key)) key_len = sizeof(s_device_key);
    memcpy(s_device_key, key, key_len);
    s_device_key_len = key_len;
    s_device_key_loaded = true;
    /* Check if key is non-zero */
    bool all_zero = true;
    for (size_t i = 0; i < key_len; i++) {
        if (key[i] != 0) { all_zero = false; break; }
    }
    s_device_key_provisioned = !all_zero;
}

/* Register a pending verdict request.
 *
 * P1-7 fix: A slot is "available" when EITHER:
 *   (a) it has never been used (request_id == 0 && !resolved), OR
 *   (b) it was resolved and reclaimed (resolved == true).
 * The previous logic only checked condition (a), so resolved slots were
 * never reused — once all DCLAW_PENDING_SLOTS were resolved the system
 * could not send any new verdict requests. */
void dclaw_verdict_mark_timeout(uint16_t request_id) {
    dclaw_state_t *s = dclaw_get_state();
    for (int i = 0; i < DCLAW_PENDING_SLOTS; i++) {
        if (s->pending[i].request_id == request_id) {
            s->pending[i].request_id = 0;
            s->pending[i].resolved = false;
            return;
        }
    }
}

int dclaw_verdict_register_pending(uint16_t request_id, const uint8_t *tool_hash) {
    dclaw_state_t *s = dclaw_get_state();

    for (int i = 0; i < DCLAW_PENDING_SLOTS; i++) {
        bool available = (s->pending[i].request_id == 0 && !s->pending[i].resolved)
                      || s->pending[i].resolved;
        if (available) {
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
    if (resp_len < 28) return -1;

    dclaw_state_t *s = dclaw_get_state();

    /* CRT-1 fix: Copy tool_hash to a local buffer before use to prevent
     * TOCTOU — the pending ring slot could be reclaimed by another thread
     * between the HMAC computation and the cache store. */
    uint8_t local_hash[32];
    memcpy(local_hash, pending_tool_hash, 32);

    /* Decode the 28-byte response (BLK-1: HMAC extended to 16 bytes) */
    uint16_t request_id, ttl;
    uint8_t action, severity, reason, flags;
    uint32_t server_ts;
    uint8_t received_hmac[16];

    int rc = dclaw_cbor_decode_verdict_response(resp_buf, resp_len,
                                                &request_id, &action, &severity,
                                                &ttl, &reason, &flags,
                                                &server_ts, received_hmac);
    if (rc != 0) return -1;

    /* REQ-28: Deduplication — check if already resolved */
    bool found = false;
    int slot_index = -1;
    for (int i = 0; i < DCLAW_PENDING_SLOTS; i++) {
        if (s->pending[i].request_id == request_id) {
            if (s->pending[i].resolved) {
                return 0; /* Duplicate — silently discard */
            }
            found = true;
            slot_index = i;
            break;
        }
    }
    if (!found) return -1; /* Unknown request_id */

    /* REQ-27: Verify HMAC tag BEFORE marking as resolved (Comment 23 fix).
     * If HMAC fails, the slot stays pending so a valid retry can still succeed. */
    uint8_t expected_hmac[16];
    size_t key_len;
    const uint8_t *device_key = get_device_key(&key_len);
    const char *session_id = dclaw_mqtt_get_session_id();

    /* P0-1 fix: Reject verdict responses when no real device key is provisioned.
     * Without a provisioned key, HMAC verification is meaningless because anyone
     * can compute the HMAC with the known zero-key fallback and forge ALLOW verdicts. */
    if (!s_device_key_provisioned) {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT,
                          (uint16_t)(local_hash[0] | (local_hash[1] << 8)),
                          0);
        return -1; /* device key not provisioned */
    }

    /* NEW-6 fix: HMAC covers all verdict response fields */
    compute_verdict_hmac(device_key, key_len, session_id,
                         request_id, action, severity, ttl,
                         reason, flags, server_ts,
                         local_hash, expected_hmac);

    if (!ct_compare(received_hmac, expected_hmac, 16)) {
        /* REQ-29: HMAC verification failed — leave slot pending for valid retry */
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT,
                          (uint16_t)(local_hash[0] | (local_hash[1] << 8)),
                          0);
        return -1;
    }

    /* HMAC verified — now mark as resolved and reclaim the slot (Comment 24 fix) */
    s->pending[slot_index].resolved = true;
    s->pending[slot_index].resolved_at = hal_tick_ms();
    s->pending[slot_index].request_id = 0; /* Reclaim slot for reuse */

    /* REQ-25: Update clock from server_ts */
    if (server_ts > 0) {
        s->clock.cloud_epoch = server_ts;
        s->clock.ticks_at_sync = hal_tick_ms();
        s->clock.time_trusted = true;
    }

    /* Handle REVOKE_PRIOR flag (bit 0) */
    if (flags & 0x01) {
        dclaw_cache_invalidate(local_hash);
    }

    /* Cache the verdict */
    dclaw_cache_store(local_hash, (dclaw_action_t)action,
                      (dclaw_severity_t)severity);

    /* Invoke retroactive callback when cloud returns BLOCK for a
     * previously speculatively-allowed request (Comment 41 fix).
     * Computes target_hash from tool_hash for the callback signature. */
    if ((dclaw_action_t)action == DCLAW_ACTION_BLOCK) {
        dclaw_retroactive_block_fn cb = dclaw_get_retroactive_callback();
        if (cb) {
            uint16_t target_hash = (uint16_t)(local_hash[0] | (local_hash[1] << 8));
            cb(target_hash, NULL);
        }
    }

    /* Audit the decision */
    dclaw_audit_write((dclaw_action_t)action, (dclaw_reason_t)reason,
                      (uint16_t)(local_hash[0] | (local_hash[1] << 8)),
                      0);

    return 0;
}

/* Public accessors for the device key — used by mqtt_client.c for heartbeat HMAC.
 * These mirror get_device_key() / s_device_key_provisioned but are externally
 * visible so the heartbeat publisher can sign heartbeats without duplicating the
 * key-loading logic. */
const uint8_t *dclaw_verdict_get_device_key(size_t *out_key_len) {
    return get_device_key(out_key_len);
}

bool dclaw_verdict_is_key_provisioned(void) {
    /* Ensure the key has been loaded at least once before checking the flag */
    size_t dummy;
    (void)get_device_key(&dummy);
    return s_device_key_provisioned;
}

/* Compute HMAC for outbound use (e.g., for testing/verification).
 * BLK-1: Output extended to 16 bytes (was 4). */
void dclaw_verdict_compute_expected_hmac(uint16_t request_id, uint8_t action,
                                         uint8_t severity, uint16_t ttl,
                                         uint8_t reason, uint8_t flags,
                                         uint32_t server_ts,
                                         const uint8_t *tool_hash,
                                         uint8_t *out_hmac_16bytes) {
    size_t key_len;
    const uint8_t *device_key = get_device_key(&key_len);
    const char *session_id = dclaw_mqtt_get_session_id();
    compute_verdict_hmac(device_key, key_len, session_id,
                         request_id, action, severity, ttl,
                         reason, flags, server_ts,
                         tool_hash, out_hmac_16bytes);
}
