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
#include "hmac_sha256.h"
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
extern void dclaw_cache_store_with_ttl(const uint8_t *tool_hash, dclaw_action_t action,
                                       dclaw_severity_t severity, uint16_t ttl_minutes);
extern void dclaw_cache_invalidate(const uint8_t *tool_hash);
extern const char *dclaw_mqtt_get_session_id(void);
extern int dclaw_audit_write(dclaw_action_t action, dclaw_reason_t reason,
                             uint32_t target_hash, uint16_t session_id);
extern dclaw_retroactive_block_fn dclaw_get_retroactive_callback(void);
extern int dclaw_cbor_decode_verdict_response(const uint8_t *buf, size_t len,
                                              uint16_t *request_id, uint8_t *action,
                                              uint8_t *severity, uint16_t *ttl,
                                              uint8_t *reason, uint8_t *flags,
                                              uint32_t *server_ts, uint8_t *hmac_tag);

/*
 * Verdict HMAC computation.
 * When DCLAW_HAS_MBEDTLS=1: full HMAC-SHA256 via mbedtls_md (32 bytes).
 * Otherwise: built-in HMAC-SHA256 (no external library), full 32 bytes.
 * Extended from 16 to 32 bytes to eliminate truncation-based collision risk.
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
                                 const uint8_t *request_nonce,
                                 uint8_t *out_32bytes) {
    /*
     * Full HMAC-SHA256 (32 bytes), covering ALL verdict fields.
     * Extended from 16 to 32 bytes to use full digest strength.
     * Input: HMAC-SHA256(device_key, session_id || request_id || action ||
     *        severity || ttl || reason || flags || server_ts || tool_hash[0:32]
     *        || boot_nonce || request_nonce)
     */
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

    /* Feed: severity (1 byte) */
    mbedtls_md_hmac_update(&ctx, &severity, 1);

    /* Feed: ttl (2 bytes, little-endian) */
    uint8_t ttl_le[2] = { (uint8_t)(ttl & 0xFF), (uint8_t)(ttl >> 8) };
    mbedtls_md_hmac_update(&ctx, ttl_le, 2);

    /* Feed: reason (1 byte) */
    mbedtls_md_hmac_update(&ctx, &reason, 1);

    /* Feed: flags (1 byte) */
    mbedtls_md_hmac_update(&ctx, &flags, 1);

    /* Feed: server_ts (4 bytes, little-endian) */
    uint8_t ts_le[4] = {
        (uint8_t)(server_ts & 0xFF),
        (uint8_t)((server_ts >> 8) & 0xFF),
        (uint8_t)((server_ts >> 16) & 0xFF),
        (uint8_t)((server_ts >> 24) & 0xFF)
    };
    mbedtls_md_hmac_update(&ctx, ts_le, 4);

    /* Feed: tool_hash[0:32] */
    mbedtls_md_hmac_update(&ctx, tool_hash, 32);

    mbedtls_md_hmac_update(&ctx, dclaw_get_state()->boot_nonce, 16);

    mbedtls_md_hmac_update(&ctx, request_nonce, 4);

    mbedtls_md_hmac_finish(&ctx, out_32bytes);
    mbedtls_md_free(&ctx);
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
                                 const uint8_t *request_nonce,
                                 uint8_t *out_32bytes) {
    /*
     * Full HMAC-SHA256 (32 bytes), covering ALL verdict fields.
     * Extended from 16 to 32 bytes to use full digest strength.
     * Input: HMAC-SHA256(device_key, session_id || request_id || action ||
     *        severity || ttl || reason || flags || server_ts || tool_hash[0:32]
     *        || boot_nonce || request_nonce)
     * Matches the mbedTLS path semantics exactly.
     */
    uint8_t msg[284];
    size_t msg_len = 0;

    size_t sid_len = strlen(session_id);
    if (sid_len > 220) sid_len = 220;
    memcpy(msg + msg_len, session_id, sid_len);
    msg_len += sid_len;

    /* Feed: request_id (2 bytes, little-endian) */
    msg[msg_len++] = (uint8_t)(request_id & 0xFF);
    msg[msg_len++] = (uint8_t)(request_id >> 8);

    /* Feed: action (1 byte) */
    msg[msg_len++] = action;

    /* Feed: severity (1 byte) */
    msg[msg_len++] = severity;

    /* Feed: ttl (2 bytes, little-endian) */
    msg[msg_len++] = (uint8_t)(ttl & 0xFF);
    msg[msg_len++] = (uint8_t)(ttl >> 8);

    /* Feed: reason (1 byte) */
    msg[msg_len++] = reason;

    /* Feed: flags (1 byte) */
    msg[msg_len++] = flags;

    /* Feed: server_ts (4 bytes, little-endian) */
    msg[msg_len++] = (uint8_t)(server_ts & 0xFF);
    msg[msg_len++] = (uint8_t)((server_ts >> 8) & 0xFF);
    msg[msg_len++] = (uint8_t)((server_ts >> 16) & 0xFF);
    msg[msg_len++] = (uint8_t)((server_ts >> 24) & 0xFF);

    /* Feed: tool_hash[0:32] */
    memcpy(msg + msg_len, tool_hash, 32);
    msg_len += 32;

    memcpy(msg + msg_len, dclaw_get_state()->boot_nonce, 16);
    msg_len += 16;

    memcpy(msg + msg_len, request_nonce, 4);
    msg_len += 4;

    dclaw_hmac_sha256(device_key, key_len, msg, msg_len, out_32bytes);
    dclaw_secure_zero(msg, sizeof(msg));
}

#endif /* DCLAW_HAS_MBEDTLS */

/* ct_compare() is defined in hmac_sha256.c (always compiled) and declared
 * in hmac_sha256.h. We use it here for HMAC verification. */
#if defined(DCLAW_HAS_MBEDTLS) && DCLAW_HAS_MBEDTLS == 1
#include "hmac_sha256.h"
#endif

/* Device key loaded once from HAL secure element */
static uint8_t s_device_key[32];
static size_t  s_device_key_len = 0;
static bool    s_device_key_loaded = false;
static bool    s_device_key_provisioned = false;

/* hex_nibble / hex_decode moved to dclaw_hex_decode() in hmac_sha256.c */

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
            if (dclaw_hex_decode(env_key, s_device_key, 32) == 0) {
                s_device_key_len = 32;
                loaded = true;
                /* Best-effort scrub; /proc/PID/environ snapshot is NOT cleared. */
                dclaw_scrub_env("DCLAW_DEVICE_KEY");
                fprintf(stderr, "[DCLAW] WARNING: Device key loaded from environment variable.\n"
                        "[DCLAW] WARNING: Use file-based key provisioning in production "
                        "(/etc/defenseclaw/device.key).\n");
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
            /* Fallback: 32-byte zero key.
             * Must match the Go side (bridge.go) which uses make([]byte, 32).
             * Only permitted in dev mode (DCLAW_DEV_MODE=ON). */
            fprintf(stderr, "[DCLAW] WARNING: No device key found, using zero key (dev mode only).\n");
            memset(s_device_key, 0, sizeof(s_device_key));
            s_device_key_len = 32;
#else
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

/* A pending slot that backs a speculatively allowed call is that call's only
 * revocation path: the gateway's verdict is matched to the session through
 * it. Such a slot is never reused or timed out by the 500 ms synchronous
 * bookkeeping; it is held until the verdict arrives or the speculative
 * deadline passes (dclaw_speculative_expire). */
bool dclaw_verdict_backs_speculative(uint16_t request_id) {
    if (request_id == 0) return false;
    dclaw_state_t *s = dclaw_get_state();
    for (int k = 0; k < DCLAW_SPECULATIVE_SLOTS; k++) {
        if (s->speculative[k].request_id == request_id) return true;
    }
    return false;
}

static int find_unresolved_pending(const dclaw_state_t *s, uint16_t request_id) {
    for (int i = 0; i < DCLAW_PENDING_SLOTS; i++) {
        if (s->pending[i].request_id == request_id && !s->pending[i].resolved) return i;
    }
    return -1;
}

/* Release speculative slots whose gateway verdict did not arrive before the
 * deadline, or whose pending slot no longer exists. The call already ran and
 * can no longer be verified, so its session is revoked (fail closed). */
void dclaw_speculative_expire(uint64_t now_ms) {
    dclaw_state_t *s = dclaw_get_state();
    for (int k = 0; k < DCLAW_SPECULATIVE_SLOTS; k++) {
        dclaw_speculative_slot_t *sp = &s->speculative[k];
        if (sp->request_id == 0) continue;
        int p = find_unresolved_pending(s, sp->request_id);
        if (p >= 0 && now_ms < sp->revoke_deadline_ms) continue;
        uint16_t session = sp->session_id;
        if (p >= 0) {
            s->pending[p].request_id = 0;
            s->pending[p].resolved = false;
        }
        memset(sp, 0, sizeof(*sp));
        dclaw_session_revoke(session);
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_TIMEOUT, 0, session);
        dclaw_retroactive_block_fn cb = dclaw_get_retroactive_callback();
        if (cb) cb(session, "(verdict-timeout)");
    }
}

/* A synchronous request whose transport entry was evicted can no longer be
 * matched; free its slot. Slots backing speculative calls are kept. */
void dclaw_verdict_mark_timeout(uint16_t request_id) {
    dclaw_state_t *s = dclaw_get_state();
    if (dclaw_verdict_backs_speculative(request_id)) return;
    for (int i = 0; i < DCLAW_PENDING_SLOTS; i++) {
        if (s->pending[i].request_id == request_id) {
            s->pending[i].request_id = 0;
            s->pending[i].resolved = false;
            return;
        }
    }
}

/* Register a pending verdict request.
 *
 * A slot is "available" when EITHER:
 *   (a) it has never been used (request_id == 0 && !resolved), OR
 *   (b) it was resolved and reclaimed (resolved == true).
 * An unresolved slot older than the synchronous deadline is reclaimed,
 * unless it backs a speculative call. Returns -1 when no slot is free; the
 * caller then fails closed. */
int dclaw_verdict_register_pending(uint16_t request_id, const uint8_t *tool_hash) {
    dclaw_state_t *s = dclaw_get_state();
    uint64_t now = hal_tick_ms();
    (void)tool_hash; /* stored externally for HMAC verification */

    dclaw_speculative_expire(now);

    for (int i = 0; i < DCLAW_PENDING_SLOTS; i++) {
        bool available = (s->pending[i].request_id == 0 && !s->pending[i].resolved)
                      || s->pending[i].resolved;
        if (available) {
            s->pending[i].request_id = request_id;
            s->pending[i].resolved = false;
            s->pending[i].resolved_at = now;
            hal_random_bytes(s->pending[i].request_nonce, 4);
            return i;
        }
    }

    for (int i = 0; i < DCLAW_PENDING_SLOTS; i++) {
        if (s->pending[i].request_id != 0 && !s->pending[i].resolved &&
            !dclaw_verdict_backs_speculative(s->pending[i].request_id)) {
            if (s->pending[i].resolved_at != 0 &&
                (now - s->pending[i].resolved_at) > DCLAW_VERDICT_TIMEOUT_MS) {
                /* Reclaim stale synchronous slot */
                s->pending[i].request_id = request_id;
                s->pending[i].resolved = false;
                s->pending[i].resolved_at = now;
                hal_random_bytes(s->pending[i].request_nonce, 4);
                return i;
            }
        }
    }

    return -1; /* No free slots */
}

/* Process a received verdict response */
int dclaw_verdict_handle_response(const uint8_t *resp_buf, size_t resp_len,
                                  const uint8_t *pending_tool_hash) {
    if (resp_len < 44) return -1;

    dclaw_state_t *s = dclaw_get_state();

    uint8_t local_hash[32];
    memcpy(local_hash, pending_tool_hash, 32);

    /* Decode the 44-byte response (HMAC extended to full 32 bytes) */
    uint16_t request_id, ttl;
    uint8_t action, severity, reason, flags;
    uint32_t server_ts;
    uint8_t received_hmac[32];

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

    /* REQ-27: Verify HMAC tag BEFORE marking as resolved.
     * If HMAC fails, the slot stays pending so a valid retry can still succeed. */
    uint8_t expected_hmac[32];
    size_t key_len;
    const uint8_t *device_key = get_device_key(&key_len);
    const char *session_id = dclaw_mqtt_get_session_id();

    if (!s_device_key_provisioned) {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT,
                          (uint32_t)local_hash[0] | ((uint32_t)local_hash[1] << 8)
                          | ((uint32_t)local_hash[2] << 16) | ((uint32_t)local_hash[3] << 24),
                          0);
        return -1;
    }

    compute_verdict_hmac(device_key, key_len, session_id,
                         request_id, action, severity, ttl,
                         reason, flags, server_ts,
                         local_hash, s->pending[slot_index].request_nonce,
                         expected_hmac);

    if (!ct_compare(received_hmac, expected_hmac, 32)) {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT,
                          (uint32_t)local_hash[0] | ((uint32_t)local_hash[1] << 8)
                          | ((uint32_t)local_hash[2] << 16) | ((uint32_t)local_hash[3] << 24),
                          0);
        return -1;
    }

    if (action > DCLAW_ACTION_ESCALATE) {
        return -1; /* invalid action value */
    }

    /* HMAC verified — now mark as resolved and reclaim the slot */
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

    /* The authenticated wire TTL is in minutes. A zero TTL (including
     * emergency lockdown BLOCK) must not leave a reusable cache entry. */
    dclaw_cache_store_with_ttl(local_hash, (dclaw_action_t)action,
                               (dclaw_severity_t)severity, ttl);

    /* Retroactive revocation: if this request was speculatively allowed and
     * the gateway now blocks it, revoke the session and notify. */
    for (int i = 0; i < DCLAW_SPECULATIVE_SLOTS; i++) {
        dclaw_speculative_slot_t *slot = &s->speculative[i];
        if (slot->request_id == 0 || slot->request_id != request_id) continue;
        uint16_t spec_session = slot->session_id;
        memset(slot, 0, sizeof(*slot));
        if ((dclaw_action_t)action == DCLAW_ACTION_BLOCK) {
            dclaw_session_revoke(spec_session);
            dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_RETROACTIVE,
                              (uint32_t)local_hash[0] | ((uint32_t)local_hash[1] << 8)
                              | ((uint32_t)local_hash[2] << 16) | ((uint32_t)local_hash[3] << 24),
                              spec_session);
            dclaw_retroactive_block_fn cb = dclaw_get_retroactive_callback();
            if (cb) cb(spec_session, "(cloud-verdict)");
        }
        break;
    }

    /* Audit the decision */
    dclaw_audit_write((dclaw_action_t)action, (dclaw_reason_t)reason,
                      (uint32_t)local_hash[0] | ((uint32_t)local_hash[1] << 8)
                      | ((uint32_t)local_hash[2] << 16) | ((uint32_t)local_hash[3] << 24),
                      0);

    /* Release any IPC reply waiting on this verdict. */
    dclaw_verdict_ready_fn ready = dclaw_get_verdict_ready_callback();
    if (ready) {
        dclaw_verdict_t v = {
            .action = (dclaw_action_t)action,
            .reason = (dclaw_reason_t)reason,
            .severity = (dclaw_severity_t)severity,
            .mode = DCLAW_VERDICT_SYNC,
            .ttl_minutes = ttl,
            .from_cache = false,
        };
        ready(request_id, &v);
    }

    return 0;
}

/* Zero all key material on shutdown to prevent key leakage in core dumps
 * or memory-scanning attacks after the daemon exits. */
void dclaw_verdict_protocol_shutdown(void)
{
    dclaw_secure_zero(s_device_key, sizeof(s_device_key));
    s_device_key_len = 0;
    s_device_key_loaded = false;
    s_device_key_provisioned = false;
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

/* A production daemon must not run with an unprovisioned or all-zero device
 * key: it would publish unsigned registration and heartbeat frames and
 * every escalation would time out. Called at startup with
 * production = !DCLAW_DEV_MODE; returns -1 when the daemon must refuse to
 * start. */
int dclaw_verdict_require_device_key(bool production) {
    if (!production) return 0;
    if (dclaw_verdict_is_key_provisioned()) return 0;
    fprintf(stderr, "[DCLAW] ERROR: A nonzero device key is required in production. "
            "Provision /etc/defenseclaw/device.key (or DCLAW_DEVICE_KEY).\n");
    return -1;
}

/* Compute HMAC for outbound use (e.g., for testing/verification).
 * Full 32-byte HMAC-SHA256 output (extended from 16 bytes).
 * Includes request_nonce for per-request HMAC freshness. */
void dclaw_verdict_compute_expected_hmac(uint16_t request_id, uint8_t action,
                                         uint8_t severity, uint16_t ttl,
                                         uint8_t reason, uint8_t flags,
                                         uint32_t server_ts,
                                         const uint8_t *tool_hash,
                                         const uint8_t *request_nonce,
                                         uint8_t *out_hmac_32bytes) {
    size_t key_len;
    const uint8_t *device_key = get_device_key(&key_len);
    const char *session_id = dclaw_mqtt_get_session_id();
    compute_verdict_hmac(device_key, key_len, session_id,
                         request_id, action, severity, ttl,
                         reason, flags, server_ts,
                         tool_hash, request_nonce, out_hmac_32bytes);
}
