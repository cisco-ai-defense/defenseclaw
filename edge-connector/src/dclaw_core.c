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
#include "policy_tables.h"
#include "content_scanner.h"
#include "sha256.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#if DCLAW_MQTT_ENABLED
extern int dclaw_mqtt_send_verdict_request(const dclaw_tool_request_t *req,
                                           uint16_t request_id);
extern int dclaw_verdict_register_pending(uint16_t request_id, const uint8_t *tool_hash);
extern void dclaw_mqtt_pending_store(uint16_t request_id, const uint8_t *tool_hash);
extern bool dclaw_mqtt_is_connected(void);
#endif

static dclaw_state_t g_state;
static dclaw_retroactive_block_fn g_retroactive_cb = NULL;

static bool g_strict_mode = false;

/* External module functions */
extern dclaw_action_t dclaw_policy_check_hash(const uint8_t *tool_hash);
extern dclaw_action_t dclaw_policy_check_destination(const char *host);
extern dclaw_action_t dclaw_policy_check_severity(dclaw_severity_t sev);
extern dclaw_action_t dclaw_correlator_evaluate(uint16_t session_id, uint8_t cap_flags);
extern uint8_t dclaw_policy_lookup_capability(const char *tool_name);
extern bool dclaw_cache_lookup(const uint8_t *tool_hash, dclaw_verdict_t *out);
extern void dclaw_cache_store(const uint8_t *tool_hash, dclaw_action_t action,
                              dclaw_severity_t severity);
extern bool dclaw_rate_limit_check(uint8_t cap_flags);
extern int dclaw_audit_write(dclaw_action_t action, dclaw_reason_t reason,
                             uint32_t target_hash, uint16_t session_id);
extern bool dclaw_audit_key_provisioned(void);
extern int dclaw_ipc_validate_request(const dclaw_tool_request_t *req);
extern int dclaw_config_load_brokers(void);
#if DCLAW_MQTT_ENABLED
extern int dclaw_boot_counter_advance(void);
extern void dclaw_canary_record_block(void);
extern int dclaw_emergency_load_from_flash(void);
#else
static inline void dclaw_canary_record_block(void) { /* no-op: canary is part of OTA/MQTT */ }
#endif
extern void dclaw_policy_tables_init(void);
extern int dclaw_audit_ring_init(void);
extern void dclaw_audit_ring_shutdown(void);

dclaw_state_t *dclaw_get_state(void) {
    return &g_state;
}

int dclaw_init(const dclaw_device_info_t *info) {
    if (hal_init() != 0) return -1;

    memset(&g_state, 0, sizeof(g_state));
    memcpy(&g_state.device, info, sizeof(dclaw_device_info_t));
    g_state.clock.time_trusted = false;
    g_state.next_request_id = 1;
    if (hal_random_bytes(g_state.boot_nonce, sizeof(g_state.boot_nonce)) != 0) {
        fprintf(stderr, "[DCLAW] ERROR: Failed to generate boot nonce. "
                "Verdict replay protection unavailable.\n");
        memset(g_state.boot_nonce, 0, sizeof(g_state.boot_nonce));
    }

#if !DCLAW_DEV_MODE
    {
        bool nonce_zero = true;
        for (size_t i = 0; i < sizeof(g_state.boot_nonce); i++) {
            if (g_state.boot_nonce[i] != 0) { nonce_zero = false; break; }
        }
        if (nonce_zero) {
            fprintf(stderr, "[DCLAW] FATAL: Boot nonce is all-zero in production mode. "
                    "Cannot guarantee verdict anti-replay. Refusing to start.\n");
            return -1;
        }
    }
#endif

    g_state.initialized = true;
    dclaw_policy_tables_init();

    if (dclaw_config_load_brokers() != 0) {
        fprintf(stderr, "[DCLAW] ERROR: Cannot load policy partition state; refusing to start.\n");
        g_state.initialized = false;
        hal_shutdown();
        return -1;
    }

#if DCLAW_MQTT_ENABLED
    if (dclaw_boot_counter_advance() != 0) {
        fprintf(stderr, "[DCLAW] ERROR: Cannot persist boot generation; refusing to start.\n");
        g_state.initialized = false;
        hal_shutdown();
        return -1;
    }
    if (dclaw_policy_reload_from_flash() != 0 && g_state.device.policy_version != 0) {
        fprintf(stderr, "[DCLAW] ERROR: Accepted OTA policy cannot be verified from flash; refusing startup.\n");
        g_state.initialized = false;
        hal_shutdown();
        return -1;
    }
#endif

#if DCLAW_MQTT_ENABLED
    if (dclaw_emergency_load_from_flash() != 0) {
        fprintf(stderr, "[DCLAW] ERROR: Cannot restore emergency anti-replay state; refusing startup.\n");
        g_state.initialized = false;
        hal_shutdown();
        return -1;
    }
#endif

    uint64_t now = hal_tick_ms();
    g_state.audit_writer.last_flush_tick = now;

    g_state.rate_limiters[0].bucket_size = policy_rate_tool_calls_per_min;
    g_state.rate_limiters[0].refill_rate = policy_rate_tool_calls_per_min;
    g_state.rate_limiters[0].tokens = policy_rate_tool_calls_per_min;
    g_state.rate_limiters[0].last_refill_tick = now;
    g_state.rate_limiters[1].bucket_size = policy_rate_network_per_min;
    g_state.rate_limiters[1].refill_rate = policy_rate_network_per_min;
    g_state.rate_limiters[1].tokens = policy_rate_network_per_min;
    g_state.rate_limiters[1].last_refill_tick = now;
    g_state.rate_limiters[2].bucket_size = policy_rate_actuations_per_min;
    g_state.rate_limiters[2].refill_rate = policy_rate_actuations_per_min;
    g_state.rate_limiters[2].tokens = policy_rate_actuations_per_min;
    g_state.rate_limiters[2].last_refill_tick = now;

#if !DCLAW_DEV_MODE
    if (!dclaw_audit_key_provisioned()) {
        fprintf(stderr, "[DCLAW] ERROR: Cannot start without DCLAW_AUDIT_KEY in "
                "production mode. Provide a valid 64-hex-char audit key.\n");
        return -2;
    }
#endif

    dclaw_audit_ring_init();

    {
#if !DCLAW_DEV_MODE
        g_strict_mode = true; /* production: sync-block by default */
        const char *strict = getenv("DCLAW_STRICT_MODE");
        if (strict && strcmp(strict, "0") == 0) {
            g_strict_mode = false;
            fprintf(stderr, "[DCLAW] Speculative execution enabled (DCLAW_STRICT_MODE=0).\n");
        }
#else
        const char *strict = getenv("DCLAW_STRICT_MODE");
        if (strict && strcmp(strict, "1") == 0) {
            g_strict_mode = true;
            fprintf(stderr, "[DCLAW] Strict mode enabled — all capabilities require sync cloud approval.\n");
        }
#endif
    }

    return 0;
}

void dclaw_register_retroactive_callback(dclaw_retroactive_block_fn cb) {
    g_retroactive_cb = cb;
}

dclaw_retroactive_block_fn dclaw_get_retroactive_callback(void) {
    return g_retroactive_cb;
}

/* Forward declarations for key-material zeroing on shutdown */
#if DCLAW_MQTT_ENABLED
extern void dclaw_verdict_protocol_shutdown(void);
extern void dclaw_mqtt_shutdown(void);
#endif

void dclaw_shutdown(void) {
    dclaw_flush_audit();
    dclaw_audit_ring_shutdown();
#if DCLAW_MQTT_ENABLED
    /* Zero device key material to prevent leakage in core dumps */
    dclaw_mqtt_shutdown();
    dclaw_verdict_protocol_shutdown();
#endif
    /* Zero boot nonce and any other sensitive state */
    dclaw_secure_zero(g_state.boot_nonce, sizeof(g_state.boot_nonce));
    g_state.initialized = false;
    hal_shutdown();
}

#if DCLAW_MQTT_ENABLED
extern int dclaw_cbor_encode_heartbeat(uint8_t *buf, size_t *out_len, size_t buf_size);
#endif

void dclaw_get_health(uint8_t *out_heartbeat, size_t *out_len, size_t buf_size) {
#if DCLAW_MQTT_ENABLED
    size_t len = 0;
    if (dclaw_cbor_encode_heartbeat(out_heartbeat, &len, buf_size) == 0) {
        *out_len = len;
    } else {
        *out_len = 0;
    }
#else
    (void)out_heartbeat;
    (void)buf_size;
    *out_len = 0;
#endif
}

static uint32_t compute_target_hash(const uint8_t *tool_hash) {
    return (uint32_t)tool_hash[0] | ((uint32_t)tool_hash[1] << 8)
         | ((uint32_t)tool_hash[2] << 16) | ((uint32_t)tool_hash[3] << 24);
}


#if DCLAW_SPECULATIVE_EXECUTION
static bool is_sync_block_required(uint8_t cap_flags) {
    for (size_t i = 0; i < escalation_table_count; i++) {
        if ((cap_flags & escalation_table[i].cap_flag) && escalation_table[i].mode == 0) {
            return true;
        }
    }
    return false;
}
#endif

static dclaw_verdict_t make_verdict(dclaw_action_t action, dclaw_reason_t reason,
                                    dclaw_verdict_mode_t mode) {
    dclaw_verdict_t v = {
        .action = action,
        .reason = reason,
        .severity = DCLAW_SEV_INFO,
        .mode = mode,
        .ttl_minutes = 0,
        .from_cache = false,
    };
    return v;
}

dclaw_verdict_t dclaw_evaluate(const dclaw_tool_request_t *req) {
    if (!req) return (dclaw_verdict_t){.action = DCLAW_ACTION_BLOCK, .reason = DCLAW_REASON_INVALID_INPUT};

    g_state.eval_count++;

    /* SYSTEM scope should only be set internally (e.g., by content
     * scanners or the daemon itself), not from IPC callers.  Override
     * SYSTEM scope on inbound requests to UNKNOWN so external callers
     * cannot bypass scope-specific content scanning rules. */
    if (g_state.emergency.block_all_active) {
        uint32_t th = compute_target_hash(req->tool_hash);
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_BLOCK,
                          th, req->session_id);
        g_state.eval_denied_count++;
        return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_BLOCK, DCLAW_VERDICT_SYNC);
    }

    uint32_t target_hash = compute_target_hash(req->tool_hash);

    /* Step 1: Input validation */
    if (dclaw_ipc_validate_request(req) != 0) {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT,
                          target_hash, req->session_id);
        g_state.eval_denied_count++;
        dclaw_canary_record_block();
        return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT, DCLAW_VERDICT_SYNC);
    }

    /* Step 1a: Hash-to-name binding — verify that the submitted tool_hash
     * is the SHA-256 of the submitted tool_name. An attacker could submit
     * exec_shell's hash with sensor_read as the name to bypass capability
     * lookup (which is based on name) while the cache/verdict uses the hash.
     * This check binds them together: if they don't match, BLOCK.
     *
     * An empty tool_name is rejected as INVALID_INPUT to prevent an attacker
     * from submitting any hash with no name and bypassing capability-based controls. */
    if (req->tool_name[0] == '\0') {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT,
                          target_hash, req->session_id);
        g_state.eval_denied_count++;
        dclaw_canary_record_block();
        return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT, DCLAW_VERDICT_SYNC);
    }
    {
        uint8_t computed_hash[DCLAW_SHA256_DIGEST_SIZE];
        size_t name_len = strlen(req->tool_name);
        dclaw_sha256((const uint8_t *)req->tool_name, name_len, computed_hash);
        if (memcmp(computed_hash, req->tool_hash, DCLAW_SHA256_DIGEST_SIZE) != 0) {
            dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_HASH_MISMATCH,
                              target_hash, req->session_id);
            g_state.eval_denied_count++;
            dclaw_canary_record_block();
            return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_HASH_MISMATCH, DCLAW_VERDICT_SYNC);
        }
    }

    /* Step 1b: Override caller-provided cap_flags with trusted policy lookup.
     * The IPC caller cannot be trusted to declare its own capabilities —
     * a malicious caller could submit CAP_SENSOR_READ for exec_shell to
     * bypass rate limiting and correlation checks. */
    uint8_t trusted_cap_flags = dclaw_policy_lookup_capability(req->tool_name);
    if (trusted_cap_flags == DCLAW_CAP_UNKNOWN) {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT,
                          target_hash, req->session_id);
        g_state.eval_denied_count++;
        dclaw_canary_record_block();
        return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT,
                            DCLAW_VERDICT_SYNC);
    }

    static bool in_eval = false;
    if (in_eval) {
        return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT, DCLAW_VERDICT_SYNC);
    }
    in_eval = true;

    dclaw_tool_request_t trusted_req;
    memcpy(&trusted_req, req, sizeof(dclaw_tool_request_t));
    trusted_req.cap_flags = trusted_cap_flags;
    /* Fix content pointer aliasing: after memcpy, content still points into
     * the original request's buffer. Rebind to the copy's own buffer so the
     * trusted_req is fully self-contained. */
    if (trusted_req.content == req->content_buf)
        trusted_req.content = trusted_req.content_buf;
    if (trusted_req.content_scope == DCLAW_CONTENT_SCOPE_SYSTEM) {
        trusted_req.content_scope = DCLAW_CONTENT_SCOPE_UNKNOWN;
    }
    req = &trusted_req;

    /* Step 2: Rate limit check */
    if (!dclaw_rate_limit_check(req->cap_flags)) {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_RATE_LIMIT,
                          target_hash, req->session_id);
        g_state.eval_denied_count++;
        dclaw_canary_record_block();
        in_eval = false;
        return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_RATE_LIMIT, DCLAW_VERDICT_SYNC);
    }

    /* Step 3: Content scan (if content provided) */
#if DCLAW_CONTENT_SCAN
    if (req->content && req->content_len > 0) {
        dclaw_scan_context_t scan_ctx;
        dclaw_content_scope_t scope = req->content_scope ?
            (dclaw_content_scope_t)req->content_scope :
            dclaw_infer_content_scope((dclaw_direction_t)req->direction);
        dclaw_content_scan(req->content, req->content_len, scope, &scan_ctx);
        dclaw_action_t scan_action = dclaw_content_scan_worst_action(&scan_ctx, scope);
        if (scan_action == DCLAW_ACTION_BLOCK) {
            dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CONTENT_BLOCK,
                              target_hash, req->session_id);
            g_state.eval_denied_count++;
            dclaw_canary_record_block();
            in_eval = false;
            return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_CONTENT_BLOCK,
                                DCLAW_VERDICT_SYNC);
        }
    }
#endif

    /* Step 3b: If content was truncated, escalate to cloud for a full
     * inspection rather than relying on the partial local scan. Truncated
     * content may hide malicious payloads past the cutoff point. */
    if (req->flags & DCLAW_FLAG_CONTENT_TRUNCATED) {
#if DCLAW_MQTT_ENABLED
        dclaw_audit_write(DCLAW_ACTION_ESCALATE, DCLAW_REASON_CONTENT_BLOCK,
                          target_hash, req->session_id);
        g_state.eval_escalated_count++;
        in_eval = false;
        return make_verdict(DCLAW_ACTION_ESCALATE, DCLAW_REASON_CONTENT_BLOCK,
                            DCLAW_VERDICT_PENDING);
#endif
#if !DCLAW_MQTT_ENABLED
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CONTENT_BLOCK,
                          target_hash, req->session_id);
        g_state.eval_denied_count++;
        in_eval = false;
        return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_CONTENT_BLOCK,
                            DCLAW_VERDICT_SYNC);
#endif
    }

    /* Step 4: Deny-list hash check */
    if (dclaw_policy_check_hash(req->tool_hash) == DCLAW_ACTION_BLOCK) {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_HASH_DENY,
                          target_hash, req->session_id);
        g_state.eval_denied_count++;
        dclaw_canary_record_block();
        in_eval = false;
        return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_HASH_DENY, DCLAW_VERDICT_SYNC);
    }

    /* Step 5: Destination allow/deny + SSRF check (if network capability) */
    if (req->cap_flags & (DCLAW_CAP_NET_FETCH | DCLAW_CAP_SEND_MSG)) {
        if (req->destination[0] == '\0') {
            dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_DEST_DENY,
                              target_hash, req->session_id);
            g_state.eval_denied_count++;
            dclaw_canary_record_block();
            in_eval = false;
            return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_DEST_DENY,
                                DCLAW_VERDICT_SYNC);
        }
        if (dclaw_ssrf_check_destination(req->destination) == DCLAW_ACTION_BLOCK) {
            dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_SSRF_BLOCK,
                              target_hash, req->session_id);
            g_state.eval_denied_count++;
            dclaw_canary_record_block();
            in_eval = false;
            return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_SSRF_BLOCK,
                                DCLAW_VERDICT_SYNC);
        }
        if (dclaw_policy_check_destination(req->destination) == DCLAW_ACTION_BLOCK) {
            dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_DEST_DENY,
                              target_hash, req->session_id);
            g_state.eval_denied_count++;
            dclaw_canary_record_block();
            in_eval = false;
            return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_DEST_DENY, DCLAW_VERDICT_SYNC);
        }
    }

    /* Step 6: Capability sequence correlation */
    dclaw_action_t seq_result = dclaw_correlator_evaluate(req->session_id, req->cap_flags);
    if (seq_result == DCLAW_ACTION_BLOCK) {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CAP_SEQUENCE,
                          target_hash, req->session_id);
        g_state.eval_denied_count++;
        dclaw_canary_record_block();
        in_eval = false;
        return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_CAP_SEQUENCE, DCLAW_VERDICT_SYNC);
    }

    /* Step 7: Verdict cache lookup */
    dclaw_verdict_t cached;
    if (dclaw_cache_lookup(req->tool_hash, &cached)) {
        g_state.eval_cache_hit_count++;
        dclaw_audit_write(cached.action, cached.reason, target_hash, req->session_id);
        switch (cached.action) {
            case DCLAW_ACTION_ALLOW:    g_state.eval_allowed_count++;   break;
            case DCLAW_ACTION_BLOCK:    g_state.eval_denied_count++;  dclaw_canary_record_block(); break;
            case DCLAW_ACTION_WARN:     g_state.eval_warned_count++;    break;
            case DCLAW_ACTION_ESCALATE: g_state.eval_escalated_count++; break;
        }
        in_eval = false;
        return cached;
    }

    /* Step 8: No local decision — need cloud escalation */
#if DCLAW_MQTT_ENABLED
    {
        if (++g_state.next_request_id == 0) g_state.next_request_id = 1;
        uint16_t request_id = g_state.next_request_id;
        /* Store the tool hash so the HMAC verifier can look it up on response.
         * If the pending slot registration fails (all slots full), return
         * BLOCK immediately rather than sending a request that can never be
         * correlated with its response — the IPC caller would hang forever. */
        if (dclaw_verdict_register_pending(request_id, req->tool_hash) < 0) {
            dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_TIMEOUT,
                              target_hash, req->session_id);
            g_state.eval_denied_count++;
            in_eval = false;
            return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_TIMEOUT,
                                DCLAW_VERDICT_SYNC);
        }
        dclaw_mqtt_pending_store(request_id, req->tool_hash);

        /* Attempt to send the verdict request to the cloud */
        int send_rc = -1;
        if (dclaw_mqtt_is_connected()) {
            send_rc = dclaw_mqtt_send_verdict_request(req, request_id);
        }

#if DCLAW_SPECULATIVE_EXECUTION
        if (!g_strict_mode && !is_sync_block_required(req->cap_flags)) {
            /* Speculative mode: allow the agent to proceed, cloud will respond async.
             * If send failed, still return ALLOW — the request is logged for audit. */
            dclaw_audit_write(DCLAW_ACTION_ESCALATE, DCLAW_REASON_CLOUD_BLOCK,
                              target_hash, req->session_id);
            g_state.eval_escalated_count++;
            in_eval = false;
            return make_verdict(DCLAW_ACTION_ALLOW, DCLAW_REASON_CLOUD_BLOCK,
                                DCLAW_VERDICT_PENDING);
        }
#endif

        /* Sync block mode: must wait for cloud verdict.
         * If the send failed, we have no verdict to wait for — block on timeout. */
        if (send_rc != 0) {
            dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_TIMEOUT,
                              target_hash, req->session_id);
            g_state.eval_denied_count++;
            in_eval = false;
            return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_TIMEOUT,
                                DCLAW_VERDICT_SYNC);
        }

        /* Send succeeded — return PENDING so the caller knows to wait for the
         * async response (which will arrive via MQTT and be handled by
         * dclaw_verdict_handle_response). */
        dclaw_audit_write(DCLAW_ACTION_ESCALATE, DCLAW_REASON_CLOUD_BLOCK,
                          target_hash, req->session_id);
        g_state.eval_escalated_count++;
        in_eval = false;
        return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_BLOCK,
                            DCLAW_VERDICT_PENDING);
    }
#else
    /* MQTT not enabled — no cloud path available.
     * Without MQTT, speculative ALLOW is pointless because no cloud
     * will ever respond. All uncached tools BLOCK with CLOUD_TIMEOUT. */
    dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_TIMEOUT,
                      target_hash, req->session_id);
    g_state.eval_denied_count++;
    in_eval = false;
    return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_TIMEOUT, DCLAW_VERDICT_SYNC);
#endif /* DCLAW_MQTT_ENABLED */
}
