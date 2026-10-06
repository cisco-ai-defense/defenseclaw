#include "defenseclaw.h"
#include "platform.h"
#include "policy_tables.h"
#include "content_scanner.h"
#include <string.h>

#if DCLAW_MQTT_ENABLED
extern int dclaw_mqtt_send_verdict_request(const dclaw_tool_request_t *req,
                                           uint16_t request_id);
extern int dclaw_verdict_register_pending(uint16_t request_id, const uint8_t *tool_hash);
extern void dclaw_mqtt_pending_store(uint16_t request_id, const uint8_t *tool_hash);
extern bool dclaw_mqtt_is_connected(void);
#endif

static dclaw_state_t g_state;
static dclaw_retroactive_block_fn g_retroactive_cb = NULL;

/* External module functions */
extern dclaw_action_t dclaw_policy_check_hash(const uint8_t *tool_hash);
extern dclaw_action_t dclaw_policy_check_destination(const char *host);
extern dclaw_action_t dclaw_correlator_evaluate(uint16_t session_id, uint8_t cap_flags);
extern uint8_t dclaw_policy_lookup_capability(const char *tool_name);
extern bool dclaw_cache_lookup(const uint8_t *tool_hash, dclaw_verdict_t *out);
extern void dclaw_cache_store(const uint8_t *tool_hash, dclaw_action_t action,
                              dclaw_severity_t severity);
extern bool dclaw_rate_limit_check(uint8_t cap_flags);
extern int dclaw_audit_write(dclaw_action_t action, dclaw_reason_t reason,
                             uint16_t target_hash, uint16_t session_id);
extern int dclaw_ipc_validate_request(const dclaw_tool_request_t *req);
extern int dclaw_config_load_brokers(void);
extern void dclaw_canary_record_block(void);

dclaw_state_t *dclaw_get_state(void) {
    return &g_state;
}

int dclaw_init(const dclaw_device_info_t *info) {
    if (hal_init() != 0) return -1;

    memset(&g_state, 0, sizeof(g_state));
    memcpy(&g_state.device, info, sizeof(dclaw_device_info_t));
    g_state.clock.time_trusted = false;
    g_state.next_request_id = 1;
    g_state.initialized = true;
    dclaw_config_load_brokers();

    uint64_t now = hal_tick_ms();
    g_state.audit_writer.last_flush_tick = now;

    g_state.rate_limiters[0].bucket_size = 60;
    g_state.rate_limiters[0].refill_rate = 60;
    g_state.rate_limiters[0].tokens = 60;
    g_state.rate_limiters[0].last_refill_tick = now;
    g_state.rate_limiters[1].bucket_size = 30;
    g_state.rate_limiters[1].refill_rate = 30;
    g_state.rate_limiters[1].tokens = 30;
    g_state.rate_limiters[1].last_refill_tick = now;
    g_state.rate_limiters[2].bucket_size = 10;
    g_state.rate_limiters[2].refill_rate = 10;
    g_state.rate_limiters[2].tokens = 10;
    g_state.rate_limiters[2].last_refill_tick = now;

    return 0;
}

void dclaw_register_retroactive_callback(dclaw_retroactive_block_fn cb) {
    g_retroactive_cb = cb;
}

void dclaw_shutdown(void) {
    dclaw_flush_audit();
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

static uint16_t compute_target_hash(const uint8_t *tool_hash) {
    return (uint16_t)(tool_hash[0] | (tool_hash[1] << 8));
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

    uint16_t target_hash = compute_target_hash(req->tool_hash);

    /* Step 1: Input validation */
    if (dclaw_ipc_validate_request(req) != 0) {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT,
                          target_hash, req->session_id);
        g_state.eval_denied_count++;
        dclaw_canary_record_block();
        return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT, DCLAW_VERDICT_SYNC);
    }

    /* Step 1b: Override caller-provided cap_flags with trusted policy lookup.
     * The IPC caller cannot be trusted to declare its own capabilities —
     * a malicious caller could submit CAP_SENSOR_READ for exec_shell to
     * bypass rate limiting and correlation checks. (Comment 18 fix) */
    uint8_t trusted_cap_flags = dclaw_policy_lookup_capability(req->tool_name);

    /* Use a mutable copy with the trusted capability flags */
    dclaw_tool_request_t trusted_req;
    memcpy(&trusted_req, req, sizeof(dclaw_tool_request_t));
    trusted_req.cap_flags = trusted_cap_flags;
    req = &trusted_req;

    /* Step 2: Rate limit check */
    if (!dclaw_rate_limit_check(req->cap_flags)) {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_RATE_LIMIT,
                          target_hash, req->session_id);
        g_state.eval_denied_count++;
        dclaw_canary_record_block();
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
            return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_CONTENT_BLOCK,
                                DCLAW_VERDICT_SYNC);
        }
    }
#endif

    /* Step 4: Deny-list hash check */
    if (dclaw_policy_check_hash(req->tool_hash) == DCLAW_ACTION_BLOCK) {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_HASH_DENY,
                          target_hash, req->session_id);
        g_state.eval_denied_count++;
        dclaw_canary_record_block();
        return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_HASH_DENY, DCLAW_VERDICT_SYNC);
    }

    /* Step 5: Destination allow/deny + SSRF check (if network capability) */
    if ((req->cap_flags & (DCLAW_CAP_NET_FETCH | DCLAW_CAP_SEND_MSG)) &&
        req->destination[0] != '\0') {
#if DCLAW_CONTENT_SCAN
        if (dclaw_ssrf_check_destination(req->destination) == DCLAW_ACTION_BLOCK) {
            dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_SSRF_BLOCK,
                              target_hash, req->session_id);
            g_state.eval_denied_count++;
            return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_SSRF_BLOCK,
                                DCLAW_VERDICT_SYNC);
        }
#endif
        if (dclaw_policy_check_destination(req->destination) == DCLAW_ACTION_BLOCK) {
            dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_DEST_DENY,
                              target_hash, req->session_id);
            g_state.eval_denied_count++;
            return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_DEST_DENY, DCLAW_VERDICT_SYNC);
        }
    }

    /* Step 6: Capability sequence correlation */
    dclaw_action_t seq_result = dclaw_correlator_evaluate(req->session_id, req->cap_flags);
    if (seq_result == DCLAW_ACTION_BLOCK) {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CAP_SEQUENCE,
                          target_hash, req->session_id);
        g_state.eval_denied_count++;
        return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_CAP_SEQUENCE, DCLAW_VERDICT_SYNC);
    }

    /* Step 7: Verdict cache lookup */
    dclaw_verdict_t cached;
    if (dclaw_cache_lookup(req->tool_hash, &cached)) {
        dclaw_audit_write(cached.action, cached.reason, target_hash, req->session_id);
        switch (cached.action) {
            case DCLAW_ACTION_ALLOW:    g_state.eval_allowed_count++;   break;
            case DCLAW_ACTION_BLOCK:    g_state.eval_denied_count++;    break;
            case DCLAW_ACTION_WARN:     g_state.eval_warned_count++;    break;
            case DCLAW_ACTION_ESCALATE: g_state.eval_escalated_count++; break;
        }
        return cached;
    }

    /* Step 8: No local decision — need cloud escalation */
#if DCLAW_MQTT_ENABLED
    {
        uint16_t request_id = g_state.next_request_id++;
        /* Store the tool hash so the HMAC verifier can look it up on response */
        dclaw_mqtt_pending_store(request_id, req->tool_hash);
        dclaw_verdict_register_pending(request_id, req->tool_hash);

        /* Attempt to send the verdict request to the cloud */
        int send_rc = -1;
        if (dclaw_mqtt_is_connected()) {
            send_rc = dclaw_mqtt_send_verdict_request(req, request_id);
        }

#if DCLAW_SPECULATIVE_EXECUTION
        if (!is_sync_block_required(req->cap_flags)) {
            /* Speculative mode: allow the agent to proceed, cloud will respond async.
             * If send failed, still return ALLOW — the request is logged for audit. */
            dclaw_audit_write(DCLAW_ACTION_ESCALATE, DCLAW_REASON_CLOUD_BLOCK,
                              target_hash, req->session_id);
            g_state.eval_escalated_count++;
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
            return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_TIMEOUT,
                                DCLAW_VERDICT_SYNC);
        }

        /* Send succeeded — return PENDING so the caller knows to wait for the
         * async response (which will arrive via MQTT and be handled by
         * dclaw_verdict_handle_response). */
        dclaw_audit_write(DCLAW_ACTION_ESCALATE, DCLAW_REASON_CLOUD_BLOCK,
                          target_hash, req->session_id);
        g_state.eval_escalated_count++;
        return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_BLOCK,
                            DCLAW_VERDICT_PENDING);
    }
#else
    /* MQTT not enabled — no cloud path available */
#if DCLAW_SPECULATIVE_EXECUTION
    if (!is_sync_block_required(req->cap_flags)) {
        dclaw_audit_write(DCLAW_ACTION_ESCALATE, DCLAW_REASON_CLOUD_BLOCK,
                          target_hash, req->session_id);
        g_state.eval_escalated_count++;
        return make_verdict(DCLAW_ACTION_ALLOW, DCLAW_REASON_CLOUD_BLOCK,
                            DCLAW_VERDICT_PENDING);
    }
#endif
    dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_TIMEOUT,
                      target_hash, req->session_id);
    g_state.eval_denied_count++;
    return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_TIMEOUT, DCLAW_VERDICT_SYNC);
#endif /* DCLAW_MQTT_ENABLED */
}

dclaw_action_t dclaw_check_destination(const char *host, uint16_t port) {
    (void)port;
    return dclaw_policy_check_destination(host);
}

void dclaw_report_result(uint16_t session_id, const char *tool_name,
                         bool success, const char *output_summary) {
    (void)output_summary;
    uint8_t dummy_hash[32] = {0};
    if (tool_name) {
        for (size_t i = 0; tool_name[i] && i < 32; i++)
            dummy_hash[i] = (uint8_t)tool_name[i];
    }
    uint16_t target_hash = (uint16_t)(dummy_hash[0] | (dummy_hash[1] << 8));
    dclaw_audit_write(success ? DCLAW_ACTION_ALLOW : DCLAW_ACTION_BLOCK,
                      DCLAW_REASON_POLICY_TABLE, target_hash, session_id);
}
