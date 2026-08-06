#include "defenseclaw.h"
#include "platform.h"
#include "policy_tables.h"
#include <string.h>

static dclaw_state_t g_state;
static dclaw_retroactive_block_fn g_retroactive_cb = NULL;

/* External module functions */
extern dclaw_action_t dclaw_policy_check_hash(const uint8_t *tool_hash);
extern dclaw_action_t dclaw_policy_check_destination(const char *host);
extern dclaw_action_t dclaw_correlator_evaluate(uint16_t session_id, uint8_t cap_flags);
extern bool dclaw_cache_lookup(const uint8_t *tool_hash, dclaw_verdict_t *out);
extern void dclaw_cache_store(const uint8_t *tool_hash, dclaw_action_t action,
                              dclaw_severity_t severity);
extern bool dclaw_rate_limit_check(uint8_t cap_flags);
extern int dclaw_audit_write(dclaw_action_t action, dclaw_reason_t reason,
                             uint16_t target_hash, uint16_t session_id);
extern int dclaw_ipc_validate_request(const dclaw_tool_request_t *req);
extern int dclaw_config_load_brokers(void);

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

    uint32_t now = hal_tick_ms();
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

void dclaw_get_health(uint8_t *out_heartbeat, uint8_t *out_len) {
    (void)out_heartbeat;
    *out_len = 0;
}

static uint16_t compute_target_hash(const uint8_t *tool_hash) {
    return (uint16_t)(tool_hash[0] | (tool_hash[1] << 8));
}

static bool is_sync_block_required(uint8_t cap_flags) {
    for (size_t i = 0; i < escalation_table_count; i++) {
        if ((cap_flags & escalation_table[i].cap_flag) && escalation_table[i].mode == 0) {
            return true;
        }
    }
    return false;
}

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
    uint16_t target_hash = compute_target_hash(req->tool_hash);

    /* Step 1: Input validation */
    if (dclaw_ipc_validate_request(req) != 0) {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT,
                          target_hash, req->session_id);
        return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT, DCLAW_VERDICT_SYNC);
    }

    /* Step 2: Rate limit check */
    if (!dclaw_rate_limit_check(req->cap_flags)) {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_RATE_LIMIT,
                          target_hash, req->session_id);
        return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_RATE_LIMIT, DCLAW_VERDICT_SYNC);
    }

    /* Step 3: Deny-list hash check */
    if (dclaw_policy_check_hash(req->tool_hash) == DCLAW_ACTION_BLOCK) {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_HASH_DENY,
                          target_hash, req->session_id);
        return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_HASH_DENY, DCLAW_VERDICT_SYNC);
    }

    /* Step 4: Destination allow/deny (if network capability) */
    if ((req->cap_flags & (DCLAW_CAP_NET_FETCH | DCLAW_CAP_SEND_MSG)) &&
        req->destination[0] != '\0') {
        if (dclaw_policy_check_destination(req->destination) == DCLAW_ACTION_BLOCK) {
            dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_DEST_DENY,
                              target_hash, req->session_id);
            return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_DEST_DENY, DCLAW_VERDICT_SYNC);
        }
    }

    /* Step 5: Capability sequence correlation */
    dclaw_action_t seq_result = dclaw_correlator_evaluate(req->session_id, req->cap_flags);
    if (seq_result == DCLAW_ACTION_BLOCK) {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CAP_SEQUENCE,
                          target_hash, req->session_id);
        return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_CAP_SEQUENCE, DCLAW_VERDICT_SYNC);
    }

    /* Step 6: Verdict cache lookup */
    dclaw_verdict_t cached;
    if (dclaw_cache_lookup(req->tool_hash, &cached)) {
        dclaw_audit_write(cached.action, cached.reason, target_hash, req->session_id);
        return cached;
    }

    /* Step 7: No local decision — need cloud escalation */
#if DCLAW_SPECULATIVE_EXECUTION
    if (!is_sync_block_required(req->cap_flags)) {
        /* Speculative: return PENDING, agent can proceed */
        dclaw_audit_write(DCLAW_ACTION_ESCALATE, DCLAW_REASON_CLOUD_BLOCK,
                          target_hash, req->session_id);
        return make_verdict(DCLAW_ACTION_ALLOW, DCLAW_REASON_CLOUD_BLOCK, DCLAW_VERDICT_PENDING);
    }
#endif

    /* Sync block: would wait for cloud here (MQTT publish + wait).
     * For Phase 1 without cloud connected, default to BLOCK on timeout. */
    dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_TIMEOUT,
                      target_hash, req->session_id);
    return make_verdict(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_TIMEOUT, DCLAW_VERDICT_SYNC);
}

dclaw_action_t dclaw_check_destination(const char *host, uint16_t port) {
    (void)port;
    return dclaw_policy_check_destination(host);
}

void dclaw_report_result(uint16_t session_id, const char *tool_name,
                         bool success, const char *output_summary) {
    (void)session_id; (void)tool_name; (void)success; (void)output_summary;
}
