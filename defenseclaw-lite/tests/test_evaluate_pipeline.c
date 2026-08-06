#include "defenseclaw.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

extern dclaw_state_t *dclaw_get_state(void);

static dclaw_tool_request_t make_request(const char *name, uint8_t caps, const char *dest) {
    dclaw_tool_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.tool_name, name, DCLAW_TOOL_NAME_MAX - 1);
    memset(req.tool_hash, 0x42, 32);
    req.cap_flags = caps;
    req.session_id = 1;
    if (dest) strncpy(req.destination, dest, DCLAW_DESTINATION_MAX - 1);
    return req;
}

static void test_allowed_local_decision(void) {
    dclaw_tool_request_t req = make_request("read-sensor", DCLAW_CAP_SENSOR_READ, NULL);
    dclaw_verdict_t v = dclaw_evaluate(&req);
    /* No deny hash, no sequence match, no dest check — goes to cache (miss) then escalate.
     * With speculative enabled and SENSOR_READ: should be PENDING */
    assert(v.mode == DCLAW_VERDICT_PENDING);
    printf("  PASS: sensor_read with no local rule -> PENDING (speculative)\n");
}

static void test_sync_block_cap_blocks(void) {
    dclaw_tool_request_t req = make_request("motor-control", DCLAW_CAP_ACTUATE, NULL);
    dclaw_verdict_t v = dclaw_evaluate(&req);
    /* ACTUATE is sync_block, cloud unreachable -> BLOCK with CLOUD_TIMEOUT */
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_CLOUD_TIMEOUT);
    assert(v.mode == DCLAW_VERDICT_SYNC);
    printf("  PASS: actuate cap (sync_block) with no cloud -> BLOCK\n");
}

static void test_destination_deny(void) {
    dclaw_tool_request_t req = make_request("curl", DCLAW_CAP_NET_FETCH, "evil.attacker.io");
    dclaw_verdict_t v = dclaw_evaluate(&req);
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_DEST_DENY);
    printf("  PASS: blocked destination -> BLOCK with DEST_DENY\n");
}

static void test_allowed_destination(void) {
    dclaw_tool_request_t req = make_request("api-call", DCLAW_CAP_NET_FETCH, "api.openai.com");
    dclaw_verdict_t v = dclaw_evaluate(&req);
    /* Allowed dest, speculative cap -> PENDING */
    assert(v.mode == DCLAW_VERDICT_PENDING);
    printf("  PASS: allowed destination + speculative cap -> PENDING\n");
}

static void test_capability_sequence_block(void) {
    /* First: NET_FETCH */
    dclaw_tool_request_t req1 = make_request("download", DCLAW_CAP_NET_FETCH, "api.openai.com");
    req1.session_id = 50;
    dclaw_evaluate(&req1);

    /* Second: EXEC_SHELL in same session -> should trigger sequence rule */
    dclaw_tool_request_t req2 = make_request("bash", DCLAW_CAP_EXEC_SHELL, NULL);
    req2.session_id = 50;
    dclaw_verdict_t v = dclaw_evaluate(&req2);
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_CAP_SEQUENCE);
    printf("  PASS: NET_FETCH -> EXEC_SHELL sequence -> BLOCK\n");
}

static void test_rate_limit_triggers(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->rate_limiters[0].tokens = 0; /* exhaust global tokens */

    dclaw_tool_request_t req = make_request("test", DCLAW_CAP_READ_FS, NULL);
    dclaw_verdict_t v = dclaw_evaluate(&req);
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_RATE_LIMIT);
    printf("  PASS: rate limit exhaustion -> BLOCK\n");

    s->rate_limiters[0].tokens = 60;
}

static void test_invalid_input_blocks(void) {
    dclaw_tool_request_t req = make_request("test", DCLAW_CAP_READ_FS, NULL);
    req.cap_flags = 0x80; /* invalid bit */
    dclaw_verdict_t v = dclaw_evaluate(&req);
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_INVALID_INPUT);
    printf("  PASS: invalid cap_flags -> BLOCK with INVALID_INPUT\n");
}

int main(void) {
    hal_init();
    dclaw_device_info_t info = {.device_id = 42, .tenant_id = 1, .fleet_id = 1};
    dclaw_init(&info);

    printf("test_evaluate_pipeline:\n");
    test_allowed_local_decision();
    test_sync_block_cap_blocks();
    test_destination_deny();
    test_allowed_destination();
    test_capability_sequence_block();
    test_rate_limit_triggers();
    test_invalid_input_blocks();
    printf("  ALL PASSED (7 tests)\n");

    dclaw_shutdown();
    return 0;
}
