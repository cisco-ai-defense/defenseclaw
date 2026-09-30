#include "defenseclaw.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

extern dclaw_action_t dclaw_correlator_evaluate(uint16_t session_id, uint8_t cap_flags);

static void test_single_cap_no_sequence(void) {
    dclaw_action_t r = dclaw_correlator_evaluate(1, DCLAW_CAP_READ_FS);
    assert(r == DCLAW_ACTION_ALLOW);
    printf("  PASS: single capability (no sequence) -> ALLOW\n");
}

static void test_dangerous_sequence_blocks(void) {
    /* Rule: NET_FETCH -> EXEC_SHELL -> BLOCK */
    dclaw_correlator_evaluate(2, DCLAW_CAP_NET_FETCH);
    dclaw_action_t r = dclaw_correlator_evaluate(2, DCLAW_CAP_EXEC_SHELL);
    assert(r == DCLAW_ACTION_BLOCK);
    printf("  PASS: NET_FETCH -> EXEC_SHELL -> BLOCK\n");
}

static void test_warn_sequence(void) {
    /* Rule: READ_FS -> SEND_MSG -> WARN */
    dclaw_correlator_evaluate(3, DCLAW_CAP_READ_FS);
    dclaw_action_t r = dclaw_correlator_evaluate(3, DCLAW_CAP_SEND_MSG);
    assert(r == DCLAW_ACTION_WARN);
    printf("  PASS: READ_FS -> SEND_MSG -> WARN\n");
}

static void test_net_fetch_actuate_blocks(void) {
    /* Rule: NET_FETCH -> ACTUATE -> BLOCK */
    dclaw_correlator_evaluate(4, DCLAW_CAP_NET_FETCH);
    dclaw_action_t r = dclaw_correlator_evaluate(4, DCLAW_CAP_ACTUATE);
    assert(r == DCLAW_ACTION_BLOCK);
    printf("  PASS: NET_FETCH -> ACTUATE -> BLOCK\n");
}

static void test_different_sessions_independent(void) {
    dclaw_correlator_evaluate(10, DCLAW_CAP_NET_FETCH);
    /* Different session — should not trigger sequence */
    dclaw_action_t r = dclaw_correlator_evaluate(11, DCLAW_CAP_EXEC_SHELL);
    assert(r == DCLAW_ACTION_ALLOW);
    printf("  PASS: different sessions are independent\n");
}

static void test_non_matching_sequence_allows(void) {
    dclaw_correlator_evaluate(5, DCLAW_CAP_READ_FS);
    dclaw_action_t r = dclaw_correlator_evaluate(5, DCLAW_CAP_READ_FS);
    assert(r == DCLAW_ACTION_ALLOW);
    printf("  PASS: READ_FS -> READ_FS (no rule match) -> ALLOW\n");
}

static void test_session_reuse_after_eviction(void) {
    /* Fill all 16 sessions, then one more should evict oldest */
    for (int i = 100; i < 117; i++) {
        dclaw_correlator_evaluate((uint16_t)i, DCLAW_CAP_READ_FS);
    }
    /* Session 100 should have been evicted; a new call should work */
    dclaw_action_t r = dclaw_correlator_evaluate(100, DCLAW_CAP_READ_FS);
    assert(r == DCLAW_ACTION_ALLOW);
    printf("  PASS: session eviction + reuse works\n");
}

int main(void) {
    hal_init();
    dclaw_device_info_t info = {.device_id = 1};
    dclaw_init(&info);

    printf("test_correlator:\n");
    test_single_cap_no_sequence();
    test_dangerous_sequence_blocks();
    test_warn_sequence();
    test_net_fetch_actuate_blocks();
    test_different_sessions_independent();
    test_non_matching_sequence_allows();
    test_session_reuse_after_eviction();
    printf("  ALL PASSED (7 tests)\n");

    dclaw_shutdown();
    return 0;
}
