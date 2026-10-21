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
#include <stdio.h>
#include <string.h>
#include <assert.h>

extern dclaw_action_t dclaw_correlator_evaluate(uint16_t session_id, uint8_t cap_flags);
extern dclaw_state_t *dclaw_get_state(void);

/* Append a runtime (OTA-style) sequence rule to rt_policy. */
static void add_rt_rule(uint8_t a, uint8_t b, uint8_t c, uint8_t len, uint8_t action) {
    dclaw_policy_table_t *rt = &dclaw_get_state()->rt_policy;
    assert(rt->sequence_rules_count < DCLAW_RT_MAX_SEQUENCE_RULES);
    size_t i = rt->sequence_rules_count++;
    memset(&rt->sequence_rules[i], 0, sizeof(rt->sequence_rules[i]));
    rt->sequence_rules[i].seq[0] = a;
    rt->sequence_rules[i].seq[1] = b;
    rt->sequence_rules[i].seq[2] = c;
    rt->sequence_rules[i].seq_len = len;
    rt->sequence_rules[i].action = action;
}

static void test_single_cap_no_sequence(void) {
    dclaw_action_t r = dclaw_correlator_evaluate(1, DCLAW_CAP_READ_FS);
    assert(r == DCLAW_ACTION_ALLOW);
    (void)r;
    printf("  PASS: single capability (no sequence) -> ALLOW\n");
}

static void test_dangerous_sequence_blocks(void) {
    /* Rule: NET_FETCH -> EXEC_SHELL -> BLOCK */
    dclaw_correlator_evaluate(2, DCLAW_CAP_NET_FETCH);
    dclaw_action_t r = dclaw_correlator_evaluate(2, DCLAW_CAP_EXEC_SHELL);
    assert(r == DCLAW_ACTION_BLOCK);
    (void)r;
    printf("  PASS: NET_FETCH -> EXEC_SHELL -> BLOCK\n");
}

static void test_warn_sequence(void) {
    /* Rule: READ_FS -> SEND_MSG -> WARN */
    dclaw_correlator_evaluate(3, DCLAW_CAP_READ_FS);
    dclaw_action_t r = dclaw_correlator_evaluate(3, DCLAW_CAP_SEND_MSG);
    assert(r == DCLAW_ACTION_WARN);
    (void)r;
    printf("  PASS: READ_FS -> SEND_MSG -> WARN\n");
}

static void test_net_fetch_actuate_blocks(void) {
    /* Rule: NET_FETCH -> ACTUATE -> BLOCK */
    dclaw_correlator_evaluate(4, DCLAW_CAP_NET_FETCH);
    dclaw_action_t r = dclaw_correlator_evaluate(4, DCLAW_CAP_ACTUATE);
    assert(r == DCLAW_ACTION_BLOCK);
    (void)r;
    printf("  PASS: NET_FETCH -> ACTUATE -> BLOCK\n");
}

static void test_different_sessions_independent(void) {
    dclaw_correlator_evaluate(10, DCLAW_CAP_NET_FETCH);
    /* Different session — should not trigger sequence */
    dclaw_action_t r = dclaw_correlator_evaluate(11, DCLAW_CAP_EXEC_SHELL);
    assert(r == DCLAW_ACTION_ALLOW);
    (void)r;
    printf("  PASS: different sessions are independent\n");
}

static void test_non_matching_sequence_allows(void) {
    dclaw_correlator_evaluate(5, DCLAW_CAP_READ_FS);
    dclaw_action_t r = dclaw_correlator_evaluate(5, DCLAW_CAP_READ_FS);
    assert(r == DCLAW_ACTION_ALLOW);
    (void)r;
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
    (void)r;
    printf("  PASS: session eviction + reuse works\n");
}

/* Regression: actions were ranked by enum value (WARN=2, ESCALATE=3 >
 * BLOCK=1), so a co-matching WARN or ESCALATE rule downgraded a BLOCK. */
static void test_warn_rule_does_not_override_block(void) {
    /* Longer WARN rule whose suffix is the compiled NET_FETCH -> EXEC_SHELL BLOCK rule */
    add_rt_rule(DCLAW_CAP_READ_FS, DCLAW_CAP_NET_FETCH, DCLAW_CAP_EXEC_SHELL, 3,
                DCLAW_ACTION_WARN);
    dclaw_correlator_evaluate(20, DCLAW_CAP_READ_FS);
    dclaw_correlator_evaluate(20, DCLAW_CAP_NET_FETCH);
    dclaw_action_t r = dclaw_correlator_evaluate(20, DCLAW_CAP_EXEC_SHELL);
    assert(r == DCLAW_ACTION_BLOCK);
    (void)r;
    printf("  PASS: co-matching WARN rule does not downgrade BLOCK\n");
}

static void test_escalate_rule_does_not_override_block(void) {
    add_rt_rule(DCLAW_CAP_NET_FETCH, DCLAW_CAP_ACTUATE, 0, 2, DCLAW_ACTION_ESCALATE);
    dclaw_correlator_evaluate(21, DCLAW_CAP_NET_FETCH);
    dclaw_action_t r = dclaw_correlator_evaluate(21, DCLAW_CAP_ACTUATE);
    assert(r == DCLAW_ACTION_BLOCK);
    (void)r;
    printf("  PASS: co-matching ESCALATE rule does not downgrade BLOCK\n");
}

static void test_escalate_outranks_warn(void) {
    add_rt_rule(DCLAW_CAP_READ_FS, DCLAW_CAP_SEND_MSG, 0, 2, DCLAW_ACTION_ESCALATE);
    dclaw_correlator_evaluate(22, DCLAW_CAP_READ_FS);
    dclaw_action_t r = dclaw_correlator_evaluate(22, DCLAW_CAP_SEND_MSG);
    assert(r == DCLAW_ACTION_ESCALATE);
    (void)r;
    printf("  PASS: ESCALATE outranks WARN\n");
}

static void test_unknown_action_fails_closed(void) {
    /* An out-of-range action byte (e.g. from a malformed OTA bundle) must
     * be treated as BLOCK, not passed through as an unrecognised value. */
    add_rt_rule(DCLAW_CAP_SENSOR_READ, DCLAW_CAP_SEND_MSG, 0, 2, 0xC8);
    dclaw_correlator_evaluate(23, DCLAW_CAP_SENSOR_READ);
    dclaw_action_t r = dclaw_correlator_evaluate(23, DCLAW_CAP_SEND_MSG);
    assert(r == DCLAW_ACTION_BLOCK);
    (void)r;
    printf("  PASS: unknown rule action fails closed to BLOCK\n");
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
    test_warn_rule_does_not_override_block();
    test_escalate_rule_does_not_override_block();
    test_escalate_outranks_warn();
    test_unknown_action_fails_closed();
    printf("  ALL PASSED (11 tests)\n");

    dclaw_shutdown();
    return 0;
}
