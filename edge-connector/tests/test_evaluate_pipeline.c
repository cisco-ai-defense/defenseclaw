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
#include "sha256.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

extern dclaw_state_t *dclaw_get_state(void);
extern void dclaw_cache_store_with_ttl(const uint8_t *tool_hash, dclaw_action_t action,
                                       dclaw_severity_t severity, uint16_t ttl_minutes);

static dclaw_tool_request_t make_request(const char *name, uint8_t caps, const char *dest) {
    dclaw_tool_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.tool_name, name, DCLAW_TOOL_NAME_MAX - 1);
    /* Compute correct SHA-256 of the tool name to satisfy hash-to-name binding */
    dclaw_sha256((const uint8_t *)name, strlen(name), req.tool_hash);
    req.cap_flags = caps;
    req.session_id = 1;
    if (dest) strncpy(req.destination, dest, DCLAW_DESTINATION_MAX - 1);
    return req;
}

static void test_allowed_local_decision(void) {
    dclaw_tool_request_t req = make_request("read-sensor", DCLAW_CAP_SENSOR_READ, NULL);
    dclaw_verdict_t v = dclaw_evaluate(&req);
    /* No gateway is reachable in this test, so the request cannot be sent.
     * Even a speculative-capable class must not be allowed: an unsent
     * request could never be verified or revoked. */
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_CLOUD_TIMEOUT);
    printf("  PASS: sensor_read with no reachable gateway -> BLOCK, not speculative ALLOW\n");
    (void)v;
}

static void test_sync_block_cap_blocks(void) {
    dclaw_tool_request_t req = make_request("motor-control", DCLAW_CAP_ACTUATE, NULL);
    dclaw_verdict_t v = dclaw_evaluate(&req);
    /* ACTUATE is sync_block, cloud unreachable -> BLOCK with CLOUD_TIMEOUT */
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_CLOUD_TIMEOUT);
    assert(v.mode == DCLAW_VERDICT_SYNC);
    (void)v;
    printf("  PASS: actuate cap (sync_block) with no cloud -> BLOCK\n");
}

static void test_destination_deny(void) {
    /* Public literal outside the signed allowlist exercises DEST_DENY. */
    dclaw_get_state()->online = true;

    dclaw_tool_request_t req = make_request("curl", DCLAW_CAP_NET_FETCH, "9.9.9.9");
    dclaw_verdict_t v = dclaw_evaluate(&req);
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_DEST_DENY);
    (void)v;
    printf("  PASS: blocked destination -> BLOCK with DEST_DENY\n");

    dclaw_get_state()->online = false;
}

static void test_network_destination_required(void) {
    dclaw_tool_request_t missing = make_request("curl", DCLAW_CAP_NET_FETCH, NULL);
    dclaw_verdict_t verdict = dclaw_evaluate(&missing);
    assert(verdict.action == DCLAW_ACTION_BLOCK);
    assert(verdict.reason == DCLAW_REASON_DEST_DENY);

    dclaw_tool_request_t hostname = make_request("curl", DCLAW_CAP_NET_FETCH,
                                                "http://localhost.localdomain/");
    verdict = dclaw_evaluate(&hostname);
    assert(verdict.action == DCLAW_ACTION_BLOCK);
    assert(verdict.reason == DCLAW_REASON_SSRF_BLOCK);

    dclaw_tool_request_t private_ip = make_request("curl", DCLAW_CAP_NET_FETCH,
                                                  "169.254.169.254");
    verdict = dclaw_evaluate(&private_ip);
    assert(verdict.action == DCLAW_ACTION_BLOCK);
    assert(verdict.reason == DCLAW_REASON_SSRF_BLOCK);
    printf("  PASS: missing, hostname, and private network targets block in all profiles\n");
}

static void test_unknown_tool_cannot_use_cloud_allow(void) {
    dclaw_tool_request_t unknown = make_request("custom_network_tool", DCLAW_CAP_NET_FETCH,
                                               "http://127.0.0.1/");
    /* Simulate a previous cloud ALLOW for the same hash. Unknown names must
     * stop before the verdict cache or the cloud dispatch path. */
    dclaw_cache_store_with_ttl(unknown.tool_hash, DCLAW_ACTION_ALLOW,
                               DCLAW_SEV_INFO, 60);
    dclaw_verdict_t verdict = dclaw_evaluate(&unknown);
    assert(verdict.action == DCLAW_ACTION_BLOCK);
    assert(verdict.reason == DCLAW_REASON_INVALID_INPUT);
    printf("  PASS: unknown network tool blocks before cached/cloud ALLOW\n");
}

static void test_allowed_destination(void) {
    /* A public literal in the signed allowlist reaches the later decision. */
    dclaw_get_state()->online = true;

    dclaw_tool_request_t req = make_request("api-call", DCLAW_CAP_NET_FETCH, "8.8.8.8");
    dclaw_verdict_t v = dclaw_evaluate(&req);
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_CLOUD_TIMEOUT);
    printf("  PASS: allowed destination + no reachable gateway -> BLOCK\n");
    (void)v;

    dclaw_get_state()->online = false;
}

static void test_capability_sequence_block(void) {
    /* Sequence tracking still records an allowed public network destination. */
    dclaw_get_state()->online = true;

    /* First: NET_FETCH */
    dclaw_tool_request_t req1 = make_request("download", DCLAW_CAP_NET_FETCH, "8.8.8.8");
    req1.session_id = 50;
    dclaw_evaluate(&req1);

    /* Second: EXEC_SHELL in same session -> should trigger sequence rule */
    dclaw_tool_request_t req2 = make_request("bash", DCLAW_CAP_EXEC_SHELL, NULL);
    req2.session_id = 50;
    dclaw_verdict_t v = dclaw_evaluate(&req2);
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_CAP_SEQUENCE);
    (void)v;
    printf("  PASS: NET_FETCH -> EXEC_SHELL sequence -> BLOCK\n");

    dclaw_get_state()->online = false;
}

static void test_truncated_content_keeps_local_guards(void) {
    dclaw_tool_request_t private_ip = make_request("curl", DCLAW_CAP_NET_FETCH,
                                                   "169.254.169.254");
    private_ip.flags = DCLAW_FLAG_CONTENT_TRUNCATED;
    private_ip.content = "benign prefix";
    private_ip.content_len = (uint16_t)strlen(private_ip.content);
    dclaw_verdict_t verdict = dclaw_evaluate(&private_ip);
    assert(verdict.action == DCLAW_ACTION_BLOCK);
    assert(verdict.reason == DCLAW_REASON_SSRF_BLOCK);

    dclaw_tool_request_t denied = make_request("curl", DCLAW_CAP_NET_FETCH, "9.9.9.9");
    denied.flags = DCLAW_FLAG_CONTENT_TRUNCATED;
    denied.content = "benign prefix";
    denied.content_len = (uint16_t)strlen(denied.content);
    verdict = dclaw_evaluate(&denied);
    assert(verdict.action == DCLAW_ACTION_BLOCK);
    assert(verdict.reason == DCLAW_REASON_DEST_DENY);

    dclaw_tool_request_t network = make_request("download", DCLAW_CAP_NET_FETCH, "8.8.8.8");
    network.session_id = 510;
    (void)dclaw_evaluate(&network);
    dclaw_tool_request_t shell = make_request("bash", DCLAW_CAP_EXEC_SHELL, NULL);
    shell.session_id = 510;
    shell.flags = DCLAW_FLAG_CONTENT_TRUNCATED;
    shell.content = "benign prefix";
    shell.content_len = (uint16_t)strlen(shell.content);
    verdict = dclaw_evaluate(&shell);
    assert(verdict.action == DCLAW_ACTION_BLOCK);
    assert(verdict.reason == DCLAW_REASON_CAP_SEQUENCE);

    dclaw_tool_request_t plain = make_request("read_file", DCLAW_CAP_READ_FS, NULL);
    plain.flags = DCLAW_FLAG_CONTENT_TRUNCATED;
    plain.content = "benign prefix";
    plain.content_len = (uint16_t)strlen(plain.content);
    verdict = dclaw_evaluate(&plain);
    assert(verdict.action == DCLAW_ACTION_BLOCK);
    assert(verdict.reason == DCLAW_REASON_CONTENT_BLOCK);
    assert(verdict.mode == DCLAW_VERDICT_SYNC);
    printf("  PASS: truncated content retains SSRF, destination, sequence, and fail-closed guards\n");
}

static void test_rate_limit_triggers(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->rate_limiters[0].tokens = 0; /* exhaust global tokens */

    dclaw_tool_request_t req = make_request("read_file", DCLAW_CAP_READ_FS, NULL);
    dclaw_verdict_t v = dclaw_evaluate(&req);
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_RATE_LIMIT);
    (void)v;
    printf("  PASS: rate limit exhaustion -> BLOCK\n");

    s->rate_limiters[0].tokens = 60;
}

static void test_invalid_input_blocks(void) {
    dclaw_tool_request_t req = make_request("test", DCLAW_CAP_READ_FS, NULL);
    req.cap_flags = 0x80; /* invalid bit */
    dclaw_verdict_t v = dclaw_evaluate(&req);
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_INVALID_INPUT);
    (void)v;
    printf("  PASS: invalid cap_flags -> BLOCK with INVALID_INPUT\n");
}

#if DCLAW_CONTENT_SCAN
static void test_content_scan_blocks_secret_in_pipeline(void) {
    dclaw_tool_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.tool_name, "read_data", DCLAW_TOOL_NAME_MAX);
    dclaw_sha256((const uint8_t *)"read_data", strlen("read_data"), req.tool_hash);
    req.cap_flags = DCLAW_CAP_READ_FS;
    req.session_id = 99;
    req.content = "api_key = sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";
    req.content_len = (uint16_t)strlen(req.content);

    dclaw_verdict_t v = dclaw_evaluate(&req);
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_CONTENT_BLOCK);
    (void)v;
    printf("  PASS: content scan blocks secret in pipeline\n");
}

static void reset_limits(void) {
    extern void dclaw_ipc_rate_limit_reset(void);
    dclaw_state_t *s = dclaw_get_state();
    for (int i = 0; i < DCLAW_RATE_LIMITERS; i++)
        s->rate_limiters[i].tokens = s->rate_limiters[i].bucket_size;
    dclaw_ipc_rate_limit_reset();
}

static void set_severity_rule(uint8_t severity, uint8_t action) {
    dclaw_policy_table_t *rt = &dclaw_get_state()->rt_policy;
    for (size_t i = 0; i < rt->severity_rules_count; i++) {
        if (rt->severity_rules[i].severity == severity) {
            rt->severity_rules[i].action = action;
            return;
        }
    }
    assert(rt->severity_rules_count < DCLAW_RT_MAX_SEVERITY_RULES);
    rt->severity_rules[rt->severity_rules_count].severity = severity;
    rt->severity_rules[rt->severity_rules_count].action = action;
    rt->severity_rules_count++;
}

/* Severity rules can tighten the content-scope threshold but never loosen it. */
static void test_severity_rules_only_tighten(void) {
    dclaw_policy_table_t *rt = &dclaw_get_state()->rt_policy;
    size_t saved_count = rt->severity_rules_count;
    uint8_t saved[DCLAW_RT_MAX_SEVERITY_RULES][2];
    for (size_t i = 0; i < saved_count; i++) {
        saved[i][0] = rt->severity_rules[i].severity;
        saved[i][1] = rt->severity_rules[i].action;
    }

    /* An email address is a MEDIUM finding: TOOL_OUTPUT only warns. */
    dclaw_tool_request_t req = make_request("read_data", DCLAW_CAP_READ_FS, NULL);
    req.session_id = 120;
    req.content = "contact: alice@example.com";
    req.content_len = (uint16_t)strlen(req.content);
    req.content_scope = DCLAW_CONTENT_SCOPE_TOOL_OUTPUT;
    reset_limits();
    dclaw_verdict_t v = dclaw_evaluate(&req);
    assert(v.reason != DCLAW_REASON_CONTENT_BLOCK);

    set_severity_rule(DCLAW_SEV_MEDIUM, DCLAW_ACTION_BLOCK);
    reset_limits();
    v = dclaw_evaluate(&req);
    assert(v.action == DCLAW_ACTION_BLOCK && v.reason == DCLAW_REASON_CONTENT_BLOCK);

    /* Unknown action byte fails closed. */
    set_severity_rule(DCLAW_SEV_MEDIUM, 0xC8);
    reset_limits();
    v = dclaw_evaluate(&req);
    assert(v.action == DCLAW_ACTION_BLOCK && v.reason == DCLAW_REASON_CONTENT_BLOCK);

    /* Rules that try to allow MEDIUM/HIGH cannot lower the USER_INPUT
     * threshold, which blocks MEDIUM findings. */
    set_severity_rule(DCLAW_SEV_MEDIUM, DCLAW_ACTION_ALLOW);
    set_severity_rule(DCLAW_SEV_HIGH, DCLAW_ACTION_ALLOW);
    req.content_scope = DCLAW_CONTENT_SCOPE_USER_INPUT;
    reset_limits();
    v = dclaw_evaluate(&req);
    assert(v.action == DCLAW_ACTION_BLOCK && v.reason == DCLAW_REASON_CONTENT_BLOCK);
    (void)v;

    rt->severity_rules_count = saved_count;
    for (size_t i = 0; i < saved_count; i++) {
        rt->severity_rules[i].severity = saved[i][0];
        rt->severity_rules[i].action = saved[i][1];
    }
    printf("  PASS: severity rules tighten but never loosen content thresholds\n");
}

static void test_no_content_field_backward_compat(void) {
    dclaw_tool_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.tool_name, "read_sensor", DCLAW_TOOL_NAME_MAX);
    dclaw_sha256((const uint8_t *)"read_sensor", strlen("read_sensor"), req.tool_hash);
    req.cap_flags = DCLAW_CAP_SENSOR_READ;
    req.session_id = 101;

    dclaw_verdict_t v = dclaw_evaluate(&req);
    assert(v.reason != DCLAW_REASON_CONTENT_BLOCK);
    (void)v;
    printf("  PASS: no content field = backward compatible (no content block)\n");
}
#endif

static void test_hash_mismatch_blocks(void) {
    /* Submit exec_shell's name but with sensor_read's hash — should be blocked
     * by the hash-to-name binding check before capability lookup. */
    dclaw_tool_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.tool_name, "exec_shell", DCLAW_TOOL_NAME_MAX);
    /* Use a different tool's hash to simulate the attack */
    dclaw_sha256((const uint8_t *)"sensor_read", strlen("sensor_read"), req.tool_hash);
    req.cap_flags = DCLAW_CAP_SENSOR_READ; /* attacker tries benign cap */
    req.session_id = 200;

    dclaw_verdict_t v = dclaw_evaluate(&req);
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_HASH_MISMATCH);
    (void)v;
    printf("  PASS: hash-name mismatch -> BLOCK with HASH_MISMATCH\n");
}


#if DCLAW_VERDICT_CACHE_SIZE > 0
static void refill_limits(void) {
    extern void dclaw_ipc_rate_limit_reset(void);
    dclaw_state_t *s = dclaw_get_state();
    for (int i = 0; i < DCLAW_RATE_LIMITERS; i++)
        s->rate_limiters[i].tokens = s->rate_limiters[i].bucket_size;
    dclaw_ipc_rate_limit_reset();
}

/* Regression: a cached gateway ALLOW for an actuation, shell or file-write
 * tool was returned for 60 minutes without the synchronous hold. */
static void test_cached_allow_not_used_for_physical_classes(void) {
    static const char *const physical[] = { "gpio_write", "exec_shell", "write_file" };
    for (size_t i = 0; i < sizeof(physical) / sizeof(physical[0]); i++) {
        refill_limits();
        dclaw_tool_request_t req = make_request(physical[i], 0, NULL);
        req.session_id = (uint16_t)(60 + i);
        dclaw_cache_store_with_ttl(req.tool_hash, DCLAW_ACTION_ALLOW, DCLAW_SEV_INFO, 60);
        dclaw_verdict_t v = dclaw_evaluate(&req);
        assert(!v.from_cache);
        assert(v.action == DCLAW_ACTION_BLOCK);
        assert(v.reason == DCLAW_REASON_CLOUD_TIMEOUT); /* escalated; no gateway here */
        /* A cached BLOCK still applies. */
        dclaw_cache_store_with_ttl(req.tool_hash, DCLAW_ACTION_BLOCK, DCLAW_SEV_INFO, 60);
        v = dclaw_evaluate(&req);
        assert(v.action == DCLAW_ACTION_BLOCK && v.from_cache);
        (void)v;
    }
    printf("  PASS: physical classes are escalated despite a cached ALLOW\n");
}

/* Regression: a WARN from a local sequence rule was dropped when the tool
 * had a cached ALLOW. */
static void test_cached_allow_keeps_local_warn(void) {
    refill_limits();
    dclaw_tool_request_t first = make_request("sensor_read", 0, NULL);
    first.session_id = 70;
    (void)dclaw_evaluate(&first);
    refill_limits();
    dclaw_tool_request_t net = make_request("api-call", 0, "8.8.8.8"); /* SENSOR_READ -> NET_FETCH: warn */
    net.session_id = 70;
    dclaw_cache_store_with_ttl(net.tool_hash, DCLAW_ACTION_ALLOW, DCLAW_SEV_INFO, 60);
    dclaw_verdict_t v = dclaw_evaluate(&net);
    assert(v.from_cache);
    assert(v.action == DCLAW_ACTION_WARN);
    /* Without the rule match the cached ALLOW is returned as is. */
    refill_limits();
    net.session_id = 71;
    v = dclaw_evaluate(&net);
    assert(v.from_cache && v.action == DCLAW_ACTION_ALLOW);
    (void)v;
    printf("  PASS: local WARN is kept over a cached ALLOW\n");
}

/* Regression: an ESCALATE from a local rule was dropped when the tool had a
 * cached ALLOW; it must reach the gateway. */
static void test_local_escalate_bypasses_cached_allow(void) {
    dclaw_policy_table_t *rt = &dclaw_get_state()->rt_policy;
    size_t saved = rt->sequence_rules_count;
    assert(saved < DCLAW_RT_MAX_SEQUENCE_RULES);
    memset(&rt->sequence_rules[saved], 0, sizeof(rt->sequence_rules[saved]));
    rt->sequence_rules[saved].seq[0] = DCLAW_CAP_READ_FS;
    rt->sequence_rules[saved].seq[1] = DCLAW_CAP_SENSOR_READ;
    rt->sequence_rules[saved].seq_len = 2;
    rt->sequence_rules[saved].action = DCLAW_ACTION_ESCALATE;
    rt->sequence_rules_count = saved + 1;

    refill_limits();
    dclaw_tool_request_t rd = make_request("read_file", 0, NULL);
    rd.session_id = 72;
    (void)dclaw_evaluate(&rd);
    refill_limits();
    dclaw_tool_request_t sr = make_request("get_state", 0, NULL);
    sr.session_id = 72;
    dclaw_cache_store_with_ttl(sr.tool_hash, DCLAW_ACTION_ALLOW, DCLAW_SEV_INFO, 60);
    dclaw_verdict_t v = dclaw_evaluate(&sr);
    assert(!v.from_cache);
    assert(v.action == DCLAW_ACTION_BLOCK && v.reason == DCLAW_REASON_CLOUD_TIMEOUT);
    (void)v;
    rt->sequence_rules_count = saved;
    printf("  PASS: local ESCALATE is escalated despite a cached ALLOW\n");
}

#if DCLAW_CONTENT_SCAN
/* A content WARN (MEDIUM finding in tool output) is kept over a cached ALLOW. */
static void test_cached_allow_keeps_content_warn(void) {
    refill_limits();
    dclaw_tool_request_t req = make_request("get_temperature", 0, NULL);
    req.session_id = 73;
    req.content = "contact ops@example.com";
    req.content_len = (uint16_t)strlen(req.content);
    req.content_scope = DCLAW_CONTENT_SCOPE_TOOL_OUTPUT;
    dclaw_cache_store_with_ttl(req.tool_hash, DCLAW_ACTION_ALLOW, DCLAW_SEV_INFO, 60);
    dclaw_verdict_t v = dclaw_evaluate(&req);
    assert(v.from_cache && v.action == DCLAW_ACTION_WARN);
    (void)v;
    printf("  PASS: content WARN is kept over a cached ALLOW\n");
}
#endif
#endif /* DCLAW_VERDICT_CACHE_SIZE > 0 */

int main(void) {
    hal_init();
    dclaw_device_info_t info = {.device_id = 42, .tenant_id = 1, .fleet_id = 1};
    dclaw_init(&info);

    printf("test_evaluate_pipeline:\n");
    test_allowed_local_decision();
    test_sync_block_cap_blocks();
    test_destination_deny();
    test_network_destination_required();
    test_unknown_tool_cannot_use_cloud_allow();
    test_allowed_destination();
    test_capability_sequence_block();
    test_truncated_content_keeps_local_guards();
    test_rate_limit_triggers();
    test_invalid_input_blocks();
#if DCLAW_CONTENT_SCAN
    test_content_scan_blocks_secret_in_pipeline();
    test_no_content_field_backward_compat();
    test_severity_rules_only_tighten();
#endif
    test_hash_mismatch_blocks();
#if DCLAW_VERDICT_CACHE_SIZE > 0
    test_cached_allow_not_used_for_physical_classes();
    test_cached_allow_keeps_local_warn();
    test_local_escalate_bypasses_cached_allow();
#if DCLAW_CONTENT_SCAN
    test_cached_allow_keeps_content_warn();
#endif
#endif
    printf("  ALL PASSED\n");

    dclaw_shutdown();
    return 0;
}
