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
extern void dclaw_cache_store(const uint8_t *tool_hash, dclaw_action_t action,
                              dclaw_severity_t severity);

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
    /* BLK-1: In production builds (DEV_MODE=OFF), strict mode is default,
     * so even speculative-capable profiles return BLOCK (sync). In dev builds,
     * speculative exec returns PENDING. Both are correct behavior. */
#if DCLAW_SPECULATIVE_EXECUTION && DCLAW_DEV_MODE
    assert(v.mode == DCLAW_VERDICT_PENDING);
    printf("  PASS: sensor_read with no local rule -> PENDING (speculative, dev)\n");
#else
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_CLOUD_TIMEOUT);
    printf("  PASS: sensor_read with no cloud -> BLOCK (strict/no-spec)\n");
#endif
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
    dclaw_cache_store(unknown.tool_hash, DCLAW_ACTION_ALLOW, DCLAW_SEV_INFO);
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
#if DCLAW_SPECULATIVE_EXECUTION && DCLAW_DEV_MODE
    assert(v.mode == DCLAW_VERDICT_PENDING);
    printf("  PASS: allowed destination + speculative cap -> PENDING (dev)\n");
#else
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_CLOUD_TIMEOUT);
    printf("  PASS: allowed destination + no cloud -> BLOCK (strict/no-spec)\n");
#endif
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
    test_rate_limit_triggers();
    test_invalid_input_blocks();
#if DCLAW_CONTENT_SCAN
    test_content_scan_blocks_secret_in_pipeline();
    test_no_content_field_backward_compat();
#endif
    test_hash_mismatch_blocks();
#if DCLAW_CONTENT_SCAN
    printf("  ALL PASSED (12 tests)\n");
#else
    printf("  ALL PASSED (10 tests)\n");
#endif

    dclaw_shutdown();
    return 0;
}
