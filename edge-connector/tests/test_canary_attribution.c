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

/* The canary must roll back a policy that causes many distinct denials, but
 * must not be triggerable by junk requests or by one call repeated. */

#include "defenseclaw.h"
#include "platform.h"
#include "sha256.h"
#include "hmac_sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

extern dclaw_state_t *dclaw_get_state(void);
extern int dclaw_apply_policy(const uint8_t *blob, uint32_t len, const uint8_t *sig);
extern void dclaw_canary_tick_at(uint64_t now_ms);
extern void dclaw_ipc_rate_limit_reset(void);

static const char *OTA_KEY_HEX =
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

/* Apply a signed policy whose destination allowlist is empty, so every
 * network call with a public destination is a policy (DEST_DENY) denial. */
static void apply_policy_sections(uint16_t version, uint16_t baseline, uint8_t sections);
static void apply_policy(uint16_t version, uint16_t baseline) {
    apply_policy_sections(version, baseline, 0x87);
}

/* sections: 0x80 marker | 0x01 severity | 0x02 sequence | 0x04 destination allowlist.
 * An omitted section keeps the device's current table. */
static void apply_policy_sections(uint16_t version, uint16_t baseline, uint8_t sections) {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);
    uint8_t blob[64] = {0};
    blob[0] = (uint8_t)(version >> 8); blob[1] = (uint8_t)version;
    blob[3] = 56;
    blob[4] = (uint8_t)(baseline >> 8); blob[5] = (uint8_t)baseline;
    blob[8] = sections;
    uint8_t sig[64] = {0};
    dclaw_hmac_sha256(key, 32, blob, sizeof(blob), sig);
    assert(dclaw_apply_policy(blob, sizeof(blob), sig) == 0);
    assert(dclaw_get_state()->canary.canary_active);
}

static dclaw_tool_request_t make_request(const char *name, const char *dest, uint16_t session) {
    dclaw_tool_request_t r;
    memset(&r, 0, sizeof(r));
    strncpy(r.tool_name, name, DCLAW_TOOL_NAME_MAX - 1);
    dclaw_sha256((const uint8_t *)name, strlen(name), r.tool_hash);
    r.session_id = session;
    if (dest) strncpy(r.destination, dest, DCLAW_DESTINATION_MAX - 1);
    return r;
}

static void evaluate_n(dclaw_tool_request_t *r, int n) {
    dclaw_state_t *s = dclaw_get_state();
    for (int i = 0; i < n; i++) {
        for (int k = 0; k < DCLAW_RATE_LIMITERS; k++)
            s->rate_limiters[k].tokens = s->rate_limiters[k].bucket_size;
        dclaw_ipc_rate_limit_reset();
        (void)dclaw_evaluate(r);
    }
}

/* Run `minutes` canary minutes, calling `per_minute` once per minute. */
static void run_minutes(int minutes, void (*per_minute)(void)) {
    dclaw_state_t *s = dclaw_get_state();
    uint64_t t0 = s->canary.canary_started_at;
    for (int m = 0; m < minutes && s->canary.canary_active; m++) {
        per_minute();
        dclaw_canary_tick_at(t0 + (uint64_t)(m + 1) * 60000 + 1);
    }
}

static void junk_minute(void) {
    dclaw_tool_request_t r = make_request("not_a_real_tool", NULL, 1);
    evaluate_n(&r, 30);
    dclaw_tool_request_t bad = make_request("sensor_read", NULL, 1);
    dclaw_sha256((const uint8_t *)"bash", 4, bad.tool_hash); /* hash mismatch */
    evaluate_n(&bad, 30);
}

static void repeat_minute(void) {
    dclaw_tool_request_t r = make_request("web_fetch", "9.9.9.9", 2);
    evaluate_n(&r, 30);
}

static const char *NET_TOOLS[] = {
    "net_fetch", "net-fetch", "web_search", "web_fetch", "fetch", "http_request",
    "http-request", "curl", "fetch_url", "fetch-url",
};

static void distinct_minute(void) {
    for (size_t i = 0; i < sizeof(NET_TOOLS) / sizeof(NET_TOOLS[0]); i++) {
        dclaw_tool_request_t r = make_request(NET_TOOLS[i], "9.9.9.9", 3);
        evaluate_n(&r, 1);
    }
}

static void test_junk_does_not_roll_back(void) {
    dclaw_state_t *s = dclaw_get_state();
    apply_policy(1, 1); /* threshold: > 5 counted denials per minute */
    run_minutes(4, junk_minute);
    assert(s->canary.canary_active);
    assert(s->device.policy_version == 1);
    printf("  PASS: unknown-tool and hash-mismatch floods do not trigger rollback\n");
}

static void test_repeated_denial_counts_once(void) {
    dclaw_state_t *s = dclaw_get_state();
    apply_policy(2, 1);
    run_minutes(4, repeat_minute);
    assert(s->canary.canary_active);
    assert(s->canary.canary_blocks[0] == 1);
    printf("  PASS: one policy denial repeated 30x/min counts once per minute\n");
}

static void test_distinct_policy_denials_roll_back(void) {
    dclaw_state_t *s = dclaw_get_state();
    apply_policy(3, 1);
    run_minutes(4, distinct_minute);
    assert(!s->canary.canary_active);
    printf("  PASS: many distinct policy denials still trigger rollback\n");
}

extern void dclaw_policy_rollback(void);
extern void dclaw_policy_tables_init(void);

static const char *SHELL_TOOLS[] = {
    "bash", "exec", "run_command", "terminal", "execute_code", "run_python",
    "exec-shell", "run-command", "shell", "run_script",
};

/* Each minute: 10 distinct shell tools, each after an allowlisted fetch, all
 * denied by the compiled-in NET_FETCH -> EXEC_SHELL rule, which no push can
 * change. */
static void compiled_rule_minute(void) {
    static uint16_t session = 600;
    for (size_t i = 0; i < sizeof(SHELL_TOOLS) / sizeof(SHELL_TOOLS[0]); i++) {
        dclaw_tool_request_t fetch = make_request("api-call", "8.8.8.8", session);
        dclaw_tool_request_t sh = make_request(SHELL_TOOLS[i], NULL, session);
        evaluate_n(&fetch, 1);
        evaluate_n(&sh, 1);
        session++;
    }
}

/* Regression: compiled-in sequence rules were counted as policy denials. */
static void test_compiled_sequence_rules_do_not_count(void) {
    dclaw_state_t *s = dclaw_get_state();
    dclaw_policy_tables_init(); /* earlier tests left an empty allowlist live */
    apply_policy_sections(4, 1, 0x83); /* keeps the compiled destination allowlist */
    run_minutes(4, compiled_rule_minute);
    assert(s->canary.canary_active);
    assert(s->canary.canary_blocks[0] == 0);
    printf("  PASS: compiled-in sequence denials do not trigger rollback\n");
}

/* Regression: rollback re-read the previous partition on top of the
 * rejected tables, so a section the previous policy omitted stayed rejected. */
static void test_rollback_restores_omitted_section(void) {
    dclaw_state_t *s = dclaw_get_state();
    dclaw_policy_tables_init();
    apply_policy_sections(5, 1, 0x83); /* v5: no allowlist section -> compiled list */
    size_t before = s->rt_policy.dest_allowlist_count;
    assert(before > 0);
    apply_policy_sections(6, 1, 0x87); /* v6: empty allowlist (deny all) */
    assert(s->rt_policy.dest_allowlist_count == 0);
    dclaw_policy_rollback();
    assert(s->rt_policy.dest_allowlist_count == before);
    printf("  PASS: rollback restores a section the previous policy omitted\n");
}

int main(void) {
    /* Start from an empty flash file this test owns. */
    const char *tmp = getenv("TMPDIR");
    char flash_dir[512], flash_path[600];
    snprintf(flash_dir, sizeof(flash_dir), "%s/dclaw-canary-XXXXXX",
             (tmp && *tmp) ? tmp : "/tmp");
    assert(mkdtemp(flash_dir) != NULL);
    snprintf(flash_path, sizeof(flash_path), "%s/flash.bin", flash_dir);
    setenv("DCLAW_FLASH_PATH", flash_path, 1);
    setenv("DCLAW_OTA_HMAC_KEY", OTA_KEY_HEX, 1);
    hal_init();
    dclaw_device_info_t info = {.device_id = 42, .tenant_id = 1, .fleet_id = 1};
    dclaw_init(&info);
    dclaw_get_state()->device.policy_version = 0;

    printf("test_canary_attribution:\n");
    test_junk_does_not_roll_back();
    test_repeated_denial_counts_once();
    test_distinct_policy_denials_roll_back();
    test_compiled_sequence_rules_do_not_count();
    test_rollback_restores_omitted_section();
    printf("  ALL PASSED (5 tests)\n");

    dclaw_shutdown();
    unlink(flash_path);
    rmdir(flash_dir);
    return 0;
}
