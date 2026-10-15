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

extern dclaw_action_t dclaw_policy_check_hash(const uint8_t *tool_hash);
extern dclaw_action_t dclaw_policy_check_destination(const char *host);
extern dclaw_action_t dclaw_policy_check_severity(dclaw_severity_t sev);
extern uint8_t dclaw_policy_lookup_capability(const char *tool_name);

static void test_hash_miss_allows(void) {
    uint8_t hash[32];
    memset(hash, 0xDE, 32);
    assert(dclaw_policy_check_hash(hash) == DCLAW_ACTION_ALLOW);
    printf("  PASS: unknown hash returns ALLOW\n");
}

static void test_dest_exact_match(void) {
    assert(dclaw_policy_check_destination("8.8.8.8") == DCLAW_ACTION_ALLOW);
    printf("  PASS: exact destination match returns ALLOW\n");
}

static void test_dest_url_match(void) {
    assert(dclaw_policy_check_destination("https://1.1.1.1:443/path") == DCLAW_ACTION_ALLOW);
    printf("  PASS: public IP in URL matches allowlist\n");
}

static void test_dest_not_in_list_blocks(void) {
    assert(dclaw_policy_check_destination("evil-attacker.net") == DCLAW_ACTION_BLOCK);
    printf("  PASS: destination not in allowlist returns BLOCK\n");
}

static void test_tool_capability_mapping(void) {
    assert(dclaw_policy_lookup_capability("web_search") == DCLAW_CAP_NET_FETCH);
    assert(dclaw_policy_lookup_capability("read_file") == DCLAW_CAP_READ_FS);
    assert(dclaw_policy_lookup_capability("custom_network_tool") == DCLAW_CAP_UNKNOWN);
    printf("  PASS: known tools keep mappings, unknown tool has no capability\n");
}

static void test_severity_critical_blocks(void) {
    assert(dclaw_policy_check_severity(DCLAW_SEV_CRITICAL) == DCLAW_ACTION_BLOCK);
    printf("  PASS: CRITICAL severity -> BLOCK\n");
}

static void test_severity_medium_warns(void) {
    assert(dclaw_policy_check_severity(DCLAW_SEV_MEDIUM) == DCLAW_ACTION_WARN);
    printf("  PASS: MEDIUM severity -> WARN\n");
}

static void test_severity_low_allows(void) {
    assert(dclaw_policy_check_severity(DCLAW_SEV_LOW) == DCLAW_ACTION_ALLOW);
    printf("  PASS: LOW severity -> ALLOW\n");
}

int main(void) {
    hal_init();
    dclaw_device_info_t info = {.device_id = 1};
    dclaw_init(&info);

    printf("test_policy_table:\n");
    test_hash_miss_allows();
    test_dest_exact_match();
    test_dest_url_match();
    test_dest_not_in_list_blocks();
    test_tool_capability_mapping();
    test_severity_critical_blocks();
    test_severity_medium_warns();
    test_severity_low_allows();
    printf("  ALL PASSED (8 tests)\n");

    dclaw_shutdown();
    return 0;
}
