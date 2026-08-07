#include "defenseclaw.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

extern dclaw_action_t dclaw_policy_check_hash(const uint8_t *tool_hash);
extern dclaw_action_t dclaw_policy_check_destination(const char *host);
extern dclaw_action_t dclaw_policy_check_severity(dclaw_severity_t sev);

static void test_hash_miss_allows(void) {
    uint8_t hash[32];
    memset(hash, 0xDE, 32);
    assert(dclaw_policy_check_hash(hash) == DCLAW_ACTION_ALLOW);
    printf("  PASS: unknown hash returns ALLOW\n");
}

static void test_dest_exact_match(void) {
    assert(dclaw_policy_check_destination("api.openai.com") == DCLAW_ACTION_ALLOW);
    printf("  PASS: exact destination match returns ALLOW\n");
}

static void test_dest_wildcard_match(void) {
    assert(dclaw_policy_check_destination("tools.cisco.com") == DCLAW_ACTION_ALLOW);
    printf("  PASS: wildcard *.cisco.com matches subdomains\n");
}

static void test_dest_not_in_list_blocks(void) {
    assert(dclaw_policy_check_destination("evil-attacker.net") == DCLAW_ACTION_BLOCK);
    printf("  PASS: destination not in allowlist returns BLOCK\n");
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
    test_dest_wildcard_match();
    test_dest_not_in_list_blocks();
    test_severity_critical_blocks();
    test_severity_medium_warns();
    test_severity_low_allows();
    printf("  ALL PASSED (7 tests)\n");

    dclaw_shutdown();
    return 0;
}
