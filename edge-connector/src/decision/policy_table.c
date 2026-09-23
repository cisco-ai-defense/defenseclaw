#include "defenseclaw.h"
#include "platform.h"
#include <string.h>

/* Policy tables are compiled into generated/policy_tables.h by the policy compiler.
 * For Phase 1 bootstrap, we use a minimal default policy. */

#include "policy_tables.h"

static int compare_hash(const uint8_t *a, const uint8_t *b) {
    return memcmp(a, b, 32);
}

dclaw_action_t dclaw_policy_check_hash(const uint8_t *tool_hash) {
    /* Binary search over sorted deny_hashes table */
    int lo = 0, hi = (int)deny_hashes_count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int cmp = compare_hash(tool_hash, deny_hashes[mid]);
        if (cmp == 0) return DCLAW_ACTION_BLOCK;
        if (cmp < 0) hi = mid - 1;
        else lo = mid + 1;
    }
    return DCLAW_ACTION_ALLOW;
}

dclaw_action_t dclaw_policy_check_destination(const char *host) {
    /* Linear scan over destination allowlist (small, ≤256 entries) */
    for (size_t i = 0; i < dest_allowlist_count; i++) {
        if (strcmp(host, dest_allowlist[i]) == 0) {
            return DCLAW_ACTION_ALLOW;
        }
        /* Wildcard prefix match: *.example.com */
        if (dest_allowlist[i][0] == '*' && dest_allowlist[i][1] == '.') {
            const char *suffix = &dest_allowlist[i][1];
            size_t suffix_len = strlen(suffix);
            size_t host_len = strlen(host);
            if (host_len >= suffix_len &&
                strcmp(host + host_len - suffix_len, suffix) == 0) {
                return DCLAW_ACTION_ALLOW;
            }
        }
    }
    return DCLAW_ACTION_BLOCK;
}

dclaw_action_t dclaw_policy_check_severity(dclaw_severity_t sev) {
    for (size_t i = 0; i < severity_rules_count; i++) {
        if (severity_rules[i].severity == (uint8_t)sev) {
            return (dclaw_action_t)severity_rules[i].action;
        }
    }
    return DCLAW_ACTION_ALLOW;
}
