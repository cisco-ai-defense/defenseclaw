#include "defenseclaw.h"
#include "platform.h"
#include <string.h>

/* Policy tables are compiled into generated/policy_tables.h by the policy compiler.
 * For Phase 1 bootstrap, we use a minimal default policy. */

#include "policy_tables.h"

/* === Trusted tool-name-to-capability mapping (Comment 18 fix) ===
 *
 * The caller-provided cap_flags in the IPC request cannot be trusted.
 * This table maps known tool names to their correct capability flags.
 * Unknown tools default to CAP_EXEC_SHELL (fail-closed).
 */
typedef struct {
    const char *tool_name;
    uint8_t     cap_flags;
} dclaw_tool_cap_entry_t;

static const dclaw_tool_cap_entry_t tool_cap_map[] = {
    /* File system */
    { "read_file",      DCLAW_CAP_READ_FS },
    { "read-file",      DCLAW_CAP_READ_FS },
    { "read_data",      DCLAW_CAP_READ_FS },
    { "write_file",     DCLAW_CAP_WRITE_FS },
    { "write-file",     DCLAW_CAP_WRITE_FS },

    /* Shell execution */
    { "exec_shell",     DCLAW_CAP_EXEC_SHELL },
    { "exec-shell",     DCLAW_CAP_EXEC_SHELL },
    { "run_command",    DCLAW_CAP_EXEC_SHELL },
    { "run-command",    DCLAW_CAP_EXEC_SHELL },
    { "bash",           DCLAW_CAP_EXEC_SHELL },
    { "shell",          DCLAW_CAP_EXEC_SHELL },

    /* Network */
    { "net_fetch",      DCLAW_CAP_NET_FETCH },
    { "net-fetch",      DCLAW_CAP_NET_FETCH },
    { "http_request",   DCLAW_CAP_NET_FETCH },
    { "http-request",   DCLAW_CAP_NET_FETCH },
    { "curl",           DCLAW_CAP_NET_FETCH },
    { "fetch_url",      DCLAW_CAP_NET_FETCH },
    { "fetch-url",      DCLAW_CAP_NET_FETCH },
    { "download",       DCLAW_CAP_NET_FETCH },
    { "api_call",       DCLAW_CAP_NET_FETCH },
    { "api-call",       DCLAW_CAP_NET_FETCH },

    /* Messaging */
    { "send_message",   DCLAW_CAP_SEND_MSG },
    { "send-message",   DCLAW_CAP_SEND_MSG },

    /* Actuation */
    { "actuate",        DCLAW_CAP_ACTUATE },
    { "motor_control",  DCLAW_CAP_ACTUATE },
    { "motor-control",  DCLAW_CAP_ACTUATE },
    { "dangerous",      DCLAW_CAP_ACTUATE },

    /* Sensor */
    { "sensor_read",    DCLAW_CAP_SENSOR_READ },
    { "sensor-read",    DCLAW_CAP_SENSOR_READ },
    { "read_sensor",    DCLAW_CAP_SENSOR_READ },
    { "read-sensor",    DCLAW_CAP_SENSOR_READ },
    { "sensor",         DCLAW_CAP_SENSOR_READ },
};
static const size_t tool_cap_map_count = sizeof(tool_cap_map) / sizeof(tool_cap_map[0]);

uint8_t dclaw_policy_lookup_capability(const char *tool_name) {
    if (!tool_name || tool_name[0] == '\0') {
        return DCLAW_CAP_EXEC_SHELL; /* fail-closed default */
    }
    for (size_t i = 0; i < tool_cap_map_count; i++) {
        if (strcmp(tool_name, tool_cap_map[i].tool_name) == 0) {
            return tool_cap_map[i].cap_flags;
        }
    }
    /* Unknown tool: default to EXEC_SHELL (fail-closed — most restrictive) */
    return DCLAW_CAP_EXEC_SHELL;
}

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
