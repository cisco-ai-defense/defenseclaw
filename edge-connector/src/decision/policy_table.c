#include "defenseclaw.h"
#include "platform.h"
#include <string.h>
#include <stdio.h>

/* Policy tables are compiled into generated/policy_tables.h by the policy compiler.
 * For Phase 1 bootstrap, we use a minimal default policy. */

#include "policy_tables.h"

extern dclaw_state_t *dclaw_get_state(void);

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

    /* P1-9 fix: Common adapter tool names (HA, PicoClaw, IoT connectors).
     * Without these entries, adapter tools default to EXEC_SHELL and get
     * blocked by the fail-closed policy. */

    /* Sensor-class adapter tools → SENSOR_READ */
    { "get_state",        DCLAW_CAP_SENSOR_READ },
    { "battery_status",   DCLAW_CAP_SENSOR_READ },
    { "read_sensor",      DCLAW_CAP_SENSOR_READ },
    { "get_temperature",  DCLAW_CAP_SENSOR_READ },
    { "check_status",     DCLAW_CAP_SENSOR_READ },
    { "list_devices",     DCLAW_CAP_SENSOR_READ },
    { "get_history",      DCLAW_CAP_SENSOR_READ },
    { "get_sensors",      DCLAW_CAP_SENSOR_READ },
    { "scan_surroundings", DCLAW_CAP_SENSOR_READ },
    { "check_room_state", DCLAW_CAP_SENSOR_READ },

    /* Actuation-class adapter tools → ACTUATE */
    { "turn_on",          DCLAW_CAP_ACTUATE },
    { "turn_off",         DCLAW_CAP_ACTUATE },
    { "set_temperature",  DCLAW_CAP_ACTUATE },
    { "start_motor",      DCLAW_CAP_ACTUATE },
    { "drive",            DCLAW_CAP_ACTUATE },
    { "move",             DCLAW_CAP_ACTUATE },
    { "explore",          DCLAW_CAP_ACTUATE },
    { "go_to_room",       DCLAW_CAP_ACTUATE },
    { "follow_nearest",   DCLAW_CAP_ACTUATE },
    { "follow_start",     DCLAW_CAP_ACTUATE },
    { "follow_stop",      DCLAW_CAP_ACTUATE },
    { "stop",             DCLAW_CAP_ACTUATE },
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

/*
 * dclaw_policy_tables_init — populate runtime tables from compiled-in defaults.
 * Called once during dclaw_init(). After OTA, dclaw_policy_reload_from_flash()
 * overwrites these with the flash-resident policy.
 */
void dclaw_policy_tables_init(void) {
    dclaw_state_t *s = dclaw_get_state();
    dclaw_policy_table_t *rt = &s->rt_policy;
    memset(rt, 0, sizeof(*rt));

    /* Copy compiled-in deny hashes */
    rt->deny_hashes_count = deny_hashes_count;
    if (rt->deny_hashes_count > DCLAW_RT_MAX_DENY_HASHES)
        rt->deny_hashes_count = DCLAW_RT_MAX_DENY_HASHES;
    for (size_t i = 0; i < rt->deny_hashes_count; i++) {
        memcpy(rt->deny_hashes[i], deny_hashes[i], 32);
    }

    /* Copy compiled-in destination allowlist */
    rt->dest_allowlist_count = dest_allowlist_count;
    if (rt->dest_allowlist_count > DCLAW_RT_MAX_DEST_ALLOWLIST)
        rt->dest_allowlist_count = DCLAW_RT_MAX_DEST_ALLOWLIST;
    for (size_t i = 0; i < rt->dest_allowlist_count; i++) {
        strncpy(rt->dest_allowlist[i], dest_allowlist[i], DCLAW_RT_MAX_DEST_LEN - 1);
        rt->dest_allowlist[i][DCLAW_RT_MAX_DEST_LEN - 1] = '\0';
    }

    /* Copy compiled-in severity rules */
    rt->severity_rules_count = severity_rules_count;
    if (rt->severity_rules_count > DCLAW_RT_MAX_SEVERITY_RULES)
        rt->severity_rules_count = DCLAW_RT_MAX_SEVERITY_RULES;
    for (size_t i = 0; i < rt->severity_rules_count; i++) {
        rt->severity_rules[i].severity = severity_rules[i].severity;
        rt->severity_rules[i].action = severity_rules[i].action;
    }

    /* Copy compiled-in sequence rules */
    rt->sequence_rules_count = sequence_rules_count;
    if (rt->sequence_rules_count > DCLAW_RT_MAX_SEQUENCE_RULES)
        rt->sequence_rules_count = DCLAW_RT_MAX_SEQUENCE_RULES;
    for (size_t i = 0; i < rt->sequence_rules_count; i++) {
        memcpy(rt->sequence_rules[i].seq, sequence_rules[i].seq, 4);
        rt->sequence_rules[i].seq_len = sequence_rules[i].seq_len;
        rt->sequence_rules[i].action = sequence_rules[i].action;
    }

    rt->loaded = false; /* compiled-in defaults, not from flash */
}

dclaw_action_t dclaw_policy_check_hash(const uint8_t *tool_hash) {
    dclaw_state_t *s = dclaw_get_state();
    dclaw_policy_table_t *rt = &s->rt_policy;

    /* Binary search over sorted deny_hashes table (runtime copy) */
    int lo = 0, hi = (int)rt->deny_hashes_count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int cmp = compare_hash(tool_hash, rt->deny_hashes[mid]);
        if (cmp == 0) return DCLAW_ACTION_BLOCK;
        if (cmp < 0) hi = mid - 1;
        else lo = mid + 1;
    }
    return DCLAW_ACTION_ALLOW;
}

dclaw_action_t dclaw_policy_check_destination(const char *host) {
    dclaw_state_t *s = dclaw_get_state();
    dclaw_policy_table_t *rt = &s->rt_policy;

    /* Linear scan over destination allowlist (runtime copy, small ≤256 entries) */
    for (size_t i = 0; i < rt->dest_allowlist_count; i++) {
        if (strcmp(host, rt->dest_allowlist[i]) == 0) {
            return DCLAW_ACTION_ALLOW;
        }
        /* Wildcard prefix match: *.example.com */
        if (rt->dest_allowlist[i][0] == '*' && rt->dest_allowlist[i][1] == '.') {
            const char *suffix = &rt->dest_allowlist[i][1];
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
    dclaw_state_t *s = dclaw_get_state();
    dclaw_policy_table_t *rt = &s->rt_policy;

    for (size_t i = 0; i < rt->severity_rules_count; i++) {
        if (rt->severity_rules[i].severity == (uint8_t)sev) {
            return (dclaw_action_t)rt->severity_rules[i].action;
        }
    }
    return DCLAW_ACTION_ALLOW;
}
