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
#include <string.h>
#include <strings.h>
#include <stdio.h>

/* Policy tables are compiled into generated/policy_tables.h by the policy compiler.
 * For Phase 1 bootstrap, we use a minimal default policy. */

#include "policy_tables.h"

extern dclaw_state_t *dclaw_get_state(void);

/* === Trusted tool-name-to-capability mapping ===
 *
 * The caller-provided cap_flags in the IPC request cannot be trusted.
 * This table maps known tool names to their correct capability flags.
 * Unknown tools return CAP_UNKNOWN and are refused before cache/cloud lookup.
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
    { "cat",            DCLAW_CAP_READ_FS },
    { "list_files",     DCLAW_CAP_READ_FS },
    { "list_dir",       DCLAW_CAP_READ_FS },
    { "write_file",     DCLAW_CAP_WRITE_FS },
    { "write-file",     DCLAW_CAP_WRITE_FS },
    { "save",           DCLAW_CAP_WRITE_FS },
    { "create_file",    DCLAW_CAP_WRITE_FS },
    { "delete_file",    DCLAW_CAP_WRITE_FS },
    { "edit_file",      DCLAW_CAP_WRITE_FS },

    /* Shell execution */
    { "exec_shell",     DCLAW_CAP_EXEC_SHELL },
    { "exec-shell",     DCLAW_CAP_EXEC_SHELL },
    { "exec",           DCLAW_CAP_EXEC_SHELL },
    { "run_command",    DCLAW_CAP_EXEC_SHELL },
    { "run-command",    DCLAW_CAP_EXEC_SHELL },
    { "execute_code",   DCLAW_CAP_EXEC_SHELL },
    { "run_python",     DCLAW_CAP_EXEC_SHELL },
    { "terminal",       DCLAW_CAP_EXEC_SHELL },
    { "bash",           DCLAW_CAP_EXEC_SHELL },
    { "shell",          DCLAW_CAP_EXEC_SHELL },

    /* Network */
    { "net_fetch",      DCLAW_CAP_NET_FETCH },
    { "net-fetch",      DCLAW_CAP_NET_FETCH },
    { "web_search",     DCLAW_CAP_NET_FETCH },
    { "web_fetch",      DCLAW_CAP_NET_FETCH },
    { "fetch",          DCLAW_CAP_NET_FETCH },
    { "http_request",   DCLAW_CAP_NET_FETCH },
    { "http-request",   DCLAW_CAP_NET_FETCH },
    { "curl",           DCLAW_CAP_NET_FETCH },
    { "fetch_url",      DCLAW_CAP_NET_FETCH },
    { "fetch-url",      DCLAW_CAP_NET_FETCH },
    { "download",       DCLAW_CAP_NET_FETCH },
    { "api_call",       DCLAW_CAP_NET_FETCH },
    { "api-call",       DCLAW_CAP_NET_FETCH },
    { "call_api",       DCLAW_CAP_NET_FETCH },
    { "requests_get",   DCLAW_CAP_NET_FETCH },
    { "requests_post",  DCLAW_CAP_NET_FETCH },

    /* Messaging */
    { "send_message",   DCLAW_CAP_SEND_MSG },
    { "send-message",   DCLAW_CAP_SEND_MSG },
    { "send_email",     DCLAW_CAP_SEND_MSG },
    { "notify",         DCLAW_CAP_SEND_MSG },

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


    /* Sensor-class adapter tools → SENSOR_READ */
    { "get_state",        DCLAW_CAP_SENSOR_READ },
    { "battery_status",   DCLAW_CAP_SENSOR_READ },
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
    /* Reviewed names from shipped Home Assistant, Bubbaloop and ESP-Claw adapters. */
    /* ACTUATE */
    { "activate_scene", DCLAW_CAP_ACTUATE },
    { "arm_alarm", DCLAW_CAP_ACTUATE },
    { "arm_move_to", DCLAW_CAP_ACTUATE },
    { "call_service", DCLAW_CAP_ACTUATE },
    { "close_cover", DCLAW_CAP_ACTUATE },
    { "disarm_alarm", DCLAW_CAP_ACTUATE },
    { "emergency_stop", DCLAW_CAP_ACTUATE },
    { "fire_event", DCLAW_CAP_ACTUATE },
    { "follow_path", DCLAW_CAP_ACTUATE },
    { "gpio_write", DCLAW_CAP_ACTUATE },
    { "gripper_close", DCLAW_CAP_ACTUATE },
    { "gripper_open", DCLAW_CAP_ACTUATE },
    { "i2c_write", DCLAW_CAP_ACTUATE },
    { "led_set", DCLAW_CAP_ACTUATE },
    { "lock", DCLAW_CAP_ACTUATE },
    { "media_next", DCLAW_CAP_ACTUATE },
    { "media_pause", DCLAW_CAP_ACTUATE },
    { "media_play", DCLAW_CAP_ACTUATE },
    { "media_previous", DCLAW_CAP_ACTUATE },
    { "media_stop", DCLAW_CAP_ACTUATE },
    { "motor_set_speed", DCLAW_CAP_ACTUATE },
    { "motor_stop", DCLAW_CAP_ACTUATE },
    { "navigate_to", DCLAW_CAP_ACTUATE },
    { "open_cover", DCLAW_CAP_ACTUATE },
    { "play_media", DCLAW_CAP_ACTUATE },
    { "press_button", DCLAW_CAP_ACTUATE },
    { "pwm_set", DCLAW_CAP_ACTUATE },
    { "select_option", DCLAW_CAP_ACTUATE },
    { "servo_set_angle", DCLAW_CAP_ACTUATE },
    { "set_brightness", DCLAW_CAP_ACTUATE },
    { "set_color", DCLAW_CAP_ACTUATE },
    { "set_cover_position", DCLAW_CAP_ACTUATE },
    { "set_fan_mode", DCLAW_CAP_ACTUATE },
    { "set_humidity", DCLAW_CAP_ACTUATE },
    { "set_hvac_mode", DCLAW_CAP_ACTUATE },
    { "set_value", DCLAW_CAP_ACTUATE },
    { "set_volume", DCLAW_CAP_ACTUATE },
    { "spi_transfer", DCLAW_CAP_ACTUATE },
    { "toggle", DCLAW_CAP_ACTUATE },
    { "trigger_alarm", DCLAW_CAP_ACTUATE },
    { "tts_speak", DCLAW_CAP_ACTUATE },
    { "unlock", DCLAW_CAP_ACTUATE },
    { "vacuum_return_home", DCLAW_CAP_ACTUATE },
    { "vacuum_start", DCLAW_CAP_ACTUATE },
    { "vacuum_stop", DCLAW_CAP_ACTUATE },
    /* EXEC_SHELL */
    { "firmware_update", DCLAW_CAP_EXEC_SHELL },
    { "install_addon", DCLAW_CAP_EXEC_SHELL },
    { "lua_eval", DCLAW_CAP_EXEC_SHELL },
    { "lua_load", DCLAW_CAP_EXEC_SHELL },
    { "ota_update", DCLAW_CAP_EXEC_SHELL },
    { "pipeline_deploy", DCLAW_CAP_EXEC_SHELL },
    { "plugin_install", DCLAW_CAP_EXEC_SHELL },
    { "reboot", DCLAW_CAP_EXEC_SHELL },
    { "reload_automations", DCLAW_CAP_EXEC_SHELL },
    { "reload_config", DCLAW_CAP_EXEC_SHELL },
    { "reload_scenes", DCLAW_CAP_EXEC_SHELL },
    { "reload_scripts", DCLAW_CAP_EXEC_SHELL },
    { "restart_ha", DCLAW_CAP_EXEC_SHELL },
    { "run_script", DCLAW_CAP_EXEC_SHELL },
    { "start_addon", DCLAW_CAP_EXEC_SHELL },
    { "stop_addon", DCLAW_CAP_EXEC_SHELL },
    { "system_restart", DCLAW_CAP_EXEC_SHELL },
    { "trigger_automation", DCLAW_CAP_EXEC_SHELL },
    { "update_addon", DCLAW_CAP_EXEC_SHELL },
    /* NET_FETCH */
    { "call_webhook", DCLAW_CAP_NET_FETCH },
    { "cloud_sync", DCLAW_CAP_NET_FETCH },
    { "http_fetch", DCLAW_CAP_NET_FETCH },
    { "model_download", DCLAW_CAP_NET_FETCH },
    { "mqtt_publish", DCLAW_CAP_NET_FETCH },
    { "register_webhook", DCLAW_CAP_NET_FETCH },
    { "remove_integration", DCLAW_CAP_NET_FETCH },
    { "setup_integration", DCLAW_CAP_NET_FETCH },
    { "zenoh_publish", DCLAW_CAP_NET_FETCH },
    /* READ_FS */
    { "config_get", DCLAW_CAP_READ_FS },
    { "file_list", DCLAW_CAP_READ_FS },
    { "file_read", DCLAW_CAP_READ_FS },
    { "fs_list", DCLAW_CAP_READ_FS },
    { "fs_read", DCLAW_CAP_READ_FS },
    { "model_load", DCLAW_CAP_READ_FS },
    /* SEND_MSG */
    { "send_notification", DCLAW_CAP_SEND_MSG },
    /* SENSOR_READ */
    { "adc_read", DCLAW_CAP_SENSOR_READ },
    { "aruco_detect", DCLAW_CAP_SENSOR_READ },
    { "battery_level", DCLAW_CAP_SENSOR_READ },
    { "ble_scan", DCLAW_CAP_SENSOR_READ },
    { "camera_capture", DCLAW_CAP_SENSOR_READ },
    { "camera_list", DCLAW_CAP_SENSOR_READ },
    { "camera_stream_start", DCLAW_CAP_SENSOR_READ },
    { "camera_stream_stop", DCLAW_CAP_SENSOR_READ },
    { "face_detect", DCLAW_CAP_SENSOR_READ },
    { "get_addon_info", DCLAW_CAP_SENSOR_READ },
    { "get_addons", DCLAW_CAP_SENSOR_READ },
    { "get_all_states", DCLAW_CAP_SENSOR_READ },
    { "get_integrations_manifest", DCLAW_CAP_SENSOR_READ },
    { "get_area_registry", DCLAW_CAP_SENSOR_READ },
    { "get_areas", DCLAW_CAP_SENSOR_READ },
    { "get_automations", DCLAW_CAP_SENSOR_READ },
    { "get_blueprints", DCLAW_CAP_SENSOR_READ },
    { "get_calendar_events", DCLAW_CAP_SENSOR_READ },
    { "get_calendars", DCLAW_CAP_SENSOR_READ },
    { "get_camera_image", DCLAW_CAP_SENSOR_READ },
    { "get_config", DCLAW_CAP_SENSOR_READ },
    { "get_device_registry", DCLAW_CAP_SENSOR_READ },
    { "get_devices", DCLAW_CAP_SENSOR_READ },
    { "get_energy_data", DCLAW_CAP_SENSOR_READ },
    { "get_entities", DCLAW_CAP_SENSOR_READ },
    { "get_entity_history", DCLAW_CAP_SENSOR_READ },
    { "get_entity_registry", DCLAW_CAP_SENSOR_READ },
    { "get_entity_state", DCLAW_CAP_SENSOR_READ },
    { "get_error_log", DCLAW_CAP_SENSOR_READ },
    { "get_integrations", DCLAW_CAP_SENSOR_READ },
    { "get_logbook", DCLAW_CAP_SENSOR_READ },
    { "get_media_players", DCLAW_CAP_SENSOR_READ },
    { "get_notifications", DCLAW_CAP_SENSOR_READ },
    { "get_persons", DCLAW_CAP_SENSOR_READ },
    { "get_scenes", DCLAW_CAP_SENSOR_READ },
    { "get_scripts", DCLAW_CAP_SENSOR_READ },
    { "get_sensor_data", DCLAW_CAP_SENSOR_READ },
    { "get_services", DCLAW_CAP_SENSOR_READ },
    { "get_shopping_list", DCLAW_CAP_SENSOR_READ },
    { "get_statistics", DCLAW_CAP_SENSOR_READ },
    { "get_status", DCLAW_CAP_SENSOR_READ },
    { "get_todo_items", DCLAW_CAP_SENSOR_READ },
    { "get_zones", DCLAW_CAP_SENSOR_READ },
    { "gpio_read", DCLAW_CAP_SENSOR_READ },
    { "gps_position", DCLAW_CAP_SENSOR_READ },
    { "humidity_read", DCLAW_CAP_SENSOR_READ },
    { "i2c_read", DCLAW_CAP_SENSOR_READ },
    { "image_classify", DCLAW_CAP_SENSOR_READ },
    { "image_depth_estimate", DCLAW_CAP_SENSOR_READ },
    { "image_detect_objects", DCLAW_CAP_SENSOR_READ },
    { "image_feature_match", DCLAW_CAP_SENSOR_READ },
    { "image_segment", DCLAW_CAP_SENSOR_READ },
    { "imu_read", DCLAW_CAP_SENSOR_READ },
    { "lidar_scan", DCLAW_CAP_SENSOR_READ },
    { "optical_flow", DCLAW_CAP_SENSOR_READ },
    { "pose_estimate", DCLAW_CAP_SENSOR_READ },
    { "pressure_read", DCLAW_CAP_SENSOR_READ },
    { "search_entities", DCLAW_CAP_SENSOR_READ },
    { "stereo_depth", DCLAW_CAP_SENSOR_READ },
    { "system_metrics", DCLAW_CAP_SENSOR_READ },
    { "temperature_read", DCLAW_CAP_SENSOR_READ },
    { "wifi_scan", DCLAW_CAP_SENSOR_READ },
    { "video_record_start", DCLAW_CAP_SENSOR_READ },
    { "video_record_stop", DCLAW_CAP_SENSOR_READ },
    /* WRITE_FS */
    { "config_set", DCLAW_CAP_WRITE_FS },
    { "create_automation", DCLAW_CAP_WRITE_FS },
    { "delete_automation", DCLAW_CAP_WRITE_FS },
    { "file_write", DCLAW_CAP_WRITE_FS },
    { "fs_write", DCLAW_CAP_WRITE_FS },
    { "model_save", DCLAW_CAP_WRITE_FS },
    { "update_automation", DCLAW_CAP_WRITE_FS },
};
static const size_t tool_cap_map_count = sizeof(tool_cap_map) / sizeof(tool_cap_map[0]);

uint8_t dclaw_policy_lookup_capability(const char *tool_name) {
    if (!tool_name || tool_name[0] == '\0') {
        return DCLAW_CAP_UNKNOWN;
    }
    for (size_t i = 0; i < tool_cap_map_count; i++) {
        if (strcmp(tool_name, tool_cap_map[i].tool_name) == 0) {
            return tool_cap_map[i].cap_flags;
        }
    }
    return DCLAW_CAP_UNKNOWN;
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

/*
 * Extract hostname from a destination string that may be a full URL.
 * If dest contains "://", skip past the scheme and extract the hostname portion
 * (up to the next '/', ':', or end of string). Otherwise return dest as-is.
 * The extracted hostname is written into out_buf (NUL-terminated).
 * Returns a pointer to the hostname (either out_buf or dest itself).
 *
 * Also skip userinfo (user:pass@) in the authority section,
 * matching the behavior of content_scanner.c:extract_host(). Without this,
 * a URL like "http://user:pass@evil.com" would be matched against the
 * allowlist as "user:pass@evil.com" instead of "evil.com", causing
 * inconsistent results between the SSRF check and the allowlist check.
 */
static const char *extract_hostname(const char *dest, char *out_buf, size_t buf_size) {
    const char *host_start = dest;

    /* Skip scheme if present */
    const char *scheme_end = strstr(dest, "://");
    if (scheme_end) {
        host_start = scheme_end + 3;
    }

    /* Skip userinfo (user:pass@) if present — scan for '@' before '/' */
    const char *scan = host_start;
    while (*scan && *scan != '/' && *scan != '?') {
        if (*scan == '@') {
            host_start = scan + 1;
            break;
        }
        scan++;
    }

    /* Handle IPv6 bracket notation: [::1], [fc00::1] */
    if (*host_start == '[') {
        host_start++;
        const char *bracket_end = host_start;
        while (*bracket_end && *bracket_end != ']') bracket_end++;
        size_t host_len = (size_t)(bracket_end - host_start);
        if (host_len == 0 || host_len >= buf_size) {
            return dest;
        }
        memcpy(out_buf, host_start, host_len);
        out_buf[host_len] = '\0';
        return out_buf;
    }

    /* Hostname extends to ':', '/', '?', or end of string.
     * This strips the port from bare "host:port" destinations (no scheme)
     * as well as from full URLs like "http://host:port/path". */
    const char *host_end = host_start;
    while (*host_end != '\0' && *host_end != '/' && *host_end != ':' && *host_end != '?') {
        host_end++;
    }
    size_t host_len = (size_t)(host_end - host_start);
    if (host_len == 0) {
        return dest;
    }
    if (host_len >= buf_size) {
        host_len = buf_size - 1;
    }
    memcpy(out_buf, host_start, host_len);
    out_buf[host_len] = '\0';
    return out_buf;
}

dclaw_action_t dclaw_policy_check_destination(const char *dest) {
    dclaw_state_t *s = dclaw_get_state();
    dclaw_policy_table_t *rt = &s->rt_policy;

    char host_buf[DCLAW_RT_MAX_DEST_LEN];
    const char *host = extract_hostname(dest, host_buf, sizeof(host_buf));

    /* Linear scan over explicit public IP literals (runtime copy, ≤256). */
    for (size_t i = 0; i < rt->dest_allowlist_count; i++) {
        if (strcasecmp(host, rt->dest_allowlist[i]) == 0) {
            return DCLAW_ACTION_ALLOW;
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
