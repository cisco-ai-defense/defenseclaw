/*
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: Apache-2.0
 *
 * Muse Gadget SDK → DefenseClaw bridge.
 *
 * Maps Muse link.invoke commands (system.run, file.read, file.write,
 * device.health) to DefenseClaw capability flags and evaluates them
 * through the standard dclaw_evaluate() pipeline before execution.
 *
 * Integration points:
 *   Linux: Python Executor subclass calls dclaw_evaluate() via ctypes/FFI
 *          before running each command.
 *   ESP32: C function called from the Muse command dispatcher before
 *          invoking the shell or filesystem handler.
 */

#ifndef DCLAW_MUSE_BRIDGE_H
#define DCLAW_MUSE_BRIDGE_H

#include "defenseclaw.h"
#include <string.h>

/* Muse command names as defined by the Gadget SDK protocol */
#define MUSE_CMD_SYSTEM_RUN    "system.run"
#define MUSE_CMD_FILE_READ     "file.read"
#define MUSE_CMD_FILE_WRITE    "file.write"
#define MUSE_CMD_DEVICE_HEALTH "device.health"

/* Map a Muse command name to DefenseClaw capability flags.
 * Returns 0 (DCLAW_CAP_UNKNOWN) for unrecognized commands. */
static inline uint8_t muse_command_to_caps(const char *command) {
    if (strcmp(command, MUSE_CMD_SYSTEM_RUN) == 0)
        return DCLAW_CAP_EXEC_SHELL;
    if (strcmp(command, MUSE_CMD_FILE_READ) == 0)
        return DCLAW_CAP_READ_FS;
    if (strcmp(command, MUSE_CMD_FILE_WRITE) == 0)
        return DCLAW_CAP_WRITE_FS;
    if (strcmp(command, MUSE_CMD_DEVICE_HEALTH) == 0)
        return DCLAW_CAP_SENSOR_READ;
    return DCLAW_CAP_UNKNOWN;
}

/* Populate a dclaw_tool_request_t from a Muse link.invoke message.
 * The caller must provide a valid sha256 hash of the command + params.
 * Returns 0 on success, -1 if the command is not recognized. */
static inline int muse_build_request(
    dclaw_tool_request_t *req,
    const char *command,
    const uint8_t tool_hash[32],
    uint16_t session_id,
    const char *content,
    uint16_t content_len
) {
    memset(req, 0, sizeof(*req));

    uint8_t caps = muse_command_to_caps(command);
    if (caps == DCLAW_CAP_UNKNOWN)
        return -1;

    size_t name_len = strlen(command);
    if (name_len >= DCLAW_TOOL_NAME_MAX)
        name_len = DCLAW_TOOL_NAME_MAX - 1;
    memcpy(req->tool_name, command, name_len);
    req->tool_name[name_len] = '\0';

    memcpy(req->tool_hash, tool_hash, 32);
    req->cap_flags = caps;
    req->session_id = session_id;
    req->direction = DCLAW_DIRECTION_REQUEST;
    req->content_scope = DCLAW_CONTENT_SCOPE_USER_INPUT;

    if (content && content_len > 0) {
        uint16_t copy_len = content_len;
        if (copy_len > DCLAW_CONTENT_MAX - 1)
            copy_len = DCLAW_CONTENT_MAX - 1;
        memcpy(req->content_buf, content, copy_len);
        req->content_buf[copy_len] = '\0';
        req->content = req->content_buf;
        req->content_len = copy_len;
    }

    return 0;
}

#endif /* DCLAW_MUSE_BRIDGE_H */
