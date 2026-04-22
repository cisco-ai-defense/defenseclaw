# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""v7 standardized vocabulary for the ``code`` / ``subsystem`` fields
on every ``EventError`` emission.

Mirrors ``internal/gatewaylog/error_codes.go`` 1:1. The Go file is
the source of truth; Python parity is enforced by
``scripts/check_error_codes.py``.

The ``(Subsystem, Code)`` pair is stable and safe to alert on;
adding a new code is a minor schema bump, removing / renaming one is
breaking.
"""

from __future__ import annotations

from typing import Final

# --- Error codes -----------------------------------------------------
# Sink subsystem
ERR_SINK_DELIVERY_FAILED: Final[str] = "SINK_DELIVERY_FAILED"
ERR_SINK_QUEUE_FULL: Final[str]      = "SINK_QUEUE_FULL"

# Telemetry subsystem
ERR_EXPORT_FAILED: Final[str] = "EXPORT_FAILED"

# Config subsystem
ERR_CONFIG_LOAD_FAILED: Final[str] = "CONFIG_LOAD_FAILED"

# Policy subsystem
ERR_POLICY_LOAD_FAILED: Final[str] = "POLICY_LOAD_FAILED"

# Auth subsystem
ERR_AUTH_INVALID_TOKEN: Final[str]  = "AUTH_INVALID_TOKEN"
ERR_AUTH_MISSING_TOKEN: Final[str]  = "AUTH_MISSING_TOKEN"
ERR_AUTH_CSRF_MISMATCH: Final[str]  = "AUTH_CSRF_MISMATCH"
ERR_AUTH_ORIGIN_BLOCKED: Final[str] = "AUTH_ORIGIN_BLOCKED"

# Correlation subsystem
ERR_INVALID_HEADER: Final[str] = "INVALID_HEADER"

# Cisco Inspect subsystem
ERR_INVALID_RESPONSE: Final[str] = "INVALID_RESPONSE"

# Subprocess (scanner / openshell)
ERR_SUBPROCESS_EXIT: Final[str] = "SUBPROCESS_EXIT"

# Webhook subsystem
ERR_WEBHOOK_DELIVERY_FAILED: Final[str] = "WEBHOOK_DELIVERY_FAILED"
ERR_WEBHOOK_COOLDOWN: Final[str]        = "WEBHOOK_COOLDOWN"

# Quarantine subsystem
ERR_FS_MOVE_FAILED: Final[str] = "FS_MOVE_FAILED"
ERR_FS_LINK_FAILED: Final[str] = "FS_LINK_FAILED"

# Stream subsystem
ERR_CLIENT_DISCONNECT: Final[str] = "CLIENT_DISCONNECT"
ERR_UPSTREAM_ERROR: Final[str]    = "UPSTREAM_ERROR"
ERR_STREAM_TIMEOUT: Final[str]    = "STREAM_TIMEOUT"

# SQLite subsystem
ERR_SQLITE_BUSY: Final[str] = "SQLITE_BUSY"

# Any subsystem
ERR_PANIC_RECOVERED: Final[str] = "PANIC_RECOVERED"

# LiteLLM bridge
ERR_LLM_BRIDGE_ERROR: Final[str] = "LLM_BRIDGE_ERROR"

# Gatewaylog subsystem — runtime schema validator rejected an event
ERR_SCHEMA_VIOLATION: Final[str] = "SCHEMA_VIOLATION"


ALL_ERROR_CODES: Final[tuple[str, ...]] = (
    ERR_SINK_DELIVERY_FAILED,
    ERR_SINK_QUEUE_FULL,
    ERR_EXPORT_FAILED,
    ERR_CONFIG_LOAD_FAILED,
    ERR_POLICY_LOAD_FAILED,
    ERR_AUTH_INVALID_TOKEN,
    ERR_AUTH_MISSING_TOKEN,
    ERR_AUTH_CSRF_MISMATCH,
    ERR_AUTH_ORIGIN_BLOCKED,
    ERR_INVALID_HEADER,
    ERR_INVALID_RESPONSE,
    ERR_SUBPROCESS_EXIT,
    ERR_WEBHOOK_DELIVERY_FAILED,
    ERR_WEBHOOK_COOLDOWN,
    ERR_FS_MOVE_FAILED,
    ERR_FS_LINK_FAILED,
    ERR_CLIENT_DISCONNECT,
    ERR_UPSTREAM_ERROR,
    ERR_STREAM_TIMEOUT,
    ERR_SQLITE_BUSY,
    ERR_PANIC_RECOVERED,
    ERR_LLM_BRIDGE_ERROR,
    ERR_SCHEMA_VIOLATION,
)


# --- Subsystems ------------------------------------------------------
SUBSYSTEM_SIDECAR: Final[str]         = "sidecar"
SUBSYSTEM_WATCHER: Final[str]         = "watcher"
SUBSYSTEM_GATEWAY: Final[str]         = "gateway"
SUBSYSTEM_SCANNER: Final[str]         = "scanner"
SUBSYSTEM_POLICY: Final[str]          = "policy"
SUBSYSTEM_GUARDRAIL: Final[str]       = "guardrail"
SUBSYSTEM_AUTH: Final[str]            = "auth"
SUBSYSTEM_CONFIG: Final[str]          = "config"
SUBSYSTEM_INSPECT: Final[str]         = "inspect"
SUBSYSTEM_APPROVALS: Final[str]       = "approvals"
SUBSYSTEM_SINK: Final[str]            = "sink"
SUBSYSTEM_TELEMETRY: Final[str]       = "telemetry"
SUBSYSTEM_CORRELATION: Final[str]     = "correlation"
SUBSYSTEM_STREAM: Final[str]          = "stream"
SUBSYSTEM_CISCO_INSPECT: Final[str]   = "cisco-inspect"
SUBSYSTEM_OPENSHELL: Final[str]       = "openshell"
SUBSYSTEM_WEBHOOK: Final[str]         = "webhook"
SUBSYSTEM_QUARANTINE: Final[str]      = "quarantine"
SUBSYSTEM_AGENT_REGISTRY: Final[str]  = "agent-registry"
SUBSYSTEM_SQLITE: Final[str]          = "sqlite"
SUBSYSTEM_ADMISSION: Final[str]       = "admission"
SUBSYSTEM_CONFIG_MUTATION: Final[str] = "config_mutation"
SUBSYSTEM_GATEWAYLOG: Final[str]      = "gatewaylog"


ALL_SUBSYSTEMS: Final[tuple[str, ...]] = (
    SUBSYSTEM_SIDECAR,
    SUBSYSTEM_WATCHER,
    SUBSYSTEM_GATEWAY,
    SUBSYSTEM_SCANNER,
    SUBSYSTEM_POLICY,
    SUBSYSTEM_GUARDRAIL,
    SUBSYSTEM_AUTH,
    SUBSYSTEM_CONFIG,
    SUBSYSTEM_INSPECT,
    SUBSYSTEM_APPROVALS,
    SUBSYSTEM_SINK,
    SUBSYSTEM_TELEMETRY,
    SUBSYSTEM_CORRELATION,
    SUBSYSTEM_STREAM,
    SUBSYSTEM_CISCO_INSPECT,
    SUBSYSTEM_OPENSHELL,
    SUBSYSTEM_WEBHOOK,
    SUBSYSTEM_QUARANTINE,
    SUBSYSTEM_AGENT_REGISTRY,
    SUBSYSTEM_SQLITE,
    SUBSYSTEM_ADMISSION,
    SUBSYSTEM_CONFIG_MUTATION,
    SUBSYSTEM_GATEWAYLOG,
)
