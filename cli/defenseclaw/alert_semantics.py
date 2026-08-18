# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Shared semantic vocabulary for alert projections and presentation."""

ALERT_ALL_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "ERROR", "WARNING")
ALERT_ACTIONABLE_SEVERITIES = ("CRITICAL", "HIGH", "ERROR")

ALERT_NON_ALLOW_OUTCOMES = (
    "alert",
    "ask",
    "block",
    "blocked",
    "confirm",
    "deny",
    "denied",
    "fail",
    "failed",
    "failure",
    "quarantine",
    "quarantined",
    "reject",
    "rejected",
    "revoked",
    "terminated",
    "timed_out",
)

ALERT_LEGACY_FINDING_ACTIONS = (
    "alert",
    "connector-hook-tampered",
    "gateway-multi-turn-injection",
    "gateway-session-prompt-alert",
    "gateway-tool-call-flagged",
    "gateway-tool-call-judge-flagged",
    "scan-finding",
    "tool-result-pii-alert",
)
