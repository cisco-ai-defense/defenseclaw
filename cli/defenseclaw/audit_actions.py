# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Curated registry of every audit-event `action` string emitted by
DefenseClaw.

Mirrors ``internal/audit/actions.go`` 1:1. The Go file is the source
of truth; Python parity is enforced by ``scripts/check_audit_actions.py``.

Rules
-----
* NEVER use a raw string literal at an audit log call site. Import
  the constant below.
* Adding a new action is a minor schema bump: append here, extend
  Go, regenerate the schema (``make check-schemas``), run
  ``make check-audit-actions``.
* Removing or renaming a constant is a breaking change: bump
  ``defenseclaw.version.SchemaVersion`` and announce to downstream.
"""

from __future__ import annotations

from typing import Final

# Lifecycle
ACTION_INIT: Final[str]  = "init"
ACTION_STOP: Final[str]  = "stop"
ACTION_READY: Final[str] = "ready"

# Scan pipeline
ACTION_SCAN: Final[str]         = "scan"
ACTION_SCAN_START: Final[str]   = "scan-start"
ACTION_RESCAN: Final[str]       = "rescan"
ACTION_RESCAN_START: Final[str] = "rescan-start"

# Admission gate
ACTION_BLOCK: Final[str] = "block"
ACTION_ALLOW: Final[str] = "allow"
ACTION_WARN: Final[str]  = "warn"

# Quarantine / runtime enforcement
ACTION_QUARANTINE: Final[str] = "quarantine"
ACTION_RESTORE: Final[str]    = "restore"
ACTION_DISABLE: Final[str]    = "disable"
ACTION_ENABLE: Final[str]     = "enable"

# Deploy / drift
ACTION_DEPLOY: Final[str] = "deploy"
ACTION_DRIFT: Final[str]  = "drift"

# Network egress
ACTION_NETWORK_EGRESS_BLOCKED: Final[str] = "network-egress-blocked"
ACTION_NETWORK_EGRESS_ALLOWED: Final[str] = "network-egress-allowed"

# Guardrail
ACTION_GUARDRAIL_BLOCK: Final[str] = "guardrail-block"
ACTION_GUARDRAIL_WARN: Final[str]  = "guardrail-warn"
ACTION_GUARDRAIL_ALLOW: Final[str] = "guardrail-allow"

# Approval flow
ACTION_APPROVAL_REQUEST: Final[str] = "approval-request"
ACTION_APPROVAL_GRANTED: Final[str] = "approval-granted"
ACTION_APPROVAL_DENIED: Final[str]  = "approval-denied"

# Tool runtime
ACTION_TOOL_CALL: Final[str]   = "tool-call"
ACTION_TOOL_RESULT: Final[str] = "tool-result"

# Operator mutations (v7 Activity)
ACTION_CONFIG_UPDATE: Final[str]   = "config-update"
ACTION_POLICY_UPDATE: Final[str]   = "policy-update"
ACTION_POLICY_RELOAD: Final[str]   = "policy-reload"
ACTION_ACTION: Final[str]          = "action"
ACTION_ACK_ALERTS: Final[str]      = "acknowledge-alerts"
ACTION_DISMISS_ALERTS: Final[str]  = "dismiss-alerts"

# Webhook / notifier
ACTION_WEBHOOK_DELIVERED: Final[str] = "webhook-delivered"
ACTION_WEBHOOK_FAILED: Final[str]    = "webhook-failed"

# Sink / telemetry health
ACTION_SINK_FAILURE: Final[str]  = "sink-failure"
ACTION_SINK_RESTORED: Final[str] = "sink-restored"

# Runtime alert
ACTION_ALERT: Final[str] = "alert"

# Connector observability ingress (native OTLP and hook telemetry).
# Mirrors internal/audit/actions.go::ActionOTelIngest*.
ACTION_OTEL_INGEST_LOGS: Final[str]      = "otel.ingest.logs"
ACTION_OTEL_INGEST_METRICS: Final[str]   = "otel.ingest.metrics"
ACTION_OTEL_INGEST_TRACES: Final[str]    = "otel.ingest.traces"
ACTION_OTEL_INGEST_MALFORMED: Final[str] = "otel.ingest.malformed"

# Codex notify webhook (agent-turn-complete et al.). The notify
# bridge POSTs codex's JSON arg to /api/v1/codex/notify; the
# gateway derives the action key from the payload's `type` field.
# `codex.notify.<sanitized-type>` is a curated dynamic suffix
# family — see is_known_action_prefix.
ACTION_CODEX_NOTIFY: Final[str]                     = "codex.notify"
ACTION_CODEX_NOTIFY_AGENT_TURN_COMPLETE: Final[str] = "codex.notify.agent-turn-complete"
ACTION_CODEX_NOTIFY_MALFORMED: Final[str]           = "codex.notify.malformed"


ALL_ACTIONS: Final[tuple[str, ...]] = (
    ACTION_INIT,
    ACTION_STOP,
    ACTION_READY,
    ACTION_SCAN,
    ACTION_SCAN_START,
    ACTION_RESCAN,
    ACTION_RESCAN_START,
    ACTION_BLOCK,
    ACTION_ALLOW,
    ACTION_WARN,
    ACTION_QUARANTINE,
    ACTION_RESTORE,
    ACTION_DISABLE,
    ACTION_ENABLE,
    ACTION_DEPLOY,
    ACTION_DRIFT,
    ACTION_NETWORK_EGRESS_BLOCKED,
    ACTION_NETWORK_EGRESS_ALLOWED,
    ACTION_GUARDRAIL_BLOCK,
    ACTION_GUARDRAIL_WARN,
    ACTION_GUARDRAIL_ALLOW,
    ACTION_APPROVAL_REQUEST,
    ACTION_APPROVAL_GRANTED,
    ACTION_APPROVAL_DENIED,
    ACTION_TOOL_CALL,
    ACTION_TOOL_RESULT,
    ACTION_CONFIG_UPDATE,
    ACTION_POLICY_UPDATE,
    ACTION_POLICY_RELOAD,
    ACTION_ACTION,
    ACTION_ACK_ALERTS,
    ACTION_DISMISS_ALERTS,
    ACTION_WEBHOOK_DELIVERED,
    ACTION_WEBHOOK_FAILED,
    ACTION_SINK_FAILURE,
    ACTION_SINK_RESTORED,
    ACTION_ALERT,
    ACTION_OTEL_INGEST_LOGS,
    ACTION_OTEL_INGEST_METRICS,
    ACTION_OTEL_INGEST_TRACES,
    ACTION_OTEL_INGEST_MALFORMED,
    ACTION_CODEX_NOTIFY,
    ACTION_CODEX_NOTIFY_AGENT_TURN_COMPLETE,
    ACTION_CODEX_NOTIFY_MALFORMED,
)


_CODEX_NOTIFY_PREFIX: Final[str] = "codex.notify."
_CODEX_NOTIFY_SUFFIX_MAX_LEN: Final[int] = 64


def is_known_action(s: str) -> bool:
    """Return True when ``s`` is a registered audit action.

    Callers that accept audit actions from untrusted surfaces
    (CLI args, HTTP payloads, plugin RPC) should reject unknown
    values rather than silently passing them through to SQLite.

    For dynamic suffix families (``codex.notify.<sanitized-type>``)
    use :func:`is_known_action_prefix` in addition to this check.
    """
    return s in ALL_ACTIONS


def is_known_action_prefix(s: str) -> bool:
    """Return True when ``s`` is a curated dynamic-suffix action.

    Today this only covers ``codex.notify.<sanitized-type>``: the
    codex notify handler builds the action key from the inbound
    payload's ``type`` field after running it through a strict
    ``[a-z0-9._-]{1,64}`` allow-list. Mirrors
    ``IsKnownActionPrefix`` in ``internal/audit/actions.go`` so
    the Python audit-row validators agree with the Go writer.
    """
    if not s.startswith(_CODEX_NOTIFY_PREFIX):
        return False
    suffix = s[len(_CODEX_NOTIFY_PREFIX):]
    if not suffix or len(suffix) > _CODEX_NOTIFY_SUFFIX_MAX_LEN:
        return False
    return all(
        ('a' <= c <= 'z') or ('0' <= c <= '9') or c in ('-', '_', '.')
        for c in suffix
    )
