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
ACTION_CONNECTOR_HOOK: Final[str]              = "connector-hook"
ACTION_CONNECTOR_HOOK_SYNTHETIC: Final[str]    = "connector-hook-synthetic"
ACTION_ASSET_POLICY: Final[str]                = "asset-policy"

# Connector hook self-heal. Mirrors
# internal/audit/actions.go::ActionConnectorHook{Tampered,Repaired}.
# The hook config guard re-installs a connector's hook block after a
# user manually removes it while the gateway is running.
ACTION_CONNECTOR_HOOK_TAMPERED: Final[str]     = "connector-hook-tampered"
ACTION_CONNECTOR_HOOK_REPAIRED: Final[str]     = "connector-hook-repaired"

# Codex notify webhook (agent-turn-complete et al.). The notify
# bridge POSTs codex's JSON arg to /api/v1/codex/notify; the
# gateway derives the action key from the payload's `type` field.
# `codex.notify.<sanitized-type>` is a curated dynamic suffix
# family — see is_known_action_prefix.
ACTION_CODEX_NOTIFY: Final[str]                     = "codex.notify"
ACTION_CODEX_NOTIFY_AGENT_TURN_COMPLETE: Final[str] = "codex.notify.agent-turn-complete"
ACTION_CODEX_NOTIFY_MALFORMED: Final[str]           = "codex.notify.malformed"

# Sidecar lifecycle and bootstrap instrumentation.
ACTION_SIDECAR_START: Final[str] = "sidecar-start"
ACTION_SIDECAR_STOP: Final[str] = "sidecar-stop"
ACTION_SIDECAR_CONNECTED: Final[str] = "sidecar-connected"
ACTION_SIDECAR_DISCONNECTED: Final[str] = "sidecar-disconnected"
ACTION_SIDECAR_WATCHER_VERDICT: Final[str] = "sidecar-watcher-verdict"
ACTION_SIDECAR_WATCHER_DISABLE: Final[str] = "sidecar-watcher-disable"
ACTION_SIDECAR_WATCHER_DISABLE_PLUGIN: Final[str] = "sidecar-watcher-disable-plugin"
ACTION_SIDECAR_WATCHER_BLOCK_MCP: Final[str] = "sidecar-watcher-block-mcp"
ACTION_BOOTSTRAP: Final[str] = "bootstrap"

# Watcher lifecycle instrumentation.
ACTION_WATCH_START: Final[str] = "watch-start"
ACTION_WATCH_STOP: Final[str] = "watch-stop"
ACTION_WATCHER_BLOCK: Final[str] = "watcher-block"
ACTION_INSTALL_DETECTED: Final[str] = "install-detected"
ACTION_INSTALL_REJECTED: Final[str] = "install-rejected"
ACTION_INSTALL_ALLOWED: Final[str] = "install-allowed"
ACTION_INSTALL_ALLOWED_SKIP_ENFORCE: Final[str] = "install-allowed-skip-enforce"
ACTION_INSTALL_CLEAN: Final[str] = "install-clean"
ACTION_INSTALL_WARNING: Final[str] = "install-warning"
ACTION_INSTALL_SCAN_ERROR: Final[str] = "install-scan-error"
ACTION_INSTALL_ENFORCED: Final[str] = "install-enforced"
ACTION_INSTALL_BLOCKED: Final[str] = "install-blocked"
ACTION_INSTALL_DEP: Final[str] = "install-dep"

# Gateway session router instrumentation.
ACTION_GATEWAY_READY: Final[str] = "gateway-ready"
ACTION_GATEWAY_SESSION_MESSAGE: Final[str] = "gateway-session-message"
ACTION_GATEWAY_SESSION_PROMPT_ALERT: Final[str] = "gateway-session-prompt-alert"
ACTION_GATEWAY_SESSION_ERROR: Final[str] = "gateway-session-error"
ACTION_GATEWAY_CHAT_ERROR: Final[str] = "gateway-chat-error"
ACTION_GATEWAY_AGENT_START: Final[str] = "gateway-agent-start"
ACTION_GATEWAY_AGENT_END: Final[str] = "gateway-agent-end"
ACTION_GATEWAY_AGENT_ERROR: Final[str] = "gateway-agent-error"
ACTION_GATEWAY_TOOL_CALL: Final[str] = "gateway-tool-call"
ACTION_GATEWAY_TOOL_CALL_BLOCKED: Final[str] = "gateway-tool-call-blocked"
ACTION_GATEWAY_TOOL_CALL_FLAGGED: Final[str] = "gateway-tool-call-flagged"
ACTION_GATEWAY_TOOL_CALL_JUDGE_FLAGGED: Final[str] = "gateway-tool-call-judge-flagged"
ACTION_GATEWAY_TOOL_RESULT: Final[str] = "gateway-tool-result"
ACTION_GATEWAY_APPROVAL_REQUESTED: Final[str] = "gateway-approval-requested"
ACTION_GATEWAY_APPROVAL_DENIED: Final[str] = "gateway-approval-denied"
ACTION_GATEWAY_APPROVAL_GRANTED: Final[str] = "gateway-approval-granted"
ACTION_GATEWAY_APPROVAL_PENDING: Final[str] = "gateway-approval-pending"
ACTION_GATEWAY_MULTI_TURN_INJECTION: Final[str] = "gateway-multi-turn-injection"
ACTION_GATEWAY_DOWN: Final[str] = "gateway-down"
ACTION_GATEWAY_RECOVERED: Final[str] = "gateway-recovered"
ACTION_GATEWAY_DEGRADED: Final[str] = "gateway-degraded"
ACTION_TOOL_RESULT_PII_ALERT: Final[str] = "tool-result-pii-alert"

# Gateway judge-bodies / judge-store sidecar lifecycle.
ACTION_GATEWAY_JUDGE_BODIES_READY: Final[str] = "gateway.judge_bodies.ready"
ACTION_GATEWAY_JUDGE_BODIES_FALLBACK: Final[str] = "gateway.judge_bodies.fallback"
ACTION_GATEWAY_JUDGE_BODIES_CLOSE_SKIPPED: Final[str] = "gateway.judge_bodies.close_skipped"
ACTION_GATEWAY_JUDGE_BODIES_CLOSE_ERROR: Final[str] = "gateway.judge_bodies.close_error"
ACTION_GATEWAY_JUDGE_STORE_DRAIN_TIMEOUT: Final[str] = "gateway.judge_store.drain_timeout"

# Guardrail and inspect instrumentation.
ACTION_GUARDRAIL_START: Final[str] = "guardrail-start"
ACTION_GUARDRAIL_HEALTHY: Final[str] = "guardrail-healthy"
ACTION_GUARDRAIL_VERDICT: Final[str] = "guardrail-verdict"
ACTION_GUARDRAIL_INSPECTION: Final[str] = "guardrail-inspection"
ACTION_GUARDRAIL_OPA_INSPECTION: Final[str] = "guardrail-opa-inspection"
ACTION_GUARDRAIL_OPA_VERDICT: Final[str] = "guardrail-opa-verdict"
ACTION_GUARDRAIL_CONFIG_RELOAD: Final[str] = "guardrail-config-reload"
ACTION_GUARDRAIL_DEGRADED: Final[str] = "guardrail-degraded"
ACTION_GUARDRAIL_LAUNDER: Final[str] = "guardrail-launder"
ACTION_GUARDRAIL_NOTIFY_INJECT: Final[str] = "guardrail-notify-inject"
ACTION_GUARDRAIL_TOOL_CALL_PARSE_ERROR: Final[str] = "guardrail-tool-call-parse-error"
ACTION_GUARDRAIL_TOOL_CALL_INSPECT: Final[str] = "guardrail-tool-call-inspect"
ACTION_GUARDRAIL_DISABLE: Final[str] = "guardrail-disable"
ACTION_GUARDRAIL_ENABLE: Final[str] = "guardrail-enable"
ACTION_GUARDRAIL_FAIL_MODE: Final[str] = "guardrail-fail-mode"
ACTION_GUARDRAIL_HILT: Final[str] = "guardrail-hilt"
ACTION_GUARDRAIL_BLOCK_MESSAGE: Final[str] = "guardrail-block-message"
ACTION_LLM_JUDGE_RESPONSE: Final[str] = "llm-judge-response"
ACTION_INSPECT_TOOL_CONFIRM: Final[str] = "inspect-tool-confirm"
ACTION_INSPECT_TOOL_BLOCK: Final[str] = "inspect-tool-block"
ACTION_INSPECT_TOOL_ALERT: Final[str] = "inspect-tool-alert"
ACTION_INSPECT_TOOL_ALLOW: Final[str] = "inspect-tool-allow"
ACTION_INSPECT_REVEAL: Final[str] = "inspect-reveal"

# Setup, operator, API, and sink instrumentation.
ACTION_API_AUTH_FAILURE: Final[str] = "api-auth-failure"
ACTION_API_CONFIG_PATCH: Final[str] = "api-config-patch"
ACTION_API_ENFORCE_ALLOW: Final[str] = "api-enforce-allow"
ACTION_API_ENFORCE_BLOCK: Final[str] = "api-enforce-block"
ACTION_API_ENFORCE_UNBLOCK: Final[str] = "api-enforce-unblock"
ACTION_API_MCP_SCAN: Final[str] = "api-mcp-scan"
ACTION_API_PLUGIN_DISABLE: Final[str] = "api-plugin-disable"
ACTION_API_PLUGIN_ENABLE: Final[str] = "api-plugin-enable"
ACTION_API_PLUGIN_SCAN: Final[str] = "api-plugin-scan"
ACTION_API_SKILL_DISABLE: Final[str] = "api-skill-disable"
ACTION_API_SKILL_ENABLE: Final[str] = "api-skill-enable"
ACTION_API_SKILL_FETCH: Final[str] = "api-skill-fetch"
ACTION_API_SKILL_SCAN: Final[str] = "api-skill-scan"
ACTION_SINK_FLUSH_ERROR: Final[str] = "sink-flush-error"
ACTION_SETUP_SKILL_SCANNER: Final[str] = "setup-skill-scanner"
ACTION_SETUP_MCP_SCANNER: Final[str] = "setup-mcp-scanner"
ACTION_SETUP_GATEWAY: Final[str] = "setup-gateway"
ACTION_SETUP_GUARDRAIL: Final[str] = "setup-guardrail"
ACTION_SETUP_HOOK_CONNECTOR: Final[str] = "setup-hook-connector"
ACTION_SETUP_CONNECTOR_MODE: Final[str] = "setup-connector-mode"
ACTION_SETUP_REDACTION_TOGGLE: Final[str] = "setup-redaction-toggle"
ACTION_SETUP_NOTIFICATIONS_TOGGLE: Final[str] = "setup-notifications-toggle"
ACTION_SETUP_NOTIFICATIONS_SET: Final[str] = "setup-notifications-set"
ACTION_SETUP_SPLUNK: Final[str] = "setup-splunk"
ACTION_SETUP_OBSERVABILITY: Final[str] = "setup-observability"
ACTION_SETUP_LOCAL_OBSERVABILITY: Final[str] = "setup-local-observability"
ACTION_SETUP_WEBHOOK: Final[str] = "setup-webhook"
ACTION_DOCTOR: Final[str] = "doctor"
ACTION_UPGRADE: Final[str] = "upgrade"
ACTION_INIT_GATEWAY: Final[str] = "init-gateway"
ACTION_INIT_GUARDRAIL: Final[str] = "init-guardrail"
ACTION_INIT_NOTIFICATIONS_TOGGLE: Final[str] = "init-notifications-toggle"
ACTION_INIT_SANDBOX: Final[str] = "init-sandbox"
ACTION_INIT_SIDECAR: Final[str] = "init-sidecar"
ACTION_POLICY_CREATE: Final[str] = "policy-create"
ACTION_POLICY_ACTIVATE: Final[str] = "policy-activate"
ACTION_POLICY_DELETE: Final[str] = "policy-delete"
ACTION_REGISTRY_ADD: Final[str] = "registry-add"
ACTION_REGISTRY_EDIT: Final[str] = "registry-edit"
ACTION_REGISTRY_REMOVE: Final[str] = "registry-remove"
ACTION_SCAN_ENFORCED: Final[str] = "scan-enforced"
ACTION_SCAN_FINDING: Final[str] = "scan-finding"
ACTION_DISMISS_ALERT: Final[str] = "dismiss-alert"
ACTION_SKILL_BLOCK: Final[str] = "skill-block"
ACTION_SKILL_UNBLOCK: Final[str] = "skill-unblock"
ACTION_SKILL_ALLOW: Final[str] = "skill-allow"
ACTION_SKILL_DISABLE: Final[str] = "skill-disable"
ACTION_SKILL_ENABLE: Final[str] = "skill-enable"
ACTION_SKILL_QUARANTINE: Final[str] = "skill-quarantine"
ACTION_SKILL_RESTORE: Final[str] = "skill-restore"
ACTION_PLUGIN_INSTALL: Final[str] = "plugin-install"
ACTION_PLUGIN_REMOVE: Final[str] = "plugin-remove"
ACTION_PLUGIN_BLOCK: Final[str] = "plugin-block"
ACTION_PLUGIN_ALLOW: Final[str] = "plugin-allow"
ACTION_PLUGIN_DISABLE: Final[str] = "plugin-disable"
ACTION_PLUGIN_ENABLE: Final[str] = "plugin-enable"
ACTION_PLUGIN_QUARANTINE: Final[str] = "plugin-quarantine"
ACTION_PLUGIN_RESTORE: Final[str] = "plugin-restore"
ACTION_BLOCK_MCP: Final[str] = "block-mcp"
ACTION_ALLOW_MCP: Final[str] = "allow-mcp"
ACTION_MCP_UNBLOCK: Final[str] = "mcp-unblock"
ACTION_MCP_SET: Final[str] = "mcp-set"
ACTION_MCP_SET_BLOCKED: Final[str] = "mcp-set-blocked"
ACTION_MCP_UNSET: Final[str] = "mcp-unset"
ACTION_TOOL_BLOCK: Final[str] = "tool-block"
ACTION_TOOL_ALLOW: Final[str] = "tool-allow"
ACTION_TOOL_UNBLOCK: Final[str] = "tool-unblock"


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
    ACTION_CONNECTOR_HOOK,
    ACTION_CONNECTOR_HOOK_SYNTHETIC,
    ACTION_ASSET_POLICY,
    ACTION_CONNECTOR_HOOK_TAMPERED,
    ACTION_CONNECTOR_HOOK_REPAIRED,
    ACTION_CODEX_NOTIFY,
    ACTION_CODEX_NOTIFY_AGENT_TURN_COMPLETE,
    ACTION_CODEX_NOTIFY_MALFORMED,
    ACTION_SIDECAR_START,
    ACTION_SIDECAR_STOP,
    ACTION_SIDECAR_CONNECTED,
    ACTION_SIDECAR_DISCONNECTED,
    ACTION_SIDECAR_WATCHER_VERDICT,
    ACTION_SIDECAR_WATCHER_DISABLE,
    ACTION_SIDECAR_WATCHER_DISABLE_PLUGIN,
    ACTION_SIDECAR_WATCHER_BLOCK_MCP,
    ACTION_BOOTSTRAP,
    ACTION_WATCH_START,
    ACTION_WATCH_STOP,
    ACTION_WATCHER_BLOCK,
    ACTION_INSTALL_DETECTED,
    ACTION_INSTALL_REJECTED,
    ACTION_INSTALL_ALLOWED,
    ACTION_INSTALL_ALLOWED_SKIP_ENFORCE,
    ACTION_INSTALL_CLEAN,
    ACTION_INSTALL_WARNING,
    ACTION_INSTALL_SCAN_ERROR,
    ACTION_INSTALL_ENFORCED,
    ACTION_INSTALL_BLOCKED,
    ACTION_INSTALL_DEP,
    ACTION_GATEWAY_READY,
    ACTION_GATEWAY_SESSION_MESSAGE,
    ACTION_GATEWAY_SESSION_PROMPT_ALERT,
    ACTION_GATEWAY_SESSION_ERROR,
    ACTION_GATEWAY_CHAT_ERROR,
    ACTION_GATEWAY_AGENT_START,
    ACTION_GATEWAY_AGENT_END,
    ACTION_GATEWAY_AGENT_ERROR,
    ACTION_GATEWAY_TOOL_CALL,
    ACTION_GATEWAY_TOOL_CALL_BLOCKED,
    ACTION_GATEWAY_TOOL_CALL_FLAGGED,
    ACTION_GATEWAY_TOOL_CALL_JUDGE_FLAGGED,
    ACTION_GATEWAY_TOOL_RESULT,
    ACTION_GATEWAY_APPROVAL_REQUESTED,
    ACTION_GATEWAY_APPROVAL_DENIED,
    ACTION_GATEWAY_APPROVAL_GRANTED,
    ACTION_GATEWAY_APPROVAL_PENDING,
    ACTION_GATEWAY_MULTI_TURN_INJECTION,
    ACTION_GATEWAY_DOWN,
    ACTION_GATEWAY_RECOVERED,
    ACTION_GATEWAY_DEGRADED,
    ACTION_TOOL_RESULT_PII_ALERT,
    ACTION_GATEWAY_JUDGE_BODIES_READY,
    ACTION_GATEWAY_JUDGE_BODIES_FALLBACK,
    ACTION_GATEWAY_JUDGE_BODIES_CLOSE_SKIPPED,
    ACTION_GATEWAY_JUDGE_BODIES_CLOSE_ERROR,
    ACTION_GATEWAY_JUDGE_STORE_DRAIN_TIMEOUT,
    ACTION_GUARDRAIL_START,
    ACTION_GUARDRAIL_HEALTHY,
    ACTION_GUARDRAIL_VERDICT,
    ACTION_GUARDRAIL_INSPECTION,
    ACTION_GUARDRAIL_OPA_INSPECTION,
    ACTION_GUARDRAIL_OPA_VERDICT,
    ACTION_GUARDRAIL_CONFIG_RELOAD,
    ACTION_GUARDRAIL_DEGRADED,
    ACTION_GUARDRAIL_LAUNDER,
    ACTION_GUARDRAIL_NOTIFY_INJECT,
    ACTION_GUARDRAIL_TOOL_CALL_PARSE_ERROR,
    ACTION_GUARDRAIL_TOOL_CALL_INSPECT,
    ACTION_GUARDRAIL_DISABLE,
    ACTION_GUARDRAIL_ENABLE,
    ACTION_GUARDRAIL_FAIL_MODE,
    ACTION_GUARDRAIL_HILT,
    ACTION_GUARDRAIL_BLOCK_MESSAGE,
    ACTION_LLM_JUDGE_RESPONSE,
    ACTION_INSPECT_TOOL_CONFIRM,
    ACTION_INSPECT_TOOL_BLOCK,
    ACTION_INSPECT_TOOL_ALERT,
    ACTION_INSPECT_TOOL_ALLOW,
    ACTION_INSPECT_REVEAL,
    ACTION_API_AUTH_FAILURE,
    ACTION_API_CONFIG_PATCH,
    ACTION_API_ENFORCE_ALLOW,
    ACTION_API_ENFORCE_BLOCK,
    ACTION_API_ENFORCE_UNBLOCK,
    ACTION_API_MCP_SCAN,
    ACTION_API_PLUGIN_DISABLE,
    ACTION_API_PLUGIN_ENABLE,
    ACTION_API_PLUGIN_SCAN,
    ACTION_API_SKILL_DISABLE,
    ACTION_API_SKILL_ENABLE,
    ACTION_API_SKILL_FETCH,
    ACTION_API_SKILL_SCAN,
    ACTION_SINK_FLUSH_ERROR,
    ACTION_SETUP_SKILL_SCANNER,
    ACTION_SETUP_MCP_SCANNER,
    ACTION_SETUP_GATEWAY,
    ACTION_SETUP_GUARDRAIL,
    ACTION_SETUP_HOOK_CONNECTOR,
    ACTION_SETUP_CONNECTOR_MODE,
    ACTION_SETUP_REDACTION_TOGGLE,
    ACTION_SETUP_NOTIFICATIONS_TOGGLE,
    ACTION_SETUP_NOTIFICATIONS_SET,
    ACTION_SETUP_SPLUNK,
    ACTION_SETUP_OBSERVABILITY,
    ACTION_SETUP_LOCAL_OBSERVABILITY,
    ACTION_SETUP_WEBHOOK,
    ACTION_DOCTOR,
    ACTION_UPGRADE,
    ACTION_INIT_GATEWAY,
    ACTION_INIT_GUARDRAIL,
    ACTION_INIT_NOTIFICATIONS_TOGGLE,
    ACTION_INIT_SANDBOX,
    ACTION_INIT_SIDECAR,
    ACTION_POLICY_CREATE,
    ACTION_POLICY_ACTIVATE,
    ACTION_POLICY_DELETE,
    ACTION_REGISTRY_ADD,
    ACTION_REGISTRY_EDIT,
    ACTION_REGISTRY_REMOVE,
    ACTION_SCAN_ENFORCED,
    ACTION_SCAN_FINDING,
    ACTION_DISMISS_ALERT,
    ACTION_SKILL_BLOCK,
    ACTION_SKILL_UNBLOCK,
    ACTION_SKILL_ALLOW,
    ACTION_SKILL_DISABLE,
    ACTION_SKILL_ENABLE,
    ACTION_SKILL_QUARANTINE,
    ACTION_SKILL_RESTORE,
    ACTION_PLUGIN_INSTALL,
    ACTION_PLUGIN_REMOVE,
    ACTION_PLUGIN_BLOCK,
    ACTION_PLUGIN_ALLOW,
    ACTION_PLUGIN_DISABLE,
    ACTION_PLUGIN_ENABLE,
    ACTION_PLUGIN_QUARANTINE,
    ACTION_PLUGIN_RESTORE,
    ACTION_BLOCK_MCP,
    ACTION_ALLOW_MCP,
    ACTION_MCP_UNBLOCK,
    ACTION_MCP_SET,
    ACTION_MCP_SET_BLOCKED,
    ACTION_MCP_UNSET,
    ACTION_TOOL_BLOCK,
    ACTION_TOOL_ALLOW,
    ACTION_TOOL_UNBLOCK,
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
