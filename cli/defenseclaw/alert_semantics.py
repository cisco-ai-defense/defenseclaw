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

# Decision codes of refusals that are audited only and never alerts: a
# sandbox harness's own request that it does without (GAP-0130), and
# OpenShell's refusal of a name lookup, whose connection is refused (and
# alerted) on its own (GAP-0134). Mirrors SandboxEgressCodeHarnessFetch and
# SandboxEgressCodeLookupRefused in internal/audit/store.go.
ALERT_AUDIT_ONLY_DECISION_CODES = ("SANDBOX_EGRESS_HARNESS_FETCH", "SANDBOX_EGRESS_LOOKUP_REFUSED")

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

# The VS Code Local harness runs Copilot hooks under Claude-style event names
# (PreToolUse); the Copilot CLI sends the camelCase names Setup registers
# (preToolUse). Alerts show the CLI name for both, so one hook point is not
# split in two (GAP-2619). Mirrors copilotCLIHookFileLocalEvents in
# internal/gateway/connector/hook_only_copilot_vscode.go.
_COPILOT_LOCAL_TO_CLI_EVENT = {
    "SessionStart": "sessionStart",
    "UserPromptSubmit": "userPromptSubmitted",
    "PreToolUse": "preToolUse",
    "PostToolUse": "postToolUse",
    "Stop": "agentStop",
    "SubagentStop": "subagentStop",
}


def copilot_hook_target(target: str, connector: str = "") -> str:
    """``copilot:PreToolUse`` -> ``copilot:preToolUse``; a bare ``PreToolUse``
    becomes ``preToolUse`` when ``connector`` is copilot. Other targets are
    returned unchanged."""
    text = target or ""
    head, sep, event = text.partition(":")
    if sep and head.strip().lower() == "copilot":
        cli = _COPILOT_LOCAL_TO_CLI_EVENT.get(event.strip())
        return f"{head}:{cli}" if cli else text
    if (connector or "").strip().lower() == "copilot":
        return _COPILOT_LOCAL_TO_CLI_EVENT.get(text.strip(), text)
    return text


_COPILOT_CLI_TO_LOCAL_EVENT = {cli: local for local, cli in _COPILOT_LOCAL_TO_CLI_EVENT.items()}


def copilot_hook_target_spellings(target: str, connector: str = "") -> tuple[str, ...]:
    """Every stored spelling of one Copilot hook target, canonical first:
    ``copilot:PreToolUse`` -> (``copilot:preToolUse``, ``copilot:PreToolUse``).
    A bare event name expands only when ``connector`` is copilot. Lookups by
    target use it so both harnesses match (GAP-2619); any other target gives
    a one-item tuple."""
    text = target or ""
    canonical = copilot_hook_target(text, connector)
    head, sep, event = canonical.partition(":")
    if sep and head.strip().lower() == "copilot":
        local = _COPILOT_CLI_TO_LOCAL_EVENT.get(event.strip())
        return (canonical, f"{head}:{local}") if local else (text,)
    if not sep and (connector or "").strip().lower() == "copilot":
        local = _COPILOT_CLI_TO_LOCAL_EVENT.get(canonical.strip())
        return (canonical, local) if local else (text,)
    return (text,)
