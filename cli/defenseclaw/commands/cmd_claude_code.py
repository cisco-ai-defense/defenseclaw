# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Runtime bridge for Claude Code hooks."""

from __future__ import annotations

import json
import secrets
import sys
import uuid
from typing import Any

import click
import requests

from defenseclaw import config as cfg_mod
from defenseclaw.gateway import OrchestratorClient


@click.group(name="claude-code")
def claude_code() -> None:
    """Claude Code hook runtime integration."""


@claude_code.command("hook")
@click.option("--event", "event_name", default=None, help="Override hook_event_name when stdin is missing it.")
def claude_code_hook(event_name: str | None) -> None:
    """Run one DefenseClaw Claude Code hook evaluation."""
    payload = _read_hook_payload()
    if event_name and not payload.get("hook_event_name"):
        payload["hook_event_name"] = event_name

    cfg = _load_config_for_hook()
    if not getattr(cfg, "claude_code", None) or not cfg.claude_code.enabled:
        _emit_fail_open(payload)
        return

    headers = _correlation_headers(payload)
    try:
        client = OrchestratorClient(
            host=cfg.gateway.host or "127.0.0.1",
            port=cfg.gateway.api_port,
            timeout=5,
            token=cfg.gateway.resolved_token(),
        )
        response = client.claude_code_hook(_normalize_payload(payload), headers=headers, timeout=_timeout_for(payload))
    except (requests.RequestException, OSError, ValueError) as exc:
        print(f"defenseclaw claude-code hook: sidecar unavailable; allowing Claude Code to continue ({exc})", file=sys.stderr)
        _emit_fail_open(payload, fail_closed=bool(getattr(cfg.claude_code, "fail_closed", False)))
        return

    hook_output = response.get("claude_code_output")
    if isinstance(hook_output, dict) and hook_output:
        click.echo(json.dumps(hook_output, separators=(",", ":")))


def _read_hook_payload() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"defenseclaw claude-code hook: invalid JSON payload; allowing Claude Code to continue ({exc})", file=sys.stderr)
        return {}
    if not isinstance(parsed, dict):
        print("defenseclaw claude-code hook: payload was not an object; allowing Claude Code to continue", file=sys.stderr)
        return {}
    return parsed


def _load_config_for_hook():
    try:
        return cfg_mod.load()
    except Exception as exc:
        print(f"defenseclaw claude-code hook: config unavailable; using defaults ({exc})", file=sys.stderr)
        return cfg_mod.default_config()


def _normalize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {"raw": tool_input}
    normalized = dict(payload)
    normalized["hook_event_name"] = payload.get("hook_event_name", "")
    normalized["tool_input"] = tool_input
    normalized["bridge"] = {
        "name": "defenseclaw-python-cli",
        "command": "defenseclaw claude-code hook",
    }
    return normalized


def _correlation_headers(payload: dict[str, Any]) -> dict[str, str]:
    trace_id = secrets.token_hex(16)
    span_id = secrets.token_hex(8)
    headers = {
        "X-DefenseClaw-Request-Id": str(uuid.uuid4()),
        "X-DefenseClaw-Agent-Id": "claude-code",
        "X-DefenseClaw-Destination-App": "claude-code",
        "traceparent": f"00-{trace_id}-{span_id}-01",
    }
    session_id = str(payload.get("session_id") or "")
    if session_id:
        headers["X-DefenseClaw-Session-Id"] = session_id
    return headers


def _timeout_for(payload: dict[str, Any]) -> int:
    event = str(payload.get("hook_event_name") or "")
    if event == "SessionEnd":
        return 60
    if event in {"Stop", "SubagentStop", "PostToolBatch"}:
        return 90
    if event == "SessionStart":
        return 45
    return 20


def _emit_fail_open(payload: dict[str, Any], fail_closed: bool = False) -> None:
    event = str(payload.get("hook_event_name") or "")
    if fail_closed and event in _FAIL_CLOSED_EVENTS:
        reason = "DefenseClaw Claude Code hook could not reach the sidecar and fail_closed is enabled."
        click.echo(json.dumps(_deny_output(event, reason), separators=(",", ":")))


_FAIL_CLOSED_EVENTS = {
    "UserPromptSubmit",
    "UserPromptExpansion",
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "PostToolBatch",
    "TaskCreated",
    "TaskCompleted",
    "Stop",
    "SubagentStop",
    "TeammateIdle",
    "ConfigChange",
    "PreCompact",
    "Elicitation",
    "ElicitationResult",
}


def _deny_output(event: str, reason: str) -> dict[str, Any]:
    if event == "PreToolUse":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
    if event == "PermissionRequest":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {"behavior": "deny", "message": reason},
            }
        }
    if event in {"TaskCreated", "TaskCompleted", "TeammateIdle"}:
        return {"continue": False, "stopReason": reason}
    if event in {"Elicitation", "ElicitationResult"}:
        return {
            "hookSpecificOutput": {
                "hookEventName": event,
                "action": "decline",
                "content": {},
            }
        }
    return {"decision": "block", "reason": reason}
