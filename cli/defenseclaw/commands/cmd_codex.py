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

"""Runtime bridge for Codex hooks."""

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


@click.group()
def codex() -> None:
    """Codex hook runtime integration."""


@codex.command("hook")
@click.option("--event", "event_name", default=None, help="Override hook_event_name when stdin is missing it.")
def codex_hook(event_name: str | None) -> None:
    """Run one DefenseClaw Codex hook evaluation.

    This command is called by Codex. It must keep stdout machine-readable:
    diagnostics go to stderr, and fail-open cases emit no output except for
    Stop, where Codex expects JSON when output is present.
    """
    payload = _read_hook_payload()
    if event_name and not payload.get("hook_event_name"):
        payload["hook_event_name"] = event_name

    cfg = _load_config_for_hook()
    if not getattr(cfg, "codex", None) or not cfg.codex.enabled:
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
        response = client.codex_hook(_normalize_payload(payload), headers=headers, timeout=_timeout_for(payload))
    except (requests.RequestException, OSError, ValueError) as exc:
        print(f"defenseclaw codex hook: sidecar unavailable; allowing Codex to continue ({exc})", file=sys.stderr)
        _emit_fail_open(payload, fail_closed=bool(getattr(cfg.codex, "fail_closed", False)))
        return

    codex_output = response.get("codex_output")
    if isinstance(codex_output, dict) and codex_output:
        click.echo(json.dumps(codex_output, separators=(",", ":")))


def _read_hook_payload() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"defenseclaw codex hook: invalid JSON payload; allowing Codex to continue ({exc})", file=sys.stderr)
        return {}
    if not isinstance(parsed, dict):
        print("defenseclaw codex hook: payload was not an object; allowing Codex to continue", file=sys.stderr)
        return {}
    return parsed


def _load_config_for_hook():
    try:
        return cfg_mod.load()
    except Exception as exc:
        print(f"defenseclaw codex hook: config unavailable; using defaults ({exc})", file=sys.stderr)
        return cfg_mod.default_config()


def _normalize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {"raw": tool_input}
    return {
        "hook_event_name": payload.get("hook_event_name", ""),
        "session_id": payload.get("session_id", ""),
        "turn_id": payload.get("turn_id", ""),
        "transcript_path": payload.get("transcript_path"),
        "cwd": payload.get("cwd", ""),
        "model": payload.get("model", ""),
        "source": payload.get("source", ""),
        "tool_name": payload.get("tool_name", ""),
        "tool_use_id": payload.get("tool_use_id", ""),
        "tool_input": tool_input,
        "tool_response": payload.get("tool_response"),
        "prompt": payload.get("prompt", ""),
        "stop_hook_active": payload.get("stop_hook_active", False),
        "last_assistant_message": payload.get("last_assistant_message"),
        "bridge": {
            "name": "defenseclaw-python-cli",
            "command": "defenseclaw codex hook",
        },
    }


def _correlation_headers(payload: dict[str, Any]) -> dict[str, str]:
    trace_id = secrets.token_hex(16)
    span_id = secrets.token_hex(8)
    headers = {
        "X-DefenseClaw-Request-Id": str(uuid.uuid4()),
        "X-DefenseClaw-Agent-Id": "codex",
        "X-DefenseClaw-Destination-App": "codex",
        "traceparent": f"00-{trace_id}-{span_id}-01",
    }
    session_id = str(payload.get("session_id") or "")
    if session_id:
        headers["X-DefenseClaw-Session-Id"] = session_id
    return headers


def _timeout_for(payload: dict[str, Any]) -> int:
    event = str(payload.get("hook_event_name") or "")
    if event == "Stop":
        return 90
    if event == "SessionStart":
        return 45
    return 20


def _emit_fail_open(payload: dict[str, Any], fail_closed: bool = False) -> None:
    event = str(payload.get("hook_event_name") or "")
    if fail_closed and event in {"PreToolUse", "PermissionRequest", "UserPromptSubmit"}:
        reason = "DefenseClaw Codex hook could not reach the sidecar and fail_closed is enabled."
        if event == "PreToolUse":
            out = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        elif event == "PermissionRequest":
            out = {
                "hookSpecificOutput": {
                    "hookEventName": "PermissionRequest",
                    "decision": {"behavior": "deny", "message": reason},
                }
            }
        else:
            out = {"decision": "block", "reason": reason}
        click.echo(json.dumps(out, separators=(",", ":")))
        return

    if event == "Stop":
        click.echo(json.dumps({"continue": True}, separators=(",", ":")))

