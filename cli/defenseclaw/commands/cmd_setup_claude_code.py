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

"""`defenseclaw setup claude-code` — install and inspect Claude Code hooks."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import click
import requests

from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.gateway import OrchestratorClient

_OWNED_COMMAND = "defenseclaw claude-code hook"

_CLAUDE_CODE_EVENTS = (
    "SessionStart",
    "InstructionsLoaded",
    "UserPromptSubmit",
    "UserPromptExpansion",
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "PostToolUseFailure",
    "PostToolBatch",
    "PermissionDenied",
    "Notification",
    "SubagentStart",
    "SubagentStop",
    "TaskCreated",
    "TaskCompleted",
    "Stop",
    "StopFailure",
    "TeammateIdle",
    "ConfigChange",
    "CwdChanged",
    "FileChanged",
    "WorktreeRemove",
    "PreCompact",
    "PostCompact",
    "SessionEnd",
    "Elicitation",
    "ElicitationResult",
)

_TOOL_EVENTS = {"PreToolUse", "PermissionRequest", "PostToolUse", "PostToolUseFailure", "PermissionDenied"}
_FILE_MATCHER = "CLAUDE.md|.claude/settings.json|.claude/settings.local.json|.mcp.json|.env|.envrc|package.json|pyproject.toml|go.mod|Cargo.toml|requirements.txt"


@click.command("claude-code")
@click.option("--non-interactive", is_flag=True, help="Use defaults instead of prompts.")
@click.option("--scope", type=click.Choice(["user", "repo"]), default=None,
              help="Where to install hooks (default from config, then user).")
@click.option("--scan-on-session-start/--no-scan-on-session-start", default=None,
              help="Enable or disable Claude Code component scans on SessionStart.")
@click.option("--scan-on-stop/--no-scan-on-stop", default=None,
              help="Enable or disable CodeGuard scans from Stop/SubagentStop/SessionEnd hooks.")
@click.option("--fail-closed/--fail-open", default=None,
              help="Block eligible events when the hook bridge cannot reach the sidecar.")
@click.option("--disable", is_flag=True, help="Remove DefenseClaw-owned Claude Code hooks.")
@click.option("--status", "show_status", is_flag=True, help="Show Claude Code integration status.")
@click.option("--scan-components", is_flag=True, help="Ask the sidecar to scan Claude Code skills/plugins/MCP config now.")
@click.option("--dry-run", is_flag=True, help="Show what would change without writing files.")
@click.option("--force", is_flag=True, help="Replace invalid settings JSON instead of failing.")
@pass_ctx
def claude_code_setup(
    app: AppContext,
    non_interactive: bool,
    scope: str | None,
    scan_on_session_start: bool | None,
    scan_on_stop: bool | None,
    fail_closed: bool | None,
    disable: bool,
    show_status: bool,
    scan_components: bool,
    dry_run: bool,
    force: bool,
) -> None:
    """Configure DefenseClaw hooks for Claude Code."""
    cfg = app.cfg
    scope = scope or getattr(getattr(cfg, "claude_code", None), "install_scope", "") or "user"
    if scan_on_session_start is not None:
        cfg.claude_code.scan_on_session_start = scan_on_session_start
    if scan_on_stop is not None:
        cfg.claude_code.scan_on_stop = scan_on_stop
    if fail_closed is not None:
        cfg.claude_code.fail_closed = fail_closed

    if show_status:
        _print_status(cfg, scope)
        return

    if not non_interactive and not disable:
        click.echo()
        click.echo("  Claude Code Integration Setup")
        click.echo()
        scope = click.prompt("  Install scope", type=click.Choice(["user", "repo"]), default=scope)
        cfg.claude_code.scan_on_session_start = click.confirm(
            "  Scan Claude Code components when a session starts",
            default=cfg.claude_code.scan_on_session_start,
        )
        cfg.claude_code.scan_on_stop = click.confirm(
            "  Scan changed files when a turn/subagent/session stops",
            default=cfg.claude_code.scan_on_stop,
        )
        cfg.claude_code.fail_closed = click.confirm(
            "  Fail closed if the sidecar is unavailable",
            default=cfg.claude_code.fail_closed,
        )

    settings_path = _settings_path(scope)

    if disable:
        changed = _write_settings(settings_path, install=False, dry_run=dry_run, force=force)
        if not dry_run:
            cfg.claude_code.enabled = False
            cfg.save()
        if changed:
            click.echo(f"  Claude Code hooks removed from {settings_path}")
        else:
            click.echo(f"  No DefenseClaw Claude Code hooks found in {settings_path}")
        return

    changed = _write_settings(settings_path, install=True, dry_run=dry_run, force=force)
    if not dry_run:
        cfg.claude_code.enabled = True
        cfg.claude_code.install_scope = scope
        cfg.save()

    click.echo(f"  Claude Code hooks {'would be installed' if dry_run else 'installed'}: {settings_path}")
    if changed:
        click.echo("  Hook events: " + ", ".join(_CLAUDE_CODE_EVENTS))
        click.echo("  Note: WorktreeCreate is intentionally not installed because Claude Code hooks replace default worktree behavior.")

    _print_sidecar_line(cfg)

    if scan_components:
        _scan_components(cfg, dry_run=dry_run)

    if app.logger and not dry_run:
        app.logger.log_action("setup-claude-code", "config", f"scope={scope} settings={settings_path}")


def _settings_path(scope: str) -> Path:
    if scope == "repo":
        root = _git_root()
        return root / ".claude" / "settings.local.json"
    return Path.home() / ".claude" / "settings.json"


def _git_root() -> Path:
    try:
        out = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True, stderr=subprocess.DEVNULL)
        return Path(out.strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        return Path.cwd()


def _write_settings(path: Path, *, install: bool, dry_run: bool, force: bool) -> bool:
    data = _load_settings(path, force=force)
    before = json.dumps(data, sort_keys=True)
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        if not force:
            raise click.ClickException(f"{path} has invalid hooks shape; use --force to replace it")
        hooks = {}
        data["hooks"] = hooks

    _remove_owned_hooks(hooks)
    if install:
        for event in _CLAUDE_CODE_EVENTS:
            hooks.setdefault(event, []).append(_hook_group(event))

    after = json.dumps(data, sort_keys=True)
    changed = before != after
    if changed and not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")
    return changed


def _load_settings(path: Path, *, force: bool) -> dict[str, Any]:
    if not path.exists():
        return {"hooks": {}}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        if force:
            return {"hooks": {}}
        raise click.ClickException(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        if force:
            return {"hooks": {}}
        raise click.ClickException(f"{path} must contain a JSON object")
    return data


def _remove_owned_hooks(hooks: dict[str, Any]) -> None:
    for event, groups in list(hooks.items()):
        if not isinstance(groups, list):
            continue
        kept_groups = []
        for group in groups:
            if not isinstance(group, dict):
                kept_groups.append(group)
                continue
            entries = group.get("hooks")
            if not isinstance(entries, list):
                kept_groups.append(group)
                continue
            kept_entries = [h for h in entries if not _is_owned_hook(h)]
            if kept_entries:
                g = dict(group)
                g["hooks"] = kept_entries
                kept_groups.append(g)
        if kept_groups:
            hooks[event] = kept_groups
        else:
            hooks.pop(event, None)


def _is_owned_hook(entry: Any) -> bool:
    return isinstance(entry, dict) and _OWNED_COMMAND in str(entry.get("command", ""))


def _hook_group(event: str) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "type": "command",
        "command": _OWNED_COMMAND,
        "statusMessage": _status_message(event),
        "timeout": 60 if event == "SessionEnd" else 90 if event in {"Stop", "SubagentStop", "PostToolBatch"} else 30,
    }
    group: dict[str, Any] = {"hooks": [entry]}
    if event in _TOOL_EVENTS:
        group["matcher"] = "*"
    elif event == "SessionStart":
        group["matcher"] = "startup|resume|clear|compact"
    elif event == "InstructionsLoaded":
        group["matcher"] = "*"
    elif event == "FileChanged":
        group["matcher"] = _FILE_MATCHER
    elif event in {"Notification", "SubagentStart", "SubagentStop", "StopFailure", "ConfigChange",
                   "PreCompact", "PostCompact", "Elicitation", "ElicitationResult"}:
        group["matcher"] = "*"
    return group


def _status_message(event: str) -> str:
    return {
        "SessionStart": "DefenseClaw: scanning Claude Code components",
        "InstructionsLoaded": "DefenseClaw: reviewing loaded instructions",
        "UserPromptSubmit": "DefenseClaw: scanning prompt",
        "UserPromptExpansion": "DefenseClaw: checking expanded prompt",
        "PreToolUse": "DefenseClaw: checking tool input",
        "PermissionRequest": "DefenseClaw: checking permission request",
        "PostToolUse": "DefenseClaw: reviewing tool output",
        "PostToolUseFailure": "DefenseClaw: reviewing failed tool output",
        "PostToolBatch": "DefenseClaw: reviewing tool batch",
        "PermissionDenied": "DefenseClaw: recording permission denial",
        "Stop": "DefenseClaw: scanning changed code",
        "SubagentStop": "DefenseClaw: scanning subagent changes",
        "SessionEnd": "DefenseClaw: final session scan",
        "FileChanged": "DefenseClaw: checking changed file",
        "ConfigChange": "DefenseClaw: checking config change",
    }.get(event, "DefenseClaw: checking Claude Code event")


def _hooks_installed(path: Path) -> bool:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict):
        return False
    seen = set()
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            continue
        for group in groups:
            for entry in group.get("hooks", []) if isinstance(group, dict) else []:
                if _is_owned_hook(entry):
                    seen.add(event)
    return all(event in seen for event in _CLAUDE_CODE_EVENTS)


def _print_status(cfg: Any, scope: str) -> None:
    settings_path = _settings_path(scope)
    click.echo("  Claude Code integration")
    click.echo(f"    enabled:      {getattr(cfg.claude_code, 'enabled', False)}")
    click.echo(f"    mode:         {getattr(cfg.claude_code, 'mode', 'inherit')}")
    click.echo(f"    scope:        {scope}")
    click.echo(f"    hooks:        {'installed' if _hooks_installed(settings_path) else 'not installed'} ({settings_path})")
    _print_sidecar_line(cfg)


def _print_sidecar_line(cfg: Any) -> None:
    try:
        client = _client(cfg)
        client.health()
        click.echo(f"    sidecar:      reachable ({client.base_url})")
    except Exception as exc:
        click.echo(f"    sidecar:      unreachable ({exc})")


def _scan_components(cfg: Any, *, dry_run: bool) -> None:
    if dry_run:
        click.echo("  Would request Claude Code component scan from sidecar.")
        return
    try:
        response = _client(cfg).claude_code_hook({
            "hook_event_name": "SessionStart",
            "source": "setup-scan-components",
            "cwd": os.getcwd(),
            "scan_components": True,
        }, timeout=120)
    except (requests.RequestException, OSError) as exc:
        click.echo(f"  Claude Code component scan failed: {exc}", err=True)
        raise SystemExit(1) from exc
    action = response.get("action", "allow")
    reason = response.get("reason", "")
    click.echo(f"  Claude Code component scan submitted: action={action}" + (f" reason={reason}" if reason else ""))


def _client(cfg: Any) -> OrchestratorClient:
    return OrchestratorClient(
        host=cfg.gateway.host or "127.0.0.1",
        port=cfg.gateway.api_port,
        timeout=5,
        token=cfg.gateway.resolved_token(),
    )
