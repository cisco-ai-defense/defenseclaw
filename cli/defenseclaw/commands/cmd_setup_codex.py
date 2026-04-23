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

"""`defenseclaw setup codex` — install and inspect Codex hooks."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import click
import requests

# Matches a codex_hooks key line in TOML, tolerating whitespace around the
# assignment and rejecting similarly-named keys such as `codex_hooks_extra`.
_CODEX_HOOKS_KEY_RE = re.compile(r"^codex_hooks\s*=")
# Matches `codex_hooks = true` ignoring surrounding whitespace; used only as
# a last-resort fallback when tomllib parsing fails on malformed files.
_CODEX_HOOKS_TRUE_RE = re.compile(r"(?m)^\s*codex_hooks\s*=\s*true\s*$")

from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.gateway import OrchestratorClient

_OWNED_COMMAND = "defenseclaw codex hook"
_CODEX_EVENTS = ("SessionStart", "UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse", "Stop")


@click.command("codex")
@click.option("--non-interactive", is_flag=True, help="Use defaults instead of prompts.")
@click.option("--enable-feature", is_flag=True, help="Enable [features].codex_hooks in ~/.codex/config.toml.")
@click.option("--scope", type=click.Choice(["user", "repo"]), default=None,
              help="Where to install hooks (default from config, then user).")
@click.option("--scan-on-session-start/--no-scan-on-session-start", default=None,
              help="Enable or disable Codex component scans on SessionStart.")
@click.option("--scan-on-stop/--no-scan-on-stop", default=None,
              help="Enable or disable CodeGuard scans from the Stop hook.")
@click.option("--fail-closed/--fail-open", default=None,
              help="Block when the hook bridge cannot reach the sidecar.")
@click.option("--disable", is_flag=True, help="Remove DefenseClaw-owned Codex hooks.")
@click.option("--status", "show_status", is_flag=True, help="Show Codex integration status.")
@click.option("--scan-components", is_flag=True, help="Ask the sidecar to scan Codex skills/plugins/MCP config now.")
@click.option("--dry-run", is_flag=True, help="Show what would change without writing files.")
@click.option("--force", is_flag=True, help="Replace invalid hooks.json instead of failing.")
@pass_ctx
def codex_setup(
    app: AppContext,
    non_interactive: bool,
    enable_feature: bool,
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
    """Configure DefenseClaw hooks for Codex."""
    cfg = app.cfg
    scope = scope or getattr(getattr(cfg, "codex", None), "install_scope", "") or "user"
    if scan_on_session_start is not None:
        cfg.codex.scan_on_session_start = scan_on_session_start
    if scan_on_stop is not None:
        cfg.codex.scan_on_stop = scan_on_stop
    if fail_closed is not None:
        cfg.codex.fail_closed = fail_closed

    if show_status:
        _print_status(cfg, scope)
        return

    if not non_interactive and not disable:
        click.echo()
        click.echo("  Codex Integration Setup")
        click.echo()
        scope = click.prompt("  Install scope", type=click.Choice(["user", "repo"]), default=scope)
        enable_feature = click.confirm("  Enable Codex hooks feature flag", default=enable_feature or True)
        cfg.codex.scan_on_session_start = click.confirm(
            "  Scan Codex components when a session starts",
            default=cfg.codex.scan_on_session_start,
        )
        cfg.codex.scan_on_stop = click.confirm("  Scan changed files when a turn stops", default=cfg.codex.scan_on_stop)
        cfg.codex.fail_closed = click.confirm(
            "  Fail closed if the sidecar is unavailable",
            default=cfg.codex.fail_closed,
        )

    hooks_path = _hooks_path(scope)
    config_path = _codex_config_path()

    if disable:
        changed = _write_hooks(hooks_path, install=False, dry_run=dry_run, force=force)
        if not dry_run:
            cfg.codex.enabled = False
            cfg.save()
        if changed:
            click.echo(f"  Codex hooks removed from {hooks_path}")
        else:
            click.echo(f"  No DefenseClaw Codex hooks found in {hooks_path}")
        return

    changed = _write_hooks(hooks_path, install=True, dry_run=dry_run, force=force)
    feature_enabled = _feature_flag_enabled(config_path)
    if enable_feature:
        feature_enabled = _set_feature_flag(config_path, dry_run=dry_run)

    if not dry_run:
        cfg.codex.enabled = True
        cfg.codex.install_scope = scope
        cfg.save()

    click.echo(f"  Codex hooks {'would be installed' if dry_run else 'installed'}: {hooks_path}")
    if changed:
        click.echo("  Hook events: " + ", ".join(_CODEX_EVENTS))
    if feature_enabled:
        click.echo("  Codex hook feature flag: enabled")
    else:
        click.echo(f"  Codex hook feature flag: missing in {config_path}")
        click.echo("  Re-run with --enable-feature to let DefenseClaw set it.")

    _print_sidecar_line(cfg)

    if scan_components:
        _scan_components(cfg, dry_run=dry_run)

    if app.logger and not dry_run:
        app.logger.log_action("setup-codex", "config", f"scope={scope} hooks={hooks_path}")


def _hooks_path(scope: str) -> Path:
    if scope == "repo":
        root = _git_root()
        return root / ".codex" / "hooks.json"
    return Path.home() / ".codex" / "hooks.json"


def _git_root() -> Path:
    try:
        out = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True, stderr=subprocess.DEVNULL)
        return Path(out.strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        return Path.cwd()


def _codex_config_path() -> Path:
    return Path.home() / ".codex" / "config.toml"


def _write_hooks(path: Path, *, install: bool, dry_run: bool, force: bool) -> bool:
    data = _load_hooks(path, force=force)
    before = json.dumps(data, sort_keys=True)
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        if not force:
            raise click.ClickException(f"{path} has invalid hooks shape; use --force to replace it")
        hooks = {}
        data["hooks"] = hooks

    _remove_owned_hooks(hooks)
    if install:
        for event in _CODEX_EVENTS:
            hooks.setdefault(event, []).append(_hook_group(event))

    after = json.dumps(data, sort_keys=True)
    changed = before != after
    if changed and not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")
    return changed


def _load_hooks(path: Path, *, force: bool) -> dict[str, Any]:
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
        "timeout": 90 if event == "Stop" else 30,
    }
    group: dict[str, Any] = {"hooks": [entry]}
    if event == "SessionStart":
        group["matcher"] = "startup|resume"
    elif event in {"PreToolUse", "PermissionRequest", "PostToolUse"}:
        group["matcher"] = "Bash"
    return group


def _status_message(event: str) -> str:
    return {
        "SessionStart": "DefenseClaw: preparing Codex session",
        "UserPromptSubmit": "DefenseClaw: scanning prompt",
        "PreToolUse": "DefenseClaw: checking Bash command",
        "PermissionRequest": "DefenseClaw: checking permission request",
        "PostToolUse": "DefenseClaw: reviewing Bash output",
        "Stop": "DefenseClaw: scanning changed code",
    }.get(event, "DefenseClaw: checking Codex event")


def _feature_flag_enabled(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        import tomllib
        data = tomllib.loads(path.read_text())
    except Exception:
        # Anchored regex so we don't report "enabled" when a comment or
        # differently-named key happens to contain the substring
        # `codex_hooks = true`.
        return bool(_CODEX_HOOKS_TRUE_RE.search(path.read_text()))
    features = data.get("features")
    if not isinstance(features, dict):
        return False
    return bool(features.get("codex_hooks", False))


def _set_feature_flag(path: Path, *, dry_run: bool) -> bool:
    text = path.read_text() if path.exists() else ""
    lines = text.splitlines()
    in_features = False
    features_seen = False
    key_seen = False
    out: list[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_features and not key_seen:
                out.append("codex_hooks = true")
                key_seen = True
            in_features = stripped == "[features]"
            features_seen = features_seen or in_features
        # Exact key match only — `startswith("codex_hooks")` would also
        # clobber neighbouring keys like `codex_hooks_extra = 1`.
        if in_features and _CODEX_HOOKS_KEY_RE.match(stripped):
            out.append("codex_hooks = true")
            key_seen = True
            continue
        out.append(line)

    if features_seen and in_features and not key_seen:
        out.append("codex_hooks = true")
    if not features_seen:
        if out and out[-1].strip():
            out.append("")
        out.extend(["[features]", "codex_hooks = true"])

    if not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(out).rstrip() + "\n")
    return True


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
    return all(event in seen for event in _CODEX_EVENTS)


def _print_status(cfg: Any, scope: str) -> None:
    hooks_path = _hooks_path(scope)
    config_path = _codex_config_path()
    click.echo("  Codex integration")
    click.echo(f"    enabled:      {getattr(cfg.codex, 'enabled', False)}")
    click.echo(f"    mode:         {getattr(cfg.codex, 'mode', 'inherit')}")
    click.echo(f"    scope:        {scope}")
    click.echo(f"    hooks:        {'installed' if _hooks_installed(hooks_path) else 'not installed'} ({hooks_path})")
    click.echo(f"    feature flag: {'enabled' if _feature_flag_enabled(config_path) else 'missing'} ({config_path})")
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
        click.echo("  Would request Codex component scan from sidecar.")
        return
    try:
        response = _client(cfg).codex_hook({
            "hook_event_name": "SessionStart",
            "source": "setup-scan-components",
            "cwd": os.getcwd(),
            "scan_components": True,
        }, timeout=120)
    except (requests.RequestException, OSError) as exc:
        click.echo(f"  Codex component scan failed: {exc}", err=True)
        raise SystemExit(1) from exc
    action = response.get("action", "allow")
    reason = response.get("reason", "")
    click.echo(f"  Codex component scan submitted: action={action}" + (f" reason={reason}" if reason else ""))


def _client(cfg: Any) -> OrchestratorClient:
    return OrchestratorClient(
        host=cfg.gateway.host or "127.0.0.1",
        port=cfg.gateway.api_port,
        timeout=5,
        token=cfg.gateway.resolved_token(),
    )
