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

"""CLI command modules."""

from __future__ import annotations

import shutil
import sys
from typing import Any

import click


def hint(*lines: str) -> None:
    """Print dim post-command hints, only when stdout is a terminal."""
    if not sys.stdout.isatty():
        return
    width = shutil.get_terminal_size().columns
    click.echo()
    for line in lines:
        # GAP-2363: a "Label:  command" hint wider than the terminal puts the
        # command on its own line, so the wrap never splits the command.
        label, sep, command = line.partition(":  ")
        if sep and len(line) > width:
            click.echo(click.style(f"{label}:", dim=True))
            click.echo(click.style(f"  {command}", dim=True))
        else:
            click.echo(click.style(line, dim=True))


def resolve_list_connector(app: Any, requested: str | None) -> str:
    """Resolve and validate a ``--connector`` override for list commands.

    Multi-connector installs let ``skill``/``mcp``/``plugin list`` target a
    specific connector's catalog (the TUI focus selector relies on this).
    When ``requested`` is empty the active connector is returned unchanged,
    except that cleanup-only connectors are rejected with migration guidance.
    When supplied, it must be one of the configured active connectors
    (case-insensitive) — otherwise a ``UsageError`` is raised so a typo can't
    silently fall back to the active connector and show the wrong catalog.
    """
    cfg = getattr(app, "cfg", None)
    active = (
        cfg.active_connector()
        if cfg is not None and hasattr(cfg, "active_connector")
        else "openclaw"
    )
    requested = requested.strip() if requested else ""
    try:
        if cfg is not None and hasattr(cfg, "active_connectors"):
            configured = list(cfg.active_connectors())
        else:
            configured = [active]
    except Exception:  # noqa: BLE001 — fall back to the singular active connector.
        configured = [active]
    # Match connector-name-insensitively: fold case AND the hyphen/underscore
    # aliases (e.g. "open-hands" → "openhands") via connector_paths.normalize
    # so a user passing a documented alias resolves the configured canonical
    # peer instead of hitting "not configured".
    from defenseclaw import connector_paths
    from defenseclaw.connector_contracts import normalize_connector

    def _normalize_alias(name: str) -> str:
        return connector_paths.normalize(normalize_connector(name))

    by_norm = {_normalize_alias(name): name for name in configured if name}
    match = active if not requested else by_norm.get(_normalize_alias(requested))
    if match is None:
        wanted = _normalize_alias(requested)
        setup_name = "claude-code" if wanted == "claudecode" else wanted
        setup_cmd = (
            f"defenseclaw setup {setup_name}"
            if connector_paths.is_known(wanted)
            else "defenseclaw setup <connector>"
        )
        names = sorted(name for name in configured if name)
        if not names:
            # GAP-1690: with nothing configured, don't name the phantom
            # "openclaw" default; say so and give the next step.
            raise click.ClickException(
                f"connector {requested!r} is not configured: no connector is "
                f"configured yet. Set one up first: {setup_cmd}"
            )
        raise click.UsageError(
            f"connector {requested!r} is not configured. Configured connectors: "
            f"{', '.join(names)}. To add it: {setup_cmd}"
        )
    return match


NO_CONNECTOR_HINT = "no connector configured — run 'defenseclaw setup <connector>'"


def echo_no_connector() -> None:
    """Print the empty state of a list command with no connector configured.

    With ``--json`` stdout stays JSON (an empty list) and the hint goes to
    stderr, so scripts and the TUI panels can parse the output (GAP-2073).
    """
    ctx = click.get_current_context(silent=True)
    if ctx is not None and ctx.params.get("as_json"):
        click.echo("[]")
        click.echo(NO_CONNECTOR_HINT, err=True)
        return
    click.echo(NO_CONNECTOR_HINT)


def resolve_list_connectors(app: Any, requested: str | None) -> list[str]:
    """Resolve which connector(s) a *list* command should cover.

    This is the plural companion to :func:`resolve_list_connector` and
    encodes the uniform UX rule for ``skill``/``mcp``/``plugin list``:

    * An explicit ``--connector X`` narrows to exactly that one validated
      peer.
    * With no flag the listing covers every active connector.
      ``Config.active_connectors()`` returns a single name on a
      single-connector install and N names on a fan-out install, so the
      caller renders the same way regardless of count — the operator never
      has to think about "single vs multi".
    * When **nothing is configured** (e.g. after ``setup remove`` clears the
      last connector) this prints a one-line pointer to ``setup`` and exits
      cleanly instead of fanning out to a phantom ``openclaw``. That keeps
      every consumer — ``mcp/skill/plugin list``, ``codeguard``, and the
      ``mcp set``/``unset`` mutators that share this resolver — from
      silently operating against ``~/.openclaw`` when no connector exists.
    """
    if requested and requested.strip():
        return [resolve_list_connector(app, requested)]
    cfg = getattr(app, "cfg", None)
    # Zero-config guard. ``active_connectors()`` already returns [] here, but
    # the singular fallback at the bottom would otherwise floor back to
    # "openclaw" — so intercept explicitly and surface the empty state. The
    # message text mirrors the no-connector hint used elsewhere.
    if cfg is not None and hasattr(cfg, "has_connector_configured"):
        try:
            configured = cfg.has_connector_configured()
        except Exception:  # noqa: BLE001 — fail open to legacy behavior.
            configured = True
        if not configured:
            echo_no_connector()
            raise SystemExit(0)
    try:
        if cfg is not None and hasattr(cfg, "active_connectors"):
            names = [n for n in cfg.active_connectors() if n]
            if names:
                return names
    except click.UsageError:
        raise
    except Exception:  # noqa: BLE001 — fall back to the singular active connector.
        pass
    return [resolve_list_connector(app, "")]


def list_scope_title(label: str, connector: str, detail: str = "") -> str:
    """Build a rich table title that names the connector in scope.

    Mirrors the MCP list table's ``(connector=...)`` banner so Skills and
    Plugins list output also makes the active-connector default
    discoverable on multi-connector installs. ``detail`` is the existing
    count suffix (e.g. ``"(2/3 ready)"``) appended after the connector tag.
    """
    head = f"{label} (connector={connector})"
    return f"{head} {detail}" if detail else head


# Shared ``--connector`` help text for the *list* commands (skill/mcp/plugin
# list). Bare (no flag) these fan out to EVERY active connector via
# ``resolve_list_connectors``; passing ``--connector X`` narrows to one
# validated peer. Stating that here keeps the flag help consistent with the
# actual default if this constant is reused.
LIST_CONNECTOR_HELP = (
    "Narrow the listing to one configured connector. "
    "Default: every active connector; pass --connector <name> to scope to a "
    "single configured peer."
)


def compute_verdict(
    action_entry: Any | None = None,
    scan_entry: dict[str, Any] | None = None,
) -> tuple[str, str]:
    """Derive a (label, rich_style) verdict from action + scan state.

    Priority: explicit enforcement actions > scan severity > no data.
    """
    if action_entry and not action_entry.actions.is_empty():
        a = action_entry.actions
        if a.file == "quarantine":
            return "quarantined", "red"
        if a.install == "block":
            # The watcher blocked the asset but could not move it into
            # quarantine storage, or took a linked asset out of the folder
            # (internal/watcher quarantineFailedReason, errLinkRemoved).
            reason = str(getattr(action_entry, "reason", "") or "")
            if reason.startswith("quarantine failed"):
                return "quarantine failed", "red"
            if reason.startswith("link removed"):
                return "link removed", "red"
            return "blocked", "red"
        if a.runtime == "disable":
            return "disabled", "red"
        if a.install == "allow":
            return "allowed", "green"
    if scan_entry:
        sev = scan_entry.get("max_severity", "CLEAN")
        if sev in ("CRITICAL", "HIGH"):
            return "rejected", "red"
        if sev in ("MEDIUM", "LOW"):
            return "warning", "yellow"
        if sev == "CLEAN":
            return "clean", "green"
    return "-", ""
