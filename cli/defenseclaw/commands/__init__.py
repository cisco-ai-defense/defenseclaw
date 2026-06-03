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

import sys
from typing import Any

import click


def hint(*lines: str) -> None:
    """Print dim post-command hints, only when stdout is a terminal."""
    if not sys.stdout.isatty():
        return
    click.echo()
    for line in lines:
        click.echo(click.style(line, dim=True))


def resolve_list_connector(app: Any, requested: str | None) -> str:
    """Resolve and validate a ``--connector`` override for list commands.

    Multi-connector installs let ``skill``/``mcp``/``plugin list`` target a
    specific connector's catalog (the TUI focus selector relies on this).
    When ``requested`` is empty the active connector is returned unchanged,
    so single-connector behaviour is untouched. When supplied, it must be
    one of the configured active connectors (case-insensitive) — otherwise
    a ``UsageError`` is raised so a typo can't silently fall back to the
    active connector and show the wrong catalog.
    """
    cfg = getattr(app, "cfg", None)
    active = (
        cfg.active_connector()
        if cfg is not None and hasattr(cfg, "active_connector")
        else "openclaw"
    )
    if not requested:
        return active
    requested = requested.strip()
    try:
        if cfg is not None and hasattr(cfg, "active_connectors"):
            configured = list(cfg.active_connectors())
        else:
            configured = [active]
    except Exception:  # noqa: BLE001 — fall back to the singular active connector.
        configured = [active]
    by_lower = {name.lower(): name for name in configured if name}
    match = by_lower.get(requested.lower())
    if match is None:
        allowed = ", ".join(sorted(configured)) or active
        raise click.UsageError(
            f"connector {requested!r} is not configured. Active connectors: {allowed}."
        )
    return match


def resolve_list_connectors(app: Any, requested: str | None) -> list[str]:
    """Resolve which connector(s) a *list* command should cover.

    This is the plural companion to :func:`resolve_list_connector` and
    encodes the uniform UX rule for ``skill``/``mcp``/``plugin list``:

    * An explicit ``--connector X`` narrows to exactly that one validated
      peer.
    * With no flag the listing covers **every active connector**.
      ``Config.active_connectors()`` returns a single name on a
      single-connector install and N names on a fan-out install, so the
      caller renders the same way regardless of count — the operator never
      has to think about "single vs multi".
    """
    if requested and requested.strip():
        return [resolve_list_connector(app, requested)]
    cfg = getattr(app, "cfg", None)
    try:
        if cfg is not None and hasattr(cfg, "active_connectors"):
            names = [n for n in cfg.active_connectors() if n]
            if names:
                return names
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
# list). Their default scope is the single active connector — unlike the
# *scan* commands, whose bare/``--all`` form fans out to every active
# connector. Stating the default here makes that asymmetry discoverable
# without changing any actual default behaviour.
LIST_CONNECTOR_HELP = (
    "List for a specific configured connector. "
    "Default: the active connector; on multi-connector installs pass "
    "--connector <name> to target a configured peer."
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
