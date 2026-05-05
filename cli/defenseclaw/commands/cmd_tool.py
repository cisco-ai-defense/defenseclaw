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

"""defenseclaw tool — Manage tool-level block/allow lists.

Tools are named functions exposed by skills or MCP servers.
Block/allow rules can be global (any source) or scoped to a specific source.

Global:  defenseclaw tool block delete_file
Scoped:  defenseclaw tool block delete_file --source filesystem
"""

from __future__ import annotations

import json

import click

from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx


def _target_name(name: str, source: str) -> str:
    """Build target_name: 'source/name' if source given, else 'name'."""
    return f"{source}/{name}" if source else name


# ---------------------------------------------------------------------------
# tool group
# ---------------------------------------------------------------------------

@click.group()
def tool() -> None:
    """Manage tool-level block/allow lists.

    Tools are named actions exposed by skills or MCP servers.
    Block/allow rules can be global (any source) or scoped to a specific
    skill/MCP server with --source.

    \b
    Examples:
      defenseclaw tool block delete_file --reason "too dangerous"
      defenseclaw tool block delete_file --source filesystem
      defenseclaw tool allow search --source web-search
      defenseclaw tool list
      defenseclaw tool list --blocked
      defenseclaw tool status delete_file
      defenseclaw tool unblock delete_file
    """


# ---------------------------------------------------------------------------
# tool block
# ---------------------------------------------------------------------------

@tool.command()
@click.argument("name")
@click.option("--source", default="", help="Scope to a specific skill or MCP server name")
@click.option("--reason", default="", help="Reason for blocking")
@pass_ctx
def block(app: AppContext, name: str, source: str, reason: str) -> None:
    """Add a tool to the block list.

    Blocked tools are flagged at runtime when called. Use --source to scope
    the rule to a specific skill or MCP server; without --source the block
    applies globally regardless of which source exposes the tool.

    \b
    Examples:
      defenseclaw tool block delete_file --reason "destructive"
      defenseclaw tool block write_file --source filesystem --reason "read-only env"
    """
    from defenseclaw.enforce import PolicyEngine

    target = _target_name(name, source)
    if not reason:
        reason = "manual block via CLI"

    pe = PolicyEngine(app.store)
    pe.block("tool", target, reason)

    if app.logger:
        app.logger.log_action("tool-block", target, f"reason={reason}")

    scope_note = f" (scoped to {source!r})" if source else " (global)"
    click.echo(
        f"{ux._style('[tool]', fg='red', bold=True)} {name!r}{scope_note} "
        f"{ux._style('added to block list', fg='red')}"
    )


# ---------------------------------------------------------------------------
# tool allow
# ---------------------------------------------------------------------------

@tool.command()
@click.argument("name")
@click.option("--source", default="", help="Scope to a specific skill or MCP server name")
@click.option("--reason", default="", help="Reason for allowing")
@pass_ctx
def allow(app: AppContext, name: str, source: str, reason: str) -> None:
    """Add a tool to the allow list (skip scan gate).

    Allow-listed tools bypass the scan gate during execution checks.
    Use --source to scope the rule to a specific skill or MCP server.

    \b
    Examples:
      defenseclaw tool allow search --source web-search --reason "vetted"
      defenseclaw tool allow read_file
    """
    from defenseclaw.enforce import PolicyEngine

    target = _target_name(name, source)
    if not reason:
        reason = "manual allow via CLI"

    pe = PolicyEngine(app.store)
    pe.allow("tool", target, reason)

    if app.logger:
        app.logger.log_action("tool-allow", target, f"reason={reason}")

    scope_note = f" (scoped to {source!r})" if source else " (global)"
    click.echo(
        f"{ux._style('[tool]', fg='green', bold=True)} {name!r}{scope_note} "
        f"{ux._style('added to allow list', fg='green')}"
    )


# ---------------------------------------------------------------------------
# tool unblock
# ---------------------------------------------------------------------------

@tool.command()
@click.argument("name")
@click.option("--source", default="", help="Scope to match the scoped entry (if any)")
@pass_ctx
def unblock(app: AppContext, name: str, source: str) -> None:
    """Remove a tool from the block/allow list.

    Pass --source to remove a scoped entry; without --source removes the
    global entry.

    \b
    Examples:
      defenseclaw tool unblock delete_file
      defenseclaw tool unblock write_file --source filesystem
    """
    from defenseclaw.enforce import PolicyEngine

    target = _target_name(name, source)
    pe = PolicyEngine(app.store)
    pe.unblock("tool", target)

    if app.logger:
        app.logger.log_action("tool-unblock", target, "removed from block/allow list")

    scope_note = f" (scoped to {source!r})" if source else " (global)"
    click.echo(
        f"{ux.dim('[tool]')} {name!r}{scope_note} removed from block/allow list"
    )


# ---------------------------------------------------------------------------
# tool list
# ---------------------------------------------------------------------------

@tool.command("list")
@click.option("--blocked", "filter_blocked", is_flag=True, help="Show only blocked tools")
@click.option("--allowed", "filter_allowed", is_flag=True, help="Show only allowed tools")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@pass_ctx
def list_tools(app: AppContext, filter_blocked: bool, filter_allowed: bool, as_json: bool) -> None:
    """List tools in the block/allow list.

    By default shows all tools. Use --blocked or --allowed to filter.

    \b
    Examples:
      defenseclaw tool list
      defenseclaw tool list --blocked
      defenseclaw tool list --allowed --json
    """
    from defenseclaw.enforce import PolicyEngine

    pe = PolicyEngine(app.store)

    if filter_blocked:
        entries = pe.list_blocked_tools()
    elif filter_allowed:
        entries = pe.list_allowed_tools()
    else:
        entries = pe.list_by_type("tool")

    if as_json:
        rows = [
            {
                "name": e.target_name,
                "status": e.actions.install or "none",
                "reason": e.reason,
                "updated_at": e.updated_at.isoformat() if e.updated_at else None,
            }
            for e in entries
        ]
        click.echo(json.dumps(rows, indent=2, default=str))
        return

    if not entries:
        label = "blocked " if filter_blocked else "allowed " if filter_allowed else ""
        click.echo(f"No {label}tools in the block/allow list.")
        return

    # Align columns manually — mirrors skill/mcp list output
    name_w = max(len(e.target_name) for e in entries)
    name_w = max(name_w, 4)  # min header width
    status_w = 7  # "blocked" / "allowed"

    header = (
        f"{ux.bold('TOOL'.ljust(name_w))}  "
        f"{ux.bold('STATUS'.ljust(status_w))}  "
        f"{ux.bold('REASON'.ljust(40))}  "
        f"{ux.bold('UPDATED')}"
    )
    click.echo(header)
    click.echo(ux.dim("-" * len(header)))

    for e in entries:
        status = e.actions.install or "none"
        reason = (e.reason or "")[:40]
        updated = e.updated_at.strftime("%Y-%m-%d %H:%M") if e.updated_at else "-"

        color = "red" if status == "block" else "green" if status == "allow" else None
        line_core = f"{e.target_name:<{name_w}}  {status:<{status_w}}  {reason:<40}  {updated}"
        if color:
            click.echo(ux._style(line_core, fg=color))
        else:
            click.echo(line_core)


# ---------------------------------------------------------------------------
# tool status
# ---------------------------------------------------------------------------

@tool.command()
@click.argument("name")
@click.option("--source", default="", help="Scope to a specific skill or MCP server name")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@pass_ctx
def status(app: AppContext, name: str, source: str, as_json: bool) -> None:
    """Show the block/allow status of a tool.

    Checks scoped entry first (if --source given), then falls back to the
    global entry.

    \b
    Examples:
      defenseclaw tool status delete_file
      defenseclaw tool status write_file --source filesystem
    """
    from defenseclaw.enforce import PolicyEngine

    pe = PolicyEngine(app.store)

    scoped_entry = None
    global_entry = None

    if source:
        scoped_target = _target_name(name, source)
        scoped_entry = pe.get_action("tool", scoped_target)

    global_entry = pe.get_action("tool", name)

    if as_json:
        result = {"tool": name, "source": source or None, "scoped": None, "global": None}
        if scoped_entry:
            result["scoped"] = {
                "status": scoped_entry.actions.install or "none",
                "reason": scoped_entry.reason,
                "updated_at": scoped_entry.updated_at.isoformat() if scoped_entry.updated_at else None,
            }
        if global_entry:
            result["global"] = {
                "status": global_entry.actions.install or "none",
                "reason": global_entry.reason,
                "updated_at": global_entry.updated_at.isoformat() if global_entry.updated_at else None,
            }
        click.echo(json.dumps(result, indent=2, default=str))
        return

    click.echo(f"{ux.bold('Tool:')} {name}")
    if source:
        click.echo(f"{ux.bold('Source:')} {source}")

    if scoped_entry and not scoped_entry.actions.is_empty():
        s = scoped_entry.actions.install or "none"
        color = "red" if s == "block" else "green" if s == "allow" else None
        msg = f"  Scoped status:  {s}"
        if scoped_entry.reason:
            msg += f"  ({scoped_entry.reason})"
        click.echo(ux._style(msg, fg=color) if color else msg)
    elif source:
        click.echo(f"  {ux.dim('Scoped status:')}  none")

    if global_entry and not global_entry.actions.is_empty():
        s = global_entry.actions.install or "none"
        color = "red" if s == "block" else "green" if s == "allow" else None
        msg = f"  Global status:  {s}"
        if global_entry.reason:
            msg += f"  ({global_entry.reason})"
        click.echo(ux._style(msg, fg=color) if color else msg)
    else:
        click.echo(f"  {ux.dim('Global status:')}  none")

    # Effective status: scoped wins over global
    effective = _effective_status(scoped_entry, global_entry)
    color = "red" if effective == "block" else "green" if effective == "allow" else None
    msg = f"  Effective:      {effective}"
    if color:
        click.echo(ux._style(msg, fg=color))
    else:
        click.echo(msg)


def _effective_status(scoped_entry, global_entry) -> str:
    """Return the effective install action: scoped takes priority over global."""
    if scoped_entry and scoped_entry.actions.install:
        return scoped_entry.actions.install
    if global_entry and global_entry.actions.install:
        return global_entry.actions.install
    return "none"
