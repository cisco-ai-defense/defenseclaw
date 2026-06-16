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

Tools are named functions exposed by skills, MCP servers, or connectors.

Scoping is one of two ORTHOGONAL, mutually exclusive encodings:

* ``--connector C`` → ``@C/<tool>``  — the runtime-enforceable scope. Both
  gateway lanes (hook + sidecar) resolve connector-scoped rows then fall back
  to the bare global row.
* ``--source S``    → ``S/<tool>``   — audit/global only. The runtime payload
  carries no source, so a ``block --source`` fail-closes to a GLOBAL block and
  an ``allow --source`` row is recorded for visibility but never enforced.

Bare (global) rows apply to every connector as the fallback tier.

Global:     defenseclaw tool block delete_file
Connector:  defenseclaw tool block delete_file --connector hermes
Source:     defenseclaw tool block delete_file --source filesystem
"""

from __future__ import annotations

import json

import click

from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx

# Canonical write-tool names — mirrors internal/gateway/inspect.go
# isWriteToolName. Used only to annotate `status`: an allowed WRITE tool still
# runs CodeGuard at runtime (D2), so "allow" is not a full bypass for these.
_WRITE_TOOL_NAMES = frozenset(
    {
        "write_file", "edit_file",
        "write", "edit", "multiedit", "multi_edit",
        "applydiff", "apply_diff", "patch",
        "create_file", "createfile", "fs_write", "fs_edit",
    }
)


def _target_name(name: str, source: str) -> str:
    """Build a source-scoped target: 'source/name' if source given, else 'name'."""
    return f"{source}/{name}" if source else name


def _normalize_connector(connector: str) -> str:
    """Validate + canonicalize a ``--connector`` value.

    Empty stays empty (the global tier — applies to every connector). A
    non-empty value must be a recognized connector; otherwise the command
    fails closed with a usage error rather than silently writing a row no
    runtime lane will ever match.
    """
    if not connector:
        return ""
    from defenseclaw import connector_paths

    canon = connector_paths.normalize(connector)
    if canon not in connector_paths.KNOWN_CONNECTORS:
        raise click.BadParameter(
            f"unknown connector {connector!r}; expected one of "
            f"{', '.join(connector_paths.KNOWN_CONNECTORS)}",
            param_hint="'--connector'",
        )
    return canon


def _reject_connector_with_source(connector: str, source: str) -> None:
    """Connector- and source-scoping are orthogonal encodings; a single row
    cannot be both, so refuse to guess which the operator meant."""
    if connector and source:
        raise click.UsageError(
            "--connector and --source cannot be combined: connector scoping "
            "(@<connector>/<tool>) and source scoping (<source>/<tool>) are "
            "separate, mutually exclusive encodings."
        )


def _connector_target(name: str, connector: str) -> str:
    """Connector-scoped tool key, identical to the merged PolicyEngine encoding
    (``@<connector>/<tool>``).

    Reuses the canonical encoder so the CLI write surface and the runtime read
    gate never drift on the encoding.
    """
    from defenseclaw.enforce import PolicyEngine

    return PolicyEngine._tool_connector_target(name, connector)


def _parse_target(target_name: str) -> tuple[str, str]:
    """Decode a stored tool target_name into ``(connector, display_name)``.

    * ``@<connector>/<tool>`` → ``(connector, tool)``        connector-scoped
    * ``<source>/<tool>``     → ``("", "<source>/<tool>")``  source-scoped (shown whole)
    * ``<tool>``              → ``("", "<tool>")``            global

    Source-scoped rows keep their full ``<source>/<tool>`` display (the prefix is
    audit-only — the runtime does not enforce source scope) so existing
    operator-facing output is unchanged.
    """
    if target_name.startswith("@") and "/" in target_name:
        connector, _, tool = target_name[1:].partition("/")
        return connector, tool
    return "", target_name


def _is_global_target(target_name: str) -> bool:
    """True for a bare (global) tool row — neither connector- nor source-scoped."""
    return not target_name.startswith("@") and "/" not in target_name


def _entry_json(entry) -> dict | None:
    """Serialize an ActionEntry's install status for --json output."""
    if not entry:
        return None
    return {
        "status": entry.actions.install or "none",
        "reason": entry.reason,
        "updated_at": entry.updated_at.isoformat() if entry.updated_at else None,
    }


# ---------------------------------------------------------------------------
# tool group
# ---------------------------------------------------------------------------

@click.group()
def tool() -> None:
    """Manage tool-level block/allow lists.

    Tools are named actions exposed by skills, MCP servers, or connectors.

    \b
    Scoping (--connector and --source are mutually exclusive):
      --connector C   runtime-enforceable; applies only to connector C (@C/<tool>)
      --source S      audit/global only — a source block fail-closes to a GLOBAL
                      block; a source allow is recorded but never enforced
      (neither)       global; applies to every connector as the fallback tier

    \b
    Runtime resolution (request connector C, tool T):
      block @C/T → block T → allow @C/T → allow T → scan
    An allow skips rule/pattern/judge scanning, but WRITE tools still run
    CodeGuard.

    \b
    Examples:
      defenseclaw tool block delete_file --reason "too dangerous"
      defenseclaw tool block delete_file --connector hermes
      defenseclaw tool allow search --connector hermes --reason "vetted"
      defenseclaw tool list
      defenseclaw tool list --blocked --connector hermes
      defenseclaw tool status delete_file --connector hermes
      defenseclaw tool unblock delete_file
    """


# ---------------------------------------------------------------------------
# tool block
# ---------------------------------------------------------------------------

@tool.command()
@click.argument("name")
@click.option("--connector", default="", help="Scope to a connector (runtime-enforceable: @<connector>/<tool>)")
@click.option("--source", default="", help="Audit scope to a skill/MCP server (block fail-closes to global)")
@click.option("--reason", default="", help="Reason for blocking")
@pass_ctx
def block(app: AppContext, name: str, connector: str, source: str, reason: str) -> None:
    """Add a tool to the block list.

    \b
    Scope:
      --connector C   blocks the tool for connector C only (writes @C/<tool>);
                      the runtime enforces it per connector.
      --source S      audit only: the runtime payload carries no source, so a
                      scoped block fail-closes to a GLOBAL block and a scoped
                      audit row is kept for operator visibility.
      (neither)       global block, applies to every connector.

    \b
    Examples:
      defenseclaw tool block delete_file --reason "destructive"
      defenseclaw tool block delete_file --connector hermes
      defenseclaw tool block write_file --source filesystem --reason "read-only env"
    """
    from defenseclaw.enforce import PolicyEngine

    _reject_connector_with_source(connector, source)
    connector = _normalize_connector(connector)
    if not reason:
        reason = "manual block via CLI"

    pe = PolicyEngine(app.store)

    if connector:
        # Connector-scoped block — runtime-enforceable, isolated to C.
        pe.block_tool_for_connector(name, connector, reason)
        log_scope = _connector_target(name, connector)
        click.echo(
            f"{ux._style('[tool]', fg='red', bold=True)} {name!r} "
            f"{ux._style('added to block list', fg='red')} (connector {connector!r})"
        )
    elif source:
        # the gateway runtime carries no source on the
        # request, so a scoped entry like `filesystem/write_file` was never
        # enforced. Honor a --source block by ALSO writing the global block
        # (fail-closed); keep the scoped row as an audit record. Use
        # --connector for runtime-scoped blocks.
        pe.block("tool", name, reason)
        pe.block(
            "tool", _target_name(name, source),
            f"{reason} (scoped audit; runtime enforces globally)",
        )
        log_scope = _target_name(name, source)
        click.echo(
            f"{ux._style('[tool]', fg='red', bold=True)} {name!r} "
            f"{ux._style('added to block list', fg='red')} (global; "
            f"--source {source!r} kept for audit but is not runtime-enforced — "
            f"use --connector to scope a block)"
        )
    else:
        pe.block("tool", name, reason)
        log_scope = name
        click.echo(
            f"{ux._style('[tool]', fg='red', bold=True)} {name!r} (global) "
            f"{ux._style('added to block list', fg='red')}"
        )

    if app.logger:
        app.logger.log_action(
            "tool-block", log_scope,
            f"reason={reason} effective_target={log_scope} "
            f"requested_scope={connector or source or 'global'}",
        )


# ---------------------------------------------------------------------------
# tool allow
# ---------------------------------------------------------------------------

@tool.command()
@click.argument("name")
@click.option("--connector", default="", help="Scope to a connector (runtime-enforceable: @<connector>/<tool>)")
@click.option("--source", default="", help="Audit scope to a skill/MCP server (not runtime-enforced)")
@click.option("--reason", default="", help="Reason for allowing")
@pass_ctx
def allow(app: AppContext, name: str, connector: str, source: str, reason: str) -> None:
    """Add a tool to the allow list (skip the scan gate).

    An allow-listed tool skips rule/pattern/judge scanning at runtime, BUT
    write tools still run CodeGuard on their content (the allow bypasses the
    scan gate, not code-content inspection).

    \b
    Scope:
      --connector C   allows the tool for connector C only (writes @C/<tool>);
                      runtime-enforceable.
      --source S      audit only — a source allow is recorded but never read at
                      runtime (the payload carries no source). Use --connector.
      (neither)       global allow, applies to every connector.

    \b
    Examples:
      defenseclaw tool allow search --connector hermes --reason "vetted"
      defenseclaw tool allow read_file
    """
    from defenseclaw.enforce import PolicyEngine

    _reject_connector_with_source(connector, source)
    connector = _normalize_connector(connector)
    if not reason:
        reason = "manual allow via CLI"

    pe = PolicyEngine(app.store)

    if connector:
        pe.allow_tool_for_connector(name, connector, reason)
        target = _connector_target(name, connector)
        scope_note = f" (connector {connector!r})"
    else:
        # Global, or source-scoped audit row (never read at runtime).
        target = _target_name(name, source)
        pe.allow("tool", target, reason)
        if source:
            scope_note = f" (source {source!r}; audit-only — not runtime-enforced)"
        else:
            scope_note = " (global)"

    if app.logger:
        app.logger.log_action("tool-allow", target, f"reason={reason}")

    click.echo(
        f"{ux._style('[tool]', fg='green', bold=True)} {name!r}{scope_note} "
        f"{ux._style('added to allow list', fg='green')}"
    )


# ---------------------------------------------------------------------------
# tool unblock
# ---------------------------------------------------------------------------

@tool.command()
@click.argument("name")
@click.option("--connector", default="", help="Remove the connector-scoped entry (@<connector>/<tool>)")
@click.option("--source", default="", help="Remove the source-scoped entry (<source>/<tool>)")
@pass_ctx
def unblock(app: AppContext, name: str, connector: str, source: str) -> None:
    """Remove a tool from the block/allow list.

    Pass --connector or --source to remove the matching scoped entry; without
    either, removes the global entry.

    \b
    Examples:
      defenseclaw tool unblock delete_file
      defenseclaw tool unblock delete_file --connector hermes
      defenseclaw tool unblock write_file --source filesystem
    """
    from defenseclaw.enforce import PolicyEngine

    _reject_connector_with_source(connector, source)
    connector = _normalize_connector(connector)

    if connector:
        target = _connector_target(name, connector)
        scope_note = f" (connector {connector!r})"
    elif source:
        target = _target_name(name, source)
        scope_note = f" (source {source!r})"
    else:
        target = name
        scope_note = " (global)"

    pe = PolicyEngine(app.store)
    pe.unblock("tool", target)

    if app.logger:
        app.logger.log_action("tool-unblock", target, "removed from block/allow list")

    click.echo(
        f"{ux.dim('[tool]')} {name!r}{scope_note} removed from block/allow list"
    )


# ---------------------------------------------------------------------------
# tool list
# ---------------------------------------------------------------------------

@tool.command("list")
@click.option("--blocked", "filter_blocked", is_flag=True, help="Show only blocked tools")
@click.option("--allowed", "filter_allowed", is_flag=True, help="Show only allowed tools")
@click.option("--connector", default="", help="Show only rows in effect for this connector (its @<connector>/ rows plus global)")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@pass_ctx
def list_tools(
    app: AppContext, filter_blocked: bool, filter_allowed: bool,
    connector: str, as_json: bool,
) -> None:
    """List tools in the block/allow list.

    By default shows all tools. Use --blocked or --allowed to filter by status,
    and --connector to show only the rows in effect for one connector (its
    connector-scoped rows plus the global fallback rows).

    \b
    Examples:
      defenseclaw tool list
      defenseclaw tool list --blocked
      defenseclaw tool list --allowed --json
      defenseclaw tool list --connector hermes
    """
    from defenseclaw.enforce import PolicyEngine

    connector = _normalize_connector(connector)
    pe = PolicyEngine(app.store)

    if filter_blocked:
        entries = pe.list_blocked_tools()
    elif filter_allowed:
        entries = pe.list_allowed_tools()
    else:
        entries = pe.list_by_type("tool")

    # Decorate each entry with its parsed (connector, display name) and apply
    # the --connector filter: a connector "sees" its own @C/ rows plus the
    # global fallback rows.
    decorated = []
    for e in entries:
        conn, disp = _parse_target(e.target_name)
        if connector and not (conn == connector or _is_global_target(e.target_name)):
            continue
        decorated.append((e, conn, disp))

    if as_json:
        rows = [
            {
                "name": disp,
                "connector": conn or None,
                "status": e.actions.install or "none",
                "reason": e.reason,
                "updated_at": e.updated_at.isoformat() if e.updated_at else None,
            }
            for (e, conn, disp) in decorated
        ]
        click.echo(json.dumps(rows, indent=2, default=str))
        return

    if not decorated:
        label = "blocked " if filter_blocked else "allowed " if filter_allowed else ""
        click.echo(f"No {label}tools in the block/allow list.")
        return

    # Align columns manually — mirrors skill/mcp list output.
    name_w = max(max(len(disp) for (_, _, disp) in decorated), 4)
    conn_w = max(max(len(conn or "global") for (_, conn, _) in decorated), len("CONNECTOR"))
    status_w = 7  # "blocked" / "allowed"

    header = (
        f"{ux.bold('TOOL'.ljust(name_w))}  "
        f"{ux.bold('CONNECTOR'.ljust(conn_w))}  "
        f"{ux.bold('STATUS'.ljust(status_w))}  "
        f"{ux.bold('REASON'.ljust(40))}  "
        f"{ux.bold('UPDATED')}"
    )
    click.echo(header)
    click.echo(ux.dim("-" * len(header)))

    for e, conn, disp in decorated:
        status = e.actions.install or "none"
        reason = (e.reason or "")[:40]
        updated = e.updated_at.strftime("%Y-%m-%d %H:%M") if e.updated_at else "-"
        conn_disp = conn or "global"

        color = "red" if status == "block" else "green" if status == "allow" else None
        line_core = (
            f"{disp:<{name_w}}  {conn_disp:<{conn_w}}  "
            f"{status:<{status_w}}  {reason:<40}  {updated}"
        )
        if color:
            click.echo(ux._style(line_core, fg=color))
        else:
            click.echo(line_core)


# ---------------------------------------------------------------------------
# tool status
# ---------------------------------------------------------------------------

@tool.command()
@click.argument("name")
@click.option("--connector", default="", help="Also show the connector-scoped status (runtime-enforceable)")
@click.option("--source", default="", help="Also show the source-scoped audit row (not runtime-enforced)")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@pass_ctx
def status(app: AppContext, name: str, connector: str, source: str, as_json: bool) -> None:
    """Show the block/allow status of a tool.

    The "Effective" line mirrors the gateway's real resolution order
    (connector-scoped → global; block wins over allow; allow skips the scan
    gate but write tools still run CodeGuard). A --source row is audit-only and
    never decides the effective verdict.

    \b
    Examples:
      defenseclaw tool status delete_file
      defenseclaw tool status delete_file --connector hermes
    """
    from defenseclaw.enforce import PolicyEngine

    _reject_connector_with_source(connector, source)
    connector = _normalize_connector(connector)

    pe = PolicyEngine(app.store)

    global_entry = pe.get_action("tool", name)
    connector_entry = (
        pe.get_action("tool", _connector_target(name, connector)) if connector else None
    )
    source_entry = (
        pe.get_action("tool", _target_name(name, source)) if source else None
    )

    effective = _effective_status(connector_entry, global_entry)
    is_write = name.lower() in _WRITE_TOOL_NAMES

    if as_json:
        result = {
            "name": name,  # unified with `tool list` / skill / mcp (was "tool")
            "connector": connector or None,
            "source": source or None,
            "global": _entry_json(global_entry),
            "connector_scoped": _entry_json(connector_entry),
            "scoped": _entry_json(source_entry),  # source-scoped audit row
            "effective": effective,
        }
        click.echo(json.dumps(result, indent=2, default=str))
        return

    click.echo(f"{ux.bold('Tool:')} {name}")
    if connector:
        click.echo(f"{ux.bold('Connector:')} {connector}")
    if source:
        click.echo(
            f"{ux.bold('Source:')} {source} "
            f"{ux.dim('(audit-only — not runtime-enforced)')}"
        )

    _echo_status_line("Global status", global_entry, always=True)
    if connector:
        _echo_status_line("Connector status", connector_entry, always=True)
    if source:
        _echo_status_line("Source status", source_entry, always=True)

    color = "red" if effective == "block" else "green" if effective == "allow" else None
    msg = f"  Effective:      {effective}"
    if effective == "allow" and is_write:
        msg += "  (CodeGuard still applies to write tools)"
    click.echo(ux._style(msg, fg=color) if color else msg)


def _echo_status_line(label: str, entry, always: bool = False) -> None:
    """Echo a single '<label>:  <status>' line for a status entry."""
    if entry and not entry.actions.is_empty():
        s = entry.actions.install or "none"
        color = "red" if s == "block" else "green" if s == "allow" else None
        msg = f"  {label}:  {s}"
        if entry.reason:
            msg += f"  ({entry.reason})"
        click.echo(ux._style(msg, fg=color) if color else msg)
    elif always:
        click.echo(f"  {ux.dim(label + ':')}  none")


def _effective_status(connector_entry, global_entry) -> str:
    """Return the effective install action, mirroring the gateway runtime order:

        block @C/T → block T → allow @C/T → allow T → none

    Block wins over allow, and a connector-scoped entry wins over global within
    each verb. Source scoping does NOT participate: the runtime payload carries
    no source, so a source-scoped row never decides the effective verdict (a
    ``block --source`` already fail-closed to a global block, counted here via
    the global entry).
    """
    if connector_entry and connector_entry.actions.install == "block":
        return "block"
    if global_entry and global_entry.actions.install == "block":
        return "block"
    if connector_entry and connector_entry.actions.install == "allow":
        return "allow"
    if global_entry and global_entry.actions.install == "allow":
        return "allow"
    return "none"
