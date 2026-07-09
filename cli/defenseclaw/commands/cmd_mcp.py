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

"""defenseclaw mcp — Manage MCP servers (scan, block, allow, list, set, unset).

Reads MCP server configuration from the configured connector(s)'
connector-specific config (openclaw.json, .codex/config.toml,
.claude/settings.json, .zeptoclaw/config.json, …). For OpenClaw, writes
go through the ``openclaw config`` CLI so OpenClaw validates the schema
and hot-reloads cleanly; other connectors are written to their own
config files. ``list`` defaults to every configured connector; ``scan --all``
fans out to every configured connector.
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import shutil
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager

import click

from defenseclaw import connector_paths, ux
from defenseclaw.commands import compute_verdict as _compute_verdict
from defenseclaw.config import MCPServerEntry
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.models import ActionEntry, ActionState, ScanResult


def _parse_args(raw: str) -> list[str]:
    """Parse ``--args`` value as a JSON array or comma-separated string."""
    stripped = raw.strip()
    if stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, list):
                return [str(a) for a in parsed]
        except json.JSONDecodeError:
            # The managed Windows ``defenseclaw.cmd`` compatibility launcher
            # is retained for cmd.exe.  When PowerShell invokes that batch
            # file with a JSON value held in a variable, cmd.exe removes the
            # JSON string delimiters before ``%*`` forwards the argument.  A
            # valid value such as ["--from","C:\\\\path"] therefore arrives
            # as [--from,C:\\\\path].  Recover that narrow, bracketed form so
            # the connector stores the argv the operator supplied.  This is
            # deliberately not shell evaluation: every item remains a
            # literal subprocess argument.
            if stripped.endswith("]"):
                inner = stripped[1:-1]
                recovered: list[str] = []
                try:
                    for item in inner.split(","):
                        item = item.strip()
                        if not item:
                            continue
                        # Decode only JSON backslash escaping left behind by
                        # the stripped string delimiters.  A surviving quote
                        # means the boundary is ambiguous and must fail closed.
                        if '"' in item:
                            raise ValueError
                        decoded = json.loads(f'"{item}"')
                        if not isinstance(decoded, str):
                            raise ValueError
                        recovered.append(decoded)
                except (json.JSONDecodeError, ValueError):
                    raise click.BadParameter(
                        "malformed JSON array; pass a JSON string array or a "
                        "comma-separated argument list",
                        param_hint="--args",
                    ) from None
                return recovered
    return [a.strip() for a in raw.split(",") if a.strip()]


@click.group()
def mcp() -> None:
    """Manage MCP servers — scan, block, allow, list, set, unset.

    Multi-connector: MCP config is read per-connector. ``mcp list`` shows
    every configured connector's MCP servers by default (pass ``--connector
    X`` to narrow to one peer). The other subcommands take ``--connector
    X`` to target a configured peer; ``mcp scan --all`` fans out across every
    configured connector.
    """


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

@mcp.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option(
    "--connector",
    "connector_flag",
    default="",
    help=(
        "List MCP servers for a specific configured connector. "
        "Default: every configured connector (on a single-connector install, "
        "just that one). Pass --connector <name> to narrow to one peer."
    ),
)
@pass_ctx
def list_mcps(app: AppContext, as_json: bool, connector_flag: str) -> None:
    """List MCP servers configured for a connector.

    By default this lists **every configured connector's** MCP servers — each
    connector gets its own connector-tagged table — so the output reads
    the same whether one or many connectors are active. ``--connector
    <name>`` narrows the listing to one configured peer.
    """
    from defenseclaw.commands import resolve_list_connectors

    all_connectors = resolve_list_connectors(app, "")
    connectors = (
        resolve_list_connectors(app, connector_flag)
        if connector_flag and connector_flag.strip()
        else all_connectors
    )
    allow_legacy_plain_scans = len(all_connectors) == 1

    if as_json:
        if len(connectors) > 1:
            groups = []
            for c in connectors:
                servers = _collect_mcps_for_connector(app, c)
                scan_map = _build_mcp_scan_map(
                    app.store, servers, c,
                    allow_legacy_plain=allow_legacy_plain_scans,
                )
                actions_map = _build_mcp_actions_map(app.store, c)
                groups.append({
                    "connector": c,
                    "mcp_servers": _mcp_list_json_items(
                        servers, scan_map, actions_map, connector=c,
                    ),
                })
            click.echo(json.dumps(groups, indent=2, default=str))
        else:
            servers = _collect_mcps_for_connector(app, connectors[0])
            scan_map = _build_mcp_scan_map(
                app.store, servers, connectors[0],
                allow_legacy_plain=allow_legacy_plain_scans,
            )
            actions_map = _build_mcp_actions_map(app.store, connectors[0])
            # Flat shape (no per-connector wrapper) keeps single-connector
            # installs byte-compatible with the pre-fan-out output. An explicit
            # --connector request gets an envelope even when empty so JSON
            # automation never has to remember argv to know the scope.
            items = _mcp_list_json_items(
                servers, scan_map, actions_map, connector=connectors[0],
            )
            payload = (
                {"connector": connectors[0], "mcp_servers": items}
                if connector_flag and connector_flag.strip()
                else items
            )
            click.echo(json.dumps(payload, indent=2))
        return

    shown_any = False
    for connector in connectors:
        servers = _collect_mcps_for_connector(app, connector)
        scan_map = _build_mcp_scan_map(
            app.store, servers, connector,
            allow_legacy_plain=allow_legacy_plain_scans,
        )
        actions_map = _build_mcp_actions_map(app.store, connector)
        if not servers:
            ux.warn(
                f"No MCP servers configured for connector={connector!r} "
                f"(checked: {_mcp_source_hint(connector)}).",
            )
            continue
        _print_mcp_list_table(servers, scan_map, actions_map, connector)
        shown_any = True

    if shown_any:
        from defenseclaw.commands import hint
        hint("Scan all servers:  defenseclaw mcp scan --all")


def _collect_mcps_for_connector(
    app: AppContext, connector: str,
) -> list[MCPServerEntry]:
    """Return the per-connector MCP server list.

    The connector-aware ``cfg.mcp_servers(connector)`` reads the peer's
    own MCP config, so each configured connector resolves its own catalog when
    ``mcp list`` fans out.
    """
    return app.cfg.mcp_servers(connector)


def _mcp_source_hint(connector: str) -> str:
    """Human label for the connector-specific MCP source used by list/scan."""
    name = connector_paths.normalize(connector)
    hints = {
        "openclaw": "OpenClaw MCP config",
        "claudecode": "Claude Code settings and workspace MCP config",
        "codex": "Codex config and workspace MCP config",
        "zeptoclaw": "ZeptoClaw config and workspace MCP config",
        "hermes": "Hermes config",
        "cursor": "Cursor MCP config",
        "windsurf": "Windsurf MCP config",
        "geminicli": "Gemini CLI settings",
        "copilot": "Copilot hook MCP config",
        "openhands": "OpenHands MCP config",
        "antigravity": "Antigravity MCP config",
        "opencode": "OpenCode MCP config",
    }
    return hints.get(name, "connector-specific MCP config")


def _mcp_list_json_items(
    servers: list[MCPServerEntry],
    scan_map: dict[str, dict],
    actions_map: dict,
    *,
    connector: str = "",
) -> list[dict]:
    """Build the flat JSON item list for one connector's MCP servers.

    This is the per-connector payload; the multi-connector default wraps
    these in ``{"connector": ..., "mcp_servers": [...]}`` groups while a
    single-connector install emits the bare list (byte-compatible with
    the pre-fan-out shape).
    """
    out = []
    for s in servers:
        transport = connector_paths.infer_mcp_transport(
            s.transport, url=s.url, command=s.command,
        )
        entry: dict = {"name": s.name, "transport": transport}
        if connector:
            entry["connector"] = connector
        if s.command:
            entry["command"] = s.command
        if s.args:
            entry["args"] = s.args
        if s.url:
            entry["url"] = s.url
        if s.name in scan_map:
            entry["severity"] = scan_map[s.name]["max_severity"]
        if s.name in actions_map:
            ae = actions_map[s.name]
            if not ae.actions.is_empty():
                entry["actions"] = ae.actions.to_dict()
        verdict_label, _ = _compute_verdict(
            actions_map.get(s.name), scan_map.get(s.name),
        )
        entry["verdict"] = verdict_label
        out.append(entry)
    return out


def _print_mcp_list_table(
    servers: list[MCPServerEntry],
    scan_map: dict[str, dict],
    actions_map: dict,
    connector: str,
) -> None:
    """Render one connector-tagged MCP server table."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title=f"MCP Servers (connector={connector})")
    table.add_column("Name", style="bold")
    table.add_column("Transport")
    table.add_column("Command")
    table.add_column("URL")
    table.add_column("Severity")
    table.add_column("Verdict")
    table.add_column("Actions")

    config_names = {s.name for s in servers}

    for s in servers:
        severity = "-"
        sev_style = ""
        if s.name in scan_map:
            severity = scan_map[s.name]["max_severity"]
            sev_style = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "cyan",
                "CLEAN": "green",
            }.get(severity, "")

        actions_str = "-"
        if s.name in actions_map:
            actions_str = actions_map[s.name].actions.summary()

        verdict_label, verdict_style = _compute_verdict(
            actions_map.get(s.name), scan_map.get(s.name),
        )

        table.add_row(
            s.name,
            connector_paths.infer_mcp_transport(
                s.transport, url=s.url, command=s.command,
            ),
            s.command or "",
            s.url or "",
            f"[{sev_style}]{severity}[/{sev_style}]" if sev_style else severity,
            f"[{verdict_style}]{verdict_label}[/{verdict_style}]" if verdict_style else verdict_label,
            actions_str,
        )

    # Orphan-action rows ("removed from config") are only shown for OpenClaw's
    # connector view. Other connector catalogs are authoritative, and scoped
    # action rows must not leak into unrelated peers.
    if connector == "openclaw":
        for name, ae in actions_map.items():
            if name in config_names:
                continue
            if ae.actions.is_empty():
                continue
            actions_str = ae.actions.summary()
            table.add_row(
                f"[dim]{name}[/dim]",
                "[dim]—[/dim]",
                "[dim]removed from config[/dim]",
                "",
                "-",
                "[dim]enforcement only[/dim]",
                actions_str,
            )

    console.print(table)


_MCP_SCOPED_SCAN_PREFIX = "mcp://"


def _mcp_scoped_scan_target(connector: str, name: str) -> str:
    """Audit target for a configured MCP server copy."""
    return f"{_MCP_SCOPED_SCAN_PREFIX}{connector_paths.normalize(connector)}/{name}"


def _parse_mcp_scoped_scan_target(target: str) -> tuple[str, str]:
    """Return ``(connector, name)`` for connector-scoped MCP scan targets."""
    if not target.startswith(_MCP_SCOPED_SCAN_PREFIX):
        return "", ""
    rest = target[len(_MCP_SCOPED_SCAN_PREFIX):]
    if "/" not in rest:
        return "", ""
    connector, name = rest.split("/", 1)
    return connector_paths.normalize(connector), name


def _build_mcp_scan_map(
    store, servers: list[MCPServerEntry], connector: str = "",
    *, allow_legacy_plain: bool | None = None,
) -> dict[str, dict]:
    """Build a map of server-name -> latest scan from the DB."""
    scan_map: dict[str, dict] = {}
    if store is None:
        return scan_map
    try:
        latest = store.latest_scans_by_scanner("mcp-scanner")
    except Exception:
        return scan_map

    url_to_name: dict[str, str] = {}
    configured_names = {s.name for s in servers}
    for s in servers:
        if s.url:
            url_to_name[s.url] = s.name

    normalized_connector = connector_paths.normalize(connector) if connector else ""
    if allow_legacy_plain is None:
        allow_legacy_plain = not bool(normalized_connector)
    scan_rank: dict[str, int] = {}
    for ls in latest:
        target = ls["target"]
        if target in url_to_name:
            name = url_to_name[target]
            rank = 1
        else:
            scoped_connector, scoped_name = _parse_mcp_scoped_scan_target(target)
            if scoped_connector:
                if (
                    normalized_connector
                    and scoped_connector == normalized_connector
                    and scoped_name in configured_names
                ):
                    name = scoped_name
                    rank = 2
                else:
                    continue
            elif "/" not in target and allow_legacy_plain:
                name = target
                rank = 0
            else:
                continue
        if rank < scan_rank.get(name, -1):
            continue
        finding_count = ls["finding_count"]
        scan_map[name] = {
            "target": target,
            "clean": finding_count == 0,
            "max_severity": ls["max_severity"] if finding_count > 0 else "CLEAN",
            "total_findings": finding_count,
        }
        scan_rank[name] = rank
    return scan_map


def _effective_mcp_action_entry(
    global_entry: ActionEntry | None, scoped_entry: ActionEntry | None,
) -> ActionEntry | None:
    """Merge global + scoped rows using policy-engine per-field fallback."""
    if global_entry is None:
        return scoped_entry
    if scoped_entry is None or scoped_entry.actions.is_empty():
        return global_entry
    actions = ActionState(
        file=scoped_entry.actions.file or global_entry.actions.file,
        runtime=scoped_entry.actions.runtime or global_entry.actions.runtime,
        install=scoped_entry.actions.install or global_entry.actions.install,
    )
    return ActionEntry(
        id=scoped_entry.id,
        target_type=scoped_entry.target_type,
        target_name=scoped_entry.target_name,
        source_path=scoped_entry.source_path or global_entry.source_path,
        actions=actions,
        reason=scoped_entry.reason or global_entry.reason,
        updated_at=scoped_entry.updated_at,
        connector=scoped_entry.connector,
    )


def _build_mcp_actions_map(store, connector: str = "") -> dict:
    """Build effective server-name -> ActionEntry for one connector view."""
    actions_map: dict = {}
    if store is None:
        return actions_map
    try:
        entries = store.list_actions_by_type("mcp")
    except Exception:
        return actions_map
    normalized_connector = connector_paths.normalize(connector) if connector else ""
    for e in entries:
        if e.connector:
            continue
        actions_map.setdefault(e.target_name, e)
    if not normalized_connector:
        return actions_map
    scoped_seen: set[str] = set()
    for e in entries:
        if connector_paths.normalize(e.connector) == normalized_connector and e.target_name not in scoped_seen:
            actions_map[e.target_name] = _effective_mcp_action_entry(
                actions_map.get(e.target_name), e,
            )
            scoped_seen.add(e.target_name)
    return actions_map


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

def _resolve_scan_target(
    app: AppContext, target: str, connector: str | None = None
) -> tuple[str, MCPServerEntry | None]:
    """Resolve *target* to a scannable URL/spec and optional server entry.

    If *target* contains ``://`` it is treated as a URL and returned as-is.
    Otherwise it is looked up in ``mcp.servers`` for *connector* (defaults
    to the active connector when ``None``, so single-connector behaviour is
    unchanged). Passing the resolved connector lets ``mcp scan <name>
    --connector <c>`` find a server registered to a non-primary connector
    instead of silently looking it up in the active connector's config.
    Returns (scan_target, server_entry) — server_entry is set for local
    stdio servers so the scanner can spawn them.
    """
    if "://" in target:
        return target, None

    servers = app.cfg.mcp_servers(connector)
    by_name = {s.name: s for s in servers}
    server = by_name.get(target)
    if server is None:
        names = sorted(by_name.keys())
        hint = f"  Available: {', '.join(names)}" if names else "  No MCP servers configured."
        # Name the connector actually searched rather than a hardcoded
        # "openclaw.json" — in a multi-connector install the source is the
        # connector-specific config (e.g. claudecode → .claude/settings.json),
        # so the legacy filename was misleading. ``connector`` may be None
        # (single-connector default), in which case resolve the active one.
        searched = connector or (
            app.cfg.active_connector()
            if hasattr(app.cfg, "active_connector")
            else "openclaw"
        )
        raise click.ClickException(
            f"MCP server {target!r} not found for connector {searched!r}.\n{hint}"
        )

    if server.url:
        return server.url, server
    if server.command:
        return target, server
    raise click.ClickException(
        f"MCP server {target!r} has neither url nor command — cannot scan.",
    )


def _run_scan(app: AppContext, target: str, analyzers: str,
              scan_prompts: bool, scan_resources: bool,
              scan_instructions: bool,
              server_entry: MCPServerEntry | None = None,
              quiet: bool = False,
              allow_private: bool = False,
              connector: str = "",
              json_error_sink: list[dict] | None = None,
              audit_target: str = "") -> ScanResult | None:
    """Run the MCP scanner on *target*.  Returns None on fatal error."""
    from dataclasses import replace

    from defenseclaw.scanner.mcp import MCPScannerWrapper

    scan_cfg = app.cfg.scanners.mcp_scanner
    if analyzers:
        scan_cfg = replace(scan_cfg, analyzers=analyzers)
    if scan_prompts:
        scan_cfg = replace(scan_cfg, scan_prompts=True)
    if scan_resources:
        scan_cfg = replace(scan_cfg, scan_resources=True)
    if scan_instructions:
        scan_cfg = replace(scan_cfg, scan_instructions=True)

    # Route through the unified resolver so top-level ``llm:`` defaults
    # flow into the MCP scanner with ``scanners.mcp.llm:`` overrides
    # applied on top. ``effective_inspect_llm()`` is kept only for the
    # back-compat signature; the ``llm=`` kwarg is what the wrapper
    # actually uses internally.
    resolved_llm = app.cfg.resolve_llm("scanners.mcp")
    scanner = MCPScannerWrapper(
        scan_cfg,
        app.cfg.effective_inspect_llm(),
        app.cfg.cisco_ai_defense,
        llm=resolved_llm,
    )
    # R4: overlay the configured guardrail rule pack onto the server definition
    # (command/args/env/url). No-op when no rule_pack_dir is set.
    from defenseclaw.scanner.rulepack import maybe_wrap

    scanner = maybe_wrap(scanner, app.cfg)
    # NOTE: pre-S6.4 this printed "Scanning MCP server: <target>"; the
    # new shared scan UX renders that information once via
    # ``_scan_ui.render_preamble`` + a per-target glyph line, so we
    # no longer need a per-server announce-line here.
    def _emit_captured_stdout(text: str) -> None:
        for line in text.splitlines():
            if line:
                click.echo(line, err=True)

    captured_stdout: io.StringIO | None = None
    try:
        if quiet:
            with _route_mcpscanner_logs_to_stderr(), _capture_scan_stdout() as stdout_buffer:
                captured_stdout = stdout_buffer
                result = scanner.scan(
                    target, server_entry=server_entry, allow_private=allow_private
                )
            _emit_captured_stdout(captured_stdout.getvalue())
        else:
            result = scanner.scan(
                target, server_entry=server_entry, allow_private=allow_private
            )
    except SystemExit:
        raise
    except Exception as exc:
        if quiet and captured_stdout is not None:
            _emit_captured_stdout(captured_stdout.getvalue())
        if quiet:
            payload = _mcp_scan_error_json_payload(
                target, exc, connector=connector,
            )
            if json_error_sink is not None:
                json_error_sink.append(payload)
            else:
                click.echo(json.dumps(payload, indent=2))
        else:
            click.echo(f"error: scan failed: {exc}", err=True)
        return None

    if app.logger:
        app.logger.log_scan(replace(result, target=audit_target) if audit_target else result)
    return result


def _mcp_scan_error_json_payload(
    target: str, exc: Exception, *, connector: str = "",
) -> dict:
    payload = {
        "scanner": "mcp-scanner",
        "target": target,
        "error": f"scan failed: {exc}",
        "findings": [],
    }
    if connector:
        payload = {
            "scanner": payload["scanner"],
            "connector": connector_paths.normalize(connector),
            "target": payload["target"],
            "error": payload["error"],
            "findings": payload["findings"],
        }
    return payload


def _mcp_scan_result_json_payload(
    result: ScanResult, *, connector: str = "",
) -> dict:
    payload = json.loads(result.to_json())
    if connector:
        payload = {
            "scanner": payload["scanner"],
            "connector": connector_paths.normalize(connector),
            **{k: v for k, v in payload.items() if k != "scanner"},
        }
    return payload


@contextmanager
def _route_mcpscanner_logs_to_stderr() -> Iterator[None]:
    """Keep third-party MCP scanner logging off JSON stdout."""
    import sys

    known_names = {
        "mcpscanner",
        "mcpscanner.core",
        "mcpscanner.core.scanner",
        "mcpscanner.core.analyzers",
        "mcpscanner.core.analyzers.llm_analyzer",
    }
    known_names.update(
        name for name in logging.root.manager.loggerDict
        if isinstance(name, str) and name.startswith("mcpscanner")
    )

    loggers = [logging.getLogger(name) for name in sorted(known_names)]
    mcpscanner_logger = logging.getLogger("mcpscanner")
    original_propagate = mcpscanner_logger.propagate
    stream_handlers: list[tuple[logging.StreamHandler, object]] = []
    seen_handlers: set[int] = set()

    for logger in loggers:
        for handler in logger.handlers:
            if not isinstance(handler, logging.StreamHandler):
                continue
            ident = id(handler)
            if ident in seen_handlers:
                continue
            seen_handlers.add(ident)
            stream_handlers.append((handler, handler.stream))
            try:
                handler.setStream(sys.stderr)
            except (AttributeError, ValueError):
                handler.stream = sys.stderr

    try:
        # If the SDK logger would otherwise bubble into a root handler pointed
        # at stdout, JSON mode would still get prefixed with timestamped logs.
        mcpscanner_logger.propagate = False
        yield
    finally:
        mcpscanner_logger.propagate = original_propagate
        for handler, stream in stream_handlers:
            try:
                handler.setStream(stream)
            except (AttributeError, ValueError):
                handler.stream = stream


@contextmanager
def _capture_scan_stdout() -> Iterator[io.StringIO]:
    """Capture SDK stdout so JSON-mode stdout remains parseable.

    The MCP SDK may emit through ordinary ``print`` calls, Python logging
    handlers that captured the original stdout stream, or direct writes to fd
    1. ``redirect_stdout`` catches only the first case, so JSON mode also
    redirects the process stdout file descriptor for the duration of the SDK
    call and appends anything captured there to the same buffer.
    """
    import contextlib
    import sys
    import tempfile

    captured = io.StringIO()
    original_stdout = sys.stdout
    fd: int | None = None
    saved_fd: int | None = None
    tmp = None

    for stream in (original_stdout, getattr(sys, "__stdout__", None)):
        if stream is None:
            continue
        try:
            fd = stream.fileno()
            break
        except (AttributeError, io.UnsupportedOperation, OSError):
            continue
    if fd is None:
        try:
            os.fstat(1)
            fd = 1
        except OSError:
            fd = None

    if fd is not None:
        try:
            original_stdout.flush()
            saved_fd = os.dup(fd)
            tmp = tempfile.TemporaryFile(mode="w+b")
            os.dup2(tmp.fileno(), fd)
        except OSError:
            if saved_fd is not None:
                os.close(saved_fd)
            if tmp is not None:
                tmp.close()
            fd = None
            saved_fd = None
            tmp = None

    try:
        with contextlib.redirect_stdout(captured):
            yield captured
    finally:
        if fd is not None and saved_fd is not None and tmp is not None:
            try:
                original_stdout.flush()
            except OSError:
                pass
            os.dup2(saved_fd, fd)
            os.close(saved_fd)
            tmp.seek(0)
            captured.write(tmp.read().decode(errors="replace"))
            tmp.close()


def _print_scan_result(
    result: ScanResult, as_json: bool, *, connector: str = "",
) -> None:
    """Print the *details* of a scan result.

    The shared ``_scan_ui`` preamble + per-target glyph + summary is
    rendered by the caller (S6.4); this function now only emits the
    JSON payload, or — in human mode — the per-finding breakdown that
    appears underneath the per-target line. Keeping the breakdown
    here so call sites don't have to replicate the per-finding loop.
    """
    if as_json:
        click.echo(json.dumps(
            _mcp_scan_result_json_payload(result, connector=connector),
            indent=2,
        ))
        return
    if result.is_clean():
        return
    for f in result.findings:
        sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(f.severity, "white")
        click.echo(f"    {ux._style(f'[{f.severity}]', fg=sev_color, bold=True)}", nl=False)
        click.echo(f" {f.title}")
        if f.location:
            click.echo(f"      {ux.dim('Location:')} {f.location}")
        if f.description:
            desc = f.description[:120] + "..." if len(f.description) > 120 else f.description
            click.echo(f"      {desc}")
        if f.remediation:
            click.echo(f"      {ux.dim('Fix:')} {f.remediation}")


def _scan_all_mcp(
    app: AppContext,
    connector: str,
    analyzers: str,
    scan_prompts: bool,
    scan_resources: bool,
    scan_instructions: bool,
    as_json: bool,
    allow_private: bool = False,
    error_count_sink: list[int] | None = None,
) -> list[dict]:
    """Scan every MCP server registered for ``connector``.

    Extracted from ``mcp scan --all`` so a multi-connector install can fan
    out across each configured connector's servers (``cfg.mcp_servers(connector)``).
    """
    import time

    from defenseclaw.commands import _scan_ui
    from defenseclaw.enforce import PolicyEngine

    servers = app.cfg.mcp_servers(connector)
    if not servers:
        if not as_json:
            click.echo(f"No MCP servers configured for connector={connector!r}.")
        return []

    # F-0324: ``--all`` previously scanned every configured server with
    # no policy check, so a server an operator had explicitly blocked
    # (by name or URL) was still spawned/dialed. Filter blocked servers
    # out before scanning; checking both the name and the resolved
    # url/spec mirrors the single-target guard (F-0323).
    pe = PolicyEngine(app.store)
    scan_targets = []
    for s in servers:
        scan_target = s.url or s.name
        # N2: honor a per-connector block — resolve most-specific-wins for the
        # connector being scanned (connector-scoped entry, else global), so a
        # block scoped to a different peer doesn't skip this connector's scan.
        if pe.is_blocked_for_connector(
            "mcp", s.name, connector
        ) or pe.is_blocked_for_connector("mcp", scan_target, connector):
            if not as_json:
                click.echo(
                    f"BLOCKED: {s.name} — skipping (remove from block list first)",
                    err=True,
                )
            continue
        scan_targets.append((s, scan_target))

    if not scan_targets:
        if not as_json:
            click.echo(
                f"No scannable MCP servers for connector={connector!r} "
                "(all blocked or none configured)."
            )
        return []
    ctx = _scan_ui.ScanContext.for_mcp(
        connector=connector,
        paths=sorted({t for _, t in scan_targets}),
        as_json=as_json,
    )
    _scan_ui.render_preamble(ctx, target_count=len(scan_targets))

    clean = blocked = errored = 0
    json_rows: list[dict] = []
    started = time.monotonic()

    for s, scan_target in scan_targets:
        json_errors: list[dict] = []
        result = _run_scan(
            app, scan_target, analyzers,
            scan_prompts, scan_resources, scan_instructions,
            server_entry=s, quiet=as_json,
            allow_private=allow_private,
            connector=connector,
            json_error_sink=json_errors if as_json else None,
            audit_target=_mcp_scoped_scan_target(connector, s.name),
        )
        if result is None:
            errored += 1
            if as_json:
                json_rows.extend(json_errors)
            else:
                _scan_ui.render_per_target_status(
                    ctx, target=s.name, verdict=_scan_ui.VERDICT_ERROR,
                    detail="see error log above",
                )
            continue
        if as_json:
            json_rows.append(_mcp_scan_result_json_payload(result, connector=connector))
        else:
            if result.is_clean():
                clean += 1
                _scan_ui.render_per_target_status(
                    ctx, target=s.name, verdict=_scan_ui.VERDICT_CLEAN, findings=0,
                )
            else:
                blocked += 1
                _scan_ui.render_per_target_status(
                    ctx,
                    target=s.name,
                    verdict=_scan_ui.VERDICT_BLOCKED,
                    detail=f"max severity: {result.max_severity()}",
                    findings=len(result.findings),
                )
            _print_scan_result(result, as_json, connector=connector)

    if not as_json:
        duration_ms = int((time.monotonic() - started) * 1000)
        _scan_ui.render_summary(
            ctx,
            clean=clean,
            blocked=blocked,
            errored=errored,
            total=clean + blocked + errored,
            duration_ms=duration_ms,
        )
        from defenseclaw.commands import hint
        if blocked:
            hint("View alerts:  defenseclaw alerts")
    if error_count_sink is not None:
        error_count_sink.append(errored)
    return json_rows


def _connector_has_server(app: AppContext, connector: str, name: str) -> bool:
    """True when *connector*'s MCP config registers a server called *name*."""
    return any(s.name == name for s in app.cfg.mcp_servers(connector))


def _connector_owns_mcp_target(app: AppContext, connector: str, target: str) -> bool:
    """True when *connector* registers *target* as an MCP name or URL."""
    return any(
        s.name == target or (s.url and s.url == target)
        for s in app.cfg.mcp_servers(connector)
    )


def _mcp_policy_fanout_connectors(
    app: AppContext, pe, target: str,
) -> list[str]:
    """Connectors where a bare MCP policy command should apply.

    Bare allow/unblock targets configured server copies by name/URL and also
    includes stale connector-scoped policy rows so cleanup still works after a
    server copy has been removed from config.
    """
    from defenseclaw.commands import resolve_list_connectors

    configured = resolve_list_connectors(app, "")
    order = {connector_paths.normalize(c): idx for idx, c in enumerate(configured)}
    seen: set[str] = set()
    connectors: list[str] = []

    def add(connector: str) -> None:
        normalized = connector_paths.normalize(connector)
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        connectors.append(normalized)

    for connector in configured:
        if _connector_owns_mcp_target(app, connector, target):
            add(connector)

    list_by_type = getattr(pe, "list_by_type", None)
    if callable(list_by_type):
        entries = list_by_type("mcp")
        if isinstance(entries, list):
            for entry in entries:
                if entry.target_name == target and entry.connector:
                    add(entry.connector)

    return sorted(connectors, key=lambda c: order.get(c, len(order)))


def _mcp_has_connector_enforcement(
    app: AppContext, target: str, connector: str,
) -> bool:
    if app.store is None:
        return False
    return (
        app.store.has_action("mcp", target, "install", "block", connector)
        or app.store.has_action("mcp", target, "install", "allow", connector)
        or app.store.has_action("mcp", target, "file", "quarantine", connector)
        or app.store.has_action("mcp", target, "runtime", "disable", connector)
    )


def _scan_name_not_found_msg(
    app: AppContext, target: str, connectors: list[str],
) -> str:
    """Build the 'not found on any configured connector' message for a bare name.

    Names the connectors actually searched (each reads its own per-connector
    source) and lists what *is* available, rather than the legacy hardcoded
    'openclaw.json' mental model.
    """
    available = sorted({
        s.name for c in connectors for s in app.cfg.mcp_servers(c)
    })
    avail = (
        f"  Available: {', '.join(available)}"
        if available
        else "  No MCP servers configured on any configured connector."
    )
    return (
        f"MCP server {target!r} not found on any configured connector "
        f"({', '.join(connectors)}).\n{avail}"
    )


def _scan_one_resolved(
    app: AppContext,
    connector: str,
    target: str,
    *,
    analyzers: str,
    scan_prompts: bool,
    scan_resources: bool,
    scan_instructions: bool,
    as_json: bool,
    allow_private: bool,
    pe,
    emit_hints: bool,
) -> str:
    """Resolve, block-check, and scan a single name/URL within one connector.

    Renders the shared scan UX (preamble + per-target glyph + summary) and
    returns one of ``"clean"`` / ``"findings"`` / ``"policy-blocked"`` /
    ``"error"`` so the caller maps it to an exit code. Factored out of
    ``scan`` so a bare-name fan-out across several owning connectors (M3) can
    reuse the exact single-target rendering. ``emit_hints`` is suppressed in
    the multi-owner loop so the next-step hints print once, not per connector.
    """
    import time

    from defenseclaw.commands import _scan_ui, hint

    resolved, entry = _resolve_scan_target(app, target, connector)

    # F-0323: a server may be blocked by its NAME or by its resolved URL —
    # check both keys so neither path bypasses the block list. N2: resolve
    # most-specific-wins for this connector (connector-scoped entry, else
    # global) so a peer-scoped block only skips the scan for that peer.
    for blocked_key in {target, resolved}:
        if pe.is_blocked_for_connector("mcp", blocked_key, connector):
            click.echo(
                f"BLOCKED: {blocked_key} — remove from block list first",
                err=True,
            )
            return "policy-blocked"

    ctx = _scan_ui.ScanContext.for_mcp(
        connector=connector, paths=[resolved], as_json=as_json,
    )
    _scan_ui.render_preamble(ctx, target_count=1)

    started = time.monotonic()
    result = _run_scan(
        app, resolved, analyzers, scan_prompts, scan_resources,
        scan_instructions, server_entry=entry, quiet=as_json,
        allow_private=allow_private,
        connector=connector,
        audit_target=_mcp_scoped_scan_target(connector, entry.name) if entry else "",
    )
    if result is None:
        return "error"

    if as_json:
        _print_scan_result(result, as_json, connector=connector)
        return "clean" if result.is_clean() else "findings"

    if result.is_clean():
        _scan_ui.render_per_target_status(
            ctx, target=target, verdict=_scan_ui.VERDICT_CLEAN, findings=0,
        )
    else:
        _scan_ui.render_per_target_status(
            ctx,
            target=target,
            verdict=_scan_ui.VERDICT_BLOCKED,
            detail=f"max severity: {result.max_severity()}",
            findings=len(result.findings),
        )
    _print_scan_result(result, as_json, connector=connector)
    duration_ms = int((time.monotonic() - started) * 1000)
    _scan_ui.render_summary(
        ctx,
        clean=1 if result.is_clean() else 0,
        blocked=0 if result.is_clean() else 1,
        errored=0,
        total=1,
        duration_ms=duration_ms,
    )
    if emit_hints:
        if result.is_clean():
            hint("Scan MCP servers:  defenseclaw mcp scan --all")
        else:
            hint(
                f"Block server:  defenseclaw mcp block {target}",
                "View alerts:   defenseclaw alerts",
            )
    return "clean" if result.is_clean() else "findings"


@mcp.command()
@click.argument("target", required=False)
@click.option("--json", "as_json", is_flag=True, help="Output results as JSON")
@click.option("--analyzers", default="", help="Comma-separated analyzer list")
@click.option("--scan-prompts", is_flag=True, help="Also scan MCP prompts")
@click.option("--scan-resources", is_flag=True, help="Also scan MCP resources")
@click.option("--scan-instructions", is_flag=True, help="Also scan server instructions")
@click.option(
    "--all", "scan_all", is_flag=True,
    help=(
        "Scan every configured server across configured connectors "
        "(use --connector <name> to scope to one)."
    ),
)
@click.option(
    "--connector", "connector_flag", default="",
    help=(
        "Scope scanning to one connector: narrows a bare-name lookup to it, "
        "scans just that connector when no TARGET is given, or limits --all "
        "to it. Default: search/scan every configured connector."
    ),
)
@click.option(
    "--allow-private", "allow_private", is_flag=True,
    help=(
        "Opt in to scanning remote MCP targets that resolve to private, "
        "loopback, link-local or CGNAT addresses (blocked by default to "
        "prevent SSRF)."
    ),
)
@pass_ctx
def scan(
    app: AppContext,
    target: str | None,
    as_json: bool,
    analyzers: str,
    scan_prompts: bool,
    scan_resources: bool,
    scan_instructions: bool,
    scan_all: bool,
    connector_flag: str,
    allow_private: bool,
) -> None:
    """Scan an MCP server by name or URL.

    \b
    Modes:
      mcp scan <name>            scan a server by name — searched across every
                                 configured connector's MCP config (use --connector
                                 <name> to scope the lookup to one peer)
      mcp scan <url>             scan a direct URL
      mcp scan --connector <c>   scan every server configured on connector <c>
      mcp scan --all             scan every server on every configured connector

    TARGET resolves against the configured connector(s)' own MCP config (not a
    single shared file); on a multi-connector install a bare name is found
    wherever it lives.
    """
    from defenseclaw.commands import (
        resolve_list_connector,
        resolve_list_connectors,
    )
    from defenseclaw.enforce import PolicyEngine

    if scan_all:
        # An explicit --connector targets exactly one connector; otherwise a
        # no-flag scan uses the plural resolver so a zero-connector config exits
        # with guidance instead of falling back through active_connector().
        connectors = resolve_list_connectors(app, connector_flag)
        json_rows: list[dict] = []
        error_counts: list[int] = []
        for c in connectors:
            if len(connectors) > 1 and not as_json:
                click.secho(f"\n── connector: {c} ──", fg="cyan")
            rows = _scan_all_mcp(
                app, c, analyzers, scan_prompts, scan_resources, scan_instructions,
                as_json, allow_private=allow_private,
                error_count_sink=error_counts,
            )
            if as_json:
                json_rows.extend(rows)
        if as_json:
            click.echo(json.dumps(json_rows, indent=2))
        if sum(error_counts):
            raise SystemExit(1)
        return

    if not target:
        # M4: a discoverable single-connector scan — `mcp scan --connector X`
        # (no --all, no target) scans every server on that one connector.
        if connector_flag:
            connector = resolve_list_connector(app, connector_flag)
            error_counts: list[int] = []
            rows = _scan_all_mcp(
                app, connector, analyzers, scan_prompts, scan_resources,
                scan_instructions, as_json, allow_private=allow_private,
                error_count_sink=error_counts,
            )
            if as_json:
                click.echo(json.dumps(rows, indent=2))
            if sum(error_counts):
                raise SystemExit(1)
            return
        raise click.UsageError(
            "Specify what to scan:\n"
            "  defenseclaw mcp scan <name>            one server (searched across "
            "configured connectors)\n"
            "  defenseclaw mcp scan <url>             a direct URL\n"
            "  defenseclaw mcp scan --connector <c>   every server on connector <c>\n"
            "  defenseclaw mcp scan --all             every server on every configured "
            "connector"
        )

    connector = resolve_list_connector(app, connector_flag)

    pe = PolicyEngine(app.store)
    common = dict(
        analyzers=analyzers,
        scan_prompts=scan_prompts,
        scan_resources=scan_resources,
        scan_instructions=scan_instructions,
        as_json=as_json,
        allow_private=allow_private,
        pe=pe,
    )

    # An explicit --connector or a direct URL keeps the single-resolution
    # contract: resolve against the chosen connector (the active one when no
    # flag was passed) and scan exactly that target.
    if connector_flag or "://" in target:
        status = _scan_one_resolved(app, connector, target, emit_hints=True, **common)
        if status == "policy-blocked":
            raise SystemExit(2)
        if status == "error":
            raise SystemExit(1)
        return

    # M3: a bare name with no --connector is searched across EVERY active
    # connector's MCP config — a server registered on a non-active peer is
    # still found instead of erroring "not found for connector <active>".
    # Decision (locked): scan ALL connectors that own the name.
    connectors = resolve_list_connectors(app, "")
    owners = [c for c in connectors if _connector_has_server(app, c, target)]
    if not owners:
        raise click.ClickException(_scan_name_not_found_msg(app, target, connectors))

    if len(owners) == 1:
        # Single owner → identical UX/exit semantics to an explicit target.
        status = _scan_one_resolved(app, owners[0], target, emit_hints=True, **common)
        if status == "policy-blocked":
            raise SystemExit(2)
        if status == "error":
            raise SystemExit(1)
        return

    # Multiple owners → scan each, labeled per connector (mirrors `--all`). A
    # block-listed (or neither-url-nor-command) owner is noted and skipped so
    # one peer never aborts the rest; a hard scan error still exits non-zero.
    errored = False
    for c in owners:
        if not as_json:
            click.secho(f"\n── connector: {c} ──", fg="cyan")
        try:
            if _scan_one_resolved(app, c, target, emit_hints=False, **common) == "error":
                errored = True
        except click.ClickException as exc:
            errored = True
            click.echo(f"error [{c}]: {exc.format_message()}", err=True)
    if errored:
        raise SystemExit(1)

# ---------------------------------------------------------------------------
# block / allow / unblock  (accept name or url)
#
# N2: these accept ``--connector`` to scope the action. Bare block still writes
# an unscoped entry that applies across configured connectors; bare allow and
# unblock fan out to matching configured server copies plus any stale scoped
# policy rows for that target. ``--connector <name>`` narrows the entry to one
# peer. The connector dimension lives in the audit store's per-connector column
# (f/dbmig SK-4 foundation) via PolicyEngine.{block,allow,unblock,
# remove_action,is_blocked,is_allowed}_for_connector (mirrored in Go
# internal/enforce/policy.go). Reads resolve most-specific-wins (connector
# entry, then unscoped), so an unscoped block still applies to every connector
# while a connector-scoped block applies only to its peer.
#
# Runtime honoring: the Python admission gate (enforce/admission.py) threads the
# connector into its block/allow check, so ``mcp set --connector X`` honors a
# per-connector block. NOTE (cross-lane gap, flagged): there is no Go runtime
# enforcement point that reads the MCP block list — the install-watcher excludes
# MCP and the gateway gates tools/assets, not the mcp block list — so even a
# unscoped ``mcp block`` is not honored by a Go runtime gate today. Wiring that
# is a separate Go-gate follow-up (out of this lane).
# ---------------------------------------------------------------------------

_CONNECTOR_BLOCK_HELP = (
    "Scope to one connector. Default: create an unscoped policy entry "
    "that applies across configured connectors. "
    "Pass --connector <name> to narrow to that peer."
)


@mcp.command()
@click.argument("target")
@click.option("--reason", default="", help="Reason for blocking")
@click.option("--connector", "connector_flag", default="", help=_CONNECTOR_BLOCK_HELP)
@pass_ctx
def block(app: AppContext, target: str, reason: str, connector_flag: str) -> None:
    """Block an MCP server (by name or URL).

    Bare ``mcp block <name>`` creates an unscoped block entry that applies
    across configured connectors; ``--connector <name>`` narrows the block to
    one peer.
    """
    from defenseclaw.commands import resolve_list_connector
    from defenseclaw.enforce import PolicyEngine

    pe = PolicyEngine(app.store)
    connector = resolve_list_connector(app, connector_flag) if connector_flag else ""
    # Most-specific-wins guard so we never write a redundant connector row when
    # a global block already covers this peer. The bare path keeps the pre-N2
    # global calls.
    if connector:
        if pe.is_blocked_for_connector("mcp", target, connector):
            if app.store and app.store.has_action(
                "mcp", target, "install", "block", connector,
            ):
                click.echo(f"Already blocked for {connector}: {target}")
            else:
                click.echo(f"Already blocked globally (covers {connector}): {target}")
            return
        pe.block_for_connector(
            "mcp", target, connector, reason or "manually blocked via CLI",
        )
        click.secho(f"Blocked: {target} (connector={connector})", fg="red")
    else:
        if pe.is_blocked("mcp", target):
            click.echo(f"Already blocked: {target}")
            return
        pe.block("mcp", target, reason or "manually blocked via CLI")
        click.secho(f"Blocked: {target}", fg="red")

    if app.logger:
        app.logger.log_action(
            "block-mcp", target, f"reason={reason} connector={connector}",
        )


@mcp.command()
@click.argument("target")
@click.option("--reason", default="", help="Reason for allowing")
@click.option(
    "--connector", "connector_flag", default="",
    help=(
        "Scope to one connector. Default: allow matching configured server "
        "copies and clear stale scoped blocks. "
        "Pass --connector <name> to narrow to that peer."
    ),
)
@pass_ctx
def allow(app: AppContext, target: str, reason: str, connector_flag: str) -> None:
    """Allow an MCP server (by name or URL).

    Bare ``mcp allow <name>`` allows matching configured server copies;
    ``--connector <name>`` narrows the allow to one peer. A connector-scoped
    allow is authoritative for that peer before unscoped fallback applies.
    """
    from defenseclaw.commands import resolve_list_connector
    from defenseclaw.enforce import PolicyEngine

    pe = PolicyEngine(app.store)
    connector = resolve_list_connector(app, connector_flag) if connector_flag else ""
    if connector:
        if pe.is_allowed_for_connector("mcp", target, connector):
            if app.store and app.store.has_action(
                "mcp", target, "install", "allow", connector,
            ):
                click.echo(f"Already allowed for {connector}: {target}")
            else:
                click.echo(f"Already allowed globally (covers {connector}): {target}")
            return
        pe.allow_for_connector(
            "mcp", target, connector, reason or "manually allowed via CLI",
        )
        click.secho(f"Allowed: {target} (connector={connector})", fg="green")
    else:
        targets = _mcp_policy_fanout_connectors(app, pe, target)
        if targets:
            for target_connector in targets:
                pe.allow_for_connector(
                    "mcp",
                    target,
                    target_connector,
                    reason or "manually allowed via CLI",
                )
                click.secho(
                    f"Allowed: {target} (connector={target_connector})",
                    fg="green",
                )
            if app.store and pe.get_action("mcp", target) is not None:
                pe.remove_action("mcp", target)
            if app.logger:
                app.logger.log_action(
                    "allow-mcp", target, f"reason={reason} connector=all",
                )
            return
        if pe.is_allowed("mcp", target):
            click.echo(f"Already allowed: {target}")
            return
        pe.allow("mcp", target, reason or "manually allowed via CLI")
        click.secho(f"Allowed: {target}", fg="green")

    if app.logger:
        app.logger.log_action(
            "allow-mcp", target, f"reason={reason} connector={connector}",
        )


@mcp.command()
@click.argument("target")
@click.option(
    "--connector", "connector_flag", default="",
    help=(
        "Scope to one connector. Default: clear matching connector copies and "
        "unscoped state. "
        "Pass --connector <name> to clear only that peer's per-connector state; "
        "an unscoped block stays in force."
    ),
)
@pass_ctx
def unblock(app: AppContext, target: str, connector_flag: str) -> None:
    """Remove an MCP server from the block list and clear enforcement state.

    Unlike 'allow', this does not add the server to the allow list — it
    simply removes the block so the server goes through normal scanning
    on the next check.

    Bare ``mcp unblock <name>`` clears matching connector-scoped and unscoped
    enforcement state; ``--connector <name>`` clears only that peer's
    per-connector state (an unscoped block stays in force).
    """
    from defenseclaw.commands import resolve_list_connector
    from defenseclaw.enforce import PolicyEngine

    pe = PolicyEngine(app.store)
    connector = resolve_list_connector(app, connector_flag) if connector_flag else ""

    # State check is EXACT-match on the targeted scope (global when no
    # --connector), so a connector-scoped unblock never falsely reports a
    # global block as clearable and remove_action stays exact-match.
    if connector:
        has_state = bool(app.store) and (
            app.store.has_action("mcp", target, "install", "block", connector)
            or app.store.has_action("mcp", target, "install", "allow", connector)
            or app.store.has_action("mcp", target, "file", "quarantine", connector)
            or app.store.has_action("mcp", target, "runtime", "disable", connector)
        )
    else:
        targets = _mcp_policy_fanout_connectors(app, pe, target)
        has_unscoped_state = bool(app.store) and (
            pe.is_blocked("mcp", target)
            or pe.is_allowed("mcp", target)
            or pe.is_quarantined("mcp", target)
            or app.store.has_action("mcp", target, "runtime", "disable")
        )
        has_scoped_state = any(
            _mcp_has_connector_enforcement(app, target, target_connector)
            for target_connector in targets
        )
        if targets and (has_unscoped_state or has_scoped_state):
            for target_connector in targets:
                pe.remove_action_for_connector("mcp", target, target_connector)
                click.secho(
                    f"[mcp] {target!r} all enforcement state cleared "
                    f"(connector={target_connector}) "
                    f"(allow/block/quarantine/disable)",
                    fg="green",
                )
            if has_unscoped_state:
                pe.remove_action("mcp", target)
            click.echo(
                "  The server will go through normal scanning on next check."
            )
            if app.logger:
                app.logger.log_action(
                    "mcp-unblock", target, "manual unblock via CLI connector=all",
                )
            return
        has_state = has_unscoped_state
    if not has_state:
        scope = f" for {connector}" if connector else ""
        click.echo(f"[mcp] {target!r} has no enforcement state to clear{scope}")
        return

    if connector:
        pe.remove_action_for_connector("mcp", target, connector)
    else:
        pe.remove_action("mcp", target)
    scope = f" (connector={connector})" if connector else ""
    click.secho(
        f"[mcp] {target!r} all enforcement state cleared{scope} "
        f"(allow/block/quarantine/disable)",
        fg="green",
    )
    click.echo(
        "  The server will go through normal scanning on next check."
    )

    if app.logger:
        app.logger.log_action(
            "mcp-unblock", target, f"manual unblock via CLI connector={connector}",
        )


# ---------------------------------------------------------------------------
# set / unset  — connector-aware: delegate writes to the active
# connector's preferred surface.
# ---------------------------------------------------------------------------
#
# OpenClaw uses ``openclaw config set/unset`` (schema-validated +
# hot-reloaded). Claude Code and Codex have no equivalent CLI, so
# we patch ``~/.claude/settings.json`` and ``~/.codex/config.toml``
# directly, with explicit workspace overlays handled by the atomic JSON
# helpers in :mod:`defenseclaw.connector_paths`.
# ZeptoClaw owns its config.json from the TUI and does not expose a
# safe write surface — we surface a clear error rather than racing
# ZeptoClaw's autosave.

def _openclaw_config_set(path: str, value: str) -> None:
    """Write a value via ``openclaw config set`` (schema-validated, hot-reloaded)."""
    from defenseclaw.config import openclaw_bin, openclaw_cmd_prefix
    prefix = openclaw_cmd_prefix()
    result = subprocess.run(
        [*prefix, openclaw_bin(), "config", "set", path, value, "--strict-json"],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise click.ClickException(f"openclaw config set failed: {detail}")


def _openclaw_config_unset(path: str) -> None:
    """Remove a value via ``openclaw config unset``."""
    from defenseclaw.config import openclaw_bin, openclaw_cmd_prefix
    prefix = openclaw_cmd_prefix()
    result = subprocess.run(
        [*prefix, openclaw_bin(), "config", "unset", path],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise click.ClickException(f"openclaw config unset failed: {detail}")


def _set_mcp_via_connector(cfg, name: str, entry: dict, connector: str | None = None) -> None:
    """Dispatch ``mcp set`` to a connector's write surface.

    ``connector`` targets a specific connector (``mcp set --connector``);
    defaults to the active connector so single-connector behaviour is
    unchanged. Lets :class:`connector_paths.MCPWriteUnsupportedError`
    propagate so the fan-out caller can turn an unsupported connector into
    a per-connector skip (rather than aborting the whole fleet).
    """
    connector_paths.set_mcp_server(
        connector or cfg.active_connector(),
        name,
        entry,
        workspace_dir=cfg.connector_workspace_dir() if hasattr(cfg, "connector_workspace_dir") else None,
        openclaw_config_setter=_openclaw_config_set,
    )


def _unset_mcp_via_connector(cfg, name: str, connector: str | None = None) -> None:
    """Dispatch ``mcp unset`` to a connector's write surface.
    Symmetric with :func:`_set_mcp_via_connector`.
    """
    connector_paths.unset_mcp_server(
        connector or cfg.active_connector(),
        name,
        workspace_dir=cfg.connector_workspace_dir() if hasattr(cfg, "connector_workspace_dir") else None,
        openclaw_config_unsetter=_openclaw_config_unset,
    )


# ---------------------------------------------------------------------------
# opencode write gate (M5) — opencode EXECUTES the command[] it stores in
# opencode.json, so a `mcp set --connector opencode` write needs input
# validation ON TOP OF admission: sanitise the server name + command and block
# commands outside trusted install prefixes unless the operator explicitly
# forces the write. Scoped to opencode because it is the connector that runs an
# argv DefenseClaw writes into a config file from the CLI (other connectors are
# owned by their lanes).
# ---------------------------------------------------------------------------

# The name becomes a JSON key under opencode's top-level ``mcp`` map pointing
# at an executed server, so reject anything that isn't a plain identifier (no
# path separators, spaces, or shell metacharacters).
_OPENCODE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _validate_opencode_write(name: str, cmd: str, url: str) -> str | None:
    """Hard input validation for an opencode MCP write.

    Returns a human-readable refusal reason, or ``None`` when the inputs are
    safe to write. Admission has already run; this is the extra sanitisation a
    write of an executable into a file opencode RUNS requires.
    """
    if not _OPENCODE_NAME_RE.match((name or "").strip()):
        return (
            f"invalid opencode server name {name!r}: use letters, digits, "
            "'.', '-', '_' (no path separators, spaces, or shell characters)"
        )
    # A local (command) server must carry a real executable; a remote server
    # carries a url instead. ``set`` already requires one of the two upstream.
    if not url:
        if not (cmd or "").strip():
            return "opencode local server needs a non-empty --command"
        if any(ch in cmd for ch in ("\x00", "\n", "\r")):
            return "opencode command contains control characters"
    return None


def _opencode_command_trust_error(cmd: str) -> str | None:
    """Return a refusal reason when an opencode command is not trusted.

    Reuses the SAME allow-list the passive discovery exec-gate uses so the trust
    rule can't drift. Operators with a bespoke install can either add the
    directory to ``DEFENSECLAW_TRUSTED_BIN_PREFIXES`` or pass
    ``--force-untrusted-command`` on this one write.
    """
    c = (cmd or "").strip()
    if not c:
        return None
    # ``_is_trusted_binary_path`` needs an absolute path; resolve a bare
    # command via PATH the way opencode would at launch.
    from defenseclaw.inventory.agent_discovery import _is_trusted_binary_path

    resolved = c if os.path.isabs(c) else shutil.which(c)
    if resolved is None:
        return (
            f"opencode command {c!r} was not found on PATH — opencode will fail "
            "to launch this server until it is installed/resolvable"
        )
    if not _is_trusted_binary_path(resolved):
        return (
            f"opencode will EXECUTE {c!r} (resolved {resolved!r}), which is not "
            "in a trusted install prefix"
        )
    return None


@mcp.command("set")
@click.argument("name")
@click.option("--command", "cmd", default="", help="Server command (e.g. npx, uvx)")
@click.option("--args", "args_str", default="", help="Command args (JSON array or comma-separated)")
@click.option("--url", default="", help="Server URL (for SSE/HTTP transport)")
@click.option("--transport", default="", help="Transport type (stdio, sse)")
@click.option("--env", "env_pairs", multiple=True, help="Env vars as KEY=VAL (repeatable)")
@click.option("--skip-scan", is_flag=True, help="Skip security scan before adding")
@click.option(
    "--force-untrusted-command",
    is_flag=True,
    help="For opencode only: write a command outside trusted install prefixes.",
)
@click.option(
    "--connector", "connector_flag", default="",
    help="Scope to one connector's MCP config (default: every configured connector)",
)
@pass_ctx
def set_server(
    app: AppContext,
    name: str,
    cmd: str,
    args_str: str,
    url: str,
    transport: str,
    env_pairs: tuple[str, ...],
    skip_scan: bool,
    force_untrusted_command: bool,
    connector_flag: str,
) -> None:
    """Add or update an MCP server in the configured connector(s)' MCP config.

    Writes go to each configured connector's own config file (or one peer with
    --connector) — not a single shared config.

    Scans the server before adding unless --skip-scan is set.
    Rejects servers with HIGH/CRITICAL findings.

    \b
    Examples:
      defenseclaw mcp set context7 --command uvx --args context7-mcp
      defenseclaw mcp set deepwiki --url https://mcp.deepwiki.com/mcp
      defenseclaw mcp set myserver --command npx --args '["-y", "@myorg/mcp-server"]'
      defenseclaw mcp set myserver --command node --args server.js --env API_KEY=xxx
      defenseclaw mcp set untrusted --url http://example.com/mcp --skip-scan
    """
    from defenseclaw.commands import resolve_list_connectors
    from defenseclaw.enforce import PolicyEngine
    from defenseclaw.enforce.admission import evaluate_admission

    if not cmd and not url:
        raise click.ClickException(
            "Provide at least --command or --url.\n\n"
            "Examples:\n"
            "  defenseclaw mcp set myserver --command uvx --args my-mcp-server\n"
            "  defenseclaw mcp set myserver --url https://example.com/mcp"
        )

    # F-1821: --command and --url are mutually exclusive. The scanner decides
    # local vs remote with ``is_local = (command and not url)`` (scanner/mcp.py),
    # so a mixed entry takes the REMOTE path and scans the benign URL while the
    # local --command is what actually gets installed and run at admission time.
    # That lets a malicious publisher pair a clean URL (scanned) with an
    # unscanned command (executed). Reject the mismatch so the thing SCANNED is
    # always the thing INSTALLED (command XOR url).
    if cmd and url:
        raise click.ClickException(
            "Provide exactly one of --command or --url, not both.\n\n"
            "A local command and a remote URL are scanned differently, so a "
            "mixed entry would scan one and run the other. Choose one:\n"
            "  defenseclaw mcp set myserver --command uvx --args my-mcp-server\n"
            "  defenseclaw mcp set myserver --url https://example.com/mcp"
        )

    # Without --connector, set the server on EVERY configured connector; with it,
    # scope to one. The scan (finding generation) is connector-independent so
    # it runs once, but ADMISSION is evaluated PER connector: a connector-
    # scoped asset-policy rule (rule.connector) must gate only its own
    # connector, so a server rejected on one connector is skipped there while
    # still being written to the connectors that admit it.
    connectors = resolve_list_connectors(app, connector_flag)
    pe = PolicyEngine(app.store)
    parsed_args = _parse_args(args_str) if args_str else []

    entry: dict = {}
    if cmd:
        entry["command"] = cmd
    if args_str:
        entry["args"] = parsed_args
    if url:
        entry["url"] = url
    if transport:
        entry["transport"] = transport
    if env_pairs:
        env: dict[str, str] = {}
        for pair in env_pairs:
            if "=" not in pair:
                raise click.ClickException(f"Invalid --env format: {pair!r} (expected KEY=VAL)")
            k, v = pair.split("=", 1)
            env[k] = v
        entry["env"] = env

    def _admit(connector: str, scan_result=None):
        return evaluate_admission(
            pe,
            policy_dir=app.cfg.policy_dir,
            target_type="mcp",
            name=name,
            scan_result=scan_result,
            fallback_actions=app.cfg.mcp_actions,
            source_path=(cmd or url or "") if scan_result is not None else "",
            connector=connector,
            command=cmd,
            args=parsed_args,
            url=url,
            transport=transport,
            asset_policy=app.cfg.asset_policy,
        )

    # Pre-scan admission per connector. "blocked" (block list or a connector-
    # scoped asset rule) and "allowed" (an allow override) are decided here;
    # "scan" means that connector still needs a scan verdict.
    pre = {c: _admit(c) for c in connectors}

    # Scan once when at least one connector needs a verdict and --skip-scan was
    # not passed. Findings are connector-independent, so a single scan serves
    # the whole fan-out.
    result = None
    if (not skip_scan) and any(d.verdict == "scan" for d in pre.values()):
        # Propagate entry["env"] into the install-time scan entry. The
        # scanner spawns the local MCP subprocess to probe it; building
        # the scan entry WITHOUT env= means install-time scanning runs in
        # a different environment from what is ultimately written to the
        # connector config, so a malicious publisher could hide dangerous
        # behavior behind an env gate that only triggers at runtime.
        # Mirror runtime env.
        scan_env = entry.get("env") if isinstance(entry.get("env"), dict) else {}
        scan_entry = MCPServerEntry(
            name=name, command=cmd, args=parsed_args, url=url, transport=transport,
            env=dict(scan_env),
        )
        audit_target = (
            _mcp_scoped_scan_target(connectors[0], name)
            if len(connectors) == 1
            else ""
        )
        result = _run_scan(
            app, url or name, "", False, False, False,
            server_entry=scan_entry, audit_target=audit_target,
        )
        if result is None:
            click.secho("Scan failed — use --skip-scan to add anyway.", fg="yellow")
            raise SystemExit(1)
        _print_scan_result(result, as_json=False)

    applied: list[str] = []
    skipped: list[str] = []          # connector has no writable MCP surface
    policy_blocked: list[str] = []   # rejected by block list / asset rule
    scan_rejected: list[str] = []    # rejected by scan-findings policy
    invalid_input: list[str] = []    # opencode name/command failed validation
    write_failed: list[tuple[str, Exception]] = []  # unexpected write error
    for c in connectors:
        pre_c = pre[c]
        if pre_c.verdict == "blocked":
            click.secho(f"  blocked [{c}]: {pre_c.reason}", fg="red")
            policy_blocked.append(c)
            continue
        # M5 security gate (opencode only): opencode EXECUTES the command[] it
        # stores, so validate/sanitise the server name + command and block an
        # untrusted command prefix unless the operator forces the write.
        # Admission already ran above; invalid input refuses just this
        # connector (the fan-out continues).
        if connector_paths.normalize(c) == "opencode":
            gate_err = _validate_opencode_write(name, cmd, url)
            if gate_err:
                click.secho(f"  refused [{c}]: {gate_err}", fg="red")
                invalid_input.append(c)
                continue
            trust_err = _opencode_command_trust_error(cmd)
            if trust_err:
                if force_untrusted_command:
                    ux.warn(
                        f"{trust_err}. Proceeding because "
                        "--force-untrusted-command was supplied."
                    )
                else:
                    click.secho(
                        f"  refused [{c}]: {trust_err}. Add the directory to "
                        "DEFENSECLAW_TRUSTED_BIN_PREFIXES or re-run with "
                        "--force-untrusted-command.",
                        fg="red",
                    )
                    invalid_input.append(c)
                    continue
        allow_record = False
        if pre_c.verdict == "allowed":
            note = (
                f"Policy allows {name} without scan"
                if pre_c.source == "scan-disabled"
                else f"Allowed override for {name} — skipping scan"
            )
            click.secho(f"  {note} [{c}]", fg="yellow")
        elif result is not None:
            post_c = _admit(c, scan_result=result)
            if post_c.verdict == "rejected":
                sev = result.max_severity()
                click.secho(
                    f"  blocked [{c}]: {sev} findings — rejected by mcp_actions policy "
                    "(use --skip-scan to override)",
                    fg="red",
                )
                scan_rejected.append(c)
                continue
            allow_record = post_c.action.install == "allow"
        try:
            _set_mcp_via_connector(app.cfg, name, entry, connector=c)
            applied.append(c)
            if allow_record:
                pe.allow_for_connector("mcp", name, c, "scan clean or within policy")
        except connector_paths.MCPWriteUnsupportedError as exc:
            click.secho(f"  skipped [{c}]: {exc}", fg="yellow")
            skipped.append(c)
        except Exception as exc:  # noqa: BLE001 — isolate unexpected per-connector write
            # MCPWriteUnsupportedError above is the *expected* "no write surface"
            # case (benign skip). Any other error is unexpected — a disk-full,
            # locked-config, or serialization failure. A single-connector target
            # keeps fail-loud, pre-fan-out behavior (propagate verbatim); with
            # multiple targets one connector's failure must not abort the rest or
            # leave a silent partial write, so it is isolated and surfaced via a
            # non-zero exit below.
            if len(connectors) == 1:
                raise
            click.secho(f"  failed [{c}]: {exc}", fg="red")
            write_failed.append((c, exc))

    if not applied:
        # Scan rejection is recorded for each connector that rejected the
        # server, avoiding an unscoped row that would shadow unrelated peers.
        if scan_rejected and result is not None:
            reason = f"scan: {len(result.findings)} findings, max={result.max_severity()}"
            for c in scan_rejected:
                pe.block_for_connector("mcp", name, c, reason)
            if app.logger:
                app.logger.log_action(
                    "mcp-set-blocked", name,
                    f"severity={result.max_severity()} findings={len(result.findings)} "
                    f"connectors={','.join(scan_rejected)}",
                )
            raise SystemExit(1)
        reasons = []
        if policy_blocked:
            reasons.append(f"blocked by policy: {', '.join(policy_blocked)}")
        if scan_rejected:
            reasons.append(f"scan-rejected: {', '.join(scan_rejected)}")
        if skipped:
            reasons.append(f"no MCP write surface: {', '.join(skipped)}")
        if invalid_input:
            reasons.append(f"invalid input: {', '.join(invalid_input)}")
        if write_failed:
            reasons.append(f"write failed: {', '.join(c for c, _ in write_failed)}")
        raise click.ClickException(
            f"MCP set failed: no connector accepted {name!r} ({'; '.join(reasons)})."
        )

    not_applied = (
        policy_blocked + scan_rejected + skipped + invalid_input
        + [c for c, _ in write_failed]
    )
    # Always name the connectors that did NOT receive the server, even when the
    # server landed on 2+ connectors — otherwise a partial fan-out (e.g. 2
    # applied, 1 policy-blocked) prints a green "Added to 2 connectors" line
    # that silently omits the blocked/skipped peer.
    not_applied_suffix = (
        f" ({len(not_applied)} not applied: {', '.join(not_applied)})" if not_applied else ""
    )
    if len(applied) > 1:
        click.secho(
            f"Added MCP server: {name} to {len(applied)} connectors: "
            f"{', '.join(applied)}{not_applied_suffix}",
            fg="green",
        )
    elif not_applied:
        click.secho(
            f"Added MCP server: {name} to {applied[0]}{not_applied_suffix}",
            fg="green",
        )
    else:
        click.secho(f"Added MCP server: {name}", fg="green")

    if app.logger:
        app.logger.log_action("mcp-set", name, f"command={cmd} url={url} connectors={','.join(applied)}")

    # An unexpected per-connector write failure (not the benign "no write
    # surface" skip) is surfaced with a non-zero exit so scripts/CI notice the
    # partial application, while the connectors that did land are kept.
    if write_failed:
        if app.logger:
            app.logger.log_action(
                "mcp-set-failed", name, f"connectors={','.join(c for c, _ in write_failed)}"
            )
        raise SystemExit(1)

    from defenseclaw.commands import hint
    hint(f"Scan it now:  defenseclaw mcp scan {name}")


@mcp.command("unset")
@click.argument("name")
@click.option(
    "--connector", "connector_flag", default="",
    help="Scope to one connector's MCP config (default: every configured connector)",
)
@pass_ctx
def unset_server(app: AppContext, name: str, connector_flag: str) -> None:
    """Remove an MCP server from connector config.

    Without --connector the server is removed from EVERY configured connector that
    has it; --connector scopes the removal to one. Connectors that don't have
    the server are skipped (not an error) so one missing entry never blocks the
    rest.
    """
    from defenseclaw.commands import resolve_list_connectors

    connectors = resolve_list_connectors(app, connector_flag)
    removed: list[str] = []
    skipped: list[str] = []
    write_failed: list[tuple[str, Exception]] = []  # unexpected write error
    for c in connectors:
        if not any(s.name == name for s in app.cfg.mcp_servers(c)):
            continue
        try:
            _unset_mcp_via_connector(app.cfg, name, connector=c)
            removed.append(c)
        except connector_paths.MCPWriteUnsupportedError as exc:
            click.secho(f"  skipped [{c}]: {exc}", fg="yellow")
            skipped.append(c)
        except Exception as exc:  # noqa: BLE001 — isolate unexpected per-connector write
            # Parity with ``mcp set``: the benign "no write surface" case is
            # handled above; any other removal failure is unexpected. Re-raise
            # verbatim for a single-connector target, otherwise isolate it so a
            # writable peer is still cleaned up (surfaced via non-zero exit).
            if len(connectors) == 1:
                raise
            click.secho(f"  failed [{c}]: {exc}", fg="red")
            write_failed.append((c, exc))

    if not removed:
        if write_failed:
            raise click.ClickException(
                f"MCP server {name!r} removal failed on: "
                f"{', '.join(c for c, _ in write_failed)}."
            )
        if skipped:
            raise click.ClickException(
                f"MCP server {name!r} is present but not removable on: "
                f"{', '.join(skipped)} (no writable MCP surface)."
            )
        click.secho(
            f"MCP server {name!r} not configured on: {', '.join(connectors)}; "
            "nothing to remove.",
            fg="yellow",
        )
        if app.logger:
            app.logger.log_action("mcp-unset-noop", name, f"connectors={','.join(connectors)}")
        return

    if len(removed) > 1:
        click.secho(f"Removed MCP server: {name} from {', '.join(removed)}", fg="yellow")
    elif skipped:
        click.secho(
            f"Removed MCP server: {name} from {removed[0]} "
            f"({len(skipped)} skipped: {', '.join(skipped)})",
            fg="yellow",
        )
    else:
        click.secho(f"Removed MCP server: {name}", fg="yellow")

    if app.logger:
        app.logger.log_action("mcp-unset", name, f"connectors={','.join(removed)}")

    # Surface an unexpected per-connector removal failure with a non-zero exit
    # so scripts/CI notice the partial removal, while peers that were cleaned
    # up are kept.
    if write_failed:
        if app.logger:
            app.logger.log_action(
                "mcp-unset-failed", name, f"connectors={','.join(c for c, _ in write_failed)}"
            )
        raise SystemExit(1)
