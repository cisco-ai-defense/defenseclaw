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

Reads MCP server configuration from the active connector(s)'
connector-specific config (openclaw.json, .codex/config.toml,
.claude/settings.json, .zeptoclaw/config.json, …). For OpenClaw, writes
go through the ``openclaw config`` CLI so OpenClaw validates the schema
and hot-reloads cleanly; other connectors are written to their own
config files. ``list`` defaults to every active connector; ``scan --all``
fans out to every active connector.
"""

from __future__ import annotations

import json
import subprocess

import click

from defenseclaw import connector_paths, ux
from defenseclaw.commands import compute_verdict as _compute_verdict
from defenseclaw.config import MCPServerEntry
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.models import ScanResult


def _parse_args(raw: str) -> list[str]:
    """Parse ``--args`` value as a JSON array or comma-separated string."""
    stripped = raw.strip()
    if stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, list):
                return [str(a) for a in parsed]
        except json.JSONDecodeError:
            pass
    return [a.strip() for a in raw.split(",") if a.strip()]


@click.group()
def mcp() -> None:
    """Manage MCP servers — scan, block, allow, list, set, unset.

    Multi-connector: MCP config is read per-connector. ``mcp list`` shows
    every active connector's MCP servers by default (pass ``--connector
    X`` to narrow to one peer). The other subcommands take ``--connector
    X`` to target a configured peer (default: the active connector);
    ``mcp scan --all`` fans out across every active connector.
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
        "Default: every active connector (on a single-connector install, "
        "just that one). Pass --connector <name> to narrow to one peer."
    ),
)
@pass_ctx
def list_mcps(app: AppContext, as_json: bool, connector_flag: str) -> None:
    """List MCP servers configured for a connector.

    By default this lists **every active connector's** MCP servers — each
    connector gets its own connector-tagged table — so the output reads
    the same whether one or many connectors are active. ``--connector
    <name>`` narrows the listing to one configured peer.
    """
    from defenseclaw.commands import resolve_list_connectors

    connectors = resolve_list_connectors(app, connector_flag)
    actions_map = _build_mcp_actions_map(app.store)

    if as_json:
        if len(connectors) > 1:
            groups = []
            for c in connectors:
                servers = _collect_mcps_for_connector(app, c)
                scan_map = _build_mcp_scan_map(app.store, servers)
                groups.append({
                    "connector": c,
                    "mcp_servers": _mcp_list_json_items(servers, scan_map, actions_map),
                })
            click.echo(json.dumps(groups, indent=2, default=str))
        else:
            servers = _collect_mcps_for_connector(app, connectors[0])
            scan_map = _build_mcp_scan_map(app.store, servers)
            # Flat shape (no per-connector wrapper) keeps single-connector
            # installs byte-compatible with the pre-fan-out output.
            click.echo(json.dumps(
                _mcp_list_json_items(servers, scan_map, actions_map),
                indent=2,
            ))
        return

    shown_any = False
    for connector in connectors:
        servers = _collect_mcps_for_connector(app, connector)
        scan_map = _build_mcp_scan_map(app.store, servers)
        if not servers:
            ux.warn(
                f"No MCP servers configured for connector={connector!r} "
                "(checked the connector-specific source: openclaw.json / "
                ".claude/settings.json / .codex/config.toml / "
                ".zeptoclaw/config.json / user-global hook connector MCP files).",
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

    The connector-aware ``cfg.mcp_servers(connector)`` reads the
    connector-specific source (openclaw.json / .claude/settings.json /
    .codex/config.toml / .zeptoclaw/config.json / user-global hook
    connector MCP files), so each active connector resolves its own
    catalog when ``mcp list`` fans out.
    """
    return app.cfg.mcp_servers(connector)


def _mcp_list_json_items(
    servers: list[MCPServerEntry],
    scan_map: dict[str, dict],
    actions_map: dict,
) -> list[dict]:
    """Build the flat JSON item list for one connector's MCP servers.

    This is the per-connector payload; the multi-connector default wraps
    these in ``{"connector": ..., "mcp_servers": [...]}`` groups while a
    single-connector install emits the bare list (byte-compatible with
    the pre-fan-out shape).
    """
    out = []
    for s in servers:
        entry: dict = {"name": s.name, "transport": s.transport or "stdio"}
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
            s.transport or "stdio",
            s.command or "",
            s.url or "",
            f"[{sev_style}]{severity}[/{sev_style}]" if sev_style else severity,
            f"[{verdict_style}]{verdict_label}[/{verdict_style}]" if verdict_style else verdict_label,
            actions_str,
        )

    # Orphan-action rows ("removed from config") are connector-untagged
    # in the shared audit DB. Showing them on a non-OpenClaw connector
    # leaks OpenClaw-era MCP actions into the Codex / Claude Code /
    # ZeptoClaw view. Only surface them when the active connector is
    # OpenClaw — otherwise the connector-aware ``cfg.mcp_servers()`` is
    # already authoritative.
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


def _build_mcp_scan_map(store, servers: list[MCPServerEntry]) -> dict[str, dict]:
    """Build a map of server-name -> latest scan from the DB."""
    scan_map: dict[str, dict] = {}
    if store is None:
        return scan_map
    try:
        latest = store.latest_scans_by_scanner("mcp-scanner")
    except Exception:
        return scan_map

    url_to_name: dict[str, str] = {}
    for s in servers:
        if s.url:
            url_to_name[s.url] = s.name

    for ls in latest:
        target = ls["target"]
        if target in url_to_name:
            name = url_to_name[target]
        elif "/" not in target:
            name = target
        else:
            continue
        finding_count = ls["finding_count"]
        scan_map[name] = {
            "target": target,
            "clean": finding_count == 0,
            "max_severity": ls["max_severity"] if finding_count > 0 else "CLEAN",
            "total_findings": finding_count,
        }
    return scan_map


def _build_mcp_actions_map(store) -> dict:
    """Build a map of server-name -> ActionEntry from the DB."""
    actions_map: dict = {}
    if store is None:
        return actions_map
    try:
        entries = store.list_actions_by_type("mcp")
    except Exception:
        return actions_map
    for e in entries:
        actions_map[e.target_name] = e
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
              allow_private: bool = False) -> ScanResult | None:
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
    # NOTE: pre-S6.4 this printed "Scanning MCP server: <target>"; the
    # new shared scan UX renders that information once via
    # ``_scan_ui.render_preamble`` + a per-target glyph line, so we
    # no longer need a per-server announce-line here.
    _ = quiet  # parameter kept for back-compat with existing callers

    try:
        result = scanner.scan(
            target, server_entry=server_entry, allow_private=allow_private
        )
    except SystemExit:
        raise
    except Exception as exc:
        click.echo(f"error: scan failed: {exc}", err=True)
        return None

    if app.logger:
        app.logger.log_scan(result)
    return result


def _print_scan_result(result: ScanResult, as_json: bool) -> None:
    """Print the *details* of a scan result.

    The shared ``_scan_ui`` preamble + per-target glyph + summary is
    rendered by the caller (S6.4); this function now only emits the
    JSON payload, or — in human mode — the per-finding breakdown that
    appears underneath the per-target line. Keeping the breakdown
    here so call sites don't have to replicate the per-finding loop.
    """
    if as_json:
        click.echo(result.to_json())
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
) -> None:
    """Scan every MCP server registered for ``connector``.

    Extracted from ``mcp scan --all`` so a multi-connector install can fan
    out across each active connector's servers (``cfg.mcp_servers(connector)``).
    """
    import time

    from defenseclaw.commands import _scan_ui
    from defenseclaw.enforce import PolicyEngine

    servers = app.cfg.mcp_servers(connector)
    if not servers:
        if not as_json:
            click.echo(f"No MCP servers configured for connector={connector!r}.")
        return

    # F-0324: ``--all`` previously scanned every configured server with
    # no policy check, so a server an operator had explicitly blocked
    # (by name or URL) was still spawned/dialed. Filter blocked servers
    # out before scanning; checking both the name and the resolved
    # url/spec mirrors the single-target guard (F-0323).
    pe = PolicyEngine(app.store)
    scan_targets = []
    for s in servers:
        scan_target = s.url or s.name
        if pe.is_blocked("mcp", s.name) or pe.is_blocked("mcp", scan_target):
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
        return
    ctx = _scan_ui.ScanContext.for_mcp(
        connector=connector,
        paths=sorted({t for _, t in scan_targets}),
        as_json=as_json,
    )
    _scan_ui.render_preamble(ctx, target_count=len(scan_targets))

    clean = blocked = errored = 0
    started = time.monotonic()

    for s, scan_target in scan_targets:
        result = _run_scan(
            app, scan_target, analyzers,
            scan_prompts, scan_resources, scan_instructions,
            server_entry=s, quiet=as_json,
            allow_private=allow_private,
        )
        if result is None:
            errored += 1
            _scan_ui.render_per_target_status(
                ctx, target=s.name, verdict=_scan_ui.VERDICT_ERROR,
                detail="see error log above",
            )
            continue
        if as_json:
            _print_scan_result(result, as_json)
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
            _print_scan_result(result, as_json)

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
        else:
            hint("Scan skills:  defenseclaw skill scan all")


@mcp.command()
@click.argument("target", required=False)
@click.option("--json", "as_json", is_flag=True, help="Output results as JSON")
@click.option("--analyzers", default="", help="Comma-separated analyzer list")
@click.option("--scan-prompts", is_flag=True, help="Also scan MCP prompts")
@click.option("--scan-resources", is_flag=True, help="Also scan MCP resources")
@click.option("--scan-instructions", is_flag=True, help="Also scan server instructions")
@click.option("--all", "scan_all", is_flag=True, help="Scan every server in openclaw.json")
@click.option(
    "--connector", "connector_flag", default="",
    help=(
        "Scan a specific connector's MCP servers. Default for 'mcp scan "
        "--all' on multi-connector installs: every active connector (use "
        "--connector <name> to narrow to one)."
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

    TARGET can be a server name from openclaw.json or a direct URL.
    Use --all to scan every configured server.
    """
    import time

    from defenseclaw.commands import _scan_ui, resolve_list_connector
    from defenseclaw.enforce import PolicyEngine

    connector = resolve_list_connector(app, connector_flag)

    if scan_all:
        # An explicit --connector targets exactly one connector; otherwise a
        # multi-connector install scans every active connector's servers so
        # "--all" means every connector, not just the primary (parity).
        if connector_flag:
            connectors: list[str] = [connector]
        elif hasattr(app.cfg, "active_connectors") and len(app.cfg.active_connectors()) > 1:
            connectors = list(app.cfg.active_connectors())
        else:
            connectors = [connector]
        for c in connectors:
            if len(connectors) > 1 and not as_json:
                click.secho(f"\n── connector: {c} ──", fg="cyan")
            _scan_all_mcp(
                app, c, analyzers, scan_prompts, scan_resources, scan_instructions,
                as_json, allow_private=allow_private,
            )
        return

    if not target:
        raise click.UsageError("Missing argument 'TARGET'.")

    pe = PolicyEngine(app.store)
    # Resolve the named target against the chosen connector's MCP config
    # (``--connector``), not just the active connector's. ``connector`` is
    # the active connector when no flag was passed, so single-connector
    # behaviour is unchanged.
    resolved, entry = _resolve_scan_target(app, target, connector)

    # F-0323: a server may be blocked by its NAME or by its resolved
    # URL. Checking only the user-supplied ``target`` lets a URL-blocked
    # server be scanned via its alias (and a name-blocked server via its
    # URL). Check both keys so neither path bypasses the block list.
    for blocked_key in {target, resolved}:
        if pe.is_blocked("mcp", blocked_key):
            click.echo(
                f"BLOCKED: {blocked_key} — remove from block list first",
                err=True,
            )
            raise SystemExit(2)

    ctx = _scan_ui.ScanContext.for_mcp(
        connector=connector,
        paths=[resolved],
        as_json=as_json,
    )
    _scan_ui.render_preamble(ctx, target_count=1)

    started = time.monotonic()
    result = _run_scan(app, resolved, analyzers,
                       scan_prompts, scan_resources, scan_instructions,
                       server_entry=entry, quiet=as_json,
                       allow_private=allow_private)
    if result:
        if as_json:
            _print_scan_result(result, as_json)
        else:
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
            _print_scan_result(result, as_json)
            duration_ms = int((time.monotonic() - started) * 1000)
            _scan_ui.render_summary(
                ctx,
                clean=1 if result.is_clean() else 0,
                blocked=0 if result.is_clean() else 1,
                errored=0,
                total=1,
                duration_ms=duration_ms,
            )
        if not as_json:
            from defenseclaw.commands import hint
            if result.is_clean():
                hint("Scan skills:  defenseclaw skill scan all")
            else:
                hint(
                    f"Block server:  defenseclaw mcp block {target}",
                    "View alerts:   defenseclaw alerts",
                )
    else:
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# block / allow  (unchanged semantics, accept name or url)
# ---------------------------------------------------------------------------

@mcp.command()
@click.argument("target")
@click.option("--reason", default="", help="Reason for blocking")
@pass_ctx
def block(app: AppContext, target: str, reason: str) -> None:
    """Block an MCP server (by name or URL)."""
    from defenseclaw.enforce import PolicyEngine

    pe = PolicyEngine(app.store)
    if pe.is_blocked("mcp", target):
        click.echo(f"Already blocked: {target}")
        return
    pe.block("mcp", target, reason or "manually blocked via CLI")
    click.secho(f"Blocked: {target}", fg="red")

    if app.logger:
        app.logger.log_action("block-mcp", target, f"reason={reason}")


@mcp.command()
@click.argument("target")
@click.option("--reason", default="", help="Reason for allowing")
@pass_ctx
def allow(app: AppContext, target: str, reason: str) -> None:
    """Allow an MCP server (by name or URL)."""
    from defenseclaw.enforce import PolicyEngine

    pe = PolicyEngine(app.store)
    if pe.is_allowed("mcp", target):
        click.echo(f"Already allowed: {target}")
        return
    pe.allow("mcp", target, reason or "manually allowed via CLI")
    click.secho(f"Allowed: {target}", fg="green")

    if app.logger:
        app.logger.log_action("allow-mcp", target, f"reason={reason}")


@mcp.command()
@click.argument("target")
@pass_ctx
def unblock(app: AppContext, target: str) -> None:
    """Remove an MCP server from the block list and clear enforcement state.

    Unlike 'allow', this does not add the server to the allow list — it
    simply removes the block so the server goes through normal scanning
    on the next check.
    """
    from defenseclaw.enforce import PolicyEngine

    pe = PolicyEngine(app.store)

    has_state = (
        pe.is_blocked("mcp", target)
        or pe.is_quarantined("mcp", target)
        or app.store.has_action("mcp", target, "runtime", "disable")
    )
    if not has_state:
        click.echo(f"[mcp] {target!r} has no enforcement state to clear")
        return

    pe.remove_action("mcp", target)
    click.secho(
        f"[mcp] {target!r} all enforcement state cleared "
        f"(block/quarantine/disable)",
        fg="green",
    )
    click.echo(
        "  The server will go through normal scanning on next check."
    )

    if app.logger:
        app.logger.log_action("mcp-unblock", target, "manual unblock via CLI")


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


@mcp.command("set")
@click.argument("name")
@click.option("--command", "cmd", default="", help="Server command (e.g. npx, uvx)")
@click.option("--args", "args_str", default="", help="Command args (JSON array or comma-separated)")
@click.option("--url", default="", help="Server URL (for SSE/HTTP transport)")
@click.option("--transport", default="", help="Transport type (stdio, sse)")
@click.option("--env", "env_pairs", multiple=True, help="Env vars as KEY=VAL (repeatable)")
@click.option("--skip-scan", is_flag=True, help="Skip security scan before adding")
@click.option(
    "--connector", "connector_flag", default="",
    help="Scope to one connector's MCP config (default: every active connector)",
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
    connector_flag: str,
) -> None:
    """Add or update an MCP server in OpenClaw config.

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

    # Without --connector, set the server on EVERY active connector; with it,
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
        result = _run_scan(app, url or name, "", False, False, False, server_entry=scan_entry)
        if result is None:
            click.secho("Scan failed — use --skip-scan to add anyway.", fg="yellow")
            raise SystemExit(1)
        _print_scan_result(result, as_json=False)

    applied: list[str] = []
    skipped: list[str] = []          # connector has no writable MCP surface
    policy_blocked: list[str] = []   # rejected by block list / asset rule
    scan_rejected: list[str] = []    # rejected by scan-findings policy
    write_failed: list[tuple[str, Exception]] = []  # unexpected write error
    for c in connectors:
        pre_c = pre[c]
        if pre_c.verdict == "blocked":
            click.secho(f"  blocked [{c}]: {pre_c.reason}", fg="red")
            policy_blocked.append(c)
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
                pe.allow("mcp", name, "scan clean or within policy")
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
        # Universal scan rejection (connector-independent bad server): record
        # the global block + audit, matching the single-connector behavior.
        if scan_rejected and result is not None:
            pe.block("mcp", name, f"scan: {len(result.findings)} findings, max={result.max_severity()}")
            if app.logger:
                app.logger.log_action(
                    "mcp-set-blocked", name,
                    f"severity={result.max_severity()} findings={len(result.findings)}",
                )
            raise SystemExit(1)
        reasons = []
        if policy_blocked:
            reasons.append(f"blocked by policy: {', '.join(policy_blocked)}")
        if scan_rejected:
            reasons.append(f"scan-rejected: {', '.join(scan_rejected)}")
        if skipped:
            reasons.append(f"no MCP write surface: {', '.join(skipped)}")
        if write_failed:
            reasons.append(f"write failed: {', '.join(c for c, _ in write_failed)}")
        raise click.ClickException(
            f"MCP set failed: no connector accepted {name!r} ({'; '.join(reasons)})."
        )

    not_applied = policy_blocked + scan_rejected + skipped + [c for c, _ in write_failed]
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
    help="Scope to one connector's MCP config (default: every active connector)",
)
@pass_ctx
def unset_server(app: AppContext, name: str, connector_flag: str) -> None:
    """Remove an MCP server from connector config.

    Without --connector the server is removed from EVERY active connector that
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
        raise click.ClickException(
            f"MCP server {name!r} not found for any of: {', '.join(connectors)}."
        )

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
