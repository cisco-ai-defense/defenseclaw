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

Reads MCP server configuration from OpenClaw's ``mcp.servers`` key in
``~/.openclaw/openclaw.json``.  Writes go through the ``openclaw config``
CLI so OpenClaw validates the schema and hot-reloads cleanly.
"""

from __future__ import annotations

import json
import subprocess

import click

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
    """Manage MCP servers — scan, block, allow, list, set, unset."""


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

@mcp.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@pass_ctx
def list_mcps(app: AppContext, as_json: bool) -> None:
    """List MCP servers configured in OpenClaw."""
    from rich.console import Console
    from rich.table import Table

    servers = app.cfg.mcp_servers()
    scan_map = _build_mcp_scan_map(app.store, servers)
    actions_map = _build_mcp_actions_map(app.store)

    if as_json:
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
        click.echo(json.dumps(out, indent=2))
        return

    if not servers:
        click.echo("No MCP servers configured in openclaw.json (mcp.servers).")
        return

    console = Console()
    table = Table(title="MCP Servers (from openclaw.json)")
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

    from defenseclaw.commands import hint
    hint("Scan all servers:  defenseclaw mcp scan --all")


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

def _resolve_scan_target(app: AppContext, target: str) -> tuple[str, MCPServerEntry | None]:
    """Resolve *target* to a scannable URL/spec and optional server entry.

    If *target* contains ``://`` it is treated as a URL and returned as-is.
    Otherwise it is looked up in ``mcp.servers`` from openclaw.json.
    Returns (scan_target, server_entry) — server_entry is set for local
    stdio servers so the scanner can spawn them.
    """
    if "://" in target:
        return target, None

    servers = app.cfg.mcp_servers()
    by_name = {s.name: s for s in servers}
    server = by_name.get(target)
    if server is None:
        names = sorted(by_name.keys())
        hint = f"  Available: {', '.join(names)}" if names else "  No MCP servers configured."
        raise click.ClickException(f"MCP server {target!r} not found in openclaw.json.\n{hint}")

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
              quiet: bool = False) -> ScanResult | None:
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

    scanner = MCPScannerWrapper(scan_cfg, app.cfg.inspect_llm, app.cfg.cisco_ai_defense)
    if not quiet:
        click.echo(f"Scanning MCP server: {target}")

    try:
        result = scanner.scan(target, server_entry=server_entry)
    except SystemExit:
        raise
    except Exception as exc:
        click.echo(f"error: scan failed: {exc}", err=True)
        return None

    if app.logger:
        app.logger.log_scan(result)
    return result


def _print_scan_result(result: ScanResult, as_json: bool) -> None:
    if as_json:
        click.echo(result.to_json())
    elif result.is_clean():
        click.secho("  Status: CLEAN", fg="green")
    else:
        sev = result.max_severity()
        color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(sev, "white")
        click.secho(
            f"  Status: {sev} ({len(result.findings)} findings)",
            fg=color,
        )
        click.echo()
        for f in result.findings:
            sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(f.severity, "white")
            click.secho(f"    [{f.severity}]", fg=sev_color, nl=False)
            click.echo(f" {f.title}")
            if f.location:
                click.echo(f"      Location: {f.location}")
            if f.description:
                desc = f.description[:120] + "..." if len(f.description) > 120 else f.description
                click.echo(f"      {desc}")
            if f.remediation:
                click.echo(f"      Fix: {f.remediation}")


@mcp.command()
@click.argument("target", required=False)
@click.option("--json", "as_json", is_flag=True, help="Output results as JSON")
@click.option("--analyzers", default="", help="Comma-separated analyzer list")
@click.option("--scan-prompts", is_flag=True, help="Also scan MCP prompts")
@click.option("--scan-resources", is_flag=True, help="Also scan MCP resources")
@click.option("--scan-instructions", is_flag=True, help="Also scan server instructions")
@click.option("--all", "scan_all", is_flag=True, help="Scan every server in openclaw.json")
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
) -> None:
    """Scan an MCP server by name or URL.

    TARGET can be a server name from openclaw.json or a direct URL.
    Use --all to scan every configured server.
    """
    from defenseclaw.enforce import PolicyEngine

    if scan_all:
        servers = app.cfg.mcp_servers()
        if not servers:
            click.echo("No MCP servers configured in openclaw.json.")
            return
        has_findings = False
        for s in servers:
            scan_target = s.url or s.name
            if not as_json:
                click.echo(f"\n{'─' * 40}")
            result = _run_scan(app, scan_target, analyzers,
                               scan_prompts, scan_resources, scan_instructions,
                               server_entry=s, quiet=as_json)
            if result:
                _print_scan_result(result, as_json)
                if not result.is_clean():
                    has_findings = True
        if not as_json:
            from defenseclaw.commands import hint
            if has_findings:
                hint("View alerts:  defenseclaw alerts")
            else:
                hint("Scan skills:  defenseclaw skill scan all")
        return

    if not target:
        raise click.UsageError("Missing argument 'TARGET'.")

    pe = PolicyEngine(app.store)
    resolved, entry = _resolve_scan_target(app, target)

    if pe.is_blocked("mcp", target):
        click.echo(f"BLOCKED: {target} — remove from block list first", err=True)
        raise SystemExit(2)

    result = _run_scan(app, resolved, analyzers,
                       scan_prompts, scan_resources, scan_instructions,
                       server_entry=entry, quiet=as_json)
    if result:
        _print_scan_result(result, as_json)
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
# set / unset  — delegate writes to ``openclaw config set/unset``
# ---------------------------------------------------------------------------

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


@mcp.command("set")
@click.argument("name")
@click.option("--command", "cmd", default="", help="Server command (e.g. npx, uvx)")
@click.option("--args", "args_str", default="", help="Command args (JSON array or comma-separated)")
@click.option("--url", default="", help="Server URL (for SSE/HTTP transport)")
@click.option("--transport", default="", help="Transport type (stdio, sse)")
@click.option("--env", "env_pairs", multiple=True, help="Env vars as KEY=VAL (repeatable)")
@click.option("--skip-scan", is_flag=True, help="Skip security scan before adding")
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
    from defenseclaw.enforce import PolicyEngine
    from defenseclaw.enforce.admission import evaluate_admission

    pe = PolicyEngine(app.store)
    pre_decision = evaluate_admission(
        pe,
        policy_dir=app.cfg.policy_dir,
        target_type="mcp",
        name=name,
        fallback_actions=app.cfg.mcp_actions,
        source_path="",
    )

    if pre_decision.verdict == "blocked":
        click.secho(f"BLOCKED: {name} — unblock it first with: defenseclaw mcp unblock {name}", fg="red")
        raise SystemExit(1)

    if not cmd and not url:
        raise click.ClickException(
            "Provide at least --command or --url.\n\n"
            "Examples:\n"
            "  defenseclaw mcp set myserver --command uvx --args my-mcp-server\n"
            "  defenseclaw mcp set myserver --url https://example.com/mcp"
        )

    entry: dict = {}
    if cmd:
        entry["command"] = cmd
    if args_str:
        entry["args"] = _parse_args(args_str)
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

    scan_required = (not skip_scan) and pre_decision.verdict != "allowed"
    if scan_required:
        scan_target = url or name
        scan_entry = MCPServerEntry(
            name=name,
            command=cmd,
            args=_parse_args(args_str) if args_str else [],
            url=url,
            transport=transport,
        )
        result = _run_scan(app, scan_target, "", False, False, False,
                           server_entry=scan_entry)
        if result is None:
            click.secho("Scan failed — use --skip-scan to add anyway.", fg="yellow")
            raise SystemExit(1)

        _print_scan_result(result, as_json=False)

        from defenseclaw.enforce import PolicyEngine

        sev = result.max_severity()
        post_decision = evaluate_admission(
            pe,
            policy_dir=app.cfg.policy_dir,
            target_type="mcp",
            name=name,
            scan_result=result,
            fallback_actions=app.cfg.mcp_actions,
            source_path=cmd or url or "",
        )
        if post_decision.verdict == "rejected":
            pe = PolicyEngine(app.store)
            pe.block("mcp", name, f"scan: {len(result.findings)} findings, max={sev}")
            click.secho(
                f"\nBlocked: {name} has {sev} findings — blocked by mcp_actions policy. "
                "Use --skip-scan to override.",
                fg="red",
            )
            if app.logger:
                app.logger.log_action(
                    "mcp-set-blocked", name,
                    f"severity={sev} findings={len(result.findings)}",
                )
            raise SystemExit(1)
    elif pre_decision.verdict == "allowed":
        if pre_decision.source == "scan-disabled":
            click.secho(f"Policy allows {name} without scan.", fg="yellow")
        else:
            click.secho(f"Allowed override for {name} — skipping scan.", fg="yellow")

    _openclaw_config_set(f"mcp.servers.{name}", json.dumps(entry))

    if scan_required:
        post_decision = evaluate_admission(
            pe,
            policy_dir=app.cfg.policy_dir,
            target_type="mcp",
            name=name,
            scan_result=result,
            fallback_actions=app.cfg.mcp_actions,
            source_path=cmd or url or "",
        )
        if post_decision.action.install == "allow":
            pe.allow("mcp", name, "scan clean or within policy")

    click.secho(f"Added MCP server: {name}", fg="green")

    if app.logger:
        app.logger.log_action("mcp-set", name, f"command={cmd} url={url}")

    from defenseclaw.commands import hint
    hint(f"Scan it now:  defenseclaw mcp scan {name}")


@mcp.command("unset")
@click.argument("name")
@pass_ctx
def unset_server(app: AppContext, name: str) -> None:
    """Remove an MCP server from OpenClaw config."""
    servers = app.cfg.mcp_servers()
    if not any(s.name == name for s in servers):
        raise click.ClickException(
            f"MCP server {name!r} not found in openclaw.json."
        )

    _openclaw_config_unset(f"mcp.servers.{name}")
    click.secho(f"Removed MCP server: {name}", fg="yellow")

    if app.logger:
        app.logger.log_action("mcp-unset", name, "")
