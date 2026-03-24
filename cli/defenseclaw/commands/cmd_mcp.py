"""defenseclaw mcp — Manage MCP servers (scan, block, allow, list).

Stub implementation — consolidates MCP ops that were previously
scattered across scan.go, block.go, allow.go in the Go CLI.
"""

from __future__ import annotations

import click

from defenseclaw.context import AppContext, pass_ctx


@click.group()
def mcp() -> None:
    """Manage MCP servers — scan, block, allow, list."""


@mcp.command()
@click.argument("url")
@click.option("--json", "as_json", is_flag=True, help="Output results as JSON")
@pass_ctx
def scan(app: AppContext, url: str, as_json: bool) -> None:
    """Scan an MCP server endpoint."""
    from defenseclaw.scanner.mcp import MCPScannerWrapper

    scanner = MCPScannerWrapper(app.cfg.scanners.mcp_scanner)
    click.echo(f"Scanning MCP server: {url}")

    try:
        result = scanner.scan(url)
    except SystemExit:
        raise
    except Exception as exc:
        click.echo(f"error: scan failed: {exc}", err=True)
        raise SystemExit(1)

    if app.logger:
        app.logger.log_scan(result)

    if as_json:
        click.echo(result.to_json())
    elif result.is_clean():
        click.secho("  Status: CLEAN", fg="green")
    else:
        click.secho(
            f"  Status: {result.max_severity()} ({len(result.findings)} findings)",
            fg="red",
        )
        for f in result.findings:
            click.echo(f"    [{f.severity}] {f.title}")


@mcp.command()
@click.argument("url")
@click.option("--reason", default="", help="Reason for blocking")
@pass_ctx
def block(app: AppContext, url: str, reason: str) -> None:
    """Block an MCP server endpoint."""
    from defenseclaw.enforce import PolicyEngine

    pe = PolicyEngine(app.store)
    if pe.is_blocked("mcp", url):
        click.echo(f"Already blocked: {url}")
        return
    pe.block("mcp", url, reason or "manually blocked via CLI")
    click.secho(f"Blocked: {url}", fg="red")

    if app.logger:
        app.logger.log_action("block-mcp", url, f"reason={reason}")


@mcp.command()
@click.argument("url")
@click.option("--reason", default="", help="Reason for allowing")
@pass_ctx
def allow(app: AppContext, url: str, reason: str) -> None:
    """Allow an MCP server endpoint."""
    from defenseclaw.enforce import PolicyEngine

    pe = PolicyEngine(app.store)
    if pe.is_allowed("mcp", url):
        click.echo(f"Already allowed: {url}")
        return
    pe.allow("mcp", url, reason or "manually allowed via CLI")
    click.secho(f"Allowed: {url}", fg="green")

    if app.logger:
        app.logger.log_action("allow-mcp", url, f"reason={reason}")


@mcp.command("list")
@pass_ctx
def list_mcps(app: AppContext) -> None:
    """List MCP servers with enforcement status."""
    from rich.console import Console
    from rich.table import Table

    from defenseclaw.enforce import PolicyEngine

    pe = PolicyEngine(app.store)
    entries = pe.list_by_type("mcp")

    if not entries:
        click.echo("No MCP servers in enforcement lists.")
        return

    console = Console()
    table = Table(title="MCP Servers")
    table.add_column("Endpoint", style="bold")
    table.add_column("Status")
    table.add_column("Reason")
    table.add_column("Updated")

    for e in entries:
        status = e.actions.summary()
        style = "red" if "blocked" in status else ("green" if "allowed" in status else "")
        table.add_row(
            e.target_name,
            f"[{style}]{status}[/{style}]" if style else status,
            e.reason[:50] + "..." if len(e.reason) > 50 else e.reason,
            e.updated_at.strftime("%Y-%m-%d %H:%M"),
        )

    console.print(table)
