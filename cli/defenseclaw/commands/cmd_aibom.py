"""defenseclaw aibom — AI Bill of Materials commands.

``scan``      — query live OpenClaw to index skills, plugins, MCP, agents, tools, models, memory
``generate``  — static file analysis via cisco-aibom (existing behaviour)
"""

from __future__ import annotations

import json

import click

from defenseclaw.context import AppContext, pass_ctx


@click.group()
def aibom() -> None:
    """AI Bill of Materials — scan live OpenClaw or generate static inventory."""


# ── scan (live OpenClaw inventory) ────────────────────────────────────────


@aibom.command()
@click.option("--json", "as_json", is_flag=True, help="Output full inventory as JSON")
@click.option("--summary", "summary_only", is_flag=True, help="Show summary table only")
@click.option(
    "--only",
    "categories",
    default=None,
    help="Comma-separated categories to scan: skills,plugins,mcp,agents,tools,models,memory",
)
@pass_ctx
def scan(app: AppContext, as_json: bool, summary_only: bool, categories: str | None) -> None:
    """Index a live OpenClaw install (skills, plugins, MCP, agents, tools, models, memory).

    Calls ``openclaw`` CLI commands in parallel and builds a unified inventory.
    Results are stored in the audit DB.

    Use --only to restrict which categories are collected (faster).
    Use --summary to show only the summary table.
    """
    from defenseclaw.inventory.claw_inventory import (
        build_claw_aibom,
        claw_aibom_to_scan_result,
        format_claw_aibom_human,
    )

    cats: set[str] | None = None
    if categories:
        cats = {c.strip().lower() for c in categories.split(",") if c.strip()}

    click.echo("Scanning live OpenClaw environment …", err=True)
    inv = build_claw_aibom(app.cfg, live=True, categories=cats)
    result = claw_aibom_to_scan_result(inv, app.cfg)

    if app.logger:
        app.logger.log_scan(result)

    errors = inv.get("errors", [])
    if errors:
        click.echo(f"Warning: {len(errors)} openclaw command(s) failed", err=True)

    if as_json:
        click.echo(json.dumps(inv, indent=2))
    else:
        format_claw_aibom_human(inv, summary_only=summary_only)


# ── generate (static cisco-aibom) ────────────────────────────────────────


@aibom.command()
@click.argument("path", default=".")
@click.option("--json", "as_json", is_flag=True, help="Output results as JSON")
@pass_ctx
def generate(app: AppContext, path: str, as_json: bool) -> None:
    """Static AI Bill of Materials for a directory (uses cisco-aibom).

    Runs cisco-aibom to inventory AI components, models, and dependencies
    found via file analysis.
    """
    from defenseclaw.scanner.aibom import AIBOMScannerWrapper

    scanner = AIBOMScannerWrapper(app.cfg.scanners.aibom)
    click.echo(f"Generating AIBOM for: {path}")

    try:
        result = scanner.scan(path)
    except SystemExit:
        raise
    except Exception as exc:
        click.echo(f"error: AIBOM generation failed: {exc}", err=True)
        raise SystemExit(1)

    if app.logger:
        app.logger.log_scan(result)

    if as_json:
        click.echo(result.to_json())
    else:
        click.echo(f"  Scanner:  {result.scanner}")
        click.echo(f"  Target:   {result.target}")
        click.echo(f"  Items:    {len(result.findings)}")
        for f in result.findings:
            click.echo(f"    [{f.severity}] {f.title}")
