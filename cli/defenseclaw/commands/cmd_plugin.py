"""defenseclaw plugin — Manage plugins (install, list, remove, scan)."""

from __future__ import annotations

import os
import shutil

import click

from defenseclaw.context import AppContext, pass_ctx


@click.group()
def plugin() -> None:
    """Manage DefenseClaw plugins — install, list, remove, scan."""


@plugin.command()
@click.argument("name_or_path")
@click.option("--json", "as_json", is_flag=True, help="Output scan results as JSON")
@pass_ctx
def scan(app: AppContext, name_or_path: str, as_json: bool) -> None:
    """Scan a plugin directory for security issues.

    Uses defenseclaw-plugin-scanner to check for dangerous permissions,
    install scripts, credential theft, obfuscation, and supply chain risks.
    """
    from defenseclaw.scanner.plugin import PluginScannerWrapper

    plugin_dir = app.cfg.plugin_dir
    scan_dir = name_or_path

    if not os.path.isdir(scan_dir):
        candidate = os.path.join(plugin_dir, name_or_path)
        if os.path.isdir(candidate):
            scan_dir = candidate
        else:
            click.echo(f"error: plugin not found: {name_or_path}", err=True)
            click.echo(f"  Provide a path or an installed plugin name from {plugin_dir}", err=True)
            raise SystemExit(1)

    scanner = PluginScannerWrapper()
    if not as_json:
        click.echo(f"[plugin] scanning {scan_dir}...")

    try:
        result = scanner.scan(scan_dir)
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
        click.secho(f"  Plugin: {os.path.basename(scan_dir)}", bold=True)
        click.secho("  Verdict: CLEAN", fg="green")
    else:
        sev = result.max_severity()
        color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(sev, "white")
        click.secho(f"  Plugin:   {os.path.basename(scan_dir)}", bold=True)
        click.echo(f"  Duration: {result.duration.total_seconds():.2f}s")
        click.secho(f"  Verdict:  {sev} ({len(result.findings)} findings)", fg=color)
        click.echo()
        for f in result.findings:
            sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(f.severity, "white")
            click.secho(f"    [{f.severity}]", fg=sev_color, nl=False)
            click.echo(f" {f.title}")
            if f.location:
                click.echo(f"      Location: {f.location}")
            if f.remediation:
                click.echo(f"      Fix: {f.remediation}")


@plugin.command()
@click.argument("name_or_path")
@pass_ctx
def install(app: AppContext, name_or_path: str) -> None:
    """Install a plugin from a path or registry."""
    plugin_dir = app.cfg.plugin_dir
    os.makedirs(plugin_dir, exist_ok=True)

    if os.path.isdir(name_or_path):
        name = os.path.basename(name_or_path.rstrip("/"))
        dest = os.path.join(plugin_dir, name)
        if os.path.exists(dest):
            click.echo(f"Plugin already installed: {name}")
            click.echo(f"  Remove first with: defenseclaw plugin remove {name}")
            return
        shutil.copytree(name_or_path, dest)
        click.echo(f"Installed plugin: {name}")
        if app.logger:
            app.logger.log_action("plugin-install", name, f"source={name_or_path}")
    else:
        click.echo("Plugin registry not yet implemented.")
        click.echo("  Install from a local path: defenseclaw plugin install /path/to/plugin")


@plugin.command("list")
@pass_ctx
def list_plugins(app: AppContext) -> None:
    """List installed plugins."""
    plugin_dir = app.cfg.plugin_dir
    if not os.path.isdir(plugin_dir):
        click.echo("No plugins installed.")
        return

    entries = [e for e in os.listdir(plugin_dir) if os.path.isdir(os.path.join(plugin_dir, e))]
    if not entries:
        click.echo("No plugins installed.")
        return

    click.echo("Installed plugins:")
    for name in sorted(entries):
        click.echo(f"  {name}")


@plugin.command()
@click.argument("name")
@pass_ctx
def remove(app: AppContext, name: str) -> None:
    """Remove an installed plugin."""
    plugin_dir = app.cfg.plugin_dir
    path = os.path.join(plugin_dir, name)

    if not os.path.isdir(path):
        click.echo(f"Plugin not found: {name}")
        return

    shutil.rmtree(path)
    click.echo(f"Removed plugin: {name}")
    if app.logger:
        app.logger.log_action("plugin-remove", name, "")
