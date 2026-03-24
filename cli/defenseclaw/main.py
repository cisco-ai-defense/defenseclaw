"""DefenseClaw CLI entry point.

Click root group with pre-invoke config/db loading,
mirroring the Cobra root command in internal/cli/root.go.
"""

from __future__ import annotations

import sys

import click

from defenseclaw import __version__
from defenseclaw.commands.cmd_aibom import aibom
from defenseclaw.commands.cmd_alerts import alerts
from defenseclaw.commands.cmd_deploy import deploy
from defenseclaw.commands.cmd_init import init_cmd
from defenseclaw.commands.cmd_mcp import mcp
from defenseclaw.commands.cmd_plugin import plugin
from defenseclaw.commands.cmd_setup import setup
from defenseclaw.commands.cmd_sidecar import sidecar
from defenseclaw.commands.cmd_skill import skill
from defenseclaw.commands.cmd_status import status
from defenseclaw.context import AppContext

SKIP_LOAD_COMMANDS = {"init"}


def _is_help_invocation(ctx: click.Context) -> bool:
    # Allow `defenseclaw --help` and `<cmd> --help` to work even before init.
    if getattr(ctx, "resilient_parsing", False):
        return True
    argv = sys.argv[1:]
    return any(a in {"-h", "--help"} for a in argv)


@click.group()
@click.version_option(version=__version__, prog_name="defenseclaw")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Enterprise governance layer for OpenClaw.

    Scans skills, MCP servers, and code before they run.
    Enforces block/allow lists. Provides audit and alerting.
    """
    ctx.ensure_object(AppContext)
    app = ctx.obj

    invoked = ctx.invoked_subcommand
    if invoked in SKIP_LOAD_COMMANDS or _is_help_invocation(ctx):
        return

    from defenseclaw import config as cfg_mod
    from defenseclaw.db import Store
    from defenseclaw.logger import Logger

    try:
        app.cfg = cfg_mod.load()
    except Exception as exc:
        click.echo(
            f"Failed to load config — run 'defenseclaw init' first: {exc}",
            err=True,
        )
        raise SystemExit(1)

    try:
        app.store = Store(app.cfg.audit_db)
    except Exception as exc:
        click.echo(f"Failed to open audit store: {exc}", err=True)
        raise SystemExit(1)

    app.logger = Logger(app.store)


@cli.result_callback()
@click.pass_context
def cleanup(ctx: click.Context, *_args, **_kwargs) -> None:
    app = ctx.find_object(AppContext)
    if app:
        if app.logger:
            app.logger.close()
        if app.store:
            app.store.close()


# Register all commands
cli.add_command(init_cmd, "init")
cli.add_command(setup)
cli.add_command(deploy)
cli.add_command(sidecar)
cli.add_command(skill)
cli.add_command(plugin)
cli.add_command(mcp)
cli.add_command(aibom)
cli.add_command(status)
cli.add_command(alerts)


if __name__ == "__main__":
    cli()
