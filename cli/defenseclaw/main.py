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
from defenseclaw.commands.cmd_audit import audit
from defenseclaw.commands.cmd_codeguard import codeguard
from defenseclaw.commands.cmd_config import config_cmd
from defenseclaw.commands.cmd_doctor import doctor
from defenseclaw.commands.cmd_guardrail import guardrail
from defenseclaw.commands.cmd_init import init_cmd
from defenseclaw.commands.cmd_keys import keys_cmd
from defenseclaw.commands.cmd_mcp import mcp
from defenseclaw.commands.cmd_plugin import plugin
from defenseclaw.commands.cmd_policy import policy
from defenseclaw.commands.cmd_quickstart import quickstart_cmd
from defenseclaw.commands.cmd_sandbox import sandbox
from defenseclaw.commands.cmd_settings import settings_cmd
from defenseclaw.commands.cmd_setup import setup
from defenseclaw.commands.cmd_skill import skill
from defenseclaw.commands.cmd_status import status
from defenseclaw.commands.cmd_tool import tool
from defenseclaw.commands.cmd_tui import tui
from defenseclaw.commands.cmd_uninstall import reset_cmd, uninstall_cmd
from defenseclaw.commands.cmd_upgrade import upgrade
from defenseclaw.commands.cmd_version import version_cmd
from defenseclaw.context import AppContext

SKIP_LOAD_COMMANDS = {"init", "quickstart", "sandbox", "tui", "uninstall", "reset", "version"}

# Commands that may legitimately run before config.yaml exists or while
# it is being rewritten. The auto-validate hook below skips them to
# avoid bricking recovery workflows when the file is temporarily bad.
SKIP_AUTO_VALIDATE = SKIP_LOAD_COMMANDS | {"config", "keys", "doctor", "upgrade", "version"}


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

    # Fast-fail on config errors before any command runs, so operators
    # see a clear diagnostic instead of a deep stack trace. Skipped for
    # recovery commands (doctor/config/keys/upgrade) so a broken config
    # doesn't lock them out of the tools that would fix it.
    if invoked not in SKIP_AUTO_VALIDATE:
        from defenseclaw.commands.cmd_config import validate_config

        result = validate_config()
        if not result.ok:
            click.echo("Config validation failed:", err=True)
            if result.parse_error:
                click.echo(f"  ✗ {result.parse_error}", err=True)
            for issue in result.errors:
                click.echo(f"  ✗ {issue}", err=True)
            click.echo("  Run 'defenseclaw config validate' for details, or "
                      "'defenseclaw doctor --fix' to auto-repair.", err=True)
            raise SystemExit(1)

    _ensure_codeguard_skill(app.cfg)

    try:
        app.store = Store(app.cfg.audit_db)
        app.store.init()
    except Exception as exc:
        click.echo(f"Failed to open audit store: {exc}", err=True)
        raise SystemExit(1)

    app.logger = Logger(app.store, app.cfg.splunk)


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
cli.add_command(quickstart_cmd)
cli.add_command(setup)
cli.add_command(skill)
cli.add_command(plugin)
cli.add_command(policy)
cli.add_command(mcp)
cli.add_command(aibom)
cli.add_command(status)
cli.add_command(alerts)
cli.add_command(audit)
cli.add_command(codeguard)
cli.add_command(tool)
cli.add_command(tui)
cli.add_command(doctor)
cli.add_command(guardrail)
cli.add_command(sandbox)
cli.add_command(upgrade)
cli.add_command(keys_cmd, "keys")
cli.add_command(config_cmd, "config")
cli.add_command(settings_cmd, "settings")
cli.add_command(uninstall_cmd, "uninstall")
cli.add_command(reset_cmd, "reset")
cli.add_command(version_cmd, "version")


def _ensure_codeguard_skill(cfg) -> None:
    """Install CodeGuard skill if the agent appeared since last init."""
    try:
        from defenseclaw.codeguard_skill import ensure_codeguard_skill

        connector = getattr(cfg.guardrail, "connector", "") or ""
        ensure_codeguard_skill(cfg.claw_home_dir(), cfg.claw.config_file, connector)
    except Exception:
        pass


def _try_launch_tui() -> bool:
    """When invoked with no subcommand on a TTY, hand off to the Go TUI.

    Uses :func:`defenseclaw.gateway.resolve_gateway_binary` instead of a
    bare ``shutil.which`` so the handoff also works immediately after
    ``make all`` — see the module docstring of ``defenseclaw.gateway``
    for the full resolution order and rationale.
    """
    import os

    from defenseclaw.gateway import resolve_gateway_binary

    if not sys.stdin.isatty():
        return False

    argv = sys.argv[1:]
    if argv and not all(a.startswith("-") for a in argv):
        return False
    if any(a in {"-h", "--help", "--version"} for a in argv):
        return False

    gateway = resolve_gateway_binary()
    if gateway is None:
        return False

    os.execvp(gateway, [gateway, "tui"])
    return True  # unreachable


def main() -> None:
    """Entrypoint: try TUI handoff first, fall back to Click CLI."""
    if not _try_launch_tui():
        cli()


if __name__ == "__main__":
    main()
