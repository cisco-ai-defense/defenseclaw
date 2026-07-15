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

import json
import sys

import click

from defenseclaw import __version__, ux
from defenseclaw.commands.cmd_agent import agent
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
from defenseclaw.commands.cmd_migrations import migrations_cmd
from defenseclaw.commands.cmd_plugin import plugin
from defenseclaw.commands.cmd_policy import policy
from defenseclaw.commands.cmd_quickstart import quickstart_cmd
from defenseclaw.commands.cmd_registry import registry
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

SKIP_LOAD_COMMANDS = {
    "agent",
    "init",
    "migrations",
    "quickstart",
    "sandbox",
    "tui",
    "uninstall",
    "reset",
    "version",
}

# Commands that may legitimately run before config.yaml exists or while
# it is being rewritten. The auto-validate hook below skips them to
# avoid bricking recovery workflows when the file is temporarily bad.
# ``migrations`` joins the recovery set because operators reach for it
# precisely when something on disk is wrong; refusing to run because
# config didn't validate would defeat its purpose.
SKIP_AUTO_VALIDATE = SKIP_LOAD_COMMANDS | {"config", "keys", "doctor", "upgrade", "version"}


def _is_help_invocation(ctx: click.Context) -> bool:
    # Allow `defenseclaw --help` and `<cmd> --help` to work even before init.
    if getattr(ctx, "resilient_parsing", False):
        return True
    argv = sys.argv[1:]
    return any(a in {"-h", "--help"} for a in argv)


def _emit_version_json(
    ctx: click.Context, _param: click.Parameter | None, value: bool
) -> None:
    """Emit a stable installer-facing version record before config loading."""
    if not value or ctx.resilient_parsing:
        return
    click.echo(
        json.dumps(
            {
                "schema_version": 1,
                "name": "defenseclaw-cli",
                "version": __version__,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    ctx.exit()


@click.group()
@click.version_option(version=__version__, prog_name="defenseclaw")
@click.option(
    "--version-json",
    is_flag=True,
    is_eager=True,
    expose_value=False,
    callback=_emit_version_json,
    help="Emit the exact build version as JSON and exit.",
)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Enterprise governance layer for AI coding agents.

    Discovers AI usage, scans skills, MCP servers, plugins, and code
    before they run, and provides audit, telemetry, and enforcement.

    \b
    Multi-connector:
      One gateway enforces N agent-native connectors (codex, claudecode,
      hermes, antigravity, omnigent, and others) tracked under guardrail.connectors. Add one
      with 'defenseclaw setup <connector>' (choose Add when prompted),
      remove with 'defenseclaw setup remove <name>'. Scope policy per peer
      with 'defenseclaw guardrail ... --connector X', and inspect the
      roster with 'defenseclaw status' / 'defenseclaw guardrail status'.
      Note: OpenClaw/ZeptoClaw use the proxy path and cannot be multi peers.
    """
    ctx.ensure_object(AppContext)
    app = ctx.obj

    invoked = ctx.invoked_subcommand
    if invoked in SKIP_LOAD_COMMANDS or _is_help_invocation(ctx):
        return

    from defenseclaw import config as cfg_mod
    from defenseclaw.db import Store
    from defenseclaw.logger import Logger

    # ``status`` must not turn a clean post-reset home back into a phantom
    # initialized install. Config.load() intentionally supplies defaults for
    # some recovery workflows, so check the durable initialization marker
    # before loading and before Store.init() can recreate audit.db.
    if invoked == "status" and not cfg_mod.config_path().is_file():
        ux.echo(
            "DefenseClaw initialization required — run 'defenseclaw init' first.",
            err=True,
        )
        raise SystemExit(1)

    try:
        app.cfg = cfg_mod.load()
    except Exception as exc:
        ux.echo(
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
            ux.echo("Config validation failed:", err=True)
            if result.parse_error:
                ux.echo(f"  ✗ {result.parse_error}", err=True)
            for issue in result.errors:
                ux.echo(f"  ✗ {issue}", err=True)
            ux.echo(
                "  Run 'defenseclaw config validate' for details, or 'defenseclaw doctor --fix' to auto-repair.",
                err=True,
            )
            raise SystemExit(1)

    try:
        app.store = Store(app.cfg.audit_db)
        app.store.init()
    except Exception as exc:
        ux.echo(f"Failed to open audit store: {exc}", err=True)
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
cli.add_command(agent)
cli.add_command(quickstart_cmd)
cli.add_command(setup)
cli.add_command(skill)
cli.add_command(plugin)
cli.add_command(policy)
cli.add_command(registry)
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
cli.add_command(migrations_cmd, "migrations")
cli.add_command(keys_cmd, "keys")
cli.add_command(config_cmd, "config")
cli.add_command(settings_cmd, "settings")
cli.add_command(uninstall_cmd, "uninstall")
cli.add_command(reset_cmd, "reset")
cli.add_command(version_cmd, "version")


def _ensure_codeguard_skill(cfg) -> None:
    """Deprecated no-op: native CodeGuard assets are explicit opt-in only."""
    _ = cfg


def _try_launch_tui() -> bool:
    """When invoked with no subcommand on a TTY, launch the Textual TUI.

    We only fall through to the Click CLI when stdin is not a TTY, when
    the user passed an actual subcommand, or when ``--help``/``--version``
    is on the command line.
    """
    if not sys.stdin.isatty():
        return False

    argv = sys.argv[1:]
    if argv and not all(a.startswith("-") for a in argv):
        return False
    if any(a in {"-h", "--help", "--version", "--version-json"} for a in argv):
        return False

    if not ux.terminal_supports_tui():
        ux.echo(ux.TUI_UNAVAILABLE_MESSAGE, err=True)
        return True

    from defenseclaw.tui import run_textual_tui

    run_textual_tui()
    return True


def _force_utf8_io() -> None:
    """Reconfigure stdout/stderr to UTF-8 so framing/status glyphs never crash.

    Windows Python defaults its standard streams to the active legacy code page
    (e.g. cp1252), whose charmap codec cannot encode the box-drawing characters
    ``ux.banner()`` and the ``✓``/``✗`` status markers emit — ``defenseclaw
    init`` died on a hosted Windows runner with ``UnicodeEncodeError: 'charmap'
    codec can't encode`` before printing a single banner. Forcing UTF-8 is a
    no-op where the streams are already UTF-8 (Linux/macOS) and degrades
    gracefully if a stream is missing or not reconfigurable (e.g. redirected to
    a plain object, or None under pythonw)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8")
        except (ValueError, OSError):
            pass


def main() -> None:
    """Entrypoint: try TUI handoff first, fall back to Click CLI."""
    ux.configure_console_output()
    _force_utf8_io()
    if not _try_launch_tui():
        cli()


if __name__ == "__main__":
    main()
