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

import inspect
import json
import os
import re
import sys
from types import SimpleNamespace

from defenseclaw import __version__


def _version_json_record() -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "name": "defenseclaw-cli",
            "version": __version__,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


# Installers and Setup probe the CLI identity with exactly ``--version-json``
# under a short bound. Answer it before the command tree is imported, as the
# native Go binaries do, so the probe measures interpreter startup instead of
# importing every command module (hundreds of modules on a cold Windows host).
if __name__ == "__main__" and sys.argv[1:] == ["--version-json"]:
    sys.stdout.write(_version_json_record() + "\n")
    sys.stdout.flush()
    raise SystemExit(0)

import click

from defenseclaw import ux
from defenseclaw.commands.cmd_acp import acp_cmd
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
from defenseclaw.commands.cmd_migrate import migrate_cmd
from defenseclaw.commands.cmd_observability import observability_cmd
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
from defenseclaw.commands.cmd_upgrade import rollback, upgrade
from defenseclaw.commands.cmd_version import version_cmd
from defenseclaw.context import AppContext

SKIP_LOAD_COMMANDS = {
    "agent",
    "config",
    "init",
    "migrate",
    "observability",
    "quickstart",
    "rollback",
    "sandbox",
    "tui",
    "uninstall",
    "reset",
    "upgrade",
    "version",
}

# Commands that may legitimately run before config.yaml exists or while
# it is being rewritten. The auto-validate hook below skips them to
# avoid bricking recovery workflows when the file is temporarily bad.
# ``migrate``, ``upgrade`` and ``rollback`` join the recovery set because
# operators reach for them precisely when something on disk is wrong.
SKIP_AUTO_VALIDATE = SKIP_LOAD_COMMANDS | {"config", "keys", "doctor", "version"}

# These commands are the only top-level boundaries permitted to operate on an
# existing unconverted 0.8.x document. They either create/replace a configuration,
# migrate or replace the installation, remove it, or (for ``config``) hand the
# decision to that group's own guard, which lets only ``validate`` explain such
# a file. Every other group preflights the raw schema discriminator and stops
# with one instruction, `defenseclaw migrate`.
LEGACY_CONFIG_BOUNDARY_COMMANDS = {
    "config",
    "init",
    "migrate",
    "reset",
    "rollback",
    "uninstall",
    "upgrade",
    "version",
}

# First-run/read-only groups may run before config.yaml exists, but must reject
# an existing non-v8 document. The actual write boundary is independently
# protected by Config.save().
ALLOW_MISSING_V8_PREFLIGHT = {"agent", "config", "observability", "quickstart", "tui"}


def _cli_audit_db(cfg) -> str:
    """The audit database this CLI opens: ``cfg.audit_db``, except in the
    managed configuration folder.

    The enterprise lifecycle owns that folder (root, 0755, read by every
    enrolled user's hooks). A CLI pointed at it with ``DEFENSECLAW_HOME`` would
    create an ``audit.db`` there, and the store drops the folder's world bits
    when it creates one, so it gets an in-memory store instead (GAP-0062). On a
    managed host a database whose folder does not exist gets one too.
    """

    from defenseclaw.upgrade_shim import managed_descriptor

    descriptor = managed_descriptor()
    audit_db = cfg.audit_db
    if descriptor:
        folder = os.path.dirname(os.path.abspath(audit_db))
        # An administrator's shell aimed at the managed config has no data
        # folder of its own (root's home has no .defenseclaw), and a local
        # writer must still reach its managed refusal instead of failing to
        # open a store (GAP-0168).
        if folder == os.path.dirname(descriptor) or not os.path.isdir(folder):
            return ":memory:"
    return audit_db


def _is_help_invocation(ctx: click.Context) -> bool:
    # Allow `defenseclaw --help` and `<cmd> --help` to work even before init.
    if getattr(ctx, "resilient_parsing", False):
        return True
    argv = sys.argv[1:]
    return any(a in {"-h", "--help"} for a in argv)


#: Commands a managed device still runs for an account with a leftover
#: per-user install: removing it, the version, and doctor (which reports the
#: device as managed and names the leftover).
MANAGED_LEFTOVER_COMMANDS = {"uninstall", "version", "doctor"}


def _refuse_managed_leftover(ctx: click.Context) -> None:
    """Exit 3 when a per-user install left on a managed device would answer.

    Its config and gateway are not what the device enforces, so config get,
    guardrail mode, status and the other per-user views must not present them
    as the policy (GAP-0986, GAP-0987). ``config validate`` still checks a
    file an administrator is about to push.
    """
    invoked = ctx.invoked_subcommand
    if invoked in MANAGED_LEFTOVER_COMMANDS or (invoked == "config" and _group_child(ctx, "config") == "validate"):
        return
    from defenseclaw.config_writer import managed_leftover_config, managed_leftover_message

    if leftover := managed_leftover_config():
        ux.echo(managed_leftover_message(leftover), err=True)
        raise SystemExit(3)


def _group_child(ctx: click.Context, group: str) -> str:
    """The token after ``group`` in argv when ``group`` is the invoked command."""
    if ctx.invoked_subcommand != group:
        return ""
    argv = sys.argv[1:]
    try:
        index = argv.index(group)
    except ValueError:
        return ""
    return argv[index + 1] if index + 1 < len(argv) else ""


def _guardrail_child(ctx: click.Context) -> str:
    """The exact ``guardrail`` subcommand token, or "" for anything else.

    Click exposes only the top-level ``guardrail`` name while the root callback
    is running. Use that parsed name as the trust anchor, then locate its exact
    argv token so root-option and ``--`` prefixes do not change the result. The
    next token must be the nested command; intervening options or a different
    subcommand do not receive a bypass.
    """
    return _group_child(ctx, "guardrail")


def _is_offline_rulepack_validation(ctx: click.Context) -> bool:
    """Return whether the nested command is ``guardrail validate-pack``."""
    return _guardrail_child(ctx) == "validate-pack"


def _is_pack_repin(ctx: click.Context) -> bool:
    """Return whether the nested command is ``guardrail use-pack``.

    It re-pins an edited custom pack, so it must run while config.yaml still
    carries the stale digest. It loads the config but skips the pre-command
    validation; the writer validates the candidate it saves.
    """
    return _guardrail_child(ctx) == "use-pack"


def _is_config_optional_sandbox_command(ctx: click.Context) -> bool:
    """Return whether a ``sandbox`` stub runs without a DefenseClaw config.

    The Go command tree loads the configuration itself. These commands work
    without one, mirroring internal/cli/sandbox.go: ``sandbox teardown`` (an
    uninstall of a half-installed host), a nested ``sandbox run`` inside a
    sandbox, which runs the harness natively, and the read-only ``sandbox
    pack list|show|validate`` (an administrator reads a pack's digest before
    writing the config that pins it). An existing non-v8 document is still
    refused by the preflight.
    """
    if ctx.invoked_subcommand != "sandbox":
        return False
    argv = sys.argv[1:]
    try:
        index = argv.index("sandbox")
    except ValueError:
        return False
    child = argv[index + 1] if index + 1 < len(argv) else ""
    if child == "teardown":
        return True
    if child == "pack":
        grandchild = argv[index + 2] if index + 2 < len(argv) else ""
        return grandchild in {"list", "show", "validate"}
    return child == "run" and bool(os.environ.get("DEFENSECLAW_SANDBOX_ID", "").strip())


def _is_audit_export(ctx: click.Context) -> bool:
    """Return whether this is the ``audit export``/``findings`` gateway alias.

    The gateway binary loads the configuration and opens the audit database
    read-only itself, so the CLI must not open the store for writing first.
    """
    if ctx.invoked_subcommand != "audit":
        return False
    argv = sys.argv[1:]
    try:
        index = argv.index("audit")
    except ValueError:
        return False
    return index + 1 < len(argv) and argv[index + 1] in {"export", "findings"}


def _audit_logs_can_read_with_ide_scope_typo(ctx: click.Context, result: object) -> bool:
    """A malformed inventory scope cannot change a read-only log tail."""
    if ctx.invoked_subcommand != "audit":
        return False
    argv = sys.argv[1:]
    try:
        child = argv[argv.index("audit") + 1]
    except (ValueError, IndexError):
        return False
    errors = getattr(result, "errors", [])
    return (
        child == "logs"
        and not getattr(result, "timed_out", False)
        and not getattr(result, "parse_error", "")
        and len(errors) == 1
        and "ai_discovery.ide_inventory" in errors[0]
    )


def _emit_version_json(ctx: click.Context, _param: click.Parameter | None, value: bool) -> None:
    """Emit a stable installer-facing version record before config loading."""
    if not value or ctx.resilient_parsing:
        return
    click.echo(_version_json_record())
    ctx.exit()


# -h is the short form of --help on every command, as on defenseclaw-gateway
# (GAP-2170). Child contexts inherit help_option_names from this group.
@click.group(context_settings={"help_option_names": ["-h", "--help"]})
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
      hermes, antigravity, omnigent, and others) tracked under
      guardrail.connectors. Add one with 'defenseclaw setup <connector>'
      (choose Add when prompted), remove with
      'defenseclaw setup remove <name>'. Scope policy per peer with
      'defenseclaw guardrail ... --connector X', and inspect the roster
      with 'defenseclaw status' / 'defenseclaw guardrail status'.
      Note: OpenClaw/ZeptoClaw use the proxy path and cannot be multi peers.
    """
    ctx.ensure_object(AppContext)
    app = ctx.obj

    invoked = ctx.invoked_subcommand
    if _is_help_invocation(ctx):
        return
    if _is_offline_rulepack_validation(ctx):
        return
    if _is_audit_export(ctx):
        return

    from defenseclaw import config as cfg_mod

    _refuse_managed_leftover(ctx)
    if invoked in SKIP_LOAD_COMMANDS:
        if invoked not in LEGACY_CONFIG_BOUNDARY_COMMANDS:
            try:
                cfg_mod.require_v8_config(
                    allow_missing=invoked in ALLOW_MISSING_V8_PREFLIGHT or _is_config_optional_sandbox_command(ctx),
                )
            except cfg_mod.ConfigVersionError as exc:
                ux.echo(str(exc), err=True)
                raise SystemExit(exc.exit_code) from exc
        return

    if invoked == "setup":
        # ``setup trusted-paths`` is the public bootstrap for a custom agent
        # runtime that first-run selection must trust. Permit a missing v8
        # document here, then let the setup group admit only that narrow
        # subcommand. Existing legacy/malformed documents still fail before
        # compatibility loading or mutation.
        try:
            cfg_mod.require_v8_config(allow_missing=True)
        except cfg_mod.ConfigVersionError as exc:
            ux.echo(str(exc), err=True)
            raise SystemExit(exc.exit_code) from exc
    elif invoked not in SKIP_AUTO_VALIDATE:
        try:
            cfg_mod.require_v8_config()
        except cfg_mod.ConfigVersionError as exc:
            if isinstance(exc, cfg_mod.ManagedNotInitializedError):
                from defenseclaw.enforce.asset_lists import MANAGED_REFUSAL, audit_first_run_refusal

                audit_first_run_refusal(ctx.command, sys.argv[1:])
                if invoked in {"skill", "mcp", "plugin", "tool"}:
                    ux.echo(f"error: {MANAGED_REFUSAL}", err=True)
                    raise SystemExit(exc.exit_code) from exc
            ux.echo(str(exc), err=True)
            raise SystemExit(exc.exit_code) from exc

    if invoked == "doctor" and (damage := cfg_mod.config_damage_message()):
        # An empty config.yaml loads as built-in defaults; judging the install
        # against them printed wrong FAIL rows. Stop at the config rows, as for
        # a malformed file (GAP-1633).
        from defenseclaw.doctor_preflight import inspect_doctor_config_load_failure

        app.doctor_startup_diagnostics = inspect_doctor_config_load_failure(
            cfg_mod.ConfigVersionError(damage)
        )
        app.cfg = SimpleNamespace(data_dir=str(cfg_mod.default_data_path()))
        return

    try:
        app.cfg = cfg_mod.load()
    except Exception as exc:
        if invoked == "doctor":
            from defenseclaw.doctor_preflight import inspect_doctor_config_load_failure

            # Doctor is a recovery surface. Preserve the canonical raw-source
            # diagnostics for its own renderer instead of aborting before the
            # command starts or constructing authoritative runtime state.
            app.doctor_startup_diagnostics = inspect_doctor_config_load_failure(exc)
            # Preserve a failed cache snapshot in the same operational home the
            # TUI uses. This is not a runtime Config and is consumed only by
            # Doctor's best-effort cache writer.
            app.cfg = SimpleNamespace(data_dir=str(cfg_mod.default_data_path()))
            return
        if cfg_mod.config_path().is_file():
            # GAP-0288: the file is there and refused; `init` would not fix it.
            ux.echo(
                f"Failed to load config: {exc}. Fix it in {cfg_mod.config_path()}; "
                "'defenseclaw config validate' shows the line. "
                "A running gateway keeps its last good configuration.",
                err=True,
            )
        else:
            ux.echo(
                f"Failed to load config — run 'defenseclaw init' first: {exc}",
                err=True,
            )
        raise SystemExit(1)

    # Doctor must observe the audit database exactly as it existed at command
    # start. Generic Store.init() performs CREATE TABLE IF NOT EXISTS and would
    # turn a missing/corrupt-store diagnosis into a false pass before Doctor
    # gets a chance to inspect it. Doctor owns any explicitly requested repair.
    if invoked == "doctor":
        return

    from defenseclaw.config import is_current_schema
    from defenseclaw.db import Store
    from defenseclaw.logger import Logger

    source_is_v8 = is_current_schema(getattr(app.cfg, "_source_config_version", None))

    if invoked == "setup" and not source_is_v8:
        # A missing config is represented by an in-memory source version of
        # zero. Do not create audit/runtime state before the setup group proves
        # that the requested child is the trusted-paths bootstrap. Config.save
        # will write this fresh document at the current version while holding
        # its file lock.
        app.preinit_setup_bootstrap = True
        return

    # Fast-fail on config errors before any command runs, so operators
    # see a clear diagnostic instead of a deep stack trace. Skipped for
    # recovery commands (doctor/config/keys/upgrade) so a broken config
    # doesn't lock them out of the tools that would fix it.
    if invoked not in SKIP_AUTO_VALIDATE and invoked != "setup" and not _is_pack_repin(ctx):
        from defenseclaw.commands.cmd_config import validate_config

        result = validate_config()
        if _audit_logs_can_read_with_ide_scope_typo(ctx, result):
            ux.echo(
                "Config warning: ai_discovery.ide_inventory is invalid; log output is still available. "
                "Run 'defenseclaw config validate' to repair the scope.",
                err=True,
            )
        elif not result.ok:
            timed_out = getattr(result, "timed_out", False)
            # GAP-1788: status is read-only and config.yaml loaded, so it
            # still shows the gateway and connectors, flags the problem, and
            # exits 1 at the end.
            status_continues = invoked == "status" and not timed_out and not result.parse_error
            ux.echo("Config check did not finish:" if timed_out else "Config validation failed:", err=True)
            if result.parse_error:
                ux.echo(f"  ✗ {result.parse_error}", err=True)
            for issue in result.errors:
                ux.echo(f"  ✗ {issue}", err=True)
            if timed_out:
                ux.echo("  Nothing was changed; re-run the command.", err=True)
            elif status_continues:
                ux.echo(
                    "  A gateway that is already running keeps the config it started with; "
                    "its status follows. Fix the problem above and the gateway applies the change on its own.",
                    err=True,
                )
            else:
                ux.echo(
                    "  Run 'defenseclaw config validate' for details, repair or upgrade the configuration, "
                    "then rerun the command.",
                    err=True,
                )
            if not status_continues:
                raise SystemExit(1)
            app.config_problems = list(result.errors) or ["config.yaml does not validate"]

    # The setup group must inspect its child command before deciding whether
    # gateway-backed canonical validation and runtime/audit initialization are
    # required. ``setup trusted-paths add|list|remove`` is the deliberately
    # narrow offline trust bootstrap; every other setup path performs the same
    # validation and initialization in the setup group callback.
    if invoked == "setup":
        app.setup_runtime_deferred = True
        return

    try:
        app.store = Store(_cli_audit_db(app.cfg))
        app.store.init()
    except Exception as exc:
        from defenseclaw.audit_capacity import audit_open_failure_notice

        ux.echo(audit_open_failure_notice(app.cfg.audit_db, exc), err=True)
        raise SystemExit(1)

    if source_is_v8 and not getattr(app, "config_problems", None):
        app.logger = Logger.from_config(app.cfg)
    else:
        app.logger = Logger.no_runtime()


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
cli.add_command(acp_cmd)
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
cli.add_command(rollback)
cli.add_command(migrate_cmd, "migrate")
cli.add_command(keys_cmd, "keys")
cli.add_command(config_cmd, "config")
cli.add_command(observability_cmd, "observability")
cli.add_command(settings_cmd, "settings")
cli.add_command(uninstall_cmd, "uninstall")
cli.add_command(reset_cmd, "reset")
cli.add_command(version_cmd, "version")


_RST_LITERAL = re.compile(r"``([^`]+?)``")
_MD_BOLD = re.compile(r"\*\*([^*]+?)\*\*")


def _plain_help(text: str | None) -> str | None:
    """Show RST literals (``x``) as 'x' and drop **bold** markers (GAP-2310).

    Click prints help verbatim, so markup would show as typed.
    """
    if not text or ("``" not in text and "**" not in text):
        return text
    return _MD_BOLD.sub(r"\1", _RST_LITERAL.sub(r"'\1'", text))


def _first_sentence(text: str | None) -> str | None:
    """The first sentence of *text*, for a group's Commands list.

    Without an explicit short_help Click cuts the summary off at the terminal
    width with '...' (GAP-2036); the whole sentence wraps instead.
    """
    if not text:
        return None
    words = inspect.cleandoc(text).split("\n\n", 1)[0].split()
    if words and words[0] == "\b":
        words = words[1:]
    for i, word in enumerate(words):
        if word.endswith("."):
            return " ".join(words[: i + 1])
    return " ".join(words) or None


def _plain_help_tree(command: click.Command, seen: set[int] | None = None) -> None:
    """Clean the help text of every command and option once, at import."""
    seen = set() if seen is None else seen
    if id(command) in seen:
        return
    seen.add(id(command))
    command.help = _plain_help(command.help)
    command.short_help = _plain_help(command.short_help) or _first_sentence(command.help)
    for param in command.params:
        if isinstance(param, click.Option):
            param.help = _plain_help(param.help)
    for sub in (getattr(command, "commands", None) or {}).values():
        _plain_help_tree(sub, seen)


_plain_help_tree(cli)


_NB_HYPHEN = "\u2011"


class _HelpFormatter(click.HelpFormatter):
    """Help output that never wraps a line at a hyphen.

    Click's wrapper splits 'defenseclaw-gateway', '~/.defenseclaw/last-run.log'
    or 'log-activity' across two lines, so they can't be read or copied whole.
    Hyphens are non-breaking while a block wraps and plain again in the output.
    Redirected help gets the same ASCII stand-ins as the rest of the CLI
    (em dash, ellipsis; GAP-2598), swapped before wrapping so widths hold.
    """

    def write_text(self, text: str) -> None:
        start = len(self.buffer)
        super().write_text(ux.console_text(text).replace("-", _NB_HYPHEN))
        self._restore_hyphens(start)

    def write_dl(self, rows, col_max: int = 30, col_spacing: int = 2) -> None:
        start = len(self.buffer)
        rows = [(ux.console_text(term), ux.console_text(desc).replace("-", _NB_HYPHEN)) for term, desc in rows]
        super().write_dl(rows, col_max, col_spacing)
        self._restore_hyphens(start)

    def getvalue(self) -> str:
        return ux.console_text(super().getvalue())

    def _restore_hyphens(self, start: int) -> None:
        self.buffer[start:] = [part.replace(_NB_HYPHEN, "-") for part in self.buffer[start:]]


class _HelpContext(click.Context):
    formatter_class = _HelpFormatter


def _whole_words_help_tree(command: click.Command, seen: set[int] | None = None) -> None:
    """Give every command the help formatter that keeps hyphenated words whole."""
    seen = set() if seen is None else seen
    if id(command) in seen:
        return
    seen.add(id(command))
    command.context_class = _HelpContext
    for sub in (getattr(command, "commands", None) or {}).values():
        _whole_words_help_tree(sub, seen)


_whole_words_help_tree(cli)


def _try_launch_tui() -> bool:
    """When invoked with no arguments on a TTY, launch the Textual TUI.

    Any argument goes to the Click CLI: a subcommand, ``--help``/``--version``,
    and a mistyped option too, which Click rejects with its usage error and
    exit code 2 instead of opening the dashboard (GAP-1769).
    """
    if not sys.stdin.isatty():
        return False

    if sys.argv[1:]:
        return False

    if not ux.terminal_supports_tui():
        ux.echo(ux.tui_unavailable_message(), err=True)
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
    sys.stdout = ux.ascii_safe_redirected_stream(sys.stdout)
    sys.stderr = ux.ascii_safe_redirected_stream(sys.stderr)


def _attached_console_width() -> int:
    """Columns of the terminal this process runs in, even when stdout is piped; 0 if none."""
    for fd in (0, 1, 2):
        try:
            return os.get_terminal_size(fd).columns
        except (OSError, ValueError):
            continue
    if os.name != "nt":
        return 0
    try:
        # CONOUT$ is the console screen buffer even when every standard
        # stream is redirected (PowerShell '2>&1 | Select ...').
        with open("CONOUT$", "w") as console:
            return os.get_terminal_size(console.fileno()).columns
    except (OSError, ValueError):
        return 0


def _keep_console_width_when_piped() -> None:
    """Keep the terminal's width for tables when stdout is piped (GAP-1682).

    Rich and Click fall back to 80 columns when stdout is not a terminal.
    Rich on Windows asks only stdout and stderr, so in a 220-column
    PowerShell ``defenseclaw skill list 2>&1 | Select -First 50`` cut every
    table to 80 ASCII columns ('St...', 'Se...'). Export the console's width
    as COLUMNS, which both honour, unless the user already set it.
    """
    stdout = sys.__stdout__
    try:
        if os.environ.get("COLUMNS") or stdout is None or stdout.isatty():
            return
    except (OSError, ValueError):
        return
    width = _attached_console_width()
    if width > 0:
        os.environ["COLUMNS"] = str(width)


def _output_pipe_closed(exc: OSError) -> bool:
    """Whether *exc* means the reader of stdout went away.

    Click already ends quietly on EPIPE. Windows reports a pipe closed by
    the reader (``| Select -First 2``) as EINVAL instead, so that printed a
    traceback (GAP-1313). EINVAL counts only when stdout itself can no
    longer be flushed.
    """
    import errno

    if isinstance(exc, BrokenPipeError) or exc.errno == errno.EPIPE:
        return True
    if sys.platform != "win32" or exc.errno != errno.EINVAL:
        return False
    try:
        sys.stdout.flush()
    except OSError:
        return True
    return False


def _silence_closed_stdout() -> None:
    """Point stdout at the null device so exit-time flushes stay quiet."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.__stdout__.fileno())
    except (OSError, AttributeError, ValueError):
        pass


def main() -> None:
    """Entrypoint: try TUI handoff first, fall back to Click CLI."""
    ux.configure_console_output()
    _keep_console_width_when_piped()
    _force_utf8_io()
    from defenseclaw.config_writer import ConfigWriteError, ManagedConfigWriteError, plain_error
    from defenseclaw.logger import CanonicalObservabilityError, CanonicalObservabilityUnavailableError
    from defenseclaw.observability.v8_config import V8ConfigError

    try:
        if not _try_launch_tui():
            # GAP-2580: the TUI runs "python -m defenseclaw.main"; usage errors
            # must still name the command the user types.
            cli(prog_name="defenseclaw")
    except KeyboardInterrupt:
        # Ctrl+C outside Click's own handling (an import, the TUI handoff, the
        # upgrade's migration step) printed a Python traceback (GAP-0408).
        click.echo("\nInterrupted.", err=True)
        sys.exit(130)
    except CanonicalObservabilityUnavailableError as exc:
        # The command's audit event needs the gateway (for example after
        # init --no-start-gateway): one line with the fix, no traceback
        # (GAP-1689).
        click.echo(
            f"Error: the audit event was not recorded: {exc}. Start the gateway with "
            "'defenseclaw-gateway start' (or run 'defenseclaw setup gateway' to configure it), "
            "then run the command again.",
            err=True,
        )
        sys.exit(1)
    except CanonicalObservabilityError as exc:
        click.echo(f"Error: the audit event was not recorded: {exc}.", err=True)
        sys.exit(1)
    except ManagedConfigWriteError as exc:
        # Every command that saves config.yaml ends here when a managed
        # standalone host refuses the write: one line and the documented
        # exit 3, never a traceback.
        click.echo(f"error: {exc}", err=True)
        sys.exit(3)
    except (ConfigWriteError, V8ConfigError) as exc:
        # A change the config writer refuses (a value the schema rejects, a
        # config.yaml that changed underneath) ends here as one plain line, never
        # a traceback (GAP-0055). The file is left as it was.
        click.echo(f"Error: config.yaml was not changed: {plain_error(exc)}", err=True)
        sys.exit(1)
    except OSError as exc:
        from defenseclaw.config import ConfigSaveError

        if isinstance(exc, ConfigSaveError):
            click.echo(
                f"Error: cannot write {exc.path}: {exc.strerror}; the previous config.yaml is unchanged.",
                err=True,
            )
            sys.exit(1)
        if _output_pipe_closed(exc):
            _silence_closed_stdout()
            sys.exit(1)
        import errno

        if exc.errno != errno.ENOSPC:
            raise
        # GAP-1838: a full disk is an environment problem, not a crash.
        target = f" {exc.filename}" if exc.filename else " a file"
        click.echo(
            f"Error: the disk is full, so DefenseClaw could not write{target}. "
            "Free some space and run the command again.",
            err=True,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
