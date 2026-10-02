"""GAP-1051: every per-connector ``setup <connector>`` accepts the same
non-interactive flags as ``init`` / ``setup guardrail`` (``--non-interactive``,
``--accept-defaults``) as aliases of ``--yes``."""

import click
from defenseclaw.commands.cmd_setup import setup

CONNECTOR_COMMANDS = (
    "claude-code", "codex", "hermes", "cursor", "devin", "copilot", "openhands",
    "antigravity", "opencode", "amp", "omnigent", "kiro", "openclaw", "zeptoclaw", "remove",
)


def _flag_names(cmd: click.Command) -> set[str]:
    names: set[str] = set()
    for param in cmd.params:
        if isinstance(param, click.Option) and param.is_flag:
            names.update(param.opts)
    return names


def test_connector_setup_commands_accept_non_interactive_aliases():
    for name in CONNECTOR_COMMANDS:
        cmd = setup.commands[name]
        flags = _flag_names(cmd)
        assert {"--yes", "--non-interactive", "--accept-defaults"} <= flags, name


def test_non_interactive_sets_yes_for_hook_connector():
    cmd = setup.commands["amp"]
    ctx = cmd.make_context("amp", ["--non-interactive", "--no-restart"], resilient_parsing=True)
    assert ctx.params["yes"] is True
