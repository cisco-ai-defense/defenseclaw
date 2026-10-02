"""GAP-1051: every per-connector ``setup <connector>`` accepts the same
non-interactive flags as ``init`` / ``setup guardrail`` (``--non-interactive``,
``--accept-defaults``) as aliases of ``--yes``."""

import click
from defenseclaw.commands.cmd_setup import setup

CONNECTOR_COMMANDS = (
    "claude-code", "codex", "hermes", "cursor", "devin", "copilot", "openhands",
    "antigravity", "opencode", "amp", "omnigent", "kiro", "openclaw", "zeptoclaw", "remove",
    # GAP-1387: the other setup commands that take --yes.
    "acp", "notifications", "rotate-token", "routing",
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


def test_non_interactive_sets_yes_for_routing_and_acp():
    for name, param in (("routing", "yes"), ("acp", "assume_yes"), ("rotate-token", "yes"), ("notifications", "yes")):
        cmd = setup.commands[name]
        ctx = cmd.make_context(name, ["--non-interactive"], resilient_parsing=True)
        assert ctx.params[param] is True, name
