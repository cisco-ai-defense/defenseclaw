"""GAP-2474: setup antigravity --help names the --workspace refusal.

setup antigravity refuses --workspace (DefenseClaw owns only the global
~/.gemini/config/hooks.json), so its help must not offer the workspace pin
text the other connectors show.
"""

import click
from click.testing import CliRunner
from defenseclaw.commands import cmd_setup


def _workspace_help(name: str) -> str:
    cmd = cmd_setup.setup.commands[name]
    for param in cmd.params:
        if isinstance(param, click.Option) and "--workspace" in param.opts:
            return param.help or ""
    raise AssertionError(f"setup {name} has no --workspace option")


def test_antigravity_workspace_help_names_the_refusal():
    text = _workspace_help("antigravity")
    assert "Not supported for Antigravity" in text
    assert "refuses --workspace" in text
    assert "~/.gemini/config/hooks.json" in text
    assert "claw.workspace_dir pin" not in text
    assert "Opt into workspace-scoped" not in text


def test_antigravity_help_output_shows_the_refusal_text():
    result = CliRunner().invoke(cmd_setup.setup, ["antigravity", "--help"], terminal_width=200)
    assert result.exit_code == 0, result.output
    assert "Not supported for Antigravity" in result.output
    assert "Opt into workspace-scoped" not in result.output


def test_other_hook_connectors_keep_the_pin_help():
    for name in ("kiro", "cursor", "opencode"):
        assert "Defaults to the claw.workspace_dir pin when one is set" in _workspace_help(name), name
