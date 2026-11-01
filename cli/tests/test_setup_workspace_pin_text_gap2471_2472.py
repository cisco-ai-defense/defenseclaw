"""GAP-2471 / GAP-2472: --workspace help and the peer-move refusal name the pin.

Setup without --workspace keeps a claw.workspace_dir pin that is a folder
(GAP-0201), so neither the help nor the refusal may say that leaving the flag
out means global/user scope when a pin is set.
"""

import click
from defenseclaw.commands import cmd_setup


def _workspace_options():
    found = []
    for name, cmd in cmd_setup.setup.commands.items():
        for param in getattr(cmd, "params", []):
            if isinstance(param, click.Option) and "--workspace" in param.opts:
                found.append((name, param.help or ""))
    return found


def test_every_setup_workspace_option_names_the_pin_as_the_default():
    found = _workspace_options()
    names = {name for name, _ in found}
    assert {"guardrail", "codex", "claude-code", "kiro"} <= names, names
    for name, text in found:
        if name == "antigravity":
            continue  # refuses --workspace; its own help (GAP-2474)
        assert "Defaults to the claw.workspace_dir pin when one is set" in text, (name, text)
        assert '--workspace "" selects global/user config' in text, (name, text)


def test_refusal_with_a_pin_names_the_kept_pin_and_the_global_step():
    text = cmd_setup._workspace_peer_move_refusal("kiro", ["codex"], "/w/new", "/w/pinned")
    assert "No changes made." in text
    assert "without --workspace to keep the current pin /w/pinned" in text
    assert "keep user-global hooks" not in text
    assert 'defenseclaw setup kiro --workspace ""' in text
    assert "defenseclaw config unset claw.workspace_dir" in text
    assert "defenseclaw setup guardrail --workspace /w/new" in text


def test_refusal_without_a_pin_keeps_the_user_global_step():
    text = cmd_setup._workspace_peer_move_refusal("kiro", ["codex"], "/w/new", "")
    assert "without --workspace to keep user-global hooks" in text
    assert "current pin" not in text
    assert "defenseclaw setup guardrail --workspace /w/new" in text
