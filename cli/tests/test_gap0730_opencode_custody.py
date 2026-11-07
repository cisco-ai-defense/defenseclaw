"""GAP-0730: one account of what refuses an OpenCode plugin destination.

The gateway checks the leaf folder first and stops there, so naming the leaf
sent the user to a fix that did not clear the refusal while a folder above it
was as open. The CLI preflight, doctor and bootstrap now list every refused
element, outermost first, with one command.
"""

from __future__ import annotations

import os
from pathlib import Path

import click
import pytest
from defenseclaw import connector_paths
from defenseclaw.commands import cmd_setup

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX directory modes")


@pytest.fixture(autouse=True)
def _no_private_group(monkeypatch):
    monkeypatch.setattr("defenseclaw.file_permissions.owner_private_group", lambda *_: False)


def _tree(tmp_path: Path, config_mode: int, opencode_mode: int) -> tuple[Path, Path, Path]:
    config = tmp_path / ".config"
    opencode = config / "opencode"
    plugins = opencode / "plugins"
    plugins.mkdir(parents=True)
    config.chmod(config_mode)
    opencode.chmod(opencode_mode)
    plugins.chmod(0o700)
    return config, opencode, plugins / "defenseclaw.js"


def test_every_refused_folder_is_listed_outermost_first(tmp_path: Path) -> None:
    config, opencode, plugin = _tree(tmp_path, 0o775, 0o775)
    unsafe = connector_paths.opencode_unsafe_plugin_paths([str(plugin)])
    assert unsafe == [os.path.realpath(config), os.path.realpath(opencode)]
    named, fix = connector_paths.opencode_custody_text(unsafe)
    assert fix == f"chmod go-w {unsafe[0]} {unsafe[1]}"
    assert named.startswith(unsafe[0]) and unsafe[1] in named


def test_the_preflight_names_all_of_them_in_one_command(tmp_path: Path, monkeypatch) -> None:
    config, opencode, plugin = _tree(tmp_path, 0o775, 0o775)
    monkeypatch.setattr(connector_paths, "connector_config_files", lambda _name: [str(plugin)])
    with pytest.raises(click.ClickException) as caught:
        cmd_setup._preflight_opencode_plugin_folder()
    message = str(caught.value)
    assert f"chmod go-w {os.path.realpath(config)} {os.path.realpath(opencode)}" in message
    assert "No changes made" in message


def test_a_plugin_file_other_accounts_can_write_is_listed_last(tmp_path: Path) -> None:
    _, _, plugin = _tree(tmp_path, 0o755, 0o755)
    plugin.write_text("// managed plugin\n", encoding="utf-8")
    plugin.chmod(0o666)
    assert connector_paths.opencode_unsafe_plugin_paths([str(plugin)]) == [os.path.realpath(plugin)]


def test_private_folders_and_a_private_plugin_stay_accepted(tmp_path: Path, monkeypatch) -> None:
    _, _, plugin = _tree(tmp_path, 0o755, 0o755)
    plugin.write_text("// managed plugin\n", encoding="utf-8")
    plugin.chmod(0o600)
    assert connector_paths.opencode_unsafe_plugin_paths([str(plugin)]) == []
    monkeypatch.setattr(connector_paths, "connector_config_files", lambda _name: [str(plugin)])
    cmd_setup._preflight_opencode_plugin_folder()
