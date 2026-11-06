# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Connector setup and init on a Linux account with a private primary group."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import click
import pytest
from defenseclaw import bootstrap, connector_paths, file_permissions
from defenseclaw.commands import cmd_setup
from defenseclaw.config import default_config

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux private groups")


def _folder_tree(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path, Path]:
    home = tmp_path / "home"
    config = home / ".config"
    plugins = config / "opencode" / "plugins"
    plugins.mkdir(parents=True)
    for path in (home, config, plugins.parent, plugins):
        path.chmod(0o700)
    monkeypatch.setenv("HOME", str(home))
    plugin = plugins / "defenseclaw.js"
    monkeypatch.setattr(connector_paths, "connector_config_files", lambda _name: [str(plugin)])
    return config, plugins, plugin


def _account_records(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, gid: int, *, shared: bool = False) -> None:
    import grp
    import pwd

    uid = os.geteuid()
    passwd = tmp_path / "passwd"
    groups = tmp_path / "group"
    passwd.write_text(f"me:x:{uid}:{gid}::/home/me:/bin/sh\n", encoding="utf-8")
    member = "me,bob" if shared else ""
    groups.write_text(f"me:x:{gid}:{member}\n", encoding="utf-8")
    monkeypatch.setattr(file_permissions, "_PASSWD_FILE", str(passwd), raising=False)
    monkeypatch.setattr(file_permissions, "_GROUP_FILE", str(groups), raising=False)
    monkeypatch.setattr(pwd, "getpwuid", lambda _uid: SimpleNamespace(pw_name="me", pw_gid=gid))
    monkeypatch.setattr(grp, "getgrgid", lambda _gid: SimpleNamespace(gr_name="me", gr_mem=member.split(",") if member else []))


def test_gap0657_private_group_775_ancestors_allow_opencode_setup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config, plugins, plugin = _folder_tree(monkeypatch, tmp_path)
    _account_records(monkeypatch, tmp_path, config.stat().st_gid)
    config.chmod(0o775)
    plugins.parent.chmod(0o775)
    plugins.chmod(0o775)

    assert connector_paths.opencode_writable_plugin_folder([str(plugin)]) == ""
    cmd_setup._preflight_opencode_plugin_folder()
    missing = bootstrap._connector_readiness(default_config(), "opencode")
    assert missing.next_command == "defenseclaw setup opencode"
    plugin.write_text("// defenseclaw-managed-plugin\n", encoding="utf-8")
    ready = bootstrap._connector_readiness(default_config(), "opencode")
    assert ready.status == "pass"


def test_gap0657_owner_private_755_stays_allowed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config, plugins, plugin = _folder_tree(monkeypatch, tmp_path)
    _account_records(monkeypatch, tmp_path, config.stat().st_gid)
    config.chmod(0o755)
    plugins.parent.chmod(0o755)
    plugins.chmod(0o755)

    assert connector_paths.opencode_writable_plugin_folder([str(plugin)]) == ""
    cmd_setup._preflight_opencode_plugin_folder()


@pytest.mark.parametrize("shared,mode", [(True, 0o775), (False, 0o777)])
def test_gap0657_first_unsafe_ancestor_is_named(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, shared: bool, mode: int
) -> None:
    config, plugins, plugin = _folder_tree(monkeypatch, tmp_path)
    _account_records(monkeypatch, tmp_path, config.stat().st_gid, shared=shared)
    config.chmod(mode)
    plugins.parent.chmod(mode)
    plugins.chmod(mode)

    assert connector_paths.opencode_writable_plugin_folder([str(plugin)]) == str(config)
    with pytest.raises(click.ClickException) as caught:
        cmd_setup._preflight_opencode_plugin_folder()
    assert f"chmod go-w {config}" in str(caught.value)


def test_gap0657_group_member_keeps_folder_untrusted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config, _, plugin = _folder_tree(monkeypatch, tmp_path)
    _account_records(monkeypatch, tmp_path, config.stat().st_gid, shared=True)
    config.chmod(0o775)
    assert connector_paths.opencode_writable_plugin_folder([str(plugin)]) == str(config)
