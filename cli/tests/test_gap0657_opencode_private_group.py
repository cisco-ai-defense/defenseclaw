# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Connector setup and init on a Linux account with a private primary group."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import click
import pytest
from defenseclaw import agent_selection, bootstrap, connector_paths, file_permissions
from defenseclaw.commands import cmd_setup
from defenseclaw.config import default_config
from defenseclaw.inventory import agent_discovery

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

    assert connector_paths.opencode_unsafe_plugin_paths([str(plugin)]) == []
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

    assert connector_paths.opencode_unsafe_plugin_paths([str(plugin)]) == []
    cmd_setup._preflight_opencode_plugin_folder()


def test_gap0657_sticky_ancestor_stays_allowed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sticky = Path("/tmp")
    info = sticky.stat()
    if info.st_uid != 0 or not info.st_mode & stat.S_ISVTX:
        pytest.skip("root-owned sticky /tmp is unavailable")
    plugin = tmp_path / "plugins" / "defenseclaw.js"
    plugin.parent.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(sticky))
    monkeypatch.setenv("OPENCODE_CONFIG_DIR", str(tmp_path))
    assert connector_paths.opencode_unsafe_plugin_paths([str(plugin)]) == []
    cmd_setup._preflight_opencode_plugin_folder()


def test_gap0657_custom_config_root_names_unsafe_ancestor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    external = tmp_path / "external"
    (external / "plugins").mkdir(parents=True)
    external.chmod(0o777)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("OPENCODE_CONFIG_DIR", str(external))
    plugin = connector_paths.connector_config_files("opencode")[0]
    assert connector_paths.opencode_unsafe_plugin_paths([plugin])[:1] == [str(external)]
    with pytest.raises(click.ClickException) as caught:
        cmd_setup._preflight_opencode_plugin_folder()
    assert f"chmod go-w {external}" in str(caught.value)


@pytest.mark.parametrize("mode,shared,allowed", [(0o775, False, True), (0o775, True, False), (0o755, True, True)])
def test_gap0657_executable_prefix_uses_private_group_rule(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: int, shared: bool, allowed: bool
) -> None:
    prefix = tmp_path / "bin"
    prefix.mkdir()
    prefix.chmod(mode)
    executable = prefix / "opencode"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    _account_records(monkeypatch, tmp_path, prefix.stat().st_gid, shared=shared)
    monkeypatch.setattr(agent_selection, "_builtin_setup_trusted_prefixes", lambda: (str(prefix),))
    monkeypatch.setattr(agent_discovery, "_ai_discovery_trust_config", lambda _path: (False, ()))
    monkeypatch.setenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", str(prefix))

    assert (agent_discovery.validate_trusted_prefix(str(prefix))[1] is None) is allowed
    assert agent_discovery._is_trusted_binary_path(str(executable)) is allowed
    assert agent_selection.is_setup_trusted_binary(str(executable), str(tmp_path)) is allowed
    assert agent_selection._posix_setup_chain_is_safe(str(executable), str(prefix)) is allowed


def test_gap0657_executable_prefix_with_acl_stays_untrusted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    prefix = tmp_path / "bin"
    prefix.mkdir()
    prefix.chmod(0o775)
    _account_records(monkeypatch, tmp_path, prefix.stat().st_gid)
    native_getxattr = os.getxattr

    def getxattr(path: str, name: str, *, follow_symlinks: bool = True) -> bytes:
        if os.fspath(path) == str(prefix) and name == "system.nfs4_acl":
            return b"present"
        return native_getxattr(path, name, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(file_permissions.os, "getxattr", getxattr)
    assert file_permissions.owner_private_group(str(prefix), prefix.stat()) is False
    assert agent_discovery.validate_trusted_prefix(str(prefix))[1] == "directory is group-writable"


@pytest.mark.parametrize("shared,mode", [(True, 0o775), (False, 0o777)])
def test_gap0657_first_unsafe_ancestor_is_named(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, shared: bool, mode: int
) -> None:
    config, plugins, plugin = _folder_tree(monkeypatch, tmp_path)
    _account_records(monkeypatch, tmp_path, config.stat().st_gid, shared=shared)
    config.chmod(mode)
    plugins.parent.chmod(mode)
    plugins.chmod(mode)

    assert connector_paths.opencode_unsafe_plugin_paths([str(plugin)])[:1] == [str(config)]
    with pytest.raises(click.ClickException) as caught:
        cmd_setup._preflight_opencode_plugin_folder()
    assert f"chmod go-w {config}" in str(caught.value)


def test_gap0657_group_member_keeps_folder_untrusted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config, _, plugin = _folder_tree(monkeypatch, tmp_path)
    _account_records(monkeypatch, tmp_path, config.stat().st_gid, shared=True)
    config.chmod(0o775)
    assert connector_paths.opencode_unsafe_plugin_paths([str(plugin)])[:1] == [str(config)]


def test_gap0657_duplicate_login_name_keeps_folder_untrusted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config, _, plugin = _folder_tree(monkeypatch, tmp_path)
    gid = config.stat().st_gid
    _account_records(monkeypatch, tmp_path, gid)
    passwd = Path(file_permissions._PASSWD_FILE)
    passwd.write_text(passwd.read_text(encoding="utf-8") + f"me:x:{os.geteuid() + 1}:{gid}::/home/other:/bin/sh\n", encoding="utf-8")
    config.chmod(0o775)
    assert connector_paths.opencode_unsafe_plugin_paths([str(plugin)])[:1] == [str(config)]
