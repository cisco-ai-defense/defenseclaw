# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""OpenCode setup friction on a shared Ubuntu host (gas-ux-r1 GAP-0053).

- Ubuntu's umask 002 with user private groups left ~/.config and
  ~/.config/opencode at 0775, and setup refused them; a shared group still
  must be refused.
- OpenCode V2's background server listens on 49374 for every account, so a
  second account's server could not start.
- A detected OpenCode V1 named the V2 install but not the V1 removal npm
  needs first.
- init had no way to give the API and proxy ports.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import click
import pytest
from defenseclaw import bootstrap, connector_paths, file_permissions, opencode_service
from defenseclaw.config import default_config

linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="user private groups are a Linux convention")
posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX background server; Windows keeps the documented command")


# ---------------------------------------------------------------- private-group folders


def _opencode_home(tmp_path: Path, mode: int = 0o775) -> tuple[Path, Path]:
    """A home whose ~/.config and ~/.config/opencode have *mode* (Ubuntu umask 002: 0775)."""
    home = tmp_path / "home"
    plugins = home / ".config" / "opencode" / "plugins"
    plugins.mkdir(parents=True)
    plugins.chmod(0o700)
    for folder in (home / ".config", home / ".config" / "opencode"):
        folder.chmod(mode)
    # Some hosts give their temp root a default ACL; with one the group bits
    # are the ACL mask and the rule rightly refuses.
    for folder in (tmp_path, home, home / ".config", home / ".config" / "opencode", plugins):
        for name in ("system.posix_acl_access", "system.posix_acl_default"):
            try:
                os.removexattr(folder, name)
            except (AttributeError, OSError):
                pass
    return home, plugins / "defenseclaw.js"


def _accounts(monkeypatch, tmp_path: Path, gid: int, *, passwd_extra: str = "", group_line: str = "", nss_members=()):
    """Point the account and group files at a fixture: account "me" with private group "me"."""
    uid = os.geteuid()
    passwd = tmp_path / "passwd"
    group = tmp_path / "group"
    passwd.write_text(f"me:x:{uid}:{gid}::/home/me:/bin/bash\n" + passwd_extra, encoding="utf-8")
    group.write_text(group_line or f"me:x:{gid}:\n", encoding="utf-8")
    monkeypatch.setattr(file_permissions, "_PASSWD_FILE", str(passwd), raising=False)
    monkeypatch.setattr(file_permissions, "_GROUP_FILE", str(group), raising=False)
    import grp
    import pwd

    monkeypatch.setattr(pwd, "getpwuid", lambda _uid: SimpleNamespace(pw_name="me", pw_gid=gid))
    monkeypatch.setattr(grp, "getgrgid", lambda _gid: SimpleNamespace(gr_name="me", gr_mem=list(nss_members)))


@linux_only
def test_folders_of_the_owners_private_group_are_accepted(monkeypatch, tmp_path):
    home, plugin = _opencode_home(tmp_path)
    monkeypatch.setenv("HOME", str(home))
    _accounts(monkeypatch, tmp_path, os.stat(home / ".config").st_gid)

    assert connector_paths.opencode_writable_plugin_folder([str(plugin)]) == ""
    monkeypatch.setattr(connector_paths, "connector_config_files", lambda _name: [str(plugin)])
    from defenseclaw.commands import cmd_setup

    cmd_setup._preflight_opencode_plugin_folder()  # no refusal


@linux_only
@pytest.mark.parametrize(
    "case",
    ["shared-group", "member-in-private-group", "other-primary-account", "nss-member", "everyone-writable", "no-group-entry"],
)
def test_folders_another_account_can_write_stay_refused(monkeypatch, tmp_path, case):
    home, plugin = _opencode_home(tmp_path, 0o777 if case == "everyone-writable" else 0o775)
    monkeypatch.setenv("HOME", str(home))
    gid = os.stat(home / ".config").st_gid
    kwargs = {
        "shared-group": {"group_line": f"devs:x:{gid}:me,bob\n"},
        "member-in-private-group": {"group_line": f"me:x:{gid}:me,bob\n"},
        "other-primary-account": {"passwd_extra": f"bob:x:{os.geteuid() + 1}:{gid}::/home/bob:/bin/bash\n"},
        "nss-member": {"nss_members": ("bob",)},
        "everyone-writable": {},
        "no-group-entry": {"group_line": f"other:x:{gid + 1}:\n"},
    }[case]
    _accounts(monkeypatch, tmp_path, gid, **kwargs)

    loose = connector_paths.opencode_writable_plugin_folder([str(plugin)])
    assert loose == os.path.realpath(home / ".config" / "opencode")
    monkeypatch.setattr(connector_paths, "connector_config_files", lambda _name: [str(plugin)])
    from defenseclaw.commands import cmd_setup

    with pytest.raises(click.ClickException, match="chmod go-w"):
        cmd_setup._preflight_opencode_plugin_folder()


# ---------------------------------------------------------------- per-account service port


def _fake_opencode(tmp_path: Path, config_home: Path, channel_port: int | str = "") -> str:
    """`opencode service get|set port` and `status`, with service.json as OpenCode keeps it.

    Like OpenCode 2.2.5, `get port` prints nothing while no port is set.
    """
    service = config_home / "opencode" / "service.json"
    tmp_path.mkdir(parents=True, exist_ok=True)
    binary = tmp_path / "opencode"
    binary.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        f"path = {str(service)!r}\n"
        "data = json.load(open(path)) if os.path.exists(path) else {}\n"
        "args = sys.argv[1:]\n"
        "if args[:3] == ['service', 'get', 'port']:\n"
        f"    print(data.get('port', {channel_port!r}))\n"
        "elif args[:3] == ['service', 'set', 'port']:\n"
        "    data['port'] = int(args[3]); data.setdefault('password', 'x')\n"
        "    os.makedirs(os.path.dirname(path), exist_ok=True); json.dump(data, open(path, 'w'))\n"
        "elif args[:2] == ['service', 'status']:\n"
        "    print('stopped')\n",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    return str(binary)


class _Host:
    """One computer: listening ports and the per-account port claims in /var/tmp."""

    def __init__(self):
        self.listening: set[int] = set()
        self.claims: dict[int, int] = {}
        self.uid = 0

    def install(self, monkeypatch):
        monkeypatch.setattr(opencode_service.os, "getuid", lambda: self.uid)
        monkeypatch.setattr(bootstrap, "_api_port_free", lambda _host, port: port not in self.listening)
        monkeypatch.setattr(
            bootstrap,
            "_api_port_claimed_by_other_account",
            lambda port, prefix=bootstrap._API_PORT_CLAIM_PREFIX: self.claims.get(port, self.uid) != self.uid,
        )

        def reserve(port, prefix=bootstrap._API_PORT_CLAIM_PREFIX):
            if self.claims.get(port, self.uid) != self.uid:
                return False
            self.claims[port] = self.uid
            return True

        monkeypatch.setattr(bootstrap, "_reserve_api_port", reserve)


def _account(monkeypatch, tmp_path: Path, host: _Host, uid: int, **fake) -> tuple[str, Path]:
    config_home = tmp_path / f"u{uid}" / ".config"
    config_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    host.uid = uid
    return _fake_opencode(tmp_path / f"u{uid}", config_home, **fake), config_home / "opencode" / "service.json"


@posix_only
@pytest.mark.parametrize("unset_prints", ["", 49374])
def test_two_accounts_get_their_own_stable_service_ports(monkeypatch, tmp_path, unset_prints):
    host = _Host()
    host.install(monkeypatch)
    ports = {}
    for uid in (1001, 1002):
        binary, service = _account(monkeypatch, tmp_path, host, uid, channel_port=unset_prints)
        line = opencode_service.ensure_account_port(binary)
        ports[uid] = json.loads(service.read_text())["port"]
        assert f"uses port {ports[uid]} for this account" in line and "49374" in line
        host.listening.add(ports[uid])  # its server now runs there

    assert ports == {1001: 24000 + 1001 % 8000, 1002: 24000 + 1002 % 8000}
    assert ports[1001] != ports[1002]
    assert host.claims == {ports[1001]: 1001, ports[1002]: 1002}
    # Stable: a later setup run keeps the recorded port and says nothing.
    for uid in (1001, 1002):
        binary, service = _account(monkeypatch, tmp_path, host, uid)
        assert opencode_service.ensure_account_port(binary) == ""
        assert json.loads(service.read_text())["port"] == ports[uid]


@posix_only
def test_an_account_whose_port_another_account_holds_takes_the_next(monkeypatch, tmp_path):
    host = _Host()
    host.install(monkeypatch)
    first, _ = _account(monkeypatch, tmp_path, host, 1001)
    opencode_service.ensure_account_port(first)
    # uid 9001 derives the same port as uid 1001 (mod 8000): claimed, so the next one.
    second, service = _account(monkeypatch, tmp_path, host, 9001)
    opencode_service.ensure_account_port(second)
    assert json.loads(service.read_text())["port"] == 24000 + 1001 % 8000 + 1
    # A port something else listens on is skipped too.
    host.listening.add(24000 + 1003 % 8000)
    third, service = _account(monkeypatch, tmp_path, host, 1003)
    opencode_service.ensure_account_port(third)
    assert json.loads(service.read_text())["port"] == 24000 + 1003 % 8000 + 1


@posix_only
@pytest.mark.parametrize("case", ["set-by-user", "own-channel-port", "no-opencode-v2"])
def test_a_port_the_account_chose_is_kept(monkeypatch, tmp_path, case):
    host = _Host()
    host.install(monkeypatch)
    extra = {"channel_port": 51234} if case == "own-channel-port" else {}
    binary, service = _account(monkeypatch, tmp_path, host, 1001, **extra)
    if case == "set-by-user":
        service.parent.mkdir(parents=True, exist_ok=True)
        service.write_text(json.dumps({"port": 49374, "password": "x"}))
    assert opencode_service.ensure_account_port("" if case == "no-opencode-v2" else binary) == ""
    assert host.claims == {}
    if case == "set-by-user":
        assert json.loads(service.read_text())["port"] == 49374


@posix_only
@pytest.mark.parametrize("teardown", [False, True])
def test_setup_sets_the_port_before_it_restarts_the_server(monkeypatch, tmp_path, teardown):
    from defenseclaw.commands import cmd_setup

    order = []
    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", lambda *_a, **_k: True)
    monkeypatch.setattr(opencode_service, "account_binary", lambda data_dir=None: "/u/bin/opencode")
    monkeypatch.setattr(opencode_service, "ensure_account_port", lambda binary: order.append(f"port {binary}") or "")
    monkeypatch.setattr(opencode_service, "restart_if_running", lambda binary: order.append(f"restart {binary}") or "")
    cmd_setup._restart_services(str(tmp_path), connector="opencode", teardown=teardown)
    assert order == (["restart /u/bin/opencode"] if teardown else ["port /u/bin/opencode", "restart /u/bin/opencode"])


# ---------------------------------------------------------------- OpenCode V1 -> V2 hint


@pytest.mark.parametrize(("version", "removes_v1"), [("1.18.34", True), ("1.19.5", True), ("3.0.0", False), ("", False)])
def test_v2_hint_names_the_v1_removal_npm_needs(version, removes_v1):
    from defenseclaw.commands.cmd_setup import _connector_contract_upgrade_guidance

    guidance = _connector_contract_upgrade_guidance("opencode", "OpenCode", version)
    assert "npm install -g @opencode/cli@2" in guidance
    assert ("npm uninstall -g opencode-ai" in guidance) is removes_v1
    if removes_v1:
        assert guidance.index("npm uninstall -g opencode-ai") < guidance.index("npm install -g @opencode/cli@2")


# ---------------------------------------------------------------- init --api-port / --proxy-port


def test_init_ports_go_into_a_new_config(monkeypatch):
    monkeypatch.setattr(bootstrap, "_api_port_available", lambda _host, _port: True)
    monkeypatch.setattr(bootstrap, "_reserve_api_port", lambda _port, prefix=None: True)
    monkeypatch.setattr(bootstrap, "_guardrail_port_available", lambda _host, _port: True)
    cfg = default_config()
    steps = bootstrap.apply_first_run_ports(cfg, 16700, 16701, new_config=True)
    assert (cfg.gateway.api_port, cfg.guardrail.port) == (16700, 16701)
    assert [(s.name, s.status) for s in steps] == [("Gateway API port", "pass"), ("Guardrail proxy port", "pass")]


def test_init_ports_held_elsewhere_are_kept_with_a_warning(monkeypatch):
    monkeypatch.setattr(bootstrap, "_api_port_available", lambda _host, _port: False)
    monkeypatch.setattr(bootstrap, "_guardrail_port_available", lambda _host, _port: False)
    cfg = default_config()
    steps = bootstrap.apply_first_run_ports(cfg, 16700, 16701, new_config=True)
    assert (cfg.gateway.api_port, cfg.guardrail.port) == (16700, 16701)
    assert [s.status for s in steps] == ["warn", "warn"]
    assert "in use or claimed by another account" in steps[0].detail


def test_init_ports_leave_an_existing_config_alone():
    cfg = default_config()
    before = (cfg.gateway.api_port, cfg.guardrail.port)
    steps = bootstrap.apply_first_run_ports(cfg, 16700, 16701, new_config=False)
    assert (cfg.gateway.api_port, cfg.guardrail.port) == before
    assert [s.next_command for s in steps] == [
        "defenseclaw setup gateway --api-port 16700 --non-interactive",
        "defenseclaw setup guardrail --port 16701 --non-interactive",
    ]
    assert bootstrap.apply_first_run_ports(cfg, before[0], before[1], new_config=False) == []


def test_init_passes_the_given_ports_to_first_run(monkeypatch):
    from click.testing import CliRunner
    from defenseclaw.commands import cmd_init

    captured = {}
    monkeypatch.setattr(cmd_init, "_use_guided_first_run", lambda **_k: True)
    monkeypatch.setattr(cmd_init, "_run_first_run_cmd", lambda **kwargs: captured.update(kwargs))
    monkeypatch.setattr(cmd_init, "refuse_first_run_when_managed", lambda: None)
    result = CliRunner().invoke(
        cmd_init.init_cmd,
        ["--non-interactive", "--connector", "none", "--api-port", "16700", "--proxy-port", "16701"],
        obj=SimpleNamespace(cfg=None),
    )
    assert result.exit_code == 0, result.output
    assert (captured["api_port"], captured["proxy_port"]) == (16700, 16701)
    bad = CliRunner().invoke(cmd_init.init_cmd, ["--api-port", "70000"], obj=SimpleNamespace(cfg=None))
    assert bad.exit_code == 2 and "70000" in bad.output



# ---------------------------------------------------------------- the class: every agent folder and binary check


def _npm_prefix(tmp_path: Path, mode: int = 0o775) -> tuple[Path, Path]:
    """An npm prefix made under umask 002: ~/.npm-global/bin/opencode 0775 in 0775 folders."""
    prefix = tmp_path / "home" / ".npm-global"
    bin_dir = prefix / "bin"
    bin_dir.mkdir(parents=True)
    binary = bin_dir / "opencode"
    binary.write_text("#!/bin/sh\necho 2.2.5\n", encoding="utf-8")
    for path in (prefix, bin_dir):
        path.chmod(mode)
    binary.chmod(0o775 if mode == 0o775 else 0o777)
    for path in (tmp_path, tmp_path / "home", prefix, bin_dir):
        for name in ("system.posix_acl_access", "system.posix_acl_default"):
            try:
                os.removexattr(path, name)
            except (AttributeError, OSError):
                pass
    return prefix, binary


def _agent_checks(binary: Path, prefix: Path, monkeypatch) -> dict[str, bool]:
    """What each agent-binary check says about *binary* (True = trusted)."""
    from defenseclaw import agent_selection
    from defenseclaw.inventory import agent_discovery

    monkeypatch.setenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", str(prefix / "bin"))
    _, prefix_error = agent_discovery.validate_trusted_prefix(str(prefix / "bin"))
    return {
        "trusted-paths add": prefix_error is None,
        "discovery": agent_discovery._is_trusted_binary_path(str(binary)),
        "setup chain": agent_selection._posix_setup_chain_is_safe(str(binary), str(prefix)),
    }


@linux_only
def test_agent_binaries_in_a_private_group_npm_prefix_are_trusted(monkeypatch, tmp_path):
    prefix, binary = _npm_prefix(tmp_path)
    _accounts(monkeypatch, tmp_path, os.stat(prefix).st_gid)
    assert _agent_checks(binary, prefix, monkeypatch) == {"trusted-paths add": True, "discovery": True, "setup chain": True}


@linux_only
@pytest.mark.parametrize("case", ["shared-group", "member-in-private-group", "everyone-writable"])
def test_agent_binaries_another_account_can_write_stay_untrusted(monkeypatch, tmp_path, case):
    prefix, binary = _npm_prefix(tmp_path, 0o777 if case == "everyone-writable" else 0o775)
    gid = os.stat(prefix).st_gid
    group_line = {"shared-group": f"devs:x:{gid}:me,bob\n", "member-in-private-group": f"me:x:{gid}:me,bob\n"}.get(case, "")
    _accounts(monkeypatch, tmp_path, gid, group_line=group_line)
    assert _agent_checks(binary, prefix, monkeypatch) == {
        "trusted-paths add": False, "discovery": False, "setup chain": False,
    }


@linux_only
@pytest.mark.parametrize("private", [True, False])
def test_other_accounts_can_write_is_the_one_rule(monkeypatch, tmp_path, private):
    folder = tmp_path / "f"
    folder.mkdir()
    gid = os.stat(folder).st_gid
    _accounts(monkeypatch, tmp_path, gid, group_line="" if private else f"devs:x:{gid}:me,bob\n")
    for mode, expected in ((0o700, False), (0o755, False), (0o775, not private), (0o757, True), (0o777, True)):
        folder.chmod(mode)
        for name in ("system.posix_acl_access", "system.posix_acl_default"):
            try:
                os.removexattr(folder, name)
            except (AttributeError, OSError):
                pass
        assert file_permissions.other_accounts_can_write(str(folder), os.stat(folder)) is expected, oct(mode)


@linux_only
@pytest.mark.parametrize("shared", [False, True])
def test_the_folder_holding_the_npm_link_counts_too(monkeypatch, tmp_path, shared):
    """npm links ~/.npm-global/bin/opencode to the package: both folders are checked."""
    from defenseclaw.inventory import agent_discovery

    prefix, target = _npm_prefix(tmp_path)
    package_bin = prefix / "lib" / "node_modules" / "@opencode" / "cli" / "bin"
    package_bin.mkdir(parents=True)
    real = package_bin / "opencode.exe"
    target.rename(real)
    target.symlink_to(real)
    for folder in (prefix / "lib", prefix / "lib" / "node_modules", package_bin.parent.parent, package_bin.parent, package_bin):
        folder.chmod(0o755)
    gid = os.stat(prefix / "bin").st_gid
    _accounts(monkeypatch, tmp_path, gid, group_line=f"devs:x:{gid}:me,bob\n" if shared else "")
    monkeypatch.setenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", str(prefix))
    assert agent_discovery._is_trusted_binary_path(str(target)) is not shared
