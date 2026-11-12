# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""OpenCode setup friction on a shared Ubuntu host (gas-ux-r1 GAP-0053).

- Ubuntu's umask 002 with user private groups left ~/.config and
  ~/.config/opencode at 0775 (the private-group rule itself is GAP-0657's,
  file_permissions.owner_private_group, tested in
  test_gap0657_opencode_private_group.py; the tests below use it).
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


def _opencode_home(tmp_path: Path, mode: int = 0o775, *, config_mode: int | None = None) -> tuple[Path, Path]:
    """A home whose ~/.config and ~/.config/opencode have *mode* (Ubuntu umask 002: 0775).

    *config_mode* gives ~/.config another mode, so that ~/.config/opencode is the only
    unsafe ancestor (GAP-0657 names the first unsafe ancestor, outermost first).
    """
    home = tmp_path / "home"
    plugins = home / ".config" / "opencode" / "plugins"
    plugins.mkdir(parents=True)
    plugins.chmod(0o700)
    (home / ".config").chmod(mode if config_mode is None else config_mode)
    (home / ".config" / "opencode").chmod(mode)
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
@pytest.mark.parametrize("case", ["other-primary-account", "nss-member", "no-group-entry"])
def test_folders_another_account_can_write_stay_refused(monkeypatch, tmp_path, case):
    """The r13 refusal cases that test_gap0657_opencode_private_group.py does not pin."""
    home, plugin = _opencode_home(tmp_path, 0o775, config_mode=0o755)
    monkeypatch.setenv("HOME", str(home))
    gid = os.stat(home / ".config").st_gid
    kwargs = {
        "other-primary-account": {"passwd_extra": f"bob:x:{os.geteuid() + 1}:{gid}::/home/bob:/bin/bash\n"},
        "nss-member": {"nss_members": ("bob",)},
        "no-group-entry": {"group_line": f"other:x:{gid + 1}:\n"},
    }[case]
    _accounts(monkeypatch, tmp_path, gid, **kwargs)

    unsafe = connector_paths.opencode_unsafe_plugin_paths([str(plugin)])
    assert [str(path) for path in unsafe] == [os.path.realpath(home / ".config" / "opencode")]
    assert unsafe[0].problems == ("mode",)
    monkeypatch.setattr(connector_paths, "connector_config_files", lambda _name: [str(plugin)])
    from defenseclaw.commands import cmd_setup

    with pytest.raises(click.ClickException, match="chmod go-w"):
        cmd_setup._preflight_opencode_plugin_folder()


# ---------------------------------------------------------------- per-account service port


class _Host:
    """One computer: listening ports and the per-account port claims.

    POSIX claims are owned by a uid; Windows claims hold the account SID
    (the real Windows claim path is used, with %ProgramData% in tmp).
    """

    def __init__(self, monkeypatch, tmp_path: Path, windows: bool = False):
        self.listening: set[int] = set()
        self.claims: dict[int, int] = {}
        self.account = 0
        self.windows = windows
        self.claim_dir = tmp_path / "ProgramData"
        self.claim_dir.mkdir()
        self.tmp_path = tmp_path
        monkeypatch.setattr(bootstrap, "_windows_port_claims", lambda: self.windows)
        monkeypatch.setattr(bootstrap, "_api_port_claim_dir", lambda: str(self.claim_dir))
        monkeypatch.setattr(bootstrap, "_windows_own_sid", lambda: f"S-1-5-21-1-2-3-{self.account}")
        monkeypatch.setattr(opencode_service.os, "getuid", lambda: self.account, raising=False)
        monkeypatch.setattr(bootstrap, "_api_port_free", lambda _host, port: port not in self.listening)
        if not windows:
            monkeypatch.setattr(
                bootstrap,
                "_api_port_claimed_by_other_account",
                lambda port, prefix=bootstrap._API_PORT_CLAIM_PREFIX: self.claims.get(port, self.account) != self.account,
            )

            def reserve(port, prefix=bootstrap._API_PORT_CLAIM_PREFIX):
                if self.claims.get(port, self.account) != self.account:
                    return False
                self.claims[port] = self.account
                return True

            monkeypatch.setattr(bootstrap, "_reserve_api_port", reserve)

    def login(self, monkeypatch, account: int) -> Path:
        """Become *account*; returns its service.json path."""
        self.account = account
        config_home = self.tmp_path / f"u{account}" / ".config"
        config_home.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
        return config_home / "opencode" / "service.json"


def _port(service: Path) -> int:
    return json.loads(service.read_text())["port"]


@pytest.mark.parametrize("windows", [False, True])
def test_two_accounts_get_their_own_stable_service_ports(monkeypatch, tmp_path, windows):
    host = _Host(monkeypatch, tmp_path, windows)
    ports = {}
    for account in (1001, 1002):
        service = host.login(monkeypatch, account)
        line = opencode_service.ensure_account_port()
        ports[account] = _port(service)
        assert f"uses port {ports[account]} for this account" in line and "49374" in line
        host.listening.add(ports[account])  # its server now runs there
    assert ports == {1001: 24000 + 1001 % 8000, 1002: 24000 + 1002 % 8000}
    if windows:
        claims = {p.name: p.read_text() for p in host.claim_dir.iterdir()}
        assert claims == {
            f"defenseclaw-opencode-port-{ports[1001]}": "S-1-5-21-1-2-3-1001",
            f"defenseclaw-opencode-port-{ports[1002]}": "S-1-5-21-1-2-3-1002",
        }
    else:
        assert host.claims == {ports[1001]: 1001, ports[1002]: 1002}
    # Stable: a later setup run, and one after an upgrade (the files and the
    # claims stay), keeps the recorded port and says nothing.
    for account in (1001, 1002, 1001):
        service = host.login(monkeypatch, account)
        assert opencode_service.ensure_account_port() == ""
        assert _port(service) == ports[account]


@pytest.mark.parametrize("windows", [False, True])
def test_an_account_whose_port_another_account_holds_takes_the_next(monkeypatch, tmp_path, windows):
    host = _Host(monkeypatch, tmp_path, windows)
    host.login(monkeypatch, 1001)
    opencode_service.ensure_account_port()
    # 9001 derives the same port as 1001 (mod 8000): claimed, so the next one.
    service = host.login(monkeypatch, 9001)
    opencode_service.ensure_account_port()
    assert _port(service) == 24000 + 1001 % 8000 + 1
    # A port something else listens on is skipped too.
    host.listening.add(24000 + 1003 % 8000)
    service = host.login(monkeypatch, 1003)
    opencode_service.ensure_account_port()
    assert _port(service) == 24000 + 1003 % 8000 + 1


@pytest.mark.parametrize("case", ["set-by-user", "set-to-the-default", "not-an-object", "link"])
def test_a_port_the_account_chose_is_kept(monkeypatch, tmp_path, case):
    host = _Host(monkeypatch, tmp_path)
    service = host.login(monkeypatch, 1001)
    service.parent.mkdir(parents=True, exist_ok=True)
    body = {
        "set-by-user": '{"port": 49375, "password": "x"}',
        "set-to-the-default": '{"port": 49374, "password": "x"}',
        "not-an-object": "[1]",
    }.get(case)
    if case == "link":
        target = tmp_path / "elsewhere.json"
        target.write_text("{}")
        service.symlink_to(target)
    else:
        service.write_text(body)
    line = opencode_service.ensure_account_port()
    assert host.claims == {}
    if case in ("set-by-user", "set-to-the-default"):
        assert line == "" and service.read_text() == body
    else:
        assert line.startswith("!") and "opencode service set port" in line
        assert case != "link" or (tmp_path / "elsewhere.json").read_text() == "{}"


def test_the_password_opencode_wrote_is_kept(monkeypatch, tmp_path):
    host = _Host(monkeypatch, tmp_path)
    service = host.login(monkeypatch, 1001)
    service.parent.mkdir(parents=True, exist_ok=True)
    service.write_text('{"password": "kept"}')
    opencode_service.ensure_account_port()
    assert json.loads(service.read_text()) == {"password": "kept", "port": 25001}
    if os.name != "nt":
        assert service.stat().st_mode & 0o777 == 0o600


@posix_only
@pytest.mark.parametrize("teardown", [False, True])
def test_setup_sets_the_port_before_it_restarts_the_server(monkeypatch, tmp_path, teardown):
    from defenseclaw.commands import cmd_setup

    order = []
    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", lambda *_a, **_k: True)
    monkeypatch.setattr(opencode_service, "account_binary", lambda data_dir=None: "/u/bin/opencode")
    monkeypatch.setattr(opencode_service, "ensure_account_port", lambda: order.append("port") or "")
    monkeypatch.setattr(opencode_service, "restart_if_running", lambda binary: order.append(f"restart {binary}") or "")
    cmd_setup._restart_services(str(tmp_path), connector="opencode", teardown=teardown)
    assert order == (["restart /u/bin/opencode"] if teardown else ["port", "restart /u/bin/opencode"])


def test_the_cli_and_the_guardian_use_the_same_scheme():
    """cli/defenseclaw/opencode_service.py and internal/enterprisepolicy/opencode_service_port.go."""
    go = (Path(__file__).resolve().parents[2] / "internal/enterprisepolicy/opencode_service_port.go").read_text()
    assert f"OpenCodeDefaultServicePort = {opencode_service.DEFAULT_SERVICE_PORT}" in go
    assert f"OpenCodeAccountPortBase = {opencode_service.ACCOUNT_PORT_BASE}" in go
    assert f"OpenCodeAccountPortSpan = {opencode_service.ACCOUNT_PORT_SPAN}" in go
    assert 'filepath.Join(home, ".config", "opencode", "service.json")' in go


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
        ["--non-interactive", "--connector", "none", "--api-port", "16700", "--proxy-port", "16710"],
        obj=SimpleNamespace(cfg=None),
    )
    assert result.exit_code == 0, result.output
    assert (captured["api_port"], captured["proxy_port"]) == (16700, 16710)
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


# ---------------------------------------------------------------- every port-flag collision form


@pytest.mark.parametrize(
    ("api", "proxy", "refused"),
    [
        (28111, 28111, True),  # the same port twice
        (28111, 28112, True),  # the proxy on the first sandbox port
        (28111, 28113, True),  # the proxy on the second sandbox port
        (0, 18970, True),  # the proxy on the default API port (API chosen automatically)
        (0, 18972, True),  # ... or one of its sandbox ports
        (4000, 0, True),  # the API on the default proxy port (proxy chosen automatically)
        (3998, 0, True),  # ... its sandbox ports reach 4000
        (18789, 0, True),  # OpenClaw's gateway port
        (0, 18789, True),
        (65534, 0, True),  # no room for the sandbox ports
        (28111, 28114, False),
        (16700, 16710, False),
        (0, 4010, False),
        (19000, 0, False),
    ],
)
def test_init_refuses_every_port_flag_collision(api, proxy, refused):
    conflict = bootstrap.first_run_port_flags_conflict(api, proxy)
    assert bool(conflict) is refused, conflict


@pytest.mark.parametrize("args", [["--api-port", "28111", "--proxy-port", "28111"], ["--proxy-port", "18970"], ["--api-port", "4000"]])
def test_init_command_refuses_before_writing(monkeypatch, tmp_path, args):
    from click.testing import CliRunner
    from defenseclaw.commands import cmd_init

    ran = []
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "dc"))
    monkeypatch.setattr(cmd_init, "_use_guided_first_run", lambda **_k: ran.append("run") or True)
    monkeypatch.setattr(cmd_init, "_run_first_run_cmd", lambda **kwargs: ran.append("run"))
    monkeypatch.setattr(cmd_init, "refuse_first_run_when_managed", lambda: None)
    result = CliRunner().invoke(cmd_init.init_cmd, ["--non-interactive", "--connector", "none", *args], obj=SimpleNamespace(cfg=None))
    assert result.exit_code == 2 and "choose another" in result.output, result.output
    assert ran == [] and not (tmp_path / "dc").exists()


def test_the_automatic_picks_avoid_the_given_flags(monkeypatch):
    cfg = default_config()
    # Another account holds 18970: the next API candidate is 18980, which
    # --proxy-port took; the pick goes on to 18990.
    monkeypatch.setattr(bootstrap, "_api_port_available", lambda _h, port: port != 18970)
    monkeypatch.setattr(bootstrap, "_reserve_api_port", lambda _p, prefix=None: True)
    bootstrap.choose_first_run_api_port(cfg, bootstrap.api_port_avoid(cfg, 18981))
    assert cfg.gateway.api_port == 18990
    # --api-port 4005: the automatic proxy pick leaves 4005..4007 alone.
    cfg = default_config()
    cfg.gateway.api_port = 3999
    monkeypatch.setattr(bootstrap, "_guardrail_port_available", lambda _h, _p: True)
    bootstrap.choose_first_run_guardrail_port(cfg, bootstrap.proxy_port_avoid(cfg))
    assert cfg.guardrail.port not in {3999, 4000, 4001}


@pytest.mark.parametrize(
    ("api", "proxy", "openclaw", "refused"),
    [(18970, 18970, 0, True), (18970, 18971, 0, True), (18789, 4000, 18789, True), (18970, 18789, 18789, True),
     (18970, 4000, 0, False), (18970, 4000, 18789, False)],
)
def test_one_layout_rule_for_every_port_writer(api, proxy, openclaw, refused):
    """init, setup gateway --api-port, setup guardrail --port and config validate share it."""
    assert bool(bootstrap.port_layout_conflict(api, proxy, openclaw)) is refused


def test_config_validate_warns_on_colliding_ports(monkeypatch):
    from defenseclaw.commands import cmd_config

    cfg = default_config()
    cfg.gateway.api_port, cfg.guardrail.port = 4000, 4000
    monkeypatch.setattr(cmd_config.config_module, "load", lambda: cfg)
    assert cmd_config._port_layout_warnings() and "guardrail.port" in cmd_config._port_layout_warnings()[0]
    cfg.guardrail.port = 4010
    assert cmd_config._port_layout_warnings() == []


@linux_only
@pytest.mark.parametrize("acl", [False, True])
def test_a_symlinked_folder_is_judged_by_its_target(monkeypatch, tmp_path, acl):
    """Review M5: the ACL of the object os.stat describes, not of the link."""
    real = tmp_path / "real-bin"
    real.mkdir()
    real.chmod(0o775)
    for name in ("system.posix_acl_access", "system.posix_acl_default"):
        try:
            os.removexattr(real, name)
        except (AttributeError, OSError):
            pass
    link = tmp_path / "bin"
    link.symlink_to(real)
    _accounts(monkeypatch, tmp_path, os.stat(real).st_gid)
    if acl:
        # A POSIX access ACL granting another uid write (setfacl -m u:65534:rwx).
        import struct

        entries = [(0x01, 7, 0xFFFFFFFF), (0x02, 7, 65534), (0x04, 7, 0xFFFFFFFF), (0x10, 7, 0xFFFFFFFF), (0x20, 5, 0xFFFFFFFF)]
        data = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", tag, perm, uid) for tag, perm, uid in entries)
        try:
            os.setxattr(real, "system.posix_acl_access", data)
        except OSError as exc:
            pytest.skip(f"POSIX ACLs are not available here: {exc}")
    assert file_permissions.other_accounts_can_write(str(link), os.stat(link)) is acl
    # An lstat of the link describes the link, not the folder: not judged private.
    assert file_permissions.owner_private_group(str(link), os.lstat(link)) is False


@linux_only
@pytest.mark.parametrize("private", [True, False])
def test_the_service_port_is_written_into_a_private_group_folder(monkeypatch, tmp_path, private):
    """Live on dc-rhel (r2): the private-file writer refused a 0775 ~/.config/opencode."""
    host = _Host(monkeypatch, tmp_path)
    service = host.login(monkeypatch, 1001)
    folder = service.parent
    folder.mkdir(parents=True)
    for path in (folder.parent, folder):
        path.chmod(0o775)
        for name in ("system.posix_acl_access", "system.posix_acl_default"):
            try:
                os.removexattr(path, name)
            except (AttributeError, OSError):
                pass
    gid = os.stat(folder).st_gid
    _accounts(monkeypatch, tmp_path, gid, group_line="" if private else f"devs:x:{gid}:me,bob\n")
    line = opencode_service.ensure_account_port()
    if private:
        assert "uses port 25001" in line and _port(service) == 25001
    else:
        assert line.startswith("!") and not service.exists()


# ---------------------------------------------------------------- managed doctor: the guardian's OpenCode ports record


@posix_only
@pytest.mark.parametrize(
    ("code", "shown"),
    [
        ("opencode_port_record_unreadable", True),
        ("opencode_port_record_unchecked", True),
        ("opencode_port_account_unknown", True),
        ("other_warning", False),
        (None, False),
    ],
)
def test_managed_doctor_shows_the_opencode_ports_record_warning(monkeypatch, code, shown):
    """REVIEW-gx053-5 MF2: doctor on a managed host shows what status says, root or not."""
    from defenseclaw.commands import cmd_doctor

    warnings = [] if code is None else [{"code": code, "message": f"the record cannot be read; Remove it: sudo rm /x/{code}"}]
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout=json.dumps({"warnings": warnings}), stderr="")

    monkeypatch.setattr(cmd_doctor.subprocess, "run", run)
    problem, remedy = cmd_doctor._managed_opencode_port_record_problem()
    assert bool(problem) is shown
    assert calls and calls[0][-2:] == ["status", "--json"] and "enterprise" in calls[0]
    if shown:
        assert problem.startswith(code) and remedy == f"sudo rm /x/{code}"
