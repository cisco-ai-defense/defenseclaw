# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``defenseclaw sandbox legacy-cleanup``.

Every test builds a synthetic legacy host under a temporary directory and a
fake command runner, so nothing touches systemd, iptables, sysctl, ACLs, or
real users. The runner records each argv and emulates the side effects the
cleanup relies on (a removed file disappears, a deleted namespace is gone).

Ported Avarice regressions from the removed setup/init sandbox commands:

* F-0161 — the privileged chown targets the pinned home, never the
  attacker-writable ``$SANDBOX_HOME/.openclaw`` symlink target.
* F-0162 — a swapped symlink on a re-run is never trusted.
* F-0166 — ``route_localnet`` is restored to the saved value, never forced 0.
* F-0421 — the chown target is re-validated immediately before it runs.
* F-0425 — a symlinked ``openclaw.json`` is neither read nor written.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import stat
from dataclasses import dataclass, field
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the legacy sandbox was Linux-only")

from defenseclaw import sandbox_legacy as legacy  # noqa: E402

SANDBOX_UID = 1500
OPERATOR_UID = 1000
# The OpenClaw home's recorded owner. It is the test runner, which owns the
# temporary tree, so the parent-mode restore sees a directory the home's
# owner owns.
HOME_UID = os.getuid() if hasattr(os, "getuid") else OPERATOR_UID
NETNS = "openshell-sandbox-7f3a"
VETH = "veth-h-7f3a"
SUDO = "/usr/bin/sudo"


def tool(name: str) -> str:
    return f"/usr/bin/{name}"


def sudo(name: str, *args: str) -> tuple[str, ...]:
    return (SUDO, tool(name), *args)


# ---------------------------------------------------------------------------
# Synthetic host
# ---------------------------------------------------------------------------


@dataclass
class FakeHost:
    """Records argv and emulates the side effects cleanup depends on."""

    root: str
    route_localnet_path: str
    netns_dir: str
    group: list[str] = field(default_factory=lambda: ["alice"])
    sandbox_user: bool = True
    sandbox_processes: bool = False
    # /proc mounted with hidepid: only root sees the sandbox user's processes.
    proc_hidden: bool = False
    active_units: set[str] = field(default_factory=lambda: set(legacy.SYSTEMD_UNITS))
    live_pids: dict[int, str] = field(default_factory=dict)  # pid -> /proc/<pid>/cmdline
    acls: dict[str, set[int]] = field(default_factory=dict)  # path -> uids with named entries
    veth_up: bool = True
    veth_netns: str = NETNS
    iptables_present: dict[str, int] = field(default_factory=dict)
    binary_version: str = "openshell-sandbox 0.0.16"
    package_owner: str = ""
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def run(self, argv):
        argv = tuple(argv)
        self.calls.append(argv)
        args = list(argv[1:] if argv and argv[0] == SUDO else argv)
        name = os.path.basename(args[0]) if args else ""
        rest = args[1:]
        ok = legacy.CommandResult(0)
        # iproute2-6.1 formats: address lines carry the plain ifname; only
        # link lines carry "<name>@<peer>" and the peer's link-netns.
        if name == "ip" and rest[:4] == ["-o", "-4", "addr", "show"]:
            out = (
                f"5: {VETH}    inet 10.200.0.1/24 brd 10.200.0.255 scope global {VETH}\\"
                "       valid_lft forever preferred_lft forever\n"
                if self.veth_up else ""
            )
            return legacy.CommandResult(0, "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n" + out)
        if name == "ip" and rest[:5] == ["-o", "link", "show", "type", "veth"]:
            peer = f"link-netns {self.veth_netns}" if self.veth_netns else "link-netnsid 0"
            out = (
                f"5: {VETH}@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT "
                f"group default qlen 1000\\    link/ether 76:c7:10:c1:30:0b brd ff:ff:ff:ff:ff:ff {peer}\n"
                if self.veth_up else ""
            )
            return legacy.CommandResult(0, out)
        if name == "systemctl" and rest[:2] == ["is-active", "--quiet"]:
            return ok if rest[2] in self.active_units else legacy.CommandResult(3)
        if name == "systemctl" and rest[:2] == ["disable", "--now"]:
            self.active_units.difference_update(rest[2:])
            return ok
        if name == "getfacl":
            path = rest[-1]
            entries = "".join(f"user:{uid}:rwx\n" for uid in sorted(self.acls.get(path, ())))
            return legacy.CommandResult(0, f"# file: {path}\nuser::rwx\n{entries}group::r-x\nother::r-x\n")
        if name == "setfacl":
            recursive = "-R" in rest
            identifier, path = rest[rest.index("--") - 1], rest[-1]
            if not identifier[2:].isdigit():
                # setfacl 2.3 on a name that no longer resolves.
                return legacy.CommandResult(2, "", "Option -x: Invalid argument near character 3")
            for key in list(self.acls):
                if key == path or (recursive and key.startswith(path.rstrip("/") + "/")):
                    self.acls[key].discard(int(identifier[2:]))
            return ok
        if name == "ip" and rest[:3] == ["link", "show", "dev"]:
            return ok if self.veth_up else legacy.CommandResult(1)
        if name == "ip" and rest[:2] == ["link", "delete"]:
            self.veth_up = False
            return ok
        if name == "ip" and rest[:2] == ["netns", "delete"]:
            os.unlink(os.path.join(self.netns_dir, rest[2]))
            self.veth_up = False
            return ok
        if name == "test" and rest[0] == "-e":
            return ok if os.path.lexists(rest[1]) else legacy.CommandResult(1)
        if name == "test" and rest[0] == "-L":
            return ok if os.path.islink(rest[1]) else legacy.CommandResult(1)
        if name == "test" and rest[:2] == ["!", "-e"]:
            return ok if not os.path.exists(rest[2]) else legacy.CommandResult(1)
        if name == "iptables":
            op, key = rest[2], " ".join(rest[3:])
            present = self.iptables_present.get(key, 0)
            if op == "-C":
                return ok if present else legacy.CommandResult(1, "", "Bad rule")
            if op == "-D":
                self.iptables_present[key] = present - 1
                return ok
        if name == "sysctl":
            with open(self.route_localnet_path, "w") as fh:
                fh.write(rest[1].split("=", 1)[1] + "\n")
            return ok
        if name == "rm":
            path = rest[-1]
            if os.path.islink(path) or os.path.isfile(path):
                os.unlink(path)
            return ok
        if name == "gpasswd":
            self.group.remove(rest[1])
            return ok
        if name == "pgrep":
            visible = self.sandbox_processes and (argv[0] == SUDO or not self.proc_hidden)
            return legacy.CommandResult(0, "4242\n") if visible else legacy.CommandResult(1)
        if name == "userdel":
            self.sandbox_user = False
            return ok
        if name == "openshell-sandbox" or argv[0].endswith("/openshell-sandbox"):
            return legacy.CommandResult(0, self.binary_version + "\n")
        if name in ("dpkg", "rpm"):
            return legacy.CommandResult(0, f"{self.package_owner}: {rest[-1]}\n") if self.package_owner else legacy.CommandResult(1)
        return ok


class FakeConfig:
    """The slice of Config that cleanup reads and resets."""

    def __init__(self, data_dir: str, sandbox_home: str, pinned: str):
        self.data_dir = data_dir
        self.openshell = SimpleNamespace(mode="standalone", sandbox_home=sandbox_home)
        self.gateway = SimpleNamespace(host="10.200.0.2", port=18789, api_bind="")
        self.guardrail = SimpleNamespace(host="10.200.0.1")
        self.claw = SimpleNamespace(
            home_dir=os.path.join(sandbox_home, ".openclaw"),
            config_file=os.path.join(sandbox_home, ".openclaw", "openclaw.json"),
            openclaw_home_original=pinned,
        )
        self.saves = 0

    def save(self):
        self.saves += 1


def _write(path: str, content: str, mode: int = 0o644) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(path, mode)
    return path


UNIT_TEXT = {
    "openshell-sandbox.service": "[Unit]\nDescription=OpenShell Sandbox (DefenseClaw-managed)\n",
    "defenseclaw-sandbox.target": "[Unit]\nDescription=DefenseClaw Sandbox\nWants=openshell-sandbox.service\n",
}
LAUNCHER_TEXT = {
    "pre-sandbox.sh": '#!/bin/bash\nSANDBOX_HOME=/home/sandbox\nOC_LINK="$SANDBOX_HOME/.openclaw"\n',
    "start-sandbox.sh": '#!/bin/bash\nexec openshell-sandbox \\\n    --policy-rules "$POLICY_REGO"\n',
    "post-sandbox.sh": '#!/bin/bash\necho "Injected iptables rules via $NSENTER"\n',
    "cleanup-sandbox.sh": '#!/bin/bash\necho "Cleaned orphan namespace: $ns"\n',
}


@pytest.fixture
def host(tmp_path):
    """A complete synthetic legacy install."""
    root = str(tmp_path)
    data_dir = os.path.join(root, "operator", ".defenseclaw")
    oc_home = os.path.join(root, "data", "openclaw")
    sandbox_home = os.path.join(root, "home-sandbox")
    operator_home = os.path.join(root, "operator")
    os.makedirs(data_dir)
    os.makedirs(sandbox_home)
    unit_dir = os.path.join(root, "etc", "systemd", "system")
    launcher_dir = os.path.join(root, "usr", "local", "lib", "defenseclaw")
    for name, text in UNIT_TEXT.items():
        _write(os.path.join(unit_dir, name), text)
        _write(os.path.join(data_dir, "systemd", name), text)
    for name, text in LAUNCHER_TEXT.items():
        _write(os.path.join(launcher_dir, name), text, 0o755)
        _write(os.path.join(data_dir, "scripts", name), text, 0o755)
    _write(os.path.join(data_dir, "scripts", "run-sandbox.sh"), "#!/bin/bash\n", 0o755)
    binary = _write(os.path.join(root, "usr", "local", "bin", "openshell-sandbox"), "\x7fELF", 0o755)
    netns_dir = os.path.join(root, "run", "netns")
    _write(os.path.join(netns_dir, NETNS), "")
    route_localnet = _write(os.path.join(root, "proc", "route_localnet"), "1\n")
    _write(os.path.join(data_dir, "sandbox.netns"), NETNS + "\n")
    _write(os.path.join(data_dir, "saved.route_localnet"), "0\n")
    for rel in ("sandbox-resolv.conf", "openshell-policy.rego", "openshell-policy.yaml",
                "policies/defenseclaw-policy.yaml", "openshell.pid"):
        _write(os.path.join(data_dir, rel), "legacy\n")
    _write(
        os.path.join(oc_home, "openclaw.json"),
        json.dumps({
            "gateway": {"mode": "local", "port": 18789, "bind": "lan", "auth": {"token": "t"}},
            "models": {"providers": {"defenseclaw": {"baseUrl": "http://10.200.0.1:4000"}}},
        }),
        0o600,
    )
    # Legacy setup added o+x to an ancestor that was 0700.
    os.chmod(os.path.dirname(oc_home), 0o701)
    real_home = os.path.realpath(oc_home)
    _write(
        os.path.join(data_dir, legacy.OWNERSHIP_BACKUP_NAME),
        json.dumps({
            "openclaw_home": real_home,
            "original_uid": HOME_UID,
            "original_gid": HOME_UID,
            "original_mode": "0o755",
            "parents_modified": [{"path": os.path.dirname(real_home), "original_mode": "0o700"}],
        }),
    )
    os.symlink(real_home, os.path.join(sandbox_home, ".openclaw"))
    fake = FakeHost(root=root, route_localnet_path=route_localnet, netns_dir=netns_dir)
    fake.acls[real_home] = {SANDBOX_UID}
    for rule in legacy.iptables_rules("10.200.0.2", 18789):
        fake.iptables_present[" ".join(rule)] = 1
    system = legacy.System(
        runner=fake.run,
        resolve=tool,
        euid=lambda: OPERATOR_UID,
        trusted_uid=os.getuid(),
        unit_dir=unit_dir,
        launcher_dir=launcher_dir,
        binary_path=binary,
        netns_dir=netns_dir,
        route_localnet_path=route_localnet,
        host_os=lambda: "linux",
        invoking_user=lambda: "alice",
        lookup_user=lambda name: (
            SimpleNamespace(pw_uid=SANDBOX_UID, pw_dir=sandbox_home) if fake.sandbox_user else None
        ),
        uid_exists=lambda uid: uid != SANDBOX_UID or fake.sandbox_user,
        group_members=lambda name: list(fake.group),
        pid_alive=lambda pid: pid in fake.live_pids,
        pid_cmdline=lambda pid: fake.live_pids.get(pid),
        proc_hides_processes=lambda: fake.proc_hidden,
        home=lambda: operator_home,
        now=lambda: dt.datetime(2026, 9, 26, 12, 0, tzinfo=dt.timezone.utc),
        authenticate=lambda system: True,
    )
    cfg = FakeConfig(data_dir, sandbox_home, real_home)
    return SimpleNamespace(
        fake=fake, system=system, cfg=cfg, data_dir=data_dir, oc_home=real_home,
        sandbox_home=sandbox_home, unit_dir=unit_dir, launcher_dir=launcher_dir,
        binary=binary, root=root, operator_home=operator_home,
    )


def _plan(host, **kwargs):
    state = legacy.detect(host.cfg, system=host.system, probe_binary=kwargs.get("remove_binary", False))
    return state, legacy.plan(state, host.cfg, system=host.system, **kwargs)


def _apply(host, *, dry_run=False, yes=True, confirm=None, **kwargs):
    state, steps = _plan(host, **kwargs)
    lines: list[str] = []
    result = legacy.apply(
        steps, state, yes=yes, dry_run=dry_run, system=host.system, echo=lines.append, confirm=confirm,
    )
    return result, steps, lines


def _argvs(steps, step_id=None):
    return [cmd.argv for step in steps if step_id in (None, step.id) for cmd in step.commands]


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------


def test_full_plan_carries_exact_argv_in_order(host):
    _, steps = _plan(host)
    assert [step.id for step in steps] == [
        "units", "stopped", "network", "ownership", "openclaw_json", "group", "config", "artifacts",
    ]
    assert not any(step.blocked for step in steps)

    units = _argvs(steps, "units")
    assert units[0] == sudo("systemctl", "disable", "--now", "defenseclaw-sandbox.target", "openshell-sandbox.service")
    assert units[-1] == sudo("systemctl", "daemon-reload")
    removed = {argv[-1] for argv in units if argv[1] == tool("rm")}
    assert removed == {
        *(os.path.join(host.unit_dir, name) for name in UNIT_TEXT),
        *(os.path.join(host.launcher_dir, name) for name in LAUNCHER_TEXT),
    }

    network = next(step for step in steps if step.id == "network")
    netns = network.commands[0]
    assert netns.argv == sudo("ip", "netns", "delete", NETNS)
    assert netns.check == (tool("test"), "-e", os.path.join(host.fake.netns_dir, NETNS))
    veth = network.commands[1]
    assert veth.argv == sudo("ip", "link", "delete", VETH)
    rules = [cmd for cmd in network.commands if tool("iptables") in cmd.argv]
    assert [cmd.argv[4] for cmd in rules] == ["-D", "-D", "-D"]
    assert rules[0].argv == sudo(
        "iptables", "-t", "nat", "-D", "OUTPUT", "-d", "127.0.0.1", "-p", "tcp", "--dport", "18789",
        "-j", "DNAT", "--to-destination", "10.200.0.2:18789",
    )
    assert all(cmd.check[:5] == sudo("iptables", "-t", "nat", "-C") and cmd.run_when == "check-ok" for cmd in rules)
    assert network.commands[-1].argv == sudo("sysctl", "-w", "net.ipv4.conf.all.route_localnet=0")

    ownership = _argvs(steps, "ownership")
    chown = sudo("chown", "-hR", f"--from={SANDBOX_UID}", f"{HOME_UID}:{HOME_UID}", "--", host.oc_home)
    # The sandbox ACLs go before the chown hands the tree back.
    assert ownership[0] == sudo("setfacl", "-R", "-x", f"u:{SANDBOX_UID}", "--", host.oc_home)
    assert ownership.index(chown) > max(i for i, argv in enumerate(ownership) if argv[1] == tool("setfacl"))
    assert sudo("chmod", "700", "--", os.path.dirname(host.oc_home)) in ownership
    assert _argvs(steps, "group") == [sudo("gpasswd", "-d", "alice", "sandbox")]


def test_describe_prints_every_exact_command(host):
    _, steps = _plan(host)
    text = "\n".join(legacy.describe(steps))
    assert legacy.render_argv(
        sudo("systemctl", "disable", "--now", "defenseclaw-sandbox.target", "openshell-sandbox.service"),
    ) in text
    assert "(only if `/usr/bin/sudo /usr/bin/iptables -t nat -C OUTPUT" in text
    assert "update config.yaml (openshell.mode: 'standalone' -> ''" in text


def _clean_host(tmp_path):
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir)
    cfg = FakeConfig(data_dir, str(tmp_path / "no-sandbox"), "")
    cfg.openshell.mode = ""
    cfg.gateway.host = "127.0.0.1"
    cfg.guardrail.host = "localhost"
    cfg.claw.home_dir = "~/.openclaw"
    cfg.claw.config_file = "~/.openclaw/openclaw.json"
    fake = FakeHost(root=str(tmp_path), route_localnet_path=str(tmp_path / "rl"), netns_dir=str(tmp_path / "netns"))
    fake.veth_up = False
    fake.active_units.clear()
    system = legacy.System(
        runner=fake.run, resolve=tool, euid=lambda: OPERATOR_UID, trusted_uid=os.getuid(),
        unit_dir=str(tmp_path / "units"), launcher_dir=str(tmp_path / "lib"),
        binary_path=str(tmp_path / "bin" / "openshell-sandbox"), netns_dir=str(tmp_path / "netns"),
        route_localnet_path=str(tmp_path / "rl"), host_os=lambda: "linux", invoking_user=lambda: "alice",
        lookup_user=lambda name: None, group_members=lambda name: None, home=lambda: str(tmp_path),
        pid_alive=lambda pid: False, proc_hides_processes=lambda: fake.proc_hidden,
    )
    return cfg, fake, system


@pytest.mark.parametrize(
    "extra",
    [
        "nothing",
        # The previous release's ordinary Linux OpenClaw setup wrote this.
        "subprocess-policy",
        # Another product's veth on 10.200.0.0/24.
        "foreign-veth",
        # An unrelated `sandbox` account the operator belongs to, and a host
        # OpenClaw home: neither is proof of a legacy install.
        "sandbox-account",
    ],
)
def test_clean_host_plans_nothing_and_never_needs_sudo(tmp_path, extra):
    cfg, fake, system = _clean_host(tmp_path)
    if extra == "subprocess-policy":
        _write(os.path.join(cfg.data_dir, "policies", "defenseclaw-policy.yaml"), "version: 1\n")
    elif extra == "foreign-veth":
        fake.veth_up = True
        fake.veth_netns = "other-product"
    elif extra == "sandbox-account":
        home = tmp_path / "home-sandbox"
        os.makedirs(home)
        os.makedirs(tmp_path / ".openclaw")
        system.lookup_user = lambda name: SimpleNamespace(pw_uid=SANDBOX_UID, pw_dir=str(home))
        system.group_members = lambda name: ["alice"]
    state = legacy.detect(cfg, system=system)
    assert not state.has_system_evidence
    assert legacy.plan(state, cfg, system=system, remove_user=True) == []
    assert all(SUDO not in call for call in fake.calls)


# ---------------------------------------------------------------------------
# Apply, receipt, idempotency
# ---------------------------------------------------------------------------


def test_apply_runs_every_step_and_records_the_receipt(host):
    result, steps, _ = _apply(host)
    assert result.failed == []
    assert result.applied == [step.id for step in steps]

    for name in UNIT_TEXT:
        assert not os.path.exists(os.path.join(host.unit_dir, name))
    assert not os.path.exists(os.path.join(host.fake.netns_dir, NETNS))
    assert all(count == 0 for count in host.fake.iptables_present.values())
    with open(host.fake.route_localnet_path) as fh:
        assert fh.read().strip() == "0"
    assert not os.path.lexists(os.path.join(host.sandbox_home, ".openclaw"))
    assert host.fake.group == []

    with open(os.path.join(host.oc_home, "openclaw.json")) as fh:
        oc = json.load(fh)
    assert oc["gateway"] == {"mode": "local", "port": 18789, "bind": "loopback", "auth": {"token": "t"}}
    assert oc["models"]["providers"]["defenseclaw"]["baseUrl"] == "http://localhost:4000"

    assert host.cfg.saves == 1
    assert host.cfg.openshell.mode == ""
    assert (host.cfg.gateway.host, host.cfg.gateway.port) == ("127.0.0.1", 18789)
    assert host.cfg.guardrail.host == "localhost"
    assert host.cfg.claw.home_dir == host.oc_home
    assert host.cfg.claw.config_file == os.path.join(host.oc_home, "openclaw.json")
    assert host.cfg.claw.openclaw_home_original == ""

    backup_dir = os.path.join(host.data_dir, "backups", "legacy-sandbox-20260926T120000Z")
    for rel in ("systemd/openshell-sandbox.service", "scripts/run-sandbox.sh", "saved.route_localnet",
                "sandbox.netns", legacy.OWNERSHIP_BACKUP_NAME, "openshell.pid"):
        assert os.path.exists(os.path.join(backup_dir, rel)), rel
        assert not os.path.lexists(os.path.join(host.data_dir, rel)), rel
    assert not os.path.exists(os.path.join(host.data_dir, "systemd"))
    assert not os.path.exists(os.path.join(host.data_dir, "scripts"))

    with open(os.path.join(host.data_dir, legacy.RECEIPT_NAME)) as fh:
        receipt = json.load(fh)
    assert receipt["completed"] is True
    assert receipt["legacy_gateway"] == {"host": "10.200.0.2", "port": 18789}
    assert receipt["sandbox_uid"] == SANDBOX_UID
    assert {key: value["status"] for key, value in receipt["steps"].items()} == {
        step.id: "done" for step in steps
    }
    assert stat.S_IMODE(os.stat(os.path.join(host.data_dir, legacy.RECEIPT_NAME)).st_mode) == 0o600


def test_rerun_after_cleanup_is_a_no_op(host):
    _apply(host)
    calls_before = len(host.fake.calls)
    state, steps = _plan(host)
    assert steps == []
    assert all(SUDO not in call for call in host.fake.calls[calls_before:])
    assert state.receipt["completed"] is True


def test_partial_cleanup_skips_completed_steps(host):
    # A previous run already handled the NAT rules and recorded it; stale
    # evidence (the namespace) is gone too, so only what is left is planned.
    os.unlink(os.path.join(host.fake.netns_dir, NETNS))
    host.fake.veth_up = False
    with open(os.path.join(host.data_dir, legacy.RECEIPT_NAME), "w") as fh:
        json.dump({"version": 1, "steps": {"network": {"status": "done"}}}, fh)
    os.unlink(os.path.join(host.data_dir, "saved.route_localnet"))
    _, steps = _plan(host)
    assert "network" not in [step.id for step in steps]
    assert not [call for call in _argvs(steps) if tool("iptables") in call]
    assert "units" in [step.id for step in steps]


def test_recorded_gateway_survives_the_config_reset(host):
    host.cfg.gateway.port = 18800
    for rule in legacy.iptables_rules("10.200.0.2", 18800):
        host.fake.iptables_present[" ".join(rule)] = 1
    _apply(host)
    # The config now says 127.0.0.1:18789, but a later run still targets the
    # rules that were written for the recorded legacy gateway.
    state = legacy.detect(host.cfg, system=host.system)
    assert state.legacy_gateway == {"host": "10.200.0.2", "port": 18800}


def _snapshot(root: str) -> dict[str, tuple[int, int, int]]:
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            info = os.lstat(path)
            out[path] = (info.st_mode, info.st_size, info.st_mtime_ns)
    return out


def test_dry_run_prints_argv_and_changes_nothing(host):
    before = _snapshot(host.root)
    result, steps, lines = _apply(host, dry_run=True)
    assert result.dry_run and result.applied == []
    text = "\n".join(lines)
    for argv in _argvs(steps):
        assert legacy.render_argv(argv) in text
    assert "Dry run: nothing was changed." in text
    assert _snapshot(host.root) == before
    assert not os.path.exists(os.path.join(host.data_dir, legacy.RECEIPT_NAME))
    assert host.cfg.saves == 0
    assert all(SUDO not in call for call in host.fake.calls)


def test_declined_consent_changes_nothing(host):
    with pytest.raises(SystemExit):
        _apply(host, yes=False, confirm=lambda prompt: False)
    assert all(SUDO not in call for call in host.fake.calls)
    assert host.cfg.saves == 0


def test_sudo_is_validated_once_before_any_step(host):
    host.system.authenticate = lambda system: False
    with pytest.raises(Exception, match="sudo authentication failed"):
        _apply(host)
    assert all(SUDO not in call for call in host.fake.calls)
    assert not os.path.exists(os.path.join(host.data_dir, legacy.RECEIPT_NAME))


def test_blocked_steps_leave_the_receipt_unfinished(host):
    path = os.path.join(host.data_dir, legacy.OWNERSHIP_BACKUP_NAME)
    with open(path) as fh:
        backup = json.load(fh)
    backup["original_uid"] = "not-a-number"
    with open(path, "w") as fh:
        json.dump(backup, fh)
    result, _, _ = _apply(host)
    assert "ownership" in result.skipped and result.failed == []
    with open(os.path.join(host.data_dir, legacy.RECEIPT_NAME)) as fh:
        assert json.load(fh)["completed"] is False
    from defenseclaw.sandbox_legacy import quick_evidence

    assert "an unfinished legacy-cleanup receipt" in quick_evidence(host.cfg)


def test_failed_units_step_stops_before_later_steps(host):
    runner = host.fake.run

    def failing(argv):
        if tool("systemctl") in argv and "disable" in argv:
            host.fake.calls.append(tuple(argv))
            return legacy.CommandResult(1, "", "Access denied")
        return runner(argv)

    host.system.runner = failing
    result, _, lines = _apply(host)
    assert result.failed == ["units"] and result.applied == []
    assert host.cfg.saves == 0
    assert any("Access denied" in line for line in lines)


# ---------------------------------------------------------------------------
# Units and launchers
# ---------------------------------------------------------------------------


def test_unit_without_marker_is_left_and_not_disabled(host):
    _write(os.path.join(host.unit_dir, "openshell-sandbox.service"), "[Unit]\nDescription=Someone else\n")
    _, steps = _plan(host)
    units = next(step for step in steps if step.id == "units")
    assert units.commands[0].argv == sudo("systemctl", "disable", "--now", "defenseclaw-sandbox.target")
    assert sudo("rm", "-f", "--", os.path.join(host.unit_dir, "openshell-sandbox.service")) not in _argvs(steps)
    assert any("not DefenseClaw-generated" in note for note in units.notes)


@pytest.mark.parametrize(
    "tamper, reason",
    [("group-writable", "group/other writable"), ("symlink", "not a regular file"), ("foreign", "not root")],
)
def test_tampered_launcher_is_refused(host, tamper, reason):
    path = os.path.join(host.launcher_dir, "pre-sandbox.sh")
    if tamper == "group-writable":
        os.chmod(path, 0o775)
    elif tamper == "symlink":
        os.unlink(path)
        os.symlink(os.path.join(host.root, "elsewhere"), path)
    else:
        host.system.trusted_uid = os.getuid() + 1
    _, steps = _plan(host)
    assert sudo("rm", "-f", "--", path) not in _argvs(steps)
    units = next(step for step in steps if step.id == "units")
    assert any(path in note and reason in note for note in units.notes + [units.blocked])


# ---------------------------------------------------------------------------
# Nothing after the units step runs under a live legacy sandbox
# ---------------------------------------------------------------------------


def _non_systemd_host(host):
    """A container or WSL host: run-sandbox.sh started everything, no units."""
    import shutil

    shutil.rmtree(host.unit_dir)
    shutil.rmtree(host.launcher_dir)
    host.fake.active_units.clear()


def _receipt(host):
    with open(os.path.join(host.data_dir, legacy.RECEIPT_NAME)) as fh:
        return json.load(fh)


def test_live_run_sandbox_launcher_stops_cleanup_before_any_host_change(host):
    _non_systemd_host(host)
    _write(os.path.join(host.data_dir, "sandbox.pids"), "4242 openshell-sandbox\n4243 defenseclaw-gateway\n")
    host.fake.live_pids = {4242: "openshell-sandbox --policy-rules /x", 4243: "/usr/local/bin/defenseclaw-gateway"}
    result, steps, lines = _apply(host)
    assert steps[0].id == "stopped"
    assert result.failed == ["stopped"] and result.applied == []
    # Nothing privileged ran: no chown, ACL, NAT, or namespace change.
    assert not [call for call in host.fake.calls if call and call[0] == SUDO]
    text = "\n".join(lines)
    assert "PID 4242 (openshell-sandbox) from sandbox.pids is running" in text
    assert "PID 4243 (defenseclaw-gateway) from sandbox.pids is running" in text
    assert "run-sandbox.sh stop" in text
    # The stop path and its PID file stay where the operator expects them.
    for rel in ("sandbox.pids", "scripts/run-sandbox.sh", legacy.OWNERSHIP_BACKUP_NAME):
        assert os.path.exists(os.path.join(host.data_dir, rel)), rel
    assert host.cfg.saves == 0
    receipt = _receipt(host)
    assert "ownership" not in receipt["steps"] and receipt["completed"] is False


@pytest.mark.parametrize("cmdline", ["/usr/sbin/sshd -D", ""])
def test_recorded_pid_reused_or_gone_does_not_block(host, cmdline):
    _non_systemd_host(host)
    _write(os.path.join(host.data_dir, "sandbox.pids"), "4242 openshell-sandbox\n")
    _write(os.path.join(host.data_dir, "openshell.pid"), "4244\n")
    # 4242 now belongs to an unrelated process (or is a zombie); 4244 is gone.
    host.fake.live_pids = {4242: cmdline}
    result, _, _ = _apply(host)
    assert result.failed == [] and "stopped" in result.applied
    assert not os.path.exists(os.path.join(host.data_dir, "sandbox.pids"))


def test_recorded_pid_with_an_unreadable_cmdline_counts_as_running(host):
    _write(os.path.join(host.data_dir, "openshell.pid"), "4244\n")
    host.fake.live_pids = {4244: None}
    result, _, lines = _apply(host)
    assert result.failed == ["stopped"]
    assert any("PID 4244 (openshell-sandbox) from openshell.pid is running" in line for line in lines)


def test_sandbox_processes_stop_cleanup_after_the_units(host):
    host.fake.sandbox_processes = True
    result, _, lines = _apply(host)
    assert result.applied == ["units"] and result.failed == ["stopped"]
    assert any(f"uid {SANDBOX_UID} still runs" in line for line in lines)
    assert not [call for call in host.fake.calls if tool("chown") in call or tool("setfacl") in call]
    assert host.cfg.saves == 0


def test_hidepid_proc_looks_for_sandbox_processes_as_root(host):
    # Under hidepid an unprivileged pgrep exits 1 ("no process") while the
    # sandbox user still runs some; only root's pgrep sees them.
    host.fake.proc_hidden = True
    host.fake.sandbox_processes = True
    _, steps = _plan(host, remove_user=True)
    stopped = next(step for step in steps if step.id == "stopped")
    assert stopped.actions[0].privileged
    assert f"`sudo pgrep -u {SANDBOX_UID}` finds no process" in stopped.actions[0].description
    user = next(step for step in steps if step.id == "user")
    assert user.commands[0].check == sudo("pgrep", "-u", str(SANDBOX_UID))

    result, _, lines = _apply(host, remove_user=True)
    assert result.applied == ["units"] and result.failed == ["stopped"]
    assert any(f"uid {SANDBOX_UID} still runs PID 4242" in line for line in lines)
    assert sudo("pgrep", "-u", str(SANDBOX_UID)) in host.fake.calls
    assert (tool("pgrep"), "-u", str(SANDBOX_UID)) not in host.fake.calls
    assert host.fake.sandbox_user is True and host.cfg.saves == 0


def test_hidepid_probe_as_root_is_skipped_for_root_and_without_hidepid(host):
    host.fake.proc_hidden = False
    assert legacy._uid_process_probe(host.system, SANDBOX_UID) == (tool("pgrep"), "-u", str(SANDBOX_UID))
    host.fake.proc_hidden = True
    assert legacy._uid_process_probe(host.system, SANDBOX_UID) == sudo("pgrep", "-u", str(SANDBOX_UID))
    host.system.euid = lambda: 0
    assert legacy._uid_process_probe(host.system, SANDBOX_UID) == (tool("pgrep"), "-u", str(SANDBOX_UID))
    # Without a trusted sudo the uid cannot be checked, which counts as running.
    host.system.euid = lambda: OPERATOR_UID
    host.system.resolve = lambda name: None if name == "sudo" else tool(name)
    result, _, lines = _apply(host)
    assert result.failed == ["stopped"]
    assert any(f"cannot check for processes of uid {SANDBOX_UID}" in line for line in lines)


def test_privileged_probe_action_authenticates_sudo_first(host):
    state = legacy.detect(host.cfg, system=host.system)
    ran: list[str] = []

    def probe() -> str:
        ran.append("probe")
        return "ok"

    host.system.authenticate = lambda system: False
    unprivileged = [legacy.Step("stopped", "check", actions=[legacy.Action("probe", probe)])]
    legacy.apply(unprivileged, state, yes=True, dry_run=False, system=host.system, echo=lambda line: None)
    assert ran == ["probe"]
    privileged = [legacy.Step("stopped", "check", actions=[legacy.Action("probe", probe, privileged=True)])]
    with pytest.raises(Exception, match="sudo authentication failed"):
        legacy.apply(privileged, state, yes=True, dry_run=False, system=host.system, echo=lambda line: None)
    assert ran == ["probe"]


@pytest.mark.parametrize(
    ("mounts", "hidden"),
    [
        ("proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n", False),
        ("proc /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=2 0 0\n", True),
        ("proc /proc proc rw,relatime,hidepid=invisible 0 0\n", True),
        ("proc /proc proc rw,relatime,hidepid=noaccess,gid=27 0 0\n", True),
        ("proc /proc proc rw,relatime,hidepid=ptraceable 0 0\n", True),
        ("proc /proc proc rw,relatime,hidepid=0 0 0\n", False),
        ("proc /proc proc rw,relatime,hidepid=off 0 0\n", False),
        # A container's second proc mount elsewhere does not count; the last
        # /proc mount is the one in effect.
        ("proc /proc proc rw,hidepid=2 0 0\nproc /srv/proc proc rw 0 0\n", True),
        ("proc /proc proc rw,hidepid=2 0 0\nproc /proc proc rw 0 0\n", False),
        ("/dev/sda1 / ext4 rw 0 0\n", False),
    ],
)
def test_proc_hides_processes_reads_the_proc_mount(tmp_path, mounts, hidden):
    path = tmp_path / "mounts"
    path.write_text(mounts)
    assert legacy._proc_hides_processes(str(path)) is hidden


def test_proc_hides_processes_without_a_mount_table(tmp_path):
    assert legacy._proc_hides_processes(str(tmp_path / "missing")) is False


def test_foreign_unit_left_running_stops_cleanup(host):
    # The units step leaves a unit it did not generate alone, so it may still run.
    _write(os.path.join(host.unit_dir, "openshell-sandbox.service"), "[Unit]\nDescription=Someone else\n")
    result, _, lines = _apply(host)
    assert result.failed == ["stopped"]
    assert any("openshell-sandbox.service is active" in line for line in lines)
    assert host.cfg.saves == 0


def test_blocked_units_step_stops_cleanup(host):
    host.system.resolve = lambda name: None if name == "systemctl" else tool(name)
    result, steps, lines = _apply(host)
    assert next(step for step in steps if step.id == "units").blocked
    assert result.failed == ["stopped"]
    assert any("cannot check defenseclaw-sandbox.target" in line for line in lines)
    assert not [call for call in host.fake.calls if tool("chown") in call]


def test_stopped_check_is_planned_only_when_later_steps_exist(host):
    _, steps = _plan(host)
    stopped = next(step for step in steps if step.id == "stopped")
    assert not stopped.commands
    assert f"`pgrep -u {SANDBOX_UID}` finds no process" in stopped.actions[0].description
    _apply(host)
    assert legacy.plan(legacy.detect(host.cfg, system=host.system), host.cfg, system=host.system) == []


# ---------------------------------------------------------------------------
# Network: namespace, veth, iptables -C, route_localnet (F-0166)
# ---------------------------------------------------------------------------


def test_iptables_delete_runs_only_while_check_matches():
    calls = []
    remaining = {"n": 2}

    def runner(argv):
        calls.append(argv)
        if "-C" in argv:
            return legacy.CommandResult(0 if remaining["n"] else 1)
        remaining["n"] -= 1
        return legacy.CommandResult(0)

    system = legacy.System(runner=runner, resolve=tool, euid=lambda: 0)
    command = legacy.Command(
        ("iptables", "-t", "nat", "-D", "POSTROUTING"), check=("iptables", "-t", "nat", "-C", "POSTROUTING"),
        run_when="check-ok", repeat=8,
    )
    assert legacy._run_command(command, system) == (True, "ran")
    assert [argv[3] for argv in calls] == ["-C", "-D", "-C", "-D", "-C"]

    calls.clear()
    assert legacy._run_command(command, system) == (True, "already clean")
    assert [argv[3] for argv in calls] == ["-C"]


def test_namespace_already_removed_by_the_unit_stop_is_skipped(host):
    state, steps = _plan(host)
    os.unlink(os.path.join(host.fake.netns_dir, NETNS))
    network = next(step for step in steps if step.id == "network")
    ok, detail = legacy._run_command(network.commands[0], host.system)
    assert ok and detail == "already clean"
    assert sudo("ip", "netns", "delete", NETNS) not in host.fake.calls


def test_malformed_recorded_namespace_is_ignored(host):
    _write(os.path.join(host.data_dir, "sandbox.netns"), "../../etc\n")
    state, steps = _plan(host)
    assert state.netns == ""
    assert not [argv for argv in _argvs(steps) if "netns" in argv]
    assert "malformed" in state.netns_note


def test_veth_is_deleted_only_when_its_peer_is_in_the_recorded_namespace(host):
    state, steps = _plan(host)
    assert state.veths == [VETH]
    assert sudo("ip", "link", "delete", VETH) in _argvs(steps, "network")

    for peer in ("someone-elses-ns", ""):
        host.fake.veth_netns = peer  # "" prints link-netnsid: a namespace with no name
        state, steps = _plan(host)
        assert state.veths == []
        assert sudo("ip", "link", "delete", VETH) not in _argvs(steps)
        network = next(step for step in steps if step.id == "network")
        assert any(f"veth {VETH} carries 10.200.0.1" in note for note in network.notes)


def test_address_holder_that_is_not_a_veth_is_ignored(host):
    host.fake.veth_up = True
    runner = host.fake.run

    def no_veths(argv):
        if list(argv[-4:]) == ["link", "show", "type", "veth"]:
            return legacy.CommandResult(0, "")
        return runner(argv)

    host.system.runner = no_veths
    state, steps = _plan(host)
    assert state.veths == [] and state.veth_notes == []
    assert not [argv for argv in _argvs(steps) if "link" in argv and "delete" in argv]


def test_f0166_restores_saved_route_localnet_not_zero(host):
    _write(os.path.join(host.data_dir, "saved.route_localnet"), "1\n")
    _write(host.fake.route_localnet_path, "1\n")
    _, steps = _plan(host)
    assert not [argv for argv in _argvs(steps) if tool("sysctl") in argv]

    _write(host.fake.route_localnet_path, "0\n")
    _, steps = _plan(host)
    assert sudo("sysctl", "-w", "net.ipv4.conf.all.route_localnet=1") in _argvs(steps)
    assert sudo("sysctl", "-w", "net.ipv4.conf.all.route_localnet=0") not in _argvs(steps)


def test_f0166_missing_saved_value_leaves_sysctl_alone(host):
    os.unlink(os.path.join(host.data_dir, "saved.route_localnet"))
    _, steps = _plan(host)
    assert not [argv for argv in _argvs(steps) if tool("sysctl") in argv]
    network = next(step for step in steps if step.id == "network")
    assert any("no saved net.ipv4.conf.all.route_localnet value" in note for note in network.notes)


# ---------------------------------------------------------------------------
# Ownership, ACLs, symlink (F-0161, F-0162, F-0421)
# ---------------------------------------------------------------------------


def test_acls_are_removed_from_the_home_and_every_ancestor(host):
    _, steps = _plan(host)
    ownership = _argvs(steps, "ownership")
    identifier = f"u:{SANDBOX_UID}"
    assert sudo("setfacl", "-R", "-x", identifier, "--", host.oc_home) in ownership
    assert sudo("setfacl", "-R", "-d", "-x", identifier, "--", host.oc_home) in ownership
    ancestors = [argv[-1] for argv in ownership if argv[2:4] == ("-x", identifier)]
    assert ancestors == legacy._ancestors(host.oc_home)
    assert ancestors[-1] == "/"


def test_missing_setfacl_skips_acl_removal_with_a_note(host):
    host.system.resolve = lambda name: None if name == "setfacl" else tool(name)
    _, steps = _plan(host)
    ownership = next(step for step in steps if step.id == "ownership")
    assert not [argv for argv in ownership.commands if tool("setfacl") in argv.argv]
    assert any("setfacl is not installed" in note for note in ownership.notes)


def test_f0161_privileged_commands_never_follow_a_swapped_symlink(host, tmp_path):
    evil = str(tmp_path / "evil")
    os.makedirs(evil)
    link = os.path.join(host.sandbox_home, ".openclaw")
    os.unlink(link)
    os.symlink(evil, link)
    result, steps, _ = _apply(host)
    assert result.failed == []
    privileged = [call for call in host.fake.calls if call and call[0] == SUDO]
    assert not [call for call in privileged if any(evil in part for part in call)]
    assert sudo("rm", "-f", "--", link) in privileged
    assert os.path.isdir(evil)


def test_f0162_rerun_with_a_swapped_symlink_trusts_nothing_new(host, tmp_path):
    _apply(host)
    evil = str(tmp_path / "evil")
    os.makedirs(evil)
    os.symlink(evil, os.path.join(host.sandbox_home, ".openclaw"))
    calls_before = len(host.fake.calls)
    _apply(host)
    new_calls = host.fake.calls[calls_before:]
    assert not [call for call in new_calls if tool("chown") in call or tool("setfacl") in call]
    assert not [call for call in new_calls if any(evil in part for part in call)]


def test_f0421_home_swapped_after_planning_is_refused(host, tmp_path):
    state, steps = _plan(host)
    evil = str(tmp_path / "evil")
    os.makedirs(evil)
    moved = host.oc_home + ".real"
    os.rename(host.oc_home, moved)
    os.symlink(evil, host.oc_home)
    lines: list[str] = []
    result = legacy.apply(steps, state, yes=True, dry_run=False, system=host.system, echo=lines.append)
    assert "ownership" in result.failed
    assert not [call for call in host.fake.calls if tool("chown") in call]
    assert any("no longer a real directory" in line for line in lines)


@pytest.mark.parametrize(
    "backup_patch, message",
    [
        ({"openclaw_home": "EVIL"}, "refusing a possibly tampered backup"),
        ({"original_uid": "0"}, "non-integer uid/gid"),
        ({"original_uid": True}, "non-integer uid/gid"),
        ({"original_gid": -1}, "negative uid/gid"),
        ({"original_uid": SANDBOX_UID}, "names the sandbox user"),
    ],
)
def test_tampered_ownership_backup_is_refused(host, tmp_path, backup_patch, message):
    path = os.path.join(host.data_dir, legacy.OWNERSHIP_BACKUP_NAME)
    with open(path) as fh:
        backup = json.load(fh)
    if backup_patch.get("openclaw_home") == "EVIL":
        evil = str(tmp_path / "evil")
        os.makedirs(evil)
        backup_patch = {"openclaw_home": evil}
    backup.update(backup_patch)
    with open(path, "w") as fh:
        json.dump(backup, fh)
    result, steps, _ = _apply(host)
    ownership = next(step for step in steps if step.id == "ownership")
    assert message in ownership.blocked
    assert not [call for call in host.fake.calls if tool("chown") in call or tool("setfacl") in call]
    # The backup is evidence: keep it so the operator can fix it and re-run.
    assert os.path.exists(path)
    assert "ownership" in result.skipped


@pytest.mark.parametrize("home", ["/etc", "/home/alice", "/root/.openclaw", "/usr/local"])
def test_system_paths_never_receive_a_recursive_chown(home):
    assert legacy.validate_restore_home(home)


def test_dangling_sandbox_symlink_to_data_openclaw(host):
    # The test host's state: /home/sandbox/.openclaw -> /data/openclaw, which
    # no longer exists. Nothing is chowned; the dangling link and the ACLs on
    # surviving ancestors are still removed.
    import shutil

    shutil.rmtree(host.oc_home)
    _, steps = _plan(host)
    ownership = _argvs(steps, "ownership")
    assert not [argv for argv in ownership if tool("chown") in argv]
    assert sudo("rm", "-f", "--", os.path.join(host.sandbox_home, ".openclaw")) in ownership
    assert sudo("setfacl", "-x", f"u:{SANDBOX_UID}", "--", os.path.dirname(host.oc_home)) in ownership
    assert "openclaw_json" not in [step.id for step in steps]
    result, _, _ = _apply(host)
    assert result.failed == []
    assert not os.path.lexists(os.path.join(host.sandbox_home, ".openclaw"))
    assert host.cfg.claw.home_dir == host.oc_home


def test_home_dir_resets_to_tilde_when_it_resolves_to_the_pinned_home(host):
    os.makedirs(host.operator_home, exist_ok=True)
    os.symlink(host.oc_home, os.path.join(host.operator_home, ".openclaw"))
    _, steps = _plan(host)
    config = next(step for step in steps if step.id == "config")
    assert "claw.home_dir" in config.actions[0].description
    _apply(host)
    assert host.cfg.claw.home_dir == "~/.openclaw"
    assert host.cfg.claw.config_file == "~/.openclaw/openclaw.json"


def _after_old_disable(host):
    """What the removed `sandbox setup --disable` left: units, ACLs, the sandbox user."""
    os.unlink(os.path.join(host.data_dir, legacy.OWNERSHIP_BACKUP_NAME))
    os.unlink(os.path.join(host.sandbox_home, ".openclaw"))
    host.cfg.openshell.mode = ""
    host.cfg.gateway.host = "127.0.0.1"
    host.cfg.guardrail.host = "localhost"
    host.cfg.claw.home_dir = "~/.openclaw"
    host.cfg.claw.config_file = "~/.openclaw/openclaw.json"
    host.cfg.claw.openclaw_home_original = ""
    os.makedirs(host.operator_home, exist_ok=True)
    os.symlink(host.oc_home, os.path.join(host.operator_home, ".openclaw"))


def test_acls_the_old_disable_left_are_removed_before_the_user(host):
    _after_old_disable(host)
    state, steps = _plan(host, remove_user=True)
    assert (state.openclaw_home, state.openclaw_home_source) == (host.oc_home, "fallback")
    ownership = _argvs(steps, "ownership")
    assert sudo("setfacl", "-R", "-x", f"u:{SANDBOX_UID}", "--", host.oc_home) in ownership
    assert sudo("setfacl", "-R", "-d", "-x", f"u:{SANDBOX_UID}", "--", host.oc_home) in ownership
    assert sudo("setfacl", "-x", f"u:{SANDBOX_UID}", "--", os.path.dirname(host.oc_home)) in ownership
    # Nothing to chown (the old --disable did), and openclaw.json is left alone.
    assert not [argv for argv in ownership if argv[1] == tool("chown")]
    assert "openclaw_json" not in [step.id for step in steps]

    result, _, _ = _apply(host, remove_user=True)
    assert result.failed == []
    assert host.fake.acls[host.oc_home] == set()
    acl_removed = host.fake.calls.index(sudo("setfacl", "-R", "-x", f"u:{SANDBOX_UID}", "--", host.oc_home))
    assert acl_removed < host.fake.calls.index(sudo("userdel", "-r", "sandbox"))


def test_home_fallback_needs_legacy_evidence(host):
    _after_old_disable(host)
    import shutil

    shutil.rmtree(host.unit_dir)
    shutil.rmtree(host.launcher_dir)
    shutil.rmtree(os.path.join(host.data_dir, "systemd"))
    shutil.rmtree(os.path.join(host.data_dir, "scripts"))
    for rel in legacy.DATA_DIR_ARTIFACTS:
        if os.path.lexists(os.path.join(host.data_dir, rel)):
            os.unlink(os.path.join(host.data_dir, rel))
    os.unlink(os.path.join(host.fake.netns_dir, NETNS))
    host.fake.veth_up = False
    state, steps = _plan(host)
    assert not state.has_system_evidence and state.openclaw_home == ""
    assert not [argv for argv in _argvs(steps) if tool("setfacl") in argv]


def test_refused_backup_keeps_the_pin_so_a_rerun_still_refuses(host, tmp_path):
    victim = str(tmp_path / "srv" / "victim")
    os.makedirs(victim)
    path = os.path.join(host.data_dir, legacy.OWNERSHIP_BACKUP_NAME)
    with open(path) as fh:
        backup = json.load(fh)
    backup["openclaw_home"] = victim
    with open(path, "w") as fh:
        json.dump(backup, fh)
    for _ in range(2):
        result, steps, _ = _apply(host)
        ownership = next(step for step in steps if step.id == "ownership")
        assert "refusing a possibly tampered backup" in ownership.blocked
        assert {"ownership", "config"} <= set(result.skipped)
        # The pin that exposed the mismatch survives the run.
        assert host.cfg.claw.openclaw_home_original == host.oc_home
        assert host.cfg.saves == 0
        assert os.path.exists(path)
    assert not [call for call in host.fake.calls if any(victim in part for part in call)]


def test_recorded_home_keeps_refusing_a_rewritten_backup_after_the_pin_is_gone(host, tmp_path):
    runner = host.fake.run

    def acl_fails(argv):
        if tool("setfacl") in argv:
            host.fake.calls.append(tuple(argv))
            return legacy.CommandResult(1, "", "Operation not supported")
        return runner(argv)

    host.system.runner = acl_fails
    result, _, _ = _apply(host)
    assert "ownership" in result.failed and "config" in result.failed
    assert host.cfg.claw.openclaw_home_original == host.oc_home
    assert _receipt(host)["openclaw_home"] == host.oc_home

    # Something rewrites the backup and clears the pin between runs.
    victim = str(tmp_path / "srv" / "victim")
    os.makedirs(victim)
    path = os.path.join(host.data_dir, legacy.OWNERSHIP_BACKUP_NAME)
    with open(path) as fh:
        backup = json.load(fh)
    backup["openclaw_home"] = victim
    with open(path, "w") as fh:
        json.dump(backup, fh)
    host.cfg.claw.openclaw_home_original = ""
    host.system.runner = runner
    state, steps = _plan(host)
    assert "recorded by an earlier cleanup run" in state.ownership_error
    assert not [argv for argv in _argvs(steps) if any(victim in part for part in argv)]


def _rewrite_backup_parents(host, parents, **extra):
    path = os.path.join(host.data_dir, legacy.OWNERSHIP_BACKUP_NAME)
    with open(path) as fh:
        backup = json.load(fh)
    backup["parents_modified"] = parents
    backup.update(extra)
    with open(path, "w") as fh:
        json.dump(backup, fh)


@pytest.mark.parametrize(
    "entry, extra, reason",
    [
        ({"path": "/", "original_mode": "0o700"}, {}, "it is a system directory"),
        # Legacy setup only ever added o+x; this would take away more.
        ({"path": "PARENT", "original_mode": "0o600"}, {}, "not the current mode with only o+x cleared"),
        ({"path": "PARENT", "original_mode": "0o000"}, {}, "not the current mode with only o+x cleared"),
        ({"path": "PARENT", "original_mode": "0o700"}, {"original_uid": HOME_UID + 1}, "not by the OpenClaw home's owner"),
    ],
)
def test_parent_mode_restore_only_clears_the_o_x_legacy_added(host, entry, extra, reason):
    parent = os.path.dirname(host.oc_home)
    entry = dict(entry, path=parent if entry["path"] == "PARENT" else entry["path"])
    _rewrite_backup_parents(host, [entry], **extra)
    _, steps = _plan(host)
    assert not [argv for argv in _argvs(steps) if argv[1] == tool("chmod")]
    ownership = next(step for step in steps if step.id == "ownership")
    assert any(note.startswith(f"left {entry['path']} at mode") and reason in note for note in ownership.notes)


def test_deleted_sandbox_user_uid_is_recovered_from_its_acls(host):
    host.fake.sandbox_user = False
    state, steps = _plan(host)
    assert state.sandbox_uid == SANDBOX_UID
    ownership = _argvs(steps, "ownership")
    assert sudo("setfacl", "-R", "-x", f"u:{SANDBOX_UID}", "--", host.oc_home) in ownership
    assert [argv[:4] for argv in ownership if argv[1] == tool("chown")] == [
        sudo("chown", "-hR", f"--from={SANDBOX_UID}"),
    ]
    assert not [argv for argv in _argvs(steps) if f"u:{legacy.SANDBOX_USER}" in argv]
    result, _, _ = _apply(host)
    assert result.failed == []
    assert _receipt(host)["sandbox_uid"] == SANDBOX_UID and _receipt(host)["completed"] is True


def test_unrecoverable_sandbox_uid_never_uses_the_bare_name(host):
    host.fake.sandbox_user = False
    host.fake.acls.clear()
    state, steps = _plan(host)
    assert state.sandbox_uid is None
    assert not [argv for argv in _argvs(steps) if any(part.startswith("u:") for part in argv)]
    ownership = next(step for step in steps if step.id == "ownership")
    assert any("its uid is unknown" in note for note in ownership.notes)
    result, _, _ = _apply(host)
    assert result.failed == []


# ---------------------------------------------------------------------------
# openclaw.json (F-0425)
# ---------------------------------------------------------------------------


def test_f0425_symlinked_openclaw_json_is_refused(tmp_path):
    secret = tmp_path / "secret.json"
    secret.write_text('{"private": "do-not-touch"}')
    config = tmp_path / "openclaw.json"
    os.symlink(secret, config)
    with pytest.raises(RuntimeError, match="refusing to read"):
        legacy.restore_openclaw_gateway(str(config))
    assert secret.read_text() == '{"private": "do-not-touch"}'
    assert os.path.islink(config)


def test_f0425_regular_openclaw_json_is_restored_in_place(tmp_path):
    config = tmp_path / "openclaw.json"
    config.write_text(json.dumps({
        "gateway": {"mode": "local", "port": 1234, "bind": "lan"},
        "models": {"providers": {"defenseclaw": {"baseUrl": "http://proxy.internal:4000"}}},
    }))
    os.chmod(config, 0o640)
    assert legacy.restore_openclaw_gateway(str(config)) == "gateway settings restored"
    data = json.loads(config.read_text())
    assert data["gateway"] == {"mode": "local", "port": 18789, "bind": "loopback"}
    # Only a baseUrl that pointed at the legacy veth host is rewritten.
    assert data["models"]["providers"]["defenseclaw"]["baseUrl"] == "http://proxy.internal:4000"
    assert stat.S_IMODE(os.stat(config).st_mode) == 0o640
    assert legacy.restore_openclaw_gateway(str(config)) == "already in host mode"
    assert legacy.restore_openclaw_gateway(str(tmp_path / "missing.json")) == "no openclaw.json to restore"


def test_openclaw_json_with_comments_and_trailing_commas_is_restored(tmp_path):
    config = tmp_path / "openclaw.json"
    config.write_text('// managed by hand\n{"gateway": {"bind": "lan", "port": 18789, /* sandbox */},}\n')
    assert legacy.restore_openclaw_gateway(str(config)) == "gateway settings restored"
    assert json.loads(config.read_text())["gateway"] == {"bind": "loopback", "port": 18789, "mode": "local"}


def test_failed_openclaw_json_rewrite_is_retried_on_the_next_run(host):
    config = os.path.join(host.oc_home, "openclaw.json")
    with open(config) as fh:
        good = fh.read()
    _write(config, "{ not json", 0o600)
    result, _, _ = _apply(host)
    assert "openclaw_json" in result.failed and "config" in result.failed
    # The home stays findable: the pin and the backup are kept for the retry.
    assert host.cfg.claw.openclaw_home_original == host.oc_home
    assert os.path.exists(os.path.join(host.data_dir, legacy.OWNERSHIP_BACKUP_NAME))

    _write(config, good, 0o600)
    result, steps, _ = _apply(host)
    assert "openclaw_json" in [step.id for step in steps]
    assert result.failed == []
    with open(config) as fh:
        assert json.load(fh)["gateway"]["bind"] == "loopback"
    assert host.cfg.claw.openclaw_home_original == ""
    assert _receipt(host)["completed"] is True
    assert "an unfinished legacy-cleanup receipt" not in legacy.quick_evidence(host.cfg)


# ---------------------------------------------------------------------------
# Opt-in: sandbox user and legacy binary
# ---------------------------------------------------------------------------


def test_remove_user_is_opt_in_and_refused_while_processes_run(host):
    _, steps = _plan(host)
    assert "user" not in [step.id for step in steps]
    assert any("--remove-user" in hint for hint in legacy.hints(
        legacy.detect(host.cfg, system=host.system), remove_user=False, remove_binary=False,
    ))

    host.fake.sandbox_processes = True
    result, steps, lines = _apply(host, remove_user=True)
    user = next(step for step in steps if step.id == "user")
    assert user.commands[0].argv == sudo("userdel", "-r", "sandbox")
    assert user.commands[0].check == (tool("pgrep"), "-u", str(SANDBOX_UID))
    # A live sandbox process already stops the run at the stopped check.
    assert result.failed == ["stopped"] and result.applied == ["units"]
    assert host.fake.sandbox_user is True
    assert not [call for call in host.fake.calls if tool("userdel") in call]

    # The userdel gate still holds on its own.
    ok, detail = legacy._run_command(
        legacy.Command(user.commands[0].argv, check=user.commands[0].check, run_when="check-fails"), host.system,
    )
    assert not ok and "found a blocker" in detail


def test_remove_user_deletes_an_idle_sandbox_user(host):
    result, _, _ = _apply(host, remove_user=True)
    assert "user" in result.applied
    assert host.fake.sandbox_user is False


def test_remove_user_refuses_when_openclaw_home_lives_in_sandbox_home(host):
    inside = os.path.join(host.sandbox_home, "oc")
    os.makedirs(inside)
    host.cfg.claw.openclaw_home_original = inside
    with open(os.path.join(host.data_dir, legacy.OWNERSHIP_BACKUP_NAME), "w") as fh:
        json.dump({"openclaw_home": inside, "original_uid": OPERATOR_UID, "original_gid": OPERATOR_UID}, fh)
    _, steps = _plan(host, remove_user=True)
    user = next(step for step in steps if step.id == "user")
    assert "userdel -r" in user.blocked


def test_remove_user_waits_for_a_refused_ownership_restore(host, tmp_path):
    path = os.path.join(host.data_dir, legacy.OWNERSHIP_BACKUP_NAME)
    with open(path) as fh:
        backup = json.load(fh)
    backup["openclaw_home"] = str(tmp_path)
    with open(path, "w") as fh:
        json.dump(backup, fh)
    _, steps = _plan(host, remove_user=True)
    user = next(step for step in steps if step.id == "user")
    assert "waits for the OpenClaw home ownership and ACL restore" in user.blocked and not user.commands


def test_remove_user_is_refused_while_the_home_keeps_sandbox_acls(host):
    runner = host.fake.run

    def acl_fails(argv):
        if tool("setfacl") in argv:
            host.fake.calls.append(tuple(argv))
            return legacy.CommandResult(1, "", "Operation not supported")
        return runner(argv)

    host.system.runner = acl_fails
    result, _, lines = _apply(host, remove_user=True)
    assert "ownership" in result.failed and "user" in result.failed
    assert host.fake.sandbox_user is True
    assert not [call for call in host.fake.calls if tool("userdel") in call]
    assert any("ownership and ACL restore did not complete" in line for line in lines)

    # Even with the step marked done, a leftover ACL entry still refuses.
    host.system.runner = runner
    state, steps = _plan(host, remove_user=True)
    state.receipt["steps"]["ownership"] = {"status": "done"}
    user = next(step for step in steps if step.id == "user")
    userdel = next(command for command in user.commands if tool("userdel") in command.argv)
    assert f"still carries ACL entries for uid {SANDBOX_UID}" in userdel.precondition()


def test_remove_user_probes_an_unreadable_sandbox_home_as_root(host, monkeypatch):
    link = os.path.join(host.sandbox_home, ".openclaw")
    monkeypatch.setattr(legacy, "_sandbox_link_state", lambda path: "unknown")
    _, steps = _plan(host, remove_user=True)
    user = next(step for step in steps if step.id == "user")
    assert user.commands[0].argv == sudo("test", "!", "-e", link) and user.commands[0].refusal
    assert "the step stops here unless it succeeds" in "\n".join(legacy.describe(steps))

    # The sandbox's own OpenClaw state lives there as a real directory.
    os.unlink(link)
    os.makedirs(link)
    result, _, lines = _apply(host, remove_user=True)
    assert "user" in result.failed and host.fake.sandbox_user is True
    assert any(f"{link} still exists" in line for line in lines)


def test_remove_user_refuses_claw_paths_in_the_sandbox_home_without_a_pin(host, monkeypatch):
    # Legacy setup without setfacl kept the only OpenClaw state in the sandbox home.
    os.unlink(os.path.join(host.data_dir, legacy.OWNERSHIP_BACKUP_NAME))
    host.cfg.claw.openclaw_home_original = ""
    monkeypatch.setattr(legacy, "_sandbox_link_state", lambda path: "unknown")
    _, steps = _plan(host, remove_user=True)
    user = next(step for step in steps if step.id == "user")
    assert "may hold the only OpenClaw state" in user.blocked


def test_remove_user_refuses_an_account_whose_home_is_elsewhere(host):
    host.system.lookup_user = lambda name: SimpleNamespace(pw_uid=SANDBOX_UID, pw_dir="/srv/sandbox")
    state, steps = _plan(host, remove_user=True)
    user = next(step for step in steps if step.id == "user")
    assert "not the configured sandbox home" in user.blocked and not user.commands


def test_binary_is_not_executed_without_remove_binary(host):
    state, _ = _plan(host)
    assert not [call for call in host.fake.calls if call and call[0] == host.binary]
    assert any("--remove-binary" in hint for hint in legacy.hints(state, remove_user=False, remove_binary=False))


def test_remove_binary_requires_a_legacy_unpackaged_build(host):
    _, steps = _plan(host, remove_binary=True)
    assert sudo("rm", "-f", "--", host.binary) in _argvs(steps, "binary")

    host.fake.binary_version = "openshell-sandbox 0.1.1"
    _, steps = _plan(host, remove_binary=True)
    binary = next(step for step in steps if step.id == "binary")
    assert "not a legacy 0.0.x build" in binary.blocked and not binary.commands

    host.fake.binary_version = "openshell-sandbox 0.0.16"
    host.fake.package_owner = "openshell"
    _, steps = _plan(host, remove_binary=True)
    binary = next(step for step in steps if step.id == "binary")
    assert "owned by package openshell" in binary.blocked


# ---------------------------------------------------------------------------
# Trusted executable resolution (ported from the removed sandbox commands)
# ---------------------------------------------------------------------------


def test_trusted_command_ignores_path(tmp_path, monkeypatch):
    planted = tmp_path / "setfacl"
    planted.write_text("#!/bin/sh\n")
    planted.chmod(0o755)
    monkeypatch.setattr(legacy, "TRUSTED_SYSTEM_DIRS", ())
    monkeypatch.setenv("PATH", str(tmp_path))
    assert legacy.trusted_system_command("setfacl") is None
    assert legacy.trusted_system_command("../bin/sh") is None


def test_trusted_file_requires_root_owned_unwritable_chain(monkeypatch):
    script = "/opt/defenseclaw/tool"
    good_file = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
    good_dir = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
    metadata = {script: good_file, "/opt/defenseclaw": good_dir, "/opt": good_dir, "/": good_dir}
    monkeypatch.setattr(legacy.os.path, "realpath", lambda path: path)
    monkeypatch.setattr(legacy.os, "lstat", lambda path: metadata[path])
    assert legacy.trusted_root_owned_file(script) == script
    metadata["/opt/defenseclaw"] = SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0)
    assert legacy.trusted_root_owned_file(script) is None
    metadata["/opt/defenseclaw"] = good_dir
    metadata[script] = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=1000)
    assert legacy.trusted_root_owned_file(script) is None


def test_trusted_command_follows_a_root_owned_alternatives_chain(monkeypatch):
    link = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
    executable = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
    directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
    metadata = {
        "/usr/sbin/iptables": link, "/etc/alternatives/iptables": link, "/usr/sbin/iptables-nft": executable,
        "/usr/sbin": directory, "/usr": directory, "/etc/alternatives": directory, "/etc": directory, "/": directory,
    }
    targets = {"/usr/sbin/iptables": "/etc/alternatives/iptables", "/etc/alternatives/iptables": "/usr/sbin/iptables-nft"}
    monkeypatch.setattr(legacy, "TRUSTED_SYSTEM_DIRS", ("/usr/sbin",))
    monkeypatch.setattr(legacy.os, "lstat", lambda path: metadata[path])
    monkeypatch.setattr(legacy.os, "readlink", lambda path: targets[path])
    monkeypatch.setattr(legacy.os.path, "realpath", lambda path: path)
    monkeypatch.setattr(legacy.os, "access", lambda path, mode: True)
    # The validated name is returned, not the chain target: iptables-nft and
    # xtables-nft-multi dispatch on argv[0].
    assert legacy.trusted_system_command("iptables") == "/usr/sbin/iptables"
    metadata["/etc/alternatives/iptables"] = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=1000)
    assert legacy.trusted_system_command("iptables") is None


def test_privileged_argv_resolves_sudo_and_helper():
    system = legacy.System(resolve={"sudo": "/usr/bin/sudo", "chown": "/usr/sbin/chown"}.get, euid=lambda: 1000)
    assert legacy.privileged_argv(system, "chown", "-hR", "1:1", "--", "/srv") == (
        "/usr/bin/sudo", "/usr/sbin/chown", "-hR", "1:1", "--", "/srv",
    )
    root = legacy.System(resolve={"chown": "/usr/sbin/chown"}.get, euid=lambda: 0)
    assert legacy.privileged_argv(root, "chown", "x")[0] == "/usr/sbin/chown"
    with pytest.raises(legacy.UntrustedCommandError, match="trusted system sudo binary not found"):
        legacy.privileged_argv(legacy.System(resolve={"chown": "/usr/sbin/chown"}.get, euid=lambda: 1000), "chown")


def test_missing_trusted_helper_blocks_the_step(host):
    host.system.resolve = lambda name: None if name == "gpasswd" else tool(name)
    _, steps = _plan(host)
    group = next(step for step in steps if step.id == "group")
    assert group.blocked == "trusted system gpasswd binary not found"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_dry_run_uses_the_plan(host, monkeypatch):
    from defenseclaw.commands.cmd_sandbox import sandbox
    from defenseclaw.context import AppContext

    monkeypatch.setattr(legacy, "System", lambda: host.system)
    app = AppContext()
    app.cfg = host.cfg
    result = CliRunner().invoke(sandbox, ["legacy-cleanup", "--dry-run"], obj=app)
    assert result.exit_code == 0, result.output
    assert "Stop and remove the legacy systemd units" in result.output
    assert "Dry run: nothing was changed." in result.output
    assert host.cfg.saves == 0


def test_cli_reports_a_clean_host(host, monkeypatch):
    from defenseclaw.commands.cmd_sandbox import sandbox
    from defenseclaw.context import AppContext

    _apply(host)
    monkeypatch.setattr(legacy, "System", lambda: host.system)
    app = AppContext()
    app.cfg = host.cfg
    result = CliRunner().invoke(sandbox, ["legacy-cleanup"], obj=app)
    assert result.exit_code == 0, result.output
    assert "nothing to clean up" in result.output


def test_cli_prints_next_steps_after_apply(host, monkeypatch):
    from defenseclaw.commands.cmd_sandbox import sandbox
    from defenseclaw.context import AppContext

    os.makedirs(os.path.join(host.oc_home, "extensions", "planted"))
    monkeypatch.setattr(legacy, "System", lambda: host.system)
    app = AppContext()
    app.cfg = host.cfg
    result = CliRunner().invoke(sandbox, ["legacy-cleanup", "--yes"], obj=app)
    assert result.exit_code == 0, result.output
    assert f"the agent could write anywhere in {host.oc_home}, including openclaw.json, extensions" in result.output
    for _why, command in legacy.NEXT_STEPS:
        assert command in result.output


def test_next_steps_scan_before_anything_restarts_openclaw():
    commands = [command for _why, command in legacy.NEXT_STEPS]
    assert "openclaw gateway restart" not in commands
    guardrail = commands.index("defenseclaw setup guardrail")  # restarts the gateway and OpenClaw
    for scan in ("defenseclaw skill scan --all", "defenseclaw plugin scan --all", "defenseclaw mcp scan --all"):
        assert commands.index(scan) < guardrail


def test_cli_completes_a_receipt_with_no_work_left(host, monkeypatch):
    from defenseclaw.commands.cmd_sandbox import sandbox
    from defenseclaw.context import AppContext

    _apply(host)
    path = os.path.join(host.data_dir, legacy.RECEIPT_NAME)
    receipt = _receipt(host)
    receipt["completed"] = False
    with open(path, "w") as fh:
        json.dump(receipt, fh)
    assert "an unfinished legacy-cleanup receipt" in legacy.quick_evidence(host.cfg)
    monkeypatch.setattr(legacy, "System", lambda: host.system)
    app = AppContext()
    app.cfg = host.cfg

    result = CliRunner().invoke(sandbox, ["legacy-cleanup", "--dry-run"], obj=app)
    assert result.exit_code == 0, result.output
    assert _receipt(host)["completed"] is False  # a dry run changes nothing

    result = CliRunner().invoke(sandbox, ["legacy-cleanup"], obj=app)
    assert result.exit_code == 0, result.output
    assert "legacy cleanup is complete" in result.output
    assert "an unfinished legacy-cleanup receipt" not in legacy.quick_evidence(host.cfg)
