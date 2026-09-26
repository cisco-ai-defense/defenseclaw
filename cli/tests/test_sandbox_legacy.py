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
    veth_up: bool = True
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
        if name == "ip" and rest[:4] == ["-o", "-4", "addr", "show"]:
            out = f"5: {VETH}@if4    inet 10.200.0.1/24 brd 10.200.0.255 scope global {VETH}\n" if self.veth_up else ""
            return legacy.CommandResult(0, "1: lo    inet 127.0.0.1/8 scope host lo\n" + out)
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
            return ok if self.sandbox_processes else legacy.CommandResult(1)
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
    os.chmod(os.path.dirname(oc_home), 0o711)
    real_home = os.path.realpath(oc_home)
    _write(
        os.path.join(data_dir, legacy.OWNERSHIP_BACKUP_NAME),
        json.dumps({
            "openclaw_home": real_home,
            "original_uid": OPERATOR_UID,
            "original_gid": OPERATOR_UID,
            "original_mode": "0o755",
            "parents_modified": [{"path": os.path.dirname(real_home), "original_mode": "0o700"}],
        }),
    )
    os.symlink(real_home, os.path.join(sandbox_home, ".openclaw"))
    fake = FakeHost(root=root, route_localnet_path=route_localnet, netns_dir=netns_dir)
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
        lookup_user=lambda name: SimpleNamespace(pw_uid=SANDBOX_UID) if fake.sandbox_user else None,
        group_members=lambda name: list(fake.group),
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
        "units", "network", "ownership", "openclaw_json", "group", "config", "artifacts",
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
    assert ownership[0] == sudo(
        "chown", "-hR", f"--from={SANDBOX_UID}", f"{OPERATOR_UID}:{OPERATOR_UID}", "--", host.oc_home,
    )
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


def test_clean_host_plans_nothing_and_never_needs_sudo(tmp_path):
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
    system = legacy.System(
        runner=fake.run, resolve=tool, euid=lambda: OPERATOR_UID, trusted_uid=os.getuid(),
        unit_dir=str(tmp_path / "units"), launcher_dir=str(tmp_path / "lib"),
        binary_path=str(tmp_path / "bin" / "openshell-sandbox"), netns_dir=str(tmp_path / "netns"),
        route_localnet_path=str(tmp_path / "rl"), host_os=lambda: "linux", invoking_user=lambda: "alice",
        lookup_user=lambda name: None, group_members=lambda name: None, home=lambda: str(tmp_path),
    )
    state = legacy.detect(cfg, system=system)
    assert legacy.plan(state, cfg, system=system) == []
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
    assert "user" in result.failed
    assert host.fake.sandbox_user is True
    assert not [call for call in host.fake.calls if tool("userdel") in call]


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

    monkeypatch.setattr(legacy, "System", lambda: host.system)
    app = AppContext()
    app.cfg = host.cfg
    result = CliRunner().invoke(sandbox, ["legacy-cleanup", "--yes"], obj=app)
    assert result.exit_code == 0, result.output
    for _why, command in legacy.NEXT_STEPS:
        assert command in result.output
