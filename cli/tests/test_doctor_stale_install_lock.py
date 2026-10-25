# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""oss-outage-open round h loop 2 (P2): doctor finds and clears an install
lock a stopped installer left, which made OpenCode and Amp block every tool
call a healthy gateway answered. The rule is the plugins' installLockState;
a live, uncertain or interrupted install keeps its lock."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw.commands import cmd_doctor

REPO = Path(__file__).resolve().parents[2]


def _exited_pid() -> int:
    proc = subprocess.Popen([sys.executable, "-c", ""])
    proc.wait()
    return proc.pid


def _lock(folder: Path, pid: str | None, age: float = 0, deadline: str | None = None) -> Path:
    lock = folder / ".install.lock"
    lock.mkdir(parents=True)
    if pid is not None:
        (lock / "pid").write_text(pid, encoding="ascii")
    if deadline is not None:
        (lock / "deadline").write_text(deadline, encoding="ascii")
    if age:
        then = time.time() - age
        os.utime(lock, (then, then))
    return lock


@pytest.fixture
def account(tmp_path, monkeypatch):
    data = tmp_path / "data"
    home = tmp_path / "home"
    data.mkdir()
    home.mkdir()
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    return SimpleNamespace(data=data, home=home, cfg=SimpleNamespace(data_dir=str(data), deployment_mode=""))


DEAD = _exited_pid()


@pytest.mark.parametrize(
    ("pid", "age", "record", "want"),
    [
        (f"{DEAD}\n", 0, None, "stale"),
        (f"{DEAD}\r\n", 0, None, "stale"),
        (f"{os.getppid()}\n", 0, None, "held"),
        (None, 0, None, "held"),
        (" ", 0, None, "held"),
        (None, 11 * 60, None, "stale"),
        ("abc", 0, None, "held"),
        ("99999999999", 0, None, "held"),
        (str(os.getppid()), 7 * 3600, None, "stale"),
        (f"{DEAD}\n", 0, "previous.new", "recovery"),
        (f"{DEAD}\n", 0, ".repair", "recovery"),
        (f"{DEAD}\n", 0, ".rollback-hold", "recovery"),
        (f"{DEAD}\n", 0, ".lifecycle-txn.json", "recovery"),
    ],
)
def test_install_lock_state_follows_the_plugin_rule(account, pid, age, record, want):
    _lock(account.data, pid, age)
    if record:
        (account.data / record).mkdir()
    assert cmd_doctor._install_lock_state(str(account.data))[0] == want


PAST = str(int(time.time()) - 60)
FUTURE = str(int(time.time()) + 3600)


# oss-outage-open round i: the lock records a deadline (install.sh writes
# pid, started and deadline). Past it the lock is no lock, also for a running
# pid (reused) and an interrupted install's kept lock; the six-hour bound
# caps a later recorded deadline; a deadline that cannot be read holds.
@pytest.mark.parametrize(
    ("pid", "age", "deadline", "record", "want"),
    [
        (str(os.getppid()), 0, FUTURE, None, "held"),
        (str(os.getppid()), 0, PAST, None, "stale"),
        (str(os.getppid()), 7 * 3600, str(int(time.time()) + 100 * 86400), None, "stale"),
        (f"{DEAD}\n", 0, FUTURE, None, "stale"),
        (f"{DEAD}\n", 0, PAST, "previous.new", "stale"),
        (f"{DEAD}\n", 0, FUTURE, "previous.new", "recovery"),
        (str(os.getppid()), 0, "soon", None, "held"),
    ],
)
def test_install_lock_state_honours_the_recorded_deadline(account, pid, age, deadline, record, want):
    _lock(account.data, pid, age, deadline)
    if record:
        (account.data / record).mkdir()
    assert cmd_doctor._install_lock_state(str(account.data))[0] == want


def test_a_deadline_that_cannot_be_read_holds_until_the_six_hour_bound(account):
    lock = _lock(account.data, f"{DEAD}\n")
    (lock / "deadline").mkdir()
    assert cmd_doctor._install_lock_state(str(account.data))[0] == "held"


def test_a_lock_that_is_not_a_folder_or_a_pid_that_is_not_a_file_is_held(account):
    (account.data / ".install.lock").write_text(str(DEAD))
    assert cmd_doctor._install_lock_state(str(account.data))[0] == "held"
    lock = _lock(account.home, None)
    (lock / "pid").mkdir()
    assert cmd_doctor._install_lock_state(str(account.home))[0] == "held"
    assert cmd_doctor._install_lock_state(str(account.data / "absent"))[0] == "none"


def test_doctor_warns_and_fix_removes_only_a_stale_lock(account):
    stale = _lock(account.data, f"{DEAD}\n")
    live = _lock(account.home, f"{os.getppid()}\n")
    r = cmd_doctor._DoctorResult(mode="check")
    cmd_doctor._check_install_lock(account.cfg, r)
    rows = [row for row in r.checks if row.get("label", "").startswith("Install lock")]
    assert len(rows) == 2 and all(row["status"] == "warn" for row in rows)
    assert any("doctor --fix" in str(row.get("remediation", "")) for row in rows)
    assert cmd_doctor._fix_stale_install_lock(account.cfg, assume_yes=True, plan_only=True)[0] == "plan"
    assert stale.exists()
    tag, detail = cmd_doctor._fix_stale_install_lock(account.cfg, assume_yes=True)
    assert tag == "pass", detail
    assert not stale.exists() and live.exists()
    assert not [p for p in account.data.iterdir() if p.name.startswith(".install.lock")]
    assert cmd_doctor._fix_stale_install_lock(account.cfg, assume_yes=True)[0] == "skip"


def test_fix_keeps_a_lock_an_interrupted_install_keeps(account):
    lock = _lock(account.data, f"{DEAD}\n")
    (account.data / "previous.new").mkdir()
    r = cmd_doctor._DoctorResult(mode="check")
    cmd_doctor._check_install_lock(account.cfg, r)
    assert "installer again" in str(r.checks[-1].get("remediation", ""))
    assert cmd_doctor._fix_stale_install_lock(account.cfg, assume_yes=True)[0] == "skip"
    assert lock.exists()


def test_fix_puts_back_a_lock_an_installer_took_over(account, monkeypatch):
    lock = _lock(account.data, f"{DEAD}\n")
    real = cmd_doctor._install_lock_state

    def took_over(folder, name=".install.lock"):
        if name != ".install.lock":
            (Path(folder) / name / "pid").write_text(str(os.getppid()))
        return real(folder, name)

    monkeypatch.setattr(cmd_doctor, "_install_lock_state", took_over)
    tag, _ = cmd_doctor._fix_stale_install_lock(account.cfg, assume_yes=True)
    assert tag == "fail"
    assert (lock / "pid").read_text() == str(os.getppid())


def test_managed_install_is_left_alone(account):
    lock = _lock(account.data, f"{DEAD}\n")
    cfg = SimpleNamespace(data_dir=str(account.data), deployment_mode="managed_enterprise")
    r = cmd_doctor._DoctorResult(mode="check")
    cmd_doctor._check_install_lock(cfg, r)
    assert not r.checks
    assert cmd_doctor._fix_stale_install_lock(cfg, assume_yes=True)[0] == "skip"
    assert lock.exists()


def test_the_repair_is_registered_and_documented():
    ids = [spec.repair_id for spec in cmd_doctor._doctor_repair_specs()]
    assert "doctor.install.stale-lock.clear" in ids
    for page in ("troubleshooting/doctor.mdx", "reference/commands/cli.mdx"):
        assert "doctor.install.stale-lock.clear" in (REPO / "docs-site/content/docs" / page).read_text()
    # The plugins and doctor share the same records and bounds.
    for asset in ("amp-plugin.ts", "opencode-plugin.js"):
        body = (REPO / "internal/gateway/connector/hooks" / asset).read_text()
        for record in cmd_doctor._INSTALL_RECOVERY_RECORDS:
            assert f'"{record}"' in body, (asset, record)
        assert "10 * 60 * 1000" in body and "6 * 60 * 60 * 1000" in body
