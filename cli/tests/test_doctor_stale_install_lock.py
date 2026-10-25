# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""oss-outage-open round h loop 2 (P2): doctor finds and clears an install
lock a stopped installer left, which made OpenCode and Amp block every tool
call a healthy gateway answered. The rule is the plugins' installLockState;
a live, uncertain or interrupted install keeps its lock."""

from __future__ import annotations

import os
import shutil
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


def _lock(folder: Path, pid: str | None, age: float = 0, deadline: str | None = None, pid_age: float = 0) -> Path:
    lock = folder / ".install.lock"
    lock.mkdir(parents=True)
    if pid is not None:
        (lock / "pid").write_text(pid, encoding="ascii")
        if pid_age:
            then = time.time() - pid_age
            os.utime(lock / "pid", (then, then))
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
        # Round k: no wait expires a lock without a pid (no clock is read).
        (None, 11 * 60, None, "held"),
        ("abc", 0, None, "held"),
        ("99999999999", 0, None, "held"),
        (str(os.getppid()), 7 * 3600, None, "held"),
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


# oss-outage-open rounds j and k (one liveness rule, no clock): a live
# installer keeps its lock for as long as it runs, so neither its age nor a
# deadline an earlier build recorded expires it; a PID-only lock of 1.0.2 or
# 1.0.3 holds while its pid names a process, whenever the pid was written (a
# clock may not tell a reused pid; a proc-start record does); an interrupted
# install keeps its lock.
@pytest.mark.parametrize(
    ("pid", "age", "deadline", "pid_age", "record", "want"),
    [
        (str(os.getppid()), 7 * 3600, PAST, 0, None, "held"),
        # Without a proc-start record no clock tells a reused pid from a
        # live owner: it holds.
        (str(os.getppid()), 7 * 3600, None, 7 * 3600, None, "held"),
        (str(os.getppid()), 3600, None, 3600, None, "held"),
        (str(os.getppid()), 30 * 86400, None, 30 * 86400, None, "held"),
        # Loop round 2 P2: a lock naming doctor's own pid is a reused pid.
        (str(os.getpid()), 0, None, 0, None, "stale"),
        (f"{DEAD}\n", 3600, None, 3600, None, "stale"),
        (f"{DEAD}\n", 0, PAST, 0, "previous.new", "recovery"),
        (str(os.getppid()), 0, "soon", 0, None, "held"),
    ],
)
def test_install_lock_state_holds_while_its_owner_runs(account, pid, age, deadline, pid_age, record, want):
    _lock(account.data, pid, age, deadline, pid_age)
    if record:
        (account.data / record).mkdir()
    assert cmd_doctor._install_lock_state(str(account.data))[0] == want


_IDENTITY_SYSTEM = sys.platform.startswith("linux") or sys.platform == "darwin" or os.name == "nt"


def _other(identity: str) -> str:
    """The record of another process that had the same pid (a reused pid)."""
    return identity[:-1] + str((int(identity[-1]) + 1) % 10)


# oss-outage-open round k (rules 1 and 3): install.sh and install.ps1 record
# their own identity (proc-start: the Linux boot id and kernel start, the
# macOS creation second, the Windows creation FILETIME). Compared as it is,
# it holds a live owner and drops a reused pid on every system, however the
# clock stepped: the pid file and the lock are dated a week back and a week
# ahead (round j loop 2 P1: a step made a live macOS or Windows owner look
# reused; P2: a reused pid held a dead lock for a whole session).
@pytest.mark.skipif(not _IDENTITY_SYSTEM, reason="no process identity reader here")
@pytest.mark.parametrize("step", [0, -7 * 86400, 7 * 86400])
@pytest.mark.parametrize(("reused", "want"), [(False, "held"), (True, "stale")])
def test_the_proc_start_record_tells_a_live_owner_across_a_clock_step(account, reused, want, step):
    identity = cmd_doctor._process_identity(os.getppid())
    assert identity
    lock = _lock(account.data, str(os.getppid()))
    (lock / "proc-start").write_text((_other(identity) if reused else identity) + "\n", encoding="ascii")
    if step:
        then = time.time() + step
        for path in (lock / "pid", lock / "proc-start", lock):
            os.utime(path, (then, then))
    assert cmd_doctor._install_lock_state(str(account.data))[0] == want


@pytest.mark.skipif(not _IDENTITY_SYSTEM, reason="no process identity reader here")
def test_the_identity_of_another_process_is_read():
    first = cmd_doctor._process_identity(os.getppid())
    assert first and cmd_doctor._process_identity(os.getppid()) == first
    assert cmd_doctor._process_identity(DEAD) is None
    if sys.platform.startswith("linux"):
        boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        line = Path(f"/proc/{os.getppid()}/stat").read_text(encoding="utf-8")
        assert first == f"{boot} {line[line.rfind(')') + 1 :].split()[19]}"


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


def _live_owner(lock: Path) -> None:
    """A running installer's record: this test's parent pid and its identity."""
    (lock / "pid").write_text(f"{os.getppid()}\n", encoding="ascii")
    identity = cmd_doctor._process_identity(os.getppid())
    if identity:
        (lock / "proc-start").write_text(identity + "\n", encoding="ascii")


def _replace(lock: Path, *, owner=None) -> None:
    """An installer's takeover: the old folder goes and a new one takes its path."""
    shutil.rmtree(lock)
    lock.mkdir()
    if owner is not None:
        owner(lock)


def _other_stale(lock: Path) -> None:
    (lock / "pid").write_text(f"{_exited_pid()}\n", encoding="ascii")


def _symlink_to_stale(lock: Path) -> None:
    shutil.rmtree(lock)
    other = _lock(lock.parent / "elsewhere", f"{DEAD}\n")
    lock.symlink_to(other, target_is_directory=True)


def _file_in_place(lock: Path) -> None:
    shutil.rmtree(lock)
    lock.write_text(str(os.getppid()), encoding="ascii")


def _lock_view(lock: Path):
    """What a hook and an installer see at the lock path."""
    if not os.path.lexists(lock):
        return None
    info = os.lstat(lock)
    if not lock.is_dir() or lock.is_symlink():
        return (info.st_ino, "not a folder")
    # The claim doctor itself puts in the lock (claim-<pid>-...) is no change.
    own = (f"claim-{os.getpid()}-", f".claim-{os.getpid()}-")
    entries = (p for p in lock.iterdir() if not p.name.startswith(own))
    return (info.st_ino, tuple(sorted((p.name, p.read_bytes()) for p in entries)))


# oss-outage-open round k loop 2 (P2): doctor classified a lock as stale,
# then, after its prompt, moved whatever lock was at the path aside. An
# installer that had taken the lock over meanwhile (and stopped the gateway)
# lost its canonical lock until doctor put it back, so a default-tier hook
# saw no install and failed open, and a second installer could take the
# vacant path. The stale decision is now bound to the folder's identity and
# its owner record, and doctor never moves or removes a lock that changed.
RACES = {
    "a new folder of a live installer": lambda lock: _replace(lock, owner=_live_owner),
    "a new folder whose installer has not written its pid yet": lambda lock: _replace(lock),
    "a new folder of another stopped installer": lambda lock: _replace(lock, owner=_other_stale),
    "a live installer's record in the same folder": _live_owner,
    "an interrupted install beside it": lambda lock: (lock.parent / "previous.new").mkdir(),
    "a file": _file_in_place,
    "a link to a stale lock": _symlink_to_stale,
}


@pytest.mark.parametrize("race", sorted(RACES))
def test_fix_never_moves_a_lock_that_changed_after_its_check(account, monkeypatch, race):
    if race == "a link to a stale lock" and os.name == "nt":
        pytest.skip("folder links need a privilege on Windows")
    lock = _lock(account.data, f"{DEAD}\n")
    seen: list = []
    after: list = []

    def watch(real):
        def call(*args, **kwargs):
            result = real(*args, **kwargs)
            seen.append(_lock_view(lock))
            return result

        return call

    def prompt(*_args, **_kwargs):
        RACES[race](lock)
        after.append(_lock_view(lock))
        # From here on, every change doctor makes is checked against it.
        for name in ("rename", "replace", "unlink", "remove", "rmdir"):
            monkeypatch.setattr(os, name, watch(getattr(os, name)))
        monkeypatch.setattr(shutil, "rmtree", watch(shutil.rmtree))
        return True

    monkeypatch.setattr(cmd_doctor.click, "confirm", prompt)
    tag, detail = cmd_doctor._fix_stale_install_lock(account.cfg, assume_yes=False)
    assert tag == "skip", detail
    assert "changed since the check" in detail
    assert after[0] is not None
    # Never missing, never another folder, never another content.
    assert all(view == after[0] for view in seen), seen
    assert _lock_view(lock) == after[0]
    assert not [p for p in account.data.iterdir() if p.name.startswith(".install.lock.")]


@pytest.mark.skipif(os.name == "nt", reason="the pinned handle refuses the takeover on Windows (native test below)")
def test_fix_keeps_a_lock_an_installer_takes_over_while_doctor_removes_the_old_one(account, monkeypatch):
    lock = _lock(account.data, f"{DEAD}\n")
    (lock / "started").write_text("1", encoding="ascii")
    real_unlink = os.unlink
    after: list = []

    def unlink(path, *args, **kwargs):
        if not after:
            # The takeover lands after doctor's last check, before its first removal.
            after.append(None)
            _replace(lock, owner=_live_owner)
            after[0] = _lock_view(lock)
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", unlink)
    tag, detail = cmd_doctor._fix_stale_install_lock(account.cfg, assume_yes=True)
    assert tag == "skip", detail
    assert after and _lock_view(lock) == after[0]
    assert cmd_doctor._install_lock_state(str(account.data))[0] == "held"


def test_fix_removes_the_pid_first_and_shows_no_missing_lock_until_the_folder_goes(account, monkeypatch):
    lock = _lock(account.data, f"{DEAD}\n")
    for name in ("started", "proc-start", "deadline"):
        (lock / name).write_text("1", encoding="ascii")
    states: list = []
    real_unlink = os.unlink

    def unlink(path, *args, **kwargs):
        result = real_unlink(path, *args, **kwargs)
        states.append(cmd_doctor._install_lock_state(str(account.data))[0])
        return result

    monkeypatch.setattr(os, "unlink", unlink)
    tag, detail = cmd_doctor._fix_stale_install_lock(account.cfg, assume_yes=True)
    assert tag == "pass", detail
    # The four owner files, then doctor's own claim, each leave the lock held.
    assert states == ["held"] * 5
    assert not os.path.lexists(lock)


def test_fix_leaves_a_lock_with_a_folder_inside_whole(account):
    lock = _lock(account.data, f"{DEAD}\n")
    (lock / "inner").mkdir()
    tag, detail = cmd_doctor._fix_stale_install_lock(account.cfg, assume_yes=True)
    assert tag == "fail" and "holds a folder" in detail
    assert (lock / "pid").read_text() == f"{DEAD}\n" and (lock / "inner").is_dir()


@pytest.mark.skipif(os.name != "nt", reason="Windows only")
def test_a_pinned_lock_cannot_be_moved_or_removed_and_goes_by_its_handle(account):
    lock = _lock(account.data, None)
    held = cmd_doctor._open_install_lock(str(lock), pin=True)
    assert held is not None
    try:
        with pytest.raises(OSError):
            os.rename(lock, account.data / "aside")
        with pytest.raises(OSError):
            os.rmdir(lock)
        assert cmd_doctor._remove_held_install_lock(str(lock), held) == "removed"
    finally:
        cmd_doctor._close_install_lock(held)
    assert not os.path.lexists(lock)


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
        # One identity record, and no clock (round k).
        assert '"proc-start"' in body and "NO_PID_MS" not in body and "START_SLACK" not in body


def _wait_ended(proc: subprocess.Popen) -> None:
    """Wait until proc has exited but is not reaped (a zombie; on Windows its handle stays open)."""
    deadline = time.time() + 20
    while not (cmd_doctor._process_ended(proc.pid) if os.name != "nt" else not cmd_doctor._pid_running(proc.pid)):
        assert time.time() < deadline, f"pid {proc.pid} never read as ended"
        time.sleep(0.01)


# oss-outage-open round l loop 1 (P2): an installer that exited but is not
# reaped (a zombie) keeps its pid and its start, so doctor and every hook
# held its lock for good. Its lock is stale, with its record or without one.
@pytest.mark.parametrize("record", [True, False])
def test_the_lock_of_an_exited_unreaped_installer_is_stale(account, record):
    proc = subprocess.Popen([sys.executable, "-c", ""])
    try:
        identity = cmd_doctor._process_identity(proc.pid)
        _wait_ended(proc)
        identity = identity or cmd_doctor._process_identity(proc.pid)
        lock = _lock(account.data, f"{proc.pid}\n")
        if record and identity:
            (lock / "proc-start").write_text(identity + "\n", encoding="ascii")
        state, detail = cmd_doctor._install_lock_state(str(account.data))
        assert state == "stale", detail
    finally:
        proc.wait()


def _claim(lock: Path, pid: int, identity: str | None, name: str | None = None) -> Path:
    path = lock / (name or f"claim-{pid}-1")
    path.write_text(f"{pid}\n{identity or ''}\n", encoding="ascii")
    return path


# oss-outage-open round l loop 1 (P2): doctor and installers take a stale lock
# over one at a time. Doctor claims the lock (install.sh take_lock) before its
# last check, so an installer that claims it later waits; and a lock another
# run has claimed stays whole, its claim with it.
def test_fix_claims_the_lock_before_its_last_check_and_removes_its_claim_last(account, monkeypatch):
    lock = _lock(account.data, f"{DEAD}\n")
    real_state = cmd_doctor._install_lock_state
    claims: list = []

    def state(folder, held=None):
        if held is not None:
            claims.extend(
                (p.name, p.read_text(encoding="ascii")) for p in lock.iterdir() if p.name.startswith("claim-")
            )
        return real_state(folder, held)

    monkeypatch.setattr(cmd_doctor, "_install_lock_state", state)
    tag, detail = cmd_doctor._fix_stale_install_lock(account.cfg, assume_yes=True)
    assert tag == "pass", detail
    assert len(claims) == 1, claims
    name, body = claims[0]
    assert name.startswith(f"claim-{os.getpid()}-")
    assert body.splitlines()[0] == str(os.getpid())
    identity = cmd_doctor._process_identity(os.getpid())
    if identity:
        assert body.splitlines()[1] == identity
    assert not os.path.lexists(lock)


def test_fix_leaves_a_lock_another_run_has_claimed_whole(account):
    lock = _lock(account.data, f"{DEAD}\n")
    other = subprocess.Popen(
        ["sleep", "30"] if os.name != "nt" else [sys.executable, "-c", "import time; time.sleep(30)"]
    )
    try:
        claim = _claim(lock, other.pid, cmd_doctor._process_identity(other.pid))
        before = _lock_view(lock)
        tag, detail = cmd_doctor._fix_stale_install_lock(account.cfg, assume_yes=True)
        assert tag == "skip" and "changed since the check" in detail, detail
        assert _lock_view(lock) == before and claim.exists()
        assert not [p for p in lock.iterdir() if p.name.startswith((f"claim-{os.getpid()}-", f".claim-{os.getpid()}-"))]
    finally:
        other.kill()
        other.wait()


def test_fix_removes_a_lock_whose_claims_are_of_runs_that_are_gone(account):
    lock = _lock(account.data, f"{DEAD}\n")
    _claim(lock, DEAD, None)
    alive = subprocess.Popen(
        ["sleep", "30"] if os.name != "nt" else [sys.executable, "-c", "import time; time.sleep(30)"]
    )
    try:
        identity = cmd_doctor._process_identity(alive.pid)
        if identity:
            # A reused pid: the claim names another process than this one.
            _claim(lock, alive.pid, identity + "0", name=f"claim-{alive.pid}-2")
        tag, detail = cmd_doctor._fix_stale_install_lock(account.cfg, assume_yes=True)
        assert tag == "pass", detail
        assert not os.path.lexists(lock)
    finally:
        alive.kill()
        alive.wait()
