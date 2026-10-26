# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Doctor recovers only abandoned per-user installer locks.

The carry keeps the oss-outage-open identity rule (cmd_doctor._install_lock_state,
hookexec installLockStale): a lock is stale only when its installer is proven
gone. It reads no clock, so an old lock whose installer still runs is held.
"""

import os
import time
from types import SimpleNamespace

from defenseclaw.commands import cmd_doctor


def _planned(cfg) -> str:
    return cmd_doctor._fix_stale_install_lock(cfg, assume_yes=True, plan_only=True)[0]


def test_doctor_clears_install_locks_whose_installer_is_gone(tmp_path, monkeypatch):
    home = tmp_path / "home"
    data = tmp_path / "separate-data"
    home.mkdir()
    data.mkdir()
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    cfg = SimpleNamespace(data_dir=str(data), deployment_mode="oss")

    # A pid that names no process, and doctor's own pid (no reader writes a lock).
    for root, pid in ((home, "99999999"), (data, str(os.getpid()))):
        lock = root / ".install.lock"
        lock.mkdir()
        (lock / "pid").write_text(pid + "\n")

    assert _planned(cfg) == "plan"
    assert (home / ".install.lock").exists() and (data / ".install.lock").exists()
    tag, detail = cmd_doctor._fix_stale_install_lock(cfg, assume_yes=True)
    assert tag == "pass", detail
    assert not (home / ".install.lock").exists()
    assert not (data / ".install.lock").exists()
    assert _planned(cfg) == "skip"


def test_doctor_preserves_live_and_managed_install_locks(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    lock = tmp_path / ".install.lock"
    lock.mkdir()
    # A running process other than doctor holds the lock.
    (lock / "pid").write_text(str(os.getppid()) + "\n")
    cfg = SimpleNamespace(data_dir=str(tmp_path), deployment_mode="oss")
    assert _planned(cfg) == "skip"
    assert cmd_doctor._fix_stale_install_lock(cfg, assume_yes=True)[0] == "skip"
    assert lock.exists()
    then = time.time() - 660
    os.utime(lock, (then, then))
    # No clock: an old lock whose installer still runs stays held.
    assert _planned(cfg) == "skip"
    assert cmd_doctor._fix_stale_install_lock(cfg, assume_yes=True)[0] == "skip"
    assert lock.exists()
    cfg.deployment_mode = "managed_enterprise"
    assert _planned(cfg) == "skip"
    assert cmd_doctor._fix_stale_install_lock(cfg, assume_yes=True)[0] == "skip"
    assert lock.exists()
