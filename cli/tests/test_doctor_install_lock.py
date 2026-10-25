# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Doctor recovers only abandoned per-user installer locks."""

import os
import time
from types import SimpleNamespace

from defenseclaw.commands import cmd_doctor


def test_doctor_clears_dead_and_aged_install_locks(tmp_path, monkeypatch):
    home = tmp_path / "home"
    data = tmp_path / "separate-data"
    home.mkdir()
    data.mkdir()
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    cfg = SimpleNamespace(data_dir=str(data), deployment_mode="oss")

    for root, pid, age in ((home, "99999999", 0), (data, str(os.getpid()), 660)):
        lock = root / ".install.lock"
        lock.mkdir()
        (lock / "pid").write_text(pid + "\n")
        if age:
            then = time.time() - age
            os.utime(lock, (then, then))

    planned = cmd_doctor._plan_stale_install_lock(cfg)
    assert planned.state == "applicable"
    assert (home / ".install.lock").exists() and (data / ".install.lock").exists()
    tag, detail = cmd_doctor._fix_stale_install_lock(cfg, assume_yes=True)
    assert tag == "pass", detail
    assert not (home / ".install.lock").exists()
    assert not (data / ".install.lock").exists()
    assert cmd_doctor._plan_stale_install_lock(cfg).state == "noop"


def test_doctor_preserves_live_and_managed_install_locks(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    lock = tmp_path / ".install.lock"
    lock.mkdir()
    (lock / "pid").write_text(str(os.getpid()) + "\n")
    cfg = SimpleNamespace(data_dir=str(tmp_path), deployment_mode="oss")
    assert cmd_doctor._plan_stale_install_lock(cfg).state == "noop"
    assert cmd_doctor._fix_stale_install_lock(cfg, assume_yes=True)[0] == "skip"
    assert lock.exists()
    cfg.deployment_mode = "managed_enterprise"
    then = time.time() - 660
    os.utime(lock, (then, then))
    assert cmd_doctor._plan_stale_install_lock(cfg).state == "noop"
    assert lock.exists()
