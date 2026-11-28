# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw doctor`` substrate notifier row (mirror of the Go doctor row)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw.commands.cmd_doctor import (
    _check_substrate_notifier,
    _DoctorResult,
    substrate_admin_notifications_off,
)
from defenseclaw.notification_capabilities import desktop_notifier_tool_missing


def _cfg(*, substrate=True, enabled=True, asks=True, task_end=True, admin=""):
    return SimpleNamespace(
        substrate=SimpleNamespace(enabled=substrate, activity=SimpleNamespace(notifications=admin)),
        notifications=SimpleNamespace(enabled=enabled, substrate=SimpleNamespace(asks=asks, task_end=task_end)),
    )


def _row(cfg, system, which):
    r = _DoctorResult()
    _check_substrate_notifier(cfg, r, system=system, which=which)
    return [c for c in r.checks if c["label"] == "Substrate notifier"]


def test_tool_missing_per_platform() -> None:
    none = lambda _: None  # noqa: E731
    some = lambda name: "/usr/bin/" + name  # noqa: E731
    assert desktop_notifier_tool_missing("linux", none) == "notify-send"
    assert desktop_notifier_tool_missing("darwin", none) == "osascript"
    assert desktop_notifier_tool_missing("windows", none) == ""
    assert desktop_notifier_tool_missing("linux", some) == ""


# The table Go's TestSubstrateNotificationsOffTable reads (GAP-1020).
REPO_ROOT = Path(__file__).resolve().parents[2]
OFF_TABLE = REPO_ROOT / "internal" / "config" / "testdata" / "substrate_activity_notifications.json"


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    """An empty DefenseClaw home: no launcher context unless a test adds one."""
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    return tmp_path


def test_no_row_without_substrate_or_launcher() -> None:
    assert _row(_cfg(substrate=False), "linux", lambda _: None) == []


def test_row_on_a_laptop_with_a_launcher_context(_home) -> None:
    # GAP-1020: substrate.enabled is a cluster key; `substrate watch` runs on
    # the laptop, where only the launcher's context file says it is used.
    (_home / "substrate").mkdir()
    (_home / "substrate" / "contexts.json").write_text('{"current": "c", "contexts": {}}')
    (row,) = _row(_cfg(substrate=False), "linux", lambda _: None)
    assert row["status"] == "warn"


def test_admin_off_reads_like_go() -> None:
    cases = json.loads(OFF_TABLE.read_text())["cases"]
    assert cases
    for case in cases:
        assert substrate_admin_notifications_off(case["value"]) is case["off"], case
        (row,) = _row(_cfg(admin=case["value"]), "linux", lambda _: None)
        assert (row["status"] == "skip" and "administrator" in row["detail"]) is case["off"], case


@pytest.mark.parametrize(
    "cfg,system",
    [
        (_cfg(enabled=False), "linux"),
        (_cfg(asks=False, task_end=False), "linux"),
        (_cfg(admin="off"), "linux"),
        (_cfg(), "freebsd"),
    ],
)
def test_off_or_unsupported_is_a_skip(cfg, system) -> None:
    (row,) = _row(cfg, system, lambda _: None)
    assert row["status"] == "skip"


def test_missing_tool_is_a_warning_with_the_install_step() -> None:
    (row,) = _row(_cfg(), "linux", lambda _: None)
    assert row["status"] == "warn"
    assert "notify-send" in row["detail"]
    assert "libnotify" in row["remediation"]


def test_present_tool_passes() -> None:
    (row,) = _row(_cfg(), "darwin", lambda name: "/usr/bin/" + name)
    assert row["status"] == "pass"
    assert "osascript" in row["detail"]


@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0), reason="needs a directory the user cannot search")
def test_unsearchable_launcher_dir_is_a_skip_row_not_a_crash(_home) -> None:
    # GAP-1045: Path.is_file() re-raises EACCES on Python 3.11-3.13, which
    # killed the whole doctor run on a laptop whose substrate dir is mode 000.
    d = _home / "substrate"
    d.mkdir()
    (d / "contexts.json").write_text("{}")
    d.chmod(0)
    try:
        (row,) = _row(_cfg(substrate=False), "linux", lambda _: None)
    finally:
        d.chmod(0o700)
    assert row["status"] == "skip"
    assert "cannot be read" in row["detail"]
