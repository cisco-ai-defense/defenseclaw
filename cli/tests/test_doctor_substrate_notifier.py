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

from types import SimpleNamespace

import pytest
from defenseclaw.commands.cmd_doctor import _check_substrate_notifier, _DoctorResult
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


def test_no_row_when_substrate_is_off() -> None:
    assert _row(_cfg(substrate=False), "linux", lambda _: None) == []


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
