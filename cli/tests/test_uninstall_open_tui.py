# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""An open ``defenseclaw tui`` stops ``uninstall --all`` before it removes data (GAP-2576)."""

from __future__ import annotations

from pathlib import Path

import click
import pytest
from defenseclaw import tui as tui_module
from defenseclaw.commands import cmd_uninstall
from defenseclaw.file_lock import TUI_LOCK_FILENAME, hold_tui_lock, release_tui_lock, tui_lock_held


def _data_dir(tmp_path: Path) -> Path:
    data = tmp_path / ".defenseclaw"
    data.mkdir()
    (data / "config.yaml").write_text("version: 8\n", encoding="utf-8")
    return data


def test_open_tui_blocks_data_removal_until_it_quits(tmp_path: Path) -> None:
    data = _data_dir(tmp_path)
    plan = cmd_uninstall.UninstallPlan(data_dir=str(data), remove_data_dir=True)
    lock = hold_tui_lock(str(data))
    assert lock is not None
    try:
        with pytest.raises(click.ClickException, match=r"defenseclaw tui\) is open"):
            cmd_uninstall._validate_plan(plan)
        # The default uninstall keeps the data, so an open TUI does not stop it.
        cmd_uninstall._validate_plan(cmd_uninstall.UninstallPlan(data_dir=str(data)))
    finally:
        release_tui_lock(lock, str(data))
    assert not (data / TUI_LOCK_FILENAME).exists()
    cmd_uninstall._validate_plan(plan)


def test_lock_left_by_a_closed_tui_does_not_block(tmp_path: Path) -> None:
    data = _data_dir(tmp_path)
    (data / TUI_LOCK_FILENAME).write_text("", encoding="utf-8")
    assert not tui_lock_held(str(data))


def test_tui_holds_the_lock_while_it_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from defenseclaw import config
    from defenseclaw.tui import app

    data = _data_dir(tmp_path)
    seen: list[bool] = []

    class FakeTUI:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def run(self) -> None:
            seen.append(tui_lock_held(str(data)))

    monkeypatch.setattr(app, "DefenseClawTUI", FakeTUI)
    monkeypatch.setattr(tui_module, "_harden_textual_stdin_decoder", lambda: None)
    monkeypatch.setattr(tui_module, "_hold_windows_ctrl_c_until_exit", lambda: None)
    monkeypatch.setattr(config, "require_v8_config", lambda **_kwargs: None)
    monkeypatch.setattr(config, "source_config_version", lambda: 8)
    monkeypatch.setattr(config, "load", lambda **_kwargs: object())
    monkeypatch.setattr(config, "default_data_path", lambda: data)
    monkeypatch.setattr(config, "config_path", lambda: data / "config.yaml")

    tui_module.run_textual_tui()

    assert seen == [True]
    assert not (data / TUI_LOCK_FILENAME).exists()
