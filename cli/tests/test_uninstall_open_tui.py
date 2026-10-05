# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""An open ``defenseclaw tui`` stops ``uninstall --all`` before it removes data (GAP-2576, GAP-2585)."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from types import SimpleNamespace

import click
import pytest
from defenseclaw import tui as tui_module
from defenseclaw.commands import cmd_uninstall
from defenseclaw.file_lock import hold_tui_lock, release_tui_lock, tui_lock_held


def _data_dir(tmp_path: Path) -> Path:
    data = tmp_path / ".defenseclaw"
    data.mkdir()
    (data / "config.yaml").write_text("version: 8\n", encoding="utf-8")
    return data


def _lock_files(data: Path) -> list[str]:
    return sorted(name for name in os.listdir(data) if name.endswith(".lock"))


def test_open_tui_blocks_data_removal_until_it_quits(tmp_path: Path) -> None:
    data = _data_dir(tmp_path)
    plan = cmd_uninstall.UninstallPlan(data_dir=str(data), remove_data_dir=True, remove_binaries=True)
    lock = hold_tui_lock(str(data))
    assert lock is not None
    try:
        # The refusal names the exact terminal command (GAP-2585).
        with pytest.raises(click.ClickException, match=r"run `defenseclaw uninstall --all --binaries` in a terminal"):
            cmd_uninstall._validate_plan(plan)
        # The default uninstall keeps the data, so an open TUI does not stop it.
        cmd_uninstall._validate_plan(cmd_uninstall.UninstallPlan(data_dir=str(data)))
    finally:
        release_tui_lock(lock, str(data))
    assert _lock_files(data) == []
    cmd_uninstall._validate_plan(cmd_uninstall.UninstallPlan(data_dir=str(data), remove_data_dir=True))


def test_second_tui_still_blocks_after_the_first_quits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # GAP-2576 verify: the second TUI ran without the shared lock, and the
    # first one removed it on quit, so uninstall --all went ahead.
    data = _data_dir(tmp_path)
    monkeypatch.setattr(os, "getpid", lambda: 1001)
    first = hold_tui_lock(str(data))
    monkeypatch.setattr(os, "getpid", lambda: 1002)
    second = hold_tui_lock(str(data))
    assert first is not None and second is not None
    try:
        monkeypatch.setattr(os, "getpid", lambda: 1001)
        release_tui_lock(first, str(data))
        assert _lock_files(data) == ["tui-1002.lock"]
        assert tui_lock_held(str(data))
    finally:
        monkeypatch.setattr(os, "getpid", lambda: 1002)
        release_tui_lock(second, str(data))
    assert not tui_lock_held(str(data))


def test_lock_left_by_a_closed_tui_does_not_block(tmp_path: Path) -> None:
    data = _data_dir(tmp_path)
    (data / "tui.lock").write_text("", encoding="utf-8")
    (data / "tui-4242.lock").write_text("", encoding="utf-8")
    assert not tui_lock_held(str(data))


def test_dry_run_warns_that_the_real_run_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = _data_dir(tmp_path)
    plan = cmd_uninstall.UninstallPlan(data_dir=str(data), remove_data_dir=True)
    monkeypatch.setattr(cmd_uninstall, "_dispatch_native_windows_uninstall", lambda **_kwargs: False)
    monkeypatch.setattr(cmd_uninstall, "_build_plan", lambda **_kwargs: plan)
    monkeypatch.setattr(cmd_uninstall, "_render_plan", lambda *_args, **_kwargs: None)
    warnings: list[str] = []
    monkeypatch.setattr(cmd_uninstall.ux, "warn", lambda text, **_kwargs: warnings.append(text))
    lock = hold_tui_lock(str(data))
    try:
        cmd_uninstall.uninstall_cmd.callback(
            wipe_data=True,
            binaries=False,
            keep_openclaw=False,
            skip_sandbox_teardown=False,
            dry_run=True,
            yes=True,
        )
    finally:
        release_tui_lock(lock, str(data))
    assert len(warnings) == 1
    assert "a real run would stop" in warnings[0] and "`defenseclaw uninstall --all`" in warnings[0]


def test_tui_wipe_rows_name_the_terminal_command_instead_of_running() -> None:
    from defenseclaw.tui.app import DefenseClawTUI
    from defenseclaw.tui.screens.uninstall import UninstallOption, build_uninstall_model

    model = build_uninstall_model()
    statuses: list[str] = []
    ran: list[object] = []

    def fake_app(action_id: str) -> SimpleNamespace:
        async def push_screen_wait(_screen: object) -> object:
            return next(action for action in model.actions if action.action_id == action_id)

        return SimpleNamespace(
            push_screen_wait=push_screen_wait,
            _set_status=statuses.append,
            notify=lambda *_args, **_kwargs: None,
            run_worker=lambda *args, **_kwargs: ran.append(args),
            _run_command=lambda *args, **_kwargs: None,
            _render_chrome=lambda: None,
            active_panel="overview",
        )

    asyncio.run(DefenseClawTUI._open_uninstall_modal(fake_app(UninstallOption.WIPE_ALL.value)))
    assert ran == []
    assert statuses == ["Quit the TUI (Ctrl+C), then run: defenseclaw uninstall --all --binaries"]

    asyncio.run(DefenseClawTUI._open_uninstall_modal(fake_app(UninstallOption.KEEP_DATA.value)))
    assert len(ran) == 1


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
    assert _lock_files(data) == []
