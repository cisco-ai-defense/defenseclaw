# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Notifications and uninstall modal parity tests."""

from __future__ import annotations

import pytest
from defenseclaw.tui.screens.consequence import ConsequenceAction
from defenseclaw.tui.screens.notifications import (
    NotificationsToggleScreen,
    build_notifications_model,
    desired_notifications_action,
    notifications_command,
)
from defenseclaw.tui.screens.uninstall import (
    UninstallOption,
    UninstallScreen,
    build_uninstall_model,
    uninstall_command_for_option,
)
from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import Static


class ModalHarness(App[ConsequenceAction | None]):
    def __init__(self, screen: Screen[ConsequenceAction | None]) -> None:
        super().__init__()
        self.screen_to_push = screen
        self.result: ConsequenceAction | None = None

    def compose(self) -> ComposeResult:
        yield Static("modal harness")

    def on_mount(self) -> None:
        self.push_screen(self.screen_to_push, self._set_result)

    def _set_result(self, result: ConsequenceAction | None) -> None:
        self.result = result


def test_notifications_model_matches_go_oracle_copy_and_argv() -> None:
    assert desired_notifications_action(True) == "off"
    assert notifications_command(True).args == ("setup", "notifications", "off", "--yes")
    assert desired_notifications_action(False) == "on"
    assert notifications_command(False).args == ("setup", "notifications", "on", "--yes")

    on_model = build_notifications_model(False, "Linux")
    on_copy = "\n".join((on_model.summary, *on_model.details, on_model.consequence))
    assert "asset-policy blocks" in on_copy
    assert "would-blocks" in on_copy
    assert "HITL approval" in on_copy
    assert "does not approve" in on_copy

    off_model = build_notifications_model(True, "Darwin")
    off_copy = "\n".join((off_model.summary, *off_model.details))
    assert "Event history" in off_copy
    assert "telemetry destinations" in off_copy
    assert "webhooks" in off_copy
    assert "not affected" in off_copy


def test_windows_notifications_model_is_native_and_has_toggle_command() -> None:
    model = build_notifications_model(True, "Windows")
    assert model.title == "Desktop notifications"
    assert "Will become:" in model.summary
    assert model.actions[0].label == "Confirm"
    assert model.actions[0].command == notifications_command(True)


def test_uninstall_model_defaults_to_dry_run_and_maps_all_argv() -> None:
    model = build_uninstall_model()

    assert model.default_action().action_id == UninstallOption.DRY_RUN.value
    assert uninstall_command_for_option(UninstallOption.DRY_RUN).args == ("uninstall", "--dry-run")
    assert uninstall_command_for_option(UninstallOption.KEEP_DATA).args == ("uninstall", "--yes")
    assert uninstall_command_for_option(UninstallOption.WIPE_DATA).args == ("uninstall", "--all", "--yes")
    assert "--yes" in "\n".join((*model.details, model.consequence))
    assert "dry-run" in model.actions[0].description


@pytest.mark.asyncio
async def test_uninstall_modal_renders_red_danger_border() -> None:
    from defenseclaw.tui.theme import DEFAULT_TOKENS
    from textual.containers import Vertical

    app = ModalHarness(UninstallScreen())
    async with app.run_test(size=(110, 34)) as pilot:
        await pilot.pause()
        dialog = app.screen.query_one("#consequence-dialog", Vertical)
        assert dialog.styles.border.top[1].hex.lower() == DEFAULT_TOKENS.accent_red.lower()


@pytest.mark.asyncio
async def test_notifications_modal_click_confirms_cli_argv() -> None:
    app = ModalHarness(NotificationsToggleScreen(currently_enabled=False, system="Linux"))

    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.click("#consequence-action-0")
        await pilot.pause()

        assert app.result is not None
        assert app.result.command is not None
        assert app.result.command.args == ("setup", "notifications", "on", "--yes")


@pytest.mark.asyncio
async def test_uninstall_modal_hotkey_then_double_enter_confirms_wipe_argv() -> None:
    app = ModalHarness(UninstallScreen())

    async with app.run_test(size=(110, 34)) as pilot:
        await pilot.press("a")  # select the wipe row (danger)
        await pilot.press("enter")  # arms only
        await pilot.pause()
        assert app.result is None

        await pilot.press("enter")  # confirms
        await pilot.pause()

        assert app.result is not None
        assert app.result.action_id == UninstallOption.WIPE_DATA.value
        assert app.result.command is not None
        assert app.result.command.args == ("uninstall", "--all", "--yes")


@pytest.mark.asyncio
async def test_uninstall_modal_double_click_confirms_keep_data_argv() -> None:
    app = ModalHarness(UninstallScreen())

    async with app.run_test(size=(110, 34)) as pilot:
        await pilot.click("#consequence-action-1")  # arms only (danger)
        await pilot.pause()
        assert app.result is None

        await pilot.click("#consequence-action-1")  # confirms
        await pilot.pause()

        assert app.result is not None
        assert app.result.action_id == UninstallOption.KEEP_DATA.value
        assert app.result.command is not None
        assert app.result.command.args == ("uninstall", "--yes")


@pytest.mark.asyncio
async def test_uninstall_modal_dry_run_default_confirms_in_one_step() -> None:
    # The default dry-run row is benign (danger=False) -> single Enter runs it.
    app = ModalHarness(UninstallScreen())

    async with app.run_test(size=(110, 34)) as pilot:
        await pilot.press("enter")
        await pilot.pause()

        assert app.result is not None
        assert app.result.action_id == UninstallOption.DRY_RUN.value
        assert app.result.command.args == ("uninstall", "--dry-run")
