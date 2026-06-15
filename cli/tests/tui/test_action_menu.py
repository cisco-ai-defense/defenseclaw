# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Action menu widget parity tests."""

from __future__ import annotations

import pytest
from defenseclaw.tui.widgets.action_menu import ActionMenuScreen, MenuAction
from textual.app import App, ComposeResult
from textual.widgets import Static


class ActionMenuHarness(App[str | None]):
    def __init__(self, actions: tuple[MenuAction, ...]) -> None:
        super().__init__()
        self.actions = actions
        self.result: str | None = None

    def compose(self) -> ComposeResult:
        yield Static("action-menu harness")

    def on_mount(self) -> None:
        self.push_screen(ActionMenuScreen("Actions", self.actions), self._set_result)

    def _set_result(self, result: str | None) -> None:
        self.result = result


@pytest.mark.asyncio
async def test_action_menu_click_runs_clicked_row() -> None:
    app = ActionMenuHarness(
        (
            MenuAction("inspect", "Inspect"),
            MenuAction("install", "Install"),
        )
    )

    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.click("#action-menu-row-1")
        await pilot.pause()

        assert app.result == "install"


@pytest.mark.asyncio
async def test_action_menu_keyboard_skips_disabled_rows() -> None:
    app = ActionMenuHarness(
        (
            MenuAction("inspect", "Inspect"),
            MenuAction("blocked", "Blocked", disabled=True),
            MenuAction("install", "Install"),
        )
    )

    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press("down")
        await pilot.press("enter")
        await pilot.pause()

        assert app.result == "install"


@pytest.mark.asyncio
async def test_action_menu_escape_cancels() -> None:
    app = ActionMenuHarness((MenuAction("inspect", "Inspect"),))

    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press("escape")
        await pilot.pause()

        assert app.result is None
