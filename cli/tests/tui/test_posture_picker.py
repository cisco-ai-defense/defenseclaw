# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""LevelPickerScreen (block at, alert at, approval): keyboard choice and cancel."""

from __future__ import annotations

import pytest
from defenseclaw.tui.screens.posture_picker import LevelPickerScreen, approval_choices, level_lines, threshold_choices
from textual.app import App, ComposeResult
from textual.widgets import Static

_UNSET = object()


class PickerHarness(App[None]):
    def __init__(self, screen: LevelPickerScreen) -> None:
        super().__init__()
        self._picker = screen
        self.result: object = _UNSET

    def compose(self) -> ComposeResult:
        yield Static("level-picker harness")

    def on_mount(self) -> None:
        self.push_screen(self._picker, self._done)

    def _done(self, result: str | None) -> None:
        self.result = result


def test_lines_mark_the_current_level_and_escape_markup() -> None:
    lines = level_lines(threshold_choices("block", "HIGH+"), 0)
    assert lines[0].startswith("> \\[1]")
    assert "← current" in lines[1]
    assert all("[/]" in line for line in lines)


@pytest.mark.asyncio
async def test_picker_starts_on_the_current_level_and_digits_move_before_enter() -> None:
    app = PickerHarness(LevelPickerScreen("Approval", approval_choices("HIGH+"), previews={"off": "never asks"}))
    async with app.run_test(size=(80, 24)) as pilot:
        screen = app.screen
        assert isinstance(screen, LevelPickerScreen)
        assert screen.highlighted.value == "HIGH+"
        await pilot.press("1")
        assert screen.highlighted.value == "off"
        assert app.result is _UNSET  # a digit only moves the cursor
        await pilot.press("down", "enter")
        await pilot.pause()
    assert app.result == "CRITICAL"


@pytest.mark.asyncio
async def test_escape_cancels_without_a_choice() -> None:
    app = PickerHarness(LevelPickerScreen("Block at", threshold_choices("block", "CRITICAL")))
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("escape")
        await pilot.pause()
    assert app.result is None
