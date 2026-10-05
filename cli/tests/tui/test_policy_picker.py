# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""PolicyPickerScreen: keyboard choice and cancel."""

from __future__ import annotations

import pytest
from defenseclaw.tui.screens.policy_picker import PolicyPickerScreen
from test_policy_state import DEFAULT, PERMISSIVE, STRICT
from textual.app import App, ComposeResult
from textual.widgets import Static

_UNSET = object()


class PickerHarness(App[None]):
    def __init__(self, selected: str = "") -> None:
        super().__init__()
        self.selected = selected
        self.result: object = _UNSET

    def compose(self) -> ComposeResult:
        yield Static("policy-picker harness")

    def on_mount(self) -> None:
        self.push_screen(PolicyPickerScreen((DEFAULT, PERMISSIVE, STRICT), selected=self.selected), self._done)

    def _done(self, result: str | None) -> None:
        self.result = result


@pytest.mark.asyncio
async def test_picker_starts_on_the_highlighted_policy_and_digits_move_before_enter() -> None:
    app = PickerHarness(selected="permissive")
    async with app.run_test(size=(80, 24)) as pilot:
        screen = app.screen
        assert isinstance(screen, PolicyPickerScreen)
        assert screen.highlighted is PERMISSIVE
        await pilot.press("3")
        assert screen.highlighted is STRICT
        assert app.result is _UNSET  # a digit only moves the cursor
        await pilot.press("up", "enter")
        await pilot.pause()
    assert app.result == "permissive"


@pytest.mark.asyncio
async def test_escape_cancels_without_a_choice() -> None:
    app = PickerHarness()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("escape")
        await pilot.pause()
    assert app.result is None
