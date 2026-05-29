# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Mode picker parity tests."""

from __future__ import annotations

import pytest
from defenseclaw.tui.screens.mode_picker import (
    MODE_PICKER_CHOICES,
    ModePickerScreen,
    choice_for_hotkey,
    choice_for_wire,
    preview_for_switch,
)
from textual.app import App, ComposeResult
from textual.widgets import Static


class ModePickerHarness(App[str | None]):
    def __init__(self, current: str = "openclaw") -> None:
        super().__init__()
        self.current = current
        self.result: str | None = None

    def compose(self) -> ComposeResult:
        yield Static("mode-picker harness")

    def on_mount(self) -> None:
        self.push_screen(ModePickerScreen(self.current), self._set_result)

    def _set_result(self, result: str | None) -> None:
        self.result = result


def test_mode_picker_choices_cover_go_connectors() -> None:
    assert [choice.wire for choice in MODE_PICKER_CHOICES] == [
        "openclaw",
        "zeptoclaw",
        "claudecode",
        "codex",
        "hermes",
        "cursor",
        "windsurf",
        "geminicli",
        "copilot",
    ]
    assert choice_for_wire("claude-code").wire == "claudecode"
    assert choice_for_hotkey("c").wire == "codex"
    assert "refresh hooks" in preview_for_switch("codex", "codex")


@pytest.mark.asyncio
async def test_mode_picker_hotkey_returns_connector() -> None:
    app = ModePickerHarness("openclaw")

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("c")
        await pilot.pause()

        assert app.result == "codex"


@pytest.mark.asyncio
async def test_mode_picker_mouse_click_returns_connector() -> None:
    app = ModePickerHarness("openclaw")

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.click("#action-menu-row-3")
        await pilot.pause()

        assert app.result == "codex"
