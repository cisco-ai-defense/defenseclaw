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
    def __init__(self, current: str = "openclaw", *, os_name: str | None = None) -> None:
        super().__init__()
        self.current = current
        self.os_name = os_name
        self.result: str | None = None

    def compose(self) -> ComposeResult:
        yield Static("mode-picker harness")

    def on_mount(self) -> None:
        self.push_screen(ModePickerScreen(self.current, os_name=self.os_name), self._set_result)

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
        "openhands",
        "antigravity",
        "opencode",
        "omnigent",
    ]
    assert choice_for_wire("claude-code").wire == "claudecode"
    assert choice_for_hotkey("c").wire == "codex"
    assert choice_for_hotkey("m").wire == "omnigent"
    assert "refresh hooks" in preview_for_switch("codex", "codex")
    assert "ALLOW/ASK/DENY" in preview_for_switch("openclaw", "omnigent")
    assert "Python policy runtime" in preview_for_switch("omnigent", "omnigent")


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
        screen = app.screen
        assert isinstance(screen, ModePickerScreen)
        codex_row = next(index for index, choice in enumerate(screen.choices) if choice.wire == "codex")
        await pilot.click(f"#action-menu-row-{codex_row}")
        await pilot.pause()

        assert app.result == "codex"


def test_mode_picker_hint_is_built_from_visible_rows() -> None:
    # macOS/Linux: every connector is visible, so the hint must advertise the
    # opencode (e) and antigravity (a) hotkeys the old hardcoded literal dropped.
    mac = ModePickerScreen(os_name="darwin")
    hint = mac._hint_text()
    assert "e" in hint and "a" in hint
    for choice in mac.choices:
        assert choice.hotkey in hint

    # Windows: proxy connectors are hidden, so their hotkeys must NOT be
    # advertised as jump keys.
    win = ModePickerScreen(os_name="windows")
    jump_keys = "/".join(c.hotkey for c in win.choices)
    assert "o" not in jump_keys.split("/")
    assert "z" not in jump_keys.split("/")


def test_mode_picker_hotkey_resolves_against_visible_rows_only() -> None:
    win = ModePickerScreen(os_name="windows")
    # openclaw/zeptoclaw are hidden on Windows -> their hotkeys are no-ops.
    assert win._visible_choice_for_hotkey("o") is None
    assert win._visible_choice_for_hotkey("z") is None
    # A supported connector still resolves.
    assert win._visible_choice_for_hotkey("c").wire == "codex"


def test_mode_picker_default_never_fabricates_hidden_connector() -> None:
    # Empty / unknown current wire lands on the first *visible* row, not the
    # hardcoded openclaw sentinel.
    assert ModePickerScreen("", os_name="darwin").current_wire == MODE_PICKER_CHOICES[0].wire
    assert ModePickerScreen("garbage-connector").current_wire == ModePickerScreen().choices[0].wire
    # On Windows openclaw is hidden, so even an explicit "openclaw" falls back
    # to the first visible row rather than selecting an unrunnable connector.
    win = ModePickerScreen("openclaw", os_name="windows")
    assert win.current_wire != "openclaw"
    assert win.current_wire == win.choices[0].wire


@pytest.mark.asyncio
async def test_mode_picker_windows_hidden_hotkey_is_noop() -> None:
    app = ModePickerHarness("claudecode", os_name="windows")

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("o")  # openclaw is hidden on Windows -> no-op
        await pilot.pause()
        assert app.result is None
        assert isinstance(app.screen, ModePickerScreen)  # still open

        await pilot.press("c")  # codex is supported -> dismisses
        await pilot.pause()
        assert app.result == "codex"
