# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Ctrl+\\ theme picker modal.

These are pure-Python tests that exercise the modal in isolation via
``Textual``'s ``App.run_test`` harness. They don't depend on the full
DefenseClaw TUI shell so they stay fast and avoid the auto-load
worker pollution that plagues integration tests.
"""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Static

from defenseclaw.tui.screens.theme_picker import (
    THEME_CHOICES,
    ThemeChoice,
    ThemePickerScreen,
)


class _HarnessApp(App[None]):
    """Minimal app that pushes the theme picker on mount.

    Captures the dismiss value so tests can assert what the picker
    returned for a given keystroke sequence.
    """

    def __init__(self, current_theme: str = "textual-dark") -> None:
        super().__init__()
        self._current_theme = current_theme
        self.dismissed: str | None = "__UNSET__"  # sentinel

    def compose(self) -> ComposeResult:
        yield Static("backdrop")

    async def on_mount(self) -> None:
        def _capture(result: str | None) -> None:
            self.dismissed = result

        self.push_screen(
            ThemePickerScreen(current_theme=self._current_theme), _capture
        )


def test_theme_choices_have_no_duplicates() -> None:
    """Each Textual theme id appears exactly once in the picker list."""

    ids = [choice.name for choice in THEME_CHOICES]
    assert len(ids) == len(set(ids)), "duplicate theme ids in THEME_CHOICES"


def test_theme_choices_include_ansi_themes_first() -> None:
    """``ansi-dark`` and ``ansi-light`` lead the list — they're the headline 8.2.5 feature."""

    assert THEME_CHOICES[0].name == "ansi-dark"
    assert THEME_CHOICES[1].name == "ansi-light"
    assert THEME_CHOICES[0].group == "ANSI"
    assert THEME_CHOICES[1].group == "ANSI"


def test_theme_choices_only_reference_real_textual_themes() -> None:
    """Every choice id MUST exist in Textual's built-in registry.

    The picker promises live-preview; a typo here would crash the
    preview branch at runtime when the operator scrolls onto a bad
    row. The test pins that contract at build time.
    """

    from textual.theme import BUILTIN_THEMES

    for choice in THEME_CHOICES:
        assert choice.name in BUILTIN_THEMES, (
            f"theme {choice.name!r} from THEME_CHOICES is not a Textual built-in"
        )


def test_theme_choice_is_frozen() -> None:
    """``ThemeChoice`` is a frozen dataclass — accidental mutation should raise."""

    choice = ThemeChoice("ansi-dark", "ANSI Dark", "ANSI")
    with pytest.raises(Exception):
        choice.name = "ansi-light"  # type: ignore[misc]


@pytest.mark.asyncio
async def test_enter_commits_current_selection() -> None:
    """Pressing Enter without moving the cursor returns the initial theme."""

    app = _HarnessApp(current_theme="ansi-dark")
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
    assert app.dismissed == "ansi-dark"


@pytest.mark.asyncio
async def test_escape_returns_none_and_rolls_back_preview() -> None:
    """Cancelling reverts the preview and dismisses with ``None``."""

    app = _HarnessApp(current_theme="textual-dark")
    async with app.run_test() as pilot:
        await pilot.pause()
        # Move down a few times so the preview lands on a different
        # theme, then Escape — the picker should set ``app.theme``
        # back to the original.
        await pilot.press("down")
        await pilot.press("down")
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
    assert app.dismissed is None
    # ``app.theme`` is left at ``textual-dark`` because the modal
    # rolled back on cancel.
    assert app.theme == "textual-dark"


@pytest.mark.asyncio
async def test_down_then_enter_commits_next_theme() -> None:
    """Scrolling down once and pressing Enter returns the next theme id."""

    app = _HarnessApp(current_theme="ansi-dark")  # index 0
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("down")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
    # ``ansi-dark`` (index 0) -> ``ansi-light`` (index 1) per
    # ``THEME_CHOICES`` ordering.
    assert app.dismissed == THEME_CHOICES[1].name


@pytest.mark.asyncio
async def test_unknown_initial_theme_starts_at_index_zero() -> None:
    """A persisted theme id Textual no longer ships falls back to index 0."""

    app = _HarnessApp(current_theme="some-removed-theme-from-future")
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
    # Cursor started at 0 (first ANSI theme) because the persisted
    # id wasn't found in the choice list.
    assert app.dismissed == THEME_CHOICES[0].name
