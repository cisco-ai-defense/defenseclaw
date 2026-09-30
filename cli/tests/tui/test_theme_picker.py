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
from defenseclaw.tui.screens.theme_picker import (
    THEME_CHOICES,
    ThemeChoice,
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
        assert choice.name in BUILTIN_THEMES, f"theme {choice.name!r} from THEME_CHOICES is not a Textual built-in"


def test_theme_choice_is_frozen() -> None:
    """``ThemeChoice`` is a frozen dataclass — accidental mutation should raise."""

    choice = ThemeChoice("ansi-dark", "ANSI Dark", "ANSI")
    with pytest.raises(Exception):
        choice.name = "ansi-light"  # type: ignore[misc]
