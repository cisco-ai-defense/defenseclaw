# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the Ctrl+P fuzzy panel jumper.

Tests the pure ``filter_choices`` helper rather than the modal screen
so we don't need a Textual event loop. The modal's render path is a
thin wrapper around the same helper, so coverage of the matcher is
the high-value layer.
"""

from __future__ import annotations

from defenseclaw.tui.screens.panel_jumper import (
    PanelChoice,
    PanelJumperScreen,
    filter_choices,
)


CHOICES = (
    PanelChoice("overview", "Overview", "1"),
    PanelChoice("alerts", "Alerts", "2"),
    PanelChoice("audit", "Audit", "9"),
    PanelChoice("activity", "Activity", "A"),
    PanelChoice("ai", "AI Discovery", "V"),
    PanelChoice("logs", "Logs", "8"),
)


def _names(choices: list[PanelChoice]) -> list[str]:
    return [c.name for c in choices]


def test_empty_query_returns_all_in_declared_order() -> None:
    result = filter_choices("", CHOICES)
    assert _names(result) == [c.name for c in CHOICES]


def test_hotkey_jumps_directly() -> None:
    """Typing a single hotkey letter should select that panel
    even if other panels also share a prefix."""

    result = filter_choices("v", CHOICES)
    # "v" is AI Discovery's hotkey AND a substring of Overview;
    # hotkey match wins so AI Discovery comes first.
    assert result[0].name == "ai"


def test_name_startswith_beats_substring() -> None:
    """A panel whose internal name starts with the query must rank
    higher than one where the query only appears mid-label."""

    result = filter_choices("al", CHOICES)
    # "al" prefixes "alerts" but is also nowhere in any other label.
    assert _names(result) == ["alerts"]


def test_label_startswith_match() -> None:
    """Queries that match the human label prefix (not the internal
    name) still find the panel — operators read labels, not names."""

    result = filter_choices("aud", CHOICES)
    assert "audit" in _names(result)
    assert result[0].name == "audit"


def test_substring_match_lower_priority() -> None:
    """Substring matches still appear, just below prefix matches."""

    # "ert" appears mid-label in "Alerts"
    result = filter_choices("ert", CHOICES)
    assert "alerts" in _names(result)


def test_initials_match() -> None:
    """Initials of multi-word labels should resolve. "AI Discovery"
    → initials "ad" → match."""

    result = filter_choices("ad", CHOICES)
    assert "ai" in _names(result)


def test_no_match_returns_empty() -> None:
    """Junk query produces an empty list, not a crash."""

    result = filter_choices("zzzzzz", CHOICES)
    assert result == []


def test_case_insensitive() -> None:
    """Case must not affect matching — operators sometimes
    Shift-type, sometimes don't."""

    assert _names(filter_choices("ALERTS", CHOICES)) == ["alerts"]
    assert _names(filter_choices("Alerts", CHOICES)) == ["alerts"]
    assert _names(filter_choices("aLeRtS", CHOICES)) == ["alerts"]


def test_sort_is_stable_within_score() -> None:
    """Choices with the same match score must keep their declared
    order so muscle memory is predictable."""

    result = filter_choices("a", CHOICES)
    a_names = _names(result)
    # "a" is Activity's hotkey (exact-match score 0), so Activity
    # wins outright. The remaining "a*" panels (alerts, audit, ai)
    # share name-startswith score 1 and must follow declared order.
    assert a_names[0] == "activity"
    assert a_names[1:4] == ["alerts", "audit", "ai"]


def test_whitespace_query_treated_as_empty() -> None:
    """Pure-whitespace queries shouldn't filter anything out;
    matches empty-query behaviour."""

    result = filter_choices("   ", CHOICES)
    assert _names(result) == [c.name for c in CHOICES]


# ---------------------------------------------------------------------------
# PanelJumperScreen action coverage
#
# Modal screens normally need a Textual harness to dispatch ``dismiss``,
# but the actions we care about (cursor wrap, choose, cancel) only
# call ``self.dismiss(...)`` and read ``self._filtered``. We instantiate
# the screen directly and monkey-patch ``dismiss`` to capture the value
# — no event loop required, so the tests stay sub-second.
# ---------------------------------------------------------------------------


def _new_screen(choices: tuple[PanelChoice, ...] = CHOICES) -> tuple[PanelJumperScreen, list[object]]:
    screen = PanelJumperScreen(choices)
    captured: list[object] = []
    screen.dismiss = lambda value=None: captured.append(value)  # type: ignore[method-assign]
    # Cursor actions call ``_refresh_list`` which queries a mounted
    # ``Static#panel-jumper-list``. We're testing the action logic,
    # not the DOM refresh, so stub it out to keep the test
    # event-loop-free.
    screen._refresh_list = lambda: None  # type: ignore[method-assign]
    return screen, captured


def test_action_cursor_down_wraps_at_end() -> None:
    """Pressing Down past the last row wraps to 0 — mirrors the Go
    TUI's quick-open and prevents the cursor from going off-screen."""

    screen, _ = _new_screen()
    last = len(screen._filtered) - 1
    screen.selected_index = last
    screen.action_cursor_down()
    assert screen.selected_index == 0


def test_action_cursor_up_wraps_at_start() -> None:
    """Pressing Up from the first row wraps to the last so muscle
    memory of 'one Up gets me to the bottom' works."""

    screen, _ = _new_screen()
    screen.selected_index = 0
    screen.action_cursor_up()
    assert screen.selected_index == len(screen._filtered) - 1


def test_action_cursor_handlers_safe_on_empty_filter() -> None:
    """If the user typed a junk query and the filtered list is empty,
    Up/Down must NOT IndexError. They early-return so the selection
    stays at 0."""

    screen, _ = _new_screen()
    screen._filtered = []
    screen.selected_index = 0
    screen.action_cursor_up()
    screen.action_cursor_down()
    assert screen.selected_index == 0


def test_action_choose_dispatches_selected_name() -> None:
    """Pressing Enter dismisses the modal with the highlighted
    panel's internal name (not the label)."""

    screen, captured = _new_screen()
    # Pick the third row deliberately so we'd catch an off-by-one.
    screen.selected_index = 2
    expected = screen._filtered[2].name
    screen.action_choose()
    assert captured == [expected]


def test_action_choose_dismisses_none_on_empty() -> None:
    """When the filter is empty (user typed gibberish) Enter must
    cancel cleanly rather than IndexError into ``_filtered[0]``."""

    screen, captured = _new_screen()
    screen._filtered = []
    screen.action_choose()
    assert captured == [None]


def test_action_choose_clamps_stale_selected_index() -> None:
    """Defensive: if ``selected_index`` somehow points past the end
    of ``_filtered`` (race between Input.Changed and a key event)
    we clamp to the last row instead of crashing."""

    screen, captured = _new_screen()
    # Simulate the race: list shrinks but selected_index is stale.
    screen._filtered = list(CHOICES[:2])
    screen.selected_index = 99
    screen.action_choose()
    # Should have dismissed with the LAST filtered choice's name.
    assert captured == [screen._filtered[-1].name]


def test_action_cancel_returns_none() -> None:
    """Esc dismisses with None so the caller knows the operator
    bailed out without picking anything."""

    screen, captured = _new_screen()
    screen.action_cancel()
    assert captured == [None]
