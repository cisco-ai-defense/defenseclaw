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

from defenseclaw.tui.screens.panel_jumper import PanelChoice, filter_choices


CHOICES = (
    PanelChoice("overview", "Overview", "1"),
    PanelChoice("alerts", "Alerts", "2"),
    PanelChoice("audit", "Audit", "9"),
    PanelChoice("activity", "Activity", "A"),
    PanelChoice("ai", "AI Discovery", "V"),
    PanelChoice("logs", "Logs", "8"),
    PanelChoice("policy", "Policy", "7"),
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
