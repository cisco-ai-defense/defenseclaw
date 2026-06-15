# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the shared connector-filter helper."""

from __future__ import annotations

from defenseclaw.tui.services import connector_filter as cf


def test_active_connector_names_drops_blanks_and_keeps_order() -> None:
    modes = (("antigravity", "observe"), ("", ""), ("codex", "action"))
    assert cf.active_connector_names(modes) == ["antigravity", "codex"]
    assert cf.active_connector_name(modes) == "antigravity"
    assert cf.active_connector_name(()) == ""


def test_cycle_filter_rotates_all_then_each_then_back() -> None:
    names = ["antigravity", "codex", "claude-code"]
    assert cf.cycle_filter(cf.ALL, names) == "antigravity"
    assert cf.cycle_filter("antigravity", names) == "codex"
    assert cf.cycle_filter("codex", names) == "claude-code"
    assert cf.cycle_filter("claude-code", names) == cf.ALL
    # backwards
    assert cf.cycle_filter(cf.ALL, names, delta=-1) == "claude-code"


def test_cycle_filter_collapses_to_all_when_single_or_none() -> None:
    assert cf.cycle_filter("anything", ["solo"]) == cf.ALL
    assert cf.cycle_filter("anything", []) == cf.ALL


def test_normalize_filter_drops_stale_selection() -> None:
    names = ["antigravity", "codex"]
    assert cf.normalize_filter("codex", names) == "codex"
    assert cf.normalize_filter("retired", names) == cf.ALL
    assert cf.normalize_filter("", names) == cf.ALL


def test_chip_segments_hidden_for_single_connector() -> None:
    assert cf.chip_segments(cf.ALL, ["solo"]) == []
    assert cf.chip_segments(cf.ALL, []) == []


def test_chip_segments_marks_active() -> None:
    names = ["antigravity", "codex"]
    segs = cf.chip_segments("codex", names)
    assert segs == [("All", False), ("antigravity", False), ("codex", True)]
    segs_all = cf.chip_segments(cf.ALL, names)
    assert segs_all[0] == ("All", True)


def test_filter_allows_exact_and_all() -> None:
    assert cf.filter_allows(cf.ALL, "codex") is True
    assert cf.filter_allows(cf.ALL, "") is True
    assert cf.filter_allows("codex", "codex") is True
    assert cf.filter_allows("codex", "CODEX") is True
    assert cf.filter_allows("codex", "antigravity") is False
    # explicit filter hides rows with no attributed connector
    assert cf.filter_allows("codex", "") is False


def test_filter_allows_is_exact_not_substring() -> None:
    # The chip selection is always a full connector name, so a selection must
    # not bleed into a different connector whose name contains it as a
    # substring (regression: "claw" used to match "openclaw"/"zeptoclaw").
    assert cf.filter_allows("claw", "openclaw") is False
    assert cf.filter_allows("claw", "zeptoclaw") is False
    assert cf.filter_allows("openclaw", "zeptoclaw") is False
    assert cf.filter_allows("openclaw", "openclaw") is True
