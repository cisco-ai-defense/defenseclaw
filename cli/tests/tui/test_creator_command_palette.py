# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Phase 12 Ctrl+K palette catalogue."""

from __future__ import annotations

from defenseclaw.tui.creator.command_palette import (
    COMMANDS,
    Command,
    filter_commands,
    find_command,
)
from defenseclaw.tui.creator.playground_model import SECTION_DEFS


def _ids() -> list[str]:
    return [c.id for c in COMMANDS]


def test_every_section_has_a_jump_command():
    section_ids = {s.id for s in SECTION_DEFS}
    palette_targets = {
        cmd.target for cmd in COMMANDS if cmd.kind == "jump"
    }
    assert section_ids == palette_targets


def test_command_ids_are_unique():
    ids = _ids()
    assert len(ids) == len(set(ids)), "duplicate Command.id detected"


def test_filter_commands_empty_query_returns_all():
    out = filter_commands("")
    assert {c.id for c in out} == set(_ids())


def test_filter_commands_substring_matches_label():
    out = filter_commands("guardrail")
    ids = [c.id for c in out]
    assert "jump.guardrail" in ids
    # The matched command should rank near the top
    assert ids[0] == "jump.guardrail"


def test_filter_commands_alias_match():
    out = filter_commands("hilt")
    ids = [c.id for c in out]
    assert "jump.guardrail" in ids


def test_filter_commands_hint_match_returns_command():
    out = filter_commands("rescan")
    ids = [c.id for c in out]
    assert "jump.watch" in ids


def test_filter_commands_subsequence_match():
    # ``yam`` should fuzz-match "Emit gateway YAML"
    out = filter_commands("yam")
    ids = [c.id for c in out]
    assert "emit.yaml" in ids


def test_filter_commands_no_match_returns_empty_list():
    out = filter_commands("zzzzz_nothing_matches")
    assert out == []


def test_filter_commands_is_deterministic_for_ties():
    a = filter_commands("toggle")
    b = filter_commands("toggle")
    assert [c.id for c in a] == [c.id for c in b]


def test_find_command_returns_command_for_known_id():
    cmd = find_command("action.save")
    assert isinstance(cmd, Command)
    assert cmd.kind == "save"


def test_find_command_returns_none_for_unknown_id():
    assert find_command("nonexistent.command") is None


def test_kinds_are_well_formed():
    valid_kinds = {
        "jump",
        "toggle",
        "save",
        "cancel",
        "lint",
        "emit-yaml",
        "emit-script",
        "diff",
    }
    for cmd in COMMANDS:
        assert cmd.kind in valid_kinds


def test_jump_targets_are_known_section_ids():
    section_ids = {s.id for s in SECTION_DEFS}
    for cmd in COMMANDS:
        if cmd.kind == "jump":
            assert cmd.target in section_ids


def test_toggle_targets_are_known_panel_ids():
    expected = {"test", "diff"}
    for cmd in COMMANDS:
        if cmd.kind == "toggle":
            assert cmd.target in expected
