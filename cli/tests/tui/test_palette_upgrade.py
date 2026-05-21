# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the Step 9 command-palette upgrade.

Covers the pure logic — risk badge derivation, MRU-aware ordering
for empty queries, and needs-arg hinting — without spinning up a
Textual event loop. The async ``test_app_shell`` suite still owns
the end-to-end keyboard/mouse coverage of the drawer.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

import pytest

from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.command_line import infer_command_risk


@dataclass
class _Guardrail:
    mode: str = "ask"
    enabled: bool = True
    connector: str = "openclaw"
    paths: object | None = None


@dataclass
class _Claw:
    mode: str = "openclaw"


@dataclass
class _Config:
    guardrail: _Guardrail = field(default_factory=_Guardrail)
    claw: _Claw = field(default_factory=_Claw)


def _make_app(mru: tuple[str, ...] = ()) -> DefenseClawTUI:
    app = DefenseClawTUI(config=_Config())
    # Inject palette MRU directly into the in-memory state — this
    # bypasses the on-disk store so the test stays hermetic and
    # doesn't depend on whether ``$HOME/.defenseclaw/tui/state.json``
    # exists.
    app.state = replace(app.state, palette_mru=mru)
    return app


def test_risk_inference_examples() -> None:
    """Sanity-check the risk classifier the palette badge uses so a
    drift in classifier semantics is caught here, not by an operator
    seeing the wrong colour badge in production."""

    assert infer_command_risk("info", ("doctor",)) == "read-only"
    assert infer_command_risk("setup", ("setup", "guardrail")) == "setup"
    assert infer_command_risk("daemon", ("restart",)) == "restart"
    assert infer_command_risk("mutation", ("uninstall",)) == "destructive"
    assert infer_command_risk("info", ("keys", "list")) == "read-only"


def test_empty_query_prefers_mru_entries_first() -> None:
    """When the operator opens the palette without typing, their
    most recently used commands must float to the top."""

    app = _make_app(mru=("status", "alerts"))
    matches = app._palette_matches("")
    names = [entry.tui_name for entry in matches]
    # MRU items appear before the "preferred" fallback set.
    assert names[0] == "status"
    assert names[1] == "alerts"


def test_empty_query_dedupes_between_mru_and_preferred() -> None:
    """A command present in both MRU and the preferred starter set
    must not appear twice — the operator would scratch their head
    seeing ``doctor`` listed two rows apart."""

    app = _make_app(mru=("doctor",))
    matches = app._palette_matches("")
    names = [entry.tui_name for entry in matches]
    assert names.count("doctor") == 1
    # And it should still be first because MRU outranks the starter.
    assert names[0] == "doctor"


def test_empty_query_with_no_mru_uses_preferred_set() -> None:
    """Fresh boot / no MRU → fall back to the curated starter pack
    so the palette is never empty."""

    app = _make_app(mru=())
    matches = app._palette_matches("")
    names = [entry.tui_name for entry in matches]
    # The first row should be the legacy preferred head — ``doctor``.
    assert names[0] == "doctor"
    # And the list should be capped at limit, not the full registry.
    assert len(names) <= 12


def test_typed_query_ignores_mru_priority() -> None:
    """Active typing overrides MRU sort so the operator's typed
    fragment always controls ranking — MRU only kicks in for the
    empty-query "what do I want to do?" case."""

    app = _make_app(mru=("uninstall", "reset"))
    matches = app._palette_matches("doctor")
    names = [entry.tui_name for entry in matches]
    assert names, "expected at least one match for 'doctor'"
    # Even though MRU had uninstall/reset at the top, the typed
    # query forces ``doctor`` to surface.
    assert "doctor" in names
    # And MRU entries that don't satisfy the query must be excluded.
    assert "uninstall" not in names
    assert "reset" not in names


def test_needs_arg_entries_carry_hint_metadata() -> None:
    """Step 9 surfaces ``arg_hint`` for commands that demand an
    argument so the palette tells the operator what they have to
    type next."""

    app = _make_app()
    needs_arg_entries = [
        entry for entry in app._command_registry if entry.needs_arg
    ]
    # We don't care about the exact count — only that at least one
    # exists and that every needs_arg entry has a non-empty hint.
    assert needs_arg_entries, "expected registry to contain needs_arg commands"
    for entry in needs_arg_entries:
        assert entry.arg_hint, f"{entry.tui_name} has needs_arg=True but no arg_hint"


def test_limit_is_respected() -> None:
    """Even with a large MRU, the palette must respect the limit
    (default 12) so the drawer never overflows the screen."""

    big_mru = tuple(f"fake-{i}" for i in range(40))
    app = _make_app(mru=big_mru)
    matches = app._palette_matches("")
    # MRU entries that aren't real registry commands get filtered
    # out; the final list should still be capped at limit.
    assert len(matches) <= 12


def test_palette_match_dataclass_immutable() -> None:
    """``CmdEntry`` is a frozen dataclass — palette rendering
    relies on it staying hashable for ``key=str(index)`` row IDs."""

    app = _make_app()
    entry = app._command_registry[0]
    with pytest.raises(Exception):  # FrozenInstanceError subclasses TypeError on some versions
        entry.tui_name = "mutated"  # type: ignore[misc]
