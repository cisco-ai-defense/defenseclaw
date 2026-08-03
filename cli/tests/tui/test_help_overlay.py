# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the ``?`` help overlay (Step 7).

Verifies the three-section structure (Global / Active panel /
While running) and confirms the active-panel block changes when the
operator switches panels — the overlay's whole point is that it's
context-aware.
"""

from __future__ import annotations

from dataclasses import dataclass

from defenseclaw.tui.app import DefenseClawTUI


@dataclass
class _Guardrail:
    connector: str = ""


@dataclass
class _Claw:
    mode: str = ""


@dataclass
class _Config:
    guardrail: _Guardrail = None  # type: ignore[assignment]
    claw: _Claw = None  # type: ignore[assignment]


def _config_for(connector: str = "openclaw") -> _Config:
    return _Config(
        guardrail=_Guardrail(connector=connector),
        claw=_Claw(mode="openclaw"),
    )


def test_help_sections_has_three_blocks() -> None:
    app = DefenseClawTUI(config=_config_for())
    sections = app._help_sections()
    titles = [title for title, _ in sections]
    assert titles[0] == "Global"
    assert titles[1].startswith("Active panel")
    assert titles[2] == "While a command is running"


def test_active_panel_section_switches_with_panel() -> None:
    """The middle "Active panel" block must reflect the current
    panel so the operator sees the right cheat sheet."""

    app = DefenseClawTUI(config=_config_for())
    app.active_panel = "alerts"
    alerts_keys = {key for key, _ in app._help_sections()[1][1]}
    app.active_panel = "logs"
    logs_keys = {key for key, _ in app._help_sections()[1][1]}
    # Alerts has severity filters (1-5), Logs doesn't; Logs has e/w,
    # Alerts doesn't — so the two blocks must be different.
    assert alerts_keys != logs_keys
    assert "1-5" in alerts_keys
    assert "e" in logs_keys


def test_running_section_includes_signal_keys() -> None:
    app = DefenseClawTUI(config=_config_for())
    running = app._help_sections()[2][1]
    keys = {k for k, _ in running}
    # These are the keys that the running-state UI surfaces — if
    # any disappears we should explicitly remove it here too.
    assert "Ctrl+C" in keys
    assert "!" in keys
    assert "Y" in keys
    assert "Ctrl+S" in keys
    assert "D" in keys


def test_ai_panel_help_includes_table_switch_shortcut() -> None:
    app = DefenseClawTUI(config=_config_for())
    app.active_panel = "ai"
    ai_shortcuts = dict(app._help_sections()[1][1])

    assert ai_shortcuts["t"] == "Switch product / model table"
    assert ai_shortcuts["j/k or Up/Down"] == "Navigate the selected table"


def test_help_body_text_includes_section_titles() -> None:
    app = DefenseClawTUI(config=_config_for())
    body = app._render_help_body()
    assert "Global" in body
    assert "Active panel" in body
    assert "While a command is running" in body
    assert "DefenseClaw Keybindings" in body


def test_unknown_active_panel_falls_back_gracefully() -> None:
    """Setting active_panel to something the cheat sheet doesn't
    know about must not crash — overlay should show a placeholder."""

    app = DefenseClawTUI(config=_config_for())
    app.active_panel = "__nonexistent__"
    sections = app._help_sections()
    active_block = sections[1][1]
    assert len(active_block) == 1
    assert "no panel-specific shortcuts" in active_block[0][0]
