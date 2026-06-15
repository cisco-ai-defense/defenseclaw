# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Connector-gated Plugins tab tests.

Mirrors the Go TUI's ``panelHidden`` contract: the Plugins panel is
visible only when the active connector is OpenClaw. For any other
connector the tab is suppressed, the digit ``5`` shortcut is a silent
no-op, and Tab/Shift+Tab cycling skips it.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
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


def _config_for(connector: str) -> _Config:
    return _Config(guardrail=_Guardrail(connector=connector), claw=_Claw(mode="openclaw"))


def test_openclaw_connector_shows_plugins() -> None:
    app = DefenseClawTUI(config=_config_for("openclaw"))
    assert app._panel_hidden("plugins") is False
    assert "plugins" in app._visible_panels()


def test_non_openclaw_connector_hides_plugins() -> None:
    app = DefenseClawTUI(config=_config_for("claudecode"))
    assert app._panel_hidden("plugins") is True
    assert "plugins" not in app._visible_panels()


def test_only_plugins_is_connector_gated() -> None:
    """Defensive: other panels must not be hidden by the same logic."""

    app = DefenseClawTUI(config=_config_for("claudecode"))
    for panel in ("overview", "alerts", "skills", "mcps", "logs", "audit", "setup"):
        assert app._panel_hidden(panel) is False, panel


def test_plugins_gate_follows_filter_in_multi_connector(monkeypatch) -> None:
    """E3/8.13: in multi-connector the Plugins tab tracks the shared connector
    filter — filtering to OpenClaw exposes the tab even when the primary
    connector is Codex, and filtering to a non-OpenClaw connector hides it
    (matching the body's openclaw-only notice)."""

    app = DefenseClawTUI(config=_config_for("codex"))
    monkeypatch.setattr(app, "_active_connector_names", lambda: ["codex", "openclaw"])

    app.connector_filter = "openclaw"
    assert app._panel_hidden("plugins") is False
    assert "plugins" in app._visible_panels()

    app.connector_filter = "codex"
    assert app._panel_hidden("plugins") is True
    assert "plugins" not in app._visible_panels()


@pytest.mark.asyncio
async def test_digit_five_is_noop_when_plugins_hidden() -> None:
    app = DefenseClawTUI(config=_config_for("claudecode"))
    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.pause()
        await pilot.press("5")
        await pilot.pause()
        assert app.active_panel != "plugins"


@pytest.mark.asyncio
async def test_digit_five_switches_when_plugins_visible() -> None:
    app = DefenseClawTUI(config=_config_for("openclaw"))
    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.pause()
        await pilot.press("5")
        await pilot.pause()
        assert app.active_panel == "plugins"


@pytest.mark.asyncio
async def test_tab_cycling_skips_hidden_plugins() -> None:
    """Tab and Shift+Tab must skip Plugins on non-OpenClaw connectors."""

    app = DefenseClawTUI(config=_config_for("claudecode"))
    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.pause()
        # MCPs (4th tab) -> Tab should go straight to Inventory (6th)
        app.action_switch_panel("mcps")
        await pilot.pause()
        app.action_next_panel()
        assert app.active_panel == "inventory"

        # Inventory -> Shift+Tab back to MCPs (skip plugins)
        app.action_previous_panel()
        assert app.active_panel == "mcps"


@pytest.mark.asyncio
async def test_tab_cycling_visits_plugins_on_openclaw() -> None:
    app = DefenseClawTUI(config=_config_for("openclaw"))
    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.pause()
        app.action_switch_panel("mcps")
        app.action_next_panel()
        assert app.active_panel == "plugins"
