# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Plugins and Tools tab visibility tests.

The Plugins panel used to be OpenClaw-only. Other connectors (Amp,
Hermes) have plugins too, so every panel is visible for every roster.
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


def _config_for(connector: str) -> _Config:
    return _Config(guardrail=_Guardrail(connector=connector), claw=_Claw(mode="openclaw"))


def test_plugins_and_tools_tabs_show_for_every_connector(monkeypatch) -> None:
    """GAP-1153: Plugins is no longer OpenClaw-only (Amp and Hermes have
    plugins) and Tools has its own tab; neither is hidden for any roster."""

    for connector in ("openclaw", "claudecode", "codex"):
        app = DefenseClawTUI(config=_config_for(connector))
        monkeypatch.setattr(app, "_active_connector_names", lambda: ["amp", "hermes", connector])
        for filt in ("", "amp", connector):
            app.connector_filter = filt
            visible = app._visible_panels()
            assert "plugins" in visible, (connector, filt)
            assert "tools" in visible, (connector, filt)


def test_tools_shortcut_is_capital_t_only() -> None:
    from defenseclaw.tui.app import CASE_SENSITIVE_PANEL_SHORTCUTS, PANEL_SHORTCUTS

    assert CASE_SENSITIVE_PANEL_SHORTCUTS == {"T": "tools"}
    assert "t" not in PANEL_SHORTCUTS
