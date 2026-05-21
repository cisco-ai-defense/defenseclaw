# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for tab unread badges driven by ``panel_seen_counts``.

These exercise the pure helpers on :class:`DefenseClawTUI` and on
:class:`TUIStateStore` so we don't have to spin up a full Textual
event loop to verify badge math. The render path (``_update_tab_labels``)
is covered by the existing app-shell snapshot tests.
"""

from __future__ import annotations

from dataclasses import dataclass

from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.services.tui_state import TUIStateStore


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


def test_tui_state_store_record_seen_count_clamps_negative() -> None:
    store = TUIStateStore(None)
    store.record_seen_count("alerts", -3)
    assert store.get_seen_count("alerts") == 0


def test_tui_state_store_record_seen_count_round_trips() -> None:
    store = TUIStateStore(None)
    store.record_seen_count("alerts", 42)
    assert store.get_seen_count("alerts") == 42
    assert store.state.panel_seen_counts["alerts"] == 42


def test_unread_count_zero_when_no_new_items() -> None:
    app = DefenseClawTUI(config=_config_for())
    # Simulate "user opened audit; 5 items existed".
    app.audit_model.items = [object()] * 5  # type: ignore[attr-defined]
    app.state_store.record_seen_count("audit", 5)
    # Stay on overview so audit is non-active and badge math runs.
    app.active_panel = "overview"
    assert app._panel_unread_count("audit") == 0


def test_unread_count_reports_delta() -> None:
    app = DefenseClawTUI(config=_config_for())
    app.audit_model.items = [object()] * 7  # type: ignore[attr-defined]
    app.state_store.record_seen_count("audit", 5)
    app.active_panel = "overview"
    assert app._panel_unread_count("audit") == 2


def test_active_panel_never_shows_badge() -> None:
    """Active panel should always report 0 unread — you can't have
    unread content on the panel you're staring at."""

    app = DefenseClawTUI(config=_config_for())
    app.audit_model.items = [object()] * 100  # type: ignore[attr-defined]
    app.state_store.record_seen_count("audit", 0)
    app.active_panel = "audit"
    assert app._panel_unread_count("audit") == 0


def test_unread_count_caps_at_99() -> None:
    app = DefenseClawTUI(config=_config_for())
    app.audit_model.items = [object()] * 500  # type: ignore[attr-defined]
    app.state_store.record_seen_count("audit", 0)
    app.active_panel = "overview"
    assert app._panel_unread_count("audit") == 99


def test_panel_total_count_sums_alerts_streams() -> None:
    """Alerts pulls from both audit_events + egress_events so the
    badge reflects "total things in the alerts feed", not just one
    half of it."""

    app = DefenseClawTUI(config=_config_for())
    app.alerts_model.audit_events = [object()] * 3  # type: ignore[attr-defined]
    app.alerts_model.egress_events = [object()] * 4  # type: ignore[attr-defined]
    assert app._panel_total_count("alerts") == 7


def test_unknown_panel_total_count_is_zero() -> None:
    """Defensive: never crash on panels we don't badge."""

    app = DefenseClawTUI(config=_config_for())
    assert app._panel_total_count("setup") == 0
    assert app._panel_total_count("__nonexistent__") == 0
