# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Cowork in the TUI and the 80x24 Overview (GAP-0046, GAP-0047, GAP-0048)."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from defenseclaw.tui.app import _fetch_cowork_status, overview_metrics_compact
from defenseclaw.tui.panels.alerts import _evaluation_surfaces, _v8_alert_event, surface_label
from defenseclaw.tui.panels.setup import _build_connector_setup_args, connector_setup_wizard_fields
from defenseclaw.tui.services.overview_state import (
    ConnectorHealth,
    HealthSnapshot,
    _connector_saw_traffic,
    cowork_overview_rows,
)
from defenseclaw.tui.services.v8_event_history import V8EventHistoryRow
from defenseclaw.tui.widgets.native_metrics import compact_metric_title
from fixtures import snapshot_app


def test_cowork_rows_say_protected_or_the_missing_step() -> None:
    assert cowork_overview_rows(None) == ()
    waiting = SimpleNamespace(
        protected=False,
        detail="not protected yet: no Cowork event has reached DefenseClaw since plugin 3 was built",
        step="upload /home/u/.defenseclaw/cowork/defenseclaw-cowork.zip in Claude, then start a Cowork task",
        last_event_at="",
    )
    rows = cowork_overview_rows(waiting, home="/home/u")
    assert rows[0][0] == "Cowork" and rows[0][1].startswith("not protected yet")
    assert rows[1] == ("Cowork next", "upload ~/.defenseclaw/cowork/defenseclaw-cowork.zip in Claude, then start a Cowork task")
    stamp = datetime.now(timezone.utc).isoformat()
    protected = SimpleNamespace(protected=True, detail="protected, action mode", step="", last_event_at=stamp)
    rows = cowork_overview_rows(protected)
    assert len(rows) == 1 and rows[0][1].startswith("protected, last event ")


def test_cowork_events_count_as_claude_code_traffic() -> None:
    assert not _connector_saw_traffic(ConnectorHealth(name="claudecode"))
    assert _connector_saw_traffic(ConnectorHealth(name="claudecode", cowork_requests=2))


def test_fetch_cowork_status_uses_the_status_row(monkeypatch) -> None:
    from defenseclaw import cowork

    seen = {}

    def fake_status(cfg, health, **kwargs):
        seen.update(health=health, **kwargs)
        return "row"

    monkeypatch.setattr(cowork, "cowork_status", fake_status)
    cfg = SimpleNamespace(active_connectors=lambda: ["claudecode"])
    health = HealthSnapshot(
        connectors=(ConnectorHealth(name="claudecode", cowork_last_activity_at="2026-11-04T08:00:00Z"),)
    )
    assert _fetch_cowork_status(cfg, health, "running") == "row"
    assert seen["gateway_running"] and seen["health_authenticated"]
    cowork_row = seen["health"]["connectors"][0]
    assert cowork_row["surfaces"]["cowork"]["last_activity_at"] == "2026-11-04T08:00:00Z"
    _fetch_cowork_status(cfg, None, "offline")
    assert not seen["gateway_running"] and seen["health"] is None
    assert _fetch_cowork_status(SimpleNamespace(), health, "running") is None


def _row(row_id: str, bucket: str, payload: dict, **extra) -> V8EventHistoryRow:
    return V8EventHistoryRow(
        id=row_id,
        timestamp=datetime.now(timezone.utc),
        bucket=bucket,
        event_name="x",
        source="gateway",
        severity="CRITICAL",
        action="",
        actor="",
        details="",
        connector="claudecode",
        redaction_profile="",
        payload=payload,
        **extra,
    )


def test_a_cowork_finding_says_cowork_in_row_and_detail() -> None:
    decision = _row(
        "d1",
        "guardrail.evaluation",
        {"defenseclaw.evaluation.id": "ev1", "defenseclaw.agent.surface": "cowork"},
        request_id="r1",
    )
    finding = _row(
        "f1",
        "security.finding",
        {"defenseclaw.evaluation.id": "ev1", "defenseclaw.finding.target_ref": "claudecode:PreToolUse"},
    )
    surfaces = _evaluation_surfaces((decision, finding))
    event = _v8_alert_event(finding, {}, surfaces)
    assert event.surface == "cowork"
    assert event.target == "cowork:PreToolUse"
    assert ("Surface", "Cowork (Claude Code)") in event.facts
    # Same request, no evaluation id: the request id carries the surface.
    by_request = _row("f2", "security.finding", {"defenseclaw.finding.target_ref": "claudecode:PreToolUse"}, request_id="r1")
    assert _v8_alert_event(by_request, {}, surfaces).surface == "cowork"
    # A Claude Code CLI call keeps its label.
    plain = _v8_alert_event(_row("f3", "security.finding", {"defenseclaw.finding.target_ref": "claudecode:PreToolUse"}))
    assert plain.target == "claudecode:PreToolUse" and plain.surface == ""
    assert surface_label("cowork") == "Cowork (Claude Code)"


def test_setup_offers_setup_cowork() -> None:
    fields = connector_setup_wizard_fields(None, overrides={"@Action": "cowork"})
    assert _build_connector_setup_args(fields) == ("setup", "cowork", "--yes")
    action = next(field for field in connector_setup_wizard_fields(None) if field.label == "Action")
    assert "cowork" not in action.options


def test_compact_cards_below_32_rows() -> None:
    assert overview_metrics_compact(24) and overview_metrics_compact(31)
    assert not overview_metrics_compact(40) and not overview_metrics_compact(0)
    assert compact_metric_title("Alert Risk", "2", 14).plain == "Alert Risk 2"
    assert compact_metric_title("Hook Calls (4 connectors)", "12", 14).plain == "Hook Calls 12"


@pytest.mark.asyncio
async def test_overview_at_80x24_has_compact_cards_and_q_quits(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert app.query_one("#overview-metrics").has_class("compact")
        # q closes an open detail first, like Esc, and does not quit.
        await pilot.press("2", "enter")
        await pilot.pause()
        assert app.alerts_model.detail_open
        await pilot.press("q")
        await pilot.pause()
        assert not app.alerts_model.detail_open and app.is_running
        await pilot.press("1", "q")
        await pilot.pause()
        assert not app.is_running
