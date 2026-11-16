# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""The Cowork row of the Claude Code connector in the Overview (1.0.8 A2)."""

from __future__ import annotations

from types import SimpleNamespace

from defenseclaw.tui import app as tui_app
from defenseclaw.tui.services.overview_state import cowork_line

HEALTH = {
    "started_at": "2026-11-03T12:00:00Z",
    "connectors": [
        {"name": "codex", "state": "running", "surfaces": {"cowork": {"requests": 9}}},
        {
            "name": "claudecode",
            "state": "running",
            "requests": 40,
            "surfaces": {"cowork": {"requests": 12, "last_activity_at": "2026-11-03T13:16:05Z"}},
        },
    ],
}


def test_health_parses_the_cowork_surface_of_claudecode() -> None:
    snapshot = tui_app._health_snapshot_from_mapping(HEALTH)
    assert snapshot is not None
    by_name = {c.name: c for c in snapshot.connectors}
    assert by_name["claudecode"].cowork_requests == 12
    assert by_name["claudecode"].cowork_last_activity_at == "2026-11-03T13:16:05Z"
    assert cowork_line(snapshot) == "12 event(s) since the gateway started, last 2026-11-03T13:16:05Z"


def test_cowork_line_without_events_or_without_claudecode() -> None:
    quiet = tui_app._health_snapshot_from_mapping({"connectors": [{"name": "claudecode", "state": "running"}]})
    assert cowork_line(quiet) == "no Cowork event since the gateway started"
    other = tui_app._health_snapshot_from_mapping({"connectors": [{"name": "codex", "state": "running"}]})
    assert cowork_line(other) == ""
    assert cowork_line(None) == ""
    bad = tui_app._health_snapshot_from_mapping(
        {"connectors": [{"name": "claudecode", "surfaces": {"cowork": {"requests": -3}}}]}
    )
    assert cowork_line(bad) == "no Cowork event since the gateway started"


def test_claudecode_configuration_lines_carry_the_cowork_row() -> None:
    snapshot = tui_app._health_snapshot_from_mapping(HEALTH)
    cfg = SimpleNamespace(
        connector_modes=(("claudecode", "action"), ("codex", "observe")),
        connector_packs=(),
        connector_is_disabled=lambda _name: False,
        guardrail_enabled=True,
        hilt_enabled=False,
        hilt_min_severity="",
        environment="",
    )
    fake = SimpleNamespace(
        overview_model=SimpleNamespace(cfg=cfg, health=snapshot, observability_status=None),
        _overview_connector_row=lambda _name: None,
    )
    lines = dict(tui_app.DefenseClawTUI._connector_configuration_lines(fake, "claudecode"))
    assert lines["Cowork"].startswith("12 event(s)")
    assert "Cowork" not in dict(tui_app.DefenseClawTUI._connector_configuration_lines(fake, "codex"))
