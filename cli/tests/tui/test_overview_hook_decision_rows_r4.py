# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The Overview counts a hook_decision-only decision once (S8 R4, #1384)."""

from __future__ import annotations

from defenseclaw.db import Store
from defenseclaw.models import Event
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.panels.audit import AuditPanelModel
from defenseclaw.tui.panels.overview import HealthSnapshot, OverviewConfig, OverviewPanelModel, SubsystemHealth
from tests.test_hook_row_verdict_r4 import _seed, store  # noqa: F401 - pytest fixture


def _app(audit_store: object) -> DefenseClawTUI:
    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="claudecode",
        guardrail_connector="claudecode",
        connector_modes=(("claudecode", "action"),),
    )
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(HealthSnapshot(gateway=SubsystemHealth(state="running")))
    return DefenseClawTUI(overview_model=overview, audit_model=AuditPanelModel(audit_store))


def test_overview_counts_each_hook_decision_once(store: Store) -> None:  # noqa: F811
    _seed(store)
    app = _app(store)
    with app._connector_hook_event_render_cache():
        metrics = {metric.key: metric.value for metric in app._overview_metric_data()}
        allow, alert, block, _newest = app._connector_hook_stats_for_connectors(("claudecode",))
        recent = app._recent_hook_scope_summary(("claudecode",))
    # Two hook_decision-only allows, a 1.0.9 allow with both rows, a block with both rows.
    assert metrics["hook_calls"] == 4
    assert (allow, alert, block) == (3, 0, 1)
    assert (recent["allow"], recent["alert"], recent["block"]) == (3, 0, 1)


def test_overview_fallback_counts_panel_rows_once() -> None:
    # Without the store aggregates the Overview counts the panel rows, once each.
    events = [
        Event(id="lone", action="hook_decision", connector="claudecode", semantic_event_id="s1",
              structured={"defenseclaw.guardrail.effective_action": "allow",
                          "defenseclaw.guardrail.raw_action": "allow"}),
        Event(id="pair-ch", action="connector-hook", connector="claudecode", semantic_event_id="s2",
              details="connector=claudecode action=allow raw_action=allow"),
        Event(id="pair-hd", action="hook_decision", connector="claudecode", semantic_event_id="s2",
              structured={"defenseclaw.guardrail.effective_action": "allow"}),
    ]

    class PanelOnlyStore:
        def count_scan_results_since(self, _since) -> int:
            return 0

    app = _app(PanelOnlyStore())
    app.audit_model.set_events(events)
    with app._connector_hook_event_render_cache():
        assert sorted(event.id for event in app._recent_connector_hook_events()) == ["lone", "pair-ch"]
