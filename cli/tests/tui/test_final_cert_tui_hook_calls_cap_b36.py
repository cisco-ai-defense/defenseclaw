# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fix batch b36: Hook Calls card past 500 calls (GAP-2583)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from defenseclaw.models import Event
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.panels.alerts import AlertsPanelModel
from defenseclaw.tui.panels.audit import AuditPanelModel
from defenseclaw.tui.panels.overview import HealthSnapshot, OverviewConfig, OverviewPanelModel, SubsystemHealth


def test_hook_calls_detail_adds_up_to_headline_past_500_rows() -> None:
    now = datetime.now(timezone.utc)
    # 512 persisted claudecode calls (489 allow, 23 block); the recent loader
    # caps at 500 rows, so 12 older allow rows fall outside its window.
    hooks = [
        Event(
            id=f"hook-{i}",
            timestamp=now - timedelta(seconds=600 - i),
            action="connector-hook",
            target="PreToolUse",
            severity="INFO",
            details=f"connector=claudecode action={'block' if i >= 489 else 'allow'}",
        )
        for i in range(512)
    ]

    class HookStore:
        def list_connector_hook_event_summaries(self, limit: int = 500) -> list[Event]:
            return list(hooks[-limit:])

        def connector_hook_event_stats(self) -> dict[str, dict[str, object]]:
            return {"claudecode": {"calls": 512, "blocks": 23, "alerts": 0, "newest": now.isoformat()}}

        def count_scan_results_since(self, _since: datetime | None) -> int:
            return 0

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="claudecode",
        guardrail_connector="claudecode",
        connector_modes=(("claudecode", "action"), ("codex", "action")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(HealthSnapshot(gateway=SubsystemHealth(state="running")))
    store = HookStore()
    app = DefenseClawTUI(
        overview_model=overview, audit_model=AuditPanelModel(store), alerts_model=AlertsPanelModel(store=store)
    )
    app.connector_filter = "claudecode"

    with app._connector_hook_event_render_cache():  # noqa: SLF001
        calls = {m.key: m for m in app._overview_metric_data()}["hook_calls"]  # noqa: SLF001

    assert calls.value == 512
    assert "allowed [" in calls.detail
    assert "]489[/]" in calls.detail and "]23[/]" in calls.detail
    assert "]477[/]" not in calls.detail
    assert "top event:" in calls.detail and "PreToolUse" in calls.detail
