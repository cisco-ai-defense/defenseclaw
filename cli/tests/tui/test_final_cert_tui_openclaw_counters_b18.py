# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fix batch b18: Overview counters on an OpenClaw-only install (GAP-2496)."""

from __future__ import annotations

import io
from datetime import datetime, timezone

from defenseclaw.db import Store
from defenseclaw.models import Event
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.panels.alerts import AlertEvent, AlertsPanelModel
from defenseclaw.tui.panels.audit import AuditPanelModel
from defenseclaw.tui.panels.overview import (
    ConnectorHealth,
    HealthSnapshot,
    OverviewConfig,
    OverviewPanelModel,
    SubsystemHealth,
)
from rich.console import Console


def _openclaw_store(tmp_path) -> Store:
    store = Store(str(tmp_path / "audit.db"))
    store.init()
    now = datetime.now(timezone.utc)
    rows = [
        ("inspect-tool-allow", "write", "INFO"),
        ("inspect-tool-allow", "read", "INFO"),
        ("inspect-tool-block", "exec", "CRITICAL"),
        ("guardrail-verdict", "", "INFO"),
        ("guardrail-verdict", "", "INFO"),
        ("block", "prompt", "CRITICAL"),
    ]
    for i, (action, target, severity) in enumerate(rows):
        store.log_event(
            Event(id=f"oc-{i}", timestamp=now, action=action, target=target, severity=severity, connector="openclaw")
        )
    # A hook connector's inspect-tool rows stay out of the proxy counts.
    store.log_event(Event(id="cc-1", timestamp=now, action="inspect-tool-block", target="Bash", connector="claudecode"))
    return store


def test_proxy_connector_stats_count_tool_inspections_llm_verdicts_and_blocks(tmp_path) -> None:
    store = _openclaw_store(tmp_path)
    try:
        stats = store.connector_hook_event_stats()
    finally:
        store.close()
    assert stats["openclaw"]["calls"] == 5
    assert stats["openclaw"]["blocks"] == 2
    assert "claudecode" not in stats


def test_openclaw_only_overview_counts_blocks_and_does_not_say_quiet(tmp_path) -> None:
    store = _openclaw_store(tmp_path)
    cfg = OverviewConfig(
        data_dir=str(tmp_path),
        claw_mode="openclaw",
        guardrail_connector="openclaw",
        guardrail_enabled=True,
        connector_modes=(("openclaw", "action"),),
    )
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(
        HealthSnapshot(
            gateway=SubsystemHealth(state="running"),
            connector=ConnectorHealth(name="openclaw", state="running", requests=8, tool_inspections=3, tool_blocks=1),
        )
    )
    alerts = AlertsPanelModel(store=store)
    alerts.set_events(
        [
            AlertEvent(id="a1", severity="CRITICAL", action="inspect-tool-block", target="exec", connector="openclaw"),
            AlertEvent(id="a2", severity="CRITICAL", action="block", target="prompt", connector="openclaw"),
        ]
    )
    audit = AuditPanelModel(store)
    audit.refresh()
    app = DefenseClawTUI(overview_model=overview, audit_model=audit, alerts_model=alerts)
    overview.not_configured = False  # the test has no config.yaml on disk
    try:
        with app._connector_hook_event_render_cache():  # noqa: SLF001
            metrics = {m.key: m for m in app._overview_metric_data()}  # noqa: SLF001
            body = app._overview_body_text(overview.service_cards())  # noqa: SLF001
            console = Console(file=io.StringIO(), width=160, color_system=None)
            console.print(app._overview_renderable())  # noqa: SLF001
            screen = console.file.getvalue()
    finally:
        store.close()

    calls = metrics["hook_calls"]
    assert calls.label == "Inspections (openclaw)"
    assert calls.value == 5
    assert "8" in calls.detail and "LLM req" in calls.detail and "3" in calls.detail
    assert metrics["blocks"].value == 2
    assert "Runtime signals are quiet" not in body
    assert "2 critical/high alerts need review" in body
    assert "Inspections" in body and "Hook calls" not in body
    # The rendered screen (banner and ENFORCEMENT box) says the same.
    assert "Runtime signals are quiet" not in screen
    assert "2 critical/high alerts need review" in screen
    assert "Inspections" in screen and "Hook calls" not in screen
