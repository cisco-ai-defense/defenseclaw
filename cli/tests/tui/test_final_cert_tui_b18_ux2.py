# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI UX batch 18 (GAP-2430 .. GAP-2444)."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import defenseclaw.tui.app as app_module
from defenseclaw.observability.v8_status import V8DestinationStatus, V8OperatorStatus
from defenseclaw.tui.command_line import ParsedCommand
from defenseclaw.tui.panels.alerts import AlertEvent, AlertsPanelModel
from defenseclaw.tui.panels.overview import (
    DoctorCache,
    DoctorCheck,
    HealthSnapshot,
    OverviewConfig,
    OverviewPanelModel,
    SubsystemHealth,
)
from defenseclaw.tui.screens.command_preview import build_command_preview
from defenseclaw.tui.services.catalog_state import PluginRow, PluginScanSummary, _format_plugin_detail
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.fit_columns import FitColumn, FitColumnsTable
from defenseclaw.tui.widgets.native_metrics import fit_metric_detail, fit_metric_title
from rich.text import Text

sys.path.insert(0, str(Path(__file__).parent))
from fixtures import snapshot_app  # noqa: E402

NOW = datetime(2026, 10, 3, 9, 30, tzinfo=timezone.utc)


def _plain(value: object) -> str:
    return value.plain if isinstance(value, Text) else str(value)


def test_card_detail_drops_whole_items_and_keeps_the_number() -> None:
    # GAP-2430: "UserPromptSubmit x1…" for x11, "7 wi…" for "7 with no calls".
    detail = "most blocked: [cyan]UserPromptSubmit[/] x11 · all connectors 120"
    assert _plain(fit_metric_detail(detail, 36)) == "most blocked: UserPromptSubmit x11 …"
    calls = "claudecode 366 · codex 16 · 7 with no calls"
    assert _plain(fit_metric_detail(calls, 36)) == "claudecode 366 · codex 16 …"
    assert _plain(fit_metric_detail(calls, 60)) == calls
    # GAP-2443: at 80x24 the label gives way, never the count.
    assert _plain(fit_metric_detail("claudecode 380 · codex 2", 13)) == "claudeco… 380"
    assert _plain(fit_metric_detail("Critical 15 · High 9", 14)) == "Critical 15 …"


def test_card_title_drops_words_instead_of_cutting() -> None:
    # GAP-2443: "Hook Calls (…" at 80x24.
    assert fit_metric_title("Hook Calls (4 connectors)", 30) == "Hook Calls (4 connectors)"
    assert fit_metric_title("Hook Calls (4 connectors)", 15) == "Hook Calls (4)"
    assert fit_metric_title("Hook Calls (claudecode)", 14) == "Hook Calls"


def test_configuration_url_wraps_after_dots() -> None:
    # GAP-2443: "https://us.api.inspect.aidefe" / "nse.security.cisco.com".
    wrapped = app_module._wrap_at_separators("https://us.api.inspect.aidefense.security.cisco.com", 29)
    assert wrapped.split("\n") == ["https://us.api.inspect.", "aidefense.security.cisco.com"]


def _export(name: str, kind: str = "otlp") -> V8DestinationStatus:
    return V8DestinationStatus(
        name=name,
        kind=kind,
        enabled=True,
        generated=kind == "sqlite",
        capabilities=("traces",),
        selected_signals=("traces",),
        policy_form="capability_default",
        endpoint="http://127.0.0.1:19996",
        route_count=1,
        buckets=(),
        redaction_profiles=("none",),
    )


def _status(*destinations: V8DestinationStatus) -> V8OperatorStatus:
    return V8OperatorStatus(
        source="config.yaml",
        data_dir="/tmp/dc",
        plan_digest="a" * 64,
        bucket_catalog_version=1,
        retention_days=30,
        local_path="/tmp/dc/audit.db",
        judge_bodies_path="",
        destinations=destinations,
        buckets=(),
        warnings=(),
    )


def _model() -> OverviewPanelModel:
    return OverviewPanelModel(OverviewConfig(data_dir="/tmp/dc", claw_mode="codex"), version="test")


def test_doctor_failure_for_a_removed_destination_is_not_a_current_failure() -> None:
    # GAP-2431: a red "Doctor found 1 failure(s)" for sf3r10-dead after it was removed.
    model = _model()
    model.set_doctor_cache(
        DoctorCache(
            captured_at=NOW - timedelta(minutes=2),
            passed=131,
            failed=1,
            checks=(DoctorCheck("fail", "Destination: sf3r10-dead", "connection refused"),),
        )
    )
    model.set_observability_status(_status(_export("local-sqlite", "sqlite")))
    messages = [notice.message for notice in model.build_notices(now=NOW)]
    assert not any("Doctor found" in message or "failed outcome" in message for message in messages)
    assert any("no longer exist - press [d] to refresh" in message for message in messages)
    box = model.doctor_box(now=NOW)
    assert "1 stale" in box.summary_parts
    assert box.checks[0].badge == "STALE" and "destination removed" in box.checks[0].detail

    model.set_observability_status(_status(_export("sf3r10-dead")))
    assert any("Doctor found 1 failure(s)" in notice.message for notice in model.build_notices(now=NOW))


def test_failing_export_marks_telemetry_degraded_with_a_next_step() -> None:
    # GAP-2432: Telemetry stayed a green "running" while Setup said "needs attention".
    model = _model()
    model.set_observability_status(_status(_export("local-sqlite", "sqlite"), _export("sf3r10-dead")))
    details = {"destinations": [{"name": "sf3r10-dead", "health_state": "failing", "reason": "connection_failed"}]}
    model.set_health(HealthSnapshot(telemetry=SubsystemHealth(state="running", details=details)))
    assert model.subsystem_state("telemetry") == "degraded"
    assert any(
        notice.level == "warn" and "defenseclaw setup observability test sf3r10-dead" in notice.message
        for notice in model.build_notices(now=NOW)
    )
    model.set_health(HealthSnapshot(telemetry=SubsystemHealth(state="running", details={})))
    assert model.subsystem_state("telemetry") == "running"


def test_ai_agent_name_stays_whole_while_vendor_is_dropped() -> None:
    # GAP-2434: "Tabby Terminal AI Integra…" beside "Tabby (tabby-terminal)".
    columns = (
        FitColumn("STATE"),
        FitColumn("AGENT", flex_min=app_module.AI_AGENT_NAME_MIN),
        FitColumn("VENDOR", priority=1),
        FitColumn("CONF", priority=2, justify="right"),
        FitColumn("LAST SEEN"),
    )
    row = (
        Text("[GONE]"),
        Text("Tabby Terminal AI Integration"),
        Text("Tabby (tabby-terminal)"),
        Text("60%"),
        Text("seen 2h ago"),
    )
    table = FitColumnsTable(columns, [row], show_header=False)
    kept = dict(table.kept_columns(60))
    assert 2 not in kept and kept[1] is None


def test_plugin_detail_after_a_fresh_scan_points_to_the_output() -> None:
    # GAP-2437: "press s to rescan" and "Findings press s" right after a scan.
    scan = PluginScanSummary(clean=False, max_severity="MEDIUM", total_findings=4, scanned_at="2026-10-03 09:27:00 UTC")
    row = PluginRow(id="photon", name="photon", status="enabled", enabled=True, scan=scan, connector="hermes")
    fresh = _format_plugin_detail(row, NOW)
    assert "press s to rescan" not in fresh
    assert "Findings   listed in the scan output (A)" in fresh
    old = _format_plugin_detail(row, NOW + timedelta(hours=3))
    assert "press s to rescan with this build" in old
    assert "Findings   press s to rescan and list them" in old


def test_registry_require_confirm_focuses_cancel_and_letters_need_capitals() -> None:
    # GAP-2438: "krea" + Enter on Activity turned registry approval on.
    command = ParsedCommand(
        binary="defenseclaw",
        args=("registry", "require", "--type", "mcp", "--enabled"),
        display_name="registry require",
        category="registry",
        risk="mutation",
        needs_preview=True,
    )
    assert build_command_preview(command).cancel_by_default is True
    for letter in "avnrpt":
        assert letter not in app_module.PANEL_SHORTCUTS
        assert letter.upper() in app_module.CASE_SENSITIVE_PANEL_SHORTCUTS
    assert app_module.LOWERCASE_PANEL_FALLBACK["sandboxes"] >= {"p"}


def test_alert_badge_count_follows_the_connector_scope() -> None:
    # GAP-2441: "Alerts(24)" and "24 alerts" while the scoped panel listed 15.
    model = AlertsPanelModel()
    model.set_events(
        [
            AlertEvent(id="a1", severity="HIGH", action="connector-hook", target="x", connector="claudecode"),
            AlertEvent(id="a2", severity="HIGH", action="connector-hook", target="y", connector="codex"),
            AlertEvent(id="a3", severity="CRITICAL", action="connector-hook", target="z", connector="codex"),
        ]
    )
    assert model.connector_scope_count() == model.total_count() == 3
    model.set_connector_filter("claudecode")
    assert model.connector_scope_count() == 1
    model.set_filter("nothing-matches")
    assert model.connector_scope_count() == 1


def test_open_tab_reads_in_full_with_bracket_counts_at_160_columns(monkeypatch) -> None:
    # GAP-2442: "6 Invento…" and "A Activi…" with Windows "(24)" counts.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", True)
    tab_fit._NAMES_CACHE.clear()
    tab_fit._WIDE_CACHE.clear()
    for active, title, unread in (
        ("inventory", "6 Inventory", {"alerts": 24, "audit": 10, "logs": 205}),
        ("activity", "A Activity", {"alerts": 24, "logs": 215}),
    ):
        labels = tab_fit.fit_tab_labels(app_module.PANELS, active, unread, 146)
        assert labels[active] == title, labels
        assert tab_fit.strip_width(tuple(labels.values())) <= 146


async def test_setup_header_counts_tasks_at_80x24(tmp_path) -> None:
    # GAP-2444: "Setup · 11 ok — i readiness details" counted tasks, not checks.
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("0")
        await pilot.pause()
        header = app._setup_header()  # noqa: SLF001
    assert " task ok" in header or " tasks ok" in header
    assert "i task details" in header or "i details" in header
