# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# SPDX-License-Identifier: Apache-2.0

"""Deterministic coverage for deferred TUI panel rendering (WIN-AUD-041)."""

from __future__ import annotations

import asyncio
import sys
import threading
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

import pytest
from defenseclaw.db import Store
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.panels.alerts import AlertEvent, AlertsPanelModel
from defenseclaw.tui.panels.audit import AuditPanelModel
from defenseclaw.tui.panels.overview import OverviewConfig, OverviewPanelModel
from defenseclaw.tui.services.overview_state import ConnectorHealth, HealthSnapshot, SubsystemHealth
from rich.text import Text
from textual.widgets import DataTable


async def _wait_until(predicate: Callable[[], bool], *, timeout: float = 8.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() >= deadline:
            raise AssertionError("timed out waiting for deferred TUI work")
        await asyncio.sleep(0.01)


async def _wait_for_panel(app: DefenseClawTUI, panel: str) -> None:
    await _wait_until(
        lambda: panel not in app._panel_render_queued  # noqa: SLF001
        and panel not in app._panel_render_running  # noqa: SLF001
        and panel not in app._panel_render_pending,  # noqa: SLF001
    )


def _multi_connector_overview(data_dir: Path | None = None) -> OverviewPanelModel:
    connectors = ("claudecode", "cursor", "openclaw")
    model = OverviewPanelModel(
        OverviewConfig(
            data_dir=str(data_dir or ""),
            claw_mode="claudecode",
            guardrail_enabled=True,
            connector_modes=tuple((name, "block" if name != "cursor" else "observe") for name in connectors),
            connector_packs=tuple((name, "strict" if name != "cursor" else "default") for name in connectors),
        ),
        version="test",
    )
    model.set_health(
        HealthSnapshot(
            gateway=SubsystemHealth(state="running"),
            connectors=tuple(
                ConnectorHealth(
                    name=name,
                    state="running",
                    requests=2_000,
                    tool_blocks=200,
                )
                for name in connectors
            ),
        )
    )
    return model


@pytest.mark.asyncio
async def test_tab_acknowledges_before_blocked_overview_and_discards_stale_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = DefenseClawTUI(overview_model=_multi_connector_overview())
    entered = threading.Event()
    release = threading.Event()
    calls = 0

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.press("2")
        await _wait_for_panel(app, "alerts")
        original = app._build_overview_render_snapshot  # noqa: SLF001

        def blocked_builder(detached: DefenseClawTUI, generation: int, source: tuple[str, object | None]):
            nonlocal calls
            calls += 1
            call_number = calls
            entered.set()
            if call_number == 1:
                assert release.wait(5)
            snapshot = original(detached, generation, source)
            label = "stale overview generation" if call_number == 1 else "fresh overview generation"
            return replace(
                snapshot,
                body_text=label,
                body_renderable=Text(label),
                body_signature=("overview", False, label),
            )

        monkeypatch.setattr(app, "_build_overview_render_snapshot", blocked_builder)
        started = perf_counter()
        app.action_switch_panel("overview")
        await _wait_until(entered.is_set)

        # The tab and panel chrome are already correct while the provider is
        # intentionally blocked after the acknowledgement paint.
        assert perf_counter() - started < 0.5
        assert app.active_panel == "overview"
        assert app.query_one("#tabs").active == "tab-overview"
        assert not app.query_one("#overview-controls").has_class("hidden")
        assert app.query_one("#alerts-controls").has_class("hidden")

        # Queue a newer Overview generation through a different panel. The
        # blocked result must never overwrite it when released.
        app.action_switch_panel("audit")
        app.action_switch_panel("overview")
        release.set()
        await _wait_until(lambda: app.body_text == "fresh overview generation")
        await _wait_for_panel(app, "overview")

        assert calls == 2
        assert "stale" not in app.body_text
        assert app.query_one("#tabs").active == "tab-overview"


@pytest.mark.asyncio
async def test_alerts_reuses_unchanged_hidden_table_on_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alerts = AlertsPanelModel()
    alerts.show_all_severities = True
    alerts.set_events(
        [
            AlertEvent(
                id=f"alert-{index}",
                severity="HIGH",
                action="connector-hook",
                target="preToolUse",
                details="connector=claudecode decision=block",
            )
            for index in range(80)
        ]
    )
    app = DefenseClawTUI(alerts_model=alerts)

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.press("2")
        await _wait_for_panel(app, "alerts")
        table = app.query_one("#panel-table", DataTable)
        assert table.row_count == 80

        clears = 0
        original_clear = table.clear

        def counted_clear(*args: Any, **kwargs: Any) -> Any:
            nonlocal clears
            clears += 1
            return original_clear(*args, **kwargs)

        monkeypatch.setattr(table, "clear", counted_clear)
        app.action_switch_panel("overview")
        assert table.has_class("hidden")
        app.action_switch_panel("alerts")
        assert not table.has_class("hidden")
        await _wait_for_panel(app, "alerts")

        assert table.row_count == 80
        assert clears == 0


@pytest.mark.asyncio
async def test_alerts_pending_generation_finishes_with_fresh_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alerts = AlertsPanelModel()
    alerts.show_all_severities = True
    alerts.set_events([AlertEvent(id="old", severity="HIGH", action="block", target="old")])
    app = DefenseClawTUI(alerts_model=alerts)
    entered = threading.Event()
    release = threading.Event()
    original = app._build_panel_render_snapshot  # noqa: SLF001
    calls = 0

    def blocked_builder(detached: DefenseClawTUI, panel: str, generation: int):
        nonlocal calls
        calls += 1
        if calls == 1:
            entered.set()
            assert release.wait(5)
        return original(detached, panel, generation)

    monkeypatch.setattr(app, "_build_panel_render_snapshot", blocked_builder)
    async with app.run_test(size=(140, 40)):
        app.action_switch_panel("alerts")
        await _wait_until(entered.is_set)
        alerts.set_events(
            [
                AlertEvent(id="new-1", severity="CRITICAL", action="block", target="one"),
                AlertEvent(id="new-2", severity="HIGH", action="block", target="two"),
            ]
        )
        app._schedule_active_panel_refresh("test-refresh")  # noqa: SLF001
        release.set()
        await _wait_until(lambda: app.query_one("#panel-table", DataTable).row_count == 2)
        await _wait_for_panel(app, "alerts")

        assert calls == 2
        assert "All 2" in app.body_text
        assert {event.id for event in alerts.audit_events} == {"new-1", "new-2"}


@pytest.mark.asyncio
async def test_rapid_switches_coalesce_state_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = DefenseClawTUI(data_dir=tmp_path)
    saves = 0

    def counted_save(*_args: object, **_kwargs: object) -> bool:
        nonlocal saves
        saves += 1
        return True

    monkeypatch.setattr(app.state_store, "save", counted_save)
    async with app.run_test(size=(140, 40)):
        app.action_switch_panel("alerts")
        app.action_switch_panel("audit")
        app.action_switch_panel("overview")

        assert saves == 0
        await _wait_until(lambda: saves == 1)
        assert app.state.active_panel == "overview"


def test_overview_snapshot_queries_each_source_once() -> None:
    class CountingStore:
        def __init__(self) -> None:
            self.stats_queries = 0
            self.event_queries = 0
            self.scan_queries = 0

        def connector_hook_event_stats(self) -> dict[str, dict[str, object]]:
            self.stats_queries += 1
            now = datetime.now(timezone.utc).isoformat()
            return {
                "claudecode": {"calls": 4_000, "blocks": 400, "alerts": 200, "newest": now},
                "cursor": {"calls": 2_000, "blocks": 100, "alerts": 100, "newest": now},
                "openclaw": {"calls": 1_000, "blocks": 50, "alerts": 50, "newest": now},
            }

        def list_connector_hook_event_summaries(self, _limit: int) -> list[object]:
            self.event_queries += 1
            return []

        def count_scan_results_since(self, _since: datetime | None) -> int:
            self.scan_queries += 1
            return 17

        def audit_data_version(self) -> tuple[int, int]:
            return (1, 7_000)

    store = CountingStore()
    app = DefenseClawTUI(
        alerts_model=AlertsPanelModel(store=store),
        audit_model=AuditPanelModel(store),
        overview_model=_multi_connector_overview(),
    )
    detached = app._detached_render_context("overview")  # noqa: SLF001
    snapshot = app._build_overview_render_snapshot(  # noqa: SLF001
        detached,
        41,
        ("shared", store),
    )

    assert snapshot.generation == 41
    assert len(snapshot.metrics) == 4
    assert len(snapshot.connector_rows) == 3
    assert snapshot.enforcement.total_scans == 17
    assert sum(row.calls for row in snapshot.connector_rows) == 7_000
    assert store.stats_queries == 1
    assert store.event_queries == 1
    assert store.scan_queries == 1


def _seed_responsiveness_store(path: Path, *, event_count: int = 7_000) -> Store:
    store = Store(str(path))
    store.init()
    now = datetime.now(timezone.utc)
    connectors = ("claudecode", "cursor", "openclaw")
    rows: list[tuple[object, ...]] = []
    for index in range(event_count):
        connector = connectors[index % len(connectors)]
        decision = "block" if index % 7 == 0 else "alert" if index % 5 == 0 else "allow"
        severity = "HIGH" if decision == "block" else "MEDIUM" if decision == "alert" else "LOW"
        rows.append(
            (
                f"event-{index}",
                (now - timedelta(seconds=index)).isoformat(),
                "connector-hook",
                "preToolUse",
                "fixture",
                f"connector={connector} decision={decision} severity={severity} tool=Bash",
                None,
                severity,
                f"run-{index // 20}",
                connector,
                int(decision == "block"),
            )
        )
    store.db.executemany(
        """INSERT INTO audit_events (
               id, timestamp, action, target, actor, details,
               structured_json, severity, run_id, connector, enforced
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )
    store.db.commit()
    return store


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows responsiveness guard")
@pytest.mark.asyncio
async def test_native_windows_high_volume_tab_ack_under_150ms(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _seed_responsiveness_store(tmp_path / "audit.db")
    try:
        alerts = AlertsPanelModel(tmp_path, store=store)
        alerts.show_all_severities = True
        audit = AuditPanelModel(store)
        app = DefenseClawTUI(
            data_dir=tmp_path,
            alerts_model=alerts,
            audit_model=audit,
            overview_model=_multi_connector_overview(tmp_path),
        )
        builder_started = threading.Event()
        original = app._build_overview_render_snapshot  # noqa: SLF001

        def observed_builder(detached: DefenseClawTUI, generation: int, source: tuple[str, object | None]):
            builder_started.set()
            return original(detached, generation, source)

        monkeypatch.setattr(app, "_build_overview_render_snapshot", observed_builder)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.press("2")
            await _wait_for_panel(app, "alerts")
            assert len(alerts.audit_events) == 500
            assert len(audit.items) == 500

            started = perf_counter()
            app.action_switch_panel("overview")
            # Model a health/config/audit invalidation landing in the same turn;
            # it coalesces onto the one latest Overview generation.
            app._health_poll_running = True  # noqa: SLF001
            app._schedule_active_panel_refresh("health-and-audit")  # noqa: SLF001
            await _wait_until(builder_started.is_set)
            acknowledgement_ms = (perf_counter() - started) * 1_000

            assert app.query_one("#tabs").active == "tab-overview"
            assert acknowledgement_ms < 150
            await _wait_for_panel(app, "overview")
            snapshot = app._overview_render_snapshot  # noqa: SLF001
            assert snapshot is not None
            hook_calls = next(metric.value for metric in snapshot.metrics if metric.key == "hook_calls")
            assert hook_calls == 7_000
    finally:
        store.close()
