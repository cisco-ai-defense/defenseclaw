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
import copy
import sqlite3
import sys
import threading
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import perf_counter, sleep
from typing import Any

import defenseclaw.tui.app as app_module
import pytest
from defenseclaw.db import Store
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.panels.alerts import AlertEvent, AlertsPanelModel
from defenseclaw.tui.panels.audit import AuditPanelModel
from defenseclaw.tui.panels.logs import FILTER_NONE, LogsPanelModel
from defenseclaw.tui.panels.overview import OverviewConfig, OverviewPanelModel
from defenseclaw.tui.services.overview_state import ConnectorHealth, HealthSnapshot, SubsystemHealth
from defenseclaw.tui.widgets.native_metrics import OverviewMetrics
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
    # This regression targets switch-generated renders only. Mounted network
    # and periodic pollers can legitimately enqueue an additional Overview
    # generation, obscuring whether the stale switch result was discarded.
    monkeypatch.setattr(app, "_schedule_health_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_ai_usage_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_credentials_refresh", lambda: None)
    monkeypatch.setattr(app, "_periodic_refresh", lambda: None)

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
        acknowledgement_seconds = perf_counter() - started

        # The tab and panel chrome are already correct while the provider is
        # queued to block after the acknowledgement paint. Worker-thread start
        # latency is deliberately outside this synchronous UI budget.
        assert acknowledgement_seconds < 0.5
        assert app.active_panel == "overview"
        assert app.query_one("#tabs").active == "tab-overview"
        assert not app.query_one("#overview-controls").has_class("hidden")
        assert app.query_one("#alerts-controls").has_class("hidden")
        await _wait_until(entered.is_set)

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
    monkeypatch.setattr(app, "_schedule_health_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_ai_usage_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_credentials_refresh", lambda: None)
    monkeypatch.setattr(app, "_periodic_refresh", lambda: None)
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


@pytest.mark.asyncio
async def test_blocked_state_save_does_not_delay_tab_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = DefenseClawTUI(data_dir=tmp_path)
    entered = threading.Event()
    release = threading.Event()
    saves = 0

    def blocked_save(*_args: object, **_kwargs: object) -> bool:
        nonlocal saves
        saves += 1
        entered.set()
        assert release.wait(5)
        return True

    monkeypatch.setattr(app.state_store, "save", blocked_save)
    monkeypatch.setattr(app, "_schedule_health_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_ai_usage_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_credentials_refresh", lambda: None)
    monkeypatch.setattr(app, "_periodic_refresh", lambda: None)

    async with app.run_test(size=(140, 40)):
        app._schedule_state_save(delay=0.01)  # noqa: SLF001
        await _wait_until(entered.is_set)
        try:
            started = perf_counter()
            app.action_switch_panel("alerts")
            acknowledgement_ms = (perf_counter() - started) * 1_000

            assert acknowledgement_ms < 150
            assert app.active_panel == "alerts"
            assert app.query_one("#tabs").active == "tab-alerts"
        finally:
            release.set()
        await _wait_until(lambda: not app._state_save_running)  # noqa: SLF001
        assert saves >= 1


@pytest.mark.asyncio
async def test_health_poll_overview_disk_refresh_does_not_block_tab_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = DefenseClawTUI(overview_model=_multi_connector_overview())
    entered = threading.Event()
    release = threading.Event()
    original = app._build_overview_disk_refresh_snapshot  # noqa: SLF001

    monkeypatch.setattr(
        app_module,
        "_fetch_gateway_health",
        lambda _config: app_module.GatewayHealthResult("offline", "fixture"),
    )
    monkeypatch.setattr(app, "_schedule_health_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_ai_usage_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_credentials_refresh", lambda: None)
    monkeypatch.setattr(app, "_periodic_refresh", lambda: None)

    def blocked_builder(detached: DefenseClawTUI, source: tuple[str, object | None]):
        entered.set()
        assert release.wait(5)
        return original(detached, source)

    monkeypatch.setattr(app, "_build_overview_disk_refresh_snapshot", blocked_builder)

    async with app.run_test(size=(150, 44)):
        def fail_sync_refresh() -> None:
            raise AssertionError("disk refresh ran on the UI thread")

        monkeypatch.setattr(app, "_refresh_overview_disk_models", fail_sync_refresh)
        await app._poll_health()  # noqa: SLF001
        await _wait_until(entered.is_set)

        started = perf_counter()
        app.action_switch_panel("alerts")
        acknowledgement_ms = (perf_counter() - started) * 1_000

        assert acknowledgement_ms < 150
        assert app.active_panel == "alerts"
        assert app.query_one("#tabs").active == "tab-alerts"

        release.set()
        await _wait_until(
            lambda: not app._overview_disk_refresh_running  # noqa: SLF001
            and "__overview_disk__" not in app._panel_render_workers,  # noqa: SLF001
        )


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
    # The production gateway owns the complete v8 event projection.  Python's
    # bootstrap store intentionally creates only its compatibility subset, so
    # make this high-volume fixture match a gateway-migrated database.
    columns = {
        str(row[1]) for row in store.db.execute("PRAGMA table_info(audit_events)")
    }
    for column in (
        "source",
        "signal",
        "payload_json",
        "projected_record_json",
        "redaction_profile",
        "trace_id",
        "request_id",
        "session_id",
        "turn_id",
        "scan_id",
        "finding_id",
    ):
        if column not in columns:
            store.db.execute(f"ALTER TABLE audit_events ADD COLUMN {column} TEXT")
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
                "guardrail.evaluation",
                "guardrail.evaluated",
                "gateway",
                "logs",
                "{}",
                "{}",
                "none",
            )
        )
    store.db.executemany(
        """INSERT INTO audit_events (
               id, timestamp, action, target, actor, details,
               structured_json, severity, run_id, connector, enforced,
               bucket, event_name, source, signal, payload_json,
               projected_record_json, redaction_profile
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
        audit.show_all_events = True
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
        monkeypatch.setattr(app, "_schedule_health_poll", lambda: None)
        monkeypatch.setattr(app, "_schedule_ai_usage_poll", lambda: None)
        monkeypatch.setattr(app, "_schedule_credentials_refresh", lambda: None)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.press("2")
            await _wait_for_panel(app, "alerts")
            # Repository-backed snapshots are loaded off the Textual event
            # loop.  Panel rendering can settle before that first immutable
            # snapshot is applied, so wait for the data boundary explicitly.
            await _wait_until(
                lambda: len(alerts.audit_events) == 500 and len(audit.items) == 500
            )
            assert len(alerts.audit_events) == 500
            assert len(audit.items) == 500

            started = perf_counter()
            app.action_switch_panel("overview")
            # Model a health/config/audit invalidation landing in the same turn;
            # it coalesces onto the one latest Overview generation.
            app._health_poll_running = True  # noqa: SLF001
            app._schedule_active_panel_refresh("health-and-audit")  # noqa: SLF001
            acknowledgement_ms = (perf_counter() - started) * 1_000

            assert app.query_one("#tabs").active == "tab-overview"
            assert acknowledgement_ms < 150
            await _wait_until(builder_started.is_set)
            await _wait_for_panel(app, "overview")
            snapshot = app._overview_render_snapshot  # noqa: SLF001
            assert snapshot is not None
            hook_calls = next(metric.value for metric in snapshot.metrics if metric.key == "hook_calls")
            assert hook_calls == 7_000
    finally:
        store.close()


@pytest.mark.asyncio
async def test_passive_refresh_does_not_starve_slow_overview(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = DefenseClawTUI(overview_model=_multi_connector_overview())
    app.active_panel = "alerts"
    monkeypatch.setattr(app, "_schedule_health_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_ai_usage_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_credentials_refresh", lambda: None)
    monkeypatch.setattr(app, "_periodic_refresh", lambda: None)

    entered = threading.Event()
    release = threading.Event()
    calls = 0
    applied: list[int] = []
    original_builder = app._build_overview_render_snapshot  # noqa: SLF001
    original_apply = app._apply_overview_render_snapshot  # noqa: SLF001

    def blocked_builder(
        detached: DefenseClawTUI,
        generation: int,
        source: tuple[str, object | None],
    ):
        nonlocal calls
        calls += 1
        if calls == 1:
            entered.set()
            assert release.wait(5)
        return original_builder(detached, generation, source)

    def observed_apply(snapshot: object) -> None:
        applied.append(snapshot.generation)
        original_apply(snapshot)

    monkeypatch.setattr(app, "_build_overview_render_snapshot", blocked_builder)
    monkeypatch.setattr(app, "_apply_overview_render_snapshot", observed_apply)

    async with app.run_test(size=(160, 48)):
        app.action_switch_panel("overview")
        await _wait_until(entered.is_set)
        generation = app._panel_render_generation  # noqa: SLF001

        for _ in range(4):
            assert app._schedule_active_panel_refresh("periodic-audit") == generation  # noqa: SLF001
        assert app._panel_render_generation == generation  # noqa: SLF001
        assert "overview" in app._panel_passive_refresh_pending  # noqa: SLF001

        release.set()
        await _wait_until(lambda: generation in applied)
        await _wait_for_panel(app, "overview")

        assert calls == 1
        assert app._overview_render_snapshot is not None  # noqa: SLF001
        assert app._overview_render_snapshot.generation == generation  # noqa: SLF001
        assert "overview" not in app._panel_passive_refresh_pending  # noqa: SLF001
        assert app.active_panel == "overview"


@pytest.mark.asyncio
async def test_overview_reentry_keeps_last_good_body_and_mounted_metrics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = DefenseClawTUI(overview_model=_multi_connector_overview())
    monkeypatch.setattr(app, "_schedule_health_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_ai_usage_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_credentials_refresh", lambda: None)
    monkeypatch.setattr(app, "_periodic_refresh", lambda: None)

    async with app.run_test(size=(160, 48)):
        cached = app._overview_render_snapshot  # noqa: SLF001
        assert cached is not None
        assert "Loading current data" not in cached.body_text
        metrics = app.query_one("#overview-metrics", OverviewMetrics)
        tile_ids = tuple(id(tile) for tile in metrics._tiles.values())  # noqa: SLF001
        assert tile_ids

        app.action_switch_panel("alerts")
        await _wait_for_panel(app, "alerts")

        entered = threading.Event()
        release = threading.Event()
        original = app._build_overview_render_snapshot  # noqa: SLF001

        def blocked_builder(
            detached: DefenseClawTUI,
            generation: int,
            source: tuple[str, object | None],
        ):
            entered.set()
            assert release.wait(5)
            return original(detached, generation, source)

        monkeypatch.setattr(app, "_build_overview_render_snapshot", blocked_builder)
        app.action_switch_panel("overview")

        assert app.body_text == cached.body_text
        assert "Loading current data" not in app.body_text
        assert not metrics.has_class("hidden")
        assert tuple(id(tile) for tile in metrics._tiles.values()) == tile_ids  # noqa: SLF001
        await _wait_until(entered.is_set)

        release.set()
        await _wait_for_panel(app, "overview")


def test_detached_context_retains_large_row_snapshots_without_iterating() -> None:
    class ExplodingRows(list[object]):
        def __iter__(self):
            raise AssertionError("large row collection was copied on the UI loop")

    alerts = AlertsPanelModel()
    audit = AuditPanelModel()
    logs = LogsPanelModel()
    alert_rows = ExplodingRows()
    audit_rows = ExplodingRows()
    log_rows = ExplodingRows()
    alerts.audit_events = alert_rows  # type: ignore[assignment]
    audit.items = audit_rows  # type: ignore[assignment]
    logs.lines["gateway"] = log_rows  # type: ignore[assignment]
    app = DefenseClawTUI(alerts_model=alerts, audit_model=audit, logs_model=logs)

    detached = app._detached_render_context("logs")  # noqa: SLF001

    assert detached.alerts_model.audit_events is alert_rows
    assert detached.audit_model.items is audit_rows
    assert detached.logs_model.lines["gateway"] is log_rows
    assert detached.alerts_model.expanded is not alerts.expanded
    assert detached.logs_model.cursor is not logs.cursor


def test_overview_stats_reuse_version_and_preserve_last_good_through_lock() -> None:
    class FlakyStore:
        def __init__(self) -> None:
            self.version = 1
            self.codex_calls = 12
            self.fail = False
            self.stats_calls = 0

        def audit_data_version(self) -> tuple[int, int]:
            return (1, self.version)

        def connector_hook_event_stats(self) -> dict[str, dict[str, object]]:
            self.stats_calls += 1
            if self.fail:
                raise RuntimeError("database is locked")
            return {
                "codex": {
                    "calls": self.codex_calls,
                    "blocks": 2,
                    "alerts": 3,
                    "newest": None,
                },
                "claudecode": {"calls": 7, "blocks": 1, "alerts": 0, "newest": None},
            }

        def list_connector_hook_event_summaries(self, _limit: int) -> list[object]:
            return []

        def count_scan_results_since(self, _since: datetime | None) -> int:
            return 0

    def stats(snapshot: object) -> dict[str, tuple[int, int, int]]:
        return {
            connector: (calls, blocks, alerts)
            for connector, calls, blocks, alerts, _newest in snapshot.hook_stats
        }

    store = FlakyStore()
    app = DefenseClawTUI(
        alerts_model=AlertsPanelModel(store=store),
        audit_model=AuditPanelModel(store),
        overview_model=_multi_connector_overview(),
    )
    assert app._connector_hook_event_stats()["codex"]["calls"] == 12  # noqa: SLF001
    assert store.stats_calls == 1

    unchanged = app._build_overview_render_snapshot(  # noqa: SLF001
        app._detached_render_context("overview"),  # noqa: SLF001
        1,
        ("shared", store),
    )
    assert stats(unchanged)["codex"] == (12, 2, 3)
    assert store.stats_calls == 1

    store.version = 2
    store.fail = True
    locked = app._build_overview_render_snapshot(  # noqa: SLF001
        app._detached_render_context("overview"),  # noqa: SLF001
        2,
        ("shared", store),
    )
    assert stats(locked) == {"codex": (12, 2, 3), "claudecode": (7, 1, 0)}
    assert locked.audit_version == (1, 1)

    store.fail = False
    store.codex_calls = 13
    recovered = app._build_overview_render_snapshot(  # noqa: SLF001
        app._detached_render_context("overview"),  # noqa: SLF001
        3,
        ("shared", store),
    )
    assert stats(recovered) == {"codex": (13, 2, 3), "claudecode": (7, 1, 0)}
    assert recovered.audit_version == (1, 2)
    assert store.stats_calls == 3

    app._connector_hook_event_stats_cache = {  # noqa: SLF001
        connector: {
            "calls": calls,
            "blocks": blocks,
            "alerts": alerts,
            "newest": newest,
        }
        for connector, calls, blocks, alerts, newest in recovered.hook_stats
    }
    app._connector_hook_event_stats_last_good = copy.deepcopy(  # noqa: SLF001
        app._connector_hook_event_stats_cache  # noqa: SLF001
    )
    app._connector_hook_event_stats_version = recovered.audit_version  # noqa: SLF001
    app._build_overview_render_snapshot(  # noqa: SLF001
        app._detached_render_context("overview"),  # noqa: SLF001
        4,
        ("shared", store),
    )
    assert store.stats_calls == 3


def _large_logs(row_count: int = 5_000) -> tuple[LogsPanelModel, tuple[str, ...]]:
    logs = LogsPanelModel()
    rows = tuple(f"2026-07-09T12:00:{index % 60:02d}Z INFO row={index}" for index in range(row_count))
    logs.lines["gateway"] = list(rows)
    logs.filter_mode = FILTER_NONE
    logs.cursor["gateway"] = row_count // 2
    logs.cursor_moved["gateway"] = True
    return logs, rows


@pytest.mark.asyncio
async def test_large_table_commit_yields_to_latest_tab_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logs, expected = _large_logs()
    app = DefenseClawTUI(logs_model=logs)
    monkeypatch.setattr(app, "_schedule_health_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_ai_usage_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_credentials_refresh", lambda: None)
    monkeypatch.setattr(app, "_periodic_refresh", lambda: None)
    original_append = app._append_panel_table_row  # noqa: SLF001
    appended_rows = 0
    rows_before_yield: list[int] = []

    def record_yield(scheduled_at: int) -> None:
        rows_before_yield.append(appended_rows - scheduled_at)

    def slow_append(*args: object, **kwargs: object) -> None:
        nonlocal appended_rows
        original_append(*args, **kwargs)
        appended_rows += 1
        if appended_rows % 16 == 1:
            asyncio.get_running_loop().call_soon(record_yield, appended_rows)
        sleep(0.0004)

    monkeypatch.setattr(app, "_append_panel_table_row", slow_append)

    async with app.run_test(size=(160, 48)):
        table = app.query_one("#panel-table", DataTable)
        await asyncio.sleep(0)
        app.action_switch_panel("logs")
        await _wait_until(lambda: 0 < table.row_count < len(expected))
        partial_count = table.row_count
        assert not app._applying_panel_snapshot  # noqa: SLF001

        started = perf_counter()
        app.action_switch_panel("overview")
        acknowledgement_ms = (perf_counter() - started) * 1_000
        await _wait_for_panel(app, "overview")
        await _wait_until(lambda: "logs" not in app._panel_render_running)  # noqa: SLF001

        assert 0 < partial_count < len(expected)
        assert acknowledgement_ms < 150
        assert rows_before_yield
        assert max(rows_before_yield) <= 16
        assert app.active_panel == "overview"
        assert app.query_one("#tabs").active == "tab-overview"
        assert table.has_class("hidden")
        assert "Loading current data" not in app.body_text


@pytest.mark.asyncio
async def test_large_table_batched_commit_preserves_rows_and_cursor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logs, expected = _large_logs()
    app = DefenseClawTUI(logs_model=logs)
    monkeypatch.setattr(app, "_schedule_health_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_ai_usage_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_credentials_refresh", lambda: None)
    monkeypatch.setattr(app, "_periodic_refresh", lambda: None)

    async with app.run_test(size=(160, 48)):
        app.action_switch_panel("logs")
        await _wait_for_panel(app, "logs")
        table = app.query_one("#panel-table", DataTable)

        assert table.row_count == len(expected)
        assert str(table.get_row_at(0)[-1]) == expected[0]
        assert str(table.get_row_at(len(expected) // 2)[-1]) == expected[len(expected) // 2]
        assert str(table.get_row_at(len(expected) - 1)[-1]) == expected[-1]
        assert table.cursor_row == len(expected) // 2
        assert not table.has_class("hidden")


@pytest.mark.asyncio
async def test_active_writer_advances_exact_stats_after_rapid_switches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _seed_responsiveness_store(tmp_path / "audit.db")
    writer = sqlite3.connect(tmp_path / "audit.db", timeout=5.0)
    try:
        alerts = AlertsPanelModel(tmp_path, store=store)
        audit = AuditPanelModel(store)
        logs, _expected = _large_logs(300)
        app = DefenseClawTUI(
            data_dir=tmp_path,
            alerts_model=alerts,
            audit_model=audit,
            logs_model=logs,
            overview_model=_multi_connector_overview(tmp_path),
        )
        monkeypatch.setattr(app, "_schedule_health_poll", lambda: None)
        monkeypatch.setattr(app, "_schedule_ai_usage_poll", lambda: None)
        monkeypatch.setattr(app, "_schedule_credentials_refresh", lambda: None)
        monkeypatch.setattr(app, "_periodic_refresh", lambda: None)

        async with app.run_test(size=(160, 48)):
            baseline_snapshot = app._overview_render_snapshot  # noqa: SLF001
            assert baseline_snapshot is not None
            baseline = {
                connector: (calls, blocks, alert_count)
                for connector, calls, blocks, alert_count, _newest in baseline_snapshot.hook_stats
            }
            codex_before = baseline.get("codex", (0, 0, 0))
            claude_before = baseline["claudecode"]

            for index in range(3):
                writer.execute(
                    """INSERT INTO audit_events (
                           id, timestamp, action, target, actor, details,
                           structured_json, severity, run_id, connector, enforced
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        f"live-{index}",
                        (datetime.now(timezone.utc) + timedelta(microseconds=index)).isoformat(),
                        "connector-hook",
                        "preToolUse",
                        "fixture",
                        "connector=codex action=block mode=enforce severity=HIGH",
                        None,
                        "HIGH",
                        "live-run",
                        "codex",
                        1,
                    ),
                )
            writer.commit()

            for panel in ("alerts", "audit", "logs", "overview"):
                app.action_switch_panel(panel)
            target_generation = app._schedule_active_panel_refresh("active-writer")  # noqa: SLF001

            def exact_stats_visible() -> bool:
                snapshot = app._overview_render_snapshot  # noqa: SLF001
                if snapshot is None or snapshot.generation < target_generation:
                    return False
                current = {
                    connector: (calls, blocks, alert_count)
                    for connector, calls, blocks, alert_count, _newest in snapshot.hook_stats
                }
                return current.get("codex") == (
                    codex_before[0] + 3,
                    codex_before[1] + 3,
                    codex_before[2],
                )

            await _wait_until(exact_stats_visible, timeout=12.0)
            await _wait_for_panel(app, "overview")
            final_snapshot = app._overview_render_snapshot  # noqa: SLF001
            final = {
                connector: (calls, blocks, alert_count)
                for connector, calls, blocks, alert_count, _newest in final_snapshot.hook_stats
            }
            assert final["claudecode"] == claude_before
            assert app.active_panel == "overview"
            assert app.query_one("#panel-table", DataTable).has_class("hidden")
    finally:
        writer.close()
        store.close()
