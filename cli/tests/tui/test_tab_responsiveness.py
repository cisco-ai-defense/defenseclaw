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
import json
import sys
import threading
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import perf_counter

import defenseclaw.tui.panels.alerts as alerts_panel
import pytest
from defenseclaw.db import Store
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.panels.alerts import AlertEvent, AlertsPanelModel
from defenseclaw.tui.panels.audit import AuditPanelModel
from defenseclaw.tui.panels.logs import LogsPanelModel
from defenseclaw.tui.panels.overview import OverviewConfig, OverviewPanelModel
from defenseclaw.tui.services.overview_state import ConnectorHealth, HealthSnapshot, SubsystemHealth


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


def test_high_volume_alert_summary_skips_unneeded_detail_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alerts = AlertsPanelModel()
    parse_details_calls = 0
    original_parse_details = alerts_panel.parse_kv_details

    def counted_parse_details(value: str) -> dict[str, str]:
        nonlocal parse_details_calls
        parse_details_calls += 1
        return original_parse_details(value)

    monkeypatch.setattr(alerts_panel, "parse_kv_details", counted_parse_details)
    alerts.set_events(
        [
            AlertEvent(
                id=f"alert-{index}",
                severity="HIGH",
                action="connector-hook",
                target="preToolUse",
                details="connector=claudecode decision=block",
            )
            for index in range(7_000)
        ]
    )

    assert "In scope 7000" in alerts.summary_text()
    assert parse_details_calls == 0


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
                "enforcement.action",
                "action.applied",
                "gateway",
                "logs",
                json.dumps({"defenseclaw.enforcement.effective_action": decision}),
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
        return {connector: (calls, blocks, alerts) for connector, calls, blocks, alerts, _newest in snapshot.hook_stats}

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
