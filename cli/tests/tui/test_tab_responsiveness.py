# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# SPDX-License-Identifier: Apache-2.0

"""Deterministic coverage for deferred TUI panel rendering (WIN-AUD-041)."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path

import defenseclaw.tui.panels.alerts as alerts_panel
import pytest
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.panels.alerts import AlertEvent, AlertsPanelModel
from defenseclaw.tui.panels.audit import AuditPanelModel
from defenseclaw.tui.panels.logs import LogsPanelModel
from defenseclaw.tui.panels.overview import OverviewConfig, OverviewPanelModel
from defenseclaw.tui.services.overview_state import ConnectorHealth, HealthSnapshot, SubsystemHealth


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
