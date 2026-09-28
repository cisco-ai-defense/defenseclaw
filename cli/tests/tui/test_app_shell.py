# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Textual app-shell tests for the migration foundation."""

from __future__ import annotations

import io
import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw.models import Counts, Event
from defenseclaw.observability.v8_status import (
    V8BucketStatus,
    V8DestinationStatus,
    V8OperatorStatus,
)
from defenseclaw.tui.app import (
    _DEFENSECLAW_LOGO,
    DefenseClawTUI,
    _activity_refresh_bucket,
    _catalog_panel_invalidated_by_command,
    _enforcement_label,
    _event_histogram,
    _fetch_ai_usage,
    _fetch_v8_operator_status,
    _overview_config,
    _policy_posture,
)
from defenseclaw.tui.panels.alerts import AlertEvent, AlertsPanelModel
from defenseclaw.tui.panels.audit import AuditPanelModel
from defenseclaw.tui.panels.overview import (
    ConnectorHealth,
    DoctorCache,
    DoctorRepairSummary,
    EnforcementCounts,
    HealthSnapshot,
    OverviewConfig,
    OverviewPanelModel,
    SubsystemHealth,
)
from defenseclaw.tui.panels.skills import SkillRow, SkillsPanelModel
from defenseclaw.tui.panels.tools import ToolsPanelModel
from defenseclaw.tui.widgets.native_metrics import MetricDatum
from rich.text import Text
from textual.css.query import NoMatches


def test_overview_logo_matches_refreshed_banner_exactly() -> None:
    expected_lines = (
        "██████╗ ███████╗███████╗███████╗███╗   ██╗███████╗███████╗ ██████╗██╗      █████╗ ██╗    ██╗",
        "██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔════╝██╔════╝██╔════╝██║     ██╔══██╗██║    ██║",
        "██║  ██║█████╗  █████╗  █████╗  ██╔██╗ ██║███████╗█████╗  ██║     ██║     ███████║██║ █╗ ██║",
        "██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║╚════██║██╔══╝  ██║     ██║     ██╔══██║██║███╗██║",
        "██████╔╝███████╗██║     ███████╗██║ ╚████║███████║███████╗╚██████╗███████╗██║  ██║╚███╔███╔╝",
        "╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝",
    )

    assert tuple(_DEFENSECLAW_LOGO.splitlines()) == expected_lines
    assert tuple(map(len, expected_lines)) == (92, 92, 92, 92, 92, 91)


def _v8_destination(
    *,
    name: str = "collector",
    kind: str = "otlp",
    endpoint: str = "https://collector.example.test/v1/traces",
    signals: tuple[str, ...] = ("logs", "traces", "metrics"),
) -> V8DestinationStatus:
    return V8DestinationStatus(
        name=name,
        kind=kind,
        enabled=True,
        generated=False,
        capabilities=signals,
        selected_signals=signals,
        policy_form="capability_default",
        endpoint=endpoint,
        route_count=1,
        buckets=("platform.health",),
        redaction_profiles=("none",),
    )


def _v8_status(tmp_path, *destinations: V8DestinationStatus) -> V8OperatorStatus:
    return V8OperatorStatus(
        source=str(tmp_path / "config.yaml"),
        data_dir=str(tmp_path),
        plan_digest="a" * 64,
        bucket_catalog_version=1,
        retention_days=0,
        local_path=str(tmp_path / "audit.db"),
        judge_bodies_path=str(tmp_path / "judge.db"),
        destinations=destinations,
        buckets=(V8BucketStatus("platform.health", ("logs", "traces", "metrics"), "none"),),
        warnings=(),
        judge_bodies_enabled=False,
    )


def test_v8_tui_status_loader_preserves_legacy_and_bounds_invalid_source_errors(tmp_path) -> None:
    config = SimpleNamespace(data_dir=str(tmp_path))
    config_path = tmp_path / "config.yaml"
    config_path.write_text("config_version: 7\n")
    assert _fetch_v8_operator_status(config, tmp_path) == (None, "")

    config_path.write_text(
        "config_version: 8\n"
        "observability:\n"
        "  destinations:\n"
        "    - name: collector\n"
        "      kind: otlp\n"
        "      endpoint: https://user:secret@example.test/?token=must-not-render\n"
        "      unsupported: must-not-render\n"
    )
    status, error = _fetch_v8_operator_status(config, tmp_path)
    assert status is None
    assert error.startswith("invalid v8 configuration at $")
    assert "must-not-render" not in error
    assert "user:secret" not in error


def test_overview_body_signature_ignores_clock_only_labels() -> None:
    app = DefenseClawTUI()

    app.body_text = "DefenseClaw v0.0.0 uptime=12s\nCodex 0s ago\nDoctor 1m ago\nCalls 6"
    first = app._overview_body_signature()

    app.body_text = "DefenseClaw v0.0.0 uptime=13s\nCodex 1s ago\nDoctor 2m ago\nCalls 6"
    assert app._overview_body_signature() == first

    app.body_text = "DefenseClaw v0.0.0 uptime=13s\nCodex 1s ago\nDoctor 2m ago\nCalls 7"
    assert app._overview_body_signature() != first


def test_activity_refresh_bucket_uses_bounded_clock_steps() -> None:
    now = datetime(2026, 7, 1, 16, 0, tzinfo=timezone.utc)

    assert _activity_refresh_bucket(None, now) == ("none", 0)
    assert _activity_refresh_bucket(now - timedelta(seconds=9), now) == ("10s", 0)
    assert _activity_refresh_bucket(now - timedelta(seconds=10), now) == ("10s", 1)
    assert _activity_refresh_bucket(now - timedelta(seconds=59), now) == ("10s", 5)
    assert _activity_refresh_bucket(now - timedelta(seconds=60), now) == ("minute", 1)
    assert _activity_refresh_bucket(now - timedelta(minutes=59), now) == ("minute", 59)
    assert _activity_refresh_bucket(now - timedelta(hours=1), now) == ("hour", 1)
    assert _activity_refresh_bucket(now - timedelta(hours=23), now) == ("hour", 23)
    assert _activity_refresh_bucket(now - timedelta(days=1), now) == ("day", 1)


def test_connector_signature_detects_raw_activity_change_without_count_change() -> None:
    now = datetime.now(timezone.utc)
    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "observe"), ("cursor", "observe")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    app = DefenseClawTUI(overview_model=overview)

    def set_activity(at: datetime) -> None:
        overview.set_health(
            HealthSnapshot(
                gateway=SubsystemHealth(state="running"),
                connectors=(
                    ConnectorHealth(
                        name="codex",
                        state="running",
                        since=(now - timedelta(minutes=5)).isoformat(),
                        requests=4,
                        last_activity_at=at.isoformat(),
                    ),
                    ConnectorHealth(name="cursor", state="running"),
                ),
            )
        )

    set_activity(now - timedelta(seconds=20))
    first = app._overview_connector_rows_signature()
    set_activity(now)
    second = app._overview_connector_rows_signature()

    assert first != second
    row = next(row for row in app._overview_connector_rows() if row.connector == "codex")
    assert row.calls == 0
    assert row.last_activity_at == now


def test_live_overview_signature_covers_scans_alerts_and_large_tiles() -> None:
    now = datetime.now(timezone.utc)
    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "observe"), ("cursor", "observe")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(
        HealthSnapshot(
            gateway=SubsystemHealth(state="running"),
            connectors=(
                ConnectorHealth(
                    name="codex",
                    state="running",
                    since=(now - timedelta(minutes=5)).isoformat(),
                    requests=1,
                    last_activity_at=(now - timedelta(seconds=5)).isoformat(),
                ),
                ConnectorHealth(name="cursor", state="running"),
            ),
        )
    )

    class LiveStore:
        def __init__(self) -> None:
            self.scans = 1
            self.events: list[Event] = []

        def count_scan_results_since(self, _since: datetime | None) -> int:
            return self.scans

        def list_connector_hook_event_summaries(self, limit: int = 500) -> list[Event]:
            return list(self.events[-limit:])

        def connector_hook_event_stats(self) -> dict[str, dict[str, object]]:
            if not self.events:
                return {}
            newest = self.events[-1].timestamp
            return {
                "codex": {
                    "calls": len(self.events),
                    "alerts": len(self.events),
                    "blocks": 0,
                    "newest": newest.isoformat() if newest is not None else "",
                }
            }

        def audit_data_version(self) -> int:
            return len(self.events)

    store = LiveStore()
    app = DefenseClawTUI(
        overview_model=overview,
        audit_model=AuditPanelModel(store),
    )
    with app._connector_hook_event_render_cache():
        first = app._overview_live_data_signature()

    store.scans = 2
    store.events.append(
        Event(
            id="live-alert",
            timestamp=now,
            action="connector-hook",
            target="PostToolUse",
            severity="HIGH",
            details="connector=codex action=alert severity=HIGH",
        )
    )
    with app._connector_hook_event_render_cache():
        second = app._overview_live_data_signature()
        metrics = {metric.key: metric.value for metric in app._overview_metric_data()}
        enforcement = app._overview_session_enforcement_counts()
        connector = next(row for row in app._overview_connector_rows() if row.connector == "codex")

    assert first != second
    assert enforcement.total_scans == 2
    assert metrics["hook_calls"] == 1
    assert metrics["findings"] == 1
    assert connector.alerts == 1


def test_live_overview_signature_ignores_clock_driven_sparkline_motion(
    monkeypatch,
) -> None:
    app = DefenseClawTUI()
    metric = MetricDatum(
        key="hook_calls",
        label="Hook Calls",
        value=4,
        progress=4.0,
        detail="session a4 w0 b0",
        trend=(0.0, 4.0),
        state="ok",
    )
    monkeypatch.setattr(app, "_overview_connector_rows_signature", lambda: ())
    monkeypatch.setattr(app, "_overview_metric_data", lambda: (metric,))
    monkeypatch.setattr(app, "_active_connector_names", lambda: [])
    monkeypatch.setattr(app, "_enforcement_scope_breakdown", lambda _scope: (4, 0, 0))

    first = app._overview_live_data_signature()
    monkeypatch.setattr(
        app,
        "_overview_metric_data",
        lambda: (
            MetricDatum(
                key="hook_calls",
                label="Hook Calls",
                value=4,
                progress=4.0,
                detail="session a4 w0 b0",
                trend=(4.0, 0.0),
                state="ok",
            ),
        ),
    )

    assert app._overview_live_data_signature() == first


def test_command_progress_tick_stops_at_app_lifecycle_boundary(monkeypatch) -> None:
    """A final timer callback must not render after Textual starts teardown."""

    app = DefenseClawTUI()
    app._strip_state = "running"  # noqa: SLF001
    initial_spinner_tick = app._strip_spinner_tick  # noqa: SLF001
    render_calls = 0

    def render_missing_child() -> None:
        nonlocal render_calls
        render_calls += 1
        raise NoMatches("missing command strip child")

    monkeypatch.setattr(app, "_render_command_strip", render_missing_child)

    # Detached and shutting-down apps both report ``is_running == False``.
    # The interval callback must stop before changing state or querying DOM.
    app._tick_command_strip()  # noqa: SLF001
    assert app._strip_spinner_tick == initial_spinner_tick  # noqa: SLF001
    assert render_calls == 0

    # During the mounted lifecycle the same missing-widget failure remains
    # strict, so the teardown guard cannot conceal real command-strip drift.
    app._running = True  # noqa: SLF001
    with pytest.raises(NoMatches, match="missing command strip child"):
        app._tick_command_strip()  # noqa: SLF001
    assert render_calls == 1


@pytest.mark.asyncio
async def test_successful_skill_policy_mutation_reloads_loaded_skills_panel() -> None:
    skills = SkillsPanelModel(connector="hermes")
    skills.apply_loaded(
        [
            SkillRow(
                name="clean-skill",
                status="blocked",
                actions="blocked",
                install_action="block",
            )
        ]
    )
    skills.detail_open = True
    app = DefenseClawTUI(skills_model=skills)
    app.active_panel = "skills"
    reloaded: list[str] = []

    async def fake_load_catalog(panel: str) -> None:
        reloaded.append(panel)
        skills.apply_loaded(
            [
                SkillRow(
                    name="clean-skill",
                    status="allowed",
                    actions="allowed",
                    install_action="allow",
                )
            ]
        )

    app._load_catalog_model = fake_load_catalog  # type: ignore[method-assign]

    await app._handle_successful_command("defenseclaw", ("skill", "allow", "clean-skill"))  # noqa: SLF001

    assert reloaded == ["skills"]
    assert skills.selected() is not None
    assert skills.selected().status == "allowed"
    assert skills.selected().actions == "allowed"
    assert "allowed" in app._detail_text()  # noqa: SLF001


@pytest.mark.asyncio
async def test_successful_tool_policy_mutation_refreshes_and_rerenders_loaded_tools_panel() -> None:
    class Store:
        def __init__(self) -> None:
            self.entries = [
                SimpleNamespace(
                    target_name="@codex/write_file",
                    actions=SimpleNamespace(install="block"),
                    reason="manual block",
                    updated_at=None,
                )
            ]

        def list_actions_by_type(self, target_type: str) -> list[SimpleNamespace]:
            assert target_type == "tool"
            return self.entries

    store = Store()
    tools = ToolsPanelModel(store)
    tools.show_connector_column = True
    tools.set_connector_filter("codex")
    tools.refresh()
    app = DefenseClawTUI(tools_model=tools)
    app.active_panel = "tools"
    rendered: list[bool] = []

    def fake_render_chrome() -> None:
        rendered.append(True)

    app._render_chrome = fake_render_chrome  # type: ignore[method-assign]
    store.entries = [
        SimpleNamespace(
            target_name="@codex/write_file",
            actions=SimpleNamespace(install="allow"),
            reason="manual allow",
            updated_at=None,
        )
    ]

    await app._handle_successful_command("defenseclaw", ("tool", "allow", "write_file"))  # noqa: SLF001

    assert rendered == [True]
    assert tools.selected() is not None
    assert tools.selected().connector == "codex"
    assert tools.selected().status == "allowed"
    assert tools.selected().dispatch_target == "write_file"


def test_catalog_mutation_command_classifier_ignores_read_only_commands() -> None:
    assert _catalog_panel_invalidated_by_command(("skill", "allow", "clean-skill")) == "skills"
    assert _catalog_panel_invalidated_by_command(("skill", "list", "--json")) is None
    assert _catalog_panel_invalidated_by_command(("mcp", "set", "filesystem")) == "mcps"
    assert _catalog_panel_invalidated_by_command(("plugin", "info", "x")) is None
    assert _catalog_panel_invalidated_by_command(("tool", "block", "write_file")) == "tools"


def test_load_doctor_cache_schema_v2_preserves_health_and_repairs(tmp_path) -> None:
    (tmp_path / "doctor_cache.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "captured_at": "2026-05-21T02:31:22Z",
                "mode": "repair",
                "outcome": "failed",
                "exit_code": 1,
                "passed": 99,
                "failed": 99,
                "summary": {
                    "passed": 7,
                    "failed": 0,
                    "warned": 0,
                    "skipped": 1,
                },
                "checks": [{"status": "pass", "label": "Config", "detail": "valid"}],
                "repair_summary": {
                    "planned": 0,
                    "applied": 1,
                    "failed": 0,
                    "blocked": 1,
                    "manual": 0,
                    "noop": 0,
                    "declined": 0,
                    "requires_confirmation": 0,
                },
                # The detail record independently prevents a false green even
                # if a stale or partially written summary understates failures.
                "repairs": [
                    {"state": "applied", "label": "protect dotenv"},
                    {"state": "failed", "label": "restart gateway"},
                ],
            }
        ),
        encoding="utf-8",
    )
    app = DefenseClawTUI(data_dir=tmp_path)

    app._load_doctor_cache()  # noqa: SLF001 - exercise the disk consumer.

    cache = app.overview_model.doctor
    assert cache is not None
    assert (cache.passed, cache.failed, cache.warned, cache.skipped) == (7, 0, 0, 1)
    assert cache.repair_count("applied") == 1
    assert cache.repair_count("failed") == 1
    assert cache.repair_count("blocked") == 1
    box = app.overview_model.doctor_box(now=datetime(2026, 5, 21, 2, 31, 22, tzinfo=timezone.utc))
    assert box.summary_parts == ("7 pass", "1 skip")
    assert box.repair_summary_parts == ("1 applied", "1 failed", "1 blocked")
    assert box.run_outcome == "failed"
    assert box.all_green is False


def test_overview_renders_schema_v2_outcome_and_repairs_in_both_layouts() -> None:
    from rich.console import Console

    overview = OverviewPanelModel(OverviewConfig(), version="test")
    overview.set_doctor_cache(
        DoctorCache(
            captured_at=datetime.now(timezone.utc),
            passed=7,
            schema_version=2,
            mode="repair",
            outcome="failed",
            exit_code=1,
            repair_summary=DoctorRepairSummary(applied=1, failed=1, blocked=1),
            repair_states=("applied", "failed", "blocked"),
        )
    )
    app = DefenseClawTUI(overview_model=overview)

    compact = app._overview_body_text(overview.service_cards())  # noqa: SLF001
    console = Console(file=io.StringIO(), width=220, height=100, record=True)
    console.print(app._overview_renderable())  # noqa: SLF001
    wide = console.export_text()

    assert "outcome=failed" in compact
    assert "Repairs  1 applied  1 failed  1 blocked" in compact
    assert "Outcome  FAILED" in wide
    assert "Repairs  1 applied  1 failed  1 blocked" in wide


def test_load_doctor_cache_rejects_incomplete_schema_v2_as_healthy(tmp_path) -> None:
    (tmp_path / "doctor_cache.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "captured_at": "2026-05-21T02:31:22Z",
                "mode": "repair",
                "outcome": "healthy",
                # Missing exit_code and repair_summary: this may be truncated
                # or written by an incompatible producer, so it cannot restore
                # a green state even though its aggregate claims success.
                "summary": {"passed": 1, "failed": 0, "warned": 0, "skipped": 0},
                "checks": [{"status": "pass", "label": "Config", "detail": "valid"}],
                "repairs": [],
            }
        ),
        encoding="utf-8",
    )
    app = DefenseClawTUI(data_dir=tmp_path)

    app._load_doctor_cache()  # noqa: SLF001 - exercise the disk consumer.

    cache = app.overview_model.doctor
    assert cache is not None
    assert cache.cache_valid is False
    assert cache.outcome_state() == "warning"
    box = app.overview_model.doctor_box(now=datetime(2026, 5, 21, 2, 31, 22, tzinfo=timezone.utc))
    assert box.run_outcome == "warning"
    assert box.all_green is False


@pytest.mark.parametrize(
    "payload",
    (
        {
            "captured_at": "2026-05-21T02:31:22Z",
            "passed": "1",
            "failed": 0,
            "warned": 0,
            "skipped": 0,
            "checks": [],
        },
        {
            "schema_version": 2,
            "mode": "check",
            "outcome": "healthy",
            "exit_code": 0,
            "summary": {"passed": 1, "failed": 0, "warned": 0, "skipped": 0},
            "checks": [],
            "repair_summary": {
                "planned": 0,
                "applied": 0,
                "failed": 0,
                "blocked": 0,
                "manual": 0,
                "noop": 0,
                "declined": 0,
                "requires_confirmation": 0,
            },
            "repairs": [],
        },
    ),
)
def test_load_doctor_cache_rejects_malformed_or_undated_green_payload(tmp_path, payload) -> None:
    (tmp_path / "doctor_cache.json").write_text(json.dumps(payload), encoding="utf-8")
    app = DefenseClawTUI(data_dir=tmp_path)

    app._load_doctor_cache()  # noqa: SLF001 - exercise the disk consumer.

    cache = app.overview_model.doctor
    assert cache is not None
    assert cache.cache_valid is False
    assert cache.outcome_state(now=datetime(2026, 5, 21, 2, 31, 22, tzinfo=timezone.utc)) == "warning"
    assert app.overview_model.doctor_box(now=datetime(2026, 5, 21, 2, 31, 22, tzinfo=timezone.utc)).all_green is False


@pytest.mark.parametrize("repair", ({}, {"state": ""}))
def test_load_doctor_cache_rejects_blank_repair_state_as_healthy(tmp_path, repair) -> None:
    (tmp_path / "doctor_cache.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "captured_at": "2026-05-21T02:31:22Z",
                "mode": "repair",
                "outcome": "healthy",
                "exit_code": 0,
                "summary": {"passed": 1, "failed": 0, "warned": 0, "skipped": 0},
                "checks": [{"status": "pass", "label": "Config", "detail": "valid"}],
                "repair_summary": {
                    "planned": 0,
                    "applied": 0,
                    "failed": 0,
                    "blocked": 0,
                    "manual": 0,
                    "noop": 0,
                    "declined": 0,
                    "requires_confirmation": 0,
                },
                "repairs": [repair],
            }
        ),
        encoding="utf-8",
    )
    app = DefenseClawTUI(data_dir=tmp_path)

    app._load_doctor_cache()  # noqa: SLF001 - exercise the disk consumer.

    cache = app.overview_model.doctor
    assert cache is not None
    assert cache.cache_valid is False
    assert cache.repair_states == ("",)
    assert cache.outcome_state() == "warning"
    box = app.overview_model.doctor_box(now=datetime(2026, 5, 21, 2, 31, 22, tzinfo=timezone.utc))
    assert box.run_outcome == "warning"
    assert box.all_green is False


def test_load_doctor_cache_replaces_prior_green_when_refresh_is_malformed(tmp_path, monkeypatch) -> None:
    path = tmp_path / "doctor_cache.json"
    path.write_text(
        json.dumps(
            {
                "captured_at": "2026-05-21T02:31:22Z",
                "passed": 1,
                "failed": 0,
                "warned": 0,
                "skipped": 0,
                "checks": [{"status": "pass", "label": "Config", "detail": "valid"}],
            }
        ),
        encoding="utf-8",
    )
    app = DefenseClawTUI(data_dir=tmp_path)
    readiness_syncs: list[None] = []
    monkeypatch.setattr(app, "_sync_setup_readiness", lambda: readiness_syncs.append(None))

    app._load_doctor_cache()  # noqa: SLF001 - exercise the disk consumer.
    assert app.overview_model.doctor is not None
    assert app.overview_model.doctor_box(now=datetime(2026, 5, 21, 2, 31, 22, tzinfo=timezone.utc)).all_green

    path.write_text("{", encoding="utf-8")
    app._load_doctor_cache()  # noqa: SLF001 - malformed refresh must replace green state.

    cache = app.overview_model.doctor
    assert cache is not None
    assert cache.cache_valid is False
    assert cache.warned == 1
    assert cache.outcome_state() == "warning"
    assert len(cache.checks) == 1
    assert cache.checks[0].status == "warn"
    assert cache.checks[0].label == "Doctor cache"
    assert "malformed JSON" in cache.checks[0].detail
    assert readiness_syncs == [None, None]


def test_load_doctor_cache_replaces_prior_green_when_cache_disappears(tmp_path, monkeypatch) -> None:
    path = tmp_path / "doctor_cache.json"
    path.write_text(
        json.dumps(
            {
                "captured_at": "2026-05-21T02:31:22Z",
                "passed": 1,
                "failed": 0,
                "warned": 0,
                "skipped": 0,
                "checks": [{"status": "pass", "label": "Config", "detail": "valid"}],
            }
        ),
        encoding="utf-8",
    )
    app = DefenseClawTUI(data_dir=tmp_path)
    readiness_syncs: list[None] = []
    monkeypatch.setattr(app, "_sync_setup_readiness", lambda: readiness_syncs.append(None))

    app._load_doctor_cache()  # noqa: SLF001 - exercise the disk consumer.
    assert app.overview_model.doctor_box(now=datetime(2026, 5, 21, 2, 31, 22, tzinfo=timezone.utc)).all_green

    path.unlink()
    app._load_doctor_cache()  # noqa: SLF001 - a deleted refresh must replace green state.

    cache = app.overview_model.doctor
    assert cache is not None
    assert cache.cache_valid is False
    assert cache.warned == 1
    assert cache.outcome_state() == "warning"
    assert cache.checks[0].status == "warn"
    assert "no longer exists" in cache.checks[0].detail
    assert app.overview_model.keys_status().available is False
    assert readiness_syncs == [None, None]


def test_load_doctor_cache_fails_closed_on_invalid_utf8(tmp_path) -> None:
    (tmp_path / "doctor_cache.json").write_bytes(b"\xff\xfe\x00")
    app = DefenseClawTUI(data_dir=tmp_path)
    app.overview_model.set_doctor_cache(
        DoctorCache(
            captured_at=datetime.now(timezone.utc),
            passed=1,
            outcome="healthy",
        )
    )

    app._load_doctor_cache()  # noqa: SLF001 - invalid bytes must replace green state.

    cache = app.overview_model.doctor
    assert cache is not None
    assert cache.cache_valid is False
    assert cache.outcome_state() == "warning"
    assert cache.checks[0].status == "warn"
    assert "not valid UTF-8 JSON" in cache.checks[0].detail


def test_load_doctor_cache_fails_closed_when_existing_cache_cannot_be_read(tmp_path, monkeypatch) -> None:
    path = tmp_path / "doctor_cache.json"
    path.write_text("{}", encoding="utf-8")
    app = DefenseClawTUI(data_dir=tmp_path)
    readiness_syncs: list[None] = []
    monkeypatch.setattr(app, "_sync_setup_readiness", lambda: readiness_syncs.append(None))
    original_read_text = Path.read_text

    def _raise_for_doctor_cache(candidate: Path, *args, **kwargs):
        if candidate == path:
            raise OSError("permission denied")
        return original_read_text(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _raise_for_doctor_cache)

    app._load_doctor_cache()  # noqa: SLF001 - exercise the disk consumer.

    cache = app.overview_model.doctor
    assert cache is not None
    assert cache.cache_valid is False
    assert cache.outcome_state() == "warning"
    assert "could not be read" in cache.checks[0].detail
    assert readiness_syncs == [None]


@pytest.mark.parametrize("payload", ([], "healthy", 1, None))
def test_load_doctor_cache_fails_closed_on_non_object_payload(tmp_path, monkeypatch, payload) -> None:
    (tmp_path / "doctor_cache.json").write_text(json.dumps(payload), encoding="utf-8")
    app = DefenseClawTUI(data_dir=tmp_path)
    readiness_syncs: list[None] = []
    monkeypatch.setattr(app, "_sync_setup_readiness", lambda: readiness_syncs.append(None))

    app._load_doctor_cache()  # noqa: SLF001 - exercise the disk consumer.

    cache = app.overview_model.doctor
    assert cache is not None
    assert cache.cache_valid is False
    assert cache.outcome_state() == "warning"
    assert "JSON object" in cache.checks[0].detail
    assert readiness_syncs == [None]


@pytest.mark.asyncio
async def test_raw_process_log_tail_is_read_off_the_textual_thread(tmp_path, monkeypatch) -> None:
    from defenseclaw.tui.panels import logs as logs_module

    (tmp_path / "gateway.log").write_text("gateway ready\n", encoding="utf-8")
    app = DefenseClawTUI(data_dir=tmp_path)
    app.active_panel = "logs"
    app.logs_model.source = "gateway"
    request = app.logs_model.pending_file_refresh("gateway")
    assert request is not None
    reader_threads: list[int] = []
    raw_reader = logs_module._tail_text_file

    def tracked_reader(path, **kwargs):
        reader_threads.append(threading.get_ident())
        return raw_reader(path, **kwargs)

    monkeypatch.setattr(logs_module, "_tail_text_file", tracked_reader)
    await app._run_log_file_refresh(request)  # noqa: SLF001

    assert reader_threads
    assert all(thread_id != threading.get_ident() for thread_id in reader_threads)
    assert app.logs_model.lines["gateway"] == ["gateway ready"]


def test_scheduled_background_polls_are_single_flight(tmp_path) -> None:
    config = SimpleNamespace(
        data_dir=str(tmp_path),
        gateway=SimpleNamespace(api_port=18970, host="127.0.0.1", token="token"),
    )
    app = DefenseClawTUI(config=config)
    scheduled: list[object] = []

    def fake_run_worker(coro: object, **_kwargs: object) -> None:
        scheduled.append(coro)

    def close_last_scheduled() -> None:
        close = getattr(scheduled.pop(), "close", None)
        if callable(close):
            close()

    app.run_worker = fake_run_worker  # type: ignore[method-assign]

    app._schedule_health_poll()  # noqa: SLF001
    app._schedule_health_poll()  # noqa: SLF001
    assert len(scheduled) == 1
    assert app._health_poll_running is True  # noqa: SLF001
    close_last_scheduled()
    app._health_poll_running = False  # noqa: SLF001

    app._schedule_ai_usage_poll()  # noqa: SLF001
    app._schedule_ai_usage_poll()  # noqa: SLF001
    assert len(scheduled) == 1
    assert app._ai_usage_poll_running is True  # noqa: SLF001
    close_last_scheduled()
    app._ai_usage_poll_running = False  # noqa: SLF001

    app._schedule_credentials_refresh()  # noqa: SLF001
    app._schedule_credentials_refresh()  # noqa: SLF001
    assert len(scheduled) == 1
    assert app._credentials_refresh_running is True  # noqa: SLF001
    close_last_scheduled()


@pytest.mark.asyncio
async def test_background_poll_wrappers_clear_single_flight_flags(tmp_path) -> None:
    config = SimpleNamespace(
        data_dir=str(tmp_path),
        gateway=SimpleNamespace(api_port=18970, host="127.0.0.1", token="token"),
    )
    app = DefenseClawTUI(config=config)
    calls: list[str] = []

    async def fake_health() -> None:
        calls.append("health")

    async def fake_ai_usage(*, force_render: bool) -> None:
        calls.append(f"ai:{force_render}")

    async def fake_credentials() -> None:
        calls.append("credentials")

    app._poll_health = fake_health  # type: ignore[method-assign]
    app._poll_ai_usage = fake_ai_usage  # type: ignore[method-assign]
    app._load_setup_credentials = fake_credentials  # type: ignore[method-assign]

    app._health_poll_running = True  # noqa: SLF001
    await app._poll_health_once()  # noqa: SLF001
    assert app._health_poll_running is False  # noqa: SLF001

    app._ai_usage_poll_running = True  # noqa: SLF001
    await app._poll_ai_usage_once(force_render=False)  # noqa: SLF001
    assert app._ai_usage_poll_running is False  # noqa: SLF001

    app._credentials_refresh_running = True  # noqa: SLF001
    await app._refresh_credentials_once()  # noqa: SLF001
    assert app._credentials_refresh_running is False  # noqa: SLF001
    assert calls == ["health", "ai:False", "credentials"]


@pytest.mark.asyncio
async def test_health_poll_allows_scrolled_repaint_when_live_overview_changes(
    monkeypatch,
    tmp_path,
) -> None:
    now = datetime.now(timezone.utc)
    cfg = OverviewConfig(
        data_dir=str(tmp_path),
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "observe"), ("cursor", "observe")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(
        HealthSnapshot(
            gateway=SubsystemHealth(state="running"),
            connectors=(
                ConnectorHealth(
                    name="codex",
                    state="running",
                    since=(now - timedelta(minutes=5)).isoformat(),
                    requests=1,
                    last_activity_at=(now - timedelta(seconds=30)).isoformat(),
                ),
                ConnectorHealth(name="cursor", state="running"),
            ),
        )
    )
    config = SimpleNamespace(
        data_dir=str(tmp_path),
        gateway=SimpleNamespace(api_port=18970, host="127.0.0.1", token="token"),
    )
    app = DefenseClawTUI(config=config, overview_model=overview)
    with app._connector_hook_event_render_cache():
        app._overview_live_data_signature_cache = app._overview_live_data_signature()

    fresh = HealthSnapshot(
        gateway=SubsystemHealth(state="running"),
        connectors=(
            ConnectorHealth(
                name="codex",
                state="running",
                since=(now - timedelta(minutes=5)).isoformat(),
                requests=5,
                last_activity_at=now.isoformat(),
            ),
            ConnectorHealth(name="cursor", state="running"),
        ),
    )
    monkeypatch.setattr("defenseclaw.tui.app._fetch_gateway_health", lambda _cfg: fresh)
    monkeypatch.setattr(app, "_propagate_connector", lambda _snapshot: None)
    monkeypatch.setattr(app, "_mark_restart_if_gateway_restarted", lambda _snapshot: None)
    monkeypatch.setattr(app, "_sync_setup_readiness", lambda: None)
    monkeypatch.setattr(app, "_render_overview_scope_indicator", lambda: None)
    scheduled: list[bool] = []
    monkeypatch.setattr(
        app,
        "_schedule_overview_sampled_refresh",
        lambda *, allow_scrolled=False, **_kwargs: scheduled.append(allow_scrolled),
    )
    app.active_panel = "overview"
    app.help_open = False

    await app._poll_health()

    assert scheduled == [True]
    rows = {row.connector: row for row in app._overview_connector_rows()}
    assert rows["codex"].calls == 0
    assert rows["codex"].last_activity_at == now


def test_slow_refresh_scheduler_is_single_flight(tmp_path) -> None:
    app = DefenseClawTUI(config=SimpleNamespace(data_dir=str(tmp_path)))
    scheduled: list[object] = []

    def fake_run_worker(coro: object, **_kwargs: object) -> None:
        scheduled.append(coro)

    def close_last_scheduled() -> None:
        close = getattr(scheduled.pop(), "close", None)
        if callable(close):
            close()

    app.run_worker = fake_run_worker  # type: ignore[method-assign]

    app._schedule_slow_refresh()  # noqa: SLF001
    app._schedule_slow_refresh()  # noqa: SLF001

    assert len(scheduled) == 1
    assert app._slow_refresh_running is True  # noqa: SLF001
    close_last_scheduled()


@pytest.mark.asyncio
async def test_slow_refresh_uses_tools_store_refresh_without_catalog_subprocess(tmp_path) -> None:
    app = DefenseClawTUI(config=SimpleNamespace(data_dir=str(tmp_path)))
    app.tools_model.loaded = True
    refreshed: list[str] = []
    loaded: list[str] = []

    def fake_tools_refresh() -> None:
        refreshed.append("tools")

    async def fake_load_catalog(panel: str) -> None:
        loaded.append(panel)

    app.tools_model.refresh = fake_tools_refresh  # type: ignore[method-assign]
    app._load_catalog_model = fake_load_catalog  # type: ignore[method-assign]

    app._slow_refresh_running = True  # noqa: SLF001
    await app._run_slow_refresh()  # noqa: SLF001

    assert refreshed == ["tools"]
    assert loaded == []
    assert app._slow_refresh_running is False  # noqa: SLF001


@pytest.mark.asyncio
async def test_slow_tools_refresh_uses_repository_worker_when_available(tmp_path) -> None:
    app = DefenseClawTUI(config=SimpleNamespace(data_dir=str(tmp_path)))
    app.tools_model.loaded = True
    app._read_repository = object()  # type: ignore[assignment]  # noqa: SLF001
    scheduled: list[bool] = []
    app._schedule_data_refresh = (  # type: ignore[method-assign]
        lambda *, force=False: scheduled.append(force)
    )
    app.tools_model.refresh = lambda: pytest.fail("tools SQLite read ran on UI loop")  # type: ignore[method-assign]

    app._slow_refresh_running = True  # noqa: SLF001
    await app._run_slow_refresh()  # noqa: SLF001

    assert scheduled == [True]
    assert app._slow_refresh_running is False  # noqa: SLF001


@pytest.mark.asyncio
async def test_tool_mutation_refresh_uses_repository_worker(tmp_path) -> None:
    app = DefenseClawTUI(config=SimpleNamespace(data_dir=str(tmp_path)))
    app.tools_model.loaded = True
    app._read_repository = object()  # type: ignore[assignment]  # noqa: SLF001
    scheduled: list[bool] = []
    app._schedule_data_refresh = (  # type: ignore[method-assign]
        lambda *, force=False: scheduled.append(force)
    )
    app.tools_model.refresh = lambda: pytest.fail("tools SQLite read ran on UI loop")  # type: ignore[method-assign]

    await app._refresh_loaded_catalog_after_mutation("tools")  # noqa: SLF001

    assert scheduled == [True]


def test_fetch_ai_usage_uses_gateway_auth_and_accept_headers() -> None:
    seen: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API.
            seen["path"] = self.path
            seen["authorization"] = self.headers.get("Authorization", "")
            seen["accept"] = self.headers.get("Accept", "")
            body = (
                b'{"enabled":true,"summary":{"active_signals":1,"new_signals":1},'
                b'"signals":[{"signal_id":"sig1","product":"Codex","vendor":"OpenAI","state":"new"}]}'
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config = SimpleNamespace(
            gateway=SimpleNamespace(
                api_port=server.server_port,
                host="127.0.0.1",
                resolved_token=lambda: "test-bearer-xyz",
            )
        )
        snapshot = _fetch_ai_usage(config)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert snapshot is not None
    assert snapshot.enabled is True
    assert snapshot.summary.active_signals == 1
    assert snapshot.fetched_at is not None
    assert seen == {
        "path": "/api/v1/ai-usage",
        "authorization": "Bearer test-bearer-xyz",
        "accept": "application/json",
    }


# ---------------------------------------------------------------------------
# Activity panel button bar + stdin pipe (Phase 1a click-first plan).
# These regression tests lock in the bar's presence so a future
# refactor can't strand operators in front of an interactive subprocess
# (the original "Selection [3]:" bug) with no clickable way to answer.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# AI Discovery panel button bar (Phase 1b click-first plan).
# Locks in the action bar so the panel is never view-only again —
# previously operators had to leave the panel to enable/scan via the
# drawer, which was the exact friction the user called out.
# ---------------------------------------------------------------------------


def test_safe_body_renderable_falls_back_on_invalid_style() -> None:
    """Bogus single-letter ``[e]`` markup must not crash rendering.

    The audit toolbar template ``[{action.key}] {action.label}`` was
    emitting strings like ``[e] export filter`` that Rich parsed as a
    style tag named ``e``. When the renderer later resolved that
    style it raised ``MissingStyle: 'e' is not a valid color`` and
    tore down the entire TUI. ``_safe_body_renderable`` must validate
    styles up front and fall back to plain text rather than re-throw.
    """

    rendered = DefenseClawTUI._safe_body_renderable(  # noqa: SLF001 - exercising defense in depth.
        "500 shown of 500 events   [e] export filter"
    )
    # We don't care which path the wrapper took (escape vs plain
    # fallback); we only care that it returned a Text object instead
    # of crashing — that's the regression we lock in.
    plain = rendered.plain
    assert "export" in plain
    assert "filter" in plain


def test_audit_body_text_escapes_action_key_brackets() -> None:
    """Escaped brackets keep ``[e] export`` rendered as literal text.

    Without escaping, the audit body crashes with ``MissingStyle`` the
    moment the panel renders. We assert both that the raw body string
    contains the escape and that the safety wrapper resolves it back
    to literal ``[e] export`` plain text.
    """

    panel = AuditPanelModel()
    app = DefenseClawTUI(audit_model=panel)
    app.active_panel = "audit"
    body = app._audit_body_text()  # noqa: SLF001 - regression for crash on switch.
    assert "\\[e]" in body
    rendered = DefenseClawTUI._safe_body_renderable(body)  # noqa: SLF001
    assert "[e] export" in rendered.plain


def test_mark_restart_passes_started_at_to_setup_model() -> None:
    """The health worker must pass ``started_at`` into the setup model.

    Calling ``mark_restart_started`` without arguments raised
    ``TypeError`` and crashed ``_poll_health`` on every poll once the
    gateway restarted (which is exactly what ``setup`` toggles like
    redaction trigger). Verify both the happy path forwards the
    timestamp *and* a model that doesn't accept that signature falls
    back to ``clear_restart_queue`` instead of bubbling.
    """

    class FakeSetupHappy:
        def __init__(self) -> None:
            self.received: list[str] = []

        def mark_restart_started(self, started_at: str) -> bool:
            self.received.append(started_at)
            return True

        def clear_restart_queue(self) -> None:
            self.received.append("CLEARED")

    class FakeSetupLegacy:
        def __init__(self) -> None:
            self.cleared = False

        def mark_restart_started(self) -> bool:  # pragma: no cover - intentional bad signature
            raise TypeError("legacy stub mimicking pre-Phase-2 SetupPanelModel")

        def clear_restart_queue(self) -> None:
            self.cleared = True

    happy = FakeSetupHappy()
    app = DefenseClawTUI(setup_model=happy)
    app._last_gateway_started_at = "old-timestamp"  # noqa: SLF001 - exercising poll path.
    snapshot = SimpleNamespace(started_at="new-timestamp")
    app._mark_restart_if_gateway_restarted(snapshot)  # type: ignore[arg-type]  # noqa: SLF001
    assert happy.received == ["new-timestamp"]
    assert app._last_gateway_started_at == "new-timestamp"  # noqa: SLF001

    legacy = FakeSetupLegacy()
    app2 = DefenseClawTUI(setup_model=legacy)
    app2._last_gateway_started_at = "old"  # noqa: SLF001
    app2._mark_restart_if_gateway_restarted(SimpleNamespace(started_at="newer"))  # type: ignore[arg-type]  # noqa: SLF001
    assert legacy.cleared is True
    assert app2._last_gateway_started_at == "newer"  # noqa: SLF001


def test_audit_body_text_escapes_bracketed_filter_and_search_input() -> None:
    """User-supplied filter/search must not re-trigger the markup crash.

    The action-key fix escaped the static ``[e] export`` legend, but the
    Audit panel also echoes the operator's filter chip and the live ``/``
    search box. Both of those echo whatever the user typed — so a search
    for ``target:[skill]`` previously crashed the render pipeline with
    ``StyleSyntaxError: 'skill' is not a valid color``. Lock both paths
    in so future toolbar tweaks can't silently re-open the bug.
    """

    from rich.style import Style
    from rich.text import Text

    for hostile in ("target:[skill]", "run:[abc-123]", "[bogus]"):
        panel = AuditPanelModel()
        panel.filter_text = hostile
        panel.filtering = True
        app = DefenseClawTUI(audit_model=panel)
        app.active_panel = "audit"
        body = app._audit_body_text()  # noqa: SLF001 - regression for user-input crash.

        # ``from_markup`` is lazy: bad style names only blow up when
        # the renderer resolves them. Walk the spans and resolve each
        # style up-front — any unescaped ``[skill]`` shows up here.
        text = Text.from_markup(body)
        for span in text.spans:
            if isinstance(span.style, str) and span.style:
                Style.parse(span.style)  # raises if escape was missed.

        rendered = DefenseClawTUI._safe_body_renderable(body)  # noqa: SLF001
        assert hostile in rendered.plain, f"user input {hostile!r} dropped from rendered body"


def test_refresh_cached_config_closes_stale_audit_store(monkeypatch, tmp_path) -> None:
    """Reload must close the previous SQLite handles, not leak them.

    ``_refresh_cached_config`` swaps ``alerts_model.store`` and
    ``audit_model.store`` with a freshly-opened ``Store`` on every
    setup-driven reload. Replacing the attribute without calling
    ``close()`` on the prior handle leaked a file descriptor per
    reload, and a typical session triggers several (connector pick,
    registry add, redaction toggle, etc.). Verify the stale store
    gets closed and that an identical post-swap handle (operator
    just toggled a flag with no audit_db change) is left untouched.
    """

    class FakeStore:
        def __init__(self, tag: str) -> None:
            self.tag = tag
            self.closed = False

        def close(self) -> None:
            self.closed = True

    old_store = FakeStore("old")
    new_store = FakeStore("new")

    app = DefenseClawTUI(
        alerts_model=AlertsPanelModel(store=old_store),
        audit_model=AuditPanelModel(store=old_store),
    )
    # Stub the heavy fan-out so we only exercise the close-on-swap
    # branch. We don't need a real config reload — ``_audit_store``
    # is the seam that produces the replacement handle.
    monkeypatch.setattr(
        "defenseclaw.tui.app._audit_store",
        lambda _cfg: new_store,
    )
    monkeypatch.setattr(app, "_refresh_models_from_disk", lambda: None)
    monkeypatch.setattr(app, "_sync_setup_readiness", lambda: None)
    monkeypatch.setattr(app, "_propagate_connector", lambda _h: None)
    monkeypatch.setattr(app, "_write_activity", lambda *a, **kw: None)
    monkeypatch.setattr("defenseclaw.tui.app.config_module.load", lambda: app.config)

    app._refresh_cached_config()  # noqa: SLF001 - exercising reload path.

    assert old_store.closed is True, "previous audit store handle leaked"
    assert new_store.closed is False
    assert app.alerts_model.store is new_store
    assert app.audit_model.store is new_store
    assert app.tools_model.store is new_store

    # Second reload returning the SAME handle must NOT close it
    # (otherwise we'd close the live store we just installed).
    app._refresh_cached_config()  # noqa: SLF001
    assert new_store.closed is False, "live store was closed by no-op reload"


def test_refresh_cached_config_replaces_snapshot_repository(monkeypatch, tmp_path) -> None:
    old_db = tmp_path / "old.db"
    new_db = tmp_path / "new.db"
    old_db.touch()
    new_db.touch()
    old_config = SimpleNamespace(data_dir=str(tmp_path), audit_db=str(old_db))
    new_config = SimpleNamespace(data_dir=str(tmp_path), audit_db=str(new_db))

    class FakeStore:
        def close(self) -> None:
            pass

    stores = {str(old_db): FakeStore(), str(new_db): FakeStore()}

    class FakeRepository:
        def __init__(self, path: str) -> None:
            self.path = path
            self.closed = False

        def close(self) -> None:
            self.closed = True

    repositories: list[FakeRepository] = []

    def repository_factory(path: str) -> FakeRepository:
        repository = FakeRepository(path)
        repositories.append(repository)
        return repository

    monkeypatch.setattr(
        "defenseclaw.tui.app._audit_store",
        lambda cfg: stores[str(cfg.audit_db)],
    )
    monkeypatch.setattr("defenseclaw.tui.app.TUIReadRepository", repository_factory)
    app = DefenseClawTUI(config=old_config)
    app._read_snapshot = object()  # type: ignore[assignment]  # noqa: SLF001
    app._snapshot_panel_revisions = {"audit": 7}  # noqa: SLF001
    monkeypatch.setattr("defenseclaw.tui.app.config_module.load", lambda: new_config)
    monkeypatch.setattr(app, "_refresh_models_from_disk", lambda: None)
    monkeypatch.setattr(app, "_sync_setup_readiness", lambda: None)
    monkeypatch.setattr(app, "_propagate_connector", lambda _health: None)
    monkeypatch.setattr(app, "_schedule_observability_status_load", lambda: None)

    app._refresh_cached_config()  # noqa: SLF001

    assert [repository.path for repository in repositories] == [str(old_db), str(new_db)]
    assert repositories[0].closed is True
    assert repositories[1].closed is False
    assert app._read_repository is repositories[1]  # noqa: SLF001
    assert app._read_snapshot is None  # noqa: SLF001
    assert app._snapshot_panel_revisions == {}  # noqa: SLF001
    assert app.tools_model.store is stores[str(new_db)]


def test_startup_binds_alerts_model_to_audit_store(monkeypatch, tmp_path) -> None:
    """Startup alerts refresh must use the summary reader, not a second DB scan."""

    store = object()
    monkeypatch.setattr("defenseclaw.tui.app._audit_store", lambda _cfg: store)

    app = DefenseClawTUI(
        config=SimpleNamespace(audit_db=str(tmp_path / "audit.sqlite")),
        data_dir=tmp_path,
    )

    assert app.alerts_model.store is store


def test_startup_retries_configured_audit_db_that_does_not_exist_yet(monkeypatch, tmp_path) -> None:
    audit_db = tmp_path / "gateway-will-create.db"
    paths: list[str] = []

    class Repository:
        def __init__(self, path: str) -> None:
            paths.append(path)

        def close(self) -> None:
            pass

    monkeypatch.setattr("defenseclaw.tui.app.TUIReadRepository", Repository)
    app = DefenseClawTUI(config=SimpleNamespace(audit_db=str(audit_db)))

    assert paths == [str(audit_db)]
    assert app._read_repository is not None  # noqa: SLF001


def test_repository_mode_never_falls_back_to_ui_thread_sql_before_first_snapshot() -> None:
    calls: list[str] = []

    class Store:
        def count_scan_results_since(self, _since: object) -> int:
            calls.append("scan-count")
            return 0

        def connector_hook_event_stats(self) -> dict[str, object]:
            calls.append("hook-stats")
            return {}

        def list_connector_hook_event_summaries(self, _limit: int) -> list[object]:
            calls.append("hook-events")
            return []

    store = Store()
    app = DefenseClawTUI(
        alerts_model=AlertsPanelModel(store=store),
        audit_model=AuditPanelModel(store=store),
    )
    app._read_repository = object()  # type: ignore[assignment]  # noqa: SLF001
    app._read_snapshot = None  # noqa: SLF001

    app._overview_session_enforcement_counts()  # noqa: SLF001
    app._connector_hook_event_stats()  # noqa: SLF001
    app._recent_connector_hook_events()  # noqa: SLF001

    assert calls == []


def test_overview_uses_repository_session_scan_count() -> None:
    from defenseclaw.tui.services.read_repository import TUIReadSnapshot

    app = DefenseClawTUI()
    app._read_repository = object()  # type: ignore[assignment]  # noqa: SLF001
    app._read_snapshot = TUIReadSnapshot(  # noqa: SLF001
        revision=1,
        data_version=1,
        enforcement_counts=Counts(total_scans=99),
        session_scan_count=4,
        session_scan_since=datetime(2026, 7, 10, tzinfo=timezone.utc),
    )
    app.overview_model.set_enforcement_counts(EnforcementCounts(total_scans=99))

    assert app._overview_session_enforcement_counts().total_scans == 4  # noqa: SLF001


def test_refresh_alerts_mirrors_loaded_alerts_with_cheap_enforcement_counts(tmp_path) -> None:
    """Refreshing alerts should mirror loaded canonical rows and cheap counts."""

    class FakeStore:
        def get_counts(self) -> object:
            raise AssertionError("refresh should not scan counts")

        def get_enforcement_counts(self) -> Counts:
            return Counts(
                blocked_skills=7,
                allowed_skills=8,
                blocked_mcps=9,
                allowed_mcps=10,
                total_scans=11,
            )

    alerts = AlertsPanelModel(store=FakeStore())
    alerts.set_events([AlertEvent(id="a1", severity="HIGH", action="scan", target="skill://one")])
    # This unit isolates the app-level count projection. Canonical SQLite
    # ingestion is covered by test_v8_event_history.py.
    alerts.refresh = lambda: None  # type: ignore[method-assign]
    overview = OverviewPanelModel()
    overview.set_enforcement_counts(
        EnforcementCounts(
            blocked_skills=2,
            allowed_skills=3,
            blocked_mcps=4,
            allowed_mcps=5,
            total_scans=6,
            active_alerts=999,
        )
    )
    app = DefenseClawTUI(
        data_dir=tmp_path,
        alerts_model=alerts,
        overview_model=overview,
    )

    app._refresh_alerts()  # noqa: SLF001 - regression for the startup refresh path.

    assert overview.enforcement == EnforcementCounts(
        blocked_skills=7,
        allowed_skills=8,
        blocked_mcps=9,
        allowed_mcps=10,
        total_scans=11,
        active_alerts=1,
    )


def test_safe_body_renderable_handles_bracketed_status_strings() -> None:
    """``_set_status`` now routes its f-string through ``_safe_body_renderable``.

    Several status callers pass operator-supplied text straight through
    (e.g. ``self.audit_model.active_filter_label()`` after typing
    ``target:[skill]`` into the ``/`` search box). The previous
    implementation inlined that text into a Rich-parsed f-string and
    inherited the same ``MissingStyle`` / ``StyleSyntaxError`` crash
    class the audit-body fix closed. Verify the exact composed string
    the new ``_set_status`` feeds into the widget — ``f"{text}  [#444444]│[/]  {strip}"`` —
    survives the defensive wrapper on hostile input that uses
    *invalid* style names (the actual crash trigger). Inputs that
    happen to spell a valid Rich style (``[red]``) still get
    interpreted as markup — that's a known UX wart of layering
    user text inside a markup-parsed f-string and is the reason
    source-side escaping (see ``_audit_body_text``) is preferred
    for the panels we've already fixed.
    """

    safe = DefenseClawTUI._safe_body_renderable  # noqa: SLF001 - exercising defense in depth.
    for hostile in (
        "target:[skill]",
        "run:[abc-xyz]",
        "search:[unmatched",  # unbalanced bracket -> MarkupError fallback.
    ):
        composed = f"{hostile}  [#444444]│[/]  Ready"
        rendered = safe(composed)
        assert isinstance(rendered, Text)
        # Defensive guarantee: no crash, and the operator's text
        # survives as literal characters in the rendered plain text
        # (either via the validator dropping the bogus span or the
        # MarkupError fallback returning the whole string verbatim).
        assert hostile in rendered.plain


def test_judge_history_prefix_escapes_index_brackets() -> None:
    """``judge_response_detail_pairs`` must escape numeric prefixes.

    Without escaping, the modal renders ``[1] Timestamp`` which Rich
    interprets as ANSI color 1 (red) for the entire row, and once
    the operator has 16+ retained rows the prefix flips to ``[16]``
    and explodes with ``MissingStyle: '16' is not a valid color``.
    """

    from defenseclaw.tui.screens.judge_history import judge_response_detail_pairs

    rows = [
        {
            "timestamp": "2026-05-21T00:00:00Z",
            "kind": "policy",
            "direction": "inbound",
            "action": "allow",
            "severity": "LOW",
            "category": "",
            "rule": "",
            "decision_score": 0.0,
            "abridged": False,
            "source": "judge",
            "request_id": "r1",
            "trace_id": "t1",
            "span_id": "s1",
            "model": "m",
        }
        for _ in range(2)
    ]
    pairs = judge_response_detail_pairs(rows)
    labels = [label for label, _ in pairs if label]
    assert any(label.startswith("\\[1]") for label in labels)
    assert any(label.startswith("\\[2]") for label in labels)
    for label in labels:
        assert not label.startswith("[1]")
        assert not label.startswith("[2]")


def test_setup_webhook_summary_escapes_status_brackets() -> None:
    """Webhook summaries must escape ``[enabled]`` / ``[disabled]``."""

    from defenseclaw.tui.panels.setup import _webhook_summary_fields

    cfg = {
        "webhooks": [
            {"type": "webhook", "name": "ops", "url": "https://example/test", "enabled": True},
            {"type": "webhook", "name": "audit", "url": "https://example/audit", "enabled": False},
        ]
    }
    fields = _webhook_summary_fields(cfg)
    summaries = [field.value for field in fields if field.value]
    assert any(summary.startswith("\\[enabled]") for summary in summaries)
    assert any(summary.startswith("\\[disabled]") for summary in summaries)
    for summary in summaries:
        assert not summary.startswith("[enabled]")
        assert not summary.startswith("[disabled]")


def test_mode_picker_choice_action_escapes_hotkey_brackets() -> None:
    """Mode-picker MenuActions must escape the hotkey bracket."""

    from defenseclaw.tui.screens.mode_picker import MODE_PICKER_CHOICES, _choice_action

    for choice in MODE_PICKER_CHOICES:
        action = _choice_action(choice, current_wire="")
        assert action.label.startswith("\\["), action.label
        assert f"\\[{choice.hotkey}]" in action.label


# ---------------------------------------------------------------------
# Phase-1 markup-safety regression suite. Together with the existing
# audit/judge-history/setup/mode-picker/consequence tests above, these
# cover every "must not crash" Rich-markup site we audited in the TUI
# (RichLog writes, command-progress snippet, native overview notices,
# native metric detail strings, hint bar, judge-history modal,
# command-preview modal, and the shared detail modal).
# ---------------------------------------------------------------------


_HOSTILE_CORPUS = (
    "plain text",
    "target:[skill]",
    "run:[abc]",
    "[INFO] starting",
    "[WARN] retrying",
    "[ERROR] something broke",
    "[OK] ready",
    "Selection [3]:",
    "prompt[16]",  # numeric color 16+ is invalid
    "path with brackets [a/b/c]",
    "unclosed [bracket",
    "nested [bold][skill]nope[/][/]",
    "chr [\\u001b[31mred\\u001b[0m]",
)


def test_safe_body_renderable_handles_hostile_corpus() -> None:
    """Every string in our hostile corpus must survive the safety
    wrapper — either parsed cleanly or falling back to plain text —
    and the original characters must show up in the rendered plain
    text. This is the regression net for every future panel author:
    if ``_body_text``/``_detail_text`` ever produces a string with the
    same shape, the rendering pipeline still won't crash the TUI.
    """

    safe = DefenseClawTUI._safe_body_renderable  # noqa: SLF001
    for hostile in _HOSTILE_CORPUS:
        rendered = safe(hostile)
        assert isinstance(rendered, Text)
        # The visible characters survive: both the bracket fallback
        # path (returns the raw string) and the markup-parsing path
        # (drops the spans) preserve the literal characters.
        assert hostile.replace("[/", "").replace("[/]", "") in rendered.plain or rendered.plain.startswith(hostile[:20])


def test_write_activity_safe_escapes_subprocess_output(monkeypatch) -> None:
    """``_write_activity_safe`` must hand a safe renderable to the
    Activity RichLog — that's the whole point of the helper. Without
    safe-handling, a subprocess line like ``[INFO] foo`` crashes the
    Rich parser and tears down the activity stream.

    Implementation note: the helper switched from ``rich_escape``
    (which left ANSI bytes intact and leaked them as visible
    ``[1;33m...`` in the UI) to ``Text.from_ansi`` (which converts
    ANSI SGR sequences AND treats remaining content as opaque text,
    closing both the markup crash AND the ANSI leak in one go).
    Verify we now hand a ``Text`` object with the literal content
    preserved.
    """

    from rich.text import Text

    captured: list = []

    class _FakeRichLog:
        def write(self, renderable) -> None:  # noqa: ANN001
            captured.append(renderable)

    fake = _FakeRichLog()
    app = DefenseClawTUI.__new__(DefenseClawTUI)
    app.activity_lines = []  # type: ignore[attr-defined]

    def _query_one(_selector, _expected_type):  # noqa: ANN001
        return fake

    monkeypatch.setattr(app, "query_one", _query_one, raising=False)
    # ``[skill]`` is the canonical risk shape — Rich's markup parser
    # treats it as an opening style tag. Text.from_ansi consumes
    # the entire string as opaque text (no markup re-parse), so the
    # literal brackets survive verbatim into the Text's ``.plain``
    # without needing a separate escape pass.
    app._write_activity_safe("prompt: [skill] continue")  # noqa: SLF001
    assert len(captured) == 1
    rendered = captured[0]
    assert isinstance(rendered, Text), (
        "must hand a rich.text.Text object so RichLog skips its markup "
        "re-parse and the bracketed token can't take down the stream"
    )
    assert rendered.plain == "prompt: [skill] continue"


def test_write_activity_safe_converts_ansi_color_codes_to_styles(monkeypatch) -> None:
    """``_write_activity_safe`` must translate ANSI SGR sequences from
    subprocess stdout into actual Rich styles, NOT leak the raw escape
    bytes through to the renderer as visible literals like ``[1;33m``.

    Repro of the bug the operator screenshotted: ``ux.warn`` ->
    ``click.style`` writes ``\\x1b[1;33m\u25b3 warning:\\x1b[0m \\x1b[33mfoo\\x1b[0m``
    to stdout. The pre-fix safe writer fed those bytes verbatim to
    the Activity RichLog, which rendered them as the literal text
    the operator saw on screen. The fix routes through
    ``Text.from_ansi`` so the SGR codes become actual styles.
    """

    from rich.text import Text

    captured: list = []

    class _FakeRichLog:
        def write(self, renderable) -> None:  # noqa: ANN001
            captured.append(renderable)

    fake = _FakeRichLog()
    app = DefenseClawTUI.__new__(DefenseClawTUI)
    app.activity_lines = []  # type: ignore[attr-defined]

    def _query_one(_selector, _expected_type):  # noqa: ANN001
        return fake

    monkeypatch.setattr(app, "query_one", _query_one, raising=False)
    # Exact byte sequence ``click.style("warning:", fg="yellow", bold=True)``
    # produces — bold + yellow on, then reset.
    app._write_activity_safe("\x1b[1;33mwarning:\x1b[0m foo")  # noqa: SLF001

    assert len(captured) == 1
    rendered = captured[0]
    assert isinstance(rendered, Text)
    # The plain text must NOT include the raw escape bytes — that's
    # the operator-visible regression we're closing.
    assert "\x1b" not in rendered.plain
    assert "[1;33m" not in rendered.plain
    assert "[0m" not in rendered.plain
    # The visible content is the bare strings (escape bytes consumed).
    assert rendered.plain == "warning: foo"
    # And the styling must have been applied — there should be at
    # least one span (for the bold-yellow ``warning:`` segment).
    assert len(rendered.spans) >= 1, "ANSI codes should produce styled spans"


def test_findings_metric_detail_renders_bracketed_target_literally() -> None:
    """Build the metric detail string with a hostile target token and
    confirm Rich renders the brackets as literal characters. If the
    escape regresses, ``[skill]`` is consumed as a style tag and the
    detail line silently loses the target name.
    """

    app = DefenseClawTUI.__new__(DefenseClawTUI)
    # ``_top_finding_target`` returns ``(target, severity_letter)``;
    # the ``[skill]`` shape is the canonical Rich-tag risk pattern.
    app._top_finding_target = lambda: ("target [skill]:malware", "H")  # type: ignore[method-assign]  # noqa: SLF001
    detail = DefenseClawTUI._findings_metric_detail(  # noqa: SLF001
        app, critical=1, high=2, medium=0, low=0
    )
    rendered_plain = Text.from_markup(detail).plain
    # The bracketed target survives in the rendered detail string.
    assert "[skill]" in rendered_plain


def test_ai_metric_detail_renders_bracketed_vendor_literally() -> None:
    """Same shape as the findings test: feed a vendor name with a
    bracketed token through the AI metric detail formatter and verify
    the brackets render literally.
    """

    ai_box = SimpleNamespace(rows=[SimpleNamespace(vendor="acme[v2]")])
    app = DefenseClawTUI.__new__(DefenseClawTUI)
    detail = DefenseClawTUI._ai_agents_metric_detail(app, ai_box)  # noqa: SLF001
    rendered_plain = Text.from_markup(detail).plain
    assert "acme[v2]" in rendered_plain


def test_hint_bar_disables_markup_parsing() -> None:
    """HintBar passes user filter strings (e.g. ``target:[skill]``)
    straight into the Static label. The Static must have ``markup=False``
    so a bracketed filter can't crash the hint bar's update path.
    """

    from defenseclaw.tui.widgets.hint_bar import HintBar

    bar = HintBar()
    # Textual stores the Static's markup flag at ``_render_markup``.
    # We assert the canonical attribute first; if a future Textual
    # release renames it, fall back to a render-shape probe so the
    # test still distinguishes "literal text" from "parsed markup".
    flag = getattr(bar, "_render_markup", None)
    if flag is None:
        # Try the alternative attribute names some Textual versions use.
        for name in ("use_markup", "_markup", "markup"):
            value = getattr(bar, name, None)
            if value is not None:
                flag = value
                break
    assert flag is False, "HintBar must opt out of Rich markup parsing"


def test_judge_history_format_pair_renders_bracketed_value_literally() -> None:
    """Judge bodies are raw JSON snippets; the modal must escape
    ``value`` so a bracketed token in the body never crashes the
    markup-parsed Static. Behavioral check: feed the format helper a
    hostile value and confirm Rich renders the brackets as literal
    characters in the resulting markup string.
    """

    from defenseclaw.tui.screens.judge_history import _format_pair

    rendered = _format_pair("Raw", "prompt: [skill] Tell me [16]")
    # Render the markup string the same way the modal's Static would.
    plain = Text.from_markup(rendered).plain
    # ``rich.markup.escape`` is conservative: it escapes ``[skill]``
    # (lowercase tag-shape) and leaves numeric ``[16]`` alone because
    # Rich treats numeric tokens as literal text already. Both must
    # survive in the rendered plain text; if the escape regresses,
    # ``[skill]`` is dropped silently.
    assert "[skill]" in plain
    assert "[16]" in plain


def test_detail_modal_table_renders_bracketed_label_value_literally() -> None:
    """Build a ``DetailModalModel.table()`` from rows that include
    bracketed values (audit ``target=[skill]`` is a real shape we see
    in the wild) and verify the rendered table preserves the literal
    brackets. The previous code path forwarded the raw values into
    Rich markup and crashed when any value contained ``[lowercase]``.
    """

    from io import StringIO

    from defenseclaw.tui.screens.detail import DetailModalModel
    from rich.console import Console

    rows = (
        ("Action", "scan"),
        ("Target", "[skill] malware"),
        ("Detail", "policy=[strict] match=[allow]"),
    )
    model = DetailModalModel.from_pairs("Audit Detail", rows)
    table = model.table()
    # Render through a Rich console capturing plain text — that's
    # exactly what the modal's Static does when displayed.
    buf = StringIO()
    Console(file=buf, force_terminal=False, width=120).print(table)
    plain = buf.getvalue()
    assert "[skill]" in plain
    assert "[strict]" in plain
    assert "[allow]" in plain


def test_tui_panel_outputs_survive_hostile_markup_corpus() -> None:
    """Fuzz-style sweep: feed each hostile corpus string through
    ``_safe_body_renderable`` (the wrapper used by every panel body
    and detail update) and assert the result is a ``Text`` object —
    *never* an exception. This is the floor: as long as the wrapper
    holds, no panel can crash the TUI mid-frame, even if a future
    panel author forgets to escape user input on the way in.
    """

    safe = DefenseClawTUI._safe_body_renderable  # noqa: SLF001
    for hostile in _HOSTILE_CORPUS:
        # Compose hostile text into the kinds of strings panels build
        # at runtime so the test exercises the same surfaces an
        # operator would hit.
        for composed in (
            hostile,
            f"[bold #22D3EE]Header[/]\n{hostile}",
            f"line 1\n  {hostile}\n  follow-up",
            f"{hostile}  [#444444]│[/]  Ready",
        ):
            # No exception is the primary contract; the assertion
            # below is the strict shape contract.
            rendered = safe(composed)
            assert isinstance(rendered, Text), composed
            # Strict: every visible character that wasn't a markup
            # delimiter must survive into ``.plain``. We strip only
            # the bracket pairs Rich actually parses (lowercase tags,
            # close tags, hex/style spans) before comparing.
            for char in hostile:
                if char not in "[]/":
                    # Spot-check: any non-bracket character that was
                    # in the hostile string should also be in the
                    # rendered plain text. This catches catastrophic
                    # truncation that ``isinstance`` alone would miss.
                    if char.isalnum() or char in " :,.-_":
                        assert char in rendered.plain, f"character {char!r} dropped while rendering {composed!r}"


# ---------------------------------------------------------------------
# Phase-2 markup-safety regression suite. These complement the
# Phase-1 crash-site tests above by covering the *fallback* sites —
# strings the safety wrapper catches but Rich silently drops content
# from. They also include a static scanner that walks the TUI source
# tree and bans any new unescaped lowercase-bracket tokens, with an
# explicit allow-list for known-safe Rich style names.
# ---------------------------------------------------------------------


def test_setup_wizard_mode_hint_renders_bracketed_hint_literally() -> None:
    """The wizard-mode body builds a hint span with the same shape
    used in the live ``_setup_body_text`` fallback. Reconstruct that
    fragment with a hostile bracketed hint (``webhooks[0].url`` is
    the canonical real-world shape) and verify Rich's parser preserves
    the brackets in plain text. Without ``rich_escape(focused.hint)``
    the ``[0]`` is consumed as a style tag and the whole hint span
    silently collapses to plain text — the operator stops getting any
    actionable wizard guidance.
    """

    from defenseclaw.tui.theme import DEFAULT_TOKENS as TOKENS
    from rich.markup import escape as rich_escape

    hostile_hint = "set webhooks[0].url to your endpoint"
    # Mirror the exact fragment in app.py:_setup_body_text so a
    # refactor that drops the ``rich_escape`` call site still fails.
    fragment = "\n[" + TOKENS.text_secondary + "]" + rich_escape(hostile_hint) + "[/]"
    plain = Text.from_markup(fragment).plain
    # The full hint, brackets included, must survive Rich parsing.
    assert "webhooks[0].url" in plain


def test_setup_observability_summary_renders_canonical_destination_policy(tmp_path) -> None:
    """The Setup summary is derived from the masked canonical v8 plan."""

    from defenseclaw.tui.panels.setup import _v8_observability_fields

    fields = _v8_observability_fields(
        _v8_status(
            tmp_path,
            _v8_destination(
                name="primary",
                kind="http_jsonl",
                endpoint="https://logs.example.test/ingest",
                signals=("logs",),
            ),
        )
    )
    summary = next(field.value for field in fields if field.label == "primary")
    assert summary == (
        "http_jsonl · enabled · signals=logs · "
        "redaction=unredacted (none) · buckets=platform.health · "
        "limits=not-applicable · "
        "https://logs.example.test/ingest"
    )
    assert all("audit_sinks" not in field.key for field in fields)


def test_audit_panel_render_text_renders_e_export_close_filter_literally() -> None:
    """The audit header embeds ``[e] export  [/] filter``. Both
    bracket pairs are problematic for Rich: ``[e]`` is a lowercase
    tag-shape and ``[/]`` is an unmatched close that raises
    ``MarkupError``. Render through ``Text.from_markup`` (which
    raises on real malformed markup) and assert both literals appear
    in the plain text.
    """

    panel = AuditPanelModel()
    # Inject a synthetic event so render_text reaches the header line.
    panel.set_events(
        [
            Event(
                id="1",
                action="scan",
                target="example",
                severity="HIGH",
                details="",
            )
        ]
    )
    panel.apply_filter()
    rendered = panel.render_text(height=24)
    plain = Text.from_markup(rendered).plain
    assert "[e] export" in plain
    assert "[/] filter" in plain


def test_audit_panel_summary_text_renders_e_export_close_filter_literally() -> None:
    """Same defense as ``render_text`` but for the lighter-weight
    summary header used in toolbars and tooltips.
    """

    panel = AuditPanelModel()
    plain = Text.from_markup(panel.summary_text()).plain
    assert "[e] export" in plain
    assert "[/] filter" in plain


def test_alerts_summary_text_renders_user_filter_text_literally() -> None:
    """Set a hostile filter on the alerts panel and confirm the
    summary line keeps the bracketed text literal. Without the
    escape Rich would parse ``[skill]`` as an opening style tag and
    silently truncate the search prompt.
    """

    alerts = AlertsPanelModel()
    alerts.filter_text = "target:[skill]"
    alerts.filtering = True
    rendered = alerts.summary_text()
    plain = Text.from_markup(rendered).plain
    assert "target:[skill]" in plain


def test_alerts_finding_scanner_badge_renders_literally() -> None:
    """Build an alert event with a finding whose ``scanner`` field is
    a lowercase identifier (``trivy``, ``semgrep`` are real values),
    select that alert in the panel, and verify the detail text
    preserves the ``[scanner]`` badge literally. Rich would otherwise
    consume the badge as a style tag and the operator would lose the
    most useful piece of triage info.
    """

    from defenseclaw.tui.panels.alerts import AlertDetailInfo, AlertFinding

    event = AlertEvent(
        id="evt-1",
        severity="HIGH",
        action="alert",
        target="/tmp/vendor",
    )
    finding = AlertFinding(
        id="f-1",
        scan_id="s-1",
        severity="HIGH",
        title="Critical CVE",
        scanner="trivy",
        location="/tmp/vendor",
    )
    info = AlertDetailInfo(event=event, findings=(finding,))

    alerts = AlertsPanelModel()
    alerts.detail_open = True
    # ``get_detail_info`` is the resolution seam used by both
    # ``detail_text`` and ``detail_pairs``. Patch it so we don't need
    # a full event store wired up just to surface a finding.
    alerts.get_detail_info = lambda: info  # type: ignore[method-assign]

    text_plain = Text.from_markup(alerts.detail_text()).plain
    assert "[trivy]" in text_plain

    pairs_plain = "\n".join(Text.from_markup(value).plain for _label, value in alerts.detail_pairs())
    assert "[trivy]" in pairs_plain


# Static scanner: the regression net for this entire bug class.
# ----------------------------------------------------------------

# The empirical rule (verified by probing Rich at runtime): Rich
# treats ``[X]`` as a markup tag iff X starts with a lowercase letter,
# ``#`` (hex color), or ``@`` (variable). Everything else — uppercase,
# numeric, whitespace-led, ``/`` close-tag, ``!``, etc. — is rendered
# as literal text. So the *only* unsafe shape we have to ban is a
# bracket pair starting with a lowercase letter.
import ast as _ast_scanner
import re as _re_scanner

# Rich style names that are intentional and safe to leave unescaped.
# Anything in this set is allowed to appear as ``[name]`` in markup
# strings without a backslash escape because Rich resolves it to a
# real style.
_RICH_STYLE_ALLOWLIST = frozenset(
    {
        "bold",
        "dim",
        "italic",
        "underline",
        "blink",
        "reverse",
        "strike",
        "conceal",
        "overline",
        "frame",
        "encircle",
        "black",
        "red",
        "green",
        "yellow",
        "blue",
        "magenta",
        "cyan",
        "white",
        "bright_black",
        "bright_red",
        "bright_green",
        "bright_yellow",
        "bright_blue",
        "bright_magenta",
        "bright_cyan",
        "bright_white",
        "on red",
        "on green",
        "on blue",
        "on yellow",
        "on cyan",
        "on magenta",
        "on white",
        "on black",
        "link",
        "reset",
        "none",
    }
)

# Per-string-literal allow-list for legitimate intentional uses
# of bracket-tag-shaped tokens that we don't want the scanner to
# flag (e.g. example markup in docstrings/help text, hostile-input
# corpora used by the markup tests themselves). Each entry is a
# substring; if the literal *contains* the substring, it's exempt.
_LITERAL_ALLOWLIST: tuple[str, ...] = (
    # Test fixtures that deliberately exercise hostile inputs.
    "target:[skill]",
    "prompt[16]",
    "Selection [3]:",
    "unclosed [bracket",
    "nested [bold][skill]nope",
    # Help / cheatsheet text that documents valid Rich markup.
    "[bold #22D3EE]",
    "[#9FB2CC]",
    # Docstring example in _safe_body_renderable's prose.
    "``[e] export``",
    # CLI usage hint shown in the command palette / error messages
    # (rendered via _write_activity, which already escapes via
    # ``rich_escape(str(exc))`` in the Phase-1 fix).
    "<preset> [flags]",
    # TOML section name shown in setup info text — not Rich markup.
    "[mcp_servers]",
    "([mcp_servers])",
    # Audit-row demonstration text (already covered by _audit_body_text
    # which routes through ``_safe_body_renderable``).
    "[Enter] view output",
    # Regex character classes inside raw-string patterns that never
    # flow through Rich markup (validators.py / answers.py only feed
    # these into ``re.compile``).
    "[a-z0-9][a-z0-9-]",
    "[A-Z][A-Z0-9_-]",
    "[a-z_]+",
    # Overview notice hotkey hints — the consumer (``_overview_body_text``)
    # wraps ``notice.message`` in ``rich_escape`` so the brackets render
    # literally even though Rich would otherwise parse them as style
    # tags. Keeping the bracketed letters readable in the source notice
    # is more useful to the operator than spreading escape backslashes
    # through every notice message.
    "press [g] to set up",
    "press [d] to refresh",
    "press [d] on Overview",
)

# Variable expressions inside f-strings whose values are statically
# guaranteed to be safe (hex colors, known Rich styles). Adding to
# this list is fine; missing one only causes a false-positive flag.
_FSTRING_EXPR_ALLOWLIST_PREFIXES: tuple[str, ...] = (
    "TOKENS.",
    "DEFAULT_TOKENS.",
    "color",
    "snippet_color",
    "alert_color",
    "icon_color",
)


# Suffix-based allow-list: f-string expressions that statically
# evaluate to an uppercase string never produce a tag-shaped bracket
# pair, so we don't need to flag them. ``.upper()`` and known-
# uppercase attributes like ``check.badge`` (FAIL/PASS/STALE/WARN)
# fall in this bucket.
_FSTRING_EXPR_ALLOWLIST_SUFFIXES: tuple[str, ...] = (
    ".upper()",
    ".UPPER()",
)

# Specific f-string expression strings that are known-safe at runtime
# (e.g. integer indices that always render as ``[0]`` / ``[1]`` /
# ``[16]`` — numeric tokens that Rich treats as literal text).
_FSTRING_EXPR_ALLOWLIST_EXACT: frozenset[str] = frozenset(
    {
        "index",
        "i",
        "n",
        "check.badge",
        "notice.level.upper()",
        # Catalog action key (single character). The surrounding code
        # in catalog_state.py wraps the rendered chunks in ``[dim]…[/]``
        # before display, so the bracket-tag shape never reaches the
        # user's terminal as a literal — Rich consumes the outer tags
        # first and the inner bracket pair is harmless.
        "action.key",
    }
)


_RAW_BRACKET_RE = _re_scanner.compile(r"(?<!\\)\[(?P<tag>[a-z][^\[\]]{0,40})\]")
_FSTRING_BRACKET_RE = _re_scanner.compile(r"(?<!\\)\[\{(?P<expr>[^{}]+)\}\]")


def _is_allowlisted_literal(literal: str) -> bool:
    return any(fragment in literal for fragment in _LITERAL_ALLOWLIST)


def _flag_raw_string(literal: str) -> list[str]:
    """Return the offending bracket tokens from a literal Python str."""

    if _is_allowlisted_literal(literal):
        return []
    findings: list[str] = []
    for match in _RAW_BRACKET_RE.finditer(literal):
        tag = match.group("tag").rstrip()
        if tag in _RICH_STYLE_ALLOWLIST:
            continue
        first_token = tag.split(" ")[0]
        if first_token in _RICH_STYLE_ALLOWLIST:
            continue
        findings.append(match.group(0))
    return findings


def _flag_fstring_placeholder(joined_text: str) -> list[str]:
    """Return offending ``[{expr}]`` patterns from an f-string's joined
    representation. ``joined_text`` has ``{expr}`` placeholders for
    each interpolation, so a Rich-markup ``[{var}]`` literal will
    show up as ``[{var}]`` in the joined string. A Python subscript
    like ``counts[key]`` shows up as ``{counts[key]}`` (the entire
    expression sits inside one placeholder) and won't match the
    ``[{...}]`` regex because there's no literal ``[`` adjacent to
    the opening brace. That asymmetry is exactly what we want — the
    scanner only flags the genuine markup shape.
    """

    if _is_allowlisted_literal(joined_text):
        return []
    findings: list[str] = []
    for match in _FSTRING_BRACKET_RE.finditer(joined_text):
        expr = match.group("expr").strip()
        if expr.startswith(_FSTRING_EXPR_ALLOWLIST_PREFIXES):
            continue
        if expr.endswith(_FSTRING_EXPR_ALLOWLIST_SUFFIXES):
            continue
        if expr in _FSTRING_EXPR_ALLOWLIST_EXACT:
            continue
        findings.append(match.group(0))
    return findings


def _joined_str_text_and_exprs(node: object) -> tuple[str, list[str]]:
    """Convert an ``ast.JoinedStr`` to its joined text (with ``{}``
    placeholders for FormattedValue parts) and the list of Python
    source for each interpolation in order. Returns ``("", [])`` if
    ``node`` isn't a JoinedStr.
    """

    if not isinstance(node, _ast_scanner.JoinedStr):
        return "", []
    parts: list[str] = []
    exprs: list[str] = []
    for value in node.values:
        if isinstance(value, _ast_scanner.Constant) and isinstance(value.value, str):
            parts.append(value.value)
        elif isinstance(value, _ast_scanner.FormattedValue):
            exprs.append(_ast_scanner.unparse(value.value))
            parts.append("{" + exprs[-1] + "}")
    return "".join(parts), exprs


def _scan_tui_source_for_lowercase_brackets() -> list[tuple[str, int, str]]:
    """Return ``(relpath, lineno, snippet)`` for every Python string
    literal or f-string in the TUI source tree that contains an
    unescaped ``[lowercase…]`` token Rich would parse as a markup tag.

    The walk is AST-based: only ``Constant(str)`` and ``JoinedStr``
    nodes are inspected. Type subscripts (``list[str]``), dict/list
    indexing, and other non-string syntax are ignored automatically.
    """

    from pathlib import Path as _Path

    repo = _Path(__file__).resolve().parents[3]
    targets = [
        repo / "cli/defenseclaw/tui",
        repo / "cli/defenseclaw/commands/cmd_tui.py",
    ]

    files: list[_Path] = []
    for target in targets:
        if target.is_dir():
            files.extend(p for p in target.rglob("*.py") if "__pycache__" not in p.parts)
        elif target.is_file():
            files.append(target)

    findings: list[tuple[str, int, str]] = []
    for path in files:
        rel = str(path.relative_to(repo))
        try:
            tree = _ast_scanner.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        for node in _ast_scanner.walk(tree):
            if isinstance(node, _ast_scanner.Constant) and isinstance(node.value, str):
                # Skip docstrings — they're prose, not Rich-rendered.
                # We can identify a docstring as the first statement of
                # a module / class / function body, but the simpler
                # heuristic is to skip any string > 200 chars long
                # (docstrings) since real markup strings are much
                # shorter than that.
                if len(node.value) > 200:
                    continue
                bad = _flag_raw_string(node.value)
                for token in bad:
                    findings.append((rel, node.lineno, token))
            elif isinstance(node, _ast_scanner.JoinedStr):
                # Two passes for f-strings:
                # 1. Each *literal* part is plain Python str text. Run
                #    the raw regex on it the same way we'd run it on a
                #    Constant(str) — this catches ``f"[bold]{x}[/]"``-
                #    style markup written into the static parts.
                # 2. Build the joined ``"x [{expr}] y"`` shape with
                #    ``{expr}`` placeholders for each interpolation,
                #    then run the placeholder-anchored regex. That
                #    only matches when the brackets are *literal*
                #    (i.e. adjacent to the placeholder boundary), so
                #    Python subscripts inside the placeholder don't
                #    trigger false positives.
                for value in node.values:
                    if isinstance(value, _ast_scanner.Constant) and isinstance(value.value, str):
                        for token in _flag_raw_string(value.value):
                            findings.append((rel, value.lineno, token))
                joined, _exprs = _joined_str_text_and_exprs(node)
                if joined:
                    for token in _flag_fstring_placeholder(joined):
                        findings.append((rel, node.lineno, token))
    return findings


def test_no_unescaped_lowercase_bracket_tokens_in_tui_sources() -> None:
    """Permanent guardrail: walk every Python file under the TUI
    package and refuse to merge any change that introduces a new
    unescaped ``[lowercase…]`` literal or ``f"[{lowercase_var}]"``
    pattern. Rich parses such tokens as opening style tags and either
    silently drops the bracketed content or — worse — fails the
    safety wrapper's per-span ``Style.parse`` validation, forcing
    the whole panel body to plain-text fallback.

    Failures here mean the operator will see panels with content
    silently dropped (``"  Scan all"`` instead of ``"[s] Scan all"``)
    or whole-panel color regressions when the wrapper falls back.
    Either escape the bracket (``\\[s]``), pick an uppercase label,
    or — if the token is a deliberate Rich style — add it to
    ``_RICH_STYLE_ALLOWLIST`` above.
    """

    findings = _scan_tui_source_for_lowercase_brackets()
    if findings:
        report = "\n".join(f"  {rel}:{lineno}  {snippet}" for rel, lineno, snippet in findings[:50])
        # Truncated message keeps the failure log scannable.
        assert not findings, (
            f"Found {len(findings)} unescaped lowercase-bracket token(s) in "
            f"the TUI source. Each one is parsed by Rich as a style tag and "
            f"silently drops the bracketed text. Either backslash-escape the "
            f"opening bracket (``\\\\[s]``), pick an uppercase label, or — if it "
            f"is an intentional Rich style — register it in "
            f"``_RICH_STYLE_ALLOWLIST``.\n\nOffending lines:\n{report}"
        )


def test_activity_history_render_keeps_t_hotkey_literal() -> None:
    """Render the activity panel's history view and verify the ``[t]``
    hotkey survives Rich parsing. Lowercase tag-shape would otherwise
    drop the bracketed letter from the visible output.
    """

    from defenseclaw.tui.panels.activity import ActivityEntry, ActivityPanelModel

    activity = ActivityPanelModel()
    activity.entries = [ActivityEntry(command="defenseclaw doctor", done=True, exit_code=0)]
    activity.term_mode = False  # exercise the history-tab branch
    rendered = activity.render_text(height=24)
    plain = Text.from_markup(rendered).plain
    assert "[t] terminal mode" in plain
    assert "[Enter] view output" in plain  # uppercase-led, also literal


def test_event_histogram_buckets_recent_events_by_time() -> None:
    now = datetime(2026, 5, 29, 12, 0, 0, tzinfo=timezone.utc)
    window = timedelta(minutes=10)
    buckets = 10  # one bucket per minute
    timestamps = [
        now - timedelta(seconds=30),  # newest bucket (index 9)
        now - timedelta(seconds=90),  # bucket 8
        now - timedelta(seconds=95),  # bucket 8
        now - timedelta(minutes=20),  # older than the window -> dropped
        now + timedelta(minutes=1),  # in the future -> dropped
    ]
    hist = _event_histogram(timestamps, now=now, buckets=buckets, window=window)
    assert len(hist) == buckets
    assert hist[9] == 1.0
    assert hist[8] == 2.0
    assert sum(hist) == 3.0


def test_event_histogram_handles_empty_and_naive_timestamps() -> None:
    now = datetime(2026, 5, 29, 12, 0, 0, tzinfo=timezone.utc)
    assert _event_histogram([], now=now, buckets=6, window=timedelta(minutes=6)) == (0.0,) * 6
    # Naive datetimes are treated as UTC so they still bucket.
    naive = now.replace(tzinfo=None) - timedelta(seconds=10)
    hist = _event_histogram([naive], now=now, buckets=6, window=timedelta(minutes=6))
    assert sum(hist) == 1.0


def test_policy_posture_multi_connector() -> None:
    """Multi-connector posture reflects the roster, not one global pack:
    divergent packs/modes point at the roster; a uniform install names the
    shared mode + pack. Single-connector keeps the original wording."""

    # Divergent rule packs -> defer to the roster.
    divergent = OverviewConfig(
        guardrail_mode="action",
        connector_modes=(("codex", "action"), ("claudecode", "action")),
        connector_packs=(("codex", "strict"), ("claudecode", "permissive")),
    )
    assert _policy_posture(divergent) == "per-connector (see roster)"

    # Divergent modes (same/blank packs) also defer.
    divergent_modes = OverviewConfig(
        guardrail_mode="action",
        connector_modes=(("codex", "action"), ("cursor", "observe")),
    )
    assert _policy_posture(divergent_modes) == "per-connector (see roster)"

    # Uniform multi-connector: one mode + one pack across the roster.
    uniform = OverviewConfig(
        guardrail_mode="action",
        connector_modes=(("codex", "action"), ("claudecode", "action")),
        connector_packs=(("codex", "strict"), ("claudecode", "strict")),
    )
    assert _policy_posture(uniform) == "all connectors: action (strict)"

    # Single-connector wording is unchanged.
    single = OverviewConfig(guardrail_mode="action", guardrail_strategy="default")
    assert _policy_posture(single) == "action: block CRIT, alert MED+ (default)"


def test_enforcement_label_multi_connector() -> None:
    """Multi-connector enforcement reports the connector count instead of
    naming a single primary; single-connector keeps the named-connector form."""

    multi = OverviewConfig(
        guardrail_connector="codex",
        guardrail_mode="action",
        connector_modes=(("codex", "action"), ("claudecode", "action")),
    )
    assert _enforcement_label(multi) == "2 connectors (per-connector modes)"

    single = OverviewConfig(guardrail_connector="codex", guardrail_mode="action")
    assert _enforcement_label(single) == "codex hook enforcement (action)"

    omnigent = OverviewConfig(guardrail_connector="omnigent", guardrail_mode="action")
    assert _enforcement_label(omnigent) == "omnigent policy enforcement (action)"


def test_overview_reuses_hook_event_snapshot_within_one_render() -> None:
    """Overview metrics/rows should not re-query the same hook window per connector."""

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(
            ("antigravity", "action"),
            ("claudecode", "observe"),
            ("codex", "observe"),
            ("hermes", "action"),
            ("opencode", "action"),
        ),
    )
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(HealthSnapshot(gateway=SubsystemHealth(state="running")))
    events = [
        Event(
            id=f"codex-{i}",
            action="connector-hook",
            target="preToolUse",
            severity="INFO",
            details="connector=codex action=allow",
        )
        for i in range(10)
    ]

    class CountingHookStore:
        calls = 0
        scan_count_calls = 0

        def list_connector_hook_event_summaries(self, limit: int = 500) -> list[Event]:
            self.calls += 1
            return list(events[:limit])

        def count_scan_results_since(self, _since: datetime | None) -> int:
            self.scan_count_calls += 1
            return 0

    store = CountingHookStore()
    audit = AuditPanelModel(store)
    app = DefenseClawTUI(overview_model=overview, audit_model=audit)

    with app._connector_hook_event_render_cache():
        app._overview_renderable()
        metrics = {metric.key: metric for metric in app._overview_metric_data()}
        rows = {row.connector: row for row in app._overview_connector_rows()}

    assert store.calls == 1
    assert store.scan_count_calls == 1
    assert metrics["hook_calls"].value == 10
    assert rows["codex"].calls == 10


def test_cursor_disclosure_renders_for_enabled_and_disabled_rows_only() -> None:
    from rich.console import Console

    disclosure = "priority-conflict-detection=unavailable (none inferred)"
    for disabled in (False, True):
        cfg = OverviewConfig(
            claw_mode="codex",
            guardrail_connector="codex",
            connector_modes=(("codex", "action"), ("cursor", "observe")),
            connector_disabled=("cursor",) if disabled else (),
        )
        overview = OverviewPanelModel(cfg, version="test")
        overview.set_health(
            HealthSnapshot(
                gateway=SubsystemHealth(state="running"),
                connectors=(
                    (ConnectorHealth(name="codex", state="running"),)
                    if disabled
                    else (
                        ConnectorHealth(name="codex", state="running"),
                        ConnectorHealth(name="cursor", state="running"),
                    )
                ),
            )
        )
        app = DefenseClawTUI(overview_model=overview, audit_model=AuditPanelModel())
        rows = {row.connector: row for row in app._overview_connector_rows()}
        panel = app._overview_connectors_panel(list(rows.values()))
        console = Console(file=io.StringIO(), width=170, record=True)
        console.print(panel)
        rich_text = console.export_text()
        fallback_text = app._overview_connectors_text(list(rows.values()))

        assert rows["cursor"].status == ("disabled" if disabled else "running")
        assert rich_text.count(disclosure) == 1
        assert fallback_text.count(disclosure) == 1
        assert f"Cursor (cursor): {disclosure}" in rich_text
        assert f"Cursor (cursor): {disclosure}" in fallback_text
        assert f"Codex (codex): {disclosure}" not in rich_text
        assert f"Codex (codex): {disclosure}" not in fallback_text


def test_overview_connector_rows_degrade_only_unverified_opencode_runtime() -> None:
    now = datetime.now(timezone.utc)
    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="opencode",
        guardrail_connector="opencode",
        connector_modes=(("opencode", "action"), ("cursor", "observe")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(
        HealthSnapshot(
            started_at=(now - timedelta(hours=1)).isoformat(),
            gateway=SubsystemHealth(state="running"),
            api=SubsystemHealth(state="running"),
            connectors=(
                ConnectorHealth(name="opencode", state="running"),
                ConnectorHealth(name="cursor", state="running"),
            ),
        )
    )
    app = DefenseClawTUI(overview_model=overview, audit_model=AuditPanelModel())

    rows = {row.connector: row for row in app._overview_connector_rows()}

    assert rows["opencode"].status == "degraded"
    assert rows["cursor"].status == "running"


def test_connectors_health_array_parsed() -> None:
    """The /health connectors[] array maps into HealthSnapshot.connectors."""

    from defenseclaw.tui.app import _health_snapshot_from_mapping

    snap = _health_snapshot_from_mapping(
        {
            "gateway": {"state": "running"},
            "connector": {
                "name": "codex",
                "state": "running",
                "last_activity_at": "2026-07-01T14:35:00Z",
            },
            "connectors": [
                {
                    "name": "codex",
                    "state": "running",
                    "source": "manual",
                    "requests": 5,
                    "last_activity_at": "2026-07-01T14:35:00Z",
                    "load_heartbeat_at": "2026-07-01T14:35:01Z",
                },
                {
                    "name": "cursor",
                    "state": "degraded",
                    "source": 7,
                    "lastActivityAt": "2026-07-01T14:36:00Z",
                },
                {"state": "running"},  # nameless entry is skipped
            ],
        }
    )
    names = [c.name for c in snap.connectors]
    assert names == ["codex", "cursor"]
    assert snap.connectors[0].requests == 5
    assert snap.connector is not None
    assert snap.connector.last_activity_at == "2026-07-01T14:35:00Z"
    assert snap.connectors[0].last_activity_at == "2026-07-01T14:35:00Z"
    assert snap.connectors[0].source == "manual"
    assert snap.connectors[0].load_heartbeat_at == "2026-07-01T14:35:01Z"
    assert snap.connectors[1].last_activity_at == "2026-07-01T14:36:00Z"
    assert snap.connectors[1].source == ""


# --- A2: _overview_config roster build is defensive -------------------------


class _RosterGuardrail:
    """Guardrail stub with per-connector ``effective_*`` for roster tests."""

    enabled = True
    connector = ""
    mode = "observe"
    hilt = SimpleNamespace(enabled=False, min_severity="")

    def __init__(self, modes=None, disabled=(), raise_on=()):
        self._modes = modes or {}
        self._disabled = set(disabled)
        self._raise_on = set(raise_on)

    def effective_enabled(self, connector):
        return connector not in self._disabled

    def effective_mode(self, connector):
        if connector in self._raise_on:
            raise RuntimeError(f"boom:{connector}")
        return self._modes.get(connector, "observe")

    def effective_rule_pack_dir(self, connector):
        if connector in self._raise_on:
            raise RuntimeError(f"boom:{connector}")
        return ""


def _roster_config(active_connectors, guardrail) -> SimpleNamespace:
    """Minimal config stub exercising :func:`_overview_config`."""

    return SimpleNamespace(
        data_dir="/tmp/dc",
        environment="dev",
        policy_dir="",
        claw=SimpleNamespace(mode="codex"),
        guardrail=guardrail,
        llm=SimpleNamespace(provider="", model=""),
        inspect_llm=SimpleNamespace(provider="", model=""),
        cisco_ai_defense=SimpleNamespace(endpoint=""),
        privacy=SimpleNamespace(disable_redaction=False),
        active_connectors=active_connectors,
    )


def test_overview_config_degrades_when_active_connectors_raises() -> None:
    """A2: a throwing connector enumeration degrades to a single-connector
    view (empty roster) instead of crashing or blanking the whole overview."""

    def boom():
        raise RuntimeError("malformed connector key")

    cfg = _roster_config(boom, _RosterGuardrail())
    overview = _overview_config(cfg)
    assert overview is not None
    assert overview.connector_modes == ()
    # The rest of the config still resolves — only the roster is degraded.
    assert overview.claw_mode == "codex"


def test_overview_config_keeps_other_connectors_when_one_lookup_throws() -> None:
    """A2: one connector whose guardrail lookups raise must not zero the
    roster; the partial roster (all connectors) survives, the bad one blank."""

    guardrail = _RosterGuardrail(modes={"codex": "action", "cursor": "observe"}, raise_on={"cursor"})
    cfg = _roster_config(lambda: ["codex", "cursor"], guardrail)
    overview = _overview_config(cfg)
    modes = dict(overview.connector_modes)
    assert list(modes) == ["codex", "cursor"]
    assert modes["codex"] == "action"
    assert modes["cursor"] == ""  # fell back, not dropped


def test_overview_config_skips_malformed_connector_key() -> None:
    """A2: a single malformed (non-string) key is skipped while the valid
    connectors still populate the roster — it is no longer swallowed together
    with the entire roster by one broad ``except``."""

    guardrail = _RosterGuardrail(modes={"codex": "action", "cursor": "observe"})
    cfg = _roster_config(lambda: ["codex", 123, "cursor"], guardrail)
    overview = _overview_config(cfg)
    names = [connector for connector, _mode in overview.connector_modes]
    assert names == ["codex", "cursor"]


def test_overview_config_marks_disabled_connector_in_roster() -> None:
    """A2 (regression baseline): a per-connector kill switch still flags the
    connector as disabled while keeping it in the filterable roster."""

    guardrail = _RosterGuardrail(modes={"codex": "action", "cursor": "observe"}, disabled={"cursor"})
    cfg = _roster_config(lambda: ["codex", "cursor"], guardrail)
    overview = _overview_config(cfg)
    names = [connector for connector, _mode in overview.connector_modes]
    assert names == ["codex", "cursor"]
    assert overview.connector_disabled == ("cursor",)


def test_overview_config_no_connectors_yields_empty_claw_mode() -> None:
    """A1 (Root R1, display-only): a genuinely-zero-connector config resolves
    the display connector to "" — never a phantom "openclaw". The adapter passes
    the real (empty) claw.mode so active_connector_name() falls through to ""."""

    cfg = _roster_config(lambda: [], _RosterGuardrail())
    cfg.claw = SimpleNamespace(mode="")
    overview = _overview_config(cfg)
    assert overview.claw_mode == ""
    assert OverviewPanelModel(overview, version="test").active_connector_name() == ""


def test_overview_config_sets_roster_error_when_enumeration_raises() -> None:
    """A2: a throwing active_connectors() stashes a visible diagnostic in
    roster_error (surfaced by the Overview notices) instead of degrading
    silently."""

    def boom():
        raise RuntimeError("malformed connector key")

    cfg = _roster_config(boom, _RosterGuardrail())
    overview = _overview_config(cfg)
    assert "malformed connector key" in overview.roster_error
    # The model turns it into a visible error notice.
    notices = OverviewPanelModel(overview, version="test").build_notices()
    assert any(n.level == "error" for n in notices)


def test_flatten_scanner_overrides_skips_malformed() -> None:
    """N3: a malformed scanner_overrides branch is skipped, not fatal."""

    from defenseclaw.tui.app import _flatten_scanner_overrides

    flat = _flatten_scanner_overrides(
        {
            "mcp": {"LOW": {"runtime": "block", "file": "none"}},
            "bad": "not-a-dict",
            "plugin": {"HIGH": "also-bad"},
        }
    )
    assert ("mcp", "LOW", "runtime", "block") in flat
    assert all(entry[0] != "plugin" for entry in flat)
    assert _flatten_scanner_overrides("nope") == ()


def test_overview_config_reads_scanner_overrides_from_active_policy(tmp_path) -> None:
    """N3: the adapter flattens the active policy's data.json scanner_overrides
    into OverviewConfig so the Overview/status can surface them."""

    rego = tmp_path / "rego"
    rego.mkdir()
    (rego / "data.json").write_text(
        json.dumps({"scanner_overrides": {"secrets": {"HIGH": {"file": "block", "install": "warn"}}}})
    )
    cfg = _roster_config(lambda: ["codex"], _RosterGuardrail())
    cfg.policy_dir = str(tmp_path)
    overview = _overview_config(cfg)
    assert ("secrets", "HIGH", "file", "block") in overview.scanner_overrides
    assert ("secrets", "HIGH", "install", "warn") in overview.scanner_overrides
    assert "secrets" in OverviewPanelModel(overview, version="test").scanner_overrides_summary()


def test_overview_body_renders_scanner_override_summary() -> None:
    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        scanner_overrides=(("secrets", "HIGH", "file", "block"),),
    )
    overview = OverviewPanelModel(cfg, version="test")
    app = DefenseClawTUI(overview_model=overview)

    body = app._overview_body_text(overview.service_cards())  # noqa: SLF001 - render regression surface.

    assert "overrides" in body
    assert "secrets: HIGH file=block" in body


def test_destructive_intent_modal_is_danger_gated() -> None:
    """N1: a destructive catalog intent builds a red-bordered consequence modal
    whose only action is danger-gated (requires the explicit second confirm)."""

    from defenseclaw.tui.app import TOKENS
    from defenseclaw.tui.services.catalog_state import CatalogCommandIntent

    app = DefenseClawTUI()
    intent = CatalogCommandIntent(
        label="remove plugin foo",
        args=("plugin", "remove", "foo"),
        origin="plugins",
        risk="destructive",
    )
    model = app._destructive_intent_modal(intent)
    assert len(model.actions) == 1
    assert model.default_action().danger is True
    assert model.border_color == TOKENS.accent_red
    assert "plugin remove foo" in model.details[0]
