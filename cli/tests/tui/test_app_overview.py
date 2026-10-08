# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Overview app-shell unit tests: banner, live signatures, doctor cache, connector roster and posture."""

from __future__ import annotations

import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw.models import Event
from defenseclaw.observability.v8_status import (
    V8BucketStatus,
    V8DestinationStatus,
    V8OperatorStatus,
)
from defenseclaw.tui.app import (
    _DEFENSECLAW_LOGO,
    DefenseClawTUI,
    _activity_refresh_bucket,
    _agents_summary,
    _enforcement_label,
    _event_histogram,
    _fetch_v8_operator_status,
    _overview_config,
    _policy_posture,
)
from defenseclaw.tui.panels.audit import AuditPanelModel
from defenseclaw.tui.panels.overview import (
    ConnectorHealth,
    DoctorCache,
    DoctorRepairSummary,
    HealthSnapshot,
    OverviewConfig,
    OverviewPanelModel,
    SubsystemHealth,
)
from defenseclaw.tui.widgets.native_metrics import MetricDatum


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
    assert error.startswith("invalid configuration at $")
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

    # Single-connector: the fallback names the configured rule pack.
    single = OverviewConfig(guardrail_mode="action")
    assert _policy_posture(single) == "action: block CRIT, alert MED+ (default)"
    strict = OverviewConfig(guardrail_mode="action", guardrail_rule_pack_dir="/etc/policies/guardrail/strict")
    assert _policy_posture(strict) == "action: block CRIT, alert MED+ (strict)"


def test_enforcement_label_multi_connector() -> None:
    """Multi-connector enforcement reports the connector count instead of
    naming a single primary; single-connector keeps the named-connector form."""

    multi = OverviewConfig(
        guardrail_connector="codex",
        guardrail_mode="action",
        guardrail_enabled=True,
        connector_modes=(("codex", "action"), ("claudecode", "action")),
    )
    assert _enforcement_label(multi) == "2 connectors (per-connector modes)"
    # GAP-1561: after "defenseclaw uninstall" turned the guardrail off.
    off = OverviewConfig(connector_modes=multi.connector_modes)
    assert _enforcement_label(off) == "off - guardrail disabled, nothing is guarded"
    assert _agents_summary(off, 2) == "2 configured, guardrail off (nothing is guarded)"
    assert _agents_summary(multi, 2) == "2 active"

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

    disclosure = "DefenseClaw can't tell whether an Enterprise, Team or Projec"
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
        assert f"Cursor: {disclosure}" in rich_text
        assert f"Cursor: {disclosure}" in fallback_text
        assert "priority-conflict-detection" not in rich_text + fallback_text


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


def test_overview_config_reads_per_type_admission_actions() -> None:
    """N3: the adapter flattens the per-type admission actions into
    OverviewConfig so the Overview/status can surface them."""

    from defenseclaw.config import AdmissionConfig

    cfg = _roster_config(lambda: ["codex"], _RosterGuardrail())
    cfg.admission = AdmissionConfig()
    # MEDIUM quarantine is the built-in mcp action, so it is not an override.
    cfg.admission.mcp.actions = {"low": "block", "medium": "quarantine", "high": "not-an-action"}
    overview = _overview_config(cfg)
    assert ("mcp", "LOW", "install", "block") in overview.scanner_overrides
    assert all(entry[1] not in ("HIGH", "MEDIUM") for entry in overview.scanner_overrides)
    assert "mcp" in OverviewPanelModel(overview, version="test").scanner_overrides_summary()


def test_overview_and_status_include_inherited_admission_actions() -> None:
    from defenseclaw.commands.cmd_status import _scanner_overrides_summary
    from defenseclaw.config import AdmissionConfig

    cfg = _roster_config(lambda: ["codex"], _RosterGuardrail())
    cfg.admission = AdmissionConfig()
    cfg.admission.defaults.actions = {"high": "allow"}
    overview = _overview_config(cfg)

    for asset_type in ("mcp", "plugin"):
        assert (asset_type, "HIGH", "install", "none") in overview.scanner_overrides
    summary = OverviewPanelModel(overview, version="test").scanner_overrides_summary()
    assert "mcp: HIGH" in summary
    assert "plugin: HIGH" in summary
    assert "verdict=allow" in summary
    assert _scanner_overrides_summary(cfg) == summary

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


def test_overview_findings_and_connector_alerts_match_the_alerts_view() -> None:
    """GAP-2088/2089: one count per alert, the same numbers as the Alerts panel."""

    from defenseclaw.tui.panels.alerts import AlertEvent, AlertsPanelModel

    now = datetime.now(timezone.utc)
    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="claudecode",
        guardrail_connector="claudecode",
        connector_modes=(("claudecode", "action"), ("codex", "action")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(HealthSnapshot(gateway=SubsystemHealth(state="running")))
    # Each claudecode block is a hook row plus the finding row that explains it.
    hooks = [
        Event(
            id=f"hook-{i}",
            timestamp=now,
            action="connector-hook",
            target="PreToolUse",
            severity="INFO",
            details="connector=claudecode action=block severity=CRITICAL",
        )
        for i in range(2)
    ]

    class HookStore:
        def list_connector_hook_event_summaries(self, limit: int = 500) -> list[Event]:
            return list(hooks[:limit])

        def count_scan_results_since(self, _since: datetime | None) -> int:
            return 0

    store = HookStore()
    alerts = AlertsPanelModel(store=store)
    alerts.set_events(
        [
            *(
                AlertEvent(
                    id=f"finding-{i}",
                    severity="CRITICAL",
                    action="scan-finding",
                    target="PreToolUse",
                    timestamp=now,
                    connector="claudecode",
                )
                for i in range(2)
            ),
            AlertEvent(
                id="degraded-1",
                severity="HIGH",
                action="guardrail-degraded",
                target="codex",
                timestamp=now,
                connector="codex",
            ),
            # A connector-less alert still counts under scope All, as in the
            # Alerts panel (GAP-2088 r4x reopen).
            AlertEvent(
                id="export-1",
                severity="HIGH",
                action="otel-export-failed",
                target="galileo/traces",
                timestamp=now,
            ),
        ]
    )
    app = DefenseClawTUI(overview_model=overview, audit_model=AuditPanelModel(store), alerts_model=alerts)

    with app._connector_hook_event_render_cache():
        metrics = {metric.key: metric.value for metric in app._overview_metric_data()}
        rows = {row.connector: row for row in app._overview_connector_rows()}

    assert metrics["findings"] == 4
    assert rows["claudecode"].blocks == 2
    assert rows["claudecode"].alerts == 2
    assert rows["codex"].alerts == 1
