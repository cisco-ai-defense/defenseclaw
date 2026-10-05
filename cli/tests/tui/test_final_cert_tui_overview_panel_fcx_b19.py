# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI Overview panel fixes (GAP-2518, 2519, 2521, 2523, 2526)."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import defenseclaw.tui.app as app_module
from defenseclaw.tui.panels.overview import (
    DoctorCache,
    DoctorCheck,
    HealthSnapshot,
    OverviewConfig,
    OverviewPanelModel,
    SubsystemHealth,
)
from defenseclaw.tui.services.overview_state import ObservabilityDestinationRow, OverviewNotice
from rich.text import Text

sys.path.insert(0, str(Path(__file__).parent))
from fixtures import screen_text, snapshot_app  # noqa: E402

NOW = datetime(2026, 10, 3, 16, 0, tzinfo=timezone.utc)


def _model() -> OverviewPanelModel:
    model = OverviewPanelModel(OverviewConfig(data_dir="/tmp/dc", claw_mode="codex"), version="test")
    model.set_health(HealthSnapshot(api=SubsystemHealth(state="running")))
    return model


def test_doctor_box_is_not_healthy_or_failed_when_it_no_longer_describes_the_gateway() -> None:
    # GAP-2518: "HEALTHY / All checks passing" with the gateway stopped, then
    # "Outcome FAILED" and a red banner beside "1 stale failure(s)".
    model = _model()
    model.set_doctor_cache(
        DoctorCache(captured_at=NOW - timedelta(minutes=2), passed=130, skipped=29, schema_version=2, outcome="healthy")
    )
    assert model.doctor_box(now=NOW).all_green
    model.set_gateway_probe("stopped")
    box = model.doctor_box(now=NOW)
    assert (box.run_outcome, box.stale, box.all_green) == ("stale", True, False)
    assert "gateway stopped" in box.note

    model.set_doctor_cache(
        DoctorCache(
            captured_at=NOW - timedelta(minutes=2),
            passed=118,
            failed=1,
            skipped=31,
            checks=(DoctorCheck("fail", "Sidecar API", "the gateway is not running"),),
            schema_version=2,
            outcome="failed",
            exit_code=1,
        )
    )
    # Still down: the kept /health payload must not clear the failure.
    assert any("Doctor found 1 failure(s)" in n.message for n in model.build_notices(now=NOW))
    model.set_gateway_probe("running")
    messages = [notice.message for notice in model.build_notices(now=NOW)]
    assert any("1 stale failure(s)" in message for message in messages)
    assert not any("failed outcome" in message for message in messages)
    assert model.doctor_box(now=NOW).run_outcome == "stale"


def test_runtime_and_enforcement_keep_numbers_with_their_units() -> None:
    # GAP-2521: "0 blocked   0" / "allowed" and "201" / "processes" at 80 columns.
    units = [Text("● DEGRADED"), Text("0 findings"), Text("201 processes"), Text("159 connections")]
    assert app_module._fit_units(units, 31).plain.split("\n") == [  # noqa: SLF001
        "● DEGRADED   0 findings",
        "201 processes   159 connections",
    ]
    assert app_module._fit_units(units, 80).plain.count("\n") == 0  # noqa: SLF001


def test_destination_health_has_no_lifecycle_codes() -> None:
    # GAP-2523: "healthy (activated)" and "healthy (delivery_recovered)".
    def row(state: str, reason: str) -> ObservabilityDestinationRow:
        return ObservabilityDestinationRow("g", "v8", "process", "otlp", state, "logs", "-", health_reason=reason)

    assert row("healthy", "activated").health_label == "healthy"
    assert row("healthy", "delivery_recovered").health_label == "healthy"
    assert row("degraded", "queue_full").health_label == "degraded (queue full)"


def test_watchdog_row_counts_one_dir_in_the_singular() -> None:
    # GAP-2526: "2 skill dirs, 1 plugin dirs".
    model = _model()
    model.set_health(
        HealthSnapshot(watcher=SubsystemHealth(state="running", details={"skill_dirs": 2, "plugin_dirs": 1}))
    )
    assert model.watchdog_detail() == "2 skill dirs, 1 plugin dir"


async def test_notice_is_one_line_after_a_height_only_resize_to_80x24(tmp_path) -> None:
    # GAP-2519: 80x45 -> 80x24 kept the wrapped notice; its end hid under the bar.
    app = snapshot_app(tmp_path)
    message = "Doctor cache shows 1 stale failure(s) that /health disagrees with - press [d] to refresh"
    app.overview_model.build_notices = lambda now=None: (OverviewNotice("info", message),)
    async with app.run_test(size=(80, 45)) as pilot:
        app.action_switch_panel("overview")
        await pilot.pause()
        await pilot.resize_terminal(80, 24)
        await pilot.pause()
        text = screen_text(app)
    assert "disagrees with …" in text
    assert "press [d] to refresh" not in text
