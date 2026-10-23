# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Overview notices keep their remedy on the first line at 80 columns (GAP-0566)."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from defenseclaw.tui.panels.overview import (
    DoctorCache,
    DoctorCheck,
    HealthSnapshot,
    OverviewConfig,
    OverviewPanelModel,
    SubsystemHealth,
)
from defenseclaw.tui.services.overview_state import DoctorRepairSummary, RuntimeOverview

sys.path.insert(0, str(Path(__file__).parent))
from fixtures import screen_text, snapshot_app  # noqa: E402

NOW = datetime(2026, 10, 3, 16, 0, tzinfo=timezone.utc)
# Text cells of one Overview notice line in an 80-column terminal. At 80x24
# only the first line of a notice is above the fold.
NOTICE_WIDTH_AT_80 = 67


def _model() -> OverviewPanelModel:
    model = OverviewPanelModel(OverviewConfig(data_dir="/tmp/dc", claw_mode="codex"), version="test")
    model.set_health(HealthSnapshot(api=SubsystemHealth(state="running")))
    return model


def _stale_failure(model: OverviewPanelModel) -> None:
    model.set_doctor_cache(
        DoctorCache(
            captured_at=NOW - timedelta(minutes=2),
            failed=12,
            checks=tuple(DoctorCheck("fail", "Sidecar API", "the gateway is not running") for _ in range(12)),
        )
    )
    model.set_gateway_probe("running")


def _doctor_failures(model: OverviewPanelModel) -> None:
    model.set_doctor_cache(
        DoctorCache(captured_at=NOW, failed=12, checks=(DoctorCheck("fail", "Hermes hooks", "unverified"),))
    )


def _stale_cache(model: OverviewPanelModel) -> None:
    model.set_doctor_cache(DoctorCache(captured_at=NOW - timedelta(days=3), passed=3))


def _repairs(model: OverviewPanelModel) -> None:
    model.set_doctor_cache(
        DoctorCache(captured_at=NOW, passed=3, repair_summary=DoctorRepairSummary(failed=12, blocked=12))
    )


def _failed_outcome(model: OverviewPanelModel) -> None:
    model.set_doctor_cache(DoctorCache(captured_at=NOW, passed=3, schema_version=2, outcome="failed", exit_code=1))


def _warning_outcome(model: OverviewPanelModel) -> None:
    model.set_doctor_cache(DoctorCache(captured_at=NOW, passed=3, schema_version=2, outcome="warning"))


def _missing_keys(model: OverviewPanelModel) -> None:
    names = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "SPLUNK_HEC_TOKEN")
    model.set_doctor_cache(
        DoctorCache(captured_at=NOW, failed=3, checks=tuple(DoctorCheck("fail", f"credential {n}") for n in names))
    )


def _not_configured(model: OverviewPanelModel) -> None:
    model.not_configured = True


def _gateway_stopped(model: OverviewPanelModel) -> None:
    model.set_gateway_probe("stopped")


def _runtime_unobserved(model: OverviewPanelModel) -> None:
    model.set_runtime_overview(RuntimeOverview(unobserved=12))


@pytest.mark.parametrize(
    ("arrange", "remedy"),
    [
        (_stale_failure, "press [d] to refresh"),
        (_doctor_failures, "run: defenseclaw doctor"),
        (_stale_cache, "press [d] on Overview to re-probe"),
        (_repairs, "see the DOCTOR panel"),
        (_failed_outcome, "see DOCTOR panel"),
        (_warning_outcome, "see the DOCTOR panel"),
        (_missing_keys, "run: defenseclaw keys fill-missing"),
        (_not_configured, "run: defenseclaw init"),
        (_gateway_stopped, "Run: defenseclaw-gateway start"),
        (_runtime_unobserved, "press Scan now in AI Discovery"),
    ],
)
def test_the_remedy_of_a_notice_is_on_its_first_line_at_80_columns(arrange, remedy) -> None:
    model = _model()
    arrange(model)
    messages = [notice.message for notice in model.build_notices(now=NOW) if remedy in notice.message]
    assert messages, [notice.message for notice in model.build_notices(now=NOW)]
    for message in messages:
        assert message.index(remedy) + len(remedy) <= NOTICE_WIDTH_AT_80, (len(message), message)


def test_removed_destination_notice_keeps_its_refresh_hint_at_80_columns() -> None:
    from test_final_cert_tui_b18_ux2 import _export, _status

    model = _model()
    model.set_doctor_cache(
        DoctorCache(
            captured_at=NOW - timedelta(minutes=2),
            failed=1,
            checks=(DoctorCheck("fail", "Destination: sf3r10-dead", "connection refused"),),
        )
    )
    model.set_observability_status(_status(_export("local-sqlite", "sqlite")))
    messages = [n.message for n in model.build_notices(now=NOW) if "press [d] to refresh" in n.message]
    assert messages and all(len(m) <= NOTICE_WIDTH_AT_80 for m in messages), messages


async def test_stale_failure_notice_shows_its_refresh_hint_at_80x24(tmp_path) -> None:
    # GAP-0566: "[>] Doctor cache shows 1 stale failure(s) that /health
    # disagrees with -" ended at column 80 and "press [d] to refresh" was cut.
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.action_switch_panel("policies")
        app.overview_model.set_health(HealthSnapshot(api=SubsystemHealth(state="running")))
        app.overview_model.set_gateway_probe("running")
        app.overview_model.set_doctor_cache(
            DoctorCache(
                captured_at=datetime.now(timezone.utc),
                failed=1,
                checks=(DoctorCheck("fail", "Sidecar API", "the gateway is not running"),),
            )
        )
        app.action_switch_panel("overview")
        await pilot.pause()
        lines = screen_text(app).splitlines()
        notice = [line for line in lines if "stale" in line and "[>]" in line]
        assert notice and "press [d] to refresh" in notice[0], "\n".join(lines)
