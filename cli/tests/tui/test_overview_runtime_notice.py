# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The degraded Runtime notice keeps its N key and its cause at 80x24."""

from __future__ import annotations

import itertools
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from defenseclaw.tui.panels.overview import DoctorCache, DoctorCheck
from defenseclaw.tui.services.overview_state import OVERVIEW_NOTICE_WIDTH, OverviewConfig, runtime_degraded_notice

sys.path.insert(0, str(Path(__file__).parent))

import fixtures  # noqa: E402
from test_final_cert_tui_fcz_b32 import _standard_account_runtime  # noqa: E402

# Every cause head the sensor reports (internal/sensor/service.go).
_PLANES = ("inference heartbeat", "shadow egress", "agent actions")
_HEADS = [
    *(
        f"{plane} {state}"
        for plane in _PLANES
        for state in ("unavailable", "available but not running", "partially covered")
    ),
    "process table unreadable",
    "connection table unreadable",
]


@pytest.mark.parametrize("count", [1, 2, len(_HEADS)])
def test_degraded_notice_fits_one_line_with_the_key_first(count: int) -> None:
    for heads in itertools.permutations(_HEADS, count) if count < 3 else [tuple(reversed(_HEADS))]:
        notice = runtime_degraded_notice("DEGRADED", ", ".join(heads))
        assert len(notice) <= OVERVIEW_NOTICE_WIDTH, notice
        assert notice.startswith("Runtime DEGRADED · N for details: "), notice
        plane = heads[0].split(" ", 2)[:2]
        assert " ".join(plane) in notice, (heads, notice)


def test_degraded_notice_keeps_the_plane_badges_of_the_fallback_reason() -> None:
    # With no sensor reasons the cause is "partial coverage: <plane> <badge>, ...".
    notice = runtime_degraded_notice("DEGRADED", "partial coverage: shadow-egress idle")
    assert notice == "Runtime DEGRADED · N for details: shadow-egress idle"
    notice = runtime_degraded_notice("DEGRADED", "partial coverage: shadow-egress idle, agent-actions unavailable")
    assert len(notice) <= OVERVIEW_NOTICE_WIDTH and "shadow-egress idle" in notice, notice


async def test_degraded_notice_shows_the_n_key_on_the_80x24_overview(tmp_path, monkeypatch) -> None:
    app = fixtures.snapshot_app(tmp_path)
    monkeypatch.setattr(app, "_schedule_health_poll", lambda: None)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.overview_model.cfg = OverviewConfig(
            guardrail_enabled=True,
            connector_modes=(("claudecode", "action"), ("codex", "action")),
        )
        app.overview_model.set_gateway_probe("running")
        app.overview_model.runtime = _standard_account_runtime().overview()
        app.overview_model.set_doctor_cache(
            DoctorCache(
                captured_at=datetime.now(timezone.utc), failed=1, schema_version=2,
                outcome="failed", exit_code=1,
                checks=(DoctorCheck("fail", "Hermes hook", "managed hook needs repair"),),
            )
        )
        app.action_switch_panel("overview")
        await pilot.pause()
        await pilot.pause()
        for width, height in ((80, 24), (80, 40), (120, 40), (80, 24)):
            await pilot.resize_terminal(width, height)
            await pilot.pause()
            screen = fixtures.screen_text(app)
            assert "defenseclaw doctor" in screen, screen
            assert "Runtime DEGRADED" in screen and "N for details" in screen, screen


async def test_stopped_gateway_recovery_is_whole_on_the_80x24_overview(tmp_path) -> None:
    app = fixtures.snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.overview_model.cfg = OverviewConfig(
            guardrail_enabled=True,
            connector_modes=(("claudecode", "action"), ("codex", "action")),
        )
        app.overview_model.set_gateway_probe("stopped")
        app.action_switch_panel("overview")
        await pilot.pause()
        screen = fixtures.screen_text(app)
        notices = app.overview_model.build_notices()
    recovery = next(notice.message for notice in notices if "Gateway is not running" in notice.message)
    assert any(recovery in line for line in screen.splitlines()), screen
