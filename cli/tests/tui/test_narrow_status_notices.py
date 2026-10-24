# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Health and the next diagnostic command remain visible at 80 columns."""

from dataclasses import replace
from datetime import datetime, timezone

from defenseclaw.config import default_config
from defenseclaw.tui.panels.overview import DoctorCache, DoctorCheck
from defenseclaw.tui.services.overview_state import OVERVIEW_NOTICE_WIDTH
from fixtures import screen_text, snapshot_app
from rich.text import Text


async def test_config_editor_keeps_health_visible(tmp_path):
    app = snapshot_app(tmp_path, setup_config=default_config())
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("0", "c")
        await pilot.pause()
        status = screen_text(app).splitlines()[-1]
        assert all(name in status for name in ("Gateway", "Watchdog", "Guardrail")), status


async def test_config_editor_and_palette_status_labels_fit_at_80_columns(tmp_path):
    app = snapshot_app(tmp_path, setup_config=default_config())
    app.overview_model.set_health(
        replace(
            app.overview_model.health,
            policy_generation=18,
            policy_digest="sha256:" + "ab" * 32,
        )
    )
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("0", "c")
        await pilot.pause()
        status = screen_text(app).splitlines()[-1]
        assert "Config editor" in status and app.status_text in status, status
        assert all(name in status for name in ("Gateway", "Watchdog", "Guardrail")), status
        assert "gen 18" in status, status

        await pilot.press("escape", ":", *"zzqq")
        await pilot.pause()
        status = screen_text(app).splitlines()[-1]
        assert "Command palette" in status and app.status_text in status, status
        assert all(name in status for name in ("Gateway", "Watchdog", "Guardrail")), status
        assert "gen 18" in status, status
        assert "Tab complete" in app.hint_text


async def test_doctor_failure_notice_keeps_the_remediation_command(tmp_path):
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.action_switch_panel("policies")
        app.overview_model.set_doctor_cache(
            DoctorCache(
                captured_at=datetime.now(timezone.utc),
                failed=1,
                checks=(DoctorCheck("fail", "Hermes hooks", "unverified"),),
            )
        )
        notice = next(n for n in app.overview_model.build_notices() if "defenseclaw doctor" in n.message)
        assert Text.from_markup(notice.message).cell_len <= OVERVIEW_NOTICE_WIDTH
        app.action_switch_panel("overview")
        await pilot.pause()
        screen = screen_text(app)
        assert "defenseclaw doctor" in screen, screen
