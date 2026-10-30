# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Health and the next diagnostic command remain visible at 80 columns."""

import json
from dataclasses import replace
from datetime import datetime, timezone

from defenseclaw.config import default_config
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
        # The applied policy gives way to the whole palette label (cli-tui-obs GAP-0740/GAP-1361); Overview shows it.
        assert "Tab complete" in app.hint_text


async def test_doctor_failure_notice_keeps_the_remediation_command(tmp_path, monkeypatch):
    # The failed run as `defenseclaw doctor` leaves it in <data_dir>/doctor_cache.json.
    # Every Overview reload reads this file, so a background signal refresh
    # that copied the app before the cache was loaded cannot clear the notice
    # when it lands (it did on the Windows runner: notice row empty).
    (tmp_path / "doctor_cache.json").write_text(
        json.dumps(
            {
                "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                "passed": 0,
                "failed": 1,
                "warned": 0,
                "skipped": 0,
                "checks": [{"status": "fail", "label": "Hermes hooks", "detail": "unverified"}],
            }
        ),
        encoding="utf-8",
    )
    app = snapshot_app(tmp_path)
    # The fixture has no sidecar API port, so a health poll that lands during
    # the test (the Windows runner is slow enough) puts the gateway-health
    # notice in the one notice row; this test is about the Doctor notice.
    monkeypatch.setattr(app, "_schedule_health_poll", lambda: None)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.action_switch_panel("policies")
        # A signal refresh whose detached copy predates the cache load, then
        # the load: the order the slow runner hit.
        app._schedule_signal_data_refresh()  # noqa: SLF001 - drive the background reload.
        app._load_doctor_cache()  # noqa: SLF001 - exercise the disk consumer.
        notice = next(n for n in app.overview_model.build_notices() if "defenseclaw doctor" in n.message)
        assert Text.from_markup(notice.message).cell_len <= OVERVIEW_NOTICE_WIDTH
        await app.workers.wait_for_complete()
        app.action_switch_panel("overview")
        await pilot.pause()
        screen = screen_text(app)
        assert "defenseclaw doctor" in screen, screen
