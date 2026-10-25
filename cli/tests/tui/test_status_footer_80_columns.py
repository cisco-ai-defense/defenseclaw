# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""An 80-column footer keeps the current action and essential health visible."""

from dataclasses import replace

from defenseclaw.config import default_config
from fixtures import screen_text, snapshot_app


def _app_with_applied_policy(tmp_path):
    app = snapshot_app(tmp_path, setup_config=default_config())
    app.overview_model.set_health(
        replace(
            app.overview_model.health,
            policy_generation=7,
            policy_digest="sha256:" + "ab" * 32,
        )
    )
    return app


def _assert_essential_health(status):
    assert all(name in status for name in ("Gateway", "Watchdog", "Guardrail")), status
    assert "gen 7" in status, status


async def test_config_editor_and_palette_labels_fit_with_health_at_80_columns(tmp_path):
    app = _app_with_applied_policy(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("0", "c")
        await pilot.pause()
        status = screen_text(app).splitlines()[-1]
        assert "Config editor" in status, status
        _assert_essential_health(status)

        await pilot.press("escape", ":")
        await pilot.pause()
        status = screen_text(app).splitlines()[-1]
        assert "Command palette" in status, status
        _assert_essential_health(status)


async def test_long_hints_keep_health_at_80_columns(tmp_path):
    app = _app_with_applied_policy(tmp_path)
    hints = (
        "Guardrail setup form opened. Tab between fields, Ctrl+R to run.",
        "Highlight a finding first (↑/↓), then click Open finding.",
        "Filter runtime findings: type to narrow, esc to clear.",
        "Back to the Setup tasks. 3 unsaved config values kept.",
    )
    async with app.run_test(size=(80, 24)) as pilot:
        for hint in hints:
            app._set_status(hint)
            await pilot.pause()
            status = screen_text(app).splitlines()[-1]
            assert hint.split()[0] in status, status
            _assert_essential_health(status)
