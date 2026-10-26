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


def _assert_essential_health(status, *, generation=True):
    assert all(name in status for name in ("Gateway", "Watchdog", "Guardrail")), status
    assert ("gen 7" in status) == generation, status


async def test_config_editor_and_palette_labels_fit_with_health_at_80_columns(tmp_path):
    # GAP-0740, GAP-1361: the whole status text, not "Config editor. Es…".
    app = _app_with_applied_policy(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("0", "c")
        await pilot.pause()
        status = screen_text(app).splitlines()[-1]
        assert "Config editor. Esc/w: tasks." in status, status
        _assert_essential_health(status)

        await pilot.press("escape", ":")
        await pilot.pause()
        status = screen_text(app).splitlines()[-1]
        assert "Command palette. Type or pick." in status, status
        # The applied policy gives way to the whole label; Overview shows it.
        _assert_essential_health(status, generation=False)


def test_short_action_labels_fit_whole_with_health_at_80_columns():
    # GAP-1361: the help drawer, Setup and Inventory labels were cut too.
    from rich.text import Text

    from defenseclaw.tui.widgets.status_strip import ServiceStatus, StatusModel, render_status_with_hint

    model = StatusModel(
        gateway=ServiceStatus("Gateway", "running"),
        watchdog=ServiceStatus("Watchdog", "running"),
        guardrail=ServiceStatus("Guardrail", "running"),
        applied_policy="gen 2 · 81c29ce2",
    )
    for hint in (
        "Command drawer closed.",
        "Config editor. Esc/w: tasks.",
        "Command palette. Type or pick.",
        "Back to the Setup tasks.",
        "Loading inventory…",
    ):
        status = Text.from_markup(render_status_with_hint(model, hint, 80)).plain
        assert status.startswith(hint), status
        assert len(status) <= 80 and "Guardrail" in status and "Watchdog" in status, status
    roomy = Text.from_markup(render_status_with_hint(model, "Ready.", 80)).plain
    assert "gen 2 · 81c29ce2" in roomy, roomy


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
            # A later word of each hint: the first ("Guardrail") is also a
            # health label, so it proved nothing (GAP-1548).
            assert hint.split()[1] in status, status
            _assert_essential_health(status)
