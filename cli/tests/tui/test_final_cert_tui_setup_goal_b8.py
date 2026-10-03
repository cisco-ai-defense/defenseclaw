# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert batch 8: Setup goal forms and readiness hints."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from defenseclaw.tui.panels.setup import SetupPanelModel, SetupWizard, wizard_goals  # noqa: E402
from defenseclaw.tui.panels.setup_catalog import setup_detail_pairs  # noqa: E402
from defenseclaw.tui.services.setup_state import build_readiness_checks  # noqa: E402
from fixtures import screen_text, snapshot_app  # noqa: E402


def _goal(goal_id: str, cfg: object | None = None):
    return next(goal for goal in wizard_goals(SetupWizard.CONNECTOR_SETUP, cfg) if goal.id == goal_id)


async def test_rerun_form_relays_out_when_the_connector_drops_rows(tmp_path) -> None:
    # GAP-2131: switching openclaw -> a hook connector drops Scanner Mode and
    # Verify After Setup; the patched table kept the wider Field column, so
    # the Connector hint was cut at the screen edge instead of wrapping.
    from textual.widgets import DataTable

    cfg = {"guardrail": {"connector": "openclaw", "connectors": {"openclaw": {}, "codex": {}}}}
    app = snapshot_app(tmp_path, setup_config=cfg)
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("setup")
        await pilot.pause()
        app.setup_model.open_wizard_form(SetupWizard.CONNECTOR_SETUP, goal=_goal("rerun", cfg))
        app.setup_model.form_cursor = 0
        app._render_chrome()  # noqa: SLF001
        await pilot.pause()
        assert app.setup_model.form_fields[0].label == "Connector"
        before = len(app.setup_model.form_fields)
        for _ in range(8):
            await pilot.press("right")
            await pilot.pause()
            if len(app.setup_model.form_fields) < before:
                break
        fields = app.setup_model.form_fields
        assert len(fields) < before, [field.label for field in fields]
        table = app.query_one("#panel-table", DataTable)
        field_column = next(iter(table.columns.values()))
        assert field_column.content_width == max(len(field.label) for field in fields)
        hint = fields[0].hint
        assert hint.split()[-1] in screen_text(app), screen_text(app)


def test_replace_existing_hint_is_plain_words() -> None:
    # GAP-2132: the hint still said "adding this connector as a peer".
    model = SetupPanelModel({"config_version": 8, "guardrail": {"connectors": ["claudecode"]}})
    model.open_wizard_form(SetupWizard.CONNECTOR_SETUP, goal=_goal("add"))
    hint = next(field.hint for field in model.form_fields if field.label == "Replace Existing")
    assert "peer" not in hint and "connector set" not in hint
    assert hint.startswith("yes ") and "no " in hint


def test_no_connector_readiness_does_not_recommend_openclaw() -> None:
    # GAP-2134: with no connector the card said "fix: defenseclaw setup
    # openclaw --yes" to every user, hook-connector users included.
    checks = build_readiness_checks({"config_version": 8}, None, None, ())
    check = next(check for check in checks if check.title == "Connector")
    assert check.status == "fail" and check.fix is None
    assert "openclaw" not in check.detail.lower() and "Add or configure a connector" in check.detail
    model = SetupPanelModel({"config_version": 8})
    model.readiness_checks = checks
    pairs = dict(setup_detail_pairs(model))
    assert "openclaw" not in pairs["Connector"].lower()
