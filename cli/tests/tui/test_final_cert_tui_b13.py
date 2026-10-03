# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Setup card refit, readiness labels and Alerts search (final-cert TUI UX batch 13)."""

from __future__ import annotations

import sys
from pathlib import Path

from rich.console import Console

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixtures  # noqa: E402
from defenseclaw.config import default_config  # noqa: E402
from defenseclaw.tui.panels.alerts import AlertEvent, AlertsPanelModel  # noqa: E402
from defenseclaw.tui.panels.setup import SetupPanelModel, SetupWizard, wizard_goals  # noqa: E402
from defenseclaw.tui.screens.detail import DetailModalModel  # noqa: E402


def test_readiness_label_fits_one_line() -> None:
    # GAP-2127: "Registry / Asset Policy" (23 chars) wrapped in the 22-column label.
    console = Console(width=92, record=True)
    pairs = [
        ("Command", "defenseclaw setup <connector> --yes " * 6),
        ("Registry / Asset Policy", "PASS · Registry policy is ready or not required."),
    ]
    console.print(DetailModalModel.from_pairs("t", pairs).table())
    assert "Registry / Asset Policy" in console.export_text()


def test_alerts_search_matches_the_details_column() -> None:
    # GAP-2128: the rule id and title were shown in Details but not searched.
    event = AlertEvent(
        id="f1",
        severity="HIGH",
        action="scan-finding",
        target="claudecode",
        details="bucket=security.finding event_name=finding.observed source=hook summary=<redacted>",
        facts=(("Rule", "PATH-AWS-CREDS: AWS credentials file"),),
    )
    model = AlertsPanelModel()
    model.set_events([event])
    for text in ("AWS", "path-aws-creds", "credentials file"):
        model.set_filter(text)
        assert [row.event.id for row in model.filtered] == ["f1"], text
    model.set_filter("no-such-text")
    assert model.filtered == []


async def test_setup_card_keeps_its_fit_after_help_80x24(tmp_path) -> None:
    # GAP-2072: after ? and Esc the card filled its box exactly, got a
    # scrollbar, re-wrapped one column narrower and lost "… i details".
    app = fixtures.snapshot_app(tmp_path, setup_config=default_config())
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("0")
        await pilot.pause()
        for key in ("question_mark", "escape"):
            await pilot.press(key)
            await pilot.pause()
            await pilot.pause()
        panel = app.query_one("#detail-panel")
        body = app.query_one("#detail-panel-body").render()
        assert getattr(body, "plain", str(body)).endswith("… i details")
        assert not panel.show_vertical_scrollbar


def _open_goal(model: SetupPanelModel, wizard: SetupWizard, goal_id: str) -> None:
    goal = next(goal for goal in wizard_goals(wizard, {}) if goal.id == goal_id)
    model.open_wizard_form(wizard, goal=goal)


def test_rerun_form_hides_proxy_only_fields_for_hook_connectors() -> None:
    # GAP-2129: Scanner Mode / Verify After Setup showed for Claude Code and
    # changing them did not change the command.
    model = SetupPanelModel({"guardrail": {"connector": "openclaw"}})
    _open_goal(model, SetupWizard.CONNECTOR_SETUP, "rerun")
    assert {"Scanner Mode", "Verify After Setup"} <= {field.label for field in model.form_fields}
    model.form_fields = [
        field.with_value("claudecode") if field.label == "Connector" else field for field in model.form_fields
    ]
    model.recompute_dependent_fields()
    labels = {field.label for field in model.form_fields}
    assert "Scanner Mode" not in labels and "Verify After Setup" not in labels
    assert model.wizard_command_preview().startswith("defenseclaw setup claude-code --yes")


def test_remove_form_lists_non_registry_entries(tmp_path, monkeypatch) -> None:
    # GAP-2061: the pick list held only registry keys, so a mistyped name
    # listed under "Other entries in .env" could not be removed.
    (tmp_path / ".env").write_text("SPLUNK_ACCESS_TOKEN=a\nTB_DEMO_A=b\nTB_DEMO_B=c\nDEFENSECLAW_GATEWAY_TOKEN=d\n")
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    model = SetupPanelModel({})
    _open_goal(model, SetupWizard.CREDENTIALS, "remove")
    name = next(field for field in model.form_fields if field.label == "Env Name")
    assert name.kind == "choice" and name.options == ("", "SPLUNK_ACCESS_TOKEN", "TB_DEMO_A", "TB_DEMO_B")
