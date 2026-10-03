# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Setup panel wording, navigation and refit fixes (final-cert TUI batch 7)."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from rich.console import Console

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixtures  # noqa: E402
from defenseclaw.tui import app as app_module  # noqa: E402
from defenseclaw.tui.panels import setup_catalog, setup_keys  # noqa: E402
from defenseclaw.tui.panels.setup import (  # noqa: E402
    SetupPanelModel,
    SetupWizard,
    connector_setup_wizard_fields,
    wizard_goals,
)
from defenseclaw.tui.screens.detail import DetailModalModel  # noqa: E402


def test_connector_readiness_wording_and_form_hints() -> None:
    # GAP-2059: the name went to a second line; hints only repeated the label.
    console = Console(width=92, record=True)
    console.print(DetailModalModel.from_pairs("t", [("Connector: claudecode", "PASS · configured")]).table())
    assert "Connector: claudecode" in console.export_text()
    hook = {field.label: field for field in connector_setup_wizard_fields({"guardrail": {"connector": "claudecode"}})}
    assert "Scanner Mode" not in hook and "Verify After Setup" not in hook
    assert hook["Guardrail Mode"].hint.startswith("observe only logs")
    assert not any(field.hint.startswith(("Select ", "Toggle ")) for field in hook.values())
    proxy = {field.label for field in connector_setup_wizard_fields({"guardrail": {"connector": "openclaw"}})}
    assert {"Scanner Mode", "Verify After Setup"} <= proxy
    texts = " ".join(
        f"{goal.label} {goal.summary}"
        for wizard in (SetupWizard.CONNECTOR_SETUP, SetupWizard.TOKEN_ROTATION)
        for goal in wizard_goals(wizard, {})
    )
    assert "peer" not in texts and "exact rollback" not in texts and "narrows" not in texts


def test_api_keys_hint_and_remove_form(tmp_path, monkeypatch) -> None:
    # GAP-2061: "? all keys" opened the keybinding help and r was cut; the
    # remove form previewed "keys remove '' --yes" and wanted a typed name.
    hint = setup_keys.keys_hint("wizards", ("credentials",))
    assert "r reload keys" in hint and hint.endswith("? help") and len(hint) <= setup_keys.HINT_WIDTH
    (tmp_path / ".env").write_text("OLD_TYPO_KEY=x\nDEFENSECLAW_GATEWAY_TOKEN=y\n")
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    model = SetupPanelModel({})
    goal = next(goal for goal in wizard_goals(SetupWizard.CREDENTIALS, {}) if goal.id == "remove")
    model.open_wizard_form(SetupWizard.CREDENTIALS, goal=goal)
    name = next(field for field in model.form_fields if field.label == "Env Name")
    assert name.kind == "choice" and name.options == ("", "OLD_TYPO_KEY")
    assert model.wizard_command_preview() == "defenseclaw keys remove <ENV_NAME> --yes"
    model.form_fields = [field.with_value("OLD_TYPO_KEY") if field is name else field for field in model.form_fields]
    action = model.submit_wizard_form()
    assert action.intent is not None and action.intent.label == "keys remove"


async def test_setup_right_reaches_config_and_help_keeps_the_card_fit(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(app_module, "STRIP_SUCCESS_SECONDS", 0.05)
    app = fixtures.snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.action_switch_panel("setup")
        await pilot.pause()
        # GAP-2072: after ? and Esc the card lost its "… i details" ending.
        await pilot.press("question_mark")
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        await pilot.pause()
        body = app.query_one("#detail-panel-body").render()
        assert getattr(body, "plain", str(body)).endswith("… i details")
        # GAP-2060: Right on the last group wrapped past "Config editor".
        app.setup_model.active_wizard = setup_catalog.group_tasks(setup_catalog.GROUP_TITLES[-1])[0]
        await pilot.press("right")
        await pilot.pause()
        assert app.setup_model.mode == "config"
        # GAP-2058: the receipt says it hides; its result stays on the status line.
        app._strip_label = "doctor"  # noqa: SLF001
        app._strip_state = "running"  # noqa: SLF001
        app._strip_output("Health: 3 passed, 1 warning")  # noqa: SLF001
        app._strip_finished(exit_code=0, duration=0.1)  # noqa: SLF001
        await pilot.pause()
        assert "hides in" in str(app.query_one("#command-progress-hint").render())
        hidden = asyncio.Event()
        app.set_timer(0.2, hidden.set)
        await asyncio.wait_for(hidden.wait(), timeout=10)
        await pilot.pause()
        assert app.status_text.startswith("Done: doctor · ")
