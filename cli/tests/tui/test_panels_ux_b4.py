# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""TUI panels UX batch 4: alert rows, upgrade preview, filters, Tools, Registry, Setup, Runtime."""

from __future__ import annotations

import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from defenseclaw.commands import cmd_alerts
from defenseclaw.tui.command_line import ParsedCommand
from defenseclaw.tui.panels.alerts import AlertsPanelModel, _alert_details_label
from defenseclaw.tui.panels.registries import sync_source_intent
from defenseclaw.tui.panels.setup import SetupPanelModel, SetupWizard, build_wizard_args, wizard_goals
from defenseclaw.tui.screens.command_preview import build_command_preview
from defenseclaw.tui.services.catalog_state import ToolsPanelModel
from defenseclaw.tui.services.runtime_state import PlaneRow, RuntimePanelModel
from defenseclaw.tui.services.v8_event_history import V8EventHistoryRow
from defenseclaw.tui.widgets import tab_fit
from textual.widgets import Input

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import settle_panel, snapshot_app  # noqa: E402


def test_secret_finding_row_names_its_rule_title_and_post_tool_decision(monkeypatch) -> None:
    monkeypatch.setattr(cmd_alerts, "_rule_pack_titles", lambda: {"SEC-AWS-KEY": "AWS access key"})
    finding = V8EventHistoryRow(
        id="f1",
        timestamp=datetime(2026, 10, 2, 9, 0, tzinfo=timezone.utc),
        bucket="security.finding",
        event_name="finding.observed",
        source="gateway",
        severity="CRITICAL",
        action="scan-finding",
        actor="audit_logger",
        details="finding.observed",
        connector="claudecode",
        redaction_profile="",
        payload={
            "defenseclaw.evaluation.id": "ev1",
            "defenseclaw.finding.rule_id": "SEC-AWS-KEY",
            "defenseclaw.finding.title": "Secret finding",
            "defenseclaw.finding.target_ref": "claudecode:PostToolUse",
            "defenseclaw.finding.evidence_summary": "<redacted-sensitive len=20>",
            "defenseclaw.guardrail.effective_action": "allow",
        },
    )
    model = AlertsPanelModel()
    model.apply_v8_history((finding,))
    event = model.audit_events[0]
    facts = dict(event.facts)
    # GAP-1423: same rule title and decision wording as "defenseclaw alerts".
    assert facts["Rule"] == "SEC-AWS-KEY: AWS access key"
    assert facts["Decision"] == "detected after the tool ran (cannot block)"
    # GAP-1324: the Details cell names the rule, not the redaction placeholder.
    assert _alert_details_label(event).startswith("SEC-AWS-KEY: AWS access key")


def test_upgrade_preview_says_it_replaces_binaries_and_restarts() -> None:
    # GAP-1422: Overview "u" called "defenseclaw upgrade" read-only.
    preview = build_command_preview(ParsedCommand("defenseclaw", ("upgrade",), "upgrade", "overview"))
    assert preview.risk == "restart"
    assert preview.restart == "yes"
    assert "replaces the DefenseClaw binaries" in preview.summary


def test_tools_add_hint_and_registry_intents() -> None:
    # GAP-1486: b/a on an empty Tools table say how to add a rule.
    tools = ToolsPanelModel()
    tools.apply_loaded([])
    action = tools.handle_key("b")
    assert action.handled and action.intent is None
    assert "tool block <tool-name>" in action.hint
    # GAP-1485: registry commands keep the Registry panel in front.
    assert sync_source_intent("local").stay_on_panel is True


def test_active_tab_keeps_its_name_beside_large_windows_badges(monkeypatch) -> None:
    # GAP-1457: with "8(99)"-style badges at 80 columns the active tab was a bare key.
    from defenseclaw.tui.app import PANELS

    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", True)
    unread = {"alerts": 8, "logs": 99, "audit": 99, "activity": 4, "ai": 2}
    for active, label in (("inventory", "6 Inventory"), ("registries", "R Registries"), ("ai", "V AI\u2026 (2)")):  # GAP-1541
        labels = tab_fit.fit_tab_labels(PANELS, active, unread, 66)
        assert labels[active] == label
        assert tab_fit.strip_width(tuple(labels.values())) <= 66


def test_runtime_host_plane_hint_uses_linux_terms() -> None:
    # GAP-1403: Linux was told to grant macOS Endpoint Security.
    plane = PlaneRow("c", "agent actions", True, False, reason="not selected in ai_discovery.runtime.planes")
    linux = RuntimePanelModel(platform="linux").plane_fix(plane)
    assert "CAP_SYS_ADMIN" in linux and "Endpoint Security" not in linux
    assert "Endpoint Security" in RuntimePanelModel(platform="darwin").plane_fix(plane)


def test_setup_gateway_form_and_remove_credential_form() -> None:
    # GAP-1473: the Gateway form starts from the configured gateway, and an
    # unedited form moves nothing.
    cfg = {"gateway": {"host": "127.0.0.1", "port": 0, "api_port": 19020}}
    model = SetupPanelModel(cfg)
    model.open_wizard_form(SetupWizard.GATEWAY)
    values = {field.label: field.value for field in model.form_fields}
    assert (values["Host"], values["Port"], values["API Port"]) == ("127.0.0.1", "", "19020")
    args = build_wizard_args(SetupWizard.GATEWAY, model.form_fields, cfg)
    assert "--api-port" not in args and "--host" not in args

    # GAP-1395: the remove goal has its own header text, and the
    # missing-field error goes away once the field is filled.
    goal = next(goal for goal in wizard_goals(SetupWizard.CREDENTIALS, cfg) if goal.id == "remove")
    model.open_wizard_form(SetupWizard.CREDENTIALS, goal=goal)
    assert model.active_goal is goal
    model.submit_wizard_form()
    assert model.current_form_error().startswith("Missing required field(s): Env Name")
    index = next(i for i, field in enumerate(model.form_fields) if field.label == "Env Name")
    model.form_fields[index] = replace(model.form_fields[index], value="VIRUSTOTAL_API_KEY")
    assert model.current_form_error() == ""


async def test_filter_esc_registry_stay_and_cancelled_task_at_80x24(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    ran: list[tuple[str, ...]] = []

    async def fake_run(_binary: str, args: tuple[str, ...], **_kwargs: Any) -> int:
        ran.append(tuple(args))
        return 0

    async with app.run_test(size=(80, 24)) as pilot:
        # GAP-1379/GAP-1402: Esc on the list clears the filter the hint names.
        app.action_switch_panel("skills")
        await settle_panel(app, pilot)
        await pilot.press("/", *"alpha", "enter")
        await pilot.pause()
        skills = app.catalog_models["skills"]
        assert skills.filter_text == "alpha"
        await pilot.press("escape")
        await pilot.pause()
        assert skills.filter_text == ""
        assert app.query_one("#skills-filter", Input).value == ""

        # GAP-1485: a confirmed registry sync stays on the Registry panel.
        app.action_switch_panel("registries")
        await settle_panel(app, pilot)
        app._run_command = fake_run  # type: ignore[method-assign]

        async def confirm(_screen: object) -> bool:
            return True

        app.push_screen_wait = confirm  # type: ignore[method-assign]
        assert await app._confirm_and_run_intent(sync_source_intent("local")) == 0
        assert app.active_panel == "registries"
        assert ran == [("registry", "sync", "local", "--json")]

        # GAP-1478: cancelling a Setup task's confirm puts its row back.
        async def cancel(_screen: object) -> bool:
            return False

        app.push_screen_wait = cancel  # type: ignore[method-assign]
        app.setup_model.wizard_status[SetupWizard.TOKEN_ROTATION] = "running..."
        parsed = ParsedCommand("defenseclaw", ("setup", "rotate-token", "--yes"), "setup rotate-token", "setup")
        assert await app._confirm_and_run_parsed(parsed) is None
        assert app.setup_model.wizard_status.get(SetupWizard.TOKEN_ROTATION) != "running..."
        assert ran == [("registry", "sync", "local", "--json")]
