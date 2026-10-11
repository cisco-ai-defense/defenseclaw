# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI UX batch 19 (GAP-2319 to GAP-2326)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from defenseclaw.models import Event
from defenseclaw.tui import app as tui_app
from defenseclaw.tui.command_line import command_result_summary
from defenseclaw.tui.panels.activity import ActivityPanelModel
from defenseclaw.tui.panels.audit import _is_low_signal_event
from defenseclaw.tui.panels.setup import SetupWizard, wizard_state_summary
from defenseclaw.tui.panels.setup_catalog import task_status
from defenseclaw.tui.services.ai_discovery_state import AIUsageSnapshot
from defenseclaw.tui.services.overview_state import OverviewPanelModel
from defenseclaw.tui.services.setup_state import build_readiness_checks, guardrail_mode_label
from textual.widgets import Button, DataTable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixtures import snapshot_app  # noqa: E402


def test_discovery_scan_receipt_shows_the_counts() -> None:
    # GAP-2319: the receipt showed the footer hint, not the result.
    lines = [
        "AI discovery scan",
        "✓ Scan complete: active=8 new=0 changed=0 files=10",
        "Run 'defenseclaw agent usage' for the full table or 'agent discovery status' to confirm config drift.",
    ]
    expected = "Scan complete: active=8 new=0 changed=0 files=10"
    assert command_result_summary("agent discovery scan", lines) == expected
    ascii_lines = [line.replace("✓", "OK") for line in lines]
    assert command_result_summary("defenseclaw agent discovery scan", ascii_lines) == expected


def test_operator_changes_are_not_routine_audit_rows() -> None:
    # GAP-2322: the default Audit view hid the operator's own config change.
    operator = Event(action="config-update", actor="cli:operator", severity="INFO", details="model: a -> b")
    gateway = Event(action="sidecar-start", actor="defenseclaw", severity="INFO", details="sidecar starting")
    assert not _is_low_signal_event(operator)
    assert _is_low_signal_event(gateway)


def test_guardrail_setup_commands_never_open_the_terminal_picker() -> None:
    # GAP-2323: the interactive picker can't be answered from the TUI.
    intent = OverviewPanelModel().action_intent("g")
    assert intent is not None and "--non-interactive" in intent.args
    checks = build_readiness_checks({"guardrail": {"enabled": False}}, None, None, ())
    fix = next(check.fix for check in checks if check.title == "Guardrail")
    assert fix is not None and "--non-interactive" in fix.args


def test_guardrail_mode_names_connector_overrides() -> None:
    # GAP-2325: one connector switched to observe still read "action".
    cfg = {
        "guardrail": {
            "enabled": True,
            "mode": "action",
            "connectors": {"opencode": {"mode": "observe"}, "codex": {"mode": "action"}},
        }
    }
    assert guardrail_mode_label(cfg) == "action (opencode observe)"
    assert "Mode: action (opencode observe)" in wizard_state_summary(SetupWizard.GUARDRAIL, cfg)
    assert task_status(SetupWizard.GUARDRAIL, cfg).label.endswith("on · action, 1 observe")
    checks = build_readiness_checks(cfg, None, None, ())
    assert any(check.detail == "enabled in action (opencode observe) mode" for check in checks)
    assert guardrail_mode_label({"guardrail": {"mode": "action"}}) == "action"
    # GAP-0166: the only connector's own mode is the mode, not "observe, 1 action".
    solo = {"guardrail": {"enabled": True, "mode": "observe", "connectors": {"claudecode": {"mode": "action"}}}}
    assert guardrail_mode_label(solo) == "action"
    assert task_status(SetupWizard.GUARDRAIL, solo).label.endswith("on · action")


def test_overview_paths_show_home_as_tilde(monkeypatch, tmp_path) -> None:
    # GAP-2324: long home paths broke mid-path in the 80-column card.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # Windows expanduser
    want = "~" + os.sep + ".defenseclaw"
    assert tui_app._home_short(str(tmp_path / ".defenseclaw")) == want  # noqa: SLF001
    assert tui_app._home_short("/etc/defenseclaw") == "/etc/defenseclaw"  # noqa: SLF001


def test_activity_log_steps_aside_for_finished_output() -> None:
    # GAP-2326: the body and the drawer log showed the same output.
    model = ActivityPanelModel(None)
    model.add_entry("defenseclaw uninstall --dry-run")
    assert not model.shows_finished_output
    model.finish_entry(0)
    assert model.shows_finished_output
    model.handle_key("esc")
    assert not model.shows_finished_output


async def test_ai_discovery_at_80x24(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("ai")
        await pilot.pause()
        model = app.ai_discovery_model
        # GAP-2321: a local-model detail keeps its text on screen.
        model.active_table = "models"
        model.toggle_detail()
        app._render_chrome()  # noqa: SLF001
        await pilot.pause()
        assert app.query_one("#panel-table", DataTable).has_class("ai-step-aside")
        assert "seen" in app.detail_text
        model.toggle_detail()
        app._render_chrome()  # noqa: SLF001
        await pilot.pause()
        assert not app.query_one("#panel-table", DataTable).has_class("ai-step-aside")
        # GAP-2320: on in config but not running: the button says restart.
        model.set_snapshot(AIUsageSnapshot.from_mapping({"enabled": False, "configured_enabled": True}))
        app._render_chrome()  # noqa: SLF001
        await pilot.pause()
        assert str(app.query_one("#ai-enable", Button).label) == "Apply (restart gateway)"


async def test_overview_g_opens_the_guardrail_goals(tmp_path) -> None:
    # GAP-2323: g opens Setup's Guardrail goals instead of running a wizard.
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("overview")
        await pilot.pause()
        before = app.activity_model.count
        await pilot.press("g")
        await pilot.pause()
        assert app.active_panel == "setup"
        assert app.setup_model.active_wizard == SetupWizard.GUARDRAIL
        assert app.setup_model.goal_active or app.setup_model.form_active
        assert app.activity_model.count == before  # no command ran
