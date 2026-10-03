# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI batch fcy-b3: 80x24 wording and wrapping, the Setup Action dead end."""

from __future__ import annotations

from types import SimpleNamespace

from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.models import HintState
from defenseclaw.tui.panels.setup import SetupPanelModel, SetupWizard, build_wizard_args, wizard_goals
from defenseclaw.tui.widgets.hint_bar import HintEngine, pack_hint_items


def test_panel_keys_hints_break_between_items_at_80_columns() -> None:
    # GAP-2032: "u" / "unblock" on Skills, a row starting "| Enter detail" on Logs.
    engine = HintEngine()
    for panel in ("skills", "mcps", "logs", "audit", "ai-discovery", "plugins", "registries"):
        hint = engine.hint_for(HintState(active_panel=panel))
        items = hint.split(" | ")
        rows = pack_hint_items(hint, 78).split("\n")
        assert len(rows) <= 2 and all(len(row) <= 78 for row in rows), (panel, rows)
        assert not any(row.startswith("|") or row.endswith("|") for row in rows), (panel, rows)
        assert all(item in items for row in rows for item in row.split(" | ")), (panel, rows)


def test_help_overlay_keeps_a_path_in_one_piece() -> None:
    # GAP-2033: "(~/.defenseclaw/last-" / "run.log)" at 80 columns.
    desc = "Copy / save its output (~/.defenseclaw/last-run.log)"
    fake = SimpleNamespace(
        _help_sections=lambda: [("While a command is running", [("Y / Ctrl+S", desc)])],
        _body_width=lambda: 74,
    )
    body = DefenseClawTUI._render_help_body(fake)
    assert "(~/.defenseclaw/last-run.log)" in body
    assert "last-\n" not in body


def test_hook_calls_card_does_not_reuse_idle() -> None:
    # GAP-2005: the card said "3 idle" while the Agent row's "idle" means "not open".
    totals = {"claudecode": (100, 4, 0), "codex": (0, 0, 0), "hermes": (0, 0, 0), "opencode": (0, 0, 0)}
    fake = SimpleNamespace(
        _active_connector_names=lambda: list(totals),
        _connector_hook_stats_for_connectors=lambda names: (*totals[names[0]], ""),
    )
    calls, _blocks = DefenseClawTUI._multi_connector_tile_details(fake)
    assert "claudecode[/] 104" in calls
    assert "3 with no calls" in calls and "idle" not in calls


def test_connector_goals_keep_their_own_action() -> None:
    # GAP-2026: Action=batch in "Add or configure a connector" needed rows the
    # form never shows; each goal now keeps the one action it runs.
    cfg = {"guardrail": {"connector": "codex", "connectors": {"codex": {}}}}
    goals = {goal.id: goal for goal in wizard_goals(SetupWizard.CONNECTOR_SETUP, cfg)}
    for goal_id, action in (("add", "setup"), ("rerun", "setup"), ("remove", "remove"), ("bulk", "batch")):
        model = SetupPanelModel(cfg)
        model.open_wizard_form(SetupWizard.CONNECTOR_SETUP, goal=goals[goal_id])
        row = next(field for field in model.form_fields if field.label == "Action")
        assert row.options == (action,) and row.value == action, (goal_id, row)
    model = SetupPanelModel(cfg)
    model.open_wizard_form(SetupWizard.CONNECTOR_SETUP, goal=goals["remove"])
    args = build_wizard_args(SetupWizard.CONNECTOR_SETUP, model.form_fields, cfg)
    assert tuple(args[:2]) == ("setup", "remove"), args
