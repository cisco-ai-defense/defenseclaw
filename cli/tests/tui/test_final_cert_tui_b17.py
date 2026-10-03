# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI UX batch 17 (GAP-2275, GAP-2276, GAP-2278)."""

from __future__ import annotations

import json
from types import SimpleNamespace

from defenseclaw.models import Event
from defenseclaw.tui.command_line import ParsedCommand
from defenseclaw.tui.models import HintState
from defenseclaw.tui.panels.audit import (
    _event_target,
    _row_details_label,
    _row_target_label,
    _search_haystack,
)
from defenseclaw.tui.panels.setup import SetupPanelModel, SetupWizard, wizard_goals
from defenseclaw.tui.screens.command_preview import build_command_preview
from defenseclaw.tui.services.ai_discovery_state import AIDiscoveryPanelModel
from defenseclaw.tui.widgets.hint_bar import HintEngine


def _restart(*args: str) -> str:
    command = ParsedCommand(
        binary="defenseclaw",
        args=args,
        display_name=" ".join(args),
        category="setup",
        needs_preview=True,
        risk="setup",
    )
    return build_command_preview(command).restart


def test_agent_discovery_toggle_says_it_restarts_the_gateway() -> None:
    # GAP-2278: "Restart no" although enable/disable restart by default.
    assert _restart("agent", "discovery", "enable", "--yes") == "yes"
    assert _restart("agent", "discovery", "disable", "--yes") == "yes"
    assert _restart("agent", "discovery", "runtime", "enable", "--yes") == "yes"
    assert _restart("agent", "discovery", "enable", "--yes", "--no-restart") == "no"
    assert _restart("agent", "discovery", "scan") == "no"


def test_ai_discovery_hint_offers_the_pending_restart() -> None:
    # GAP-2278: the panel said "Press d to restart it", the hint "d turn on".
    model = AIDiscoveryPanelModel()
    model.snapshot = SimpleNamespace(enabled=False, restart_pending=True)
    conditions = model.hint_conditions()
    assert "restart_pending" in conditions
    hint = HintEngine().hint_for(HintState(active_panel="ai", panel_conditions=conditions))
    assert "d restart gateway" in hint and "d turn on" not in hint


def test_audit_operator_change_shows_target_and_change() -> None:
    # GAP-2275: blank TARGET, details "config.change.applied", search "llm" found nothing.
    event = Event(
        id="e1",
        action="config-update",
        actor="cli:operator",
        details="config.change.applied",
        structured={
            "defenseclaw.admin.target_ref": "config:llm:guardrail.judge",
            "defenseclaw.admin.diff": json.dumps(
                [{"path": "model", "op": "replace", "before": "haiku", "after": "sonnet"}]
            ),
        },
    )
    assert _row_target_label(event) == "config:llm:guardrail.judge"
    assert _event_target(event) == "config:llm:guardrail.judge"
    assert _row_details_label(event).startswith("model: haiku")
    haystack = _search_haystack(event)
    assert "llm" in haystack and "sonnet" in haystack
    # A gateway reload row without an admin target keeps its own details.
    reload_row = Event(id="e2", action="config-update", details="config.change.applied")
    assert _row_target_label(reload_row) == ""
    assert _row_details_label(reload_row).startswith("config.change")


def _open_goal(model: SetupPanelModel, wizard: SetupWizard, goal_id: str) -> None:
    goal = next(goal for goal in wizard_goals(wizard, {}) if goal.id == goal_id)
    model.open_wizard_form(wizard, goal=goal)


def test_destination_goals_show_only_the_rows_they_pass() -> None:
    # GAP-2276: Realm us1 showed on list/enable/remove and never reached the command.
    model = SetupPanelModel({})
    _open_goal(model, SetupWizard.OBSERVABILITY, "list")
    assert [field.label for field in model.form_fields] == ["Action", "JSON Output"]
    _open_goal(model, SetupWizard.OBSERVABILITY, "enable")
    assert [field.label for field in model.form_fields] == ["Action", "Name"]
    name = model.form_fields[1]
    assert name.hint == "Name of the destination to enable."
    _open_goal(model, SetupWizard.WEBHOOKS, "remove")
    labels = [field.label for field in model.form_fields]
    assert "URL" not in labels and "Name" in labels
