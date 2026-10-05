# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI batch fcz-b30: ACP Setup form hints explain each field."""

from __future__ import annotations

from defenseclaw.tui.panels.setup import SetupPanelModel, SetupWizard, wizard_goals


def test_acp_observe_form_hints_explain_fields() -> None:
    # GAP-2503: hints only repeated the label ("Select client.", "Sets --profile.").
    goal = next(g for g in wizard_goals(SetupWizard.ACP_GUARD, {}) if g.id == "observe")
    model = SetupPanelModel({})
    model.open_wizard_form(SetupWizard.ACP_GUARD, goal=goal)
    hints = {field.label: field.hint for field in model.form_fields}
    assert set(hints) == {"Client", "Agent", "Profile", "Action Mode"}
    for hint in hints.values():
        assert not hint.startswith(("Select ", "Sets --", "Toggle ", "Value for "))
    assert "Editor" in hints["Client"]
    assert "guards" in hints["Agent"]
    assert "acp.profiles" in hints["Profile"]
