# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert UX batch 10 (tui): small model-level checks."""

from __future__ import annotations

from defenseclaw.models import Event
from defenseclaw.tui.app import PANELS
from defenseclaw.tui.panels import setup_keys
from defenseclaw.tui.panels.audit import AuditPanelModel
from defenseclaw.tui.panels.mcps import MCPsPanelModel
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.tab_fit import fit_tab_labels, strip_width


def test_active_tab_reads_in_full_at_80_columns(monkeypatch) -> None:
    # GAP-1751: "R Registry…" at 80x24 with free cells while minor badges stayed.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    unread = {"alerts": 1, "logs": 506, "audit": 271, "activity": 1}
    for active, title in (("registries", "R Registries"), ("sandboxes", "7 Sandboxes")):
        for width in range(62, 76):
            labels = fit_tab_labels(PANELS, active, unread, width)
            assert labels[active] == title, (width, labels[active])
            assert labels["alerts"].endswith(("¹", "(1)"))  # bare keys: "2(1)" (GAP-2247)
            assert strip_width(tuple(labels.values())) <= width


def test_setup_task_list_hint_fits_one_row_with_task_keys() -> None:
    # GAP-1825: with API keys & secrets selected the hint wrapped to a second row.
    for conditions in ((), ("credentials",), ("restart_pending",), ("credentials", "restart_pending")):
        hint = setup_keys.keys_hint("wizards", conditions)
        assert len(hint) <= setup_keys.HINT_WIDTH, hint
    hint = setup_keys.keys_hint("wizards", ("credentials",))
    assert "f fill missing" in hint and "s set key" in hint and hint.endswith("? help")
    assert setup_keys.keys_hint("wizards").endswith("c config")


def test_audit_digits_switch_panels_and_h_l_step_the_chips() -> None:
    # GAP-1934: 5 filtered Audit to Credentials instead of opening Plugins.
    model = AuditPanelModel()
    model.set_events([Event(id="a", action="scan", target="skill://one", severity="HIGH")])
    for digit in "12345":
        assert model.handle_key(digit).handled is False
    assert model.common_filter == ""
    model.handle_key("l")
    assert model.show_all_events and model.common_filter == ""
    model.handle_key("l")
    assert model.common_filter == "risk"
    for _ in range(5):
        model.handle_key("l")
    assert model.common_filter == "credentials"
    model.handle_key("h")
    assert model.common_filter == "scans"


def test_hermes_mcp_empty_state_names_its_config() -> None:
    # GAP-1935: "No MCP servers configured in  (active connector: Hermes)."
    model = MCPsPanelModel(connector="hermes")
    model.apply_merged([("hermes", "[]")])
    message = model.empty_state()
    assert "config.yaml (mcp_servers)" in message
    assert "in  (" not in message
    kiro = MCPsPanelModel(connector="kiro")
    kiro.apply_merged([("kiro", "[]")])
    assert kiro.empty_state() == "No MCP servers found for Kiro."
