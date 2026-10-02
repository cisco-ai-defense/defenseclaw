# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert UX batch 9 (tui-panels): small model-level checks."""

from __future__ import annotations

import json
from types import SimpleNamespace

from defenseclaw.models import Event
from defenseclaw.tui.app import PANELS, _truncate_for_strip
from defenseclaw.tui.panels.audit import _matches_search_query
from defenseclaw.tui.panels.mcps import MCPsPanelModel
from defenseclaw.tui.panels.plugins import PluginsPanelModel
from defenseclaw.tui.panels.setup import SetupWizard
from defenseclaw.tui.panels.setup_catalog import TaskStatus
from defenseclaw.tui.panels.setup_center import task_detail
from defenseclaw.tui.panels.setup_keys import SETUP_KEYMAPS
from defenseclaw.tui.services.setup_state import CredentialRow, ReadinessCheck, build_readiness_checks
from defenseclaw.tui.widgets.tab_fit import fit_tab_labels, strip_width


def test_active_tab_takes_its_full_name_from_minor_badges() -> None:
    # GAP-1751: "R Registry…" on a 200-column screen for want of one cell.
    unread = {"alerts": 2, "logs": 2, "audit": 1, "activity": 1, "ai": 2}
    labels = fit_tab_labels(PANELS, "registries", unread, 174)
    assert labels["registries"] == "R Registries"
    assert "2" in labels["alerts"]
    assert strip_width(tuple(labels.values())) <= 174


def test_command_card_keeps_the_registry_summary_at_80_columns() -> None:
    # GAP-1754: the card cut "fetched 1, scanned 1,..." with 30 columns free.
    summary = "tb7v-local: fetched 1, scanned 1, promoted 1 MCP, blocked 0"
    assert _truncate_for_strip(summary, 76) == summary


def test_audit_free_text_block_skips_the_json_would_block_copy() -> None:
    # GAP-1780: allow rows carry an escaped JSON copy of would_block=false.
    details = (
        "connector=claudecode result=ok action=allow raw_action=allow severity=NONE mode=action "
        'would_block=false verdict={\\"action\\":\\"allow\\",\\"would_block\\":false}'
    )
    allow = Event(id="a", action="connector-hook", details=details)
    assert not _matches_search_query(allow, "block")
    assert _matches_search_query(allow, "decision:allow")


def test_live_credentials_beat_an_older_doctor_result() -> None:
    # GAP-1805: "1 required credential(s) missing" from a stale doctor run.
    doctor = {"missing_required_credentials": ["GALILEO_API_KEY"]}
    present = (CredentialRow(env_name="GALILEO_API_KEY", requirement="required", set=True),)
    checks = build_readiness_checks({}, None, doctor, present)
    row = next(check for check in checks if check.title == "Required Credentials")
    assert row.status == "pass"
    # Before the keys list loads, the doctor result still counts.
    checks = build_readiness_checks({}, None, doctor, ())
    row = next(check for check in checks if check.title == "Required Credentials")
    assert row.status == "fail"


def test_setup_task_detail_puts_the_fix_first() -> None:
    # GAP-1806: at 80x24 the fix command fell under the box border.
    check = ReadinessCheck("Required Credentials", "1 required credential(s) missing", "fail")
    model = SimpleNamespace(
        wizard_available=lambda _wizard: True,
        config={},
        readiness_checks=(check,),
        credential_snapshot=None,
    )
    text = task_detail(model, SetupWizard.CREDENTIALS, TaskStatus("attention", "keys missing")).plain
    assert text.startswith("Needs attention: 1 required credential(s) missing")


def test_setup_hint_fits_one_row_at_80_columns() -> None:
    # GAP-1825: "r refresh keys" wrapped and left "keys" on its own row.
    hint = " · ".join(f"{spec.key} {spec.label}" for spec in SETUP_KEYMAPS["wizards"] if spec.in_hint and not spec.when)
    assert len(hint) <= 78, hint


def test_plugins_header_says_verdict() -> None:
    # GAP-1749: clean/blocked sat under an "Actions" header.
    model = PluginsPanelModel(connector="hermes")
    assert model.data_table_columns()[2] == "Verdict"


def test_connector_filter_empty_state_names_the_hidden_rows() -> None:
    # GAP-1752: "Plugins 0 of 60 - No plugins detected" under a filter.
    model = PluginsPanelModel(connector="hermes")
    model.show_connector_column = True
    rows = json.dumps([{"id": "p1", "name": "p1"}, {"id": "p2", "name": "p2"}])
    model.apply_merged([("hermes", rows), ("claudecode", "[]")])
    model.set_connector_filter("claudecode")
    assert model.filtered_count() == 0
    assert model.empty_state() == (
        "No plugins for Claude Code; 2 in other connectors. Press m and pick All connectors to see them."
    )


def test_mcps_empty_state_covers_every_merged_connector() -> None:
    # GAP-1806: the All view named only Claude Code's paths.
    model = MCPsPanelModel(connector="claudecode")
    model.show_connector_column = True
    model.apply_merged([("claudecode", "[]"), ("codex", "[]"), ("hermes", "[]")])
    message = model.empty_state()
    assert message.startswith("No MCP servers found for the 3 active connectors (Claude Code, Codex, Hermes)")
    model.show_connector_column = False
    assert ".claude.json (mcpServers)" in model.empty_state()
