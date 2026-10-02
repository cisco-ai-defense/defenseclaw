# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fix batch fcx-b3: legacy audit scan, markup escape, panel keys, footer labels."""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

from rich.text import Text
from textual.markup import to_content

from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.markup_safe import escape
from defenseclaw.tui.panels.alerts import AlertsPanelModel
from defenseclaw.tui.panels.registries import RegistriesPanelModel, RegistriesTab
from defenseclaw.tui.panels.setup import SetupPanelModel, SetupWizard
from defenseclaw.tui.screens.uninstall import UninstallOption, uninstall_command_for_option
from defenseclaw.tui.services import v8_event_history
from defenseclaw.tui.services.policy_state import POLICY_VIEWS, PoliciesPanelModel


def test_alert_scan_skips_legacy_rows_whose_action_is_not_a_block(monkeypatch) -> None:
    # GAP-1674: legacy hook rows carry "action=allow" in details, so the
    # GAP-1487 pre-check (any "action") still ran the Python classifier on
    # every one of them.
    calls: list[str] = []
    classify = v8_event_history.aggregate_connector_hook_decision

    def counting(details, structured=None, enforced=None):  # type: ignore[no-untyped-def]
        calls.append(details)
        return classify(details, structured, enforced)

    monkeypatch.setattr(v8_event_history, "aggregate_connector_hook_decision", counting)
    db = sqlite3.connect(":memory:")
    db.execute(
        """CREATE TABLE audit_events (
            id TEXT PRIMARY KEY, timestamp TEXT, bucket TEXT, event_name TEXT,
            source TEXT, signal TEXT, severity TEXT, action TEXT, actor TEXT,
            details TEXT, connector TEXT, redaction_profile TEXT, run_id TEXT,
            trace_id TEXT, request_id TEXT, session_id TEXT, turn_id TEXT,
            scan_id TEXT, finding_id TEXT, payload_json TEXT, projected_record_json TEXT
        )"""
    )
    rows = [(f"fill-{i}", "2026-10-01T10:00:00Z", "he5-filler", "action=allow " + "AB01" * 100) for i in range(50)]
    rows.append(("hook-block", "2026-10-02T10:00:00Z", "connector-hook", "connector=codex action=BLOCK"))
    db.executemany(
        "INSERT INTO audit_events (id, timestamp, action, details, severity) VALUES (?, ?, ?, ?, 'INFO')",
        rows,
    )
    reader = v8_event_history.V8EventHistoryReader(SimpleNamespace(db=db))

    alert_ids = {row.id for row in reader.load_alerts(500)}

    assert "hook-block" in alert_ids
    assert not any(alert_id.startswith("fill-") for alert_id in alert_ids)
    assert calls and not any("action=allow" in details for details in calls)


def test_escape_is_safe_for_textual_and_rich_markup() -> None:
    # GAP-1675: rich.markup.escape left "[90m a=b-c" (an SGR code that lost
    # its ESC) as a Textual tag, which raised MarkupError.
    for text in ("[90m a=b-c", "foo [1m x=claudecode-hooks-v2 status=known", "[bold]x[/bold]", "[1] item", "a [ b"):
        markup = escape(text)
        assert to_content(markup).plain == text
        assert Text.from_markup(markup).plain == text
        to_content(f"[#F87171]{markup}[/]")


def test_digits_stay_panel_keys_on_registries_alerts_and_policies() -> None:
    # GAP-1700, GAP-1708: these panels took 1-7 for their own sub-views, so
    # the tab bar's "1 Overview" .. "6 Inv" did nothing there.
    registries = RegistriesPanelModel()
    alerts = AlertsPanelModel()
    policies = PoliciesPanelModel()
    for key in "1234567":
        assert registries.handle_key(key).handled is False
        assert alerts.handle_key(key).handled is False
        assert policies.handle_key(key).handled is False

    registries.handle_key("l")
    assert registries.current_tab == RegistriesTab.ENTRIES
    registries.handle_key("right")
    registries.handle_key("l")
    assert registries.current_tab == RegistriesTab.APPROVED
    registries.handle_key("h")
    assert registries.current_tab == RegistriesTab.ENTRIES

    assert alerts.active_scope_key() == "actionable"
    alerts.handle_key("l")
    assert alerts.active_scope_key() == "all"
    action = alerts.handle_key("l")
    assert alerts.active_scope_key() == "critical" and action.filter_change is not None
    alerts.handle_key("h")
    alerts.handle_key("h")
    assert alerts.active_scope_key() == "actionable"

    assert policies.view == POLICY_VIEWS[0]
    policies.handle_key("right")
    assert policies.view == POLICY_VIEWS[1]
    policies.handle_key("[")
    assert policies.view == POLICY_VIEWS[0]
    assert "←/→ view" in policies.keys_hint()


def test_footer_names_what_ran(monkeypatch) -> None:
    # GAP-1709: "Done: uninstall." after the dry-run preview and
    # "Done: setup Connector Setup." after a connector setup re-run.
    statuses: list[str] = []
    stub = SimpleNamespace(_set_status=statuses.append)
    preview = uninstall_command_for_option(UninstallOption.DRY_RUN)
    DefenseClawTUI._report_command_result(stub, preview.display_name, 0)  # type: ignore[arg-type]
    assert statuses == ["Done: uninstall dry-run (nothing changed)."]

    model = SetupPanelModel({})
    model.open_wizard_form(SetupWizard.CONNECTOR_SETUP)
    action = model.submit_wizard_form()
    assert action.intent is not None
    assert action.intent.label == "setup " + action.intent.args[1]
    assert "Connector Setup" not in action.intent.label
