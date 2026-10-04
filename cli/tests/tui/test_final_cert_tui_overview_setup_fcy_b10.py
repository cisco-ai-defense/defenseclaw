# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI batch fcy-b10: Overview tables at 80 columns, Setup form wording."""

from __future__ import annotations

import io
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.command_line import command_result_summary
from defenseclaw.tui.panels.setup import (
    SetupPanelModel,
    SetupWizard,
    _guardrail_wizard_fields_for,
    build_wizard_args,
    notifications_routing_wizard_fields,
    wizard_goals,
)
from defenseclaw.tui.services.overview_state import ConnectorOverviewRow
from defenseclaw.tui.widgets.fit_columns import FitColumn, FitColumnsTable
from rich.console import Console
from rich.text import Text

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixtures import snapshot_app  # noqa: E402


def _render(renderable: Any, width: int) -> str:
    console = Console(file=io.StringIO(), width=width, record=True)
    console.print(renderable)
    return console.export_text()


def test_overview_connectors_keep_names_and_numbers_at_80_columns() -> None:
    # GAP-2385: "C…" / "3…" for 303 calls, "MO…", "● run…" at 80 columns.
    rows = [
        ConnectorOverviewRow("claudecode", "action", "pack", "17m ago", 303, 14, 14, "running"),
        ConnectorOverviewRow("opencode", "action", "default", "—", 0, 0, 0, "idle"),
    ]
    fake = SimpleNamespace(
        _connector_filter=lambda: "",
        overview_model=SimpleNamespace(connector_priority_conflict_notice=lambda _name: ""),
    )
    panel = DefenseClawTUI._overview_connectors_panel(fake, rows)
    narrow = _render(panel, 76)
    assert "Claude Code (claudecode)" in narrow and "303" in narrow and "● running" in narrow
    assert "CALLS" in narrow and "BLOCKS" in narrow and "…" not in narrow.split("Press m")[0]
    assert "RULE PACK" not in narrow
    wide = _render(panel, 160)
    assert "RULE PACK" in wide and "LAST ACTIVITY" in wide and "17m ago" in wide


def test_destination_table_drops_limits_before_the_name() -> None:
    # GAP-2385: at 80 columns only HEALTH / QUEUE / CONFIGURED LIMITS were left.
    columns = (
        FitColumn("NAME"),
        FitColumn("KIND", priority=9),
        FitColumn("HEALTH"),
        FitColumn("QUEUE", priority=7),
        FitColumn("CONFIGURED LIMITS", priority=1),
        FitColumn("TARGET", priority=3, flex_min=16),
    )
    rows = [
        tuple(Text(cell) for cell in row)
        for row in (
            ("local-sqlite", "sqlite", "healthy (active)", "0 dropped", "not-applicable", "C:\\dc\\audit.db"),
            (
                "xw3-grafana",
                "otlp",
                "healthy (delivering)",
                "3/4096 items, 5.8 KiB/128.0 MiB",
                "queue=2048 items/64.0 MiB; batch=512 items",
                "http://127.0.0.1:4318/v1/logs",
            ),
        )
    ]
    narrow = _render(FitColumnsTable(columns, rows), 68)
    assert "local-sqlite" in narrow and "xw3-grafana" in narrow and "healthy (delivering)" in narrow
    assert "CONFIGURED LIMITS" not in narrow and "otlp" in narrow
    assert "CONFIGURED LIMITS" in _render(FitColumnsTable(columns, rows), 200)


def test_scan_all_summary_says_what_was_scanned() -> None:
    # GAP-2388: "4 connectors scanned" when no connector had a skill to scan.
    empty = [
        "-- connector: claudecode --",
        "No skills found for connector='claudecode' in configured directories:",
        "-- connector: codex --",
        "No scannable skills: 5 vendor-bundled skill(s) skipped for connector='codex'.",
    ]
    assert command_result_summary("Scan all", empty) == "2 connectors scanned · no scannable skills"
    scanned = ["-- connector: codex --", "  Summary: 3 skills scanned, clean=3, blocked=0"]
    assert command_result_summary("Scan all", scanned) == "1 connector scanned · 3 skills scanned"


async def test_overview_s_keeps_its_task_name(tmp_path) -> None:
    # GAP-2388: the direct run said "Done: defenseclaw skill scan --all."
    app = snapshot_app(tmp_path)
    names: list[str] = []

    async def run(parsed: Any, **_kw: Any) -> None:
        names.append(parsed.display_name)

    async with app.run_test(size=(80, 24)) as pilot:
        app._run_and_report = run  # type: ignore[method-assign]  # noqa: SLF001
        app.action_switch_panel("overview")
        await pilot.pause()
        await pilot.press("s")
        await pilot.pause()
    assert names == ["Scan all"]


def test_notification_and_scope_hints_use_plain_words() -> None:
    # GAP-2386: "Toggle hitl approval.", "Toggle source: hooks.", internal scope names.
    hints = {field.label: field.hint for field in notifications_routing_wizard_fields({})}
    assert all(not hint.startswith("Toggle") for label, hint in hints.items() if label != "Notification Toggles")
    assert "approval" in hints["HITL Approval"] and "gateway" in hints["Restart Gateway After"]
    scope = next(field for field in _guardrail_wizard_fields_for({}, {}) if field.label == "Scope")
    assert "global-all-active" not in scope.hint and "selected-connector" not in scope.hint
    cfg = {"guardrail": {"connector": "codex", "connectors": {"codex": {}, "hermes": {}}}}
    goals = {goal.id: goal for goal in wizard_goals(SetupWizard.CONNECTOR_SETUP, cfg)}
    model = SetupPanelModel(cfg)
    model.open_wizard_form(SetupWizard.CONNECTOR_SETUP, goal=goals["bulk"])
    fields = {field.label: field for field in model.form_fields}
    assert fields["Connectors (CSV)"].value == "codex,hermes"
    assert not any(field.hint.startswith("Batch setup only") for field in model.form_fields)
    routing = next(g for g in wizard_goals(SetupWizard.NOTIFICATIONS_ROUTING, {}) if g.id == "verdicts")
    model = SetupPanelModel({})
    model.open_wizard_form(SetupWizard.NOTIFICATIONS_ROUTING, goal=routing)
    model.form_fields = [
        f.with_value("no" if f.value == "yes" else "yes") if f.label == "HITL Approval" else f
        for f in model.form_fields
    ]
    action = model.submit_wizard_form()
    assert action.intent is not None and action.intent.label == "setup What notifies you"


def test_remove_a_connector_starts_with_nothing_picked() -> None:
    # GAP-2387: the destructive form opened on claudecode with a "to protect" hint.
    cfg = {"guardrail": {"connector": "claudecode", "connectors": {"claudecode": {}, "codex": {}}}}
    goal = next(goal for goal in wizard_goals(SetupWizard.CONNECTOR_SETUP, cfg) if goal.id == "remove")
    model = SetupPanelModel(cfg)
    model.open_wizard_form(SetupWizard.CONNECTOR_SETUP, goal=goal)
    connector = next(field for field in model.form_fields if field.label == "Connector")
    assert connector.value == "" and "stop protecting" in connector.hint
    assert model.missing_required_fields() == ("Connector",)
    assert "claudecode" not in build_wizard_args(SetupWizard.CONNECTOR_SETUP, model.form_fields, cfg)
