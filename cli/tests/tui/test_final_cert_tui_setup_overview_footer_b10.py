# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fixes: Setup readiness, Overview scope, footer receipts (b10)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from defenseclaw.models import Event
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.command_line import ParsedCommand, command_result_summary, is_listing_detail
from defenseclaw.tui.panels.alerts import AlertEvent, AlertsPanelModel
from defenseclaw.tui.panels.audit import AuditPanelModel
from defenseclaw.tui.panels.overview import OverviewConfig, OverviewPanelModel
from defenseclaw.tui.panels.setup import SetupPanelModel, SetupWizard, wizard_goals
from defenseclaw.tui.screens.command_preview import build_command_preview
from rich.text import Text


@pytest.mark.asyncio
async def test_detail_modal_scrolls_and_keeps_close_on_screen_at_80x24() -> None:
    # GAP-2177: readiness details at 80x24 ended mid-row and could not scroll.
    from defenseclaw.tui.screens.detail import DetailScreen
    from textual.app import App
    from textual.containers import VerticalScroll

    pairs = [(f"Check {i}", "WARN · a long readiness explanation that wraps onto a second line " * 2) for i in range(12)]

    class Host(App[None]):
        def on_mount(self) -> None:
            self.push_screen(DetailScreen("Setup · Protect an agent", pairs))

    app = Host()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        scroll = app.screen.query_one("#detail-scroll", VerticalScroll)
        assert scroll.max_scroll_y > 0
        assert app.screen.query_one("#detail-close").region.bottom <= 24
        await pilot.press("end")
        # The scroll is animated; a slow runner was still mid-way after one pause.
        await pilot.wait_for_scheduled_animations()
        await pilot.pause()
        assert scroll.scroll_y == scroll.max_scroll_y


def test_scoped_enforcement_alerts_match_the_alerts_scope() -> None:
    # GAP-2183: ENFORCEMENT · claudecode said "Alerts 0" next to "Critical 2".
    now = datetime.now(timezone.utc)
    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="claudecode",
        guardrail_connector="claudecode",
        connector_modes=(("claudecode", "action"), ("codex", "action")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    hooks = [
        Event(
            id=f"hook-{i}",
            timestamp=now,
            action="connector-hook",
            target="PreToolUse",
            severity="INFO",
            details="connector=claudecode action=block severity=CRITICAL",
        )
        for i in range(2)
    ]

    class HookStore:
        def list_connector_hook_event_summaries(self, limit: int = 500) -> list[Event]:
            return list(hooks[:limit])

        def count_scan_results_since(self, _since: datetime | None) -> int:
            return 0

    store = HookStore()
    alerts = AlertsPanelModel(store=store)
    alerts.set_events(
        [
            AlertEvent(
                id=f"finding-{i}",
                severity="CRITICAL",
                action="scan-finding",
                target="PreToolUse",
                timestamp=now,
                connector="claudecode",
            )
            for i in range(2)
        ]
    )
    app = DefenseClawTUI(overview_model=overview, audit_model=AuditPanelModel(store), alerts_model=alerts)
    app.connector_filter = "claudecode"

    with app._connector_hook_event_render_cache():  # noqa: SLF001
        body = Text.from_markup(app._overview_body_text(overview.service_cards())).plain  # noqa: SLF001

    assert "Alerts           2   Hook calls 2   Blocks 2" in body, body


def test_footer_summary_is_a_result_not_the_last_listing_line() -> None:
    # GAP-2184: "Done: Scan all · C:\\Users\\u\\.agents\\skills" and "· Plan digest: <hex>".
    scan = [
        "── connector: claudecode ──",
        "No skills found for connector='claudecode' in configured directories:",
        r"C:\Users\u\.claude\skills",
        "── connector: codex ──",
        "No scannable skills: 5 vendor-bundled skill(s) skipped for connector='codex'",
        "-- connector: opencode --",
        r"C:\Users\u\.agents\skills",
    ]
    # GAP-2388: it also says that none of them had a skill to scan.
    assert command_result_summary("Scan all", scan) == "3 connectors scanned · no scannable skills"
    listing = [
        "Observability destinations",
        "--------------------------",
        "NAME                     KIND         STATE     SIGNALS",
        "local-sqlite             sqlite       enabled   logs",
        "grafana                  otlp         enabled   logs,traces,metrics",
        "Retention: 7 days",
        "Plan digest: " + "ab" * 32,
    ]
    assert command_result_summary("setup Export telemetry", listing) == "2 destinations listed"
    assert is_listing_detail(r"C:\Users\u\.agents\skills") and is_listing_detail("/home/u/.claude/skills")
    assert is_listing_detail("Plan digest: " + "ab" * 32)
    assert not is_listing_detail("Saved 3 rules to policy.yaml")


def test_credentials_goals_keep_their_own_action() -> None:
    # GAP-2185: "See which credentials are set" cycled to remove, which then
    # asked for an Env Name row the form never showed.
    goals = {goal.id: goal for goal in wizard_goals(SetupWizard.CREDENTIALS, {})}
    for goal_id, action in (("list", "list"), ("check", "check"), ("fill", "fill-missing"), ("set", "set")):
        model = SetupPanelModel({})
        model.open_wizard_form(SetupWizard.CREDENTIALS, goal=goals[goal_id])
        row = next(field for field in model.form_fields if field.label == "Action")
        assert row.options == (action,) and row.value == action, (goal_id, row)


def test_read_only_setup_list_says_restart_no_and_plain_goal_words() -> None:
    # GAP-2186: "Risk read-only  Restart possible" and "canonical process-wide destinations".
    command = ParsedCommand(
        binary="defenseclaw",
        args=("setup", "observability", "list"),
        display_name="setup Export telemetry",
        category="setup",
        needs_preview=True,
    )
    preview = build_command_preview(command)
    assert (preview.risk, preview.restart) == ("read-only", "no")
    summaries = " ".join(goal.summary for goal in wizard_goals(SetupWizard.OBSERVABILITY, {}))
    assert "canonical" not in summaries and "List the telemetry destinations." in summaries
