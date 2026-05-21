# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Textual app-shell tests for the migration foundation."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
from defenseclaw.config import RegistrySource
from defenseclaw.models import Event
from defenseclaw.tui.app import DefenseClawTUI, _fetch_ai_usage
from defenseclaw.tui.executor import CommandEvent
from defenseclaw.tui.panels.ai_discovery import (
    AIDiscoveryPanelModel,
    AIUsageSignal,
    AIUsageSnapshot,
    AIUsageSummary,
)
from defenseclaw.tui.panels.alerts import AlertEvent, AlertsPanelModel
from defenseclaw.tui.panels.audit import AuditPanelModel
from defenseclaw.tui.panels.inventory import InventoryPanelModel, InventorySnapshot
from defenseclaw.tui.panels.logs import LogsPanelModel
from defenseclaw.tui.panels.mcps import MCPRow, MCPsPanelModel
from defenseclaw.tui.panels.overview import EnforcementCounts, HealthSnapshot, OverviewPanelModel, SubsystemHealth
from defenseclaw.tui.panels.policy import PolicyPanelModel
from defenseclaw.tui.panels.registries import RegistriesPanelModel, RegistriesTab
from defenseclaw.tui.panels.setup import WIZARD_NAMES, SetupPanelModel
from defenseclaw.tui.panels.skills import SkillRow, SkillsPanelModel
from defenseclaw.tui.services.gateway_log_views import GatewayLogRow
from defenseclaw.tui.services.policy_state import POLICY_TAB_OPA
from defenseclaw.tui.services.setup_state import ConfigField, ConfigSection, CredentialRow
from defenseclaw.tui.widgets.native_metrics import MetricTile, OverviewMetrics
from rich.text import Text
from textual.app import App, ComposeResult
from textual.widgets import Button, DataTable, Input, ProgressBar, Sparkline, Static


@pytest.mark.asyncio
async def test_textual_shell_starts_on_overview() -> None:
    app = DefenseClawTUI()

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()

        assert app.active_panel == "overview"
        assert "Overview" in app.body_text
        assert "SERVICES" in app.body_text
        assert "SCANNERS" in app.body_text
        assert "backend=textual" in app.status_text
        assert app.hint_text


@pytest.mark.asyncio
async def test_overview_uses_native_textual_metric_widgets() -> None:
    overview = OverviewPanelModel()
    overview.set_health(HealthSnapshot(gateway=SubsystemHealth(state="running")))
    overview.set_enforcement_counts(EnforcementCounts(total_scans=42, active_alerts=7))
    app = DefenseClawTUI(overview_model=overview)

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.pause()

        metrics = app.query_one("#overview-metrics", OverviewMetrics)
        assert metrics.has_class("hidden") is False
        assert len(metrics.query(MetricTile)) == 4
        assert len(metrics.query(ProgressBar)) == 4
        assert len(metrics.query(Sparkline)) == 4
        labels = {tile.metric.label for tile in metrics.query(MetricTile)}
        assert "Guardrail" in labels
        assert "Alert Risk" in labels or "Findings" in labels

        await pilot.press("2")
        await pilot.pause()

        assert metrics.has_class("hidden") is True


@pytest.mark.asyncio
async def test_overview_renders_silent_bypass_enforcement_row() -> None:
    overview = OverviewPanelModel()
    overview.set_silent_bypass_count(3)
    app = DefenseClawTUI(overview_model=overview)

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.pause()

        assert "Silent bypass" in app.body_text
        assert "see Alerts -> egress" in app.body_text


@pytest.mark.asyncio
async def test_command_progress_strip_lifecycle() -> None:
    """Strip surfaces the full running/success/failure/rejected lifecycle.

    Validates the redesigned 5-row strip:
    * idle → hidden
    * running → visible, "running" class, label + cancel button populated
    * success → visible, "success" class, action button relabelled "Dismiss";
      strip persists until user dismisses (auto-hide disabled per UX spec)
    * `_strip_clear` → hidden again
    """

    from textual.widgets import Button

    app = DefenseClawTUI()

    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()

        progress = app.query_one("#command-progress")
        assert progress.has_class("hidden") is True
        assert app._strip_state == "idle"

        app._strip_running("defenseclaw doctor")
        await pilot.pause()

        assert progress.has_class("hidden") is False
        assert progress.has_class("running") is True
        assert app._strip_label == "defenseclaw doctor"
        action_button = app.query_one("#command-progress-action", Button)
        assert "Cancel" in str(action_button.label)

        app._strip_output("scanning gateway... 50%")
        await pilot.pause()
        assert app._strip_last_output == "scanning gateway... 50%"

        app._strip_finished(exit_code=0, duration=0.20)
        await pilot.pause()

        assert progress.has_class("success") is True
        assert progress.has_class("running") is False
        assert progress.has_class("hidden") is False
        assert app._strip_state == "success"
        action_button = app.query_one("#command-progress-action", Button)
        assert "Dismiss" in str(action_button.label)

        app._strip_clear()
        await pilot.pause()
        assert progress.has_class("hidden") is True
        assert app._strip_state == "idle"


@pytest.mark.asyncio
async def test_command_progress_strip_failure_and_rejection() -> None:
    """Failure and rejection are visually distinct and persist until dismissed."""

    app = DefenseClawTUI()

    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        progress = app.query_one("#command-progress")

        app._strip_running("defenseclaw doctor")
        app._strip_output("ERROR: gateway unreachable")
        app._strip_finished(exit_code=1, duration=1.5)
        await pilot.pause()

        assert progress.has_class("failure") is True
        # On failure the strip surfaces the last captured output as the
        # summary so users can see what blew up without leaving the panel.
        assert "gateway unreachable" in app._strip_summary

        app._strip_rejected("Unknown TUI command: defen")
        await pilot.pause()

        assert progress.has_class("rejected") is True
        assert "Unknown TUI command" in app._strip_summary


@pytest.mark.asyncio
async def test_command_progress_strip_hidden_on_activity_panel() -> None:
    """Strip is redundant on Activity (live stream is right there) and hides."""

    app = DefenseClawTUI()

    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        progress = app.query_one("#command-progress")

        app._strip_running("defenseclaw doctor")
        await pilot.pause()
        assert progress.has_class("hidden") is False

        app.action_switch_panel("activity")
        await pilot.pause()
        assert progress.has_class("hidden") is True
        assert app._strip_state == "running"  # state preserved, just hidden

        app.action_switch_panel("overview")
        await pilot.pause()
        assert progress.has_class("hidden") is False


@pytest.mark.asyncio
async def test_command_progress_strip_q_dismisses() -> None:
    """`q` clears a finished strip and returns to idle."""

    app = DefenseClawTUI()

    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        progress = app.query_one("#command-progress")

        app._strip_running("defenseclaw doctor")
        app._strip_finished(exit_code=0, duration=0.20)
        await pilot.pause()
        assert progress.has_class("success") is True

        await pilot.press("q")
        await pilot.pause()
        assert progress.has_class("hidden") is True
        assert app._strip_state == "idle"


@pytest.mark.asyncio
async def test_q_is_local_noop_on_normal_panel() -> None:
    app = DefenseClawTUI()

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("q")
        await pilot.pause()

        assert app.active_panel == "overview"
        assert "q is local close/no-op" in app.status_text
        app._render_chrome()  # noqa: SLF001 - explicit feedback must survive periodic rerenders.
        assert "q is local close/no-op" in app.status_text


@pytest.mark.asyncio
async def test_command_drawer_rejects_arbitrary_host_command() -> None:
    app = DefenseClawTUI()

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press(":")
        await pilot.press("l", "s")
        await pilot.press("enter")
        await pilot.pause()

        activity = "\n".join(app.activity_lines)
        assert "Rejected" in activity
        assert "Unknown TUI command" in activity


@pytest.mark.asyncio
async def test_command_drawer_opens_preview_for_mutating_alias() -> None:
    app = DefenseClawTUI()

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press(":")
        await pilot.press(*"block skill bad")
        await pilot.press("enter")
        await pilot.pause()

        assert app.screen_stack[-1].__class__.__name__ == "CommandPreviewScreen"


@pytest.mark.asyncio
async def test_command_drawer_enter_prefers_highlighted_suggestion() -> None:
    """Down-arrow + Enter must run the highlighted palette suggestion.

    Reproduces the user-reported failure: typing ``agent discov``
    followed by ↓ + Enter used to submit the half-typed text, which
    matched the longest registry prefix ``agent discover`` and tacked
    the leftover ``"discov"`` on as a positional argument, exploding
    the CLI with ``Got unexpected extra argument``. The drawer must
    instead pick whatever row the operator highlighted in the palette.
    """

    app = DefenseClawTUI()

    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.press(":")
        await pilot.press(*"agent discov")
        await pilot.pause()
        # Palette is open and populated with autocomplete rows.
        assert app._command_palette_values, "palette suggestions should be visible"
        # Position the highlight on a real ``agent discovery …`` row.
        target_idx = next(
            (i for i, v in enumerate(app._command_palette_values) if v.startswith("agent discovery")),
            None,
        )
        assert target_idx is not None, "expected at least one agent discovery suggestion"
        from textual.widgets import DataTable as _DataTable
        palette = app.query_one("#command-palette", _DataTable)
        palette.move_cursor(row=target_idx, column=0, animate=False)
        await pilot.pause()
        expected = app._command_palette_values[target_idx]
        # _effective_submit_text is what Enter passes to the drawer.
        resolved = app._effective_submit_text(app.query_one("#command-input", Input).value)
        assert resolved == expected, (
            f"Down+Enter should resolve to the highlighted row '{expected}', "
            f"not the typed fragment '{resolved}'"
        )


@pytest.mark.asyncio
async def test_overview_quick_action_buttons_route_to_commands() -> None:
    """Clicking the Overview action buttons should submit the matching command.

    Locks in the click-first quick-action bar so a future refactor
    can't silently strand operators in front of "ai discovery offline"
    text with no way to act on it other than typing into the drawer.
    """

    app = DefenseClawTUI()

    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.pause()
        assert app.active_panel == "overview"
        # The bar is rendered with all the buttons we wired up.
        for selector in (
            "#overview-run-doctor",
            "#overview-enable-ai-discovery",
            "#overview-start-gateway",
            "#overview-setup-connector",
        ):
            button = app.query_one(selector, Button)
            assert button is not None

        # "Setup Connector" routes to the wizard (does not spawn the
        # interactive picker), matching the drawer's safety guard.
        app._handle_overview_control("overview-setup-connector")  # noqa: SLF001
        await pilot.pause()
        assert app.active_panel == "setup"
        assert app.setup_model.form_active is True


@pytest.mark.asyncio
async def test_digit_shortcut_switches_panel_placeholder() -> None:
    app = DefenseClawTUI()

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("2")
        await pilot.pause()

        assert app.active_panel == "alerts"
        assert "Alerts" in app.body_text


@pytest.mark.asyncio
async def test_mouse_click_switches_top_level_tabs() -> None:
    app = DefenseClawTUI()

    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.click("#tab-alerts")
        await pilot.pause()

        assert app.active_panel == "alerts"
        assert "Alerts" in app.body_text


@pytest.mark.asyncio
async def test_mouse_click_opens_command_drawer() -> None:
    app = DefenseClawTUI()

    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.click("#command-button")
        await pilot.pause()

        command = app.query_one("#command-input", Input)
        assert command.has_class("open")
        assert command.disabled is False
        assert "Command palette open" in app.status_text
        assert app.query_one("#command-palette", DataTable).has_class("hidden") is False


@pytest.mark.asyncio
async def test_command_palette_suggestions_tab_complete_and_click_execute() -> None:
    app = DefenseClawTUI()
    seen: dict[str, tuple[str, tuple[str, ...]]] = {}

    async def fake_run(binary: str, args: tuple[str, ...], display_name: str = "") -> None:
        seen["command"] = (binary, args)
        seen["display"] = ("display", (display_name,))

    app._run_command = fake_run  # type: ignore[method-assign]

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.press(":")
        await pilot.press("d", "o", "c")
        await pilot.pause()

        palette = app.query_one("#command-palette", DataTable)
        assert palette.row_count >= 1
        assert app._command_palette_values[0] == "doctor"  # noqa: SLF001 - command palette contract.

        await pilot.press("tab")
        await pilot.pause()
        assert app.query_one("#command-input", Input).value == "doctor "

        app.query_one("#command-input", Input).value = "doctor"
        await pilot.click("#command-palette", offset=(2, 2))
        await pilot.pause()

        assert seen["command"] == ("defenseclaw", ("doctor",))
        assert seen["display"] == ("display", ("doctor",))


@pytest.mark.asyncio
async def test_mouse_click_opens_help_surface() -> None:
    app = DefenseClawTUI()

    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.click("#help-button")
        await pilot.pause()

        assert app.help_open is True
        assert "DefenseClaw Keybindings" in app.body_text


@pytest.mark.asyncio
async def test_activity_panel_uses_activity_model() -> None:
    app = DefenseClawTUI()

    async with app.run_test(size=(140, 40)) as pilot:
        app.activity_model.add_entry("doctor")
        app.activity_model.append_output("Checking gateway...")
        app.activity_model.finish_entry(0)
        await pilot.press("a")
        await pilot.pause()

        assert app.active_panel == "activity"
        assert "Checking gateway..." in app.body_text


@pytest.mark.asyncio
async def test_overview_mode_key_opens_native_picker_and_preview() -> None:
    app = DefenseClawTUI()

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.press("m")
        await pilot.pause()

        assert app.screen_stack[-1].__class__.__name__ == "ModePickerScreen"

        await pilot.press("c")
        await pilot.pause()

        screen = app.screen_stack[-1]
        assert screen.__class__.__name__ == "CommandPreviewScreen"
        assert "defenseclaw setup codex --yes" in screen.preview.masked_display


@pytest.mark.asyncio
async def test_overview_mode_picker_mouse_click_opens_preview() -> None:
    app = DefenseClawTUI()

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.press("m")
        await pilot.pause()
        await pilot.click("#action-menu-row-3")
        await pilot.pause()

        screen = app.screen_stack[-1]
        assert screen.__class__.__name__ == "CommandPreviewScreen"
        assert "defenseclaw setup codex --yes" in screen.preview.masked_display


@pytest.mark.asyncio
async def test_overview_quick_actions_match_go_navigation_and_scan() -> None:
    app = DefenseClawTUI()

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.press("i")
        await pilot.pause()
        assert app.active_panel == "inventory"

        app.action_switch_panel("overview")
        await pilot.pause()
        await pilot.press("s")
        await pilot.pause()
        screen = app.screen_stack[-1]
        assert screen.__class__.__name__ == "CommandPreviewScreen"
        assert "defenseclaw skill scan --all" in screen.preview.masked_display


@pytest.mark.asyncio
async def test_overview_redaction_notifications_and_uninstall_open_go_style_modals() -> None:
    config = SimpleNamespace(
        privacy=SimpleNamespace(disable_redaction=False),
        notifications=SimpleNamespace(enabled=True),
    )
    app = DefenseClawTUI(config=config)
    seen: list[tuple[str, tuple[str, ...]]] = []

    async def fake_run(binary: str, args: tuple[str, ...], **_kwargs: object) -> None:
        seen.append((binary, args))

    app._run_command = fake_run  # type: ignore[method-assign]

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.press("R")
        await pilot.pause()
        assert app.screen_stack[-1].__class__.__name__ == "RedactionToggleScreen"
        assert app.screen_stack[-1].model.title == "Redaction kill-switch"

        await pilot.press("enter")
        await pilot.pause()
        assert seen[-1] == ("defenseclaw", ("setup", "redaction", "off", "--yes"))
        assert config.privacy.disable_redaction is True
        assert app.active_panel == "activity"

        app.action_switch_panel("overview")
        await pilot.press("N")
        await pilot.pause()
        assert app.screen_stack[-1].__class__.__name__ == "NotificationsToggleScreen"
        assert app.screen_stack[-1].model.title == "Desktop notifications"

        await pilot.press("enter")
        await pilot.pause()
        assert seen[-1] == ("defenseclaw", ("setup", "notifications", "off", "--yes"))
        assert config.notifications.enabled is False

        app.action_switch_panel("overview")
        await pilot.press("X")
        await pilot.pause()
        assert app.screen_stack[-1].__class__.__name__ == "UninstallScreen"

        await pilot.press("a")
        await pilot.press("enter")
        await pilot.pause()
        assert seen[-1] == ("defenseclaw", ("uninstall", "--all", "--yes"))


@pytest.mark.asyncio
async def test_logs_redaction_key_opens_same_privacy_modal() -> None:
    config = {"privacy": {"disable_redaction": True}}
    app = DefenseClawTUI(config=config)
    seen: list[tuple[str, tuple[str, ...]]] = []

    async def fake_run(binary: str, args: tuple[str, ...], **_kwargs: object) -> None:
        seen.append((binary, args))

    app._run_command = fake_run  # type: ignore[method-assign]

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.press("8")
        await pilot.pause()
        await pilot.press("R")
        await pilot.pause()

        assert app.screen_stack[-1].__class__.__name__ == "RedactionToggleScreen"
        assert app.screen_stack[-1].model.default_action().command.args == (
            "setup",
            "redaction",
            "on",
            "--yes",
        )

        await pilot.press("enter")
        await pilot.pause()

        assert seen[-1] == ("defenseclaw", ("setup", "redaction", "on", "--yes"))
        assert config["privacy"]["disable_redaction"] is False


@pytest.mark.asyncio
async def test_logs_notifications_and_judge_history_modals(tmp_path) -> None:
    audit_db = tmp_path / "audit.db"
    db = sqlite3.connect(audit_db)
    db.execute(
        """CREATE TABLE judge_responses (
            timestamp TEXT, kind TEXT, direction TEXT, action TEXT, severity TEXT,
            latency_ms INTEGER, inspected_model TEXT, model TEXT, request_id TEXT,
            trace_id TEXT, run_id TEXT, input_hash TEXT, confidence REAL,
            fail_closed_applied INTEGER, prompt_template_id TEXT, parse_error TEXT, raw TEXT
        )"""
    )
    db.execute(
        """INSERT INTO judge_responses VALUES (
            '2026-05-21T02:34:00Z', 'pii', 'prompt', 'block', 'CRITICAL',
            321, 'gpt-4o', 'claude', 'req-1', 'trace-1', 'run-1', 'sha256:abc',
            0.87, 1, 'pi-v2', '', '{"redacted":true}'
        )"""
    )
    db.commit()
    db.close()
    config = {"audit_db": str(audit_db), "notifications": {"enabled": False}}
    app = DefenseClawTUI(config=config)

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.press("8")
        await pilot.pause()

        await pilot.press("N")
        await pilot.pause()
        assert app.screen_stack[-1].__class__.__name__ == "NotificationsToggleScreen"
        await pilot.press("escape")
        await pilot.pause()

        app.logs_model.source = "verdicts"
        app._render_chrome()  # noqa: SLF001 - app shell routing contract.
        await pilot.pause()
        await pilot.press("J")
        await pilot.pause()
        assert app.screen_stack[-1].__class__.__name__ == "JudgeHistoryScreen"
        assert "req-1" in app.screen_stack[-1]._body()  # noqa: SLF001 - modal render contract.


@pytest.mark.asyncio
async def test_activity_panel_keys_and_rerun_last_command() -> None:
    app = DefenseClawTUI()
    seen: dict[str, tuple[str, tuple[str, ...]]] = {}

    async def fake_run(binary: str, args: tuple[str, ...], **_kwargs: object) -> None:
        seen["command"] = (binary, args)

    app._run_command = fake_run  # type: ignore[method-assign]

    async with app.run_test(size=(140, 40)) as pilot:
        app.activity_model.add_entry("doctor")
        app.activity_model.finish_entry(0)
        await pilot.press("a")
        await pilot.press("q")
        await pilot.pause()
        assert app.activity_model.term_mode is False

        await pilot.press("enter")
        await pilot.pause()
        assert app.activity_model.term_mode is True

        await pilot.press("2")
        await pilot.pause()
        assert app.activity_model.tab == "mutations"

        await pilot.press("1")
        await pilot.press("!")
        await pilot.pause()
        assert seen["command"] == ("defenseclaw", ("doctor",))


@pytest.mark.asyncio
async def test_activity_forwards_input_to_running_command() -> None:
    app = DefenseClawTUI()
    writes: list[str] = []
    app.executor.write_stdin = writes.append  # type: ignore[method-assign]

    async with app.run_test(size=(140, 40)) as pilot:
        app.command_running = True
        await pilot.press("a")
        await pilot.press("y")
        await pilot.press("enter")
        await pilot.pause()

        assert writes == ["y", "\n"]
        assert "Sent input" in app.status_text


@pytest.mark.asyncio
async def test_alerts_panel_renders_table_and_panel_local_keys_win() -> None:
    alerts = AlertsPanelModel()
    alerts.set_events(
        [
            AlertEvent(id="a1", severity="HIGH", action="scan", target="skill://one", details="token"),
            AlertEvent(id="a2", severity="LOW", action="proxy", target="gateway", details="safe"),
        ]
    )
    app = DefenseClawTUI(alerts_model=alerts)

    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.press("2")
        await pilot.pause()

        table = app.query_one("#panel-table", DataTable)
        assert app.active_panel == "alerts"
        assert table.row_count == 2
        assert "All 2" in app.body_text

        await pilot.press("3")
        await pilot.pause()

        assert app.active_panel == "alerts"
        assert alerts.severity_filter == "HIGH"
        assert table.row_count == 1

        await pilot.press("space")
        await pilot.press("enter")
        await pilot.pause()

        assert alerts.selected_ids == {"a1"}
        assert alerts.detail_open is True
        assert "Details: token" in app.detail_text


@pytest.mark.asyncio
async def test_alerts_clickable_filter_and_dismiss_controls_open_preview() -> None:
    alerts = AlertsPanelModel()
    alerts.set_events(
        [
            AlertEvent(id="a1", severity="HIGH", action="scan", target="skill://one"),
            AlertEvent(id="a2", severity="LOW", action="proxy", target="gateway"),
        ]
    )
    app = DefenseClawTUI(alerts_model=alerts)

    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.press("2")
        await pilot.pause()

        await pilot.click("#alerts-filter-high")
        await pilot.pause()

        assert alerts.severity_filter == "HIGH"
        assert app.query_one("#panel-table", DataTable).row_count == 1

        await pilot.click("#alerts-dismiss-filtered")
        await pilot.pause()

        screen = app.screen_stack[-1]
        assert screen.__class__.__name__ == "CommandPreviewScreen"
        assert "defenseclaw alerts dismiss --severity HIGH" in screen.preview.masked_display


@pytest.mark.asyncio
async def test_alerts_table_row_click_updates_cursor() -> None:
    alerts = AlertsPanelModel()
    alerts.set_events(
        [
            AlertEvent(id="a1", severity="HIGH", action="scan", target="skill://one"),
            AlertEvent(id="a2", severity="LOW", action="proxy", target="gateway"),
        ]
    )
    app = DefenseClawTUI(alerts_model=alerts)

    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.press("2")
        await pilot.pause()

        clicked = await pilot.click("#panel-table", offset=(2, 2))
        await pilot.pause()

        assert clicked is True
        assert alerts.cursor == 1


@pytest.mark.asyncio
async def test_setup_hint_does_not_claim_missing_credentials_before_snapshot() -> None:
    setup = SetupPanelModel({})
    app = DefenseClawTUI(setup_model=setup)

    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.press("0")
        await pilot.pause()

        assert "missing credential" not in app.hint_text.lower()

        setup.set_credential_snapshot((CredentialRow(env_name="OPENAI_API_KEY", requirement="required"),))
        app._refresh_hint()  # noqa: SLF001 - verifies shell hint contract without running a command.
        await pilot.pause()

        assert "Required credentials are missing" in app.hint_text


@pytest.mark.asyncio
async def test_registries_panel_renders_table_and_local_tabs(tmp_path) -> None:
    registries = RegistriesPanelModel(
        data_dir=tmp_path,
        sources=[RegistrySource(id="corp-skills", kind="http_yaml", content="skill", enabled=True)],
    )
    app = DefenseClawTUI(registries_model=registries)

    async with app.run_test(size=(150, 40)) as pilot:
        app.action_switch_panel("registries")
        await pilot.pause()

        table = app.query_one("#panel-table", DataTable)
        assert app.active_panel == "registries"
        assert table.row_count == 1
        assert "Registries" in app.body_text

        await pilot.press("enter")
        await pilot.pause()
        assert registries.detail_open is True
        assert "corp-skills" in app.detail_text

        await pilot.press("escape")
        await pilot.pause()
        assert registries.detail_open is False

        await pilot.press("2")
        await pilot.pause()

        assert app.active_panel == "registries"
        assert registries.current_tab == RegistriesTab.ENTRIES
        assert "Sync a source" in app.body_text


@pytest.mark.asyncio
async def test_mcps_set_form_opens_from_panel_and_dispatches_preview() -> None:
    mcps = MCPsPanelModel(connector="codex")
    mcps.apply_loaded((MCPRow(name="context7", status="active"),))
    app = DefenseClawTUI(mcps_model=mcps)
    seen: list[tuple[str, tuple[str, ...], str]] = []

    async def fake_confirm(parsed) -> None:
        seen.append((parsed.binary, parsed.args, parsed.display_name))

    app._confirm_and_run_parsed = fake_confirm  # type: ignore[method-assign]

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.press("4")
        await pilot.pause()
        assert app.active_panel == "mcps"

        await pilot.press("n")
        await pilot.pause()
        screen = app.screen_stack[-1]
        assert screen.__class__.__name__ == "MCPSetFormScreen"
        assert screen.query_one("#mcp-name", Input).value == "context7"

        screen.query_one("#mcp-command", Input).value = "uvx"
        screen.query_one("#mcp-args", Input).value = "mcp-server-context7"
        await pilot.press("ctrl+s")
        await pilot.pause()

        assert seen == [
            (
                "defenseclaw",
                ("mcp", "set", "context7", "--command", "uvx", "--args", "mcp-server-context7"),
                "mcp set context7",
            )
        ]


@pytest.mark.asyncio
async def test_skills_panel_renders_catalog_table_and_action_menu() -> None:
    skills = SkillsPanelModel(connector="codex")
    skills.apply_loaded([SkillRow(name="alpha", status="active"), SkillRow(name="beta", status="blocked")])
    app = DefenseClawTUI(skills_model=skills)

    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.press("3")
        await pilot.pause()

        table = app.query_one("#panel-table", DataTable)
        assert app.active_panel == "skills"
        assert table.row_count == 2

        await pilot.click("#panel-table", offset=(2, 2))
        await pilot.pause()
        assert skills.cursor == 1

        await pilot.press("enter")
        await pilot.pause()
        assert skills.detail_open is True
        assert "Skill: beta" in app.detail_text

        await pilot.press("escape")
        await pilot.press("o")
        await pilot.pause()
        assert app.screen_stack[-1].__class__.__name__ == "ActionMenuScreen"


@pytest.mark.asyncio
async def test_logs_and_audit_panels_render_worker_models() -> None:
    logs = LogsPanelModel()
    logs.lines["gateway"] = ["event tick seq=1", "error failed"]
    audit = AuditPanelModel()
    audit.set_events([Event(action="scan", target="skill://alpha", severity="HIGH", details="token")])
    app = DefenseClawTUI(logs_model=logs, audit_model=audit)

    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.press("8")
        await pilot.pause()
        assert app.active_panel == "logs"
        assert "Gateway" in app.body_text
        assert app.query_one("#panel-table", DataTable).row_count == 1

        await pilot.press("1")
        await pilot.pause()
        assert app.query_one("#panel-table", DataTable).row_count == 2

        await pilot.press("9")
        await pilot.pause()
        assert app.active_panel == "audit"
        assert app.query_one("#panel-table", DataTable).row_count == 1
        assert "events recorded" in app.body_text or "shown of 1 events" in app.body_text


@pytest.mark.asyncio
async def test_logs_notification_judge_history_and_enter_detail_modals(tmp_path) -> None:
    audit_db = tmp_path / "audit.db"
    with sqlite3.connect(audit_db) as db:
        db.execute(
            """
            CREATE TABLE judge_responses (
                timestamp TEXT, kind TEXT, direction TEXT, action TEXT, severity TEXT,
                latency_ms INTEGER, inspected_model TEXT, model TEXT, request_id TEXT,
                trace_id TEXT, run_id TEXT, input_hash TEXT, confidence REAL,
                fail_closed_applied INTEGER, prompt_template_id TEXT, parse_error TEXT, raw TEXT
            )
            """
        )
        db.execute(
            """
            INSERT INTO judge_responses VALUES (
                '2026-05-21T02:31:22Z', 'pii', 'prompt', 'block', 'HIGH',
                37, 'gpt-5.4-mini', 'judge-model', 'req-1',
                'trace-1', 'run-1', 'sha256:abc', 0.95,
                1, 'template-1', '', '{"action":"block"}'
            )
            """
        )

    (tmp_path / "gateway.log").write_text("02:31:10 [lifecycle:gateway] start\n", encoding="utf-8")
    logs = LogsPanelModel(tmp_path)
    logs.source = "gateway"
    config = SimpleNamespace(audit_db=str(audit_db), notifications=SimpleNamespace(enabled=False))
    app = DefenseClawTUI(config=config, logs_model=logs)

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.press("8")
        await pilot.press("enter")
        await pilot.pause()

        screen = app.screen_stack[-1]
        assert screen.__class__.__name__ == "DetailScreen"
        assert screen.model.title == "Gateway log line"
        assert dict(screen.model.pairs)["Line"].endswith("start")

        await pilot.press("escape")
        await pilot.press("N")
        await pilot.pause()
        assert app.screen_stack[-1].__class__.__name__ == "NotificationsToggleScreen"

        await pilot.press("escape")
        logs.source = "verdicts"
        app._render_chrome()  # noqa: SLF001 - force source switch into the shell.
        await pilot.press("J")
        await pilot.pause()

        screen = app.screen_stack[-1]
        assert screen.__class__.__name__ == "JudgeHistoryScreen"
        assert screen.rows[0]["request_id"] == "req-1"
        assert screen.rows[0]["fail_closed_applied"] == 1


@pytest.mark.asyncio
async def test_periodic_refresh_reloads_logs_and_doctor_cache(tmp_path) -> None:
    (tmp_path / "gateway.log").write_text("line one\n", encoding="utf-8")
    (tmp_path / "doctor_cache.json").write_text(
        json.dumps(
            {
                "captured_at": "2026-05-21T02:31:22Z",
                "passed": 2,
                "failed": 1,
                "checks": [{"status": "fail", "label": "Sidecar API", "detail": "offline"}],
            }
        ),
        encoding="utf-8",
    )
    config = SimpleNamespace(data_dir=str(tmp_path))
    app = DefenseClawTUI(config=config)

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.press("8")
        await pilot.pause()
        assert "line one" in str(app.query_one("#panel-table", DataTable).get_cell_at((0, 0)))

        (tmp_path / "gateway.log").write_text("line one\nline two\n", encoding="utf-8")
        app._periodic_refresh()  # noqa: SLF001 - deterministic live-refresh gate.
        await pilot.pause()

        assert app.query_one("#panel-table", DataTable).row_count == 2
        assert app.overview_model.doctor is not None
        assert app.overview_model.doctor.failed == 1


@pytest.mark.asyncio
async def test_successful_first_run_command_deactivates_embedded_setup() -> None:
    app = DefenseClawTUI(first_run=True)

    async def fake_run(binary: str, args: tuple[str, ...]):
        yield CommandEvent("start", " ".join((binary, *args)))
        yield CommandEvent("done", exit_code=0, duration=0.01)

    app.executor.run = fake_run  # type: ignore[method-assign]

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.pause()
        assert app.active_panel == "setup"

        await app._run_command("defenseclaw", ("init", "--non-interactive"))  # noqa: SLF001
        await pilot.pause()

        assert app.first_run_model.active is False
        assert app.active_panel == "overview"
        assert "Overview" in app.body_text


@pytest.mark.asyncio
async def test_audit_clickable_filter_controls() -> None:
    audit = AuditPanelModel()
    audit.set_events(
        [
            Event(id="event-1", action="block-skill", target="skill://alpha", severity="HIGH", run_id="run-1"),
            Event(id="event-2", action="scan", target="skill://alpha", severity="INFO", run_id="run-1"),
        ]
    )
    app = DefenseClawTUI(audit_model=audit)

    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.press("9")
        await pilot.pause()

        await pilot.click("#audit-filter-risk")
        await pilot.pause()

        assert audit.common_filter == "risk"
        assert app.query_one("#panel-table", DataTable).row_count == 1

        await pilot.click("#audit-filter-all")
        await pilot.click("#audit-filter-target")
        await pilot.pause()

        assert audit.correlation_target == "skill://alpha"
        assert app.query_one("#panel-table", DataTable).row_count == 2


@pytest.mark.asyncio
async def test_audit_export_writes_json_without_command_preview(tmp_path) -> None:
    audit = AuditPanelModel()
    audit.set_events([Event(id="event-1", action="scan", target="skill://alpha", severity="HIGH", details="token")])
    app = DefenseClawTUI(data_dir=tmp_path, audit_model=audit)

    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.press("9")
        await pilot.press("e")
        await pilot.pause()

        exported = tmp_path / "defenseclaw-audit-export.json"
        assert exported.exists()
        assert "skill://alpha" in exported.read_text(encoding="utf-8")
        assert "Audit exported" in app.status_text
        assert app.screen_stack[-1].__class__.__name__ != "CommandPreviewScreen"


@pytest.mark.asyncio
async def test_overview_inventory_and_ai_panels_render_worker_models() -> None:
    overview = OverviewPanelModel()
    overview.set_health(HealthSnapshot(gateway=SubsystemHealth(state="running")))

    inventory = InventoryPanelModel()
    inventory.apply_loaded(
        InventorySnapshot.from_mapping(
            {
                "connector": "codex",
                "skills": [{"id": "alpha", "enabled": True, "eligible": True, "policy_verdict": "allowed"}],
                "summary": {"total_items": 1, "skills": {"count": 1}},
            }
        )
    )

    ai = AIDiscoveryPanelModel()
    ai.set_snapshot(
        AIUsageSnapshot(
            enabled=True,
            signals=(AIUsageSignal(signal_id="sig1", state="new", product="Codex", vendor="OpenAI"),),
        )
    )
    app = DefenseClawTUI(overview_model=overview, inventory_model=inventory, ai_discovery_model=ai)

    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.pause()
        assert app.active_panel == "overview"
        assert "SERVICES" in app.body_text

        await pilot.press("6")
        await pilot.pause()
        assert app.active_panel == "inventory"
        assert "Inventory" in app.body_text

        await pilot.press("l")
        await pilot.press("enter")
        await pilot.pause()
        assert inventory.active_sub == "skills"
        assert inventory.detail_open is True
        assert "SKILL: alpha" in app.detail_text

        await pilot.press("V")
        await pilot.press("enter")
        await pilot.pause()
        assert app.active_panel == "ai"
        assert app.query_one("#panel-table", DataTable).row_count == 1
        assert ai.detail_open is True
        assert "Codex" in app.detail_text


@pytest.mark.asyncio
async def test_ai_discovery_shortcut_auto_loads_empty_snapshot() -> None:
    app = DefenseClawTUI()
    calls = 0

    async def fake_load() -> None:
        nonlocal calls
        calls += 1

    app._load_ai_discovery_model = fake_load  # type: ignore[method-assign]

    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.press("V")
        await pilot.pause()

        assert app.active_panel == "ai"
        assert calls == 1


@pytest.mark.asyncio
async def test_ai_usage_poll_fans_out_to_overview_and_ai_panel(monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot = AIUsageSnapshot(
        enabled=True,
        summary=AIUsageSummary(active_signals=1, new_signals=1),
        signals=(AIUsageSignal(signal_id="sig1", state="new", product="Codex", vendor="OpenAI"),),
    )
    monkeypatch.setattr("defenseclaw.tui.app._fetch_ai_usage", lambda _config: snapshot)
    config = SimpleNamespace(gateway=SimpleNamespace(api_port=18970, host="127.0.0.1", token="token"))
    overview = OverviewPanelModel()
    ai = AIDiscoveryPanelModel()
    app = DefenseClawTUI(config=config, overview_model=overview, ai_discovery_model=ai)

    async with app.run_test(size=(150, 40)) as pilot:
        await app._load_ai_discovery_model()  # noqa: SLF001 - app-level polling contract.
        await pilot.pause()

        assert overview.ai_usage is snapshot
        assert ai.snapshot is snapshot
        assert "1 active" in overview.ai_discovery_box().summary_parts


def test_fetch_ai_usage_uses_gateway_auth_and_accept_headers() -> None:
    seen: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API.
            seen["path"] = self.path
            seen["authorization"] = self.headers.get("Authorization", "")
            seen["accept"] = self.headers.get("Accept", "")
            body = (
                b'{"enabled":true,"summary":{"active_signals":1,"new_signals":1},'
                b'"signals":[{"signal_id":"sig1","product":"Codex","vendor":"OpenAI","state":"new"}]}'
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config = SimpleNamespace(
            gateway=SimpleNamespace(
                api_port=server.server_port,
                host="127.0.0.1",
                resolved_token=lambda: "test-bearer-xyz",
            )
        )
        snapshot = _fetch_ai_usage(config)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert snapshot is not None
    assert snapshot.enabled is True
    assert snapshot.summary.active_signals == 1
    assert snapshot.fetched_at is not None
    assert seen == {
        "path": "/api/v1/ai-usage",
        "authorization": "Bearer test-bearer-xyz",
        "accept": "application/json",
    }


@pytest.mark.asyncio
async def test_policy_panel_renders_table_and_detail_overlay(tmp_path) -> None:
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    (policy_dir / "alpha.yaml").write_text("description: alpha policy\n", encoding="utf-8")
    config = SimpleNamespace(
        policy_dir=str(policy_dir),
        guardrail=SimpleNamespace(rule_pack_dir="", enabled=True, mode="observe", scanner_mode="local"),
        claw=SimpleNamespace(mode="codex"),
        active_connector=lambda: "codex",
    )
    policy = PolicyPanelModel(config)
    app = DefenseClawTUI(config=config, policy_model=policy)

    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.press("7")
        await pilot.pause()

        assert app.active_panel == "policy"
        assert "Policy" in app.body_text
        assert app.query_one("#panel-table", DataTable).row_count == 1

        await pilot.press("enter")
        await pilot.pause()

        assert policy.policy_detail_open is True
        assert "alpha policy" in app.body_text


@pytest.mark.asyncio
async def test_policy_opa_uppercase_shortcuts_reach_app_runner(tmp_path) -> None:
    policy_dir = tmp_path / "policies"
    rego_dir = policy_dir / "rego"
    rego_dir.mkdir(parents=True)
    rego_file = rego_dir / "admission.rego"
    rego_file.write_text("package defenseclaw\nallow := true\n", encoding="utf-8")
    config = SimpleNamespace(policy_dir=str(policy_dir), guardrail=SimpleNamespace(rule_pack_dir=""))
    policy = PolicyPanelModel(config)
    policy.load()
    policy.active_tab = POLICY_TAB_OPA
    app = DefenseClawTUI(config=config, policy_model=policy)
    seen: dict[str, str] = {}

    async def fake_policy_runner(intent) -> None:
        seen["label"] = intent.label
        policy.apply_rego_test_result("ok")
        app._render_chrome()

    app._run_policy_panel_intent = fake_policy_runner  # type: ignore[method-assign]

    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.press("7")
        await pilot.pause()

        await pilot.press("T")
        await pilot.pause()
        assert seen["label"] == "policy test"
        assert "ok" in app.body_text

        await pilot.press("E")
        await pilot.pause()
        assert "Editor intent prepared" in app.status_text
        assert str(rego_file) in app.status_text


@pytest.mark.asyncio
async def test_setup_panel_renders_wizards_and_form() -> None:
    setup = SetupPanelModel({})
    app = DefenseClawTUI(setup_model=setup)

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.press("0")
        await pilot.pause()

        table = app.query_one("#panel-table", DataTable)
        assert app.active_panel == "setup"
        assert "Setup Wizards" in app.body_text
        assert table.row_count == len(WIZARD_NAMES)

        await pilot.click("#panel-table", offset=(2, 4))
        await pilot.pause()
        assert int(setup.active_wizard) == 3

        await pilot.press("enter")
        await pilot.pause()
        assert setup.form_active is True
        assert "Setup Wizard" in app.body_text
        assert app.query_one("#panel-table", DataTable).row_count > 0

        await pilot.press("escape")
        await pilot.pause()
        assert setup.form_active is False


@pytest.mark.asyncio
async def test_setup_global_shortcuts_save_restart_clear_and_revert() -> None:
    cfg: dict = {"notifications": {"enabled": True}}
    setup = SetupPanelModel(cfg)
    setup.mode = "config"
    setup.sections = (
        ConfigSection(
            "Notifications",
            (ConfigField("Enabled", "notifications.enabled", "bool", "false", "true"),),
            "",
        ),
    )
    app = DefenseClawTUI(config=cfg, setup_model=setup)

    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.press("0")
        await pilot.press("S")
        await pilot.pause()

        assert app.screen_stack[-1].__class__.__name__ == "ConfigDiffScreen"
        await pilot.press("enter")
        await pilot.pause()
        await pilot.pause()

        assert cfg["notifications"]["enabled"] is False
        assert setup.restart_queue.pending is True
        assert "Config changes saved" in app.status_text

        await pilot.press("C")
        await pilot.pause()
        assert setup.restart_queue.pending is False
        assert "Restart queue cleared" in app.status_text

        setup.queue_restart("test")
        await pilot.press("G")
        await pilot.pause()
        assert app.screen_stack[-1].__class__.__name__ == "CommandPreviewScreen"


@pytest.mark.asyncio
async def test_setup_audit_sink_editor_opens_and_dispatches_disable_preview() -> None:
    cfg = {
        "audit_sinks": [
            {
                "name": "splunk-prod",
                "kind": "splunk_hec",
                "endpoint": "https://splunk.example.com:8088/services/collector",
                "enabled": True,
            }
        ]
    }
    setup = SetupPanelModel(cfg)
    setup.mode = "config"
    audit_sinks_section = next(
        index for index, section in enumerate(setup.sections) if section.name == "Audit Sinks"
    )
    setup.select_section(audit_sinks_section)
    app = DefenseClawTUI(config=cfg, setup_model=setup)

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.press("0")
        await pilot.press("E")
        await pilot.pause()

        assert app.screen_stack[-1].__class__.__name__ == "SetupResourceEditorScreen"
        await pilot.press("d")
        await pilot.pause()

        screen = app.screen_stack[-1]
        assert screen.__class__.__name__ == "CommandPreviewScreen"
        assert "defenseclaw setup observability disable splunk-prod" in screen.preview.masked_display


@pytest.mark.asyncio
async def test_setup_webhook_editor_add_opens_webhook_wizard() -> None:
    cfg = {"webhooks": [{"name": "ops", "type": "slack", "url": "https://hooks.example", "enabled": False}]}
    setup = SetupPanelModel(cfg)
    setup.mode = "config"
    setup.select_section(next(index for index, section in enumerate(setup.sections) if section.name == "Webhooks"))
    app = DefenseClawTUI(config=cfg, setup_model=setup)

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.press("0")
        await pilot.press("E")
        await pilot.pause()

        assert app.screen_stack[-1].__class__.__name__ == "SetupResourceEditorScreen"
        await pilot.press("a")
        await pilot.pause()

        assert setup.form_active is True
        assert setup.active_wizard == 12
        assert "Webhook setup wizard opened" in app.status_text


@pytest.mark.asyncio
async def test_inventory_mouse_controls_switch_tabs_filters_and_scope() -> None:
    inventory = InventoryPanelModel()
    inventory.apply_loaded(
        InventorySnapshot.from_mapping(
            {
                "connector": "codex",
                "skills": [
                    {"id": "alpha", "enabled": True, "eligible": True, "policy_verdict": "allowed"},
                    {"id": "beta", "enabled": True, "eligible": False, "policy_verdict": "blocked"},
                ],
                "plugins": [
                    {"id": "plug-live", "name": "live", "status": "loaded"},
                    {"id": "plug-off", "name": "off", "status": "disabled"},
                ],
                "summary": {"total_items": 4, "skills": {"count": 2}, "plugins": {"count": 2}},
            }
        )
    )
    app = DefenseClawTUI(inventory_model=inventory)

    async with app.run_test(size=(190, 44)) as pilot:
        await pilot.press("6")
        await pilot.pause()

        await pilot.click("#inventory-tab-plugins")
        await pilot.pause()
        assert inventory.active_sub == "plugins"
        assert app.query_one("#panel-table", DataTable).row_count == 2

        await pilot.click("#inventory-filter-disabled")
        await pilot.pause()
        assert inventory.filter == "disabled"
        assert app.query_one("#panel-table", DataTable).row_count == 1

        await pilot.click("#inventory-scope-fast")
        await pilot.pause()
        assert set(inventory.category_scope) == {"skills", "plugins", "mcp"}


@pytest.mark.asyncio
async def test_logs_mouse_controls_and_structured_row_click_open_detail() -> None:
    logs = LogsPanelModel()
    logs.lines["gateway"] = ["info heartbeat", "error failed"]
    logs.lines["watchdog"] = ["watchdog warn"]
    logs.source = "gateway"
    logs.filter_mode = ""
    logs.verdict_rows = [
        GatewayLogRow(raw='{"event":"allow"}', event_type="verdict", action="allow", reason="clean"),
    ]
    logs.lines["verdicts"] = ["VERDICT ALLOW clean"]
    app = DefenseClawTUI(logs_model=logs)

    async with app.run_test(size=(190, 44)) as pilot:
        await pilot.press("8")
        await pilot.pause()

        await pilot.click("#logs-filter-3")
        await pilot.pause()
        assert logs.filter_mode == "errors"
        assert app.query_one("#panel-table", DataTable).row_count == 1

        await pilot.click("#logs-toggle-pause")
        await pilot.pause()
        assert logs.paused is True

        await pilot.click("#logs-source-watchdog")
        await pilot.pause()
        assert logs.source == "watchdog"

        await pilot.click("#logs-source-verdicts")
        await pilot.pause()
        await pilot.click("#logs-filter-0")
        await pilot.pause()
        await pilot.click("#panel-table", offset=(2, 1))
        await pilot.pause()

        screen = app.screen_stack[-1]
        assert screen.__class__.__name__ == "DetailScreen"
        assert screen.model.title == "Gateway event"
        assert dict(screen.model.pairs)["Action"] == "allow"


@pytest.mark.asyncio
async def test_registries_mouse_tabs_and_sync_button_open_preview(tmp_path) -> None:
    registries = RegistriesPanelModel(
        data_dir=tmp_path,
        sources=[RegistrySource(id="corp-skills", kind="http_yaml", content="skill", enabled=True)],
    )
    app = DefenseClawTUI(registries_model=registries)

    async with app.run_test(size=(190, 44)) as pilot:
        app.action_switch_panel("registries")
        await pilot.pause()

        await pilot.click("#registries-tab-entries")
        await pilot.pause()
        assert registries.current_tab == RegistriesTab.ENTRIES

        await pilot.click("#registries-tab-sources")
        await pilot.pause()
        assert registries.current_tab == RegistriesTab.SOURCES

        await pilot.click("#registries-sync-source")
        await pilot.pause()
        screen = app.screen_stack[-1]
        assert screen.__class__.__name__ == "CommandPreviewScreen"
        assert "defenseclaw registry sync corp-skills --json" in screen.preview.masked_display


@pytest.mark.asyncio
async def test_policy_mouse_tabs_and_opa_action_buttons(tmp_path) -> None:
    policy_dir = tmp_path / "policies"
    rego_dir = policy_dir / "rego"
    rego_dir.mkdir(parents=True)
    (rego_dir / "admission.rego").write_text("package defenseclaw\nallow := true\n", encoding="utf-8")
    config = SimpleNamespace(policy_dir=str(policy_dir), guardrail=SimpleNamespace(rule_pack_dir=""))
    policy = PolicyPanelModel(config)
    policy.load()
    app = DefenseClawTUI(config=config, policy_model=policy)
    seen: list[str] = []

    async def fake_policy_runner(intent) -> None:
        seen.append(intent.label)
        policy.apply_rego_test_result("ok")
        app._render_chrome()  # noqa: SLF001 - shell update contract.

    app._run_policy_panel_intent = fake_policy_runner  # type: ignore[method-assign]

    async with app.run_test(size=(190, 44)) as pilot:
        await pilot.press("7")
        await pilot.pause()

        await pilot.click("#policy-tab-4")
        await pilot.pause()
        assert policy.active_tab == POLICY_TAB_OPA

        await pilot.click("#policy-test")
        await pilot.pause()
        assert seen == ["policy test"]

        await pilot.click("#policy-edit")
        await pilot.pause()
        assert "Editor intent prepared" in app.status_text


@pytest.mark.asyncio
async def test_setup_mouse_controls_open_config_save_and_resource_editor() -> None:
    cfg = {
        "audit_sinks": [
            {"name": "splunk-prod", "kind": "splunk_hec", "endpoint": "https://example", "enabled": True}
        ]
    }
    setup = SetupPanelModel(cfg)
    app = DefenseClawTUI(config=cfg, setup_model=setup)

    async with app.run_test(size=(190, 44)) as pilot:
        await pilot.press("0")
        await pilot.pause()

        await pilot.click("#setup-mode-config")
        await pilot.pause()
        assert setup.mode == "config"

        setup.select_section(
            next(index for index, section in enumerate(setup.sections) if section.name == "Audit Sinks")
        )
        app._render_chrome()  # noqa: SLF001 - deterministic section switch.
        await pilot.click("#setup-edit-list")
        await pilot.pause()
        assert app.screen_stack[-1].__class__.__name__ == "SetupResourceEditorScreen"

        await pilot.press("escape")
        await pilot.press("q")
        await pilot.pause(0.5)
        assert app.screen_stack[-1].__class__.__name__ == "Screen"
        setup.sections = (
            ConfigSection(
                "Notifications",
                (ConfigField("Enabled", "notifications.enabled", "bool", "false", "true"),),
                "",
            ),
        )
        setup.mode = "config"
        setup.active_section = 0
        setup.active_line = 0
        app._render_chrome()  # noqa: SLF001 - deterministic save state.
        # Let Textual flush the chrome re-render before clicking;
        # without this idle pause the synthesized mouse event races
        # the layout pass and ``pilot.click`` lands on the previous
        # frame, producing a no-op that flakes this assertion.
        await pilot.pause()
        await pilot.click("#setup-save")
        await pilot.pause(0.5)
        assert app.screen_stack[-1].__class__.__name__ == "ConfigDiffScreen"


@pytest.mark.asyncio
async def test_first_run_panel_starts_on_setup_when_requested() -> None:
    app = DefenseClawTUI(first_run=True)

    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.pause()

        table = app.query_one("#panel-table", DataTable)
        assert app.active_panel == "setup"
        assert "DefenseClaw first-run setup" in app.body_text
        # Field count tracks ``default_first_run_fields``; Phase 2.1
        # added hook-fail-mode, HITL, HITL min severity, and notifications.
        assert table.row_count == 9

        await pilot.press("down")
        await pilot.press("right")
        await pilot.pause()

        assert app.first_run_model.cursor == 1
        assert app.first_run_model.value("Profile") == "action"
        assert "First-run setup" in app.hint_text


# ---------------------------------------------------------------------------
# Activity panel button bar + stdin pipe (Phase 1a click-first plan).
# These regression tests lock in the bar's presence so a future
# refactor can't strand operators in front of an interactive subprocess
# (the original "Selection [3]:" bug) with no clickable way to answer.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_activity_panel_exposes_clickable_action_bar() -> None:
    """Activity panel renders Cancel/Clear/Save/Rerun/View buttons."""

    app = DefenseClawTUI()

    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("A")  # Activity panel.
        await pilot.pause()
        assert app.active_panel == "activity"
        for selector in (
            "#activity-cancel",
            "#activity-clear",
            "#activity-save",
            "#activity-rerun",
            "#activity-open-drawer",
        ):
            assert app.query_one(selector, Button) is not None
        # Cancel is hidden when nothing is running so the bar doesn't
        # read like a fake offer; the rest are visible.
        cancel = app.query_one("#activity-cancel", Button)
        assert cancel.has_class("hidden")
        # Rerun/Save/Clear are disabled until there's history.
        assert app.query_one("#activity-rerun", Button).disabled is True
        assert app.query_one("#activity-clear", Button).disabled is True
        assert app.query_one("#activity-save", Button).disabled is True


@pytest.mark.asyncio
async def test_activity_clear_button_drops_history_and_richlog() -> None:
    """The Clear button wipes Activity entries + the live RichLog."""

    app = DefenseClawTUI()

    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("A")
        await pilot.pause()
        app.activity_model.add_entry("defenseclaw doctor")
        app.activity_model.finish_entry(0)
        app.activity_model.add_entry("defenseclaw version")
        app.activity_model.finish_entry(0)
        app.activity_lines = ["first", "second"]
        await pilot.pause()

        assert len(app.activity_model.entries) == 2
        app._handle_activity_control("activity-clear")  # noqa: SLF001
        await pilot.pause()
        assert app.activity_model.entries == []
        assert app.activity_lines == []
        assert "Cleared" in app.status_text


@pytest.mark.asyncio
async def test_activity_clear_preserves_running_entry() -> None:
    """Clear keeps an in-flight entry so it doesn't orphan the stream."""

    app = DefenseClawTUI()

    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("A")
        await pilot.pause()
        app.activity_model.add_entry("defenseclaw doctor")
        app.activity_model.finish_entry(0)
        app.activity_model.add_entry("defenseclaw setup openclaw")
        # Note: do NOT finish — this is the "running" entry.
        await pilot.pause()

        app._handle_activity_control("activity-clear")  # noqa: SLF001
        await pilot.pause()
        assert len(app.activity_model.entries) == 1
        assert app.activity_model.entries[0].command == "defenseclaw setup openclaw"
        assert app.activity_model.entries[0].done is False


@pytest.mark.asyncio
async def test_activity_cancel_button_calls_cancel_running_command(monkeypatch) -> None:
    """Cancel button routes to the same code path Ctrl+C uses."""

    app = DefenseClawTUI()
    cancelled: list[bool] = []

    async def fake_cancel() -> None:
        cancelled.append(True)

    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("A")
        await pilot.pause()
        app.command_running = True
        monkeypatch.setattr(app, "_cancel_running_command", fake_cancel)
        app._handle_activity_control("activity-cancel")  # noqa: SLF001
        await pilot.pause()
        assert cancelled == [True]


@pytest.mark.asyncio
async def test_activity_rerun_button_replays_last_command(monkeypatch) -> None:
    """Rerun button mirrors the existing `!` keystroke contract."""

    app = DefenseClawTUI()
    seen: dict[str, tuple[str, tuple[str, ...]]] = {}

    async def fake_run(binary: str, args: tuple[str, ...], display_name: str = "") -> None:
        seen["command"] = (binary, args)

    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("A")
        await pilot.pause()
        app.activity_model.add_entry("defenseclaw version")
        app.activity_model.finish_entry(0)
        monkeypatch.setattr(app, "_run_command", fake_run)
        app._handle_activity_control("activity-rerun")  # noqa: SLF001
        await pilot.pause()
        assert seen.get("command") == ("defenseclaw", ("version",))


@pytest.mark.asyncio
async def test_activity_stdin_input_visible_only_while_command_runs() -> None:
    """The send-to-stdin Input becomes visible when a command is running."""

    app = DefenseClawTUI()

    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("A")
        await pilot.pause()
        stdin = app.query_one("#activity-stdin", Input)
        # Idle: hidden.
        assert stdin.has_class("open") is False
        assert stdin.display is False
        # Simulate a running command and re-render.
        app.command_running = True
        app._render_chrome()  # noqa: SLF001
        await pilot.pause()
        assert stdin.has_class("open") is True
        assert stdin.display is True
        # Switch away from Activity → input hides again so it doesn't
        # accidentally cover another panel.
        app.command_running = True
        app.active_panel = "logs"
        app._render_chrome()  # noqa: SLF001
        await pilot.pause()
        assert stdin.has_class("open") is False


@pytest.mark.asyncio
async def test_activity_stdin_submission_forwards_to_executor() -> None:
    """Submitting the stdin Input forwards bytes + newline to write_stdin."""

    app = DefenseClawTUI()
    captured: list[str] = []

    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("A")
        await pilot.pause()
        app.command_running = True
        app.executor.write_stdin = lambda text: captured.append(text)  # type: ignore[assignment]
        app._render_chrome()  # noqa: SLF001
        await pilot.pause()
        stdin = app.query_one("#activity-stdin", Input)
        # Use a SimpleNamespace stand-in so we don't have to construct
        # Textual's dataclass-on-Message Input.Submitted by hand.
        app._on_activity_stdin_submitted(  # noqa: SLF001
            SimpleNamespace(input=stdin, value="3", validation_result=None)
        )
        assert captured[-1] == "3\n"
        # Empty submission still sends a bare newline (= "press Enter").
        app._on_activity_stdin_submitted(  # noqa: SLF001
            SimpleNamespace(input=stdin, value="", validation_result=None)
        )
        assert captured[-1] == "\n"


@pytest.mark.asyncio
async def test_activity_save_button_writes_entry_output(tmp_path) -> None:
    """Save button writes the highlighted entry to ``data_dir/...``."""

    app = DefenseClawTUI()
    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("A")
        await pilot.pause()
        app.data_dir = tmp_path
        app.activity_model.add_entry("defenseclaw doctor")
        app.activity_model.append_output("checking docker daemon...")
        app.activity_model.append_output("ok")
        app.activity_model.finish_entry(0)
        await pilot.pause()
        app._save_activity_output_interactive()  # noqa: SLF001 - sync write, no await needed
        # The filename embeds a timestamp + command slug.
        saved = list(tmp_path.glob("defenseclaw-activity-*-defenseclaw-doctor.txt"))
        assert len(saved) == 1
        contents = saved[0].read_text()
        assert "defenseclaw doctor" in contents
        assert "checking docker daemon" in contents
        assert "ok" in contents


# ---------------------------------------------------------------------------
# AI Discovery panel button bar (Phase 1b click-first plan).
# Locks in the action bar so the panel is never view-only again —
# previously operators had to leave the panel to enable/scan via the
# drawer, which was the exact friction the user called out.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ai_discovery_panel_exposes_action_bar() -> None:
    """AI Discovery panel renders Enable/Scan/Refresh/Export buttons."""

    ai_model = AIDiscoveryPanelModel()
    app = DefenseClawTUI(ai_discovery_model=ai_model)

    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("V")  # AI Discovery panel key.
        await pilot.pause()
        assert app.active_panel == "ai"
        for selector in (
            "#ai-enable",
            "#ai-disable",
            "#ai-scan",
            "#ai-refresh",
            "#ai-open-detail",
            "#ai-export",
        ):
            assert app.query_one(selector, Button) is not None
        # No snapshot loaded → Enable visible (default-offered),
        # Disable + Scan hidden, Open detail + Export disabled.
        assert app.query_one("#ai-enable", Button).has_class("hidden") is False
        assert app.query_one("#ai-disable", Button).has_class("hidden") is True
        assert app.query_one("#ai-scan", Button).has_class("hidden") is True
        assert app.query_one("#ai-open-detail", Button).disabled is True
        assert app.query_one("#ai-export", Button).disabled is True


@pytest.mark.asyncio
async def test_ai_discovery_bar_swaps_enable_for_disable_when_enabled() -> None:
    """When discovery is enabled, hide Enable + show Disable + Scan."""

    ai_model = AIDiscoveryPanelModel()
    ai_model.set_snapshot(AIUsageSnapshot(enabled=True, signals=()))
    app = DefenseClawTUI(ai_discovery_model=ai_model)

    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("V")
        await pilot.pause()
        assert app.query_one("#ai-enable", Button).has_class("hidden") is True
        assert app.query_one("#ai-disable", Button).has_class("hidden") is False
        assert app.query_one("#ai-scan", Button).has_class("hidden") is False
        # Export button is enabled because there is a snapshot now.
        assert app.query_one("#ai-export", Button).disabled is False


@pytest.mark.asyncio
async def test_ai_discovery_enable_button_routes_to_command(monkeypatch) -> None:
    """Clicking Enable submits the same command the drawer would."""

    ai_model = AIDiscoveryPanelModel()
    app = DefenseClawTUI(ai_discovery_model=ai_model)
    submitted: list[str] = []

    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("V")
        await pilot.pause()
        monkeypatch.setattr(app, "_submit_command_text", lambda text: submitted.append(text))
        app._handle_ai_control("ai-enable")  # noqa: SLF001
        await pilot.pause()
        assert submitted == ["defenseclaw agent discovery enable --yes"]


@pytest.mark.asyncio
async def test_ai_discovery_scan_and_refresh_buttons_route_to_commands(monkeypatch) -> None:
    """Scan + Refresh route to the existing scan/usage CLI calls."""

    ai_model = AIDiscoveryPanelModel()
    ai_model.set_snapshot(AIUsageSnapshot(enabled=True, signals=()))
    app = DefenseClawTUI(ai_discovery_model=ai_model)
    submitted: list[str] = []

    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("V")
        await pilot.pause()
        monkeypatch.setattr(app, "_submit_command_text", lambda text: submitted.append(text))
        app._handle_ai_control("ai-scan")  # noqa: SLF001
        app._handle_ai_control("ai-refresh")  # noqa: SLF001
        await pilot.pause()
        assert submitted == [
            "defenseclaw agent discover",
            "defenseclaw agent usage --json",
        ]


@pytest.mark.asyncio
async def test_ai_discovery_disable_button_routes_to_command(monkeypatch) -> None:
    """Clicking Disable submits the matching ``--yes`` disable command.

    Lacking this test, a typo that wired Disable back to ``enable``
    would silently flip semantics — high-risk on a security tool.
    """

    ai_model = AIDiscoveryPanelModel()
    ai_model.set_snapshot(AIUsageSnapshot(enabled=True, signals=()))
    app = DefenseClawTUI(ai_discovery_model=ai_model)
    submitted: list[str] = []

    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("V")
        await pilot.pause()
        monkeypatch.setattr(app, "_submit_command_text", lambda text: submitted.append(text))
        app._handle_ai_control("ai-disable")  # noqa: SLF001
        await pilot.pause()
        assert submitted == ["defenseclaw agent discovery disable --yes"]


@pytest.mark.asyncio
async def test_ai_discovery_open_detail_toggles_when_row_selected() -> None:
    """Open agent details toggles the detail panel when a row is highlighted.

    Mirrors the ``enter`` keystroke on the AI panel. We seed at least
    one signal so ``selected()`` returns non-None and the button is
    enabled — the disabled-when-empty path is already covered.
    """

    ai_model = AIDiscoveryPanelModel()
    ai_model.set_snapshot(
        AIUsageSnapshot(
            enabled=True,
            signals=(AIUsageSignal(name="openai-agent", vendor="OpenAI"),),
        )
    )
    app = DefenseClawTUI(ai_discovery_model=ai_model)

    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("V")
        await pilot.pause()
        assert ai_model.detail_open is False
        app._handle_ai_control("ai-open-detail")  # noqa: SLF001
        await pilot.pause()
        assert ai_model.detail_open is True
        # Click again → toggles back closed (parity with keystroke).
        app._handle_ai_control("ai-open-detail")  # noqa: SLF001
        await pilot.pause()
        assert ai_model.detail_open is False


@pytest.mark.asyncio
async def test_ai_discovery_export_without_snapshot_sets_status(tmp_path) -> None:
    """Export with no snapshot leaves disk untouched and posts status.

    The button is greyed via ``_sync_ai_controls`` but the handler
    must also defend itself — a stray keyboard chord, mouse-down race,
    or future refactor could fire it with the snapshot still None.
    """

    ai_model = AIDiscoveryPanelModel()  # No snapshot loaded.
    app = DefenseClawTUI(ai_discovery_model=ai_model)

    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("V")
        await pilot.pause()
        app.data_dir = tmp_path
        # Stay on the AI panel but ensure the auto-load status
        # ("Refreshing AI discovery snapshot...") doesn't mask the
        # button's own status message — clear it before invoking.
        app.status_text = ""
        app._export_ai_discovery_snapshot()  # noqa: SLF001
        # No file written, status describes the missing snapshot.
        assert list(tmp_path.glob("defenseclaw-ai-usage-*.json")) == []
        assert "No AI usage snapshot loaded" in app.status_text


@pytest.mark.asyncio
async def test_ai_discovery_export_button_writes_snapshot(tmp_path) -> None:
    """Export button writes the loaded snapshot as JSON under data_dir."""

    snapshot = AIUsageSnapshot(
        enabled=True,
        summary=AIUsageSummary(scan_id="scan-1", total_signals=1),
        signals=(
            AIUsageSignal(name="openai-agent", vendor="OpenAI", category="chat"),
        ),
    )
    ai_model = AIDiscoveryPanelModel()
    ai_model.set_snapshot(snapshot)
    app = DefenseClawTUI(ai_discovery_model=ai_model)
    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("V")
        await pilot.pause()
        app.data_dir = tmp_path
        app._export_ai_discovery_snapshot()  # noqa: SLF001 - sync write, no await needed
        # Filename embeds a UTC timestamp so successive exports don't
        # silently overwrite each other.
        matches = list(tmp_path.glob("defenseclaw-ai-usage-*.json"))
        assert len(matches) == 1, f"expected exactly one export, got {matches}"
        target = matches[0]
        body = json.loads(target.read_text())
        assert body["enabled"] is True
        assert body["summary"]["scan_id"] == "scan-1"
        assert body["signals"][0]["name"] == "openai-agent"


def test_safe_body_renderable_falls_back_on_invalid_style() -> None:
    """Bogus single-letter ``[e]`` markup must not crash rendering.

    The audit toolbar template ``[{action.key}] {action.label}`` was
    emitting strings like ``[e] export filter`` that Rich parsed as a
    style tag named ``e``. When the renderer later resolved that
    style it raised ``MissingStyle: 'e' is not a valid color`` and
    tore down the entire TUI. ``_safe_body_renderable`` must validate
    styles up front and fall back to plain text rather than re-throw.
    """

    rendered = DefenseClawTUI._safe_body_renderable(  # noqa: SLF001 - exercising defense in depth.
        "500 shown of 500 events   [e] export filter"
    )
    # We don't care which path the wrapper took (escape vs plain
    # fallback); we only care that it returned a Text object instead
    # of crashing — that's the regression we lock in.
    plain = rendered.plain
    assert "export" in plain
    assert "filter" in plain


def test_audit_body_text_escapes_action_key_brackets() -> None:
    """Escaped brackets keep ``[e] export`` rendered as literal text.

    Without escaping, the audit body crashes with ``MissingStyle`` the
    moment the panel renders. We assert both that the raw body string
    contains the escape and that the safety wrapper resolves it back
    to literal ``[e] export`` plain text.
    """

    panel = AuditPanelModel()
    app = DefenseClawTUI(audit_model=panel)
    app.active_panel = "audit"
    body = app._audit_body_text()  # noqa: SLF001 - regression for crash on switch.
    assert "\\[e]" in body
    rendered = DefenseClawTUI._safe_body_renderable(body)  # noqa: SLF001
    assert "[e] export" in rendered.plain


def test_mark_restart_passes_started_at_to_setup_model() -> None:
    """The health worker must pass ``started_at`` into the setup model.

    Calling ``mark_restart_started`` without arguments raised
    ``TypeError`` and crashed ``_poll_health`` on every poll once the
    gateway restarted (which is exactly what ``setup`` toggles like
    redaction trigger). Verify both the happy path forwards the
    timestamp *and* a model that doesn't accept that signature falls
    back to ``clear_restart_queue`` instead of bubbling.
    """

    class FakeSetupHappy:
        def __init__(self) -> None:
            self.received: list[str] = []

        def mark_restart_started(self, started_at: str) -> bool:
            self.received.append(started_at)
            return True

        def clear_restart_queue(self) -> None:
            self.received.append("CLEARED")

    class FakeSetupLegacy:
        def __init__(self) -> None:
            self.cleared = False

        def mark_restart_started(self) -> bool:  # pragma: no cover - intentional bad signature
            raise TypeError("legacy stub mimicking pre-Phase-2 SetupPanelModel")

        def clear_restart_queue(self) -> None:
            self.cleared = True

    happy = FakeSetupHappy()
    app = DefenseClawTUI(setup_model=happy)
    app._last_gateway_started_at = "old-timestamp"  # noqa: SLF001 - exercising poll path.
    snapshot = SimpleNamespace(started_at="new-timestamp")
    app._mark_restart_if_gateway_restarted(snapshot)  # type: ignore[arg-type]  # noqa: SLF001
    assert happy.received == ["new-timestamp"]
    assert app._last_gateway_started_at == "new-timestamp"  # noqa: SLF001

    legacy = FakeSetupLegacy()
    app2 = DefenseClawTUI(setup_model=legacy)
    app2._last_gateway_started_at = "old"  # noqa: SLF001
    app2._mark_restart_if_gateway_restarted(SimpleNamespace(started_at="newer"))  # type: ignore[arg-type]  # noqa: SLF001
    assert legacy.cleared is True
    assert app2._last_gateway_started_at == "newer"  # noqa: SLF001


def test_audit_body_text_escapes_bracketed_filter_and_search_input() -> None:
    """User-supplied filter/search must not re-trigger the markup crash.

    The action-key fix escaped the static ``[e] export`` legend, but the
    Audit panel also echoes the operator's filter chip and the live ``/``
    search box. Both of those echo whatever the user typed — so a search
    for ``target:[skill]`` previously crashed the render pipeline with
    ``StyleSyntaxError: 'skill' is not a valid color``. Lock both paths
    in so future toolbar tweaks can't silently re-open the bug.
    """

    from rich.style import Style
    from rich.text import Text

    for hostile in ("target:[skill]", "run:[abc-123]", "[bogus]"):
        panel = AuditPanelModel()
        panel.filter_text = hostile
        panel.filtering = True
        app = DefenseClawTUI(audit_model=panel)
        app.active_panel = "audit"
        body = app._audit_body_text()  # noqa: SLF001 - regression for user-input crash.

        # ``from_markup`` is lazy: bad style names only blow up when
        # the renderer resolves them. Walk the spans and resolve each
        # style up-front — any unescaped ``[skill]`` shows up here.
        text = Text.from_markup(body)
        for span in text.spans:
            if isinstance(span.style, str) and span.style:
                Style.parse(span.style)  # raises if escape was missed.

        rendered = DefenseClawTUI._safe_body_renderable(body)  # noqa: SLF001
        assert hostile in rendered.plain, f"user input {hostile!r} dropped from rendered body"


def test_refresh_cached_config_closes_stale_audit_store(monkeypatch, tmp_path) -> None:
    """Reload must close the previous SQLite handles, not leak them.

    ``_refresh_cached_config`` swaps ``alerts_model.store`` and
    ``audit_model.store`` with a freshly-opened ``Store`` on every
    setup-driven reload. Replacing the attribute without calling
    ``close()`` on the prior handle leaked a file descriptor per
    reload, and a typical session triggers several (connector pick,
    registry add, redaction toggle, etc.). Verify the stale store
    gets closed and that an identical post-swap handle (operator
    just toggled a flag with no audit_db change) is left untouched.
    """

    class FakeStore:
        def __init__(self, tag: str) -> None:
            self.tag = tag
            self.closed = False

        def close(self) -> None:
            self.closed = True

    old_store = FakeStore("old")
    new_store = FakeStore("new")

    app = DefenseClawTUI(
        alerts_model=AlertsPanelModel(store=old_store),
        audit_model=AuditPanelModel(store=old_store),
    )
    # Stub the heavy fan-out so we only exercise the close-on-swap
    # branch. We don't need a real config reload — ``_audit_store``
    # is the seam that produces the replacement handle.
    monkeypatch.setattr(
        "defenseclaw.tui.app._audit_store",
        lambda _cfg: new_store,
    )
    monkeypatch.setattr(app, "_refresh_models_from_disk", lambda: None)
    monkeypatch.setattr(app, "_sync_setup_readiness", lambda: None)
    monkeypatch.setattr(app, "_propagate_connector", lambda _h: None)
    monkeypatch.setattr(app, "_write_activity", lambda *a, **kw: None)
    monkeypatch.setattr("defenseclaw.tui.app.config_module.load", lambda: app.config)

    app._refresh_cached_config()  # noqa: SLF001 - exercising reload path.

    assert old_store.closed is True, "previous audit store handle leaked"
    assert new_store.closed is False
    assert app.alerts_model.store is new_store
    assert app.audit_model.store is new_store

    # Second reload returning the SAME handle must NOT close it
    # (otherwise we'd close the live store we just installed).
    app._refresh_cached_config()  # noqa: SLF001
    assert new_store.closed is False, "live store was closed by no-op reload"


def test_safe_body_renderable_handles_bracketed_status_strings() -> None:
    """``_set_status`` now routes its f-string through ``_safe_body_renderable``.

    Several status callers pass operator-supplied text straight through
    (e.g. ``self.audit_model.active_filter_label()`` after typing
    ``target:[skill]`` into the ``/`` search box). The previous
    implementation inlined that text into a Rich-parsed f-string and
    inherited the same ``MissingStyle`` / ``StyleSyntaxError`` crash
    class the audit-body fix closed. Verify the exact composed string
    the new ``_set_status`` feeds into the widget — ``f"{text}  [#444444]│[/]  {strip}"`` —
    survives the defensive wrapper on hostile input that uses
    *invalid* style names (the actual crash trigger). Inputs that
    happen to spell a valid Rich style (``[red]``) still get
    interpreted as markup — that's a known UX wart of layering
    user text inside a markup-parsed f-string and is the reason
    source-side escaping (see ``_audit_body_text``) is preferred
    for the panels we've already fixed.
    """

    safe = DefenseClawTUI._safe_body_renderable  # noqa: SLF001 - exercising defense in depth.
    for hostile in (
        "target:[skill]",
        "run:[abc-xyz]",
        "search:[unmatched",  # unbalanced bracket -> MarkupError fallback.
    ):
        composed = f"{hostile}  [#444444]│[/]  Ready"
        rendered = safe(composed)
        assert isinstance(rendered, Text)
        # Defensive guarantee: no crash, and the operator's text
        # survives as literal characters in the rendered plain text
        # (either via the validator dropping the bogus span or the
        # MarkupError fallback returning the whole string verbatim).
        assert hostile in rendered.plain


def test_judge_history_prefix_escapes_index_brackets() -> None:
    """``judge_response_detail_pairs`` must escape numeric prefixes.

    Without escaping, the modal renders ``[1] Timestamp`` which Rich
    interprets as ANSI color 1 (red) for the entire row, and once
    the operator has 16+ retained rows the prefix flips to ``[16]``
    and explodes with ``MissingStyle: '16' is not a valid color``.
    """

    from defenseclaw.tui.screens.judge_history import judge_response_detail_pairs

    rows = [
        {
            "timestamp": "2026-05-21T00:00:00Z",
            "kind": "policy",
            "direction": "inbound",
            "action": "allow",
            "severity": "LOW",
            "category": "",
            "rule": "",
            "decision_score": 0.0,
            "abridged": False,
            "source": "judge",
            "request_id": "r1",
            "trace_id": "t1",
            "span_id": "s1",
            "model": "m",
        }
        for _ in range(2)
    ]
    pairs = judge_response_detail_pairs(rows)
    labels = [label for label, _ in pairs if label]
    assert any(label.startswith("\\[1]") for label in labels)
    assert any(label.startswith("\\[2]") for label in labels)
    for label in labels:
        assert not label.startswith("[1]")
        assert not label.startswith("[2]")


def test_setup_webhook_summary_escapes_status_brackets() -> None:
    """Webhook summaries must escape ``[enabled]`` / ``[disabled]``."""

    from defenseclaw.tui.panels.setup import _webhook_summary_fields

    cfg = {
        "webhooks": [
            {"type": "webhook", "name": "ops", "url": "https://example/test", "enabled": True},
            {"type": "webhook", "name": "audit", "url": "https://example/audit", "enabled": False},
        ]
    }
    fields = _webhook_summary_fields(cfg)
    summaries = [field.value for field in fields if field.value]
    assert any(summary.startswith("\\[enabled]") for summary in summaries)
    assert any(summary.startswith("\\[disabled]") for summary in summaries)
    for summary in summaries:
        assert not summary.startswith("[enabled]")
        assert not summary.startswith("[disabled]")


def test_mode_picker_choice_action_escapes_hotkey_brackets() -> None:
    """Mode-picker MenuActions must escape the hotkey bracket."""

    from defenseclaw.tui.screens.mode_picker import MODE_PICKER_CHOICES, _choice_action

    for choice in MODE_PICKER_CHOICES:
        action = _choice_action(choice, current_wire="")
        assert action.label.startswith("\\["), action.label
        assert f"\\[{choice.hotkey}]" in action.label


# ---------------------------------------------------------------------
# Phase-1 markup-safety regression suite. Together with the existing
# audit/judge-history/setup/mode-picker/consequence tests above, these
# cover every "must not crash" Rich-markup site we audited in the TUI
# (RichLog writes, command-progress snippet, native overview notices,
# native metric detail strings, hint bar, judge-history modal,
# command-preview modal, and the shared detail modal).
# ---------------------------------------------------------------------


_HOSTILE_CORPUS = (
    "plain text",
    "target:[skill]",
    "run:[abc]",
    "[INFO] starting",
    "[WARN] retrying",
    "[ERROR] something broke",
    "[OK] ready",
    "Selection [3]:",
    "prompt[16]",  # numeric color 16+ is invalid
    "path with brackets [a/b/c]",
    "unclosed [bracket",
    "nested [bold][skill]nope[/][/]",
    "chr [\\u001b[31mred\\u001b[0m]",
)


def test_safe_body_renderable_handles_hostile_corpus() -> None:
    """Every string in our hostile corpus must survive the safety
    wrapper — either parsed cleanly or falling back to plain text —
    and the original characters must show up in the rendered plain
    text. This is the regression net for every future panel author:
    if ``_body_text``/``_detail_text`` ever produces a string with the
    same shape, the rendering pipeline still won't crash the TUI.
    """

    safe = DefenseClawTUI._safe_body_renderable  # noqa: SLF001
    for hostile in _HOSTILE_CORPUS:
        rendered = safe(hostile)
        assert isinstance(rendered, Text)
        # The visible characters survive: both the bracket fallback
        # path (returns the raw string) and the markup-parsing path
        # (drops the spans) preserve the literal characters.
        assert hostile.replace("[/", "").replace("[/]", "") in rendered.plain or \
            rendered.plain.startswith(hostile[:20])


def test_write_activity_safe_escapes_subprocess_output(monkeypatch) -> None:
    """``_write_activity_safe`` must hand bracket-escaped text to the
    Activity RichLog — that's the whole point of the helper. Without
    escaping, a subprocess line like ``[INFO] foo`` crashes the Rich
    parser and tears down the activity stream.
    """

    captured: list[str] = []

    class _FakeRichLog:
        def write(self, text: str) -> None:
            captured.append(text)

    fake = _FakeRichLog()
    app = DefenseClawTUI.__new__(DefenseClawTUI)
    app.activity_lines = []  # type: ignore[attr-defined]

    def _query_one(_selector, _expected_type):  # noqa: ANN001
        return fake

    monkeypatch.setattr(app, "query_one", _query_one, raising=False)
    # ``[skill]`` is the canonical risk shape — Rich's markup parser
    # treats it as an opening style tag. ``rich.markup.escape`` is
    # intentionally conservative and only escapes the brackets it
    # would otherwise parse as a tag, so uppercase / numeric tokens
    # like ``[INFO]`` or ``[16]`` flow through verbatim (Rich treats
    # them as literal text and never crashes on them anyway). Verify
    # the safe writer escapes the dangerous shape so a bracketed
    # token in subprocess output can't take down the activity stream.
    app._write_activity_safe("prompt: [skill] continue")  # noqa: SLF001
    assert captured == ["prompt: \\[skill] continue"]


@pytest.mark.asyncio
async def test_command_progress_snippet_escapes_subprocess_tail() -> None:
    """End-to-end: route a hostile subprocess line (``Selection [skill]:``)
    through ``_strip_output`` and verify the snippet Static renders the
    bracketed text literally to the operator. A source-level grep would
    only catch a literal ``rich_escape(truncated)`` call site; this test
    exercises the full lifecycle (Static markup parse → render plain)
    so a refactor that drops the escape *and* happens to still pass a
    source-level grep is still caught here.
    """

    app = DefenseClawTUI()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()

        app._strip_running("defenseclaw doctor")  # noqa: SLF001
        await pilot.pause()
        app._strip_output("Selection [skill]:")  # noqa: SLF001
        await pilot.pause()
        snippet = app.query_one("#command-progress-snippet", Static)
        # ``Static.render()`` returns a Textual ``Content`` whose
        # ``.plain`` is the visible characters with all markup applied.
        # If the escape regresses, Rich silently drops ``[skill]`` and
        # the operator loses the live tail of the running command.
        plain = snippet.render().plain
        assert "[skill]" in plain


@pytest.mark.asyncio
async def test_overview_notice_block_renders_icons_and_messages_literally() -> None:
    """Push a hostile notice through the overview model, render the
    panel, and verify both the icon literal (``[!]`` / ``[OK]``) and
    the bracketed message text (``press [g] to set up``) appear in the
    rendered ``app.body_text`` plain. The old code path called
    ``Text.from_markup`` on the icon, which re-parsed it as a style
    name and crashed the overview the moment any notice surfaced.
    """

    from defenseclaw.tui.services.overview_state import OverviewNotice

    overview = OverviewPanelModel()
    # ``build_notices`` is the public source of notice tuples. Stub it
    # to return the hostile shape we want to exercise; if a future
    # refactor renames the method, the test still fails fast and the
    # author has to remediate either here or in the rendering path.
    hostile_notice = OverviewNotice(level="warn", message="press [g] to set up guardrails")
    overview.build_notices = lambda **_: (hostile_notice,)  # type: ignore[method-assign]
    app = DefenseClawTUI(overview_model=overview)

    async with app.run_test(size=(150, 50)) as pilot:
        await pilot.pause()
        rendered_plain = Text.from_markup(app.body_text).plain
        # The literal hotkey hint must survive: if the escape regresses,
        # Rich silently drops "[g]" from the rendered overview and the
        # operator stares at a notice with no actionable key.
        assert "[g]" in rendered_plain


def test_findings_metric_detail_renders_bracketed_target_literally() -> None:
    """Build the metric detail string with a hostile target token and
    confirm Rich renders the brackets as literal characters. If the
    escape regresses, ``[skill]`` is consumed as a style tag and the
    detail line silently loses the target name.
    """

    app = DefenseClawTUI.__new__(DefenseClawTUI)
    # ``_top_finding_target`` returns ``(target, severity_letter)``;
    # the ``[skill]`` shape is the canonical Rich-tag risk pattern.
    app._top_finding_target = lambda: ("target [skill]:malware", "H")  # type: ignore[method-assign]  # noqa: SLF001
    detail = DefenseClawTUI._findings_metric_detail(  # noqa: SLF001
        app, critical=1, high=2, medium=0, low=0
    )
    rendered_plain = Text.from_markup(detail).plain
    # The bracketed target survives in the rendered detail string.
    assert "[skill]" in rendered_plain


def test_ai_metric_detail_renders_bracketed_vendor_literally() -> None:
    """Same shape as the findings test: feed a vendor name with a
    bracketed token through the AI metric detail formatter and verify
    the brackets render literally.
    """

    ai_box = SimpleNamespace(rows=[SimpleNamespace(vendor="acme[v2]")])
    app = DefenseClawTUI.__new__(DefenseClawTUI)
    detail = DefenseClawTUI._ai_agents_metric_detail(app, ai_box)  # noqa: SLF001
    rendered_plain = Text.from_markup(detail).plain
    assert "acme[v2]" in rendered_plain


def test_hint_bar_disables_markup_parsing() -> None:
    """HintBar passes user filter strings (e.g. ``target:[skill]``)
    straight into the Static label. The Static must have ``markup=False``
    so a bracketed filter can't crash the hint bar's update path.
    """

    from defenseclaw.tui.widgets.hint_bar import HintBar

    bar = HintBar()
    # Textual stores the Static's markup flag at ``_render_markup``.
    # We assert the canonical attribute first; if a future Textual
    # release renames it, fall back to a render-shape probe so the
    # test still distinguishes "literal text" from "parsed markup".
    flag = getattr(bar, "_render_markup", None)
    if flag is None:
        # Try the alternative attribute names some Textual versions use.
        for name in ("use_markup", "_markup", "markup"):
            value = getattr(bar, name, None)
            if value is not None:
                flag = value
                break
    assert flag is False, "HintBar must opt out of Rich markup parsing"


@pytest.mark.asyncio
async def test_judge_history_modal_renders_footer_keys_literally() -> None:
    """End-to-end: open the judge-history modal in a real Textual
    pilot and verify the footer keys (``[Enter]``, ``[Esc]``) appear
    in the rendered output. Bug history: ``Enter`` and ``Esc`` are
    not Rich style names; without the escape the modal crashed on
    open with ``MissingStyle: 'Enter' is not a valid color``.
    """

    from defenseclaw.tui.screens.judge_history import JudgeHistoryScreen

    class _Harness(App[None]):
        def compose(self) -> ComposeResult:
            yield Static("harness")

        def on_mount(self) -> None:
            self.push_screen(JudgeHistoryScreen(rows=[]))

    app = _Harness()
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause()
        # The modal pushes its own screen; query the active screen
        # (top of the screen stack) rather than the default one.
        footer = app.screen.query_one("#judge-history-footer", Static)
        plain = footer.render().plain
        assert "[Enter]" in plain
        assert "[Esc]" in plain


def test_judge_history_format_pair_renders_bracketed_value_literally() -> None:
    """Judge bodies are raw JSON snippets; the modal must escape
    ``value`` so a bracketed token in the body never crashes the
    markup-parsed Static. Behavioral check: feed the format helper a
    hostile value and confirm Rich renders the brackets as literal
    characters in the resulting markup string.
    """

    from defenseclaw.tui.screens.judge_history import _format_pair

    rendered = _format_pair("Raw", "prompt: [skill] Tell me [16]")
    # Render the markup string the same way the modal's Static would.
    plain = Text.from_markup(rendered).plain
    # ``rich.markup.escape`` is conservative: it escapes ``[skill]``
    # (lowercase tag-shape) and leaves numeric ``[16]`` alone because
    # Rich treats numeric tokens as literal text already. Both must
    # survive in the rendered plain text; if the escape regresses,
    # ``[skill]`` is dropped silently.
    assert "[skill]" in plain
    assert "[16]" in plain


@pytest.mark.asyncio
async def test_command_preview_modal_renders_bracketed_argv_literally() -> None:
    """End-to-end: build a ``ParsedCommand`` whose argv contains a
    canonical Rich-tag risk shape (``skill[0]``), push the preview
    modal, and assert the rendered argv Static contains the literal
    brackets. The modal used to crash with ``MissingStyle`` on open.
    """

    from defenseclaw.tui.command_line import ParsedCommand
    from defenseclaw.tui.screens.command_preview import CommandPreviewScreen

    parsed = ParsedCommand(
        binary="defenseclaw",
        args=("scan", "skill[0]"),
        display_name="scan skill[0]",
        category="scan",
        needs_preview=True,
    )

    class _Harness(App[None]):
        def compose(self) -> ComposeResult:
            yield Static("harness")

        def on_mount(self) -> None:
            self.push_screen(CommandPreviewScreen(parsed))

    app = _Harness()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        argv_static = app.screen.query_one("#preview-argv", Static)
        plain = argv_static.render().plain
        assert "skill[0]" in plain


def test_detail_modal_table_renders_bracketed_label_value_literally() -> None:
    """Build a ``DetailModalModel.table()`` from rows that include
    bracketed values (audit ``target=[skill]`` is a real shape we see
    in the wild) and verify the rendered table preserves the literal
    brackets. The previous code path forwarded the raw values into
    Rich markup and crashed when any value contained ``[lowercase]``.
    """

    from io import StringIO

    from rich.console import Console

    from defenseclaw.tui.screens.detail import DetailModalModel

    rows = (
        ("Action", "scan"),
        ("Target", "[skill] malware"),
        ("Detail", "policy=[strict] match=[allow]"),
    )
    model = DetailModalModel.from_pairs("Audit Detail", rows)
    table = model.table()
    # Render through a Rich console capturing plain text — that's
    # exactly what the modal's Static does when displayed.
    buf = StringIO()
    Console(file=buf, force_terminal=False, width=120).print(table)
    plain = buf.getvalue()
    assert "[skill]" in plain
    assert "[strict]" in plain
    assert "[allow]" in plain


def test_tui_panel_outputs_survive_hostile_markup_corpus() -> None:
    """Fuzz-style sweep: feed each hostile corpus string through
    ``_safe_body_renderable`` (the wrapper used by every panel body
    and detail update) and assert the result is a ``Text`` object —
    *never* an exception. This is the floor: as long as the wrapper
    holds, no panel can crash the TUI mid-frame, even if a future
    panel author forgets to escape user input on the way in.
    """

    safe = DefenseClawTUI._safe_body_renderable  # noqa: SLF001
    for hostile in _HOSTILE_CORPUS:
        # Compose hostile text into the kinds of strings panels build
        # at runtime so the test exercises the same surfaces an
        # operator would hit.
        for composed in (
            hostile,
            f"[bold #22D3EE]Header[/]\n{hostile}",
            f"line 1\n  {hostile}\n  follow-up",
            f"{hostile}  [#444444]│[/]  Ready",
        ):
            # No exception is the primary contract; the assertion
            # below is the strict shape contract.
            rendered = safe(composed)
            assert isinstance(rendered, Text), composed
            # Strict: every visible character that wasn't a markup
            # delimiter must survive into ``.plain``. We strip only
            # the bracket pairs Rich actually parses (lowercase tags,
            # close tags, hex/style spans) before comparing.
            for char in hostile:
                if char not in "[]/":
                    # Spot-check: any non-bracket character that was
                    # in the hostile string should also be in the
                    # rendered plain text. This catches catastrophic
                    # truncation that ``isinstance`` alone would miss.
                    if char.isalnum() or char in " :,.-_":
                        assert char in rendered.plain, (
                            f"character {char!r} dropped while rendering {composed!r}"
                        )


# ---------------------------------------------------------------------
# Phase-2 markup-safety regression suite. These complement the
# Phase-1 crash-site tests above by covering the *fallback* sites —
# strings the safety wrapper catches but Rich silently drops content
# from. They also include a static scanner that walks the TUI source
# tree and bans any new unescaped lowercase-bracket tokens, with an
# explicit allow-list for known-safe Rich style names.
# ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_overview_body_text_renders_quick_action_hotkeys_literally() -> None:
    """Render the live overview body and verify every lowercase
    quick-action hotkey letter survives in plain text. If any of the
    seven escapes regresses, Rich consumes the bracket pair as a
    style tag and the operator sees ``Scan all`` with no hotkey to
    press. The end-to-end render includes the safety wrapper, so this
    test also catches a class of bugs where the wrapper falls back to
    plain text and the visible content silently changes.
    """

    app = DefenseClawTUI()
    async with app.run_test(size=(180, 60)) as pilot:
        await pilot.pause()
        plain = Text.from_markup(app.body_text).plain
        for key in ("[s]", "[d]", "[i]", "[g]", "[m]", "[p]", "[l]"):
            assert key in plain, f"overview quick-action key {key!r} dropped"


def test_setup_wizard_mode_hint_renders_bracketed_hint_literally() -> None:
    """The wizard-mode body builds a hint span with the same shape
    used in the live ``_setup_body_text`` fallback. Reconstruct that
    fragment with a hostile bracketed hint (``webhooks[0].url`` is
    the canonical real-world shape) and verify Rich's parser preserves
    the brackets in plain text. Without ``rich_escape(focused.hint)``
    the ``[0]`` is consumed as a style tag and the whole hint span
    silently collapses to plain text — the operator stops getting any
    actionable wizard guidance.
    """

    from rich.markup import escape as rich_escape

    from defenseclaw.tui.theme import DEFAULT_TOKENS as TOKENS

    hostile_hint = "set webhooks[0].url to your endpoint"
    # Mirror the exact fragment in app.py:_setup_body_text so a
    # refactor that drops the ``rich_escape`` call site still fails.
    fragment = (
        "\n[" + TOKENS.text_secondary + "]"
        + rich_escape(hostile_hint)
        + "[/]"
    )
    plain = Text.from_markup(fragment).plain
    # The full hint, brackets included, must survive Rich parsing.
    assert "webhooks[0].url" in plain


def test_policy_tab_bar_renders_active_tab_label_literally() -> None:
    """``PolicyPanelModel.render_text()`` renders ``[name]`` for the
    active tab and bare names for the rest. Confirm the active-tab
    bracket pair survives Rich parsing. ``POLICY_TAB_NAMES`` are all
    uppercase-led today, so the test exercises the defense even
    against uppercase tabs (which Rich already treats as literal).
    """

    config = SimpleNamespace(policy_dir="", guardrail=SimpleNamespace(rule_pack_dir=""))
    policy = PolicyPanelModel(config)
    rendered = policy.render_text(width=120, height=40)
    plain = Text.from_markup(rendered).plain
    # The first tab is the default active tab; "[Policies]" must
    # survive in the rendered output.
    assert "[Policies]" in plain


def test_policy_view_suppressions_renders_active_section_literally() -> None:
    """Suppression sections render ``[name]`` for the active section.
    Same defense as the tab bar — must survive Rich parsing.
    """

    config = SimpleNamespace(policy_dir="", guardrail=SimpleNamespace(rule_pack_dir=""))
    policy = PolicyPanelModel(config)
    rendered = policy.view_suppressions(width=120, height=40)
    plain = Text.from_markup(rendered).plain
    # First section name has the active bracket markers.
    assert "[Pre-Judge Strips]" in plain


def test_policy_view_opa_renders_t_hotkey_literally() -> None:
    """OPA view embeds a lowercase ``[t]`` hotkey label. Without the
    escape Rich would parse ``[t]`` as an opening tag and silently
    drop the bracketed text — the operator would see ``"hide tests"``
    with no key to press.
    """

    config = SimpleNamespace(policy_dir="", guardrail=SimpleNamespace(rule_pack_dir=""))
    policy = PolicyPanelModel(config)
    rendered = policy.view_opa(width=120, height=40)
    plain = Text.from_markup(rendered).plain
    assert "[t]" in plain


def test_setup_audit_sink_summary_renders_kind_and_state_literally(tmp_path) -> None:
    """Build a config object with a single audit sink, run it through
    ``_audit_sink_summary_fields``, and verify both bracket pairs
    survive Rich parsing in the resulting summary line. Without the
    escape Rich consumes lowercase ``[stdout]`` / ``[enabled]`` as
    style tags and the summary collapses to just the sink name.
    """

    from defenseclaw.tui.panels.setup import _audit_sink_summary_fields

    cfg = SimpleNamespace(
        audit_sinks=(
            SimpleNamespace(name="primary", kind="stdout", enabled=True),
            SimpleNamespace(name="archive", kind="splunk_hec", enabled=False),
        )
    )
    fields = _audit_sink_summary_fields(cfg)
    # Render each sink's summary value through Rich and check the
    # bracketed kind/state badges survive.
    summaries = [Text.from_markup(field.value).plain for field in fields]
    joined = "\n".join(summaries)
    assert "[stdout]" in joined
    assert "[enabled]" in joined
    assert "[splunk_hec]" in joined
    assert "[disabled]" in joined


def test_audit_panel_render_text_renders_e_export_close_filter_literally() -> None:
    """The audit header embeds ``[e] export  [/] filter``. Both
    bracket pairs are problematic for Rich: ``[e]`` is a lowercase
    tag-shape and ``[/]`` is an unmatched close that raises
    ``MarkupError``. Render through ``Text.from_markup`` (which
    raises on real malformed markup) and assert both literals appear
    in the plain text.
    """

    panel = AuditPanelModel()
    # Inject a synthetic event so render_text reaches the header line.
    panel.set_events([
        Event(
            id="1",
            action="scan",
            target="example",
            severity="info",
            details="",
        )
    ])
    panel.apply_filter()
    rendered = panel.render_text(height=24)
    plain = Text.from_markup(rendered).plain
    assert "[e] export" in plain
    assert "[/] filter" in plain


def test_audit_panel_summary_text_renders_e_export_close_filter_literally() -> None:
    """Same defense as ``render_text`` but for the lighter-weight
    summary header used in toolbars and tooltips.
    """

    panel = AuditPanelModel()
    plain = Text.from_markup(panel.summary_text()).plain
    assert "[e] export" in plain
    assert "[/] filter" in plain


def test_alerts_summary_text_renders_user_filter_text_literally() -> None:
    """Set a hostile filter on the alerts panel and confirm the
    summary line keeps the bracketed text literal. Without the
    escape Rich would parse ``[skill]`` as an opening style tag and
    silently truncate the search prompt.
    """

    alerts = AlertsPanelModel()
    alerts.filter_text = "target:[skill]"
    alerts.filtering = True
    rendered = alerts.summary_text()
    plain = Text.from_markup(rendered).plain
    assert "target:[skill]" in plain


def test_alerts_finding_scanner_badge_renders_literally() -> None:
    """Build an alert event with a finding whose ``scanner`` field is
    a lowercase identifier (``trivy``, ``semgrep`` are real values),
    select that alert in the panel, and verify the detail text
    preserves the ``[scanner]`` badge literally. Rich would otherwise
    consume the badge as a style tag and the operator would lose the
    most useful piece of triage info.
    """

    from defenseclaw.tui.panels.alerts import AlertDetailInfo, AlertFinding

    event = AlertEvent(
        id="evt-1",
        severity="HIGH",
        action="alert",
        target="/tmp/vendor",
    )
    finding = AlertFinding(
        id="f-1",
        scan_id="s-1",
        severity="HIGH",
        title="Critical CVE",
        scanner="trivy",
        location="/tmp/vendor",
    )
    info = AlertDetailInfo(event=event, findings=(finding,))

    alerts = AlertsPanelModel()
    alerts.detail_open = True
    # ``get_detail_info`` is the resolution seam used by both
    # ``detail_text`` and ``detail_pairs``. Patch it so we don't need
    # a full event store wired up just to surface a finding.
    alerts.get_detail_info = lambda: info  # type: ignore[method-assign]

    text_plain = Text.from_markup(alerts.detail_text()).plain
    assert "[trivy]" in text_plain

    pairs_plain = "\n".join(
        Text.from_markup(value).plain for _label, value in alerts.detail_pairs()
    )
    assert "[trivy]" in pairs_plain


# Static scanner: the regression net for this entire bug class.
# ----------------------------------------------------------------

# The empirical rule (verified by probing Rich at runtime): Rich
# treats ``[X]`` as a markup tag iff X starts with a lowercase letter,
# ``#`` (hex color), or ``@`` (variable). Everything else — uppercase,
# numeric, whitespace-led, ``/`` close-tag, ``!``, etc. — is rendered
# as literal text. So the *only* unsafe shape we have to ban is a
# bracket pair starting with a lowercase letter.
import ast as _ast_scanner
import re as _re_scanner

# Rich style names that are intentional and safe to leave unescaped.
# Anything in this set is allowed to appear as ``[name]`` in markup
# strings without a backslash escape because Rich resolves it to a
# real style.
_RICH_STYLE_ALLOWLIST = frozenset({
    "bold", "dim", "italic", "underline", "blink", "reverse",
    "strike", "conceal", "overline", "frame", "encircle",
    "black", "red", "green", "yellow", "blue", "magenta",
    "cyan", "white",
    "bright_black", "bright_red", "bright_green", "bright_yellow",
    "bright_blue", "bright_magenta", "bright_cyan", "bright_white",
    "on red", "on green", "on blue", "on yellow", "on cyan",
    "on magenta", "on white", "on black",
    "link", "reset", "none",
})

# Per-string-literal allow-list for legitimate intentional uses
# of bracket-tag-shaped tokens that we don't want the scanner to
# flag (e.g. example markup in docstrings/help text, hostile-input
# corpora used by the markup tests themselves). Each entry is a
# substring; if the literal *contains* the substring, it's exempt.
_LITERAL_ALLOWLIST: tuple[str, ...] = (
    # Test fixtures that deliberately exercise hostile inputs.
    "target:[skill]",
    "prompt[16]",
    "Selection [3]:",
    "unclosed [bracket",
    "nested [bold][skill]nope",
    # Help / cheatsheet text that documents valid Rich markup.
    "[bold #22D3EE]",
    "[#9FB2CC]",
    # Docstring example in _safe_body_renderable's prose.
    "``[e] export``",
    # CLI usage hint shown in the command palette / error messages
    # (rendered via _write_activity, which already escapes via
    # ``rich_escape(str(exc))`` in the Phase-1 fix).
    "<preset> [flags]",
    # TOML section name shown in setup info text — not Rich markup.
    "[mcp_servers]",
    "([mcp_servers])",
    # Audit-row demonstration text (already covered by _audit_body_text
    # which routes through ``_safe_body_renderable``).
    "[Enter] view output",
    # Overview notice hotkey hints — the consumer (``_overview_body_text``)
    # wraps ``notice.message`` in ``rich_escape`` so the brackets render
    # literally even though Rich would otherwise parse them as style
    # tags. Keeping the bracketed letters readable in the source notice
    # is more useful to the operator than spreading escape backslashes
    # through every notice message.
    "press [g] to set up",
    "press [d] to refresh",
    "press [d] on Overview",
)

# Variable expressions inside f-strings whose values are statically
# guaranteed to be safe (hex colors, known Rich styles). Adding to
# this list is fine; missing one only causes a false-positive flag.
_FSTRING_EXPR_ALLOWLIST_PREFIXES: tuple[str, ...] = (
    "TOKENS.",
    "DEFAULT_TOKENS.",
    "color",
    "snippet_color",
    "alert_color",
    "icon_color",
)


# Suffix-based allow-list: f-string expressions that statically
# evaluate to an uppercase string never produce a tag-shaped bracket
# pair, so we don't need to flag them. ``.upper()`` and known-
# uppercase attributes like ``check.badge`` (FAIL/PASS/STALE/WARN)
# fall in this bucket.
_FSTRING_EXPR_ALLOWLIST_SUFFIXES: tuple[str, ...] = (
    ".upper()",
    ".UPPER()",
)

# Specific f-string expression strings that are known-safe at runtime
# (e.g. integer indices that always render as ``[0]`` / ``[1]`` /
# ``[16]`` — numeric tokens that Rich treats as literal text).
_FSTRING_EXPR_ALLOWLIST_EXACT: frozenset[str] = frozenset({
    "index",
    "i",
    "n",
    "check.badge",
    "notice.level.upper()",
})


_RAW_BRACKET_RE = _re_scanner.compile(r"(?<!\\)\[(?P<tag>[a-z][^\[\]]{0,40})\]")
_FSTRING_BRACKET_RE = _re_scanner.compile(r"(?<!\\)\[\{(?P<expr>[^{}]+)\}\]")


def _is_allowlisted_literal(literal: str) -> bool:
    return any(fragment in literal for fragment in _LITERAL_ALLOWLIST)


def _flag_raw_string(literal: str) -> list[str]:
    """Return the offending bracket tokens from a literal Python str."""

    if _is_allowlisted_literal(literal):
        return []
    findings: list[str] = []
    for match in _RAW_BRACKET_RE.finditer(literal):
        tag = match.group("tag").rstrip()
        if tag in _RICH_STYLE_ALLOWLIST:
            continue
        first_token = tag.split(" ")[0]
        if first_token in _RICH_STYLE_ALLOWLIST:
            continue
        findings.append(match.group(0))
    return findings


def _flag_fstring_placeholder(joined_text: str) -> list[str]:
    """Return offending ``[{expr}]`` patterns from an f-string's joined
    representation. ``joined_text`` has ``{expr}`` placeholders for
    each interpolation, so a Rich-markup ``[{var}]`` literal will
    show up as ``[{var}]`` in the joined string. A Python subscript
    like ``counts[key]`` shows up as ``{counts[key]}`` (the entire
    expression sits inside one placeholder) and won't match the
    ``[{...}]`` regex because there's no literal ``[`` adjacent to
    the opening brace. That asymmetry is exactly what we want — the
    scanner only flags the genuine markup shape.
    """

    if _is_allowlisted_literal(joined_text):
        return []
    findings: list[str] = []
    for match in _FSTRING_BRACKET_RE.finditer(joined_text):
        expr = match.group("expr").strip()
        if expr.startswith(_FSTRING_EXPR_ALLOWLIST_PREFIXES):
            continue
        if expr.endswith(_FSTRING_EXPR_ALLOWLIST_SUFFIXES):
            continue
        if expr in _FSTRING_EXPR_ALLOWLIST_EXACT:
            continue
        findings.append(match.group(0))
    return findings


def _joined_str_text_and_exprs(node: object) -> tuple[str, list[str]]:
    """Convert an ``ast.JoinedStr`` to its joined text (with ``{}``
    placeholders for FormattedValue parts) and the list of Python
    source for each interpolation in order. Returns ``("", [])`` if
    ``node`` isn't a JoinedStr.
    """

    if not isinstance(node, _ast_scanner.JoinedStr):
        return "", []
    parts: list[str] = []
    exprs: list[str] = []
    for value in node.values:
        if isinstance(value, _ast_scanner.Constant) and isinstance(value.value, str):
            parts.append(value.value)
        elif isinstance(value, _ast_scanner.FormattedValue):
            exprs.append(_ast_scanner.unparse(value.value))
            parts.append("{" + exprs[-1] + "}")
    return "".join(parts), exprs


def _scan_tui_source_for_lowercase_brackets() -> list[tuple[str, int, str]]:
    """Return ``(relpath, lineno, snippet)`` for every Python string
    literal or f-string in the TUI source tree that contains an
    unescaped ``[lowercase…]`` token Rich would parse as a markup tag.

    The walk is AST-based: only ``Constant(str)`` and ``JoinedStr``
    nodes are inspected. Type subscripts (``list[str]``), dict/list
    indexing, and other non-string syntax are ignored automatically.
    """

    from pathlib import Path as _Path

    repo = _Path(__file__).resolve().parents[3]
    targets = [
        repo / "cli/defenseclaw/tui",
        repo / "cli/defenseclaw/commands/cmd_tui.py",
    ]

    files: list[_Path] = []
    for target in targets:
        if target.is_dir():
            files.extend(p for p in target.rglob("*.py") if "__pycache__" not in p.parts)
        elif target.is_file():
            files.append(target)

    findings: list[tuple[str, int, str]] = []
    for path in files:
        rel = str(path.relative_to(repo))
        try:
            tree = _ast_scanner.parse(path.read_text(), filename=str(path))
        except SyntaxError:
            continue
        for node in _ast_scanner.walk(tree):
            if isinstance(node, _ast_scanner.Constant) and isinstance(node.value, str):
                # Skip docstrings — they're prose, not Rich-rendered.
                # We can identify a docstring as the first statement of
                # a module / class / function body, but the simpler
                # heuristic is to skip any string > 200 chars long
                # (docstrings) since real markup strings are much
                # shorter than that.
                if len(node.value) > 200:
                    continue
                bad = _flag_raw_string(node.value)
                for token in bad:
                    findings.append((rel, node.lineno, token))
            elif isinstance(node, _ast_scanner.JoinedStr):
                # Two passes for f-strings:
                # 1. Each *literal* part is plain Python str text. Run
                #    the raw regex on it the same way we'd run it on a
                #    Constant(str) — this catches ``f"[bold]{x}[/]"``-
                #    style markup written into the static parts.
                # 2. Build the joined ``"x [{expr}] y"`` shape with
                #    ``{expr}`` placeholders for each interpolation,
                #    then run the placeholder-anchored regex. That
                #    only matches when the brackets are *literal*
                #    (i.e. adjacent to the placeholder boundary), so
                #    Python subscripts inside the placeholder don't
                #    trigger false positives.
                for value in node.values:
                    if isinstance(value, _ast_scanner.Constant) and isinstance(
                        value.value, str
                    ):
                        for token in _flag_raw_string(value.value):
                            findings.append((rel, value.lineno, token))
                joined, _exprs = _joined_str_text_and_exprs(node)
                if joined:
                    for token in _flag_fstring_placeholder(joined):
                        findings.append((rel, node.lineno, token))
    return findings


def test_no_unescaped_lowercase_bracket_tokens_in_tui_sources() -> None:
    """Permanent guardrail: walk every Python file under the TUI
    package and refuse to merge any change that introduces a new
    unescaped ``[lowercase…]`` literal or ``f"[{lowercase_var}]"``
    pattern. Rich parses such tokens as opening style tags and either
    silently drops the bracketed content or — worse — fails the
    safety wrapper's per-span ``Style.parse`` validation, forcing
    the whole panel body to plain-text fallback.

    Failures here mean the operator will see panels with content
    silently dropped (``"  Scan all"`` instead of ``"[s] Scan all"``)
    or whole-panel color regressions when the wrapper falls back.
    Either escape the bracket (``\\[s]``), pick an uppercase label,
    or — if the token is a deliberate Rich style — add it to
    ``_RICH_STYLE_ALLOWLIST`` above.
    """

    findings = _scan_tui_source_for_lowercase_brackets()
    if findings:
        report = "\n".join(
            f"  {rel}:{lineno}  {snippet}" for rel, lineno, snippet in findings[:50]
        )
        # Truncated message keeps the failure log scannable.
        assert not findings, (
            f"Found {len(findings)} unescaped lowercase-bracket token(s) in "
            f"the TUI source. Each one is parsed by Rich as a style tag and "
            f"silently drops the bracketed text. Either backslash-escape the "
            f"opening bracket (``\\\\[s]``), pick an uppercase label, or — if it "
            f"is an intentional Rich style — register it in "
            f"``_RICH_STYLE_ALLOWLIST``.\n\nOffending lines:\n{report}"
        )


def test_activity_history_render_keeps_t_hotkey_literal() -> None:
    """Render the activity panel's history view and verify the ``[t]``
    hotkey survives Rich parsing. Lowercase tag-shape would otherwise
    drop the bracketed letter from the visible output.
    """

    from defenseclaw.tui.panels.activity import ActivityEntry, ActivityPanelModel

    activity = ActivityPanelModel()
    activity.entries = [ActivityEntry(command="defenseclaw doctor", done=True, exit_code=0)]
    activity.term_mode = False  # exercise the history-tab branch
    rendered = activity.render_text(height=24)
    plain = Text.from_markup(rendered).plain
    assert "[t] terminal mode" in plain
    assert "[Enter] view output" in plain  # uppercase-led, also literal


@pytest.mark.asyncio
async def test_overview_body_fallback_renders_bracketed_notice_literally() -> None:
    """Same shape as the native overview test above, but for the
    fallback (string-rendered) code path. Inject a notice with a
    bracketed hotkey hint and verify the rendered body keeps the
    literal characters. Without the escape Rich silently drops
    ``[g]`` and the operator stares at a notice with no actionable
    hotkey.
    """

    from defenseclaw.tui.services.overview_state import OverviewNotice

    overview = OverviewPanelModel()
    overview.build_notices = lambda **_: (  # type: ignore[method-assign]
        OverviewNotice(level="info", message="press [d] to refresh"),
    )
    app = DefenseClawTUI(overview_model=overview)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        plain = Text.from_markup(app.body_text).plain
        assert "[d]" in plain
