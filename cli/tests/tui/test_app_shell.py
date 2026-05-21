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
from textual.widgets import Button, DataTable, Input, ProgressBar, Sparkline


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
