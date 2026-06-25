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
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
from defenseclaw.config import RegistrySource
from defenseclaw.db import Store
from defenseclaw.models import Counts, Event
from defenseclaw.tui.app import (
    _DEFENSECLAW_LOGO,
    DefenseClawTUI,
    _catalog_panel_invalidated_by_command,
    _enforcement_label,
    _event_histogram,
    _fetch_ai_usage,
    _overview_config,
    _policy_posture,
)
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
from defenseclaw.tui.panels.logs import FILTER_HOOKS, LogsPanelModel
from defenseclaw.tui.panels.mcps import MCPRow, MCPsPanelModel
from defenseclaw.tui.panels.overview import (
    ConnectorHealth,
    EnforcementCounts,
    HealthSnapshot,
    OverviewConfig,
    OverviewPanelModel,
    SubsystemHealth,
)
from defenseclaw.tui.panels.registries import RegistriesPanelModel, RegistriesTab
from defenseclaw.tui.panels.setup import WIZARD_NAMES, SetupPanelModel
from defenseclaw.tui.panels.skills import SkillRow, SkillsPanelModel
from defenseclaw.tui.panels.tools import ToolsPanelModel
from defenseclaw.tui.services.gateway_log_views import GatewayLogRow
from defenseclaw.tui.services.setup_state import ConfigField, ConfigSection, CredentialRow
from defenseclaw.tui.services.tui_state import STATE_FILENAME
from defenseclaw.tui.widgets.action_menu import ActionMenu
from defenseclaw.tui.widgets.native_metrics import MetricTile, OverviewMetrics
from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import Button, DataTable, Input, ProgressBar, Sparkline, Static, Tab, Tabs


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
async def test_overview_scroll_keys_move_body_scroll_container() -> None:
    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(
            ("antigravity", "action"),
            ("claudecode", "observe"),
            ("codex", "observe"),
            ("hermes", "action"),
            ("opencode", "action"),
        ),
    )
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(HealthSnapshot(gateway=SubsystemHealth(state="running")))
    app = DefenseClawTUI(overview_model=overview)

    async with app.run_test(size=(120, 18)) as pilot:
        await pilot.pause()
        scroller = app.query_one("#body-scroll", VerticalScroll)
        assert scroller.max_scroll_y > 0

        await pilot.press("j")
        await pilot.pause()
        assert scroller.scroll_y >= 5

        await pilot.press("end")
        await pilot.pause()
        assert scroller.scroll_y == scroller.max_scroll_y

        assert app._last_body_signature is not None
        render_calls = 0
        original_renderable = app._overview_renderable

        def counted_renderable():
            nonlocal render_calls
            render_calls += 1
            return original_renderable()

        app._overview_renderable = counted_renderable  # type: ignore[method-assign]
        app._mark_overview_scroll_activity()
        app._render_chrome()
        assert render_calls == 0

        refresh_calls = 0

        def counted_refresh() -> None:
            nonlocal refresh_calls
            refresh_calls += 1

        metric_refresh_calls = 0

        def counted_metric_refresh() -> None:
            nonlocal metric_refresh_calls
            metric_refresh_calls += 1

        app._refresh_models_from_disk = counted_refresh  # type: ignore[method-assign]
        app._render_overview_metrics = counted_metric_refresh  # type: ignore[method-assign]
        app._overview_last_scroll_activity_at = 0.0
        app._periodic_refresh()
        assert refresh_calls == 0
        assert metric_refresh_calls == 1

        scroller.scroll_to(y=0, animate=False, immediate=True)
        app._periodic_refresh()
        assert refresh_calls == 0
        assert metric_refresh_calls == 2

        sampled_render_calls = 0

        def counted_sampled_render() -> None:
            nonlocal sampled_render_calls
            sampled_render_calls += 1

        sampled_timer_calls = 0

        def immediate_sampled_timer(_delay: float, callback, **_kwargs: object) -> object:
            nonlocal sampled_timer_calls
            sampled_timer_calls += 1
            callback()
            return object()

        app._render_chrome = counted_sampled_render  # type: ignore[method-assign]
        app.set_timer = immediate_sampled_timer  # type: ignore[method-assign]
        # Keep the mount-time interval from racing this direct sampler assertion on slow CI.
        app._periodic_refresh_running = True  # noqa: SLF001
        app._overview_sampled_refresh_scheduled = False  # noqa: SLF001 - isolate direct sampler assertions.

        scroller.scroll_to(y=scroller.max_scroll_y, animate=False, immediate=True)
        await pilot.pause()
        app._schedule_overview_sampled_refresh()
        await pilot.pause()
        assert sampled_timer_calls == 0
        assert sampled_render_calls == 0

        scroller.scroll_to(y=0, animate=False, immediate=True)
        await pilot.pause()
        app._overview_sampled_refresh_scheduled = False  # noqa: SLF001 - previous blocked call did not render.
        app._overview_last_scroll_activity_at = 0.0
        app._schedule_overview_sampled_refresh()
        await pilot.pause()
        assert sampled_timer_calls == 1
        assert sampled_render_calls == 1


def test_overview_body_signature_ignores_clock_only_labels() -> None:
    app = DefenseClawTUI()

    app.body_text = "DefenseClaw v0.0.0 uptime=12s\nCodex 0s ago\nDoctor 1m ago\nCalls 6"
    first = app._overview_body_signature()

    app.body_text = "DefenseClaw v0.0.0 uptime=13s\nCodex 1s ago\nDoctor 2m ago\nCalls 6"
    assert app._overview_body_signature() == first

    app.body_text = "DefenseClaw v0.0.0 uptime=13s\nCodex 1s ago\nDoctor 2m ago\nCalls 7"
    assert app._overview_body_signature() != first


@pytest.mark.asyncio
async def test_textual_shell_ignores_persisted_last_panel_on_startup(tmp_path) -> None:
    (tmp_path / STATE_FILENAME).write_text(
        json.dumps({"active_panel": "logs", "theme": ""}),
        encoding="utf-8",
    )
    app = DefenseClawTUI(data_dir=tmp_path)

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()

        assert app.state.active_panel == "logs"
        assert app.active_panel == "overview"
        assert app.query_one("#tabs").active == "tab-overview"
        assert "Overview" in app.body_text


@pytest.mark.asyncio
async def test_stale_tab_activation_does_not_bounce_back_after_rapid_clicks() -> None:
    app = DefenseClawTUI()

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        tabs = app.query_one("#tabs")

        # Simulate rapid mouse clicks where Textual's tab strip has already
        # moved to Logs, but the older Alerts activation is delivered first.
        tabs.active = "tab-logs"
        app._on_tab_activated(SimpleNamespace(tab=SimpleNamespace(id="tab-alerts")))  # noqa: SLF001
        app._on_tab_activated(SimpleNamespace(tab=SimpleNamespace(id="tab-logs")))  # noqa: SLF001
        await pilot.pause()

        assert app.active_panel == "logs"
        assert tabs.active == "tab-logs"


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
async def test_tool_policy_tab_is_removed() -> None:
    app = DefenseClawTUI()

    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()

        tabs = app.query_one("#tabs", Tabs)
        assert tabs.get_tab("tab-tools") is None
        assert all("Tool Policy" not in str(tab.label) for tab in tabs.query(Tab))

        await pilot.press("T")
        await pilot.pause()

        assert app.active_panel == "overview"

        app.action_switch_panel("tools")
        await pilot.pause()

        assert app.active_panel == "overview"


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

    async def fake_run(binary: str, args: tuple[str, ...], display_name: str = "", **_kwargs: object) -> None:
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
async def test_overview_mode_key_opens_native_picker_and_preview(monkeypatch: pytest.MonkeyPatch) -> None:
    # The untrusted-binary routing scans the live host; force "trusted" so the
    # picker path under test stays hermetic regardless of local installs.
    monkeypatch.setattr("defenseclaw.tui.app.untrusted_connector_dir", lambda *_a, **_k: None)
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
async def test_overview_mode_picker_mouse_click_opens_preview(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("defenseclaw.tui.app.untrusted_connector_dir", lambda *_a, **_k: None)
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
async def test_overview_mode_picker_routes_untrusted_binary_to_trusted_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Inverse of the hermetic stubs above: when the connector binary IS in an
    # untrusted directory, setup must route into the Trusted Paths editor
    # instead of dispatching a setup the trust gate would refuse.
    monkeypatch.setattr(
        "defenseclaw.tui.app.untrusted_connector_dir", lambda *_a, **_k: "/opt/untrusted/bin"
    )
    app = DefenseClawTUI()

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.press("m")
        await pilot.pause()
        await pilot.press("c")
        await pilot.pause()

        screen = app.screen_stack[-1]
        assert screen.__class__.__name__ == "TrustedPathsEditorScreen"
        assert "/opt/untrusted/bin" in screen._context_text


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

        await pilot.press("enter")  # redaction-off is a danger action -> arms only
        await pilot.pause()
        assert not seen  # not run yet; the gate requires a second confirm
        await pilot.press("enter")  # confirms
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

        await pilot.press("a")  # select the wipe row (danger)
        await pilot.press("enter")  # arms only
        await pilot.press("enter")  # confirms
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
    alerts.show_all_severities = True
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
async def test_long_alert_detail_scrolls_instead_of_clipping() -> None:
    """A rich alert detail must be fully reachable, not clipped.

    Regression: the detail pane was a bare ``Static`` capped at
    ``max-height``. Textual statics are not scrollable, so any alert
    whose detail exceeded the cap (gateway finding block + ids +
    history) silently lost its tail. The pane is now a
    ``VerticalScroll`` so the overflow scrolls into view.
    """

    alerts = AlertsPanelModel()
    long_details = " ".join(f"field{i}=value-{i}" for i in range(40))
    alerts.set_events(
        [
            AlertEvent(
                id="a1",
                severity="CRITICAL",
                action="scan",
                target="cursor:preToolUse",
                details=long_details,
                run_id="run-" + "x" * 60,
                trace_id="trace-" + "y" * 60,
                request_id="req-" + "z" * 60,
                session_id="sess-" + "w" * 60,
            )
        ]
    )
    app = DefenseClawTUI(alerts_model=alerts)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("2")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()

        panel = app.query_one("#detail-panel", VerticalScroll)
        assert not panel.has_class("hidden")
        # The full detail is rendered (last field + trailing id rows),
        # not truncated at the height cap.
        assert "field39=value-39" in app.detail_text
        assert "SessionID:" in app.detail_text
        # Overflow is scrollable, and the bottom is actually reachable.
        assert panel.max_scroll_y > 0
        panel.scroll_end(animate=False)
        await pilot.pause()
        assert panel.scroll_offset.y > 0


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
    alerts.show_all_severities = True
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
        # ``_format_skill_detail`` renders the header as
        # ``[bold]Skill[/] beta`` (no colon) — the assertion mirrors
        # the live formatting so the detail pane copy stays
        # self-documenting.
        assert "Skill[/] beta" in app.detail_text

        await pilot.press("escape")
        await pilot.press("o")
        await pilot.pause()
        assert app.screen_stack[-1].__class__.__name__ == "ActionMenuScreen"


@pytest.mark.asyncio
async def test_catalog_control_action_uses_visible_table_cursor() -> None:
    skills = SkillsPanelModel(connector="codex")
    skills.apply_loaded(
        [
            SkillRow(name="alpha", status="active"),
            SkillRow(name="beta", status="active"),
        ]
    )
    app = DefenseClawTUI(skills_model=skills)
    captured: list[tuple[str, object]] = []

    def fake_apply_catalog_action(panel: str, action: object) -> bool:
        captured.append((panel, action))
        return True

    app._apply_catalog_action = fake_apply_catalog_action  # type: ignore[method-assign]

    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.press("3")
        await pilot.pause()

        table = app.query_one("#panel-table", DataTable)
        table.move_cursor(row=1, column=0, animate=False)
        skills.set_cursor(0)

        app._handle_catalog_control("skills", "skills-block")  # noqa: SLF001

    assert skills.cursor == 1
    assert captured
    panel, action = captured[0]
    assert panel == "skills"
    assert action.intent.args == ("skill", "block", "beta")


@pytest.mark.asyncio
async def test_successful_skill_policy_mutation_reloads_loaded_skills_panel() -> None:
    skills = SkillsPanelModel(connector="hermes")
    skills.apply_loaded(
        [
            SkillRow(
                name="clean-skill",
                status="blocked",
                actions="blocked",
                install_action="block",
            )
        ]
    )
    skills.detail_open = True
    app = DefenseClawTUI(skills_model=skills)
    app.active_panel = "skills"
    reloaded: list[str] = []

    async def fake_load_catalog(panel: str) -> None:
        reloaded.append(panel)
        skills.apply_loaded(
            [
                SkillRow(
                    name="clean-skill",
                    status="allowed",
                    actions="allowed",
                    install_action="allow",
                )
            ]
        )

    app._load_catalog_model = fake_load_catalog  # type: ignore[method-assign]

    await app._handle_successful_command("defenseclaw", ("skill", "allow", "clean-skill"))  # noqa: SLF001

    assert reloaded == ["skills"]
    assert skills.selected() is not None
    assert skills.selected().status == "allowed"
    assert skills.selected().actions == "allowed"
    assert "allowed" in app._detail_text()  # noqa: SLF001


@pytest.mark.asyncio
async def test_successful_tool_policy_mutation_refreshes_and_rerenders_loaded_tools_panel() -> None:
    class Store:
        def __init__(self) -> None:
            self.entries = [
                SimpleNamespace(
                    target_name="@codex/write_file",
                    actions=SimpleNamespace(install="block"),
                    reason="manual block",
                    updated_at=None,
                )
            ]

        def list_actions_by_type(self, target_type: str) -> list[SimpleNamespace]:
            assert target_type == "tool"
            return self.entries

    store = Store()
    tools = ToolsPanelModel(store)
    tools.show_connector_column = True
    tools.set_connector_filter("codex")
    tools.refresh()
    app = DefenseClawTUI(tools_model=tools)
    app.active_panel = "tools"
    rendered: list[bool] = []

    def fake_render_chrome() -> None:
        rendered.append(True)

    app._render_chrome = fake_render_chrome  # type: ignore[method-assign]
    store.entries = [
        SimpleNamespace(
            target_name="@codex/write_file",
            actions=SimpleNamespace(install="allow"),
            reason="manual allow",
            updated_at=None,
        )
    ]

    await app._handle_successful_command("defenseclaw", ("tool", "allow", "write_file"))  # noqa: SLF001

    assert rendered == [True]
    assert tools.selected() is not None
    assert tools.selected().connector == "codex"
    assert tools.selected().status == "allowed"
    assert tools.selected().dispatch_target == "write_file"


def test_catalog_mutation_command_classifier_ignores_read_only_commands() -> None:
    assert _catalog_panel_invalidated_by_command(("skill", "allow", "clean-skill")) == "skills"
    assert _catalog_panel_invalidated_by_command(("skill", "list", "--json")) is None
    assert _catalog_panel_invalidated_by_command(("mcp", "set", "filesystem")) == "mcps"
    assert _catalog_panel_invalidated_by_command(("plugin", "info", "x")) is None
    assert _catalog_panel_invalidated_by_command(("tool", "block", "write_file")) == "tools"


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

    async def fake_run(binary: str, args: tuple[str, ...], **_kwargs: object):
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
        # F-0781: audit exports can carry sensitive identifiers, so the file
        # must be owner-only rather than world-readable under the umask.
        assert (exported.stat().st_mode & 0o777) == 0o600
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


def test_scheduled_background_polls_are_single_flight(tmp_path) -> None:
    config = SimpleNamespace(
        data_dir=str(tmp_path),
        gateway=SimpleNamespace(api_port=18970, host="127.0.0.1", token="token"),
    )
    app = DefenseClawTUI(config=config)
    scheduled: list[object] = []

    def fake_run_worker(coro: object, **_kwargs: object) -> None:
        scheduled.append(coro)

    def close_last_scheduled() -> None:
        close = getattr(scheduled.pop(), "close", None)
        if callable(close):
            close()

    app.run_worker = fake_run_worker  # type: ignore[method-assign]

    app._schedule_health_poll()  # noqa: SLF001
    app._schedule_health_poll()  # noqa: SLF001
    assert len(scheduled) == 1
    assert app._health_poll_running is True  # noqa: SLF001
    close_last_scheduled()
    app._health_poll_running = False  # noqa: SLF001

    app._schedule_ai_usage_poll()  # noqa: SLF001
    app._schedule_ai_usage_poll()  # noqa: SLF001
    assert len(scheduled) == 1
    assert app._ai_usage_poll_running is True  # noqa: SLF001
    close_last_scheduled()
    app._ai_usage_poll_running = False  # noqa: SLF001

    app._schedule_credentials_refresh()  # noqa: SLF001
    app._schedule_credentials_refresh()  # noqa: SLF001
    assert len(scheduled) == 1
    assert app._credentials_refresh_running is True  # noqa: SLF001
    close_last_scheduled()


@pytest.mark.asyncio
async def test_background_poll_wrappers_clear_single_flight_flags(tmp_path) -> None:
    config = SimpleNamespace(
        data_dir=str(tmp_path),
        gateway=SimpleNamespace(api_port=18970, host="127.0.0.1", token="token"),
    )
    app = DefenseClawTUI(config=config)
    calls: list[str] = []

    async def fake_health() -> None:
        calls.append("health")

    async def fake_ai_usage(*, force_render: bool) -> None:
        calls.append(f"ai:{force_render}")

    async def fake_credentials() -> None:
        calls.append("credentials")

    app._poll_health = fake_health  # type: ignore[method-assign]
    app._poll_ai_usage = fake_ai_usage  # type: ignore[method-assign]
    app._load_setup_credentials = fake_credentials  # type: ignore[method-assign]

    app._health_poll_running = True  # noqa: SLF001
    await app._poll_health_once()  # noqa: SLF001
    assert app._health_poll_running is False  # noqa: SLF001

    app._ai_usage_poll_running = True  # noqa: SLF001
    await app._poll_ai_usage_once(force_render=False)  # noqa: SLF001
    assert app._ai_usage_poll_running is False  # noqa: SLF001

    app._credentials_refresh_running = True  # noqa: SLF001
    await app._refresh_credentials_once()  # noqa: SLF001
    assert app._credentials_refresh_running is False  # noqa: SLF001
    assert calls == ["health", "ai:False", "credentials"]


def test_slow_refresh_scheduler_is_single_flight(tmp_path) -> None:
    app = DefenseClawTUI(config=SimpleNamespace(data_dir=str(tmp_path)))
    scheduled: list[object] = []

    def fake_run_worker(coro: object, **_kwargs: object) -> None:
        scheduled.append(coro)

    def close_last_scheduled() -> None:
        close = getattr(scheduled.pop(), "close", None)
        if callable(close):
            close()

    app.run_worker = fake_run_worker  # type: ignore[method-assign]

    app._schedule_slow_refresh()  # noqa: SLF001
    app._schedule_slow_refresh()  # noqa: SLF001

    assert len(scheduled) == 1
    assert app._slow_refresh_running is True  # noqa: SLF001
    close_last_scheduled()


@pytest.mark.asyncio
async def test_slow_refresh_uses_tools_store_refresh_without_catalog_subprocess(tmp_path) -> None:
    app = DefenseClawTUI(config=SimpleNamespace(data_dir=str(tmp_path)))
    app.tools_model.loaded = True
    refreshed: list[str] = []
    loaded: list[str] = []

    def fake_tools_refresh() -> None:
        refreshed.append("tools")

    async def fake_load_catalog(panel: str) -> None:
        loaded.append(panel)

    app.tools_model.refresh = fake_tools_refresh  # type: ignore[method-assign]
    app._load_catalog_model = fake_load_catalog  # type: ignore[method-assign]

    app._slow_refresh_running = True  # noqa: SLF001
    await app._run_slow_refresh()  # noqa: SLF001

    assert refreshed == ["tools"]
    assert loaded == []
    assert app._slow_refresh_running is False  # noqa: SLF001


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

        # Enter opens the goal menu first; a second Enter picks a goal
        # and opens the filtered form.
        await pilot.press("enter")
        await pilot.pause()
        assert setup.goal_active is True
        assert "What do you want to do?" in app.body_text

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

    async def fake_run(binary: str, args: tuple[str, ...], display_name: str = "", **_kwargs: object) -> None:
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
        # F-0782: activity output frequently contains tokens/secrets, so the
        # saved file must be owner-only (0600), not world-readable.
        assert (saved[0].stat().st_mode & 0o777) == 0o600


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
async def test_ai_discovery_enter_toggles_detail_exactly_once_per_press() -> None:
    """Each ``enter`` press flips the detail panel exactly once.

    Regression: with the DataTable focused, ``enter`` was handled twice
    — once by the app's ``on_key`` (which toggled the detail) and again
    by the table's built-in ``enter -> select_cursor`` binding, which
    posted a ``RowSelected`` that re-toggled it. The net effect made the
    detail flicker open/closed on every keypress instead of latching.
    """

    ai_model = AIDiscoveryPanelModel()
    ai_model.set_snapshot(
        AIUsageSnapshot(
            enabled=True,
            signals=(AIUsageSignal(name="openai-agent", vendor="OpenAI", product="Codex"),),
        )
    )
    app = DefenseClawTUI(ai_discovery_model=ai_model)

    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("V")
        await pilot.pause()
        assert app.active_panel == "ai"
        assert ai_model.detail_open is False

        await pilot.press("enter")
        await pilot.pause()
        assert ai_model.detail_open is True

        # Second press must close it — the double-dispatch bug left it
        # open here because the stray RowSelected toggled it a second time.
        await pilot.press("enter")
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


def test_startup_binds_alerts_model_to_audit_store(monkeypatch, tmp_path) -> None:
    """Startup alerts refresh must use the summary reader, not a second DB scan."""

    store = object()
    monkeypatch.setattr("defenseclaw.tui.app._audit_store", lambda _cfg: store)

    app = DefenseClawTUI(
        config=SimpleNamespace(audit_db=str(tmp_path / "audit.sqlite")),
        data_dir=tmp_path,
    )

    assert app.alerts_model.store is store


def test_refresh_alerts_mirrors_loaded_alerts_with_cheap_enforcement_counts(tmp_path) -> None:
    """Refreshing alerts should use actionable summaries and cheap counts."""

    class FakeStore:
        def list_actionable_alert_summaries(self, limit: int) -> list[AlertEvent]:
            assert limit == 500
            return [
                AlertEvent(id="a1", severity="HIGH", action="scan", target="skill://one"),
            ]

        def list_alert_summaries(self, _limit: int) -> list[AlertEvent]:
            raise AssertionError("default refresh should use actionable summaries")

        def list_alerts(self, _limit: int) -> list[AlertEvent]:
            raise AssertionError("refresh should use list_alert_summaries")

        def get_counts(self) -> object:
            raise AssertionError("refresh should not scan counts")

        def get_enforcement_counts(self) -> Counts:
            return Counts(
                blocked_skills=7,
                allowed_skills=8,
                blocked_mcps=9,
                allowed_mcps=10,
                total_scans=11,
            )

    overview = OverviewPanelModel()
    overview.set_enforcement_counts(
        EnforcementCounts(
            blocked_skills=2,
            allowed_skills=3,
            blocked_mcps=4,
            allowed_mcps=5,
            total_scans=6,
            active_alerts=999,
        )
    )
    app = DefenseClawTUI(
        data_dir=tmp_path,
        alerts_model=AlertsPanelModel(store=FakeStore()),
        overview_model=overview,
    )

    app._refresh_alerts()  # noqa: SLF001 - regression for the startup refresh path.

    assert overview.enforcement == EnforcementCounts(
        blocked_skills=7,
        allowed_skills=8,
        blocked_mcps=9,
        allowed_mcps=10,
        total_scans=11,
        active_alerts=1,
    )


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
    """``_write_activity_safe`` must hand a safe renderable to the
    Activity RichLog — that's the whole point of the helper. Without
    safe-handling, a subprocess line like ``[INFO] foo`` crashes the
    Rich parser and tears down the activity stream.

    Implementation note: the helper switched from ``rich_escape``
    (which left ANSI bytes intact and leaked them as visible
    ``[1;33m...`` in the UI) to ``Text.from_ansi`` (which converts
    ANSI SGR sequences AND treats remaining content as opaque text,
    closing both the markup crash AND the ANSI leak in one go).
    Verify we now hand a ``Text`` object with the literal content
    preserved.
    """

    from rich.text import Text

    captured: list = []

    class _FakeRichLog:
        def write(self, renderable) -> None:  # noqa: ANN001
            captured.append(renderable)

    fake = _FakeRichLog()
    app = DefenseClawTUI.__new__(DefenseClawTUI)
    app.activity_lines = []  # type: ignore[attr-defined]

    def _query_one(_selector, _expected_type):  # noqa: ANN001
        return fake

    monkeypatch.setattr(app, "query_one", _query_one, raising=False)
    # ``[skill]`` is the canonical risk shape — Rich's markup parser
    # treats it as an opening style tag. Text.from_ansi consumes
    # the entire string as opaque text (no markup re-parse), so the
    # literal brackets survive verbatim into the Text's ``.plain``
    # without needing a separate escape pass.
    app._write_activity_safe("prompt: [skill] continue")  # noqa: SLF001
    assert len(captured) == 1
    rendered = captured[0]
    assert isinstance(rendered, Text), (
        "must hand a rich.text.Text object so RichLog skips its markup "
        "re-parse and the bracketed token can't take down the stream"
    )
    assert rendered.plain == "prompt: [skill] continue"


def test_write_activity_safe_converts_ansi_color_codes_to_styles(monkeypatch) -> None:
    """``_write_activity_safe`` must translate ANSI SGR sequences from
    subprocess stdout into actual Rich styles, NOT leak the raw escape
    bytes through to the renderer as visible literals like ``[1;33m``.

    Repro of the bug the operator screenshotted: ``ux.warn`` ->
    ``click.style`` writes ``\\x1b[1;33m\u25b3 warning:\\x1b[0m \\x1b[33mfoo\\x1b[0m``
    to stdout. The pre-fix safe writer fed those bytes verbatim to
    the Activity RichLog, which rendered them as the literal text
    the operator saw on screen. The fix routes through
    ``Text.from_ansi`` so the SGR codes become actual styles.
    """

    from rich.text import Text

    captured: list = []

    class _FakeRichLog:
        def write(self, renderable) -> None:  # noqa: ANN001
            captured.append(renderable)

    fake = _FakeRichLog()
    app = DefenseClawTUI.__new__(DefenseClawTUI)
    app.activity_lines = []  # type: ignore[attr-defined]

    def _query_one(_selector, _expected_type):  # noqa: ANN001
        return fake

    monkeypatch.setattr(app, "query_one", _query_one, raising=False)
    # Exact byte sequence ``click.style("warning:", fg="yellow", bold=True)``
    # produces — bold + yellow on, then reset.
    app._write_activity_safe("\x1b[1;33mwarning:\x1b[0m foo")  # noqa: SLF001

    assert len(captured) == 1
    rendered = captured[0]
    assert isinstance(rendered, Text)
    # The plain text must NOT include the raw escape bytes — that's
    # the operator-visible regression we're closing.
    assert "\x1b" not in rendered.plain
    assert "[1;33m" not in rendered.plain
    assert "[0m" not in rendered.plain
    # The visible content is the bare strings (escape bytes consumed).
    assert rendered.plain == "warning: foo"
    # And the styling must have been applied — there should be at
    # least one span (for the bold-yellow ``warning:`` segment).
    assert len(rendered.spans) >= 1, "ANSI codes should produce styled spans"


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

    from defenseclaw.tui.screens.detail import DetailModalModel
    from rich.console import Console

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
    six escapes regresses, Rich consumes the bracket pair as a
    style tag and the operator sees ``Scan all`` with no hotkey to
    press. The end-to-end render includes the safety wrapper, so this
    test also catches a class of bugs where the wrapper falls back to
    plain text and the visible content silently changes.
    """

    app = DefenseClawTUI()
    async with app.run_test(size=(180, 60)) as pilot:
        await pilot.pause()
        plain = Text.from_markup(app.body_text).plain
        for key in ("[s]", "[d]", "[i]", "[g]", "[m]", "[l]"):
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

    from defenseclaw.tui.theme import DEFAULT_TOKENS as TOKENS
    from rich.markup import escape as rich_escape

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
                severity="HIGH",
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
    # Regex character classes inside raw-string patterns that never
    # flow through Rich markup (validators.py / answers.py only feed
    # these into ``re.compile``).
    "[a-z0-9][a-z0-9-]",
    "[A-Z][A-Z0-9_-]",
    "[a-z_]+",
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
    # Catalog action key (single character). The surrounding code
    # in catalog_state.py wraps the rendered chunks in ``[dim]…[/]``
    # before display, so the bracket-tag shape never reaches the
    # user's terminal as a literal — Rich consumes the outer tags
    # first and the inner bracket pair is harmless.
    "action.key",
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


def test_event_histogram_buckets_recent_events_by_time() -> None:
    now = datetime(2026, 5, 29, 12, 0, 0, tzinfo=timezone.utc)
    window = timedelta(minutes=10)
    buckets = 10  # one bucket per minute
    timestamps = [
        now - timedelta(seconds=30),  # newest bucket (index 9)
        now - timedelta(seconds=90),  # bucket 8
        now - timedelta(seconds=95),  # bucket 8
        now - timedelta(minutes=20),  # older than the window -> dropped
        now + timedelta(minutes=1),  # in the future -> dropped
    ]
    hist = _event_histogram(timestamps, now=now, buckets=buckets, window=window)
    assert len(hist) == buckets
    assert hist[9] == 1.0
    assert hist[8] == 2.0
    assert sum(hist) == 3.0


def test_event_histogram_handles_empty_and_naive_timestamps() -> None:
    now = datetime(2026, 5, 29, 12, 0, 0, tzinfo=timezone.utc)
    assert _event_histogram([], now=now, buckets=6, window=timedelta(minutes=6)) == (0.0,) * 6
    # Naive datetimes are treated as UTC so they still bucket.
    naive = now.replace(tzinfo=None) - timedelta(seconds=10)
    hist = _event_histogram([naive], now=now, buckets=6, window=timedelta(minutes=6))
    assert sum(hist) == 1.0


@pytest.mark.asyncio
async def test_overview_lists_all_active_connectors_in_rendered_panel() -> None:
    """8.13: with more than one connector active the *visible* Overview shows
    a dedicated CONNECTORS table listing every connector with its mode, while
    the CONFIGURATION panel collapses to an "Agents: N active" header."""

    from rich.console import Console

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "enforce"), ("cursor", "observe")),
        connector_packs=(("codex", "strict"), ("cursor", "permissive")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(HealthSnapshot(gateway=SubsystemHealth(state="running")))
    app = DefenseClawTUI(overview_model=overview)

    async with app.run_test(size=(170, 50)) as pilot:
        await pilot.pause()
        # Rich's Console.size only honors an explicit width when height is also
        # set; otherwise it falls back to an 80-col terminal and crops cells.
        console = Console(width=170, height=80, record=True)
        console.print(app._overview_renderable())
        text = console.export_text()

    # CONFIGURATION collapses to the unified count header.
    assert "2 active" in text
    assert "Agents" in text
    # The dedicated CONNECTORS table lists every connector + its mode/pack.
    assert "CONNECTORS" in text
    assert "Codex" in text and "codex" in text
    assert "Cursor" in text
    assert "enforce" in text
    assert "observe" in text
    assert "strict" in text and "permissive" in text


def test_policy_posture_multi_connector() -> None:
    """Multi-connector posture reflects the roster, not one global pack:
    divergent packs/modes point at the roster; a uniform install names the
    shared mode + pack. Single-connector keeps the original wording."""

    # Divergent rule packs -> defer to the roster.
    divergent = OverviewConfig(
        guardrail_mode="action",
        connector_modes=(("codex", "action"), ("claudecode", "action")),
        connector_packs=(("codex", "strict"), ("claudecode", "permissive")),
    )
    assert _policy_posture(divergent) == "per-connector (see roster)"

    # Divergent modes (same/blank packs) also defer.
    divergent_modes = OverviewConfig(
        guardrail_mode="action",
        connector_modes=(("codex", "action"), ("cursor", "observe")),
    )
    assert _policy_posture(divergent_modes) == "per-connector (see roster)"

    # Uniform multi-connector: one mode + one pack across the roster.
    uniform = OverviewConfig(
        guardrail_mode="action",
        connector_modes=(("codex", "action"), ("claudecode", "action")),
        connector_packs=(("codex", "strict"), ("claudecode", "strict")),
    )
    assert _policy_posture(uniform) == "all connectors: action (strict)"

    # Single-connector wording is unchanged.
    single = OverviewConfig(guardrail_mode="action", guardrail_strategy="default")
    assert _policy_posture(single) == "action: block CRIT, alert MED+ (default)"


def test_enforcement_label_multi_connector() -> None:
    """Multi-connector enforcement reports the connector count instead of
    naming a single primary; single-connector keeps the named-connector form."""

    multi = OverviewConfig(
        guardrail_connector="codex",
        guardrail_mode="action",
        connector_modes=(("codex", "action"), ("claudecode", "action")),
    )
    assert _enforcement_label(multi) == "2 connectors (hook observability)"

    single = OverviewConfig(guardrail_connector="codex", guardrail_mode="action")
    assert _enforcement_label(single) == "codex hook observability (action)"


@pytest.mark.asyncio
async def test_hook_calls_tile_counts_audit_events_and_deeplinks_to_logs() -> None:
    """Hook Calls reflects connector-hook audit events (not the gateway
    ``requests`` counter, which stays zero for hook connectors) and the
    tile drills into the Logs panel pre-filtered to hook activity."""

    cfg = OverviewConfig(data_dir="/tmp/dc", claw_mode="cursor", guardrail_connector="cursor")
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(
        HealthSnapshot(
            gateway=SubsystemHealth(state="running"),
            connector=ConnectorHealth(name="cursor", state="running", requests=0),
        )
    )
    audit = AuditPanelModel()
    audit.set_events(
        [
            Event(
                id=f"hook-{i}",
                action="connector-hook",
                target="preToolUse",
                severity="INFO",
                details="connector=cursor action=allow",
            )
            for i in range(5)
        ]
    )
    logs = LogsPanelModel()
    app = DefenseClawTUI(overview_model=overview, audit_model=audit, logs_model=logs)

    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()

        metrics = {metric.key: metric for metric in app._overview_metric_data()}
        assert "hook_calls" in metrics
        hook_tile = metrics["hook_calls"]
        # Value comes from the audit events, not the zeroed live counter.
        assert hook_tile.value == 5
        assert hook_tile.target_panel == "logs"
        # The sparkline is a real time histogram with a populated bucket.
        assert any(bar > 0 for bar in hook_tile.trend)

        await pilot.click("#overview-hook_calls-metric")
        await pilot.pause()
        assert app.active_panel == "logs"
        assert logs.source == "otel"
        assert logs.filter_mode == FILTER_HOOKS


@pytest.mark.asyncio
async def test_hook_calls_tile_uses_unfiltered_hook_events_from_store(tmp_path) -> None:
    """Default Audit refresh hides INFO hook rows; Overview metrics still count them."""

    store = Store(str(tmp_path / "audit.sqlite"))
    store.init()
    for i in range(4):
        store.log_event(
            Event(
                id=f"hook-info-{i}",
                action="connector-hook",
                target="preToolUse",
                severity="INFO",
                details="connector=cursor action=allow",
            )
        )
    store.log_event(
        Event(
            id="hook-block",
            action="connector-hook",
            target="preToolUse",
            severity="HIGH",
            details="connector=cursor action=block",
        )
    )

    cfg = OverviewConfig(data_dir=str(tmp_path), claw_mode="cursor", guardrail_connector="cursor")
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(
        HealthSnapshot(
            gateway=SubsystemHealth(state="running"),
            connector=ConnectorHealth(name="cursor", state="running", requests=0),
        )
    )
    audit = AuditPanelModel(store)
    audit.refresh()

    assert [event.id for event in audit.items] == ["hook-block"]

    app = DefenseClawTUI(overview_model=overview, audit_model=audit)

    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()

        metrics = {metric.key: metric for metric in app._overview_metric_data()}
        assert metrics["hook_calls"].value == 5
        assert "a4" in metrics["hook_calls"].detail
        assert "b1" in metrics["hook_calls"].detail


@pytest.mark.asyncio
async def test_hook_calls_tile_splits_stats_per_connector_in_multi() -> None:
    """D1=B: with >1 connector active, the Hook Calls tile relabels to the
    connector count and its detail attributes allow/block counts to each
    connector — instead of mislabelling every connector's activity under
    the single primary. The Blocks tile lists only connectors that blocked.
    """

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "enforce"), ("cursor", "observe")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    audit = AuditPanelModel()
    events = [
        Event(id=f"cx-a{i}", action="connector-hook", target="preToolUse",
              severity="INFO", details="connector=codex action=allow")
        for i in range(2)
    ]
    events.append(Event(id="cx-b", action="connector-hook", target="afterShellExecution",
                        severity="HIGH", details="connector=codex action=block"))
    events.append(Event(id="cu-a", action="connector-hook", target="preToolUse",
                        severity="INFO", details="connector=cursor action=allow"))
    audit.set_events(events)
    app = DefenseClawTUI(overview_model=overview, audit_model=audit)

    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()

        metrics = {m.key: m for m in app._overview_metric_data()}
        hook_tile = metrics["hook_calls"]
        # Honest label reflecting the roster, not the primary connector.
        assert hook_tile.label == "Hook Calls (2 connectors)"
        # Per-connector split: codex got 2 allows + 1 block, cursor 1 allow.
        assert "codex" in hook_tile.detail
        assert "a2" in hook_tile.detail
        assert "b1" in hook_tile.detail
        assert "cursor" in hook_tile.detail
        # The lone block is attributed to codex only.
        blocks_tile = metrics["blocks"]
        assert "codex" in blocks_tile.detail
        assert "cursor" not in blocks_tile.detail


@pytest.mark.asyncio
async def test_overview_header_tiles_scope_to_selected_connector() -> None:
    """Connector-scoped Overview tiles show connector values plus fleet context."""

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "enforce"), ("cursor", "observe")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(
        HealthSnapshot(
            gateway=SubsystemHealth(state="running"),
            connectors=(
                ConnectorHealth(name="codex", state="running"),
                ConnectorHealth(name="cursor", state="running"),
            ),
        )
    )
    audit = AuditPanelModel()
    audit.set_events(
        [
            Event(id="codex-a1", action="connector-hook", target="preToolUse",
                  severity="INFO", details="connector=codex action=allow"),
            Event(id="codex-a2", action="connector-hook", target="preToolUse",
                  severity="INFO", details="connector=codex action=allow"),
            Event(id="codex-b", action="connector-hook", target="preToolUse",
                  severity="HIGH", details="connector=codex action=block"),
            Event(id="cursor-a", action="connector-hook", target="preToolUse",
                  severity="INFO", details="connector=cursor action=allow"),
            Event(id="cursor-b", action="connector-hook", target="preToolUse",
                  severity="HIGH", details="connector=cursor action=block"),
            Event(id="old-a", action="connector-hook", target="preToolUse",
                  severity="INFO", details="action=allow"),
            Event(id="old-b", action="connector-hook", target="preToolUse",
                  severity="HIGH", details="connector=old action=block"),
        ]
    )
    alerts = AlertsPanelModel()
    alerts.set_events(
        [
            AlertEvent(id="codex-b", severity="INFO", action="connector-hook",
                       target="preToolUse",
                       details="connector=codex action=allow raw_action=alert severity=HIGH mode=observe"),
            AlertEvent(id="cursor-b", severity="MEDIUM", action="connector-hook",
                       target="preToolUse", details="connector=cursor action=alert"),
            AlertEvent(id="cursor-finding-2", severity="LOW", action="scan",
                       target="skill://cursor", details="connector=cursor scanner=skill"),
            AlertEvent(id="old-b", severity="HIGH", action="connector-hook",
                       target="preToolUse", details="connector=old action=block"),
        ]
    )
    app = DefenseClawTUI(overview_model=overview, audit_model=audit, alerts_model=alerts)

    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()

        all_metrics = {metric.key: metric for metric in app._overview_metric_data()}
        assert all_metrics["hook_calls"].label == "Hook Calls (2 connectors)"
        assert all_metrics["hook_calls"].value == 5
        assert "outside roster 2" in all_metrics["hook_calls"].detail
        assert all_metrics["blocks"].label == "Blocks"
        assert all_metrics["blocks"].value == 2
        assert "outside roster 1" in all_metrics["blocks"].detail
        assert all_metrics["findings"].label == "Findings"
        assert all_metrics["findings"].value == 3
        assert "outside roster 1" in all_metrics["findings"].detail

        app._set_connector_filter("codex")
        codex_metrics = {metric.key: metric for metric in app._overview_metric_data()}
        assert codex_metrics["hook_calls"].label == "Hook Calls (codex)"
        assert codex_metrics["hook_calls"].value == 3
        assert "fleet 7" in codex_metrics["hook_calls"].detail
        assert codex_metrics["blocks"].label == "Blocks (codex)"
        assert codex_metrics["blocks"].value == 1
        assert "fleet 3" in codex_metrics["blocks"].detail
        assert codex_metrics["findings"].label == "Findings (codex)"
        assert codex_metrics["findings"].value == 1
        assert "fleet 4" in codex_metrics["findings"].detail

        app._set_connector_filter("cursor")
        cursor_metrics = {metric.key: metric for metric in app._overview_metric_data()}
        assert cursor_metrics["hook_calls"].label == "Hook Calls (cursor)"
        assert cursor_metrics["hook_calls"].value == 2
        assert cursor_metrics["blocks"].label == "Blocks (cursor)"
        assert cursor_metrics["blocks"].value == 1
        assert cursor_metrics["findings"].label == "Findings (cursor)"
        assert cursor_metrics["findings"].value == 2
        assert "fleet 4" in cursor_metrics["findings"].detail


@pytest.mark.asyncio
async def test_overview_connector_rows_use_total_hook_stats_not_recent_window() -> None:
    """The CONNECTORS table should not look frozen at the 500-row window cap."""

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(
            ("antigravity", "action"),
            ("claudecode", "observe"),
            ("codex", "observe"),
            ("hermes", "action"),
            ("opencode", "action"),
        ),
    )
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(HealthSnapshot(gateway=SubsystemHealth(state="running")))
    base = datetime.now(timezone.utc) - timedelta(minutes=5)
    events = [
        Event(
            id=f"codex-{i}",
            timestamp=base + timedelta(seconds=i),
            action="connector-hook",
            target="preToolUse",
            severity="INFO",
            details="connector=codex action=allow",
        )
        for i in range(498)
    ]
    events.extend(
        Event(
            id=f"claudecode-{i}",
            timestamp=base + timedelta(seconds=498 + i),
            action="connector-hook",
            target="preToolUse",
            severity="INFO",
            details="connector=claudecode action=allow",
        )
        for i in range(2)
    )
    class HookStatsStore:
        def list_connector_hook_event_summaries(self, limit: int = 500) -> list[Event]:
            return list(events[-limit:])

        def connector_hook_event_stats(self) -> dict[str, dict[str, object]]:
            return {
                "antigravity": {
                    "calls": 10,
                    "alerts": 0,
                    "blocks": 0,
                    "newest": (base - timedelta(hours=1)).isoformat(),
                },
                "claudecode": {
                    "calls": 4402,
                    "alerts": 0,
                    "blocks": 0,
                    "newest": (base + timedelta(seconds=499)).isoformat(),
                },
                "codex": {
                    "calls": 16090,
                    "alerts": 0,
                    "blocks": 0,
                    "newest": (base + timedelta(minutes=10)).isoformat(),
                },
                "hermes": {
                    "calls": 152,
                    "alerts": 0,
                    "blocks": 0,
                    "newest": (base - timedelta(hours=2)).isoformat(),
                },
                "opencode": {
                    "calls": 37,
                    "alerts": 0,
                    "blocks": 0,
                    "newest": (base - timedelta(hours=3)).isoformat(),
                },
            }

    audit = AuditPanelModel(HookStatsStore())
    app = DefenseClawTUI(overview_model=overview, audit_model=audit)

    async with app.run_test(size=(190, 50)) as pilot:
        await pilot.pause()

        metrics = {metric.key: metric for metric in app._overview_metric_data()}
        assert metrics["hook_calls"].label == "Hook Calls (5 connectors)"
        assert metrics["hook_calls"].value == 20691

        rows = {row.connector: row for row in app._overview_connector_rows()}
        assert rows["codex"].calls == 16090
        assert rows["claudecode"].calls == 4402
        assert rows["antigravity"].calls == 10
        assert rows["hermes"].calls == 152
        assert rows["opencode"].calls == 37
        assert rows["codex"].last_activity != "—"


@pytest.mark.asyncio
async def test_overview_startup_uses_recent_hooks_until_health_loads() -> None:
    """Cold startup should not flash lifetime hook totals as active-session counts."""

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "observe"), ("cursor", "observe")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    base = datetime.now(timezone.utc) - timedelta(minutes=1)
    events = [
        Event(
            id="codex-a",
            timestamp=base,
            action="connector-hook",
            target="preToolUse",
            severity="INFO",
            details="connector=codex action=allow",
        ),
        Event(
            id="codex-b",
            timestamp=base + timedelta(seconds=1),
            action="connector-hook",
            target="preToolUse",
            severity="HIGH",
            details="connector=codex action=block",
        ),
        Event(
            id="cursor-a",
            timestamp=base + timedelta(seconds=2),
            action="connector-hook",
            target="preToolUse",
            severity="INFO",
            details="connector=cursor action=allow",
        ),
    ]

    class HookStatsStore:
        def __init__(self) -> None:
            self.stats_calls = 0

        def list_connector_hook_event_summaries(self, limit: int = 500) -> list[Event]:
            return list(events[-limit:])

        def connector_hook_event_stats(self) -> dict[str, dict[str, object]]:
            self.stats_calls += 1
            return {
                "codex": {
                    "calls": 20000,
                    "alerts": 500,
                    "blocks": 250,
                    "newest": (base + timedelta(hours=1)).isoformat(),
                },
                "cursor": {
                    "calls": 7000,
                    "alerts": 100,
                    "blocks": 50,
                    "newest": (base + timedelta(hours=1, seconds=1)).isoformat(),
                },
            }

    store = HookStatsStore()
    audit = AuditPanelModel(store)
    app = DefenseClawTUI(overview_model=overview, audit_model=audit)

    async with app.run_test(size=(190, 50)) as pilot:
        await pilot.pause()

        metrics = {metric.key: metric for metric in app._overview_metric_data()}
        assert metrics["hook_calls"].value == 3
        assert metrics["blocks"].value == 1
        rows = {row.connector: row for row in app._overview_connector_rows()}
        assert rows["codex"].calls == 2
        assert rows["cursor"].calls == 1
        assert store.stats_calls == 0

        overview.set_health(
            HealthSnapshot(
                gateway=SubsystemHealth(state="running"),
                connectors=(
                    ConnectorHealth(name="codex", state="running"),
                    ConnectorHealth(name="cursor", state="running"),
                ),
            )
        )
        metrics = {metric.key: metric for metric in app._overview_metric_data()}
        assert metrics["hook_calls"].value == 27000
        rows = {row.connector: row for row in app._overview_connector_rows()}
        assert rows["codex"].calls == 20000
        assert rows["cursor"].calls == 7000
        assert store.stats_calls == 1


@pytest.mark.asyncio
async def test_overview_prefers_live_connector_counts_over_lifetime_history() -> None:
    """Live health counters are the current dashboard number; history is fallback."""

    since = datetime.now(timezone.utc) - timedelta(minutes=2)
    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("claudecode", "observe"), ("codex", "observe")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(
        HealthSnapshot(
            gateway=SubsystemHealth(state="disabled"),
            guardrail=SubsystemHealth(state="running"),
            connectors=(
                ConnectorHealth(
                    name="claudecode",
                    state="running",
                    since=since.isoformat(),
                    requests=6,
                    tool_inspections=1,
                ),
                ConnectorHealth(
                    name="codex",
                    state="running",
                    since=since.isoformat(),
                    requests=135,
                    tool_inspections=73,
                ),
            ),
        )
    )
    events = [
        Event(
            id=f"claude-live-{i}",
            timestamp=since + timedelta(seconds=i),
            action="connector-hook",
            target="PreToolUse",
            severity="INFO",
            details="connector=claudecode action=allow",
        )
        for i in range(6)
    ]
    events.extend(
        [
            Event(
                id="codex-observe-would-block",
                timestamp=since + timedelta(seconds=7),
                action="connector-hook",
                target="PostToolUse",
                severity="INFO",
                details="connector=codex action=allow raw_action=block severity=CRITICAL mode=observe would_block=true",
            ),
            Event(
                id="codex-observe-alert",
                timestamp=since + timedelta(seconds=8),
                action="connector-hook",
                target="PostToolUse",
                severity="INFO",
                details="connector=codex action=allow raw_action=alert severity=HIGH mode=observe would_block=false",
            ),
        ]
    )

    class HookStatsStore:
        def __init__(self) -> None:
            self.stats_calls = 0

        def list_connector_hook_event_summaries(self, limit: int = 500) -> list[Event]:
            return list(events[-limit:])

        def connector_hook_event_stats(self) -> dict[str, dict[str, object]]:
            self.stats_calls += 1
            return {
                "claudecode": {
                    "calls": 4408,
                    "alerts": 5,
                    "blocks": 12,
                    "newest": (since + timedelta(seconds=5)).isoformat(),
                },
                "codex": {
                    "calls": 16216,
                    "alerts": 54,
                    "blocks": 27,
                    "newest": (since + timedelta(seconds=10)).isoformat(),
                },
            }

        def count_scan_results_since(self, since_arg: datetime | None) -> int:
            assert since_arg is not None
            return 2

    store = HookStatsStore()
    audit = AuditPanelModel(store)
    alerts = AlertsPanelModel()
    alerts.set_events(
        [
            AlertEvent(
                id="old-claude-finding",
                timestamp=since - timedelta(hours=1),
                severity="CRITICAL",
                action="connector-hook",
                target="old",
                details="connector=claudecode action=block",
            ),
            AlertEvent(
                id="live-claude-finding",
                timestamp=since + timedelta(seconds=3),
                severity="MEDIUM",
                action="connector-hook",
                target="live",
                details="connector=claudecode action=alert",
            ),
        ]
    )
    app = DefenseClawTUI(overview_model=overview, audit_model=audit, alerts_model=alerts)

    async with app.run_test(size=(190, 50)) as pilot:
        await pilot.pause()

        rows = {row.connector: row for row in app._overview_connector_rows()}
        assert rows["claudecode"].calls == 6
        assert rows["codex"].calls == 135
        assert rows["codex"].blocks == 0
        assert rows["codex"].alerts == 2
        assert store.stats_calls == 0

        app._set_connector_filter("codex")
        codex_metrics = {metric.key: metric for metric in app._overview_metric_data()}
        assert codex_metrics["findings"].value == 2
        assert store.stats_calls == 0

        app._set_connector_filter("claudecode")
        metrics = {metric.key: metric for metric in app._overview_metric_data()}
        assert metrics["hook_calls"].label == "Hook Calls (claudecode)"
        assert metrics["hook_calls"].value == 6
        assert metrics["findings"].value == 1
        assert store.stats_calls == 0

        session_counts = app._overview_session_enforcement_counts()
        assert session_counts.active_alerts == 3
        assert session_counts.total_scans == 2


@pytest.mark.asyncio
async def test_overview_alerts_and_findings_use_distinct_buckets() -> None:
    """Hook alerts count decisions; Findings only count severity-bearing decisions."""

    since = datetime.now(timezone.utc) - timedelta(minutes=2)
    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "observe"), ("cursor", "observe")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(
        HealthSnapshot(
            gateway=SubsystemHealth(state="disabled"),
            connectors=(
                ConnectorHealth(
                    name="codex",
                    state="running",
                    since=since.isoformat(),
                    requests=2,
                ),
                ConnectorHealth(
                    name="cursor",
                    state="running",
                    since=since.isoformat(),
                    requests=0,
                ),
            ),
        )
    )
    events = [
        Event(
            id="codex-alert-no-finding",
            timestamp=since + timedelta(seconds=1),
            action="connector-hook",
            target="PostToolUse",
            severity="INFO",
            details="connector=codex action=allow raw_action=alert severity=NONE mode=observe",
        ),
        Event(
            id="codex-alert-finding",
            timestamp=since + timedelta(seconds=2),
            action="connector-hook",
            target="PostToolUse",
            severity="INFO",
            details="connector=codex action=allow raw_action=alert severity=HIGH mode=observe",
        ),
    ]

    class HookStatsStore:
        def list_connector_hook_event_summaries(self, limit: int = 500) -> list[Event]:
            return list(events[-limit:])

    audit = AuditPanelModel(HookStatsStore())
    app = DefenseClawTUI(overview_model=overview, audit_model=audit, alerts_model=AlertsPanelModel())

    async with app.run_test(size=(190, 50)) as pilot:
        await pilot.pause()

        rows = {row.connector: row for row in app._overview_connector_rows()}
        assert rows["codex"].alerts == 2

        metrics = {metric.key: metric for metric in app._overview_metric_data()}
        assert metrics["findings"].value == 1

        session_counts = app._overview_session_enforcement_counts()
        assert session_counts.active_alerts == 2


def test_overview_reuses_hook_event_snapshot_within_one_render() -> None:
    """Overview metrics/rows should not re-query the same hook window per connector."""

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(
            ("antigravity", "action"),
            ("claudecode", "observe"),
            ("codex", "observe"),
            ("hermes", "action"),
            ("opencode", "action"),
        ),
    )
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(HealthSnapshot(gateway=SubsystemHealth(state="running")))
    events = [
        Event(
            id=f"codex-{i}",
            action="connector-hook",
            target="preToolUse",
            severity="INFO",
            details="connector=codex action=allow",
        )
        for i in range(10)
    ]

    class CountingHookStore:
        calls = 0
        scan_count_calls = 0

        def list_connector_hook_event_summaries(self, limit: int = 500) -> list[Event]:
            self.calls += 1
            return list(events[:limit])

        def count_scan_results_since(self, _since: datetime | None) -> int:
            self.scan_count_calls += 1
            return 0

    store = CountingHookStore()
    audit = AuditPanelModel(store)
    app = DefenseClawTUI(overview_model=overview, audit_model=audit)

    with app._connector_hook_event_render_cache():
        app._overview_renderable()
        metrics = {metric.key: metric for metric in app._overview_metric_data()}
        rows = {row.connector: row for row in app._overview_connector_rows()}

    assert store.calls == 1
    assert store.scan_count_calls == 1
    assert metrics["hook_calls"].value == 10
    assert rows["codex"].calls == 10


@pytest.mark.asyncio
async def test_connector_filter_defaults_to_all_and_narrows() -> None:
    """8.13: in a multi-connector install the shared connector filter defaults
    to All (""), and selecting a connector re-targets the catalog models
    (connector + --connector flag) and marks them for reload."""

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "enforce"), ("cursor", "observe")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    app = DefenseClawTUI(overview_model=overview)

    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()

        # Default filter = All connectors ("").
        assert app._connector_filter() == ""
        assert app._active_connector_names() == ["codex", "cursor"]

        app._set_connector_filter("cursor")
        assert app._connector_filter() == "cursor"
        # Catalog models now target cursor with the focus flag enabled.
        for model in (app.skills_model, app.mcps_model, app.plugins_model):
            assert model.connector == "cursor"
            assert model.connector_focus_enabled is True
            assert model.load_intent().args[-2:] == ("--connector", "cursor")

        # Clearing the filter (All) drops the per-connector scoping.
        app._set_connector_filter("")
        assert app._connector_filter() == ""
        for model in (app.skills_model, app.mcps_model, app.plugins_model):
            assert model.connector_focus_enabled is False


@pytest.mark.asyncio
async def test_catalog_inventory_show_connector_column_in_multi() -> None:
    """8.13 pass 2: a multi-connector install turns on the CONNECTOR column for
    the merged catalog + inventory panels and narrows them via the shared
    filter, without forcing a reload."""

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "enforce"), ("cursor", "observe")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    app = DefenseClawTUI(overview_model=overview)

    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()
        app._sync_catalog_connector_filters()
        for model in (
            app.skills_model,
            app.mcps_model,
            app.plugins_model,
            app.tools_model,
            app.inventory_model,
        ):
            assert model.show_connector_column is True

        app._set_connector_filter("cursor")
        app._sync_catalog_connector_filters()
        for model in (app.skills_model, app.mcps_model, app.plugins_model, app.tools_model):
            assert model.connector_filter == "cursor"
        assert app.inventory_model.connector_filter == "cursor"


@pytest.mark.asyncio
async def test_overview_connector_filter_does_not_refilter_hidden_panels(monkeypatch: pytest.MonkeyPatch) -> None:
    """Overview chip clicks should not synchronously filter every hidden table."""

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "enforce"), ("cursor", "observe")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    app = DefenseClawTUI(overview_model=overview)

    hidden_filter_calls: list[str] = []

    def record_filter(connector: str) -> None:
        hidden_filter_calls.append(connector)

    for model in (
        app.alerts_model,
        app.audit_model,
        app.logs_model,
        app.skills_model,
        app.mcps_model,
        app.plugins_model,
        app.tools_model,
        app.inventory_model,
    ):
        monkeypatch.setattr(model, "set_connector_filter", record_filter)

    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()
        app.active_panel = "overview"
        app._set_connector_filter("cursor")

    assert hidden_filter_calls == []


@pytest.mark.asyncio
async def test_overview_connector_filter_defers_full_render(monkeypatch: pytest.MonkeyPatch) -> None:
    """Overview filter changes should avoid a full chrome render in the hot path."""

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "enforce"), ("cursor", "observe")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    app = DefenseClawTUI(overview_model=overview)

    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()
        app.active_panel = "overview"
        render_calls: list[str] = []

        def record_render() -> None:
            render_calls.append("full")

        monkeypatch.setattr(app, "_render_chrome", record_render)
        app._set_connector_filter("cursor")

        assert app._connector_filter() == "cursor"
        assert render_calls == []


@pytest.mark.asyncio
async def test_catalog_inventory_no_connector_column_in_single() -> None:
    """Single-connector installs keep the CONNECTOR column off everywhere."""

    cfg = OverviewConfig(data_dir="/tmp/dc", claw_mode="cursor", guardrail_connector="cursor")
    overview = OverviewPanelModel(cfg, version="test")
    app = DefenseClawTUI(overview_model=overview)

    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()
        app._sync_catalog_connector_filters()
        for model in (
            app.skills_model,
            app.mcps_model,
            app.plugins_model,
            app.tools_model,
            app.inventory_model,
        ):
            assert model.show_connector_column is False


@pytest.mark.asyncio
async def test_connector_pill_multi_connector_reflects_filter() -> None:
    """E4/8.13: the status-strip connector pill shows "All connectors (N)" in
    the multi-connector landing state and "<connector> (filtered)" once the
    operator narrows the shared filter."""

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "enforce"), ("cursor", "observe")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    app = DefenseClawTUI(overview_model=overview)

    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()
        # Default = All connectors, count of 2.
        assert app._hint_status_model().connector == "All connectors (2)"
        app._set_connector_filter("cursor")
        assert app._hint_status_model().connector == "cursor (filtered)"


@pytest.mark.asyncio
async def test_connector_pill_single_connector_unchanged() -> None:
    """E4 no-op: single-connector installs show the bare connector name."""

    cfg = OverviewConfig(data_dir="/tmp/dc", claw_mode="cursor", guardrail_connector="cursor")
    overview = OverviewPanelModel(cfg, version="test")
    app = DefenseClawTUI(overview_model=overview)

    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()
        assert app._hint_status_model().connector == "cursor"


@pytest.mark.asyncio
async def test_catalog_body_shows_connector_chip_in_multi() -> None:
    """8.13: the Skills/MCPs/Plugins body shows the shared connector filter
    chip (All + each connector) and how to change it when more than one
    connector is active."""

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "enforce"), ("cursor", "observe")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    app = DefenseClawTUI(overview_model=overview)

    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()
        app._set_connector_filter("cursor")
        app.active_panel = "skills"
        body = app._body_text()
        assert "Connector:" in body
        assert "All" in body
        assert "cursor" in body
        assert "press" in body and "m" in body


@pytest.mark.asyncio
async def test_overview_body_shows_connector_chip_in_multi() -> None:
    """Overview shows a compact scope label; table panes keep the full chip."""

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "enforce"), ("cursor", "observe")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    app = DefenseClawTUI(overview_model=overview)

    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()
        body = app.body_text
        assert "Connector scope:" in body
        assert "All connectors" in body
        assert "press" in body and "m" in body


@pytest.mark.asyncio
async def test_catalog_body_no_connector_chip_single_connector() -> None:
    """8.13 no-op: single-connector installs show no connector chip."""

    cfg = OverviewConfig(data_dir="/tmp/dc", claw_mode="cursor", guardrail_connector="cursor")
    overview = OverviewPanelModel(cfg, version="test")
    app = DefenseClawTUI(overview_model=overview)

    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()
        app.active_panel = "skills"
        body = app._body_text()
        assert "Connector:" not in body


@pytest.mark.asyncio
async def test_connector_filter_noop_for_single_connector() -> None:
    """8.13: single-connector installs have no filter concept — the catalog
    list commands stay flag-free so behaviour is unchanged."""

    cfg = OverviewConfig(data_dir="/tmp/dc", claw_mode="cursor", guardrail_connector="cursor")
    overview = OverviewPanelModel(cfg, version="test")
    app = DefenseClawTUI(overview_model=overview)

    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()
        assert app._connector_filter() == ""
        assert app.skills_model.load_intent().args == ("skill", "list", "--json")


@pytest.mark.asyncio
async def test_hook_calls_tile_single_connector_unchanged() -> None:
    """D1=B is a no-op for single-connector installs: the label keeps the
    connector name and the detail keeps its existing aggregate form."""

    cfg = OverviewConfig(data_dir="/tmp/dc", claw_mode="cursor", guardrail_connector="cursor")
    overview = OverviewPanelModel(cfg, version="test")
    audit = AuditPanelModel()
    audit.set_events([
        Event(id=f"h{i}", action="connector-hook", target="preToolUse",
              severity="INFO", details="connector=cursor action=allow")
        for i in range(3)
    ])
    app = DefenseClawTUI(overview_model=overview, audit_model=audit)

    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()
        metrics = {m.key: m for m in app._overview_metric_data()}
        assert metrics["hook_calls"].label == "Hook Calls (cursor)"
        # No per-connector roster ⇒ helpers return empty, aggregate unchanged.
        assert app._active_connector_names() == []
        assert app._multi_connector_tile_details() == ("", "")


@pytest.mark.asyncio
async def test_overview_connector_rows_combine_config_health_and_audit() -> None:
    """8.13: the Overview CONNECTORS table rows combine config (mode + pack),
    audit-derived CALLS/BLOCKS/ALERTS, and live /health status."""

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "action"), ("cursor", "observe")),
        connector_packs=(("codex", "strict"), ("cursor", "permissive")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(
        HealthSnapshot(
            gateway=SubsystemHealth(state="running"),
            connector=ConnectorHealth(name="codex", state="running"),
            connectors=(
                ConnectorHealth(name="codex", state="running"),
                ConnectorHealth(name="cursor", state="degraded"),
            ),
        )
    )
    audit = AuditPanelModel()
    audit.set_events(
        [
            Event(id="c1", action="connector-hook", target="preToolUse",
                  severity="INFO", details="connector=codex action=allow"),
            Event(id="c2", action="connector-hook", target="preToolUse",
                  severity="HIGH", details="connector=codex action=block"),
            Event(id="c3", action="connector-hook", target="postToolUse",
                  severity="MEDIUM", details="connector=codex action=alert"),
            Event(id="x1", action="connector-hook", target="preToolUse",
                  severity="INFO", details="connector=cursor action=allow"),
        ]
    )
    app = DefenseClawTUI(overview_model=overview, audit_model=audit)

    async with app.run_test(size=(170, 50)) as pilot:
        await pilot.pause()
        rows = {row.connector: row for row in app._overview_connector_rows()}
        assert set(rows) == {"codex", "cursor"}

        codex = rows["codex"]
        assert codex.mode == "action"
        assert codex.rule_pack == "strict"
        assert codex.status == "running"
        assert codex.calls == 3
        assert codex.blocks == 1
        assert codex.alerts == 1
        assert codex.last_activity.endswith("ago")

        cursor = rows["cursor"]
        assert cursor.mode == "observe"
        assert cursor.rule_pack == "permissive"
        assert cursor.status == "degraded"
        assert cursor.calls == 1
        assert cursor.blocks == 0


@pytest.mark.asyncio
async def test_overview_disabled_connector_marked_but_still_filterable() -> None:
    """A guardrail-disabled connector keeps its history filterable (stays in
    the chip + roster) but is marked DISABLED — its CONNECTORS row status is
    forced to 'disabled' even though the gateway drops it from connectors[],
    and the chip annotates it '(off)'."""

    import re

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "action"), ("cursor", "observe")),
        connector_packs=(("codex", "strict"), ("cursor", "permissive")),
        connector_disabled=("codex",),
    )
    overview = OverviewPanelModel(cfg, version="test")
    # Gateway drops disabled codex from connectors[] — only cursor is live, and
    # the gateway itself is running (so the naive fallback would be "active").
    overview.set_health(
        HealthSnapshot(
            gateway=SubsystemHealth(state="running"),
            connectors=(ConnectorHealth(name="cursor", state="running"),),
        )
    )
    app = DefenseClawTUI(overview_model=overview, audit_model=AuditPanelModel())

    async with app.run_test(size=(170, 50)) as pilot:
        await pilot.pause()

        rows = {row.connector: row for row in app._overview_connector_rows()}
        # codex stays in the roster (history) but is forced to disabled, not the
        # running gateway-state fallback.
        assert rows["codex"].status == "disabled"
        assert rows["cursor"].status == "running"

        # Still selectable in the shared filter (history is preserved).
        assert "codex" in app._active_connector_names()

        chip = re.sub(r"\[/?[^\]]*\]", "", app._connector_chip_text())
        assert "codex (off)" in chip
        assert "cursor" in chip

        # Filtering by the disabled connector still works.
        app._set_connector_filter("codex")
        assert app._connector_filter() == "codex"


@pytest.mark.asyncio
async def test_overview_enforcement_narrows_to_selected_connector() -> None:
    """8.13: ENFORCEMENT shows global stats under "All", and narrows to the
    selected connector when picked — hook-attributed Alerts/Hook calls/Blocks
    plus Skills/MCPs/scan coverage from that connector's own aibom snapshot
    (not gateway-wide totals). SCANNERS gains a per-connector policy row."""

    import json as _json

    from rich.console import Console

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_enabled=True,
        guardrail_connector="codex",
        connector_modes=(("codex", "action"), ("cursor", "observe")),
        connector_packs=(("codex", "strict"), ("cursor", "permissive")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(
        HealthSnapshot(
            gateway=SubsystemHealth(state="running"),
            connectors=(
                ConnectorHealth(name="codex", state="running"),
                ConnectorHealth(name="cursor", state="running"),
            ),
        )
    )
    audit = AuditPanelModel()
    audit.set_events(
        [
            Event(id="c1", action="connector-hook", target="preToolUse",
                  severity="INFO", details="connector=codex action=allow"),
            Event(id="c2", action="connector-hook", target="preToolUse",
                  severity="HIGH", details="connector=codex action=block"),
            Event(id="c3", action="connector-hook", target="postToolUse",
                  severity="MEDIUM", details="connector=codex action=alert"),
            Event(id="x1", action="connector-hook", target="preToolUse",
                  severity="INFO", details="connector=cursor action=allow"),
        ]
    )
    app = DefenseClawTUI(overview_model=overview, audit_model=audit)

    async with app.run_test(size=(170, 50)) as pilot:
        await pilot.pause()

        # Seed per-connector aibom snapshots so ENFORCEMENT can show real
        # per-connector Skills/MCPs/scan numbers (no live scan in tests).
        codex_inv = _json.dumps(
            {
                "connector": "codex",
                "skills": [
                    {"id": "a", "policy_verdict": "block", "scan_target": "a"},
                    {"id": "b", "policy_verdict": "allow"},
                    {"id": "c"},
                ],
                "mcp": [{"id": "m1"}, {"id": "m2"}],
            }
        )
        cursor_inv = _json.dumps(
            {"connector": "cursor", "skills": [{"id": "z", "policy_verdict": "allow"}]}
        )
        app.inventory_model.show_connector_column = True
        app.inventory_model.apply_merged([("codex", codex_inv), ("cursor", cursor_inv)])
        # Snapshots are loaded, so the one-shot auto-load must stay dormant.
        app._enforcement_inventory_requested = True

        def render() -> str:
            console = Console(width=170, height=80, record=True)
            console.print(app._overview_renderable())
            return console.export_text()

        # "All": global posture, no per-connector framing.
        app._set_connector_filter("")
        all_text = render()
        assert "ENFORCEMENT" in all_text
        assert "ENFORCEMENT · " not in all_text
        assert "Hook calls" in all_text
        assert "Blocks" in all_text

        # Narrow to codex: connector-scoped hook metrics + per-connector
        # Skills/MCPs/scan coverage from codex's aibom snapshot.
        app._set_connector_filter("codex")
        codex_text = render()
        assert "ENFORCEMENT · codex" in codex_text
        assert "Hook calls" in codex_text
        # codex snapshot: 3 skills (1 blocked / 1 allowed), 2 mcps, 1/3 scanned.
        assert "blocked" in codex_text and "allowed" in codex_text
        assert "Scanned" in codex_text
        assert "1/3 assets" in codex_text
        assert "(gateway-wide)" not in codex_text
        # CONFIGURATION and SCANNERS narrow with ENFORCEMENT instead of
        # keeping the generic multi-connector summary.
        assert "CONFIGURATION · codex" in codex_text
        assert "Connector" in codex_text and "Codex (codex)" in codex_text
        assert "Mode" in codex_text and "action" in codex_text
        assert "Rule pack" in codex_text and "strict" in codex_text
        assert "Last activity" in codex_text
        assert "SCANNERS · codex" in codex_text
        assert "policy" in codex_text
        assert "coverage" in codex_text


@pytest.mark.asyncio
async def test_overview_connector_rows_status_falls_back_to_gateway() -> None:
    """When the gateway omits connectors[] (older builds), each row's STATUS
    falls back to the gateway state so the column is never blank."""

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "action"), ("cursor", "observe")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(HealthSnapshot(gateway=SubsystemHealth(state="running")))
    app = DefenseClawTUI(overview_model=overview, audit_model=AuditPanelModel())

    async with app.run_test(size=(170, 50)) as pilot:
        await pilot.pause()
        rows = app._overview_connector_rows()
        assert rows  # multi-connector
        assert all(row.status == "active" for row in rows)


@pytest.mark.asyncio
async def test_overview_connector_rows_empty_for_single_connector() -> None:
    """8.13 no-op: single-connector installs render no CONNECTORS table."""

    cfg = OverviewConfig(data_dir="/tmp/dc", claw_mode="cursor", guardrail_connector="cursor")
    overview = OverviewPanelModel(cfg, version="test")
    app = DefenseClawTUI(overview_model=overview, audit_model=AuditPanelModel())

    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()
        assert app._overview_connector_rows() == []
        assert app._overview_connectors_text([]) == ""


@pytest.mark.asyncio
async def test_overview_enter_drills_into_filtered_alerts() -> None:
    """8.13 drill-down: with a connector selected, Enter on the Overview jumps
    to Alerts, which the shared filter has already scoped to that connector."""

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "action"), ("cursor", "observe")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    app = DefenseClawTUI(overview_model=overview, audit_model=AuditPanelModel())

    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()
        app.active_panel = "overview"
        app._set_connector_filter("cursor")
        await pilot.press("enter")
        await pilot.pause()
        assert app.active_panel == "alerts"
        assert app.alerts_model.connector_filter == "cursor"


def test_connectors_health_array_parsed() -> None:
    """The /health connectors[] array maps into HealthSnapshot.connectors."""

    from defenseclaw.tui.app import _health_snapshot_from_mapping

    snap = _health_snapshot_from_mapping(
        {
            "gateway": {"state": "running"},
            "connector": {"name": "codex", "state": "running"},
            "connectors": [
                {"name": "codex", "state": "running", "requests": 5},
                {"name": "cursor", "state": "degraded"},
                {"state": "running"},  # nameless entry is skipped
            ],
        }
    )
    names = [c.name for c in snap.connectors]
    assert names == ["codex", "cursor"]
    assert snap.connectors[0].requests == 5


# --- A2: _overview_config roster build is defensive -------------------------


class _RosterGuardrail:
    """Guardrail stub with per-connector ``effective_*`` for roster tests."""

    enabled = True
    connector = ""
    mode = "observe"
    hilt = SimpleNamespace(enabled=False, min_severity="")

    def __init__(self, modes=None, disabled=(), raise_on=()):
        self._modes = modes or {}
        self._disabled = set(disabled)
        self._raise_on = set(raise_on)

    def effective_enabled(self, connector):
        return connector not in self._disabled

    def effective_mode(self, connector):
        if connector in self._raise_on:
            raise RuntimeError(f"boom:{connector}")
        return self._modes.get(connector, "observe")

    def effective_rule_pack_dir(self, connector):
        if connector in self._raise_on:
            raise RuntimeError(f"boom:{connector}")
        return ""


def _roster_config(active_connectors, guardrail) -> SimpleNamespace:
    """Minimal config stub exercising :func:`_overview_config`."""

    return SimpleNamespace(
        data_dir="/tmp/dc",
        environment="dev",
        policy_dir="",
        claw=SimpleNamespace(mode="codex"),
        guardrail=guardrail,
        llm=SimpleNamespace(provider="", model=""),
        inspect_llm=SimpleNamespace(provider="", model=""),
        cisco_ai_defense=SimpleNamespace(endpoint=""),
        privacy=SimpleNamespace(disable_redaction=False),
        active_connectors=active_connectors,
    )


def test_overview_config_degrades_when_active_connectors_raises() -> None:
    """A2: a throwing connector enumeration degrades to a single-connector
    view (empty roster) instead of crashing or blanking the whole overview."""

    def boom():
        raise RuntimeError("malformed connector key")

    cfg = _roster_config(boom, _RosterGuardrail())
    overview = _overview_config(cfg)
    assert overview is not None
    assert overview.connector_modes == ()
    # The rest of the config still resolves — only the roster is degraded.
    assert overview.claw_mode == "codex"


def test_overview_config_keeps_other_connectors_when_one_lookup_throws() -> None:
    """A2: one connector whose guardrail lookups raise must not zero the
    roster; the partial roster (all connectors) survives, the bad one blank."""

    guardrail = _RosterGuardrail(
        modes={"codex": "action", "cursor": "observe"}, raise_on={"cursor"}
    )
    cfg = _roster_config(lambda: ["codex", "cursor"], guardrail)
    overview = _overview_config(cfg)
    modes = dict(overview.connector_modes)
    assert list(modes) == ["codex", "cursor"]
    assert modes["codex"] == "action"
    assert modes["cursor"] == ""  # fell back, not dropped


def test_overview_config_skips_malformed_connector_key() -> None:
    """A2: a single malformed (non-string) key is skipped while the valid
    connectors still populate the roster — it is no longer swallowed together
    with the entire roster by one broad ``except``."""

    guardrail = _RosterGuardrail(modes={"codex": "action", "cursor": "observe"})
    cfg = _roster_config(lambda: ["codex", 123, "cursor"], guardrail)
    overview = _overview_config(cfg)
    names = [connector for connector, _mode in overview.connector_modes]
    assert names == ["codex", "cursor"]


def test_overview_config_marks_disabled_connector_in_roster() -> None:
    """A2 (regression baseline): a per-connector kill switch still flags the
    connector as disabled while keeping it in the filterable roster."""

    guardrail = _RosterGuardrail(
        modes={"codex": "action", "cursor": "observe"}, disabled={"cursor"}
    )
    cfg = _roster_config(lambda: ["codex", "cursor"], guardrail)
    overview = _overview_config(cfg)
    names = [connector for connector, _mode in overview.connector_modes]
    assert names == ["codex", "cursor"]
    assert overview.connector_disabled == ("cursor",)


def test_overview_config_no_connectors_yields_empty_claw_mode() -> None:
    """A1 (Root R1, display-only): a genuinely-zero-connector config resolves
    the display connector to "" — never a phantom "openclaw". The adapter passes
    the real (empty) claw.mode so active_connector_name() falls through to ""."""

    cfg = _roster_config(lambda: [], _RosterGuardrail())
    cfg.claw = SimpleNamespace(mode="")
    overview = _overview_config(cfg)
    assert overview.claw_mode == ""
    assert OverviewPanelModel(overview, version="test").active_connector_name() == ""


def test_overview_config_sets_roster_error_when_enumeration_raises() -> None:
    """A2: a throwing active_connectors() stashes a visible diagnostic in
    roster_error (surfaced by the Overview notices) instead of degrading
    silently."""

    def boom():
        raise RuntimeError("malformed connector key")

    cfg = _roster_config(boom, _RosterGuardrail())
    overview = _overview_config(cfg)
    assert "malformed connector key" in overview.roster_error
    # The model turns it into a visible error notice.
    notices = OverviewPanelModel(overview, version="test").build_notices()
    assert any(n.level == "error" for n in notices)


def test_flatten_scanner_overrides_skips_malformed() -> None:
    """N3: a malformed scanner_overrides branch is skipped, not fatal."""

    from defenseclaw.tui.app import _flatten_scanner_overrides

    flat = _flatten_scanner_overrides(
        {
            "mcp": {"LOW": {"runtime": "block", "file": "none"}},
            "bad": "not-a-dict",
            "plugin": {"HIGH": "also-bad"},
        }
    )
    assert ("mcp", "LOW", "runtime", "block") in flat
    assert all(entry[0] != "plugin" for entry in flat)
    assert _flatten_scanner_overrides("nope") == ()


def test_overview_config_reads_scanner_overrides_from_active_policy(tmp_path) -> None:
    """N3: the adapter flattens the active policy's data.json scanner_overrides
    into OverviewConfig so the Overview/status can surface them."""

    rego = tmp_path / "rego"
    rego.mkdir()
    (rego / "data.json").write_text(
        json.dumps(
            {
                "scanner_overrides": {
                    "secrets": {"HIGH": {"file": "block", "install": "warn"}}
                }
            }
        )
    )
    cfg = _roster_config(lambda: ["codex"], _RosterGuardrail())
    cfg.policy_dir = str(tmp_path)
    overview = _overview_config(cfg)
    assert ("secrets", "HIGH", "file", "block") in overview.scanner_overrides
    assert ("secrets", "HIGH", "install", "warn") in overview.scanner_overrides
    assert "secrets" in OverviewPanelModel(overview, version="test").scanner_overrides_summary()


def test_overview_body_renders_scanner_override_summary() -> None:
    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        scanner_overrides=(("secrets", "HIGH", "file", "block"),),
    )
    overview = OverviewPanelModel(cfg, version="test")
    app = DefenseClawTUI(overview_model=overview)

    body = app._overview_body_text(overview.service_cards())  # noqa: SLF001 - render regression surface.

    assert "overrides" in body
    assert "secrets: HIGH file=block" in body


def _multi_connector_app() -> DefenseClawTUI:
    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "enforce"), ("cursor", "observe")),
    )
    return DefenseClawTUI(overview_model=OverviewPanelModel(cfg, version="test"))


@pytest.mark.asyncio
async def test_connector_chip_click_sets_and_clears_filter() -> None:
    """E1: a mouse click on a connector-chip segment applies that filter (the
    coordinate-mapped path that replaces the crash-prone @click action links),
    and clicking the All segment clears it."""

    app = _multi_connector_app()
    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()
        # Render the chip (line 0 of a chip-bearing body) and its click-map.
        app.body_text = app._connector_chip_text() + "list body\nmore body"
        cursor = next(s for s in app._chip_click_segments if s[2] == "cursor")
        assert app._handle_body_chip_click((cursor[0] + cursor[1]) // 2, 0) is True
        assert app._connector_filter() == "cursor"

        # Clicking a non-chip line is ignored regardless of x.
        app.body_text = app._connector_chip_text() + "list body\nmore body"
        assert app._handle_body_chip_click(0, 1) is False

        all_seg = next(s for s in app._chip_click_segments if s[2] == "")
        assert app._handle_body_chip_click((all_seg[0] + all_seg[1]) // 2, 0) is True
        assert app._connector_filter() == ""


@pytest.mark.asyncio
async def test_overview_m_picker_updates_scope_before_deferred_render() -> None:
    """Overview keeps the picker UX while deferring the heavy dashboard repaint."""

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(("codex", "observe"), ("cursor", "observe")),
    )
    overview = OverviewPanelModel(cfg, version="test")
    app = DefenseClawTUI(overview_model=overview)

    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()
        app._overview_renderable()

        assert app._chip_click_segments == []
        assert app._handle_body_chip_click(0, len(_DEFENSECLAW_LOGO.splitlines()) + 2) is False
        scope = app.query_one("#overview-scope", Static)

        def scope_text() -> str:
            return str(scope.render())

        metrics = app.query_one("#overview-metrics", OverviewMetrics)

        def metric_labels() -> set[str]:
            return {tile.metric.label for tile in metrics.query(MetricTile)}

        assert "All connectors" in scope_text()
        assert "Hook Calls (2 connectors)" in metric_labels()

        render_calls = 0
        deferred_calls = 0
        original_renderable = app._overview_renderable

        def counted_renderable():
            nonlocal render_calls
            render_calls += 1
            return original_renderable()

        def counted_deferred_render() -> None:
            nonlocal deferred_calls
            deferred_calls += 1

        app._overview_renderable = counted_renderable  # type: ignore[method-assign]
        app._schedule_overview_deferred_render = counted_deferred_render  # type: ignore[method-assign]

        assert app._connector_filter() == ""
        await pilot.press("m")
        await pilot.pause()
        assert app.screen_stack[-1].__class__.__name__ == "ActionMenuScreen"
        assert app._connector_filter() == ""
        assert render_calls == 0

        await pilot.click("#action-menu-row-1")
        await pilot.pause()
        assert app._connector_filter() == "codex"
        assert "Codex (codex)" in scope_text()
        assert "Hook Calls (codex)" in metric_labels()
        assert render_calls == 0
        assert deferred_calls == 1

        await pilot.press("m")
        await pilot.pause()
        await pilot.click("#action-menu-row-0")
        await pilot.pause()
        assert app._connector_filter() == ""
        assert "All connectors" in scope_text()
        assert "Hook Calls (2 connectors)" in metric_labels()
        assert render_calls == 0
        assert deferred_calls == 2


@pytest.mark.asyncio
async def test_overview_repaints_connector_rows_when_activity_changes_while_scrolled() -> None:
    """Lower CONNECTORS rows update live without idle clock-only body churn."""

    cfg = OverviewConfig(
        data_dir="/tmp/dc",
        claw_mode="codex",
        guardrail_connector="codex",
        connector_modes=(
            ("antigravity", "action"),
            ("claudecode", "observe"),
            ("codex", "observe"),
            ("hermes", "action"),
            ("opencode", "action"),
        ),
    )
    overview = OverviewPanelModel(cfg, version="test")
    overview.set_health(HealthSnapshot(gateway=SubsystemHealth(state="running")))
    audit = AuditPanelModel()
    app = DefenseClawTUI(overview_model=overview, audit_model=audit)

    async with app.run_test(size=(120, 18)) as pilot:
        await pilot.pause()
        scroller = app.query_one("#body-scroll", VerticalScroll)
        assert scroller.max_scroll_y > 0
        scroller.scroll_to(y=scroller.max_scroll_y, animate=False, immediate=True)
        await pilot.pause()

        app._overview_connector_rows_signature_cache = app._overview_connector_rows_signature()
        render_calls = 0

        original_render_chrome = app._render_chrome

        def counted_render_chrome() -> None:
            nonlocal render_calls
            render_calls += 1
            original_render_chrome()

        def immediate_timer(_delay: float, callback, **_kwargs: object) -> object:
            callback()
            return object()

        app._render_chrome = counted_render_chrome  # type: ignore[method-assign]
        app.set_timer = immediate_timer  # type: ignore[method-assign]
        app._overview_last_scroll_activity_at = 0.0

        app._periodic_refresh()
        await pilot.pause()
        assert render_calls == 0

        audit.set_events(
            [
                Event(
                    id="claude-block",
                    timestamp=datetime.now(timezone.utc),
                    action="connector-hook",
                    target="preToolUse",
                    severity="HIGH",
                    details="connector=claudecode action=block",
                )
            ]
        )

        app._periodic_refresh()
        await pilot.pause()

        assert render_calls == 1
        assert app._overview_connector_rows_signature_cache == app._overview_connector_rows_signature()
        rows = {row.connector: row for row in app._overview_connector_rows()}
        assert rows["claudecode"].blocks == 1
        assert rows["claudecode"].last_activity.endswith("ago")


@pytest.mark.asyncio
async def test_setup_m_key_does_not_open_connector_filter_picker() -> None:
    """Setup is an action surface: connector scope is chosen inside wizards,
    not via the shared view filter used by catalog/signal panes."""

    app = _multi_connector_app()
    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()
        app.action_switch_panel("setup")
        await pilot.pause()
        await pilot.press("m")
        await pilot.pause()
        assert app.screen_stack[-1].__class__.__name__ != "ActionMenuScreen"


@pytest.mark.asyncio
async def test_connector_filter_picker_highlights_current_filter() -> None:
    """The `m` picker should visually start on the active shared connector filter."""

    app = _multi_connector_app()
    async with app.run_test(size=(170, 44)) as pilot:
        await pilot.pause()
        app._set_connector_filter("cursor")  # noqa: SLF001 - shared filter state setup.
        app.action_switch_panel("alerts")
        await pilot.pause()
        await pilot.press("m")
        await pilot.pause()

        screen = app.screen_stack[-1]
        menu = screen.query_one(ActionMenu)
        assert menu.selected_index == 2
        assert "cursor" in menu.actions[2].label
        assert "current" in menu.actions[2].label
        assert not menu.query_one("#action-menu-row-0", Button).has_class("-selected")
        assert menu.query_one("#action-menu-row-2", Button).has_class("-selected")


def test_destructive_intent_modal_is_danger_gated() -> None:
    """N1: a destructive catalog intent builds a red-bordered consequence modal
    whose only action is danger-gated (requires the explicit second confirm)."""

    from defenseclaw.tui.app import TOKENS
    from defenseclaw.tui.services.catalog_state import CatalogCommandIntent

    app = DefenseClawTUI()
    intent = CatalogCommandIntent(
        label="remove plugin foo",
        args=("plugin", "remove", "foo"),
        origin="plugins",
        risk="destructive",
    )
    model = app._destructive_intent_modal(intent)
    assert len(model.actions) == 1
    assert model.default_action().danger is True
    assert model.border_color == TOKENS.accent_red
    assert "plugin remove foo" in model.details[0]


@pytest.mark.asyncio
async def test_destructive_intent_routes_through_consequence_modal() -> None:
    """N1: dispatching a destructive catalog intent opens the consequence
    danger-modal (not the one-step command preview), and a single Enter only
    arms it — the command can't run on one keypress."""

    from defenseclaw.tui.services.catalog_state import CatalogCommandIntent

    app = DefenseClawTUI()
    intent = CatalogCommandIntent(
        label="remove plugin foo",
        args=("plugin", "remove", "foo"),
        origin="plugins",
        risk="destructive",
    )
    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.pause()
        app.run_worker(app._confirm_and_run_intent(intent), exclusive=False, thread=False)
        await pilot.pause()
        assert app.screen_stack[-1].__class__.__name__ == "ConsequenceModalScreen"
        # First Enter only arms the danger action; the modal stays open.
        await pilot.press("enter")
        await pilot.pause()
        assert app.screen_stack[-1].__class__.__name__ == "ConsequenceModalScreen"
        # Cancel out without running the command.
        await pilot.press("escape")
        await pilot.pause()
        assert not app.command_running
