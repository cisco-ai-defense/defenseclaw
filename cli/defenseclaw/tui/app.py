"""Initial Textual app shell for the Python TUI backend."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import time
from collections.abc import Iterable
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import monotonic
from typing import Any

from rich.console import Group, RenderableType
from rich.errors import MarkupError, MissingStyle, StyleSyntaxError
from rich.markup import escape as rich_escape
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.text import Text
from textual import events, on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.widgets import Button, DataTable, Input, RichLog, Static, Tab, Tabs

from defenseclaw import __version__
from defenseclaw import config as config_module
from defenseclaw.tui.command_line import (
    CommandLineError,
    ParsedCommand,
    infer_command_risk,
    parse_command_line,
    suggested_next_action,
)
from defenseclaw.tui.executor import CommandAlreadyRunningError, CommandExecutor
from defenseclaw.tui.models import HintState, ServiceStatus, StatusModel
from defenseclaw.tui.panels.activity import ActivityPanelModel
from defenseclaw.tui.panels.ai_discovery import AIDiscoveryPanelModel, AIUsageSnapshot
from defenseclaw.tui.panels.alerts import AlertPanelAction, AlertsPanelModel
from defenseclaw.tui.panels.audit import AuditPanelModel, _parse_kv_details
from defenseclaw.tui.panels.first_run import FirstRunPanelModel
from defenseclaw.tui.panels.inventory import FAST_SCAN_CATEGORIES, InventoryPanelModel
from defenseclaw.tui.panels.logs import (
    FILTER_HOOKS,
    FILTER_LABELS,
    FILTER_PRESETS,
    LOG_SOURCE_LABELS,
    LOG_SOURCES,
    LogsPanelModel,
)
from defenseclaw.tui.panels.mcps import MCPsPanelModel
from defenseclaw.tui.panels.overview import (
    DoctorCache,
    DoctorCheck,
    EnforcementCounts,
    OverviewCommandIntent,
    OverviewConfig,
    OverviewPanelModel,
)
from defenseclaw.tui.panels.plugins import PluginsPanelModel
from defenseclaw.tui.panels.registries import RegistriesPanelModel, RegistryPanelAction
from defenseclaw.tui.panels.setup import (
    WIZARD_DESCRIPTIONS,
    WIZARD_HOW_TO,
    WIZARD_NAMES,
    SetupPanelAction,
    SetupPanelModel,
    SetupWizard,
    connector_setup_command,
    llm_model_candidates,
    render_wizard_value,
    wizard_field_value,
    wizard_state_summary,
)
from defenseclaw.tui.panels.skills import SkillsPanelModel
from defenseclaw.tui.panels.tools import ToolsPanelModel
from defenseclaw.tui.registry import CmdEntry, build_registry
from defenseclaw.tui.screens.command_preview import CommandPreviewScreen, mask_argv
from defenseclaw.tui.screens.config_diff import ConfigDiffScreen
from defenseclaw.tui.screens.consequence import (
    ConsequenceAction,
    ConsequenceModalModel,
    ConsequenceModalScreen,
)
from defenseclaw.tui.screens.detail import DetailScreen
from defenseclaw.tui.screens.judge_history import JudgeHistoryScreen
from defenseclaw.tui.screens.mcp_set_form import MCPSetFormScreen
from defenseclaw.tui.screens.mode_picker import ModePickerScreen
from defenseclaw.tui.screens.model_picker import ModelPickerScreen
from defenseclaw.tui.screens.notifications import NotificationsToggleScreen
from defenseclaw.tui.screens.panel_jumper import PanelChoice, PanelJumperScreen
from defenseclaw.tui.screens.redaction import RedactionToggleScreen
from defenseclaw.tui.screens.setup_resource_editor import (
    SetupResourceEditorScreen,
    SetupResourceResult,
    audit_sink_rows_from_config,
    webhook_rows_from_config,
)
from defenseclaw.tui.screens.theme_picker import ThemePickerScreen
from defenseclaw.tui.screens.trusted_paths_editor import (
    TrustedPathsEditorScreen,
    trusted_paths_rows_from_config,
    untrusted_connector_dir,
)
from defenseclaw.tui.screens.uninstall import UninstallScreen
from defenseclaw.tui.services import connector_filter as connector_filter_svc
from defenseclaw.tui.services.catalog_state import (
    CatalogCommandIntent,
    CatalogListModel,
    CatalogMenuAction,
    CatalogPanelAction,
    catalog_detail_text,
    friendly_connector_name,
)
from defenseclaw.tui.services.cli_choices import CONNECTORS as _KNOWN_CONNECTORS
from defenseclaw.tui.services.overview_state import (
    ConnectorHealth,
    ConnectorOverviewRow,
    HealthSnapshot,
    SubsystemHealth,
)
from defenseclaw.tui.services.setup_state import validate_config_field
from defenseclaw.tui.services.tui_state import TUIStateStore
from defenseclaw.tui.theme import DEFAULT_TOKENS, TEXTUAL_CSS, severity_color, state_color
from defenseclaw.tui.widgets.action_menu import ActionMenuScreen, MenuAction
from defenseclaw.tui.widgets.hint_bar import HintBar
from defenseclaw.tui.widgets.native_metrics import MetricDatum, MetricTile, OverviewMetrics
from defenseclaw.tui.widgets.status_strip import render_status_strip
from defenseclaw.tui.widgets.toasts import ToastLevel, ToastManager, ToastStack

TOKENS = DEFAULT_TOKENS


# Wizard rows whose value changes must re-derive the conditional field groups
# (e.g. picking ``bedrock`` reveals the Bedrock region/auth rows). Keyed by the
# CLI flag for flagged rows, and by the visible label for flag-less rows such as
# the custom-provider ``Action`` selector.
_SETUP_DRIVER_FLAGS: dict[SetupWizard, frozenset[str]] = {
    SetupWizard.LLM: frozenset({"--provider", "--role"}),
    SetupWizard.CUSTOM_PROVIDERS: frozenset({"--base-provider-type"}),
}
_SETUP_DRIVER_LABELS: dict[SetupWizard, frozenset[str]] = {
    # The guardrail judge "Provider" row carries no flag (it is emitted as
    # ``--judge-provider`` by the arg builder), so it must be matched by label.
    SetupWizard.GUARDRAIL: frozenset({"Provider"}),
    SetupWizard.CUSTOM_PROVIDERS: frozenset({"Action"}),
}


_DEFENSECLAW_LOGO = (
    "    ____        ____                   ______\n"
    "   / __ \\___   / __/__  ____  _____ _/ ____/ /__ _      __\n"
    "  / / / / _ \\ / /_/ _ \\/ __ \\/ ___// __/ / / __ \\ | /| / /\n"
    " / /_/ /  __// __/  __/ / / (__  )/ /___/ / /_/ / |/ |/ /\n"
    "/_____/\\___//_/  \\___/_/ /_/____//_____/_/\\__,_/|__/|__/"
)


def _mini_bar(value: int, max_value: int, width: int = 14) -> str:
    """Return a small block-glyph bar suitable for inline use in panels."""

    if max_value <= 0:
        return ""
    ratio = max(0.0, min(1.0, value / max_value))
    filled = int(round(ratio * width))
    return "▰" * filled + "▱" * (width - filled)


PANELS = (
    ("overview", "1", "Overview"),
    ("alerts", "2", "Alerts"),
    ("skills", "3", "Skills"),
    ("mcps", "4", "MCPs"),
    ("plugins", "5", "Plugins"),
    ("inventory", "6", "Inventory"),
    ("logs", "8", "Logs"),
    ("audit", "9", "Audit"),
    ("activity", "A", "Activity"),
    ("ai", "V", "AI Discovery"),
    ("registries", "R", "Registries"),
    ("setup", "0", "Setup"),
)

PANEL_SHORTCUTS = {key.lower(): name for name, key, _label in PANELS}
PANEL_NAMES = {name for name, _key, _label in PANELS}


class _BodyStatic(Static):
    """The shared ``#body`` Static, made mouse-aware for the connector chip.

    E1: the connector-filter chip is rendered as a line of this Static, and
    Textual's ``@click`` action-link markup crashes the compositor when it is
    painted into this shared body (``Style.meta`` ``UnpicklingError`` — see the
    project memory note). So instead of action links, clicks are mapped from
    coordinates here and handed to :meth:`DefenseClawTUI._handle_body_chip_click`,
    which resolves the click to a chip segment (or opens the filter picker).
    """

    def on_click(self, event: events.Click) -> None:
        handler = getattr(self.app, "_handle_body_chip_click", None)
        if handler is not None and handler(event.x, event.y):
            event.stop()


class DefenseClawTUI(App[None]):
    """Textual TUI foundation.

    This first slice intentionally implements shell, routing, command
    input, Activity streaming, and placeholder panels. Full panel parity
    is driven by the migration ledger and the design spec.
    """

    CSS = TEXTUAL_CSS + """
    Screen {
        background: TOKEN_SURFACE_BASE;
        color: TOKEN_TEXT_PRIMARY;
    }

    #root {
        height: 100%;
        width: 100%;
    }

    #header {
        height: 3;
        padding: 0 1;
        background: TOKEN_SURFACE_PANEL;
        border-bottom: heavy TOKEN_BORDER_MUTED;
    }

    #title {
        width: 28;
        color: TOKEN_ACCENT_CYAN;
        text-style: bold;
    }

    #tabs {
        width: 1fr;
        color: TOKEN_TEXT_SECONDARY;
    }

    #command-button,
    #help-button {
        width: 5;
        min-width: 5;
        height: 1;
        margin: 0 0 0 1;
        border: none;
        background: TOKEN_SURFACE_RAISED;
        color: TOKEN_ACCENT_CYAN;
        text-style: bold;
    }

    #body-panel {
        height: 1fr;
        margin: 1 1 0 1;
        padding: 1 2;
        border: none;
        background: TOKEN_SURFACE_BASE;
    }

    #body {
        height: auto;
        margin-bottom: 1;
        color: TOKEN_TEXT_PRIMARY;
    }

    /* Wrapper that lets the Overview body scroll. A bare Static can't
       scroll in Textual, so a tall Overview (many connectors + all the
       panels) clipped the CONNECTORS / AI-agents boxes off-screen. Default
       height:auto keeps it a small header for the DataTable panels; the
       ``overview-scroll`` class makes it fill + scroll only on the Overview. */
    #body-scroll {
        height: auto;
    }

    #body-scroll.overview-scroll {
        height: 1fr;
        overflow-y: auto;
    }

    .panel-controls {
        height: 3;
        margin-bottom: 1;
        padding: 0 1;
        border: round TOKEN_BORDER_MUTED;
        background: TOKEN_SURFACE_RAISED;
    }

    .panel-controls Button {
        height: 1;
        min-width: 8;
        margin: 0 1 0 0;
        border: none;
        background: TOKEN_SURFACE_PANEL;
        color: TOKEN_TEXT_PRIMARY;
    }

    .panel-controls Button.active-chip {
        background: TOKEN_SURFACE_SELECTED;
        color: TOKEN_ACCENT_CYAN;
        text-style: bold;
    }

    .panel-controls Button.severity-critical {
        color: TOKEN_ACCENT_RED;
    }

    .panel-controls Button.severity-high {
        color: TOKEN_ACCENT_ORANGE;
    }

    .panel-controls Button.severity-medium {
        color: TOKEN_ACCENT_AMBER;
    }

    .panel-controls Button.severity-low {
        color: TOKEN_ACCENT_BLUE;
    }

    .panel-controls.hidden {
        display: none;
    }

    /* Catalog filter Input widgets need an explicit narrow width or
       they greedily consume the whole row and push every action
       button off the right edge. 24 cells fits "Filter MCPs by name"
       comfortably while leaving room for the seven-to-ten button
       chips that follow. */
    .panel-controls Input {
        width: 24;
        min-width: 16;
        height: 1;
        margin: 0 1 0 0;
    }

    /* Stdin pipe shown only while a command is actually running so
       operators can finish interactive subprocesses (e.g. typing "3"
       at a `Selection [3]:` prompt) with a click instead of trying
       to forward single keystrokes through the panel handler. */
    #activity-stdin {
        display: none;
        height: 3;
        margin: 0 1;
        border: round TOKEN_BORDER_ACTIVE;
        background: TOKEN_SURFACE_RAISED;
    }

    #activity-stdin.open {
        display: block;
    }

    #overview-metrics {
        margin-bottom: 1;
    }

    .hidden {
        display: none;
    }

    #panel-table {
        height: 1fr;
        border: none;
        background: TOKEN_SURFACE_BASE;
        color: TOKEN_TEXT_PRIMARY;
    }

    #panel-table > .datatable--header {
        background: TOKEN_SURFACE_PANEL;
        color: TOKEN_ACCENT_CYAN;
        text-style: bold;
    }

    #panel-table > .datatable--odd-row,
    #panel-table > .datatable--even-row {
        color: TOKEN_TEXT_PRIMARY;
        background: TOKEN_SURFACE_RAISED;
    }

    #panel-table > .datatable--cursor,
    #panel-table:focus > .datatable--cursor {
        color: TOKEN_TEXT_PRIMARY;
        background: TOKEN_SURFACE_SELECTED;
        text-style: bold;
    }

    #panel-table.hidden {
        display: none;
    }

    #detail-panel {
        height: auto;
        max-height: 16;
        margin-top: 1;
        padding: 1 2;
        border: round TOKEN_BORDER_ACTIVE;
        background: TOKEN_SURFACE_RAISED;
        color: TOKEN_TEXT_PRIMARY;
        overflow-y: auto;
        scrollbar-size-vertical: 1;
    }

    #detail-panel.hidden {
        display: none;
    }

    #detail-panel-body {
        height: auto;
        width: 1fr;
        color: TOKEN_TEXT_PRIMARY;
    }

    #activity {
        height: 11;
        margin: 1;
        padding: 0 1;
        border: round TOKEN_BORDER_MUTED;
        background: TOKEN_SURFACE_RAISED;
    }

    #activity.hidden {
        display: none;
    }

    #command-input {
        display: none;
        margin: 0 1;
        border: round TOKEN_BORDER_ACTIVE;
        background: TOKEN_SURFACE_RAISED;
    }

    #command-input.open {
        display: block;
    }

    #command-palette {
        height: 14;
        margin: 0 1 1 1;
        border: round TOKEN_BORDER_ACTIVE;
        background: TOKEN_SURFACE_PANEL;
    }

    #command-palette > .datatable--header {
        background: TOKEN_SURFACE_RAISED;
        color: TOKEN_ACCENT_CYAN;
        text-style: bold;
    }

    #command-palette > .datatable--cursor,
    #command-palette:focus > .datatable--cursor {
        background: TOKEN_SURFACE_SELECTED;
        color: TOKEN_TEXT_PRIMARY;
        text-style: bold;
    }

    #command-palette.hidden {
        display: none;
    }

    /* The command-progress strip is the single source of truth for
       command lifecycle. Hidden when idle; only visible while running
       or after a finish/rejection awaiting dismissal. Five rows tall
       (2 borders + 3 content rows) so we can show: WHAT ran, WHAT it's
       doing now, and WHAT to do next, without cramming. */
    #command-progress {
        height: 5;
        margin: 0 1;
        padding: 0 1;
        border: round TOKEN_BORDER_MUTED;
        background: TOKEN_SURFACE_RAISED;
    }

    #command-progress.hidden {
        display: none;
    }

    #command-progress.running {
        border: round TOKEN_ACCENT_AMBER;
    }

    #command-progress.success {
        border: round TOKEN_ACCENT_GREEN;
    }

    #command-progress.failure {
        border: round TOKEN_ACCENT_RED;
    }

    #command-progress.rejected {
        border: round TOKEN_ACCENT_RED;
    }

    #command-progress-header {
        height: 1;
        width: 1fr;
    }

    #command-progress-icon {
        width: 3;
        content-align: left middle;
    }

    #command-progress-label {
        width: 1fr;
        content-align: left middle;
        color: TOKEN_TEXT_PRIMARY;
        text-style: bold;
    }

    #command-progress-duration {
        width: auto;
        min-width: 8;
        margin-right: 1;
        content-align: right middle;
        color: TOKEN_TEXT_SECONDARY;
    }

    #command-progress-action {
        width: auto;
        min-width: 11;
        height: 1;
        margin: 0;
        padding: 0 1;
    }

    #command-progress-snippet {
        height: 1;
        width: 1fr;
        color: TOKEN_TEXT_SECONDARY;
        text-style: italic;
    }

    #command-progress-hint {
        height: 1;
        width: 1fr;
        color: TOKEN_TEXT_MUTED;
    }

    #status {
        height: 1;
        padding: 0 1;
        background: TOKEN_SURFACE_RAISED;
        color: TOKEN_TEXT_SECONDARY;
    }

    #hint {
        height: 2;
        padding: 0 1;
        background: TOKEN_SURFACE_SELECTED;
        color: TOKEN_TEXT_PRIMARY;
        text-style: bold;
    }

    .success {
        color: TOKEN_ACCENT_GREEN;
    }

    .failure {
        color: TOKEN_ACCENT_RED;
    }
    """.replace("TOKEN_SURFACE_BASE", TOKENS.surface_base).replace(
        "TOKEN_TEXT_PRIMARY", TOKENS.text_primary
    ).replace("TOKEN_SURFACE_PANEL", TOKENS.surface_panel).replace(
        "TOKEN_BORDER_MUTED", TOKENS.border_muted
    ).replace("TOKEN_ACCENT_CYAN", TOKENS.accent_cyan).replace(
        "TOKEN_TEXT_SECONDARY", TOKENS.text_secondary
    ).replace(
        "TOKEN_TEXT_MUTED", TOKENS.text_muted
    ).replace("TOKEN_SURFACE_RAISED", TOKENS.surface_raised).replace(
        "TOKEN_SURFACE_SELECTED", TOKENS.surface_selected
    ).replace(
        "TOKEN_BORDER_ACTIVE", TOKENS.border_active
    ).replace("TOKEN_ACCENT_GREEN", TOKENS.accent_green).replace(
        "TOKEN_ACCENT_RED", TOKENS.accent_red
    ).replace("TOKEN_ACCENT_ORANGE", TOKENS.accent_orange).replace(
        "TOKEN_ACCENT_BLUE", TOKENS.accent_blue
    ).replace(
        "TOKEN_ACCENT_AMBER", TOKENS.accent_amber
    )

    # Textual >=8.2.0: enable cross-container drag-selection with
    # auto-scroll. Operators routinely want to copy log lines, activity
    # entries, and stretches of catalog tables; in 7.x this was widget-
    # bound and clunky. With auto-scroll on, dragging the selection past
    # the viewport edge scrolls the panel so multi-page selections work
    # naturally. Combined with the ``Y`` (yank) hotkey wired earlier,
    # this is the primary copy-to-clipboard workflow.
    #
    # Tuning rationale:
    #   * ``SELECT_AUTO_SCROLL_LINES`` defaults to 1 — too granular for
    #     our wide log panels. 3 lines/frame matches the visual cadence
    #     of our RichLog scroll speed.
    #   * ``SELECT_AUTO_SCROLL_SPEED`` left at default (50 ms) — faster
    #     than that produced a "snap" effect during testing.
    ENABLE_SELECT_AUTO_SCROLL = True
    SELECT_AUTO_SCROLL_LINES = 3

    BINDINGS = [
        Binding("ctrl+c", "cancel_or_quit", "Cancel/Quit", priority=True),
        Binding("q", "local_close", "Close", show=False),
        Binding("?", "toggle_help", "Help"),
        Binding(":", "open_command", "Command"),
        Binding("ctrl+k", "open_command", "Command"),
        Binding("ctrl+p", "open_panel_jumper", "Jump panel"),
        # Ctrl+\ opens the theme picker. ``\`` was chosen because it's
        # not claimed by readline / GNU terminal conventions, doesn't
        # collide with the setup-wizard's Ctrl+T (reveal secrets), and
        # is reachable on US/UK/Intl keyboards (next to Enter). Theme
        # switching is low-frequency so a unique-but-discoverable key
        # is more useful than a Ctrl+letter that fights with existing
        # bindings.
        Binding("ctrl+backslash", "open_theme_picker", "Theme", show=False),
        # Y / Ctrl+S target the *most recent* Activity entry's output
        # so they work the same from any panel — no need to switch to
        # Activity first just to grab the log. Both are global and
        # priority=False so Input widgets (command drawer, modal
        # forms) absorb the keystroke when they're focused.
        Binding("Y", "yank_output", "Copy last output", show=False),
        Binding("ctrl+s", "save_last_run_log", "Save log", show=False),
        # ``D`` (uppercase) runs ``defenseclaw doctor`` as a quick
        # background health probe and toasts the summary. Distinct
        # from lowercase ``d`` on Overview (which goes through the
        # full preview/streaming pipeline) so operators on any panel
        # can ask "is everything still OK?" without disturbing the
        # current panel or Activity log.
        Binding("D", "run_diagnose", "Diagnose", show=False),
        Binding("tab", "next_panel", "Next"),
        Binding("shift+tab", "previous_panel", "Previous"),
    ]

    def __init__(
        self,
        *,
        config: object | None = None,
        data_dir: str | Path | None = None,
        alerts_model: AlertsPanelModel | None = None,
        registries_model: RegistriesPanelModel | None = None,
        skills_model: SkillsPanelModel | None = None,
        mcps_model: MCPsPanelModel | None = None,
        plugins_model: PluginsPanelModel | None = None,
        tools_model: ToolsPanelModel | None = None,
        logs_model: LogsPanelModel | None = None,
        audit_model: AuditPanelModel | None = None,
        overview_model: OverviewPanelModel | None = None,
        inventory_model: InventoryPanelModel | None = None,
        ai_discovery_model: AIDiscoveryPanelModel | None = None,
        setup_model: SetupPanelModel | None = None,
        first_run_model: FirstRunPanelModel | None = None,
        first_run: bool = False,
    ) -> None:
        super().__init__()
        # Textual defaults to two rows per wheel notch, which makes the dense
        # Overview dashboard feel like it is crawling. Keep this moderate so
        # logs/tables are still controllable while trackpad/wheel scrolling
        # moves a visible chunk of content.
        self.scroll_sensitivity_y = 6.0
        self.first_run_model = first_run_model or FirstRunPanelModel(active=first_run)
        self.executor = CommandExecutor()
        self.config = config
        self.data_dir = _resolve_data_dir(config, data_dir)
        # Operator's persisted session preferences (palette MRU,
        # per-panel "last seen" cursors, last filter, theme).
        # Stored in ``<data_dir>/tui-state.json`` mode 0600. Tokens
        # never live here — only opaque panel/command names.
        self.state_store = TUIStateStore(self.data_dir)
        self.state = self.state_store.load()
        if self.first_run_model.active:
            self.active_panel = "setup"
        else:
            # Plain ``defenseclaw tui`` should always land on the
            # overview dashboard. ``active_panel`` is still written for
            # older state files and unread-badge bookkeeping, but it is
            # intentionally not a launch preference.
            self.active_panel = "overview"
        self.help_open = False
        self.activity_lines: list[str] = []
        self.body_text = ""
        # E1: per-render map of clickable connector-chip segments,
        # ``[(col_start, col_end, connector)]`` in visible columns of the chip
        # line (``connector == ""`` is the All segment). Rebuilt by
        # :meth:`_connector_chip_text` and consumed by
        # :meth:`_handle_body_chip_click`; empty when no chip is shown.
        self._chip_click_segments: list[tuple[int, int, str]] = []
        self.detail_text = ""
        self.status_text = ""
        self.hint_text = ""
        self.command_running = False
        self.command_label = ""
        self._command_started_at: float = 0.0
        # Independent flag for the Shift+D "lightweight doctor" probe.
        # ``command_running`` only tracks the main executor pipeline,
        # so without this we'd let a second Shift+D press spawn a
        # parallel ``defenseclaw doctor`` subprocess.
        self._diagnose_running = False
        self.commands_run = 0
        self.activity_model = ActivityPanelModel()
        audit_store = _audit_store(config)
        self.alerts_model = alerts_model or AlertsPanelModel(self.data_dir, store=audit_store)
        self.registries_model = registries_model or RegistriesPanelModel(config, data_dir=self.data_dir)
        connector = _active_connector(config)
        self.skills_model = skills_model or SkillsPanelModel(connector=connector)
        self.mcps_model = mcps_model or MCPsPanelModel(connector=connector)
        self.plugins_model = plugins_model or PluginsPanelModel(connector=connector)
        self.tools_model = tools_model or ToolsPanelModel(_audit_store(config))
        self.logs_model = logs_model or LogsPanelModel(self.data_dir)
        self.audit_model = audit_model or AuditPanelModel(audit_store)
        self.overview_model = overview_model or OverviewPanelModel(_overview_config(config), version=__version__)
        self.inventory_model = inventory_model or InventoryPanelModel(connector=connector)
        self.ai_discovery_model = ai_discovery_model or AIDiscoveryPanelModel()
        self.setup_model = setup_model or SetupPanelModel(config)
        self.catalog_models: dict[str, CatalogListModel[Any]] = {
            "skills": self.skills_model,
            "mcps": self.mcps_model,
            "plugins": self.plugins_model,
            "tools": self.tools_model,
        }
        # 8.13: the shared connector filter. ``""`` means "All connectors"
        # (the single-connector default and the multi-connector landing
        # state). When set to an active connector name it scopes the
        # Overview tiles, the Alerts/Audit/Logs rows, and (pass 2) the
        # catalog/inventory rows to that connector. Cycled via the connector
        # chip (``m`` in a multi-connector install). Replaces the old
        # "focus one connector at a time" model.
        self.connector_filter = ""
        # One-shot guard: when a connector is selected on the Overview and its
        # per-connector aibom snapshot isn't loaded yet, we kick off the
        # inventory scan once so ENFORCEMENT can show real per-connector
        # Skills/MCPs/scan numbers instead of gateway-wide totals.
        self._enforcement_inventory_requested = False
        self._table_columns: tuple[str, ...] = ()
        self._table_rows: tuple[tuple[str, ...], ...] = ()
        self._periodic_refresh_running = False
        self._slow_refresh_running = False
        self._credentials_refresh_running = False
        self._health_poll_running = False
        self._ai_usage_poll_running = False
        # Fingerprints of the last payload pushed into the body and
        # detail ``Static`` widgets. Textual's ``Static.update`` forces
        # a layout pass even when the content is byte-for-byte
        # identical, so without these guards the 2 s
        # ``_periodic_refresh`` ticker tore the panel body down and
        # rebuilt it every tick — operators saw it as the panel
        # flickering and "switching between Activity and Logs". A
        # ``None`` sentinel means "force a repaint next render".
        self._last_body_signature: tuple[object, ...] | None = None
        self._last_detail_signature: tuple[object, ...] | None = None
        # Same idempotence guard for the shared ``#panel-table`` DataTable.
        # ``_render_panel_table`` clears and rebuilds every row, resets the
        # cursor, and refocuses the table on every call. Under the 2 s
        # ``_periodic_refresh`` ticker that meant the Logs / Audit feeds reset
        # their scroll + cursor twice a second, so operators couldn't read or
        # scroll a row before it jumped back to the top (and the constant
        # ``table.focus()`` stole focus, which read as the UI "jumping"). We
        # now skip the rebuild when the panel, columns, rows, and cursor are
        # all unchanged. ``None`` forces a repaint.
        self._last_table_signature: tuple[object, ...] | None = None
        # Overview renders ask for the same recent hook-event window several
        # times (header metrics, Enforcement, CONNECTORS rows). Cache it for a
        # single frame so keypresses don't wait behind repeated SQLite reads.
        self._connector_hook_event_cache_enabled = False
        self._recent_connector_hook_events_cache: list[Any] | None = None
        self._connector_hook_event_stats_cache: dict[str, dict[str, Any]] | None = None
        self._overview_last_render_scroll_y: float | None = None
        self._overview_last_scroll_activity_at: float = 0.0
        # Set while ``_render_panel_table`` programmatically restores the
        # DataTable cursor. Textual fires ``RowHighlighted`` for that move just
        # like a real keypress, and the handler would call the model's
        # ``set_cursor`` — which for Logs flips ``paused = True``. That
        # silently paused the live log stream the moment the panel opened. The
        # flag lets the handler ignore cursor changes it caused itself.
        self._restoring_table_cursor = False
        # Command-progress strip state machine. The strip is the single
        # source of truth for command lifecycle messaging — what ran,
        # what it's doing, and what to do next. ``idle`` means hidden;
        # any other state keeps the strip on screen until the user
        # explicitly dismisses it (success no longer auto-hides).
        self._strip_state: str = "idle"
        self._strip_label: str = ""
        self._strip_started_at: float = 0.0
        self._strip_frozen_duration: float | None = None
        self._strip_last_output: str = ""
        self._strip_summary: str = ""
        self._strip_spinner_tick: int = 0
        self._command_registry = build_registry()
        self._command_palette_values: list[str] = []
        self._last_table_click: tuple[str, int] | None = None
        # Textual posts Tabs.TabActivated for programmatic ``tabs.active``
        # changes too. Keep a one-shot count for tab ids that _render_chrome
        # selected on behalf of the app so delayed sync messages cannot bounce
        # the operator back to an older tab after rapid mouse clicks.
        self._suppressed_tab_activations: dict[str, int] = {}
        # Auto-dismissing toast queue. Mirrors the Go TUI's
        # ToastManager: cap of MAX_TOASTS (3), TTLs of 4s/4s/6s/8s for
        # info/success/warn/error. The widget itself is mounted in
        # compose() below the activity log; we re-render it whenever
        # push() or tick() mutates the queue.
        self.toasts = ToastManager()
        self._toasts_dirty = False
        # Side-effect probes used by ``_run_command`` to populate
        # ActivityEntry meta. Pre-set to safe defaults so the first
        # command can compare to "before" without crashing on
        # AttributeError when no health poll has fired yet.
        self._last_gateway_started_at: str = ""

    def compose(self) -> ComposeResult:
        # If the startup panel is connector-gated (e.g. embedded first-run
        # setup is hidden by a future gate), fall back to the first visible
        # panel. Otherwise Tabs(active=...) can point at a Tab that is not in
        # the list and Textual raises during validate_active.
        visible_panels = self._visible_panels() or ["overview"]
        if self.active_panel not in visible_panels:
            self.active_panel = visible_panels[0]
        with Vertical(id="root"):
            with Horizontal(id="header"):
                yield Static(f"DefenseClaw {__version__}", id="title")
                yield Tabs(
                    *(
                        Tab(f"{key} {label}", id=f"tab-{name}")
                        for name, key, label in PANELS
                        if not self._panel_hidden(name)
                    ),
                    active=f"tab-{self.active_panel}",
                    id="tabs",
                )
                yield Button(":", id="command-button", compact=True, tooltip="Open command drawer")
                yield Button("?", id="help-button", compact=True, tooltip="Open help")
            with Vertical(id="body-panel"):
                yield OverviewMetrics(self._overview_metric_data(), id="overview-metrics", classes="hidden")
                with VerticalScroll(id="body-scroll"):
                    yield _BodyStatic("", id="body")
                with Horizontal(id="overview-controls", classes="panel-controls hidden"):
                    # Click-first quick-actions that mirror the broken
                    # state of the overview. Each button is shown only
                    # when it would actually do something useful so the
                    # bar doesn't drown the user in disabled chrome.
                    yield Button(
                        "Start Gateway",
                        id="overview-start-gateway",
                        compact=True,
                        variant="success",
                        tooltip="Run `defenseclaw-gateway start`",
                    )
                    yield Button(
                        "Restart Gateway",
                        id="overview-restart-gateway",
                        compact=True,
                        tooltip="Run `defenseclaw-gateway restart`",
                    )
                    yield Button(
                        "Run Doctor",
                        id="overview-run-doctor",
                        compact=True,
                        tooltip="Run `defenseclaw doctor` to refresh health",
                    )
                    yield Button(
                        "Enable AI Discovery",
                        id="overview-enable-ai-discovery",
                        compact=True,
                        variant="success",
                        tooltip="Run `defenseclaw agent discovery enable --yes`",
                    )
                    yield Button(
                        "Scan AI Agents",
                        id="overview-scan-ai-discovery",
                        compact=True,
                        tooltip="Run `defenseclaw agent discovery scan`",
                    )
                    yield Button(
                        "Setup Connector",
                        id="overview-setup-connector",
                        compact=True,
                        tooltip="Open the Connector Setup wizard",
                    )
                    yield Button(
                        "Fill Missing Keys",
                        id="overview-keys-fill",
                        compact=True,
                        tooltip="Run `defenseclaw keys fill-missing`",
                    )
                with Horizontal(id="alerts-controls", classes="panel-controls hidden"):
                    yield Button("All", id="alerts-filter-all", compact=True)
                    yield Button("Critical", id="alerts-filter-critical", compact=True, classes="severity-critical")
                    yield Button("High", id="alerts-filter-high", compact=True, classes="severity-high")
                    yield Button("Medium", id="alerts-filter-medium", compact=True, classes="severity-medium")
                    yield Button("Low", id="alerts-filter-low", compact=True, classes="severity-low")
                    yield Button("Select all", id="alerts-select-all", compact=True)
                    yield Button("Ack selected", id="alerts-ack-selected", compact=True)
                    yield Button("Dismiss filtered", id="alerts-dismiss-filtered", compact=True, variant="warning")
                    yield Button("Dismiss all", id="alerts-dismiss-all", compact=True, variant="error")
                with Horizontal(id="audit-controls", classes="panel-controls hidden"):
                    yield Button("All", id="audit-filter-all", compact=True)
                    yield Button("Risk", id="audit-filter-risk", compact=True, classes="severity-high")
                    yield Button("Blocks", id="audit-filter-blocks", compact=True, classes="severity-critical")
                    yield Button("Scans", id="audit-filter-scans", compact=True, classes="severity-low")
                    yield Button("Credentials", id="audit-filter-credentials", compact=True, classes="severity-medium")
                    yield Button("Same target", id="audit-filter-target", compact=True)
                    yield Button("Same run", id="audit-filter-run", compact=True)
                    yield Button("Export", id="audit-export", compact=True)
                with Horizontal(id="inventory-controls", classes="panel-controls hidden"):
                    yield Button("Summary", id="inventory-tab-summary", compact=True)
                    yield Button("Skills", id="inventory-tab-skills", compact=True)
                    yield Button("Plugins", id="inventory-tab-plugins", compact=True)
                    yield Button("MCPs", id="inventory-tab-mcp", compact=True)
                    yield Button("Agents", id="inventory-tab-agents", compact=True)
                    yield Button("Models", id="inventory-tab-models", compact=True)
                    yield Button("Memory", id="inventory-tab-memory", compact=True)
                    yield Button("All scope", id="inventory-scope-all", compact=True)
                    yield Button("Fast", id="inventory-scope-fast", compact=True)
                    yield Button("Refresh", id="inventory-refresh", compact=True)
                with Horizontal(id="inventory-filter-controls", classes="panel-controls hidden"):
                    yield Button("All", id="inventory-filter-all", compact=True)
                    yield Button("Eligible", id="inventory-filter-eligible", compact=True, classes="severity-low")
                    yield Button("Warning", id="inventory-filter-warning", compact=True, classes="severity-medium")
                    yield Button("Blocked", id="inventory-filter-blocked", compact=True, classes="severity-critical")
                    yield Button("Loaded", id="inventory-filter-loaded", compact=True, classes="severity-low")
                    yield Button("Disabled", id="inventory-filter-disabled", compact=True)
                with Horizontal(id="logs-controls", classes="panel-controls hidden"):
                    yield Button("Gateway", id="logs-source-gateway", compact=True)
                    yield Button("Verdicts", id="logs-source-verdicts", compact=True)
                    yield Button("OTEL", id="logs-source-otel", compact=True)
                    yield Button("Watchdog", id="logs-source-watchdog", compact=True)
                    yield Button("Pause", id="logs-toggle-pause", compact=True)
                    yield Button("Detail", id="logs-open-detail", compact=True)
                    yield Button("Redaction", id="logs-redaction", compact=True)
                    yield Button("Notify", id="logs-notifications", compact=True)
                    yield Button("Judge", id="logs-judge-history", compact=True)
                with Horizontal(id="logs-filter-controls", classes="panel-controls hidden"):
                    yield Button("All", id="logs-filter-0", compact=True)
                    yield Button("No Noise", id="logs-filter-1", compact=True)
                    yield Button("Important", id="logs-filter-2", compact=True)
                    yield Button("Errors", id="logs-filter-3", compact=True, classes="severity-critical")
                    yield Button("Warnings+", id="logs-filter-4", compact=True, classes="severity-medium")
                    yield Button("Scan", id="logs-filter-5", compact=True, classes="severity-low")
                    yield Button("Drift", id="logs-filter-6", compact=True)
                    yield Button("Guardrail", id="logs-filter-7", compact=True)
                    yield Button("Hooks", id="logs-filter-8", compact=True)
                with Horizontal(id="registries-controls", classes="panel-controls hidden"):
                    yield Button("Sources", id="registries-tab-sources", compact=True)
                    yield Button("Entries", id="registries-tab-entries", compact=True)
                    yield Button("Approved", id="registries-tab-approved", compact=True)
                    yield Button("Refresh", id="registries-refresh", compact=True)
                    yield Button("Sync", id="registries-sync-source", compact=True)
                    yield Button("Sync all", id="registries-sync-all", compact=True)
                    yield Button("Approve", id="registries-approve", compact=True)
                    yield Button("Reject", id="registries-reject", compact=True)
                    yield Button("Remove", id="registries-remove-source", compact=True, variant="error")
                with Horizontal(id="setup-controls", classes="panel-controls hidden"):
                    yield Button("Wizards", id="setup-mode-wizards", compact=True)
                    yield Button("Config", id="setup-mode-config", compact=True)
                    yield Button("Open", id="setup-open", compact=True)
                    yield Button("Edit list", id="setup-edit-list", compact=True)
                    yield Button("Save", id="setup-save", compact=True)
                    yield Button("Revert", id="setup-revert", compact=True)
                    yield Button("Restart", id="setup-restart", compact=True)
                    yield Button("Clear restart", id="setup-clear-restart", compact=True)
                    yield Button("Refresh keys", id="setup-refresh-credentials", compact=True)
                with Horizontal(id="setup-wizard-controls", classes="panel-controls hidden"):
                    # Wizard-form sub-bar. Shows only while a wizard form
                    # is open (`setup_model.form_active`). Buttons route
                    # to the same key handlers as Ctrl+R / Esc / Tab /
                    # Ctrl+T / Ctrl+U so mouse-only operators get the
                    # exact same submission, cancellation, and field
                    # navigation semantics as the keystroke flow.
                    yield Button(
                        "Run wizard",
                        id="setup-wizard-run",
                        compact=True,
                        variant="success",
                        tooltip="Submit the wizard (Ctrl+R)",
                    )
                    yield Button(
                        "Cancel",
                        id="setup-wizard-cancel",
                        compact=True,
                        variant="warning",
                        tooltip="Close the wizard form without running (Esc)",
                    )
                    yield Button(
                        "Prev field",
                        id="setup-wizard-prev",
                        compact=True,
                        tooltip="Move to the previous field (Shift+Tab / ↑)",
                    )
                    yield Button(
                        "Next field",
                        id="setup-wizard-next",
                        compact=True,
                        tooltip="Move to the next field (Tab / ↓)",
                    )
                    yield Button(
                        "Toggle reveal",
                        id="setup-wizard-reveal",
                        compact=True,
                        tooltip="Show/hide secret values (Ctrl+T)",
                    )
                    yield Button(
                        "Clear field",
                        id="setup-wizard-clear",
                        compact=True,
                        tooltip="Clear the current field's value (Ctrl+U)",
                    )
                with Horizontal(id="ai-controls", classes="panel-controls hidden"):
                    # AI Discovery panel was view-only — operators had
                    # to leave the panel to enable/disable/scan via the
                    # drawer. These buttons drive the same CLI commands
                    # through `_submit_command_text` so preview gating,
                    # already-running guards, and Activity streaming
                    # keep working. Enable/Disable are mutually
                    # exclusive based on the snapshot's `enabled` flag.
                    yield Button(
                        "Enable AI Discovery",
                        id="ai-enable",
                        compact=True,
                        variant="success",
                        tooltip="Run `defenseclaw agent discovery enable --yes`",
                    )
                    yield Button(
                        "Disable AI Discovery",
                        id="ai-disable",
                        compact=True,
                        variant="warning",
                        tooltip="Run `defenseclaw agent discovery disable --yes`",
                    )
                    yield Button(
                        "Scan now",
                        id="ai-scan",
                        compact=True,
                        tooltip="Run `defenseclaw agent discover` to rescan",
                    )
                    yield Button(
                        "Refresh",
                        id="ai-refresh",
                        compact=True,
                        tooltip="Reload the AI usage snapshot (`agent usage --json`)",
                    )
                    yield Button(
                        "Open agent details",
                        id="ai-open-detail",
                        compact=True,
                        tooltip="Open the highlighted agent's detail view",
                    )
                    yield Button(
                        "Export JSON",
                        id="ai-export",
                        compact=True,
                        tooltip="Save the AI usage snapshot to disk",
                    )
                # ─── Catalog panels (Skills / MCPs / Plugins / Tools) ────────
                # All four panels share ``CatalogListModel`` semantics, so the
                # bars below all map button-id → key → ``handle_key()`` and
                # route through ``_apply_catalog_action``. Each bar carries a
                # visible filter ``Input`` so mouse-only operators get the
                # same ``/ filter`` reach the keyboard flow has. ``j/k``
                # navigation is omitted from the buttons because the
                # underlying ``DataTable`` already handles row clicks +
                # scroll; the bar focuses on the actions that have no
                # equivalent mouse affordance (Scan, Block, Allow, etc.).
                with Horizontal(id="skills-controls", classes="panel-controls hidden"):
                    yield Input(
                        placeholder="Filter skills…",
                        id="skills-filter",
                        compact=True,
                    )
                    yield Button(
                        "Clear",
                        id="skills-filter-clear",
                        compact=True,
                        tooltip="Clear the active filter (same as Esc on the filter prompt)",
                    )
                    yield Button(
                        "Refresh",
                        id="skills-refresh",
                        compact=True,
                        tooltip="Reload skills via `defenseclaw skill list --json` (r)",
                    )
                    yield Button(
                        "Detail",
                        id="skills-detail",
                        compact=True,
                        tooltip="Open detail for the highlighted row (Enter)",
                    )
                    yield Button(
                        "Menu",
                        id="skills-menu",
                        compact=True,
                        tooltip="Open the per-row action menu (o)",
                    )
                    yield Button(
                        "Scan",
                        id="skills-scan",
                        compact=True,
                        tooltip="Run `defenseclaw skill scan <name>` for the highlighted skill (s)",
                    )
                    yield Button(
                        "Block",
                        id="skills-block",
                        compact=True,
                        variant="error",
                        tooltip="Block the highlighted skill (b)",
                    )
                    yield Button(
                        "Allow",
                        id="skills-allow",
                        compact=True,
                        variant="success",
                        tooltip="Allow the highlighted skill (a)",
                    )
                    yield Button(
                        "Registry",
                        id="skills-reveal",
                        compact=True,
                        tooltip="Jump to this skill's entry on the Registries panel (R)",
                    )
                with Horizontal(id="mcps-controls", classes="panel-controls hidden"):
                    yield Input(
                        placeholder="Filter MCPs…",
                        id="mcps-filter",
                        compact=True,
                    )
                    yield Button(
                        "Clear",
                        id="mcps-filter-clear",
                        compact=True,
                        tooltip="Clear the active filter",
                    )
                    yield Button(
                        "Refresh",
                        id="mcps-refresh",
                        compact=True,
                        tooltip="Reload MCPs (r)",
                    )
                    yield Button(
                        "Detail",
                        id="mcps-detail",
                        compact=True,
                        tooltip="Open detail for the highlighted row (Enter)",
                    )
                    yield Button(
                        "Menu",
                        id="mcps-menu",
                        compact=True,
                        tooltip="Open the per-row action menu (o)",
                    )
                    yield Button(
                        "Scan",
                        id="mcps-scan",
                        compact=True,
                        tooltip="Scan the highlighted MCP (s)",
                    )
                    yield Button(
                        "Block",
                        id="mcps-block",
                        compact=True,
                        variant="error",
                        tooltip="Block the highlighted MCP (b)",
                    )
                    yield Button(
                        "Allow",
                        id="mcps-allow",
                        compact=True,
                        variant="success",
                        tooltip="Allow the highlighted MCP (a)",
                    )
                    yield Button(
                        "Add",
                        id="mcps-add",
                        compact=True,
                        variant="primary",
                        tooltip="Open the `mcp set` form to add a new server (n)",
                    )
                    yield Button(
                        "Registry",
                        id="mcps-reveal",
                        compact=True,
                        tooltip="Jump to this MCP's entry on the Registries panel (R)",
                    )
                with Horizontal(id="plugins-controls", classes="panel-controls hidden"):
                    yield Input(
                        placeholder="Filter plugins…",
                        id="plugins-filter",
                        compact=True,
                    )
                    yield Button(
                        "Clear",
                        id="plugins-filter-clear",
                        compact=True,
                        tooltip="Clear the active filter",
                    )
                    yield Button(
                        "Refresh",
                        id="plugins-refresh",
                        compact=True,
                        tooltip="Reload plugins via `defenseclaw plugin list --json` (r)",
                    )
                    yield Button(
                        "Detail",
                        id="plugins-detail",
                        compact=True,
                        tooltip="Open detail for the highlighted row (Enter)",
                    )
                    yield Button(
                        "Menu",
                        id="plugins-menu",
                        compact=True,
                        tooltip="Open the per-row action menu (o)",
                    )
                    yield Button(
                        "Scan",
                        id="plugins-scan",
                        compact=True,
                        tooltip="Scan the highlighted plugin (s)",
                    )
                with Horizontal(id="tools-controls", classes="panel-controls hidden"):
                    yield Input(
                        placeholder="Filter tool policy…",
                        id="tools-filter",
                        compact=True,
                    )
                    yield Button(
                        "Clear",
                        id="tools-filter-clear",
                        compact=True,
                        tooltip="Clear the active filter",
                    )
                    yield Button(
                        "Refresh",
                        id="tools-refresh",
                        compact=True,
                        tooltip="Reload tool policy rows from the audit store (r)",
                    )
                    yield Button(
                        "Detail",
                        id="tools-detail",
                        compact=True,
                        tooltip="Open detail for the highlighted row (Enter)",
                    )
                    yield Button(
                        "Menu",
                        id="tools-menu",
                        compact=True,
                        tooltip="Open the per-row action menu (o)",
                    )
                yield DataTable(
                    id="panel-table",
                    classes="hidden",
                    show_row_labels=False,
                    show_cursor=True,
                    cursor_type="row",
                    zebra_stripes=True,
                )
                # Scroll container so long alert / audit / log details
                # are fully reachable. A bare ``Static`` is not
                # scrollable in Textual (``is_scrollable`` needs a
                # layout or child nodes), so its ``max-height`` silently
                # clipped any detail past ~10 lines — the rich gateway
                # finding + history blocks never showed. The inner
                # ``Static`` carries the renderable; the wrapper scrolls.
                with VerticalScroll(id="detail-panel", classes="hidden"):
                    yield Static("", id="detail-panel-body")
            yield Input(
                placeholder="Type defenseclaw version, doctor, or a TUI alias",
                id="command-input",
                disabled=True,
            )
            yield DataTable(
                id="command-palette",
                classes="hidden",
                show_row_labels=False,
                show_cursor=True,
                cursor_type="row",
                zebra_stripes=True,
            )
            with Vertical(id="command-progress", classes="hidden"):
                with Horizontal(id="command-progress-header"):
                    yield Static(" ", id="command-progress-icon", markup=True)
                    yield Static("", id="command-progress-label", markup=True)
                    yield Static("", id="command-progress-duration", markup=True)
                    yield Button("✕ Cancel", id="command-progress-action", compact=True)
                yield Static("", id="command-progress-snippet", markup=True)
                yield Static("", id="command-progress-hint", markup=True)
            yield RichLog(id="activity", wrap=True, markup=True, highlight=True)
            with Horizontal(id="activity-controls", classes="panel-controls hidden"):
                # Click-first action bar for the Activity panel. Cancel
                # only appears while a command is running; the rest are
                # always visible so operators can pivot to "save the
                # last output", "rerun the last command", or "wipe the
                # scrollback" without leaving the panel. Keystrokes
                # (! rerun, Ctrl+C cancel) keep working unchanged.
                yield Button(
                    "✕ Cancel",
                    id="activity-cancel",
                    compact=True,
                    variant="error",
                    tooltip="Send SIGINT to the running command (same as Ctrl+C)",
                )
                yield Button(
                    "Clear history",
                    id="activity-clear",
                    compact=True,
                    tooltip="Drop completed Activity entries (keeps any running command)",
                )
                yield Button(
                    "Save output…",
                    id="activity-save",
                    compact=True,
                    tooltip="Write the highlighted command's output to a file",
                )
                yield Button(
                    "Rerun last",
                    id="activity-rerun",
                    compact=True,
                    tooltip="Re-invoke the most recent Activity command (same as !)",
                )
                yield Button(
                    "View in Drawer",
                    id="activity-open-drawer",
                    compact=True,
                    tooltip="Open the command drawer to issue a new command",
                )
            # Stdin pipe stays hidden until the executor reports a live
            # command; the CSS `display: none` keeps it out of the
            # layout flow until `_sync_activity_stdin` flips it on.
            stdin_pipe = Input(
                placeholder="Send to running command (Enter to submit; e.g. type 3 to answer Selection [3])",
                id="activity-stdin",
            )
            stdin_pipe.display = False
            yield stdin_pipe
            yield ToastStack(id="toasts")
            yield HintBar(id="hint")
            yield Static("", id="status")

    def on_unmount(self) -> None:
        # Signal background pollers to stop spawning fresh subprocess
        # workers; without this guard our 30 s / 60 s tickers can fire
        # during pytest teardown and leak "Event loop is closed"
        # warnings that flake the visual snapshot suite.
        self._app_shutting_down = True
        # Best-effort final flush of session state so the next launch
        # keeps palette MRU, theme, filters, and per-panel cursors.
        try:
            self.state_store.save()
        except Exception:  # noqa: BLE001
            pass

    def on_mount(self) -> None:
        self._app_shutting_down = False
        # Apply the operator's persisted theme (Textual >=8) before
        # rendering anything: starting on the default and snapping to
        # their choice after the first paint produces a visible flash.
        # Best-effort — an unknown theme id (e.g. state file from a
        # newer build with themes this binary doesn't ship) is silently
        # ignored so the app still starts.
        persisted_theme = (getattr(self.state, "theme", "") or "").strip()
        if persisted_theme:
            try:
                self.theme = persisted_theme
            except Exception:  # noqa: BLE001 - theme apply is cosmetic
                pass
        self._refresh_models_from_disk()
        self.set_interval(0.25, self._tick_command_strip)
        self.set_interval(2.0, self._periodic_refresh)
        self.set_interval(30.0, self._schedule_ai_usage_poll)
        # Mirror Go TUI: poll /health every 3s so the Overview SERVICES
        # box reflects the actual sidecar state instead of "unknown".
        # Run once immediately so the first render isn't blank, then
        # let the interval keep it fresh.
        self.set_interval(3.0, self._schedule_health_poll)
        self._schedule_health_poll()
        self._schedule_ai_usage_poll()
        # Mirror Go's loadCredentialsCmd dispatched from Init(): load
        # the credential snapshot once on mount (and again every 60 s)
        # so Setup readiness rows and the Status strip "missing
        # required credentials" warning are accurate without the
        # operator having to hit 'r' first.
        self.set_interval(60.0, self._schedule_credentials_refresh)
        self._schedule_credentials_refresh()
        # Mirror Go's slowRefreshMsg tick: every 60s re-run the load
        # subprocess for any catalog (Skills/MCPs/Plugins/Tools) and
        # the Inventory panel that the operator has already opened
        # at least once. Panels never visited stay quiet so we don't
        # spin up CLI processes for screens the operator doesn't care
        # about.
        self.set_interval(60.0, self._schedule_slow_refresh)
        self._write_activity(
            "[bold #22D3EE]Textual backend[/] ready. "
            "Go backend remains available with --backend go."
        )
        if self.first_run_model.active:
            self._write_activity("[#FBBF24]First-run setup[/] config is missing; embedded init flow is active.")
        self._render_chrome()

    def _schedule_slow_refresh(self) -> None:
        """Reload catalogs and inventory that the operator has opened.

        Mirrors Go's ``slowRefreshMsg`` ticker. We never refresh a
        catalog the operator has not visited yet — auto-load handles
        that on first visit — to keep the subprocess fan-out
        proportional to actual UI usage.
        """

        if self.config is None or getattr(self, "_app_shutting_down", False):
            return
        if self._slow_refresh_running:
            return
        self._slow_refresh_running = True
        self.run_worker(
            self._run_slow_refresh(),
            exclusive=False,
            thread=False,
        )

    async def _run_slow_refresh(self) -> None:
        try:
            for panel, model in self.catalog_models.items():
                if not getattr(model, "loaded", False):
                    continue
                if panel == "tools":
                    self.tools_model.refresh()
                    continue
                await self._load_catalog_model(panel)
            if getattr(self.inventory_model, "loaded", False):
                await self._load_inventory_model()
        finally:
            self._slow_refresh_running = False

    def on_key(self, event: events.Key) -> None:
        if len(self.screen_stack) > 1:
            return

        command = self.query_one("#command-input", Input)
        if command.has_class("open") or self.focused is command:
            if self._handle_command_palette_key(event):
                event.stop()
            return

        table = self.query_one("#panel-table", DataTable)
        if self.focused is table and event.key in {"up", "down"} and not self._active_overlay_blocks_table():
            return

        if self._handle_active_panel_key(event):
            # The active panel fully consumed this key, so suppress the
            # focused DataTable's built-in bindings too. Without
            # ``prevent_default`` an ``enter`` press ALSO fires the table's
            # ``enter -> select_cursor`` binding, which posts a second
            # ``RowSelected`` and re-toggles the detail view — the AI
            # Discovery detail visibly flickered open/closed on every Enter.
            event.stop()
            event.prevent_default()
            return

        panel = PANEL_SHORTCUTS.get(event.key.lower())
        if panel is None:
            return

        # Connector-gated panels (today: Plugins on non-OpenClaw) keep
        # the digit shortcut mapped so muscle memory does not break,
        # but the keystroke becomes a silent no-op instead of opening
        # an empty placeholder. Mirrors the Go TUI's panelHidden check.
        if self._panel_hidden(panel):
            event.stop()
            return

        self.action_switch_panel(panel)
        event.stop()

    def on_mouse_scroll_down(self, event: events.MouseScrollDown) -> None:
        self._mark_overview_scroll_activity()

    def on_mouse_scroll_up(self, event: events.MouseScrollUp) -> None:
        self._mark_overview_scroll_activity()

    def _mark_overview_scroll_activity(self) -> None:
        if self.active_panel == "overview" and not self.help_open and len(self.screen_stack) <= 1:
            self._overview_last_scroll_activity_at = monotonic()

    def _overview_scroll_activity_recent(self) -> bool:
        if not self._overview_last_scroll_activity_at:
            return False
        return monotonic() - self._overview_last_scroll_activity_at < 0.45

    def _panel_hidden(self, panel: str) -> bool:
        """Return True if ``panel`` should be hidden from tabs + cycling.

        Mirrors Go's ``Model.panelHidden`` (see ``internal/tui/app.go``).
        Today only the Plugins panel is connector-gated — DefenseClaw
        plugins are an OpenClaw-only concept (G4); showing the tab for
        any other connector would yield an empty list and operator
        confusion.

        E3/A4: in a multi-connector install the gate follows the connector
        filter so the tab tracks whatever catalog the operator is looking at,
        and under the merged "All" view it shows whenever OpenClaw is anywhere
        in the active set — not just when it is the primary. Both the tab gate
        (here) and the body/bar render gate route through
        :meth:`_plugins_visible_for_connector` so they always agree.
        """

        if panel != "plugins":
            return False
        return not self._plugins_visible_for_connector()

    def _plugins_visible_for_connector(self) -> bool:
        """Whether the Plugins panel is reachable for the current filter (A4).

        Plugins are an OpenClaw-only concept, so the panel is shown only while
        the operator is looking at OpenClaw's catalog:

        * an explicit filter shows Plugins only when it is OpenClaw;
        * under "All" (or a single-connector install) it shows when OpenClaw
          is the resolved connector, or — in a multi-connector install — when
          OpenClaw is *anywhere* in the active set.

        The last clause is the A4 fix: the singular
        ``PluginsPanelModel.is_visible_for_connector`` gate (fed the primary
        connector under "All") hid Plugins whenever OpenClaw was
        active-but-not-primary (e.g. roster ``[codex, openclaw]``). Resolving
        from the active set here closes that without touching the catalog
        state layer.
        """

        filt = self._connector_filter()
        if filt:
            return filt.lower() == "openclaw"
        if "openclaw" in self._active_connector_names():
            return True
        return _active_connector(self.config).lower() == "openclaw"

    def _visible_panels(self) -> list[str]:
        """Ordered list of panel names that should currently be visible.

        Used by tab cycling and the compose-time tab filter so the two
        always agree on what's reachable for the active connector set.
        """

        return [name for name, _key, _label in PANELS if not self._panel_hidden(name)]

    def _panel_total_count(self, panel: str) -> int:
        """Return the current "interesting items" count for ``panel``.

        Only stream-style panels (alerts, audit, logs, activity, ai)
        return a meaningful count; everything else returns 0 so the
        badge renderer can short-circuit. Defensive ``getattr``
        chains keep this safe to call before models hydrate (e.g.
        during compose() on a brand-new TUI session).
        """

        if panel == "alerts":
            audit_events = getattr(self.alerts_model, "audit_events", ()) or ()
            egress_events = getattr(self.alerts_model, "egress_events", ()) or ()
            return len(audit_events) + len(egress_events)
        if panel == "audit":
            return len(getattr(self.audit_model, "items", ()) or ())
        if panel == "activity":
            return getattr(self.activity_model, "count", 0)
        if panel == "logs":
            lines = getattr(self.logs_model, "lines", {}) or {}
            return sum(len(rows) for rows in lines.values())
        if panel == "ai":
            snapshot = getattr(self.ai_discovery_model, "snapshot", None)
            agents = getattr(snapshot, "agents", ()) if snapshot else ()
            return len(agents)
        return 0

    def _panel_unread_count(self, panel: str) -> int:
        """Return ``max(0, total - seen)`` for the tab-badge renderer.

        Capped at 99 so the tab strip stays one cell wide — anything
        above that is already "lots of new things, just open the
        panel". Skips badging on the currently active panel so the
        cursor doesn't lap itself (you can't have unread content on a
        panel you're staring at).
        """

        if panel == self.active_panel:
            return 0
        total = self._panel_total_count(panel)
        if total <= 0:
            return 0
        try:
            seen = self.state_store.get_seen_count(panel)
        except AttributeError:
            seen = 0
        return min(99, max(0, total - seen))

    def _update_tab_labels(self) -> None:
        """Refresh Tab labels with "(N)" unread badges in-place.

        Called from ``_render_chrome`` so the badges stay in sync with
        whatever just changed (panel switch, model refresh, command
        finish). Silently no-ops when the Tabs widget isn't mounted
        yet (early compose).
        """

        try:
            tabs = self.query_one("#tabs", Tabs)
        except NoMatches:
            return
        for name, key, label in PANELS:
            if self._panel_hidden(name):
                continue
            unread = self._panel_unread_count(name)
            text = f"{key} {label}"
            if unread:
                text = f"{text} ({unread})"
            # Textual >=8.0 ``Tabs.get_tab(id) -> Tab | None`` replaces
            # the older ``query_one("#tab-id", Tab)`` + NoMatches dance.
            # It returns the tab widget directly (or None for unknown
            # ids), so we skip exception-as-control-flow.
            tab = tabs.get_tab(f"tab-{name}")
            if tab is None:
                continue
            # Textual Tab.label accepts either str or rich Text; str
            # is the simplest and avoids markup escaping issues with
            # panel names that contain brackets.
            tab.label = text

    def action_switch_panel(self, panel: str) -> None:
        if panel not in PANEL_NAMES:
            visible = self._visible_panels()
            panel = visible[0] if visible else "overview"
        self.active_panel = panel
        self.help_open = False
        if self.status_text.startswith("backend=textual  panel="):
            self.status_text = ""
        self._render_chrome()
        # Persist the operator's last-active panel + clear the "unread"
        # badge for the panel they just opened. Best-effort: a failed
        # write must never block the UI.
        try:
            self.state_store.set_active_panel(panel)
            self.state_store.mark_seen(panel)
            # Record the current item count too — that's what the tab
            # badge compares against to compute "(N) new since last
            # visit". Without this the badge would stick on every
            # panel forever after the first visit.
            self.state_store.record_seen_count(panel, self._panel_total_count(panel))
            self.state = self.state_store.state
            self.state_store.save()
        except Exception:  # noqa: BLE001 - persistence is cosmetic
            pass
        if panel == "ai" and self.ai_discovery_model.snapshot is None:
            self.run_worker(self._load_ai_discovery_model(), exclusive=False, thread=False)
        # Mirror Go TUI: catalog + inventory panels auto-load on first
        # visit so the operator sees "Loading…" then the rows, instead
        # of an empty list with a small "press r to refresh" hint
        # that's easy to miss. Subsequent visits stay quiet — the slow
        # refresh loop keeps the data fresh from then on.
        if panel in self.catalog_models:
            model = self.catalog_models[panel]
            if not getattr(model, "loaded", False):
                self.run_worker(
                    self._load_catalog_model(panel),
                    exclusive=False,
                    thread=False,
                )
        elif panel == "inventory" and not getattr(self.inventory_model, "loaded", False):
            self.run_worker(
                self._load_inventory_model(),
                exclusive=False,
                thread=False,
            )

    def action_next_panel(self) -> None:
        visible = self._visible_panels()
        if not visible:
            return
        try:
            idx = visible.index(self.active_panel)
        except ValueError:
            # Active panel is currently hidden (e.g. operator landed on
            # Plugins, then the connector flipped). Treat "next" as
            # "first visible" so the operator gets unstuck immediately.
            idx = -1
        self.action_switch_panel(visible[(idx + 1) % len(visible)])

    def action_previous_panel(self) -> None:
        visible = self._visible_panels()
        if not visible:
            return
        try:
            idx = visible.index(self.active_panel)
        except ValueError:
            idx = 0
        self.action_switch_panel(visible[(idx - 1) % len(visible)])

    def action_open_command(self) -> None:
        # Refuse to open the palette while a subprocess is in flight.
        # Otherwise an operator who hit `:` (or Ctrl+K) on top of an
        # interactive ``defenseclaw setup`` ends up with the picker
        # buried under the prompt, types something into the drawer,
        # gets a confusing ``A command is already running`` error, and
        # has no obvious way to forward ``3<Enter>`` to the live
        # stdin. Bouncing them to Activity with explicit instructions
        # is the only safe path that doesn't drop their keystrokes on
        # the floor or fork a second subprocess.
        if self.command_running:
            label = self.command_label or "Previous command"
            if self.active_panel != "activity":
                self.action_switch_panel("activity")
            self._set_status(
                f"{label} is still running. Type its answer here (e.g. a number + Enter) "
                "or press Ctrl+C to cancel before opening a new command."
            )
            return
        command = self.query_one("#command-input", Input)
        command.disabled = False
        command.add_class("open")
        command.display = True
        command.value = ""
        self._render_command_palette("")
        command.focus()
        # Don't carry stale finish/rejection state into a fresh command
        # entry. Idle = strip is hidden, exactly what we want here.
        self._strip_clear()
        self._set_status("Command palette open. Type, use Up/Down, Tab complete, or click a row.")

    def action_open_panel_jumper(self) -> None:
        """Open the Ctrl+P fuzzy panel jumper modal.

        Builds a ``PanelChoice`` per *visible* panel (so the modal
        respects connector gating — no offering Plugins on Claude
        Code) and pushes the modal. The dismiss value is the panel
        name to switch to, or ``None`` to cancel.
        """

        visible = [
            PanelChoice(name=name, label=label, hotkey=key)
            for name, key, label in PANELS
            if not self._panel_hidden(name)
        ]
        if not visible:
            return

        def _on_dismiss(target: str | None) -> None:
            if not target:
                return
            self.action_switch_panel(target)

        self.push_screen(PanelJumperScreen(tuple(visible)), _on_dismiss)

    def action_open_theme_picker(self) -> None:
        """Open the Ctrl+\\ theme picker modal.

        The picker live-previews each theme as the operator scrolls;
        Enter persists the choice to ``TUIState.theme`` and Esc rolls
        back to whatever was active when the modal opened. We pass
        the *currently active* theme into the picker so it opens with
        the cursor on the operator's existing choice rather than the
        list head.
        """

        current = getattr(self, "theme", "") or "textual-dark"

        def _on_dismiss(choice: str | None) -> None:
            if not choice:
                return
            try:
                self.theme = choice
            except Exception:  # noqa: BLE001 - theme apply is cosmetic
                return
            # Persist so the next TUI launch starts with the same
            # palette. Failures are swallowed: theme persistence is
            # ergonomic, not security-critical.
            try:
                self.state_store.set_theme(choice)
                self.state = self.state_store.state
                self.state_store.save()
            except Exception:  # noqa: BLE001 - persistence is cosmetic
                pass
            self.notify_toast("info", f"Theme set to {choice}.")

        self.push_screen(ThemePickerScreen(current_theme=current), _on_dismiss)

    def action_toggle_help(self) -> None:
        self.help_open = not self.help_open
        self._render_chrome()

    @on(Tabs.TabActivated, "#tabs")
    def _on_tab_activated(self, event: Tabs.TabActivated) -> None:
        if event.tab.id is None:
            return
        suppressed = self._suppressed_tab_activations.get(event.tab.id, 0)
        if suppressed > 0:
            if suppressed == 1:
                self._suppressed_tab_activations.pop(event.tab.id, None)
            else:
                self._suppressed_tab_activations[event.tab.id] = suppressed - 1
            return
        panel = event.tab.id.removeprefix("tab-")
        if panel == self.active_panel:
            return
        self.action_switch_panel(panel)

    @on(Button.Pressed, "#command-button")
    def _on_command_button_pressed(self) -> None:
        self.action_open_command()

    @on(Button.Pressed, "#help-button")
    def _on_help_button_pressed(self) -> None:
        self.action_toggle_help()

    @on(Button.Pressed)
    def _on_panel_control_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id.startswith("overview-"):
            event.stop()
            self._handle_overview_control(button_id)
            return
        if button_id.startswith("alerts-"):
            event.stop()
            self._handle_alert_control(button_id)
            return
        if button_id.startswith("audit-"):
            event.stop()
            self._handle_audit_control(button_id)
            return
        if button_id.startswith("inventory-"):
            event.stop()
            self._handle_inventory_control(button_id)
            return
        if button_id.startswith("logs-"):
            event.stop()
            self._handle_logs_control(button_id)
            return
        if button_id.startswith("registries-"):
            event.stop()
            self._handle_registries_control(button_id)
            return
        if button_id.startswith("setup-"):
            event.stop()
            self._handle_setup_control(button_id)
            return
        if button_id.startswith("activity-"):
            event.stop()
            self._handle_activity_control(button_id)
            return
        if button_id.startswith("ai-"):
            event.stop()
            self._handle_ai_control(button_id)
            return
        # All four catalog panels share ``CatalogListModel`` and the
        # ``_apply_catalog_action`` dispatcher, so the button-id →
        # handle_key mapping is uniform. Routing each prefix into its
        # own dispatcher keeps the per-panel intent clear (e.g. mcps
        # has an extra "Add server" key that the others don't).
        if button_id.startswith("skills-"):
            event.stop()
            self._handle_catalog_control("skills", button_id)
            return
        if button_id.startswith("mcps-"):
            event.stop()
            self._handle_catalog_control("mcps", button_id)
            return
        if button_id.startswith("plugins-"):
            event.stop()
            self._handle_catalog_control("plugins", button_id)
            return
        if button_id.startswith("tools-"):
            event.stop()
            self._handle_catalog_control("tools", button_id)
            return

    def action_local_close(self) -> None:
        command = self.query_one("#command-input", Input)
        if command.has_class("open"):
            self._close_command_palette()
            self._set_status("Command drawer closed.")
            return
        if self.help_open:
            self.help_open = False
            self._render_chrome()
            return
        # `q` doubles as the strip's keyboard dismiss. We intentionally
        # never auto-hide on success per UX decision, so this is the
        # primary way users return the strip to idle.
        if self._strip_state != "idle" and self.active_panel != "activity":
            self._strip_clear()
            self._set_status("Cleared command status.")
            return
        self._set_status("q is local close/no-op. Press Ctrl+C to quit.")

    def action_cancel_or_quit(self) -> None:
        if self.command_running or self.executor.is_running:
            self.run_worker(self._cancel_running_command(), exclusive=False, thread=False)
            return
        self.exit()

    def _close_command_palette(self) -> None:
        command = self.query_one("#command-input", Input)
        command.remove_class("open")
        command.disabled = True
        command.display = False
        palette = self.query_one("#command-palette", DataTable)
        palette.add_class("hidden")
        palette.clear(columns=True)
        self._command_palette_values = []
        self.set_focus(None)

    def _handle_command_palette_key(self, event: events.Key) -> bool:
        palette = self.query_one("#command-palette", DataTable)
        command = self.query_one("#command-input", Input)
        if event.key == "escape":
            self._close_command_palette()
            self._set_status("Command drawer closed.")
            return True
        if event.key in {"up", "down"} and self._command_palette_values:
            delta = -1 if event.key == "up" else 1
            target = max(0, min(palette.cursor_row + delta, len(self._command_palette_values) - 1))
            palette.move_cursor(row=target, column=0, animate=False)
            return True
        if event.key == "tab" and self._command_palette_values:
            selected = self._selected_palette_value()
            if selected:
                command.value = selected + " "
                command.cursor_position = len(command.value)
                self._render_command_palette(command.value)
            return True
        return False

    def _render_command_palette(self, query: str) -> None:
        palette = self.query_one("#command-palette", DataTable)
        matches = self._palette_matches(query)
        self._command_palette_values = [entry.tui_name for entry in matches]
        palette.remove_class("hidden")
        palette.clear(columns=True)
        # New 4-column layout: command | cat/risk badge | argv preview
        # | hint. Mirrors the Go TUI's palette so operators get the
        # full "what would actually run" picture before pressing Enter.
        palette.add_columns("Command", "Risk", "Would run", "Needs")
        for index, entry in enumerate(matches):
            name, badge, preview, hint = _palette_row_for_entry(entry)
            palette.add_row(name, badge, preview, hint, key=str(index))
        if matches:
            palette.move_cursor(row=0, column=0, animate=False)
        else:
            palette.add_row(
                "No matching DefenseClaw command",
                "",
                "",
                "Keep typing or use raw defenseclaw ...",
            )

    def _palette_matches(self, query: str, *, limit: int = 12) -> tuple[CmdEntry, ...]:
        normalized = query.strip().lower()
        if normalized.startswith("defenseclaw "):
            normalized = normalized.removeprefix("defenseclaw ").strip()
        if normalized.startswith("defenseclaw-gateway "):
            normalized = normalized.removeprefix("defenseclaw-gateway ").strip()
        terms = tuple(term for term in normalized.split() if term)
        if not terms:
            # Empty query → MRU first, then a small "starter pack" of
            # high-value commands, then the registry tail. MRU lookup
            # is best-effort: a missing palette_mru attribute (e.g. in
            # tests that bypass the state store) falls back to the
            # legacy hardcoded preferred set.
            mru = tuple(getattr(self.state, "palette_mru", ()) or ())
            preferred = ("doctor", "status", "alerts", "scan skill --all", "setup codex", "keys list")
            by_name = {entry.tui_name: entry for entry in self._command_registry}
            seen: set[str] = set()
            head: list[CmdEntry] = []
            for name in (*mru, *preferred):
                if name in seen or name not in by_name:
                    continue
                head.append(by_name[name])
                seen.add(name)
            tail = [entry for entry in self._command_registry if entry.tui_name not in seen]
            return tuple((*head, *tail))[:limit]

        def score(entry: CmdEntry) -> tuple[int, int, str] | None:
            haystack = f"{entry.tui_name} {entry.description} {entry.category}".lower()
            if not all(term in haystack for term in terms):
                return None
            if entry.tui_name.lower().startswith(normalized):
                rank = 0
            elif all(term in entry.tui_name.lower() for term in terms):
                rank = 1
            else:
                rank = 2
            return (rank, len(entry.tui_name), entry.tui_name)

        scored = ((rank, entry) for entry in self._command_registry if (rank := score(entry)) is not None)
        return tuple(entry for _rank, entry in sorted(scored, key=lambda item: item[0])[:limit])

    def _selected_palette_value(self) -> str:
        palette = self.query_one("#command-palette", DataTable)
        return self._palette_value_at(palette.cursor_row)

    def _palette_value_at(self, row: int) -> str:
        if 0 <= row < len(self._command_palette_values):
            return self._command_palette_values[row]
        return ""

    @on(Input.Submitted, "#activity-stdin")
    def _on_activity_stdin_submitted(self, event: Input.Submitted) -> None:
        """Forward Activity-pipe input to the running subprocess.

        Every submission appends ``\n`` so we mirror how a real terminal
        delivers the line — interactive prompts like ``Selection [3]:``
        expect to see a newline before they advance. Empty submissions
        just send the newline (equivalent to "press Enter to accept the
        default") instead of silently dropping the event, which matches
        what an operator hitting Enter on a blank prompt expects.
        """

        if not (self.command_running or self.executor.is_running):
            self._set_status("No command is running — nothing to send.")
            event.input.value = ""
            return
        payload = (event.value or "") + "\n"
        try:
            self.executor.write_stdin(payload)
        except Exception as exc:  # noqa: BLE001 - executor failure should not crash TUI
            self._set_status(f"Send failed: {exc}")
            return
        sent_label = repr(event.value) if event.value else "(blank line)"
        self._set_status(f"Sent {sent_label} to running command.")
        event.input.value = ""
        # Keep focus in the input so the operator can answer multiple
        # prompts in a row (e.g. interactive setup picker with several
        # questions) without re-clicking.
        self.set_focus(event.input)

    @on(Input.Submitted, "#command-input")
    async def _on_command_submitted(self, event: Input.Submitted) -> None:
        # If the operator highlighted a palette suggestion (via ↓ or
        # by clicking a row), prefer that over the raw input text.
        # Otherwise hitting Enter after pressing Down would just run
        # whatever fragment was typed (e.g. ``agent discover`` would
        # invoke ``defenseclaw agent discover enable`` with an extra
        # positional and explode with "Got unexpected extra argument",
        # which was the exact failure mode the user reported).
        self._submit_command_text(self._effective_submit_text(event.value))

    def _effective_submit_text(self, raw_value: str) -> str:
        """Resolve the text to submit, preferring an autocompleted row.

        When the palette is open and a suggestion is highlighted, the
        intent is "run this suggestion" — autocomplete-shell muscle
        memory (fzf, zsh menu-select, IDE pickers all behave this way).
        We only override when the highlighted suggestion *extends* what
        the user typed, so raw ``defenseclaw doctor``-style commands
        still win over an unrelated palette row sitting at row 0.
        """

        typed = raw_value.strip()
        try:
            command = self.query_one("#command-input", Input)
        except Exception:  # noqa: BLE001 - palette teardown can race
            return raw_value
        if not command.has_class("open"):
            return raw_value
        suggestion = self._selected_palette_value().strip()
        if not suggestion or suggestion == typed:
            return raw_value
        # Only override when the suggestion is an extension of the
        # filter typed so far. That covers the autocomplete intent
        # ("agent discov" → highlighted "agent discovery enable")
        # without silently overriding raw commands that happen to land
        # in the palette by coincidence.
        if typed and not suggestion.lower().startswith(typed.lower()):
            return raw_value
        return suggestion

    @on(Input.Changed, "#command-input")
    def _on_command_changed(self, event: Input.Changed) -> None:
        command = self.query_one("#command-input", Input)
        if command.has_class("open"):
            self._render_command_palette(event.value)
            command.focus()

    # Catalog filter Input widgets — keep them all in one place so the
    # pattern (live filter on every keystroke, no Enter required) is
    # uniform across Skills / MCPs / Plugins / Tools. Each handler is a
    # one-line shim because all the panel-specific work lives in
    # ``_on_catalog_filter_input_changed``.
    @on(Input.Changed, "#skills-filter")
    def _on_skills_filter_changed(self, event: Input.Changed) -> None:
        self._on_catalog_filter_input_changed("skills", event.value)

    @on(Input.Changed, "#mcps-filter")
    def _on_mcps_filter_changed(self, event: Input.Changed) -> None:
        self._on_catalog_filter_input_changed("mcps", event.value)

    @on(Input.Changed, "#plugins-filter")
    def _on_plugins_filter_changed(self, event: Input.Changed) -> None:
        self._on_catalog_filter_input_changed("plugins", event.value)

    @on(Input.Changed, "#tools-filter")
    def _on_tools_filter_changed(self, event: Input.Changed) -> None:
        self._on_catalog_filter_input_changed("tools", event.value)

    @on(DataTable.RowSelected, "#command-palette")
    def _on_command_palette_row_selected(self, event: DataTable.RowSelected) -> None:
        event.stop()
        selected = self._palette_value_at(event.cursor_row)
        if selected:
            self._submit_command_text(selected)

    def _submit_command_text(self, value: str) -> None:
        self._close_command_palette()
        stripped = value.strip()
        if not stripped:
            # An empty Enter just dismisses the drawer — don't bother
            # the user with a scary "Rejected: …" toast for nothing.
            self._set_status("Command palette closed (nothing entered).")
            return
        try:
            parsed = parse_command_line(value)
        except CommandLineError as exc:
            selected = self._selected_palette_value()
            if selected and selected != stripped:
                try:
                    parsed = parse_command_line(selected)
                except CommandLineError:
                    selected = ""
            if not selected or selected == stripped:
                # Append an actionable hint instead of just echoing the
                # parser's "Unknown TUI command: defen". Operators were
                # hitting Enter mid-typing (e.g. ``defen``) and getting
                # a bare rejection with no clue what to do next.
                hint = (
                    "type a full command like `defenseclaw doctor`, pick a "
                    "highlighted palette row with Tab/Enter, or Esc to close"
                )
                # Both ``exc`` and ``hint`` flow into a markup-parsed
                # RichLog; either piece may quote argv tokens like ``[skill]``
                # that Rich would mis-parse as a style name and crash the
                # whole TUI mid-frame. Escape both.
                self._write_activity(
                    f"[#F87171]Rejected:[/] {rich_escape(str(exc))}  "
                    f"[#9FB2CC]({rich_escape(hint)})[/]"
                )
                self._strip_rejected(str(exc))
                self._set_status(f"Command rejected — {hint}.")
                return

        # Bare ``defenseclaw setup`` (no subcommand) launches the
        # interactive connector picker, which blocks on stdin and
        # leaves the user stranded in front of a "Selection [3]:"
        # prompt they can't easily answer from inside the TUI. Route
        # those requests to the Connector Setup wizard form, which
        # produces an equivalent non-interactive ``setup <connector>
        # --yes …`` invocation. (The risk classifier still tags this
        # as "setup" risk so the preview path covers any future caller
        # that bypasses this shortcut.)
        if (
            parsed.binary == "defenseclaw"
            and parsed.args == ("setup",)
        ):
            self.action_switch_panel("setup")
            self.setup_model.active_wizard = SetupWizard.CONNECTOR_SETUP
            self.setup_model.open_wizard_form(SetupWizard.CONNECTOR_SETUP)
            self._render_chrome()
            self._set_status(
                "Opened Connector Setup wizard instead of launching the "
                "interactive picker. Pick a connector with ←/→, press Ctrl+R to run."
            )
            return

        if parsed.needs_preview:
            self.run_worker(self._confirm_and_run_parsed(parsed), exclusive=False, thread=False)
            return

        self.run_worker(
            self._run_command(parsed.binary, parsed.args, display_name=parsed.display_name),
            exclusive=False,
            thread=False,
        )

    @on(DataTable.RowHighlighted, "#panel-table")
    def _on_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        # Ignore highlight events that match the cursor the model already
        # holds. Textual fires RowHighlighted both for genuine user
        # navigation AND for the programmatic move_cursor()/clear() that
        # _render_panel_table issues every render. Routing the latter into a
        # model set_cursor() would (for Logs) flip paused=True the moment the
        # panel renders or a filter is applied, silently pausing the live
        # stream. ``_restoring_table_cursor`` covers the synchronous restore;
        # the per-panel current-cursor comparison covers the async highlight
        # events Textual delivers a tick later (e.g. after clear()+add_row()).
        if self._restoring_table_cursor:
            return
        if event.cursor_row == self._active_table_cursor():
            return
        if self.active_panel == "alerts":
            self.alerts_model.set_cursor(event.cursor_row)
        elif self.active_panel == "registries":
            self.registries_model.set_cursor(event.cursor_row)
        elif self.active_panel in self.catalog_models:
            self.catalog_models[self.active_panel].set_cursor(event.cursor_row)
        elif self.active_panel == "logs":
            self.logs_model.set_cursor(event.cursor_row)
        elif self.active_panel == "audit":
            self.audit_model.set_cursor(event.cursor_row)
        elif self.active_panel == "inventory":
            self.inventory_model.set_cursor(event.cursor_row)
        elif self.active_panel == "ai":
            self.ai_discovery_model.set_cursor(event.cursor_row)
        elif self.active_panel == "setup":
            self._set_setup_cursor(event.cursor_row)

    @on(DataTable.RowSelected, "#panel-table")
    def _on_table_row_selected(self, event: DataTable.RowSelected) -> None:
        repeated_click = self._last_table_click == (self.active_panel, event.cursor_row)
        self._last_table_click = (self.active_panel, event.cursor_row)
        if self.active_panel == "alerts":
            self.alerts_model.set_cursor(event.cursor_row)
            if repeated_click:
                self._apply_alert_action(self.alerts_model.handle_key("enter"))
            else:
                self._update_body_only()
        elif self.active_panel == "registries":
            self.registries_model.set_cursor(event.cursor_row)
            if repeated_click:
                self._apply_registry_action(self.registries_model.handle_key("enter"))
            else:
                self._update_body_only()
        elif self.active_panel in self.catalog_models:
            self.catalog_models[self.active_panel].set_cursor(event.cursor_row)
            if repeated_click:
                action = self.catalog_models[self.active_panel].handle_key("enter")
                self._apply_catalog_action(self.active_panel, action)
            else:
                self._update_body_only()
        elif self.active_panel == "logs":
            self.logs_model.set_cursor(event.cursor_row)
            if self.logs_model.source in {"verdicts", "otel"} or repeated_click:
                self._open_logs_detail()
            else:
                self._update_body_only()
        elif self.active_panel == "audit":
            self.audit_model.set_cursor(event.cursor_row)
            if repeated_click:
                self._apply_audit_action(self.audit_model.handle_key("enter"))
            else:
                self._update_body_only()
        elif self.active_panel == "inventory":
            self.inventory_model.set_cursor(event.cursor_row)
            if repeated_click:
                self._apply_inventory_action(self.inventory_model.handle_key("enter"))
            else:
                self._update_body_only()
        elif self.active_panel == "ai":
            self.ai_discovery_model.set_cursor(event.cursor_row)
            if repeated_click:
                self._apply_ai_discovery_action(self.ai_discovery_model.handle_key("enter"))
            else:
                self._update_body_only()
        elif self.active_panel == "setup":
            self._set_setup_cursor(event.cursor_row)
            if repeated_click:
                self._apply_setup_action(self._handle_setup_key("enter"))
            else:
                self._update_body_only()

    async def _run_command(
        self,
        binary: str,
        args: tuple[str, ...],
        *,
        display_name: str | None = None,
    ) -> None:
        """Stream a command through the executor and reflect state in the UI.

        ``display_name`` is the human-readable label surfaced in the
        command-progress strip (the bordered box above the activity log).
        Without it the user only ever saw ``exit 0 in 1.23s`` and could
        not tell which command had finished — the strip looked like an
        empty colored box. Falling back to ``<binary> <args[0]>`` keeps
        the contract simple for callers that don't have a ParsedCommand.
        """

        label = display_name or _derive_command_label(binary, args)
        # Snapshot side-effect probes BEFORE the executor fires so we
        # can decide after the fact whether this command actually
        # reloaded config, restarted the gateway, or refreshed the
        # doctor cache — mirrors Go TUI's CommandResultMeta plumbing.
        masked_argv = tuple(
            (binary, *mask_argv(tuple(args)))
        )
        pre_started_at = self._last_gateway_started_at
        pre_doctor_mtime = self._doctor_cache_mtime()
        try:
            async for event in self.executor.run(binary, args):
                if event.kind == "start":
                    self.command_running = True
                    self.command_label = label
                    self._command_started_at = time.monotonic()
                    self.commands_run += 1
                    self.activity_model.add_entry(event.text, masked_argv=masked_argv)
                    # event.text is the parsed command label (argv joined
                    # with spaces); arguments routinely contain brackets
                    # (e.g. ``defenseclaw scan skill[0]``). Escape so the
                    # markup-parsed RichLog never crashes.
                    self._write_activity(
                        f"[#FBBF24]running[/] {rich_escape(event.text)}"
                    )
                    # The strip is the single source of truth for command
                    # lifecycle. Status text shows the ambient hint so we
                    # don't double up on "running …" in two places.
                    self._strip_running(label)
                    self._refresh_hint()
                elif event.kind == "output":
                    self.activity_model.append_output(event.text)
                    # Subprocess stdout/stderr is the highest-volume crash
                    # source: ``Selection [3]:`` / ``[INFO] foo`` / colored
                    # progress bars all break Rich's markup parser. Hand
                    # the line to the safe writer which escapes brackets.
                    self._write_activity_safe(event.text)
                    # Surface a live tail so users on Overview can see the
                    # wizard prompt or scanner progress without switching
                    # panels. ``_strip_output`` filters whitespace.
                    self._strip_output(event.text)
                elif event.kind == "done":
                    self.command_running = False
                    self.command_label = ""
                    self._command_started_at = 0.0
                    exit_code = event.exit_code or 0
                    # Re-probe side-effect signals AFTER the command
                    # finished. We compare to the snapshot taken before
                    # the executor loop, so a "restart" command that
                    # bumped gateway started_at lights up
                    # ``restart_completed=True`` while a no-op rerun
                    # leaves the flag off.
                    post_started_at = self._last_gateway_started_at
                    post_doctor_mtime = self._doctor_cache_mtime()
                    restart_completed = bool(
                        post_started_at
                        and post_started_at != pre_started_at
                        and exit_code == 0
                    )
                    config_reloaded = restart_completed or (
                        exit_code == 0
                        and binary == "defenseclaw"
                        and args
                        and args[0] in {"setup", "guardrail", "settings", "init", "registry"}
                    )
                    doctor_cache_refreshed = bool(
                        post_doctor_mtime
                        and post_doctor_mtime != pre_doctor_mtime
                        and exit_code == 0
                    )
                    next_hint = suggested_next_action(label, exit_code)
                    self.activity_model.finish_entry(
                        exit_code,
                        config_reloaded=config_reloaded,
                        restart_completed=restart_completed,
                        doctor_cache_refreshed=doctor_cache_refreshed,
                        suggested_next_action=next_hint,
                    )
                    color = "#34D399" if event.exit_code == 0 else "#F87171"
                    self._write_activity(f"[{color}]exit {event.exit_code}[/] in {event.duration:.2f}s")
                    self._strip_finished(event.exit_code or 0, event.duration or 0.0)
                    if event.exit_code == 0:
                        await self._handle_successful_command(binary, args)
                    elif binary == "defenseclaw" and args and args[0] in {"setup", "sandbox", "registry", "keys"}:
                        # A setup-family run failed (non-zero exit). Clear the
                        # "running..." badge so the Setup panel reflects the
                        # actual outcome and the user can retry without first
                        # closing/reopening the wizard.
                        self.setup_model.mark_wizard_complete(args, success=False)
                    self._refresh_models_from_disk()
                    self._render_chrome()
                    self._refresh_hint()
        except CommandAlreadyRunningError as exc:
            # Be explicit about how to resolve the collision. The bare
            # "A command is already running." toast was leaving people
            # stranded in front of an interactive ``defenseclaw setup``
            # picker with no idea how to either answer its prompt or
            # cancel it before launching something else.
            in_flight = self.command_label or "Previous command"
            guidance = (
                f"{in_flight} is still in flight — switch to Activity (press A) to "
                "answer its prompt, or press Ctrl+C to cancel it before starting a "
                "new one."
            )
            # ``exc`` may include user argv (``defenseclaw scan skill[a]``)
            # and ``guidance`` echoes the operator's own command label;
            # both must be escaped before markup parsing.
            self._write_activity(
                f"[#FBBF24]{rich_escape(str(exc))}[/]  "
                f"[#9FB2CC]{rich_escape(guidance)}[/]"
            )
            self._strip_rejected(f"{exc} — {guidance}")
            # The submit code optimistically flagged the wizard row as
            # "running..." before the executor rejected the new run; clear
            # it so the panel doesn't show two spinning wizards forever.
            if binary == "defenseclaw" and args and args[0] in {"setup", "sandbox", "registry", "keys"}:
                self.setup_model.mark_wizard_complete(args, success=False)
            self._refresh_hint()
        except Exception as exc:  # noqa: BLE001
            # Any unexpected executor failure (process spawn error,
            # asyncio cancellation, etc.) must still release the
            # wizard's running badge so operators can retry instead of
            # being stuck staring at a permanently spinning row.
            self.command_running = False
            self.command_label = ""
            self._command_started_at = 0.0
            # Exception messages routinely include argv fragments; escape.
            self._write_activity(
                f"[#F87171]command crashed: {rich_escape(str(exc))}[/]"
            )
            # Treat a crash as finished-but-failed: same dismissable strip,
            # same "press A for full output" affordance. The label stays
            # bound to the original command so users see what blew up.
            self._strip_label = label
            self._strip_last_output = str(exc)
            self._strip_finished(exit_code=1, duration=0.0)
            if binary == "defenseclaw" and args and args[0] in {"setup", "sandbox", "registry", "keys"}:
                self.setup_model.mark_wizard_complete(args, success=False)
            self._refresh_hint()

    def _render_chrome(self) -> None:
        try:
            tabs = self.query_one("#tabs", Tabs)
        except NoMatches:
            return
        tab_id = f"tab-{self.active_panel}"
        if tabs.active != tab_id and tabs.query(f"#{tab_id}"):
            self._suppressed_tab_activations[tab_id] = (
                self._suppressed_tab_activations.get(tab_id, 0) + 1
            )
            tabs.active = tab_id
        # Refresh unread "(N)" badges on every tab whenever chrome
        # re-renders. Cheap (≤ 14 string updates) and keeps the tab
        # strip honest after refresh loops add new alerts / audit
        # entries while the operator is parked on a different panel.
        self._update_tab_labels()
        # A catalog-load worker (or the periodic refresh) can reach here
        # after the screen has begun tearing down, at which point #activity
        # and #body are gone and query_one raises NoMatches — surfacing as
        # WorkerFailed and intermittently failing the TUI catalog tests.
        # Bail out quietly; there is nothing left to render.
        try:
            activity = self.query_one("#activity", RichLog)
            body_widget = self.query_one("#body", Static)
        except NoMatches:
            return
        activity.set_class(self.active_panel != "activity", "hidden")
        # The Overview body can exceed the viewport (metric tiles + notices +
        # SERVICES/CONFIG/ENFORCEMENT/SCANNERS + the CONNECTORS roster), so let
        # its wrapper scroll. DataTable panels keep #body as a short, auto-sized
        # header (the table does its own scrolling), so the class is overview-only.
        overview_active = self.active_panel == "overview" and not self.help_open
        body_scroller: VerticalScroll | None = None
        try:
            body_scroller = self.query_one("#body-scroll", VerticalScroll)
            body_scroller.set_class(overview_active, "overview-scroll")
        except Exception:  # noqa: BLE001 - the wrapper is always present; never break a render.
            pass
        if overview_active:
            current_scroll_y = body_scroller.scroll_y if body_scroller is not None else None
            scrolling_now = (
                current_scroll_y is not None
                and self._overview_last_render_scroll_y is not None
                and current_scroll_y != self._overview_last_render_scroll_y
                and self._last_body_signature is not None
            )
            wheel_active = self._overview_scroll_activity_recent() and self._last_body_signature is not None
            if scrolling_now or wheel_active:
                self._overview_last_render_scroll_y = current_scroll_y
                self._table_columns = ()
                self._table_rows = ()
            else:
                with self._connector_hook_event_render_cache():
                    renderable = self._overview_renderable()
                    body_signature = self._overview_body_signature()
                    if body_signature != self._last_body_signature:
                        body_widget.update(renderable)
                        self._last_body_signature = body_signature
                    self._overview_last_render_scroll_y = current_scroll_y
                    # Overview has no DataTable of its own and skips _body_text()
                    # (the only place these are reset), so clear the panel-table
                    # state here. Otherwise the columns/rows left over from the
                    # previously-viewed Audit/Logs panel survive and
                    # _render_panel_table() paints that stale feed at the bottom
                    # of the overview.
                    self._table_columns = ()
                    self._table_rows = ()
                    self._render_native_widgets()
        else:
            text = self._body_text()
            # Skip the layout-triggering ``Static.update`` when the body
            # content is byte-for-byte unchanged. Logs panel bodies
            # were the worst offender — 5000 lines of streaming text
            # being re-encoded into a Rich ``Text`` and pushed into
            # ``#body`` every 2 s tick is what operators saw as the
            # panel flickering and "switching between Activity and
            # Logs". The fingerprint includes ``help_open`` because
            # toggling the help overlay swaps to a different body
            # without changing ``active_panel``.
            body_signature = (self.active_panel, self.help_open, text)
            if body_signature != self._last_body_signature:
                body_widget.update(self._safe_body_renderable(text))
                self._last_body_signature = body_signature
            self._render_native_widgets()
        self._render_panel_controls()
        self._render_panel_table()
        self._render_detail_panel()
        # The strip's visibility depends on active_panel (it stays hidden
        # on Activity since the live stream is right there), so any panel
        # switch must re-render it.
        self._render_command_strip()
        self._set_status(self.status_text or self._status_text())
        self._refresh_hint()

    @staticmethod
    def _safe_body_renderable(content: str) -> Text:
        """Render a panel body string without ever crashing on markup.

        Panels emit a mix of intentional Rich markup (e.g. the help
        cheatsheet's ``[bold #22D3EE]…[/]`` styles) and untrusted
        characters that happen to use square brackets — literal
        keymap labels like ``[Esc]``, tab labels like ``[1] Commands``,
        and streamed subprocess stdout that can contain *anything*
        (think ``Selection [3]:`` from an interactive picker). The
        latter routinely confuses Rich's markup parser, which then
        raises ``MarkupError`` mid-frame and tears down the periodic
        refresh — that's the crash the operator hit after clicking
        a quick-action button on the overview.

        We first try strict markup parsing (so the intentional styles
        in help/overview keep working) and fall back to a plain-text
        rendering with markup disabled when parsing fails. The
        fallback path also escapes the brackets so downstream
        consumers won't try to re-parse them.

        ``MarkupError`` fires during ``from_markup`` itself, but bad
        style names (``[e] export`` -> style ``e``) only blow up later
        when the renderer calls ``Console.get_style`` and surfaces
        ``MissingStyle``. We catch that too — by validating each span's
        style up front against ``Style.parse`` — so a bogus style in
        any panel body falls back to plain text instead of taking down
        the whole TUI several frames later.
        """

        try:
            text = Text.from_markup(content)
        except MarkupError:
            return Text(content, no_wrap=False)
        try:
            for span in text.spans:
                style = span.style
                if isinstance(style, str) and style:
                    Style.parse(style)
        except (MissingStyle, StyleSyntaxError):
            return Text(content, no_wrap=False)
        return text

    def _help_sections(self) -> list[tuple[str, list[tuple[str, str]]]]:
        """Return the (section title, [(key, description), …]) layout
        for the ``?`` help overlay.

        Sections in display order:
          1. Global — always-available shortcuts (panel switching,
             command drawer, help toggle, quit).
          2. Active panel — context-specific hints for the panel the
             operator is currently looking at. Mirrors what would
             otherwise live in a per-panel inline cheat sheet.
          3. While command running — the small set of keys that work
             only while ``executor.is_running`` is true (e.g. cancel,
             yank output, save log). Showing them in a fixed slot
             means operators don't have to remember which keys "wake
             up" during a subprocess.
        """

        global_section: list[tuple[str, str]] = [
            ("1-9 / 0 / V R A", "Switch panel by hotkey"),
            ("Tab / Shift+Tab", "Next / previous panel"),
            (": or Ctrl+K", "Open command palette"),
            ("Ctrl+P", "Fuzzy panel jumper"),
            ("?", "Toggle this help overlay"),
            ("Ctrl+C", "Cancel running command (or quit when idle)"),
        ]

        # Per-active-panel cheat sheets. Anything we don't have a
        # tailored block for falls through to a "no extra shortcuts"
        # placeholder so the overlay never goes blank on weird panels.
        panel_sheets: dict[str, list[tuple[str, str]]] = {
            "overview": [
                ("s", "Scan all skills"),
                ("d", "Run doctor"),
                ("g", "Setup guardrail"),
                ("m", "Switch connector mode"),
                ("R", "Toggle redaction"),
                ("i / l", "Jump to Inventory / Logs"),
            ],
            "alerts": [
                ("j/k or Up/Down", "Navigate alerts"),
                ("Enter", "Toggle detail pane"),
                ("1-5", "Filter by severity (1=All 2=Crit 3=High 4=Med 5=Low)"),
                ("Space", "Toggle select current alert"),
                ("a / A or X", "Select all filtered / deselect all"),
                ("x", "Acknowledge selected alerts"),
                ("c / C", "Clear filtered / Clear ALL alerts"),
                ("y", "Copy alert details to clipboard"),
            ],
            "skills": [
                ("j/k or Up/Down", "Navigate items"),
                ("/", "Filter"),
                ("r", "Refresh"),
                ("s / b / a", "Scan / block / allow selected"),
                ("o", "Open action menu"),
            ],
            "mcps": [
                ("j/k or Up/Down", "Navigate items"),
                ("/", "Filter"),
                ("r", "Refresh"),
                ("s / b / a", "Scan / block / allow selected"),
                ("o", "Open action menu"),
            ],
            "plugins": [
                ("j/k or Up/Down", "Navigate items"),
                ("/", "Filter"),
                ("r", "Refresh"),
                ("s / b / a", "Scan / block / allow selected"),
            ],
            "inventory": [
                ("j/k or Up/Down", "Navigate items"),
                ("/", "Filter"),
                ("r", "Refresh"),
            ],
            "logs": [
                ("Space", "Pause / resume auto-scroll"),
                ("/", "Search"),
                ("e", "Errors only"),
                ("w", "Warnings+"),
                ("R", "Toggle redaction"),
                ("G / g", "Jump to end / start"),
            ],
            "audit": [
                ("j/k or Up/Down", "Navigate entries"),
                ("/", "Filter"),
                ("e", "Export to JSON"),
                ("Enter", "Open detail"),
            ],
            "activity": [
                ("j/k or Up/Down", "Navigate entries"),
                ("Enter", "Expand / collapse output"),
                ("!", "Rerun last command"),
                ("Y", "Copy selected output"),
                ("Ctrl+S", "Save selected output to file"),
            ],
            "ai": [
                ("j/k or Up/Down", "Navigate agents"),
                ("r", "Refresh discovery"),
                ("e", "Export snapshot"),
            ],
            "registries": [
                ("j/k or Up/Down", "Navigate registries"),
                ("r", "Refresh"),
            ],
            "setup": [
                ("Enter", "Run wizard / step"),
                ("r", "Refresh setup state"),
            ],
        }
        active_keys = panel_sheets.get(
            self.active_panel,
            [("(no panel-specific shortcuts)", "")],
        )
        panel_label = next(
            (label for name, _key, label in PANELS if name == self.active_panel),
            self.active_panel.title(),
        )

        running_section: list[tuple[str, str]] = [
            ("Ctrl+C", "Send SIGINT to the running subprocess"),
            ("!", "Rerun the most recent command"),
            ("Y", "Copy current output to clipboard"),
            ("Ctrl+S", "Save current output to ~/.defenseclaw/tui/last-run.log"),
            ("D", "Run defenseclaw doctor in the background"),
        ]

        return [
            ("Global", global_section),
            (f"Active panel — {panel_label}", active_keys),
            ("While a command is running", running_section),
        ]

    def _render_help_body(self) -> str:
        """Compose the ``?`` help overlay as Rich-markup text.

        Keep the renderer separate from the data so the section list
        can be unit-tested without spinning up the Textual app shell.
        """

        lines: list[str] = [
            # Single-space title — preserves the legacy
            # ``"DefenseClaw Keybindings"`` substring the
            # app-shell test asserts on, while keeping the
            # bold-cyan styling.
            "[bold #22D3EE]DefenseClaw Keybindings[/]",
            "[#475569]" + ("─" * 48) + "[/]",
            "",
        ]
        for title, entries in self._help_sections():
            lines.append(f"[bold #FBBF24]{title}[/]")
            for key, desc in entries:
                # Pad the key column to 22 chars so descriptions
                # line up vertically and the cheat sheet stays
                # scannable at a glance.
                key_text = key.ljust(22)
                if desc:
                    lines.append(f"  [#22D3EE]{key_text}[/] {desc}")
                else:
                    lines.append(f"  {key_text}")
            lines.append("")
        lines.append(
            "[#94A3B8]Press [bold]?[/bold] again to close · "
            "[bold]Esc[/bold] also closes overlays.[/]"
        )
        return "\n".join(lines)

    def _body_text(self) -> str:
        self._table_columns = ()
        self._table_rows = ()
        # E1: clear last render's chip click-map; panels that draw the chip
        # repopulate it via :meth:`_connector_chip_text`.
        self._chip_click_segments = []
        if self.help_open:
            self.body_text = self._render_help_body()
            return self.body_text
        label = next(label for name, _key, label in PANELS if name == self.active_panel)
        if self.active_panel == "overview":
            service_cards = self.overview_model.service_cards()
            self.body_text = self._overview_body_text(service_cards)
            return self.body_text
        if self.active_panel == "activity":
            self.body_text = self.activity_model.render_text()
            return self.body_text
        if self.active_panel == "alerts":
            self._sync_signal_connector_filters()
            self._table_columns = self.alerts_model.data_table_columns()
            self._table_rows = self.alerts_model.data_table_rows()
            empty = self.alerts_model.empty_state()
            suffix = f"\n\n{empty}" if empty else ""
            self.body_text = self._connector_chip_text() + self.alerts_model.summary_text() + suffix
            return self.body_text
        if self.active_panel == "registries":
            self._table_columns = self.registries_model.data_table_columns()
            self._table_rows = self.registries_model.data_table_rows()
            tab = self.registries_model.current_tab.name.title()
            empty = self.registries_model.empty_state()
            suffix = f"\n\n{empty}" if empty else ""
            self.body_text = (
                f"[bold #22D3EE]Registries[/]  {tab}\n"
                "Keys: 1 sources, 2 entries, 3 approved, r refresh, s sync source, S sync all, "
                "a approve, x reject, d remove source."
                f"{suffix}"
            )
            return self.body_text
        if self.active_panel == "inventory":
            self._sync_catalog_connector_filters()
            self._table_columns = self.inventory_model.data_table_columns()
            self._table_rows = self.inventory_model.data_table_rows()
            empty = self.inventory_model.empty_state()
            suffix = f"\n\n{empty}" if empty else ""
            self.body_text = self._inventory_body_text() + suffix
            return self.body_text
        if self.active_panel == "ai":
            self._table_columns = self.ai_discovery_model.data_table_columns()
            self._table_rows = self.ai_discovery_model.data_table_rows()
            detail = ""
            if self.ai_discovery_model.detail_open:
                detail = self._ai_discovery_detail_text()
            empty = self.ai_discovery_model.empty_state()
            header = ", ".join(self.ai_discovery_model.header_parts())
            suffix = f"\n\n{detail}" if detail else f"\n\n{empty}" if empty else ""
            self.body_text = (
                f"[bold #22D3EE]AI Discovery[/]  {header}\n"
                "Keys: r refresh usage, s scan, Enter detail, / filter."
                f"{suffix}"
            )
            return self.body_text
        if self.active_panel == "setup":
            self._table_columns, self._table_rows = self._setup_table()
            self.body_text = self._setup_body_text()
            return self.body_text
        if self.active_panel in self.catalog_models:
            model = self.catalog_models[self.active_panel]
            if self.active_panel == "plugins" and not self._plugins_visible_for_connector():
                self.body_text = f"[bold #22D3EE]Plugins[/]\n\n{self.plugins_model.openclaw_only_notice()}"
                return self.body_text
            self._sync_catalog_connector_filters()
            self._table_columns = model.data_table_columns()
            self._table_rows = model.data_table_rows()
            detail = catalog_detail_text(model.selected()) if model.detail_open else ""
            message = model.message or model.empty_state()
            suffix = f"\n\n{message}" if message and not detail and not model.filtered else ""
            # 8.13: a multi-connector install shows the shared connector
            # filter chip so the operator knows the catalog's current scope
            # and how to change it. Empty for single-connector installs.
            self.body_text = self._connector_chip_text() + model.summary_text(label) + suffix
            return self.body_text
        if self.active_panel == "logs":
            self._sync_signal_connector_filters()
            self._table_columns = self.logs_model.data_table_columns()
            self._table_rows = self.logs_model.data_table_rows()
            self.body_text = self._connector_chip_text() + self._logs_body_text()
            return self.body_text
        if self.active_panel == "audit":
            self._sync_signal_connector_filters()
            self._table_columns = self.audit_model.data_table_columns()
            self._table_rows = self.audit_model.data_table_rows()
            self.body_text = self._connector_chip_text() + self._audit_body_text()
            return self.body_text
        self.body_text = (
            f"[bold #22D3EE]{label}[/]\n\n"
            "Panel placeholder. This panel is reserved in the correct Go TUI order "
            "and will be filled by its parity wave.\n"
            "Keyboard routing, command drawer, Activity, theme, and status strip are already shared foundation."
        )
        return self.body_text

    def _status_text(self) -> str:
        return f"backend=textual  panel={self.active_panel}  hints=: command | ? help | q local close | Ctrl+C quit"

    def _render_native_widgets(self) -> None:
        metrics = self.query_one("#overview-metrics", OverviewMetrics)
        overview_visible = self.active_panel == "overview" and not self.help_open
        metrics.set_class(not overview_visible, "hidden")
        if overview_visible:
            metrics.refresh_metrics(self._overview_metric_data())

    def _render_panel_controls(self) -> None:
        overview = self.query_one("#overview-controls", Horizontal)
        alerts = self.query_one("#alerts-controls", Horizontal)
        audit = self.query_one("#audit-controls", Horizontal)
        inventory = self.query_one("#inventory-controls", Horizontal)
        inventory_filters = self.query_one("#inventory-filter-controls", Horizontal)
        logs = self.query_one("#logs-controls", Horizontal)
        logs_filters = self.query_one("#logs-filter-controls", Horizontal)
        registries = self.query_one("#registries-controls", Horizontal)
        setup = self.query_one("#setup-controls", Horizontal)
        setup_wizard = self.query_one("#setup-wizard-controls", Horizontal)
        activity = self.query_one("#activity-controls", Horizontal)
        ai = self.query_one("#ai-controls", Horizontal)
        # Catalog control bars — Skills/MCPs/Plugins/Tools are independent
        # ``Horizontal`` containers (rather than one shared bar keyed on
        # active_panel) so each panel can advertise the action keys it
        # actually exposes — MCPs has "Add server", Tools omits Scan,
        # etc. Visibility flips identically; per-button availability is
        # handled in ``_sync_catalog_controls``.
        skills = self.query_one("#skills-controls", Horizontal)
        mcps = self.query_one("#mcps-controls", Horizontal)
        plugins = self.query_one("#plugins-controls", Horizontal)
        tools = self.query_one("#tools-controls", Horizontal)
        overview.set_class(self.active_panel != "overview" or self.help_open, "hidden")
        alerts.set_class(self.active_panel != "alerts" or self.help_open, "hidden")
        audit.set_class(self.active_panel != "audit" or self.help_open, "hidden")
        inventory.set_class(self.active_panel != "inventory" or self.help_open, "hidden")
        inventory_filters.set_class(
            self.active_panel != "inventory"
            or self.help_open
            or self.inventory_model.active_sub not in {"skills", "plugins"},
            "hidden",
        )
        logs.set_class(self.active_panel != "logs" or self.help_open, "hidden")
        logs_filters.set_class(self.active_panel != "logs" or self.help_open, "hidden")
        registries.set_class(self.active_panel != "registries" or self.help_open, "hidden")
        setup.set_class(self.active_panel != "setup" or self.help_open, "hidden")
        # Wizard sub-bar is doubly-scoped: panel == setup AND a wizard
        # form is open. Hide it during the wizard list, config editor,
        # and any other panel so the bar doesn't advertise actions
        # that wouldn't fire.
        setup_wizard.set_class(
            self.active_panel != "setup"
            or self.help_open
            or not self.setup_model.form_active,
            "hidden",
        )
        activity.set_class(self.active_panel != "activity" or self.help_open, "hidden")
        ai.set_class(self.active_panel != "ai" or self.help_open, "hidden")
        skills.set_class(self.active_panel != "skills" or self.help_open, "hidden")
        mcps.set_class(self.active_panel != "mcps" or self.help_open, "hidden")
        # Keep the plugins bar panel-scoped. When a connector cannot
        # load plugins, the body renders an explanatory notice and the
        # buttons naturally disable because no row is selected.
        plugins.set_class(self.active_panel != "plugins" or self.help_open, "hidden")
        tools.set_class(self.active_panel != "tools" or self.help_open, "hidden")
        # Stdin pipe is panel-scoped to Activity but command-state-scoped
        # to "executor is busy" — handle it after the per-panel sync so
        # the visibility check sees the freshest state.
        self._sync_activity_stdin()
        if self.active_panel == "overview" and not self.help_open:
            self._sync_overview_controls()
        if self.active_panel == "alerts" and not self.help_open:
            self._sync_alert_controls()
        if self.active_panel == "audit" and not self.help_open:
            self._sync_audit_controls()
        if self.active_panel == "inventory" and not self.help_open:
            self._sync_inventory_controls()
        if self.active_panel == "logs" and not self.help_open:
            self._sync_logs_controls()
        if self.active_panel == "registries" and not self.help_open:
            self._sync_registries_controls()
        if self.active_panel == "setup" and not self.help_open:
            self._sync_setup_controls()
            if self.setup_model.form_active:
                self._sync_setup_wizard_controls()
        if self.active_panel == "activity" and not self.help_open:
            self._sync_activity_controls()
        if self.active_panel == "ai" and not self.help_open:
            self._sync_ai_controls()
        if self.active_panel in self.catalog_models and not self.help_open:
            self._sync_catalog_controls(self.active_panel)

    def _sync_overview_controls(self) -> None:
        """Light up the click-first quick actions for the Overview panel.

        Each button is shown only when it would actually do something
        useful right now (e.g. "Enable AI Discovery" appears only when
        discovery is disabled or offline). Buttons that wouldn't make
        sense for the current state are hidden so the bar doesn't read
        like a static palette dump.
        """

        gateway_state = ""
        cards = self.overview_model.service_cards()
        for card in cards:
            if card.name.lower() == "gateway":
                gateway_state = (card.state or "").lower()
                break
        gateway_offline = gateway_state in {"", "unknown", "down", "stopped", "offline", "error", "failed"}
        gateway_running = gateway_state in {"running", "ok", "healthy", "up"}

        ai_box = self.overview_model.ai_discovery_box()
        ai_status = (ai_box.status or "").lower()
        ai_can_enable = ai_status in {"disabled", "offline"}
        ai_can_scan = ai_status in {"empty", "ready"}

        doctor = getattr(self.overview_model, "doctor", None)
        doctor_failed = bool(doctor and getattr(doctor, "failed", 0))

        connector_present = bool(self.overview_model.active_connector_name())

        keys = self.overview_model.keys_status()
        keys_missing = bool(getattr(keys, "missing", None))

        self._set_button_visible("#overview-start-gateway", gateway_offline)
        self._set_button_visible("#overview-restart-gateway", gateway_running)
        self._set_button_visible("#overview-run-doctor", True)
        self._set_button_active("#overview-run-doctor", doctor_failed)
        self._set_button_visible("#overview-enable-ai-discovery", ai_can_enable)
        self._set_button_visible("#overview-scan-ai-discovery", ai_can_scan)
        self._set_button_visible("#overview-setup-connector", not connector_present)
        self._set_button_visible("#overview-keys-fill", keys_missing)

    def _set_button_visible(self, selector: str, visible: bool) -> None:
        try:
            button = self.query_one(selector, Button)
        except Exception:  # noqa: BLE001 - button missing during teardown
            return
        button.set_class(not visible, "hidden")
        # Disable hidden buttons too so they can't steal keyboard focus.
        button.disabled = not visible

    def _sync_alert_controls(self) -> None:
        active = (self.alerts_model.severity_filter or "all").lower()
        for key in ("all", "critical", "high", "medium", "low"):
            self._set_button_active(f"#alerts-filter-{key}", active == key)
        selected = len(self.alerts_model.selected_ids)
        filtered = len(self.alerts_model.filtered_ids())
        self.query_one("#alerts-ack-selected", Button).disabled = selected == 0
        self.query_one("#alerts-dismiss-filtered", Button).disabled = filtered == 0
        self.query_one("#alerts-dismiss-all", Button).disabled = not self.alerts_model.filtered

    def _sync_audit_controls(self) -> None:
        active = self.audit_model.common_filter or "all"
        for key in ("all", "risk", "blocks", "scans", "credentials"):
            self._set_button_active(f"#audit-filter-{key}", active == key)
        self._set_button_active("#audit-filter-target", bool(self.audit_model.correlation_target))
        self._set_button_active("#audit-filter-run", bool(self.audit_model.correlation_run_id))
        selected = self.audit_model.selected()
        self.query_one("#audit-filter-target", Button).disabled = selected is None or not bool(selected.target)
        self.query_one("#audit-filter-run", Button).disabled = selected is None or not bool(selected.run_id)
        self.query_one("#audit-export", Button).disabled = not bool(self.audit_model.filtered)

    def _sync_inventory_controls(self) -> None:
        for tab in self.inventory_model.subtab_info():
            self._set_button_active(f"#inventory-tab-{tab.subtab}", tab.active)
        self._set_button_active("#inventory-scope-all", not bool(self.inventory_model.category_scope))
        self._set_button_active("#inventory-scope-fast", self.inventory_model.is_fast_scan())
        active_filter = self.inventory_model.filter or "all"
        for key in ("all", "eligible", "warning", "blocked", "loaded", "disabled"):
            self._set_button_active(f"#inventory-filter-{key}", active_filter == key)
        skills_mode = self.inventory_model.active_sub == "skills"
        plugins_mode = self.inventory_model.active_sub == "plugins"
        self.query_one("#inventory-filter-eligible", Button).disabled = not skills_mode
        self.query_one("#inventory-filter-warning", Button).disabled = not skills_mode
        self.query_one("#inventory-filter-loaded", Button).disabled = not plugins_mode
        self.query_one("#inventory-filter-disabled", Button).disabled = not plugins_mode

    def _sync_logs_controls(self) -> None:
        for source in LOG_SOURCES:
            self._set_button_active(f"#logs-source-{source}", self.logs_model.source == source)
        self._set_button_active("#logs-toggle-pause", self.logs_model.paused)
        self.query_one("#logs-judge-history", Button).disabled = self.logs_model.source != "verdicts"
        for index, preset in enumerate(FILTER_PRESETS):
            self._set_button_active(f"#logs-filter-{index}", self.logs_model.filter_mode == preset)

    def _sync_registries_controls(self) -> None:
        active = self.registries_model.current_tab.name.lower()
        for key in ("sources", "entries", "approved"):
            self._set_button_active(f"#registries-tab-{key}", active == key)
        selected_source = self.registries_model.selected_source()
        selected_entry = self.registries_model.selected_entry()
        entry_tab = active in {"entries", "approved"}
        self.query_one("#registries-sync-source", Button).disabled = not bool(selected_source or selected_entry)
        self.query_one("#registries-approve", Button).disabled = not entry_tab or selected_entry is None
        self.query_one("#registries-reject", Button).disabled = not entry_tab or selected_entry is None
        self.query_one("#registries-remove-source", Button).disabled = active != "sources" or selected_source is None

    def _sync_setup_controls(self) -> None:
        self._set_button_active("#setup-mode-wizards", self.setup_model.mode == "wizards")
        self._set_button_active("#setup-mode-config", self.setup_model.mode == "config")
        current = self.setup_model.current_section()
        self.query_one("#setup-edit-list", Button).disabled = not (
            self.setup_model.mode == "config"
            and current is not None
            and current.name in {"Audit Sinks", "Webhooks"}
        )
        self.query_one("#setup-save", Button).disabled = self.setup_model.mode != "config"
        self.query_one("#setup-revert", Button).disabled = self.setup_model.mode != "config"
        self.query_one("#setup-restart", Button).disabled = not self.setup_model.restart_queue.pending
        self.query_one("#setup-clear-restart", Button).disabled = not self.setup_model.restart_queue.pending

    def _sync_setup_wizard_controls(self) -> None:
        """Light up the wizard form action bar to match the live form state.

        Run is disabled when there are still required fields to fill
        in — the same gate ``submit_wizard_form()`` enforces — so the
        button can't pretend to work when it would only surface an
        error. Toggle reveal is enabled iff the focused field's kind
        is ``password``, matching Ctrl+T's no-op behaviour elsewhere.
        Clear is enabled only on free-text-ish kinds the keystroke
        handler accepts text into. Prev/Next are always enabled while
        the form is open (Tab/Shift+Tab parity).
        """

        model = self.setup_model
        missing = model.missing_required_fields()
        try:
            run_button = self.query_one("#setup-wizard-run", Button)
        except NoMatches:
            return
        run_button.disabled = bool(missing)
        run_button.tooltip = (
            f"Missing required field(s): {', '.join(missing)}"
            if missing
            else "Submit the wizard (Ctrl+R)"
        )
        self.query_one("#setup-wizard-cancel", Button).disabled = False
        has_navigable = any(field.kind != "section" for field in model.form_fields)
        self.query_one("#setup-wizard-prev", Button).disabled = not has_navigable
        self.query_one("#setup-wizard-next", Button).disabled = not has_navigable
        # Field kinds: see ``WizardFieldKind`` in panels/setup.py —
        # only "password" surfaces secret-reveal semantics, and only
        # the typed-input kinds accept Ctrl+U as a meaningful clear.
        focused = model.focused_row_metadata()
        focused_kind = getattr(focused, "kind", "") if focused is not None else ""
        self.query_one("#setup-wizard-reveal", Button).disabled = focused_kind != "password"
        clearable_kinds = {"string", "password", "int"}
        self.query_one("#setup-wizard-clear", Button).disabled = focused_kind not in clearable_kinds

    def _sync_activity_controls(self) -> None:
        """Toggle Activity action-bar buttons to match the live state.

        Cancel only appears while a command is running so the bar
        doesn't read like a fake offer when there's nothing to cancel.
        Save/Rerun are disabled (greyed) instead of hidden when there's
        no history yet — they're permanent fixtures and disappearing
        them on every fresh launch would feel jittery.
        """

        running = bool(self.command_running or self.executor.is_running)
        self._set_button_visible("#activity-cancel", running)
        has_history = bool(self.activity_model.entries)
        self.query_one("#activity-clear", Button).disabled = not has_history
        self.query_one("#activity-save", Button).disabled = not has_history
        rerun_disabled = (not self.activity_model.last_command) or running
        self.query_one("#activity-rerun", Button).disabled = rerun_disabled

    def _sync_activity_stdin(self) -> None:
        """Show the send-to-stdin Input only while a command is running.

        The pipe forwards bytes through ``executor.write_stdin`` so the
        operator can answer interactive prompts (e.g. ``Selection [3]:``)
        with a click rather than trying to type individual keystrokes
        through ``_forward_activity_stdin``. We only show it on Activity
        — operators monitoring Logs or Audit don't need an input field
        hanging around.
        """

        try:
            stdin = self.query_one("#activity-stdin", Input)
        except NoMatches:
            return
        running = bool(self.command_running or self.executor.is_running)
        want_open = running and self.active_panel == "activity" and not self.help_open
        is_open = stdin.has_class("open")
        if want_open and not is_open:
            stdin.add_class("open")
            stdin.display = True
        elif not want_open and is_open:
            stdin.remove_class("open")
            stdin.display = False
            stdin.value = ""

    def _sync_ai_controls(self) -> None:
        """Toggle AI Discovery action-bar buttons to match the snapshot.

        Enable/Disable are mutually exclusive — we hide the one that
        doesn't apply so the bar reads as "what can I do right now?"
        instead of "here's every button, half of them are a no-op".
        Open agent details / Export are disabled (greyed) when there's
        no row highlighted / no snapshot loaded — they're permanent
        fixtures so disappearing them on every load would feel jittery.
        """

        snapshot = self.ai_discovery_model.snapshot
        enabled = bool(snapshot and snapshot.enabled)
        # When the snapshot is missing entirely (offline / never loaded)
        # we don't know whether discovery is on, so default to offering
        # Enable; the existing CLI flag is idempotent so this is safe.
        snapshot_known = snapshot is not None
        self._set_button_visible("#ai-enable", (not enabled) or (not snapshot_known))
        self._set_button_visible("#ai-disable", enabled)
        # Scan only makes sense when discovery is on — discover requires
        # the daemon to be running, otherwise the CLI errors out.
        self._set_button_visible("#ai-scan", enabled)
        self.query_one("#ai-refresh", Button).disabled = False
        # Open agent details requires a highlighted row.
        self.query_one("#ai-open-detail", Button).disabled = self.ai_discovery_model.selected() is None
        # Export needs an actual snapshot.
        self.query_one("#ai-export", Button).disabled = snapshot is None

    # Per-catalog-panel button-id → key map. Each catalog panel routes
    # its action bar through ``handle_key`` so the click flow is
    # byte-for-byte equivalent to the keystroke flow (preview gating,
    # already-running guards, action-menu opening, etc. all share the
    # same code path). Buttons that don't have a key equivalent
    # (e.g. ``Detail`` opens a row instead of toggling the model's
    # filter prompt) are routed through ``_apply_catalog_action`` as
    # if they were the corresponding key. ``filter-clear`` is special-
    # cased because it has no key shortcut — it directly calls
    # ``CatalogListModel.clear_filter()``.
    _CATALOG_BUTTON_KEYS: dict[str, dict[str, str]] = {
        "skills": {
            "refresh": "r",
            "detail": "enter",
            "menu": "o",
            "scan": "s",
            "block": "b",
            "allow": "a",
            "reveal": "R",
        },
        "mcps": {
            "refresh": "r",
            "detail": "enter",
            "menu": "o",
            "scan": "s",
            "block": "b",
            "allow": "a",
            "add": "n",
            "reveal": "R",
        },
        "plugins": {
            "refresh": "r",
            "detail": "enter",
            "menu": "o",
            "scan": "s",
        },
        "tools": {
            "refresh": "r",
            "detail": "enter",
            "menu": "o",
        },
    }

    def _handle_catalog_control(self, panel: str, button_id: str) -> None:
        """Translate a catalog control-bar click into a model key dispatch.

        Mirrors how ``_handle_logs_control`` works for the Logs panel —
        the bar is just a click-first façade over the same
        ``handle_key`` surface the keyboard uses, so any action a user
        runs from the bar also lands in Activity, also obeys the
        preview gate, and also rolls into Audit identically.
        """

        keys = self._CATALOG_BUTTON_KEYS.get(panel, {})
        prefix = f"{panel}-"
        suffix = button_id.removeprefix(prefix)
        # "filter-clear" has no key shortcut on the catalog model — wipe
        # the filter text directly so the body and table both repaint.
        if suffix == "filter-clear":
            model = self.catalog_models.get(panel)
            if model is None:
                return
            model.clear_filter()
            try:
                self.query_one(f"#{panel}-filter", Input).value = ""
            except NoMatches:
                pass
            self._set_status(f"{panel.title()} filter cleared.")
            self._render_chrome()
            return
        key = keys.get(suffix)
        if key is None:
            return
        model = self.catalog_models.get(panel)
        if model is None:
            return
        self._sync_catalog_cursor_from_table(panel)
        action = model.handle_key(key)
        self._apply_catalog_action(panel, action)

    def _sync_catalog_cursor_from_table(self, panel: str) -> None:
        """Use the visible table cursor as source of truth before row actions."""

        if panel != self.active_panel:
            return
        model = self.catalog_models.get(panel)
        if model is None or not self._table_rows:
            return
        try:
            table = self.query_one("#panel-table", DataTable)
        except NoMatches:
            return
        if table.has_class("hidden"):
            return
        cursor_row = getattr(table, "cursor_row", -1)
        if 0 <= cursor_row < model.filtered_count():
            model.set_cursor(cursor_row)

    def _sync_catalog_controls(self, panel: str) -> None:
        """Toggle catalog control-bar buttons to match panel state.

        Buttons that require a highlighted row (``Detail``, ``Scan``,
        ``Block``, ``Allow``, ``Reveal``) are greyed when the table is
        empty so a click can't fall into a silent ``(no skill selected)``
        no-op. The filter ``Clear`` button is greyed when no filter is
        active so the bar honestly advertises "nothing to clear".
        """

        model = self.catalog_models.get(panel)
        if model is None:
            return
        has_row = model.selected() is not None
        has_filter = bool(model.filter_text)
        # Common controls present on every catalog bar.
        row_only_suffixes = ("detail", "menu", "scan", "block", "allow", "reveal")
        for suffix in row_only_suffixes:
            try:
                button = self.query_one(f"#{panel}-{suffix}", Button)
            except NoMatches:
                continue
            button.disabled = not has_row
        # Filter-clear depends on whether a filter is set, not on row
        # selection.
        try:
            self.query_one(f"#{panel}-filter-clear", Button).disabled = not has_filter
        except NoMatches:
            pass
        # Keep the Input widget's value in sync with the model so an
        # external mutation (e.g. ``/`` keyboard flow or a filter
        # cleared programatically) shows up in the box.
        try:
            filter_input = self.query_one(f"#{panel}-filter", Input)
        except NoMatches:
            return
        if filter_input.value != model.filter_text:
            filter_input.value = model.filter_text

    def _on_catalog_filter_input_changed(self, panel: str, value: str) -> None:
        """Live-filter the catalog model as the user types in the Input.

        We treat the Input as the canonical source of truth while it's
        focused; the model's ``set_filter`` re-applies the filter and
        re-clamps the cursor, which makes the body text + table reflect
        the typed query without the operator pressing Enter.
        """

        model = self.catalog_models.get(panel)
        if model is None:
            return
        model.set_filter(value)
        self._render_chrome()

    def _set_button_active(self, selector: str, active: bool) -> None:
        try:
            self.query_one(selector, Button).set_class(active, "active-chip")
        except NoMatches:
            return

    def _handle_overview_control(self, button_id: str) -> None:
        """Route an Overview quick-action button to the matching command.

        Each button is a thin wrapper around a single ``defenseclaw``
        invocation — this hands off to the same drawer pipeline a
        keystroke would use so preview gating, "already running"
        guards, and Activity-panel output streaming all keep working.
        """

        # Gateway lifecycle.
        if button_id == "overview-start-gateway":
            self._submit_command_text("defenseclaw-gateway start")
            return
        if button_id == "overview-restart-gateway":
            self._submit_command_text("defenseclaw-gateway restart")
            return
        # Diagnostics.
        if button_id == "overview-run-doctor":
            self._submit_command_text("defenseclaw doctor")
            return
        # AI Discovery quick actions — equivalent to the registry
        # palette rows, but one click away from the overview itself.
        if button_id == "overview-enable-ai-discovery":
            self._submit_command_text("defenseclaw agent discovery enable --yes")
            return
        if button_id == "overview-scan-ai-discovery":
            self._submit_command_text("defenseclaw agent discovery scan")
            return
        # Setup shortcuts: route to the in-TUI wizard, not the
        # interactive picker subprocess.
        if button_id == "overview-setup-connector":
            self.action_switch_panel("setup")
            self.setup_model.active_wizard = SetupWizard.CONNECTOR_SETUP
            self.setup_model.open_wizard_form(SetupWizard.CONNECTOR_SETUP)
            self._render_chrome()
            self._set_status(
                "Opened Connector Setup wizard — pick a connector with ←/→, "
                "Tab between fields, Ctrl+R to run."
            )
            return
        if button_id == "overview-keys-fill":
            self._submit_command_text("defenseclaw keys fill-missing")
            return

    def _handle_alert_control(self, button_id: str) -> None:
        severity_by_button = {
            "alerts-filter-all": "",
            "alerts-filter-critical": "CRITICAL",
            "alerts-filter-high": "HIGH",
            "alerts-filter-medium": "MEDIUM",
            "alerts-filter-low": "LOW",
        }
        if button_id in severity_by_button:
            self.alerts_model.set_severity_filter_exact(severity_by_button[button_id])  # type: ignore[arg-type]
            self._set_status(self.alerts_model.active_filter_label() or "Showing all alerts.")
            self._render_chrome()
            return
        key_by_button = {
            "alerts-select-all": "a",
            "alerts-ack-selected": "x",
            "alerts-dismiss-filtered": "c",
            "alerts-dismiss-all": "C",
        }
        if button_id in key_by_button:
            self._apply_alert_action(self.alerts_model.handle_key(key_by_button[button_id]))

    def _handle_audit_control(self, button_id: str) -> None:
        preset_by_button = {
            "audit-filter-all": "",
            "audit-filter-risk": "risk",
            "audit-filter-blocks": "blocks",
            "audit-filter-scans": "scans",
            "audit-filter-credentials": "credentials",
        }
        if button_id in preset_by_button:
            self.audit_model.set_common_filter(preset_by_button[button_id])  # type: ignore[arg-type]
            self._set_status(self.audit_model.active_filter_label() or "Showing all audit events.")
            self._render_chrome()
            return
        key_by_button = {
            "audit-filter-target": "t",
            "audit-filter-run": "u",
            "audit-export": "e",
        }
        if button_id in key_by_button:
            self._apply_audit_action(self.audit_model.handle_key(key_by_button[button_id]))

    def _handle_inventory_control(self, button_id: str) -> None:
        tab_prefix = "inventory-tab-"
        if button_id.startswith(tab_prefix):
            self.inventory_model.set_active_subtab(button_id.removeprefix(tab_prefix))  # type: ignore[arg-type]
            self._render_chrome()
            return
        if button_id == "inventory-scope-all":
            self.inventory_model.set_category_scope(())
            self._set_status("Inventory scope: all categories.")
            self._render_chrome()
            return
        if button_id == "inventory-scope-fast":
            if self.inventory_model.is_fast_scan():
                self.inventory_model.set_category_scope(())
            else:
                self.inventory_model.set_category_scope(FAST_SCAN_CATEGORIES)
            self._set_status(f"Inventory scope: {','.join(self.inventory_model.category_scope) or 'all'}.")
            self._render_chrome()
            return
        if button_id == "inventory-refresh":
            self._apply_inventory_action(self.inventory_model.handle_key("r"))
            return
        filter_by_button = {
            "inventory-filter-all": "",
            "inventory-filter-eligible": "eligible",
            "inventory-filter-warning": "warning",
            "inventory-filter-blocked": "blocked",
            "inventory-filter-loaded": "loaded",
            "inventory-filter-disabled": "disabled",
        }
        if button_id in filter_by_button:
            self.inventory_model.set_filter(filter_by_button[button_id])  # type: ignore[arg-type]
            self._set_status(f"Inventory filter: {self.inventory_model.filter or 'all'}.")
            self._render_chrome()

    def _handle_logs_control(self, button_id: str) -> None:
        source_prefix = "logs-source-"
        if button_id.startswith(source_prefix):
            source = button_id.removeprefix(source_prefix)
            self.logs_model.set_source(source)  # type: ignore[arg-type]
            self._set_status(f"Logs source: {LOG_SOURCE_LABELS.get(source, source)}.")
            self._render_chrome()
            return
        filter_prefix = "logs-filter-"
        if button_id.startswith(filter_prefix):
            try:
                index = int(button_id.removeprefix(filter_prefix))
            except ValueError:
                return
            if 0 <= index < len(FILTER_PRESETS):
                self.logs_model.set_filter(FILTER_PRESETS[index])
                label = FILTER_LABELS.get(FILTER_PRESETS[index], FILTER_PRESETS[index])
                self._set_status(f"Logs filter: {label}.")
                self._render_chrome()
            return
        if button_id == "logs-open-detail":
            self._open_logs_detail()
            return
        key_by_button = {
            "logs-toggle-pause": "space",
            "logs-redaction": "R",
            "logs-notifications": "N",
            "logs-judge-history": "J",
        }
        if button_id in key_by_button:
            self._apply_logs_action(self.logs_model.handle_key(key_by_button[button_id]))

    def _handle_registries_control(self, button_id: str) -> None:
        key_by_button = {
            "registries-tab-sources": "1",
            "registries-tab-entries": "2",
            "registries-tab-approved": "3",
            "registries-refresh": "r",
            "registries-sync-source": "s",
            "registries-sync-all": "S",
            "registries-approve": "a",
            "registries-reject": "x",
            "registries-remove-source": "d",
        }
        key = key_by_button.get(button_id)
        if key is not None:
            self._apply_registry_action(self.registries_model.handle_key(key))

    def _handle_setup_control(self, button_id: str) -> None:
        if button_id == "setup-mode-wizards":
            self.setup_model.mode = "wizards"
            self._render_chrome()
            return
        if button_id == "setup-mode-config":
            self.setup_model.mode = "config"
            self.setup_model.active_line = self.setup_model.first_editable_line()
            self._render_chrome()
            return
        # Wizard-form buttons share the keystroke handler so we get
        # `submit_wizard_form()` validation, secret-reveal toggling,
        # and field navigation for free. Routing through the same
        # `_apply_setup_action` pipe means CommandPreviewScreen,
        # CommandPreview gating, and `mark_wizard_complete` callbacks
        # all fire identically to Ctrl+R / Esc / Tab paths.
        wizard_key_by_button = {
            "setup-wizard-run": "ctrl+r",
            "setup-wizard-cancel": "esc",
            "setup-wizard-prev": "shift+tab",
            "setup-wizard-next": "tab",
            "setup-wizard-reveal": "ctrl+t",
            "setup-wizard-clear": "ctrl+u",
        }
        if button_id in wizard_key_by_button:
            if not self.setup_model.form_active:
                self._set_status("Open a wizard first, then use these controls.")
                return
            self._apply_setup_action(
                self._handle_setup_key(wizard_key_by_button[button_id])
            )
            return
        key_by_button = {
            "setup-open": "enter",
            "setup-edit-list": "E",
            "setup-save": "S",
            "setup-revert": "R",
            "setup-restart": "G",
            "setup-clear-restart": "C",
            "setup-refresh-credentials": "r",
        }
        key = key_by_button.get(button_id)
        if key is not None:
            self._apply_setup_action(self._handle_setup_key(key))

    def _handle_activity_control(self, button_id: str) -> None:
        """Route an Activity action-bar button to the matching helper.

        These buttons sit alongside the existing keyboard shortcuts
        (``!`` rerun, ``Ctrl+C`` cancel) so operators on a mouse-only
        terminal aren't locked out of the panel's lifecycle controls.
        Cancel and Rerun both reuse the exact code paths the keystroke
        version exercises so we don't accumulate a second implementation
        of "send SIGINT" or "rerun last".
        """

        if button_id == "activity-cancel":
            if self.command_running or self.executor.is_running:
                self.run_worker(self._cancel_running_command(), exclusive=False, thread=False)
            else:
                self._set_status("No command is running.")
            return
        if button_id == "activity-clear":
            removed = self.activity_model.clear_history()
            try:
                self.query_one("#activity", RichLog).clear()
            except NoMatches:
                pass
            self.activity_lines = []
            self._render_chrome()
            self._set_status(
                f"Cleared {removed} Activity entr{'y' if removed == 1 else 'ies'}."
                if removed
                else "Activity history is already empty."
            )
            return
        if button_id == "activity-save":
            # Synchronous write — the typical Activity output is a few
            # KB and `Path.write_text` is fast enough that spinning up
            # a worker just to call it would hide failures behind the
            # exception-swallowing default of `run_worker(thread=False)`.
            self._save_activity_output_interactive()
            return
        if button_id == "activity-rerun":
            # Reuse the existing "!" handler so we share validation,
            # preview gating, and toast messaging with the keystroke.
            self._handle_activity_key("!")
            return
        if button_id == "activity-open-drawer":
            self.action_open_command()
            return

    # ------------------------------------------------------------------
    # Yank / save-log helpers (Step 10).
    #
    # ``Y`` copies the most recent Activity entry's output to the OS
    # clipboard; ``Ctrl+S`` writes that same output to a stable path
    # (``~/.defenseclaw/tui/last-run.log``) so the operator can ``tail
    # -f`` it from another terminal or attach it to a bug report
    # without scrolling the TUI back to the start of a long run.
    # ------------------------------------------------------------------

    def _clipboard_copy(self, text: str) -> tuple[bool, str]:
        """Push ``text`` to the OS clipboard, returning ``(ok, transport)``.

        Tries the platform-appropriate command-line tool in order:
        pbcopy (macOS) → wl-copy (Wayland) → xclip → xsel (X11). If
        none of those exist or all of them fail, we fall back to a
        last-resort file at ``~/.defenseclaw/tui/last-copy.txt`` so
        operators on headless boxes still have *some* way to recover
        the payload. Failure here never crashes the TUI — the caller
        toasts the outcome.
        """

        if not text:
            return False, ""
        candidates: tuple[tuple[str, tuple[str, ...]], ...] = (
            ("pbcopy", ("pbcopy",)),
            ("wl-copy", ("wl-copy",)),
            ("xclip", ("xclip", "-selection", "clipboard")),
            ("xsel", ("xsel", "--clipboard", "--input")),
        )
        payload = text.encode("utf-8", errors="replace")
        for name, argv in candidates:
            if shutil.which(argv[0]) is None:
                continue
            try:
                proc = subprocess.run(
                    argv,
                    input=payload,
                    check=False,
                    capture_output=True,
                    timeout=4,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            if proc.returncode == 0:
                return True, name
        # File fallback: still useful — operators can ``cat`` it from
        # another shell. Mode 0600 so the contents stay scoped to the
        # current user; activity output frequently contains tokens
        # and secrets that the masker may not have caught upstream.
        target = (self.data_dir or Path.home() / ".defenseclaw" / "tui") / "last-copy.txt"
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
        except OSError:
            return False, ""
        return True, f"file:{target}"

    def _last_run_output_payload(self) -> tuple[str, str] | None:
        """Return ``(header, body)`` for the most recent Activity entry.

        Both Y and Ctrl+S share the same source so they always agree
        on "what is the last command". Returns ``None`` when there is
        no Activity history yet (fresh TUI session). ``body`` is the
        raw output stream joined with newlines; ``header`` describes
        the run (command label, status, timestamp) for the saved log
        — kept out of the clipboard payload so the operator only
        pastes the actual output, not the metadata.
        """

        if not self.activity_model.entries:
            return None
        entry = self.activity_model.entries[-1]
        stamp = entry.started_at.astimezone(timezone.utc).isoformat()
        status = entry.status_label or ("running" if not entry.done else f"exit {entry.exit_code}")
        header = (
            f"# {entry.command}\n"
            f"# {status}\n"
            f"# started {stamp}\n"
            f"# saved   {datetime.now(timezone.utc).isoformat()}\n"
            "\n"
        )
        body = "\n".join(entry.output)
        return header, body

    def action_yank_output(self) -> None:
        """Copy the last Activity entry's output to the OS clipboard."""

        payload = self._last_run_output_payload()
        if payload is None:
            self.notify_toast("warn", "No command output to copy yet.")
            return
        _, body = payload
        if not body.strip():
            self.notify_toast("warn", "Last command produced no output.")
            return
        ok, transport = self._clipboard_copy(body)
        if ok:
            if transport.startswith("file:"):
                # File fallback transports the *target path* in ``transport``;
                # surface that so the operator knows where to ``cat`` from.
                self.notify_toast(
                    "info",
                    f"No clipboard tool found · wrote output to {transport[5:]}",
                )
            else:
                self.notify_toast("success", f"Copied last output to clipboard ({transport}).")
        else:
            self.notify_toast(
                "error",
                "Copy failed — install pbcopy / wl-copy / xclip and try again.",
            )

    def action_run_diagnose(self) -> None:
        """Spawn ``defenseclaw doctor`` in the background, toast result.

        Designed as a "tap D, get answer" health probe — distinct from
        the lowercase ``d`` shortcut on Overview, which routes through
        the full preview/streaming pipeline and takes over the Activity
        panel. This variant stays out of the way: it doesn't switch
        panels, doesn't write to the RichLog, and reports the outcome
        through a single toast so operators don't lose their place.

        If another command is already running through the main
        executor we toast a warn instead of fighting for the slot;
        the doctor probe is best-effort.
        """

        if self.command_running:
            self.notify_toast(
                "warn",
                "Cannot diagnose while another command is running. "
                "Wait for it to finish or press Ctrl+C to cancel.",
            )
            return
        if self._diagnose_running:
            # Second Shift+D while the first probe is still going.
            # Without this guard ``run_worker`` would happily spawn a
            # parallel ``defenseclaw doctor`` subprocess — two
            # concurrent probes write to the same toast lane and race
            # on stdout pipes.
            self.notify_toast("warn", "Diagnose already running — waiting for current probe to finish.")
            return
        self._diagnose_running = True
        self.notify_toast("info", "Running defenseclaw doctor…")
        self.run_worker(
            self._run_diagnose_background(),
            exclusive=False,
            thread=False,
        )

    async def _run_diagnose_background(self) -> None:
        """Run ``defenseclaw doctor`` and toast a one-line summary.

        Output is captured but intentionally NOT written to Activity —
        Step 11's whole point is "lightweight probe". If the operator
        wants the full streamed view they have lowercase ``d`` on
        Overview. The toast's summary line is the first non-empty
        stdout line for read-only success, or a short failure tail
        for non-zero exits.

        Always clears ``_diagnose_running`` in a ``finally`` so a
        crashed probe can't permanently lock subsequent Shift+D
        presses behind the "already running" guard.
        """

        try:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "defenseclaw",
                    "doctor",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
            except (FileNotFoundError, OSError) as exc:
                # Most common failure here: ``defenseclaw`` binary not on
                # PATH (e.g. running the TUI from a checkout without
                # ``uv pip install -e .``). Surface clearly so the user
                # knows it's a setup issue, not a doctor verdict.
                self.notify_toast("error", f"Diagnose failed to launch: {exc}")
                return

            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60.0)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                self.notify_toast(
                    "error",
                    "Diagnose timed out after 60s — run `defenseclaw doctor` manually.",
                )
                return

            text = (stdout or b"").decode("utf-8", errors="replace")
            # Strip ANSI color codes so the toast doesn't render escape
            # sequences as literal characters — the doctor CLI emits
            # bracketed colour codes for the section headers.
            clean = _ANSI_RE.sub("", text)
            lines = [line.rstrip() for line in clean.splitlines() if line.strip()]
            summary = _diagnose_summary_line(lines)
            if proc.returncode == 0:
                self.notify_toast("success", f"Doctor OK · {summary}" if summary else "Doctor OK")
            else:
                # Non-zero exit: prefer the *last* non-empty line because
                # CLI tooling almost universally writes the "failure
                # reason" as the final pre-exit line.
                tail = lines[-1] if lines else ""
                self.notify_toast(
                    "warn",
                    f"Doctor exit {proc.returncode} · {tail}" if tail else f"Doctor exit {proc.returncode}",
                )
        finally:
            self._diagnose_running = False

    def action_save_last_run_log(self) -> None:
        """Write the last Activity entry's output to ``last-run.log``."""

        payload = self._last_run_output_payload()
        if payload is None:
            self.notify_toast("warn", "No command output to save yet.")
            return
        header, body = payload
        target = (self.data_dir or Path.home() / ".defenseclaw" / "tui") / "last-run.log"
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(header + body + "\n", encoding="utf-8")
            try:
                os.chmod(target, 0o600)
            except OSError:
                # Best effort — Windows / restricted filesystems don't
                # honour chmod and that's fine; the data still landed
                # at the intended path with normal user perms.
                pass
        except OSError as exc:
            self.notify_toast("error", f"Save failed: {exc}")
            return
        self.notify_toast("success", f"Wrote last-run.log → {target}")

    def _save_activity_output_interactive(self) -> None:
        """Write the highlighted Activity entry's output to a file.

        Uses the data_dir convention (same as ``_export_audit``) and
        falls back to the working directory when no data_dir is wired
        yet. The filename embeds the command's timestamp so repeated
        saves don't clobber previous artifacts. Synchronous — Activity
        outputs are bounded by ``Executor`` ring-buffer size so this
        always completes in single-digit milliseconds for typical use.
        """

        if not self.activity_model.entries:
            self._set_status("No Activity entries to save.")
            return
        cursor = max(0, min(self.activity_model.cursor, len(self.activity_model.entries) - 1))
        entry = self.activity_model.entries[cursor]
        stamp = entry.started_at.strftime("%Y%m%d-%H%M%S")
        safe_command = "".join(c if c.isalnum() else "-" for c in entry.command)[:40].strip("-") or "command"
        filename = f"defenseclaw-activity-{stamp}-{safe_command}.txt"
        target = (self.data_dir or Path.cwd()) / filename
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            header = (
                f"# {entry.command}\n"
                f"# {entry.status_label}\n"
                f"# saved {datetime.now(timezone.utc).isoformat()}\n\n"
            )
            target.write_text(header + "\n".join(entry.output) + "\n", encoding="utf-8")
            # F-0782: command output frequently contains tokens/secrets, so
            # the saved transcript must be owner-only, not world-readable.
            os.chmod(target, 0o600)
        except OSError as exc:
            self._set_status(f"Save failed: {exc}")
            return
        self._set_status(f"Saved Activity output to {target}")

    def _handle_ai_control(self, button_id: str) -> None:
        """Route an AI Discovery action-bar button to the matching helper.

        Enable/Disable/Scan/Refresh are thin wrappers around the CLI
        the existing keystroke shortcuts already exercise — sharing
        `_submit_command_text` means preview gating, "already running"
        guards, and Activity-panel streaming keep working unchanged.
        Open agent details routes to the panel's own toggle so the
        detail surface stays in sync regardless of how it was opened.
        """

        if button_id == "ai-enable":
            self._submit_command_text("defenseclaw agent discovery enable --yes")
            return
        if button_id == "ai-disable":
            self._submit_command_text("defenseclaw agent discovery disable --yes")
            return
        if button_id == "ai-scan":
            self._submit_command_text("defenseclaw agent discover")
            return
        if button_id == "ai-refresh":
            self._submit_command_text("defenseclaw agent usage --json")
            return
        if button_id == "ai-open-detail":
            if self.ai_discovery_model.selected() is None:
                self._set_status("Highlight an agent row first (↑/↓), then click Open agent details.")
                return
            self.ai_discovery_model.toggle_detail()
            self._render_chrome()
            return
        if button_id == "ai-export":
            self._export_ai_discovery_snapshot()
            return

    def _export_ai_discovery_snapshot(self) -> None:
        """Write the loaded AI usage snapshot to a JSON file on disk.

        Mirrors the ``_export_audit`` pattern so operators have a
        single mental model for "Export" buttons across panels: target
        lives under ``data_dir`` and the response is surfaced via the
        status line. We use ``dataclasses.asdict`` over a custom field
        list so future additions to ``AIUsageSnapshot`` automatically
        appear in the export — bespoke field plucking has bitrotted in
        this codebase before.

        Filename embeds a UTC timestamp so back-to-back exports don't
        silently overwrite each other (operators routinely scan twice
        to diff before/after enabling/disabling AI discovery).
        """

        snapshot = self.ai_discovery_model.snapshot
        if snapshot is None:
            self._set_status("No AI usage snapshot loaded — try Refresh first.")
            return
        # `replace(microsecond=0)` keeps the suffix short and stable;
        # second-level resolution is fine because a human can't click
        # Export twice in one second.
        stamp = datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y%m%dT%H%M%SZ")
        target = (self.data_dir or Path.cwd()) / f"defenseclaw-ai-usage-{stamp}.json"
        payload = asdict(snapshot)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps(payload, indent=2, default=self._json_default),
                encoding="utf-8",
            )
        except OSError as exc:
            self._set_status(f"AI export failed: {exc}")
            return
        self._set_status(f"Exported AI usage snapshot to {target}")

    @staticmethod
    def _json_default(value: Any) -> Any:
        """Coerce datetime / Path / set / tuple into JSON-safe shapes.

        Returns ``Any`` rather than ``str`` because the ``default=``
        callback for ``json.dumps`` is allowed (and here, expected) to
        return non-string types — sets and tuples become lists, which
        ``json.dumps`` then encodes recursively.
        """

        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, (set, frozenset, tuple)):
            return list(value)
        return repr(value)

    def _overview_metric_data(self) -> tuple[MetricDatum, ...]:
        """Build the metric-tile row for the Overview header.

        For every known connector (see KNOWN_CONNECTORS) the tiles
        surface what an operator actually wants to know about the
        integration: how many tool calls have been seen, how many were
        blocked, the severity breakdown of recent findings, and the
        AI-agent count. The label tracks the active connector name so a
        cursor deployment reads "Hook Calls (cursor)", not a stale
        default. When no connector is configured we fall back to the
        generic alert / scan / guardrail / agent set.
        """

        counts = self._overview_session_enforcement_counts()
        state_by_key = {
            card.key: card.state.strip().lower()
            for card in self.overview_model.service_cards()
        }
        guardrail_running = state_by_key.get("guardrail") in {"running", "enabled", "active"}
        guardrail_enabled = bool(self.overview_model.cfg and self.overview_model.cfg.guardrail_enabled)
        ai_box = self.overview_model.ai_discovery_box()
        ai_count = len(ai_box.rows) + ai_box.overflow

        selected_connector = self._connector_filter()
        multi_connectors = self._active_connector_names()
        scope_connectors = (selected_connector,) if selected_connector else tuple(multi_connectors)
        connector = selected_connector or self.overview_model.active_connector_name()
        connector_health = (
            None
            if multi_connectors and not selected_connector
            else self._connector_health_for_metric(connector, use_single=not multi_connectors or bool(selected_connector))
        )
        health = self.overview_model.health
        gateway_state = (health.gateway.state if health is not None else "").strip().lower()
        gateway_online = gateway_state in {"running", "ready", "healthy", "ok"}

        sev = self._alert_severity_counts_for_connectors(scope_connectors)
        fleet_sev = self._alert_severity_counts("")
        critical = sev.get("CRITICAL", 0)
        high = sev.get("HIGH", 0)
        medium = sev.get("MEDIUM", 0)
        low = sev.get("LOW", 0)
        total_findings = critical + high + medium + low
        fleet_findings = sum(fleet_sev.values())
        outside_roster_findings = max(fleet_findings - total_findings, 0) if scope_connectors and not selected_connector else 0

        cfg = self.overview_model.cfg
        guardrail_mode = (cfg.guardrail_mode if cfg else "") or "observe"
        guardrail_active = guardrail_running or guardrail_enabled
        guardrail_value_text = "ON" if guardrail_active else "OFF"
        if guardrail_active:
            guardrail_bits: list[str] = [
                f"[{TOKENS.accent_green}]{guardrail_mode}[/]"
            ]
            if cfg and cfg.guardrail_port:
                guardrail_bits.append(f":{cfg.guardrail_port}")
            llm_label = self._compact_llm_provider(
                cfg.llm_provider if cfg else "",
                cfg.llm_model if cfg else "",
            )
            if llm_label:
                guardrail_bits.append(f"[{TOKENS.accent_violet}]{llm_label}[/]")
            extras: list[str] = []
            if cfg and cfg.hilt_enabled:
                extras.append(f"[{TOKENS.accent_amber}]HITL[/]")
            if cfg and cfg.guardrail_judge_enabled:
                extras.append(f"[{TOKENS.accent_blue}]judge[/]")
            if cfg and not cfg.privacy_disable_redaction:
                extras.append("redact")
            if extras:
                guardrail_bits.append("·".join(extras))
            guardrail_detail = " · ".join(guardrail_bits)
        else:
            guardrail_detail = f"[{TOKENS.accent_amber}]press g to enable[/]"

        ai_detail = self._ai_agents_metric_detail(ai_box)

        is_hook_connector = (
            self.overview_model.cfg is not None
            and connector in _KNOWN_CONNECTORS
        )

        if is_hook_connector:
            if connector_health is not None:
                requests = connector_health.requests
                inspections = connector_health.tool_inspections
                errors = connector_health.errors
                tool_blocks = connector_health.tool_blocks
                subprocess_blocks = connector_health.subprocess_blocks
            else:
                requests = inspections = errors = tool_blocks = subprocess_blocks = 0
            blocks_total = tool_blocks + subprocess_blocks
            session_since = self._session_start_for_connectors(scope_connectors)
            allow_count, alert_count, block_decisions, top_hook = self._connector_hook_breakdown_for_connectors(
                scope_connectors, since=session_since
            )
            total_allow, total_alert, total_block, _total_newest = self._connector_hook_stats_for_connectors(scope_connectors)
            fleet_total_allow, fleet_total_alert, fleet_total_block, _fleet_total_newest = self._connector_hook_stats_for_connectors()
            live_hook_calls, live_blocks_value, has_live_hook_counts = self._connector_live_counts_for_connectors(scope_connectors)
            fleet_live_hook_calls, fleet_live_blocks_value, has_fleet_live_hook_counts = self._connector_live_counts_for_connectors(())

            # Prefer the gateway's live per-connector request counters when
            # available. Older gateways did not expose the connector array, so
            # fall back to grouped audit totals and finally the recent hook
            # window used by the trend sparkline.
            hook_timestamps = self._hook_event_timestamps_for_connectors(scope_connectors)
            total_hook_calls = total_allow + total_alert + total_block
            fleet_total_hook_calls = fleet_total_allow + fleet_total_alert + fleet_total_block
            fleet_hook_calls = (
                fleet_live_hook_calls
                if has_fleet_live_hook_counts
                else fleet_total_hook_calls
            )
            hook_calls = (
                live_hook_calls
                if has_live_hook_counts
                else (requests or total_hook_calls or len(hook_timestamps))
            )
            outside_roster_hook_calls = max(fleet_hook_calls - hook_calls, 0) if scope_connectors and not selected_connector else 0
            block_timestamps = self._block_event_timestamps_for_connectors(scope_connectors)
            fleet_block_timestamps = self._block_event_timestamps()
            blocks_value = (
                live_blocks_value
                if has_live_hook_counts
                else (blocks_total or total_block or len(block_timestamps))
            )
            fleet_blocks_value = (
                fleet_live_blocks_value
                if has_fleet_live_hook_counts
                else (fleet_total_block or len(fleet_block_timestamps))
            )
            outside_roster_blocks = max(fleet_blocks_value - blocks_value, 0) if scope_connectors and not selected_connector else 0
            finding_timestamps = self._finding_event_timestamps_for_connectors(scope_connectors)

            call_detail_parts: list[str] = []
            if allow_count or alert_count or block_decisions:
                call_detail_parts.append(
                    f"session [{TOKENS.accent_green}]a{allow_count}[/] "
                    f"[{TOKENS.accent_amber}]w{alert_count}[/] "
                    f"[{TOKENS.accent_red}]b{block_decisions}[/]"
                )
                if top_hook:
                    call_detail_parts.append(f"top: [{TOKENS.accent_cyan}]{top_hook}[/]")
                if selected_connector:
                    fleet_prefix = "live fleet" if has_fleet_live_hook_counts else "fleet"
                    call_detail_parts.append(f"{fleet_prefix} {fleet_hook_calls}")
                elif outside_roster_hook_calls:
                    call_detail_parts.append(f"outside roster {outside_roster_hook_calls}")
            elif inspections or errors:
                if inspections:
                    call_detail_parts.append(f"[{TOKENS.accent_blue}]{inspections}[/] inspected")
                if errors:
                    call_detail_parts.append(f"[{TOKENS.accent_red}]{errors}[/] errors")
            elif not gateway_online:
                call_detail_parts.append(f"[{TOKENS.accent_amber}]gateway offline · press : then start[/]")
            elif requests == 0:
                call_detail_parts.append("waiting for tool calls")
            else:
                call_detail_parts.append("agent active")
                if selected_connector:
                    call_detail_parts.append(f"fleet {fleet_hook_calls}")
            calls_detail = " · ".join(call_detail_parts)

            top_blocked_target, top_blocked_count = self._top_block_target_for_connectors(scope_connectors)
            block_detail_parts: list[str] = []
            if tool_blocks:
                block_detail_parts.append(f"[{TOKENS.accent_red}]{tool_blocks}[/] tool")
            if subprocess_blocks:
                block_detail_parts.append(f"[{TOKENS.accent_red}]{subprocess_blocks}[/] subprocess")
            if top_blocked_target:
                short_target = top_blocked_target if len(top_blocked_target) <= 22 else top_blocked_target[:21] + "…"
                block_detail_parts.append(f"top: [{TOKENS.accent_cyan}]{short_target}[/] x{top_blocked_count}")
            if not block_detail_parts:
                if not gateway_online:
                    block_detail_parts.append(f"[{TOKENS.text_muted}]no data — gateway offline[/]")
                else:
                    block_detail_parts.append("no blocks yet")
            if selected_connector:
                block_detail_parts.append(f"fleet {fleet_blocks_value}")
            elif outside_roster_blocks:
                block_detail_parts.append(f"outside roster {outside_roster_blocks}")
            blocks_detail = " · ".join(block_detail_parts)

            # D1=B: in multi-connector installs the aggregate counts above
            # would be mislabelled under the single primary connector, so
            # replace the detail sub-lines with a per-connector split and
            # relabel the Hook Calls tile to the connector count. No-op for
            # single-connector installs (helpers return empty).
            hook_calls_label = f"Hook Calls ({connector})"
            blocks_label = "Blocks"
            findings_label = "Findings"
            if selected_connector:
                hook_calls_label = f"Hook Calls ({selected_connector})"
                blocks_label = f"Blocks ({selected_connector})"
                findings_label = f"Findings ({selected_connector})"
            elif multi_connectors:
                multi_calls_detail, multi_blocks_detail = self._multi_connector_tile_details()
                if multi_calls_detail:
                    calls_detail = multi_calls_detail
                if multi_blocks_detail:
                    blocks_detail = multi_blocks_detail
                if outside_roster_hook_calls and "outside roster" not in calls_detail:
                    calls_detail = (
                        f"{calls_detail} · outside roster {outside_roster_hook_calls}"
                        if calls_detail
                        else f"outside roster {outside_roster_hook_calls}"
                    )
                if outside_roster_blocks and "outside roster" not in blocks_detail:
                    blocks_detail = (
                        f"{blocks_detail} · outside roster {outside_roster_blocks}"
                        if blocks_detail
                        else f"outside roster {outside_roster_blocks}"
                    )
                hook_calls_label = f"Hook Calls ({len(multi_connectors)} connectors)"

            findings_detail = self._findings_metric_detail(
                critical,
                high,
                medium,
                low,
                connector=selected_connector,
                connectors=scope_connectors,
            )
            if selected_connector:
                findings_detail = f"{findings_detail} · fleet {fleet_findings}"
            elif outside_roster_findings:
                findings_detail = f"{findings_detail} · outside roster {outside_roster_findings}"

            return (
                MetricDatum(
                    key="hook_calls",
                    label=hook_calls_label,
                    value=hook_calls,
                    progress=min(float(hook_calls), 100.0),
                    detail=calls_detail,
                    trend=self._metric_history(hook_timestamps),
                    state="ok" if hook_calls else ("error" if not gateway_online else "warn"),
                    target_panel="logs",
                ),
                MetricDatum(
                    key="blocks",
                    label=blocks_label,
                    value=blocks_value,
                    progress=min(float(blocks_value) * 5, 100.0),
                    detail=blocks_detail,
                    trend=self._metric_history(block_timestamps),
                    state="error" if blocks_value else ("ok" if hook_calls else "warn"),
                    target_panel="audit",
                ),
                MetricDatum(
                    key="findings",
                    label=findings_label,
                    value=total_findings,
                    progress=min(float(total_findings) * 5, 100.0),
                    detail=findings_detail,
                    trend=self._metric_history(finding_timestamps),
                    state="error" if critical or high else ("warn" if medium else "ok"),
                    target_panel="alerts",
                ),
                MetricDatum(
                    key="guardrail",
                    label="Guardrail",
                    value=1 if guardrail_active else 0,
                    progress=100.0 if guardrail_active else 0.0,
                    detail=guardrail_detail,
                    trend=(20, 40, 65, 80, 100) if guardrail_active else (0, 0, 8, 4, 0),
                    state="ok" if guardrail_active else "warn",
                    target_panel="audit",
                    value_text=guardrail_value_text,
                ),
            )

        return (
            MetricDatum(
                key="risk",
                label="Alert Risk",
                value=counts.active_alerts,
                progress=min(float(counts.active_alerts), 100.0),
                detail=self._findings_metric_detail(critical, high, medium, low),
                trend=self._metric_history(self._finding_event_timestamps()),
                state="error" if (critical or high) else ("warn" if medium else "ok"),
                target_panel="alerts",
            ),
            MetricDatum(
                key="scans",
                label="Scans",
                value=counts.total_scans,
                progress=min(float(counts.total_scans), 100.0),
                detail=(
                    "skill+mcp scans · "
                    f"[{TOKENS.accent_red}]{counts.blocked_skills + counts.blocked_mcps}[/] blocked"
                ),
                trend=self._metric_history(self._scan_event_timestamps()),
                state="ok" if counts.total_scans else "warn",
                target_panel="audit",
            ),
            MetricDatum(
                key="guardrail",
                label="Guardrail",
                value=1 if guardrail_active else 0,
                progress=100.0 if guardrail_active else 0.0,
                detail=guardrail_detail,
                trend=(20, 40, 65, 80, 100) if guardrail_active else (0, 0, 8, 4, 0),
                state="ok" if guardrail_active else "warn",
                target_panel="audit",
                value_text=guardrail_value_text,
            ),
            MetricDatum(
                key="ai",
                label="AI Agents",
                value=ai_count,
                progress=min(float(ai_count * 12), 100.0),
                detail=ai_detail,
                trend=_metric_trend(ai_count),
                state="ok" if ai_count else "warn",
                target_panel="ai",
            ),
        )

    @contextmanager
    def _connector_hook_event_render_cache(self):
        previous_enabled = self._connector_hook_event_cache_enabled
        previous_cache = self._recent_connector_hook_events_cache
        previous_stats_cache = self._connector_hook_event_stats_cache
        self._connector_hook_event_cache_enabled = True
        self._recent_connector_hook_events_cache = None
        self._connector_hook_event_stats_cache = None
        try:
            yield
        finally:
            self._connector_hook_event_cache_enabled = previous_enabled
            self._recent_connector_hook_events_cache = previous_cache
            self._connector_hook_event_stats_cache = previous_stats_cache

    def _connector_health_for_metric(self, connector: str, *, use_single: bool) -> Any | None:
        """Live health row for a metric's connector scope."""

        health = self.overview_model.health
        if health is None:
            return None
        want = connector.strip().lower()
        for conn in health.connectors:
            if conn.name.strip().lower() == want:
                return conn
        if use_single and health.connector is not None:
            if not want or health.connector.name.strip().lower() == want:
                return health.connector
        return None

    @staticmethod
    def _connector_health_has_live_window(connector_health: Any) -> bool:
        """True when a health row represents a current gateway counter window."""

        if not connector_health:
            return False
        if (getattr(connector_health, "since", "") or "").strip():
            return True
        return any(
            _coerce_nonnegative_int(getattr(connector_health, field, 0))
            for field in (
                "requests",
                "errors",
                "tool_inspections",
                "tool_blocks",
                "subprocess_blocks",
            )
        )

    def _connector_live_counts_for_connectors(
        self, connectors: Iterable[str] = (),
    ) -> tuple[int, int, bool]:
        """Return live ``(requests, blocks, has_live_window)`` for a scope."""

        health = self.overview_model.health
        if health is None:
            return 0, 0, False
        scope = self._normalize_connector_scope(connectors)
        rows: list[Any] = []
        for conn in health.connectors:
            name = conn.name.strip().lower()
            if not scope or any(want in name for want in scope):
                rows.append(conn)
        if not rows and health.connector is not None:
            name = health.connector.name.strip().lower()
            if not scope or any(want in name for want in scope):
                rows.append(health.connector)
        live_rows = [row for row in rows if self._connector_health_has_live_window(row)]
        if not live_rows:
            return 0, 0, False
        requests = sum(_coerce_nonnegative_int(getattr(row, "requests", 0)) for row in live_rows)
        blocks = sum(
            _coerce_nonnegative_int(getattr(row, "tool_blocks", 0))
            + _coerce_nonnegative_int(getattr(row, "subprocess_blocks", 0))
            for row in live_rows
        )
        return requests, blocks, True

    def _session_start_for_connectors(
        self, connectors: Iterable[str] = (),
    ) -> datetime | None:
        """Start of the active gateway/session window for a connector scope."""

        health = self.overview_model.health
        if health is None:
            return None
        scope = self._normalize_connector_scope(connectors)
        starts: list[datetime] = []
        for conn in health.connectors:
            name = conn.name.strip().lower()
            if scope and not any(want in name for want in scope):
                continue
            since = _parse_timestamp(conn.since)
            if since is not None:
                starts.append(since)
        if not starts and health.connector is not None:
            name = health.connector.name.strip().lower()
            if not scope or any(want in name for want in scope):
                since = _parse_timestamp(health.connector.since)
                if since is not None:
                    starts.append(since)
        if not starts:
            since = _parse_timestamp(health.guardrail.since)
            if since is not None:
                starts.append(since)
        return min(starts) if starts else None

    def _overview_session_enforcement_counts(self) -> EnforcementCounts:
        """Overview counts using the active gateway/session where possible."""

        current = self.overview_model.enforcement
        scope = tuple(self._active_connector_names())
        session_start = self._session_start_for_connectors(scope)
        total_scans = current.total_scans
        store = getattr(self.alerts_model, "store", None) or getattr(self.audit_model, "store", None)
        loader = getattr(store, "count_scan_results_since", None)
        if callable(loader):
            try:
                total_scans = int(loader(session_start))
            except Exception:  # noqa: BLE001 - retain the last known count.
                total_scans = current.total_scans
        return EnforcementCounts(
            blocked_skills=current.blocked_skills,
            allowed_skills=current.allowed_skills,
            blocked_mcps=current.blocked_mcps,
            allowed_mcps=current.allowed_mcps,
            total_scans=total_scans,
            active_alerts=self._session_alert_count_for_connectors(scope),
        )

    def _session_alert_count_for_connectors(self, connectors: Iterable[str] = ()) -> int:
        """Count current-session alert decisions for an Overview connector scope."""

        scope = self._normalize_connector_scope(connectors)
        since = self._session_start_for_connectors(scope)
        seen: set[tuple[str, ...]] = set()

        if self.alerts_model is not None:
            for row in self.alerts_model.flat_rows():
                if row.kind == "scan_finding":
                    continue
                event = row.event
                if not self._event_in_session(event, since):
                    continue
                if not self._event_matches_connectors(event, scope):
                    continue
                bucket = self._event_metric_severity_bucket(event)
                if bucket in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                    seen.add(self._event_count_key(event))

        for event in self._recent_connector_hook_events():
            if not self._event_in_session(event, since):
                continue
            if not self._event_matches_connectors(event, scope):
                continue
            if self._hook_decision(event) in {"alert", "warn"}:
                seen.add(self._event_count_key(event))

        return len(seen)

    @staticmethod
    def _event_count_key(event: Any) -> tuple[str, ...]:
        event_id = str(getattr(event, "id", "") or "").strip()
        if event_id:
            return ("id", event_id)
        timestamp = getattr(event, "timestamp", None)
        timestamp_key = timestamp.isoformat() if isinstance(timestamp, datetime) else ""
        return (
            "event",
            timestamp_key,
            str(getattr(event, "action", "") or ""),
            str(getattr(event, "target", "") or ""),
            str(getattr(event, "details", "") or ""),
        )

    @staticmethod
    def _event_in_session(event: Any, since: datetime | None) -> bool:
        if since is None:
            return True
        ts = getattr(event, "timestamp", None)
        if not isinstance(ts, datetime):
            return False
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts >= since

    def _alert_severity_counts(self, connector: str = "") -> dict[str, int]:
        """Severity counts for the active Overview metric scope."""

        return self._alert_severity_counts_for_connectors((connector,) if connector else ())

    def _alert_severity_counts_for_connectors(self, connectors: Iterable[str] = ()) -> dict[str, int]:
        """Severity counts for a connector roster scope."""

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        scope = self._normalize_connector_scope(connectors)
        since = self._session_start_for_connectors(scope)
        seen: set[tuple[str, ...]] = set()
        if self.alerts_model is not None:
            for row in self.alerts_model.flat_rows():
                if row.kind == "scan_finding":
                    continue
                if not self._event_in_session(row.event, since):
                    continue
                if not self._event_matches_connectors(row.event, scope):
                    continue
                bucket = self._event_metric_severity_bucket(row.event)
                if bucket in counts:
                    seen.add(self._event_count_key(row.event))
                    counts[bucket] += 1
        for event in self._recent_connector_hook_events():
            if not self._event_in_session(event, since):
                continue
            if not self._event_matches_connectors(event, scope):
                continue
            key = self._event_count_key(event)
            if key in seen:
                continue
            if self._hook_decision(event) not in {"alert", "warn", "block"}:
                continue
            bucket = self._event_metric_severity_bucket(event)
            if bucket in counts:
                seen.add(key)
                counts[bucket] += 1
        return counts

    @staticmethod
    def _normalize_connector_scope(connectors: Iterable[str]) -> tuple[str, ...]:
        return tuple(connector.strip().lower() for connector in connectors if connector.strip())

    @staticmethod
    def _event_connector(event: Any) -> str:
        return _parse_kv_details(getattr(event, "details", "") or "").get("connector", "").strip().lower()

    @staticmethod
    def _event_metric_severity_bucket(event: Any) -> str:
        bucket = _metric_severity_bucket(getattr(event, "severity", "") or "")
        if bucket in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            return bucket
        if str(getattr(event, "action", "") or "").strip().lower() == "connector-hook":
            detail_bucket = _metric_severity_bucket(
                _parse_kv_details(getattr(event, "details", "") or "").get("severity", "")
            )
            if detail_bucket in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                return detail_bucket
        return bucket

    @staticmethod
    def _event_matches_connector(event: Any, connector: str) -> bool:
        return DefenseClawTUI._event_matches_connectors(event, (connector,) if connector else ())

    @staticmethod
    def _event_matches_connectors(event: Any, connectors: Iterable[str]) -> bool:
        scope = DefenseClawTUI._normalize_connector_scope(connectors)
        if not scope:
            return True
        got = DefenseClawTUI._event_connector(event)
        return bool(got) and any(want in got for want in scope)

    @staticmethod
    def _hook_decision(event: Any) -> str:
        details = _parse_kv_details(getattr(event, "details", "") or "")
        action = details.get("action", "").strip().lower()
        raw_action = details.get("raw_action", "").strip().lower()
        mode = details.get("mode", "").strip().lower()
        would_block = details.get("would_block", "").strip().lower() == "true"

        if action in {"block", "deny"}:
            return "block"
        if action in {"alert", "warn"}:
            return "alert"
        if action == "allow" and mode == "observe":
            if raw_action in {"block", "deny"} or would_block:
                return "alert"
            if raw_action in {"alert", "warn"}:
                return "alert"
        return action

    def _connector_hook_event_stats(self) -> dict[str, dict[str, Any]]:
        """All-time connector-hook counts plus latest timestamps.

        The recent event window is intentionally capped for render speed and
        trend sparklines. These grouped totals power user-facing counters so a
        busy connector does not appear stuck at ``498`` just because the latest
        500 rows also include two old rows from another connector.
        """

        if self._connector_hook_event_cache_enabled and self._connector_hook_event_stats_cache is not None:
            return self._connector_hook_event_stats_cache
        stats: dict[str, dict[str, Any]] = {}
        store = getattr(self.audit_model, "store", None) if self.audit_model is not None else None
        loader = getattr(store, "connector_hook_event_stats", None)
        if callable(loader):
            try:
                raw_stats = loader() or {}
            except Exception:  # noqa: BLE001 - fall back to the recent in-memory window.
                raw_stats = {}
            for raw_connector, raw in raw_stats.items():
                connector = str(raw_connector or "").strip().lower()
                if not connector or not isinstance(raw, dict):
                    continue
                calls = _coerce_nonnegative_int(raw.get("calls"))
                blocks = _coerce_nonnegative_int(raw.get("blocks"))
                alerts = _coerce_nonnegative_int(raw.get("alerts"))
                stats[connector] = {
                    "calls": calls,
                    "blocks": min(blocks, calls),
                    "alerts": min(alerts, calls),
                    "newest": _parse_timestamp(raw.get("newest")),
                }
        if not stats:
            for event in self._recent_connector_hook_events():
                connector = self._event_connector(event) or "__unattributed__"
                entry = stats.setdefault(
                    connector,
                    {"calls": 0, "blocks": 0, "alerts": 0, "newest": None},
                )
                entry["calls"] = int(entry["calls"]) + 1
                decision = self._hook_decision(event)
                if decision in {"block", "deny"}:
                    entry["blocks"] = int(entry["blocks"]) + 1
                elif decision in {"alert", "warn"}:
                    entry["alerts"] = int(entry["alerts"]) + 1
                ts = getattr(event, "timestamp", None)
                if isinstance(ts, datetime):
                    newest = entry.get("newest")
                    if newest is None or ts > newest:
                        entry["newest"] = ts
        if self._connector_hook_event_cache_enabled:
            self._connector_hook_event_stats_cache = stats
        return stats

    def _connector_hook_stats_for_connectors(
        self, connectors: Iterable[str] = (),
    ) -> tuple[int, int, int, datetime | None]:
        """Return ``(allow, alert, block, newest)`` for the connector scope."""

        scope = self._normalize_connector_scope(connectors)
        allow = alert = block = 0
        newest: datetime | None = None
        for connector, row in self._connector_hook_event_stats().items():
            if scope and not any(want in connector for want in scope):
                continue
            calls = _coerce_nonnegative_int(row.get("calls"))
            row_alerts = min(_coerce_nonnegative_int(row.get("alerts")), calls)
            row_blocks = min(_coerce_nonnegative_int(row.get("blocks")), calls)
            alert += row_alerts
            block += row_blocks
            allow += max(calls - row_alerts - row_blocks, 0)
            ts = row.get("newest")
            if isinstance(ts, datetime) and (newest is None or ts > newest):
                newest = ts
        return allow, alert, block, newest

    @staticmethod
    def _is_block_event(event: Any) -> bool:
        action = (getattr(event, "action", "") or "").lower()
        details = (getattr(event, "details", "") or "").lower()
        return (
            action in {"block", "guardrail-block", "deny", "quarantine"}
            or "action=block" in details
            or "action=deny" in details
        )

    def _findings_metric_detail(
        self,
        critical: int,
        high: int,
        medium: int,
        low: int,
        *,
        connector: str = "",
        connectors: Iterable[str] = (),
    ) -> str:
        """Severity breakdown plus the top severity event target (if any).

        The breakdown is the primary signal; the top target gives one
        more piece of context (e.g. ``top: skill:foo H``) so users can
        glance at what kind of thing is firing alerts without opening
        the Alerts panel.
        """

        breakdown = _severity_breakdown_markup(critical, high, medium, low)
        if connector:
            target, severity_letter_src = self._top_finding_target(connector)
        elif self._normalize_connector_scope(connectors):
            target, severity_letter_src = self._top_finding_target_for_connectors(connectors)
        else:
            target, severity_letter_src = self._top_finding_target()
        if not target:
            return breakdown
        short_target = target if len(target) <= 18 else target[:17] + "…"
        sev_letter = (severity_letter_src or "")[:1] or "·"
        # ``short_target`` comes from raw audit events and may contain
        # bracket characters; escape before Rich parses the markup.
        return (
            f"{breakdown} · top: [{TOKENS.accent_cyan}]"
            f"{rich_escape(short_target)}[/] {sev_letter}"
        )

    def _ai_agents_metric_detail(self, ai_box: Any) -> str:
        if not ai_box.rows:
            return ai_box.message or "no agents detected"
        vendors: dict[str, int] = {}
        for row in ai_box.rows:
            vendor = (row.vendor or "unknown").strip()
            vendors[vendor] = vendors.get(vendor, 0) + 1
        top_vendor, top_count = max(vendors.items(), key=lambda kv: kv[1])
        # Vendor strings come from arbitrary AI Discovery rows; escape.
        safe_vendor = rich_escape(top_vendor)
        if len(vendors) == 1:
            return (
                f"[{TOKENS.accent_violet}]{safe_vendor}[/] · {top_count} agent"
                + ("s" if top_count != 1 else "")
            )
        return (
            f"[{TOKENS.accent_violet}]{safe_vendor}[/] "
            f"x{top_count} · {len(vendors)} vendors"
        )

    def _connector_hook_breakdown(self, connector: str = "") -> tuple[int, int, int, str]:
        """Scan recent audit events for connector-hook action breakdown.

        Returns ``(allow, alert, block, top_event_name)`` where the top
        event is the most-frequent hook target (e.g. ``postToolUse``).
        Counts are derived from the ``action=<x>`` token embedded in the
        event details by ``logConnectorHookAudit``.

        When ``connector`` is non-empty the scan is restricted to events
        whose ``connector=<name>`` detail token matches (case-insensitive)
        — the per-connector split feeding the Overview tiles in
        multi-connector installs. The default empty value preserves the
        original aggregate behaviour for single-connector installs.
        """

        return self._connector_hook_breakdown_for_connectors((connector,) if connector else ())

    def _connector_hook_breakdown_for_connectors(
        self,
        connectors: Iterable[str] = (),
        *,
        since: datetime | None = None,
    ) -> tuple[int, int, int, str]:
        """Hook decision breakdown for a connector roster scope."""

        allow = alert = block = 0
        events_by_target: dict[str, int] = {}
        events = self._recent_connector_hook_events()
        if not events:
            return 0, 0, 0, ""
        scope = self._normalize_connector_scope(connectors)
        for event in events:
            if since is not None:
                ts = getattr(event, "timestamp", None)
                if not isinstance(ts, datetime):
                    continue
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts < since:
                    continue
            if not self._event_matches_connectors(event, scope):
                continue
            decision = self._hook_decision(event)
            if decision == "allow":
                allow += 1
            elif decision == "alert" or decision == "warn":
                alert += 1
            elif decision in {"block", "deny"}:
                block += 1
            target = (event.target or "").strip()
            if target:
                events_by_target[target] = events_by_target.get(target, 0) + 1
        top_event = ""
        if events_by_target:
            top_event, _ = max(events_by_target.items(), key=lambda kv: kv[1])
        return allow, alert, block, top_event

    def _enforcement_connector_breakdown(self, connector: str) -> tuple[int, int, int]:
        """``(calls, alerts, blocks)`` for ``connector`` from the hook stream.

        Reuses :meth:`_connector_hook_breakdown` — the same connector-attributed
        source feeding the CONNECTORS table — so the ENFORCEMENT panel and the
        per-connector roster never disagree. ``calls`` is the total decisions
        (allow + alert + block) the connector's hooks produced.
        """

        return self._enforcement_scope_breakdown((connector,))

    def _enforcement_scope_breakdown(self, connectors: Iterable[str]) -> tuple[int, int, int]:
        """``(calls, alerts, blocks)`` for an Overview connector scope."""

        since = self._session_start_for_connectors(connectors)
        allow, alert, block, _top = self._connector_hook_breakdown_for_connectors(
            connectors, since=since
        )
        live_calls, live_blocks, has_live = self._connector_live_counts_for_connectors(connectors)
        return (
            live_calls if has_live else allow + alert + block,
            alert,
            live_blocks if has_live else block,
        )

    _BLOCK_VERDICTS = frozenset({"block", "blocked", "deny", "denied", "quarantine", "quarantined"})
    _ALLOW_VERDICTS = frozenset({"allow", "allowed", "clean", "ok", "pass"})

    def _connector_scan_metrics(self, connector: str) -> dict[str, int] | None:
        """Per-connector Skills/MCPs/scan numbers from the aibom snapshot.

        Sourced from ``inventory_model.connector_snapshots`` — the per-connector
        ``aibom scan --connector`` results we already merge in multi-connector
        mode. Returns ``None`` when that connector hasn't been scanned yet so the
        ENFORCEMENT panel can show "scan pending" rather than a wrong number
        (and trigger a one-shot load). Skills/Plugins carry policy verdicts;
        MCPs only carry a count, so no blocked/allowed split is reported for them.
        """

        model = getattr(self, "inventory_model", None)
        snapshots = getattr(model, "connector_snapshots", ()) if model is not None else ()
        want = connector.strip().lower()
        snap = next((s for name, s in snapshots if name.strip().lower() == want), None)
        if snap is None:
            return None

        def _verdict(entity: object) -> str:
            return (getattr(entity, "verdict", "") or "").strip().lower()

        def _scanned(entity: object) -> bool:
            return bool(
                getattr(entity, "scan_target", "")
                or getattr(entity, "scan_findings", 0)
                or getattr(entity, "scan_severity", "")
            )

        skills = snap.skills
        plugins = snap.plugins
        return {
            "skills": len(skills),
            "skills_blocked": sum(1 for sk in skills if _verdict(sk) in self._BLOCK_VERDICTS),
            "skills_allowed": sum(1 for sk in skills if _verdict(sk) in self._ALLOW_VERDICTS),
            "plugins": len(plugins),
            "plugins_blocked": sum(1 for pl in plugins if _verdict(pl) in self._BLOCK_VERDICTS),
            "mcps": len(snap.mcps),
            "scanned": sum(1 for e in (*skills, *plugins) if _scanned(e)),
            "scannable": len(skills) + len(plugins),
        }

    def _request_enforcement_inventory(self, connector: str) -> None:
        """Kick off the per-connector inventory scan once for ENFORCEMENT.

        Only fires when a connector is selected, more than one connector is
        active, and no per-connector snapshot is loaded yet. Guarded so the
        Overview's render loop can call it idempotently without re-dispatching.
        """

        if (
            self._enforcement_inventory_requested
            or not connector
            or len(self._active_connector_names()) <= 1
            or getattr(self.inventory_model, "connector_snapshots", ())
        ):
            return
        self._enforcement_inventory_requested = True
        try:
            self.run_worker(self._load_inventory_model(), exclusive=False, thread=False)
        except Exception:  # noqa: BLE001 - outside a running app (tests) there's no worker; ignore.
            pass

    def _connector_policy_label(self, connector: str) -> str:
        """``<mode> · <rule pack>`` policy context for a connector.

        Surfaced in the SCANNERS box when a connector is selected so the
        operator sees *which* enforcement policy the (machine-wide) scanners
        apply for that connector. Empty when there's nothing to show.
        """

        cfg = self.overview_model.cfg
        if cfg is None or not connector:
            return ""
        mode = (dict(cfg.connector_modes).get(connector) or "").strip()
        pack = (dict(cfg.connector_packs).get(connector) or "").strip()
        return " · ".join(part for part in (mode, pack) if part)

    def _overview_connector_row(self, connector: str) -> ConnectorOverviewRow | None:
        """Return the rendered Overview row for ``connector`` if it is active."""

        want = (connector or "").strip().lower()
        if not want:
            return None
        for row in self._overview_connector_rows():
            if row.connector.strip().lower() == want:
                return row
        return None

    def _connector_configuration_lines(self, connector: str) -> tuple[tuple[str, str], ...]:
        """Connector-scoped CONFIGURATION rows for the filtered Overview."""

        cfg = self.overview_model.cfg
        row = self._overview_connector_row(connector)
        mode = (row.mode if row else dict(cfg.connector_modes).get(connector, "")) if cfg else ""
        rule_pack = (row.rule_pack if row else dict(cfg.connector_packs).get(connector, "")) if cfg else ""
        status = (row.status if row else "") or "unknown"
        last_activity = (row.last_activity if row else "") or "none"
        disabled = bool(cfg and (cfg.connector_is_disabled(connector) or not cfg.guardrail_enabled))
        guardrail_state = "disabled" if disabled else "enabled"
        redaction = "ON (global redacted)" if cfg and not cfg.privacy_disable_redaction else "OFF (global RAW)"
        if cfg and cfg.hilt_enabled:
            approval = f"ON (global min {cfg.hilt_min_severity or 'HIGH'})"
        else:
            approval = "OFF (global)"
        lines = [
            ("Connector", f"{friendly_connector_name(connector)} ({connector})"),
            ("Mode", mode or "?"),
            ("Rule pack", rule_pack or "default"),
            ("Guardrail", guardrail_state),
            ("Status", status),
            ("Last activity", last_activity),
            ("Redaction", redaction),
            ("Human approval", approval),
        ]
        if cfg and cfg.environment:
            lines.append(("Environment", f"{cfg.environment} (global)"))
        return tuple(lines)

    def _active_connector_names(self) -> list[str]:
        """Names of every active connector when more than one is configured.

        Sourced from ``OverviewConfig.connector_modes`` (populated by the
        adapter from ``Config.active_connectors()``), so it is empty for
        the common single-connector install and the Overview tiles keep
        their original aggregate presentation untouched.
        """

        cfg = self.overview_model.cfg
        modes = list(cfg.connector_modes) if cfg else []
        if len(modes) <= 1:
            return []
        return [connector for connector, _mode in modes if connector]

    def _connector_filter(self) -> str:
        """The active connector filter (``""`` = All connectors).

        Returns ``""`` for single-connector installs (nothing to filter) and
        for the multi-connector "All" landing state. When the operator has
        picked a connector via the chip it returns that name, clamped to a
        still-active connector (a torn-down connector silently falls back to
        All). This is the single source of truth honoured by the Overview
        tiles, the Alerts/Audit/Logs row filters, and the connector chip.
        """

        return connector_filter_svc.normalize_filter(
            self.connector_filter, self._active_connector_names()
        )

    def _set_connector_filter(self, connector: str) -> None:
        """Set the shared connector filter to ``connector`` (``""`` = All).

        8.13 pass 2: the catalog/inventory panels load *every* active connector
        up-front (merged, with a CONNECTOR column), so changing the filter only
        re-filters the already-loaded rows in-memory — no reload churn. The
        model-level ``connector`` is still pointed at the filtered connector
        (or the primary under All) so per-row actions (scan/info/install) target
        the right connector. The Alerts/Audit/Logs rows and Overview tiles read
        :meth:`_connector_filter` directly at render time.
        """

        connector = connector_filter_svc.normalize_filter(
            connector, self._active_connector_names()
        )
        self.connector_filter = connector
        focus_enabled = bool(connector)
        action_connector = connector or self.overview_model.active_connector_name()
        for model in (
            self.skills_model,
            self.mcps_model,
            self.plugins_model,
            self.tools_model,
            self.inventory_model,
        ):
            try:
                # Keep action intents (scan/info/install) pointed at the
                # filtered connector; under All they target the primary.
                model.set_connector(action_connector)
            except AttributeError:
                pass
            if hasattr(model, "connector_focus_enabled"):
                model.connector_focus_enabled = focus_enabled
        if connector:
            friendly = friendly_connector_name(connector)
            self._set_status(f"Filtered to {friendly} ({connector}).")
        else:
            self._set_status("Showing all connectors.")
        # Keep connector-chip clicks responsive: the active panel syncs its
        # model filters during render, and hidden panels sync when opened.
        # Eagerly refiltering Logs/Audit/catalog data here made an Overview
        # chip click pay for every table in the app.
        self._render_chrome()

    def _sync_catalog_connector_filters(self) -> None:
        """Push the shared connector filter + column flag to catalog/inventory.

        Mirrors :meth:`_sync_signal_connector_filters`: in a multi-connector
        install the merged rows show a CONNECTOR column and narrow to the
        active filter; single-connector installs reset to "All / no column"
        so the original presentation is untouched. Cheap + idempotent (the
        model setters early-return when unchanged), so it is safe per render.
        """

        multi = len(self._active_connector_names()) > 1
        selected = self._connector_filter()
        for model in (
            self.skills_model,
            self.mcps_model,
            self.plugins_model,
            self.tools_model,
            self.inventory_model,
        ):
            if hasattr(model, "show_connector_column"):
                model.show_connector_column = multi
            if hasattr(model, "set_connector_filter"):
                model.set_connector_filter(selected if multi else "")

    def _connector_chip_text(self) -> str:
        """Rich-markup connector filter chip, or ``""`` for ≤1 connector.

        Renders ``Connector: [All] antigravity codex`` with the active
        segment highlighted, plus a hint that ``m`` cycles the filter. Shown
        at the top of every filterable pane so the operator always knows the
        current scope and how to change it.

        E1: as it builds the markup it also records each segment's visible
        column span in ``self._chip_click_segments`` so a mouse click on the
        chip can be resolved back to a connector (see
        :meth:`_handle_body_chip_click`) without the crash-prone ``@click``
        action-link markup. Labels are plain ASCII and the style tags are
        zero-width, so the visible column == character offset.
        """

        self._chip_click_segments = []
        segments = connector_filter_svc.chip_segments(
            self._connector_filter(), self._active_connector_names()
        )
        if not segments:
            return ""
        cfg = self.overview_model.cfg
        rendered: list[str] = []
        click_segments: list[tuple[int, int, str]] = []
        # The chip line starts with the literal "Connector: " label.
        col = len("Connector: ")
        for index, (label, is_active) in enumerate(segments):
            if index > 0:
                col += 2  # the "  " join between rendered segments
            disabled = cfg is not None and cfg.connector_is_disabled(label)
            text = f"{label} (off)" if disabled else label
            if is_active:
                rendered.append(
                    f"[{TOKENS.surface_base} on {TOKENS.accent_cyan}] {text} [/]"
                )
                visible = f" {text} "
            elif disabled:
                rendered.append(f"[{TOKENS.text_muted}]{text}[/]")
                visible = text
            else:
                rendered.append(f"[{TOKENS.text_secondary}]{text}[/]")
                visible = text
            value = "" if label == connector_filter_svc.ALL_LABEL else label
            click_segments.append((col, col + len(visible), value))
            col += len(visible)
        self._chip_click_segments = click_segments
        chip = "  ".join(rendered)
        return (
            f"[{TOKENS.text_secondary}]Connector:[/] {chip}  "
            f"[{TOKENS.text_muted}](press [bold]m[/] to filter)[/]\n\n"
        )

    def _handle_body_chip_click(self, x: int, y: int) -> bool:
        """Resolve a click on the ``#body`` Static to a connector chip action.

        E1: returns True (and applies the filter) when ``(x, y)`` lands on a
        chip segment of the connector chip. The clicked line is validated by
        content — its plain text must begin with ``Connector:`` — so a click on
        any other body line is ignored regardless of the chip's line offset
        (it is line 0 on catalog/signal panes but follows a header elsewhere,
        e.g. Inventory). A click on the chip line but outside a labelled
        segment (the trailing hint) opens the filter picker as a fallback.
        """

        segments = self._chip_click_segments
        if not segments:
            return False
        lines = self.body_text.split("\n")
        if y < 0 or y >= len(lines):
            return False
        plain = re.sub(r"\[/?[^\[\]]*\]", "", lines[y])
        if not plain.startswith("Connector:") and not self._overview_chip_visual_line(y):
            return False
        for start, end, value in segments:
            if start <= x < end:
                self._set_connector_filter(value)
                return True
        # On the chip line but between/after segments — offer the picker so the
        # click is never a dead no-op.
        if len(self._active_connector_names()) > 1:
            self.run_worker(self._open_mode_picker(), exclusive=False, thread=False)
            return True
        return False

    def _overview_chip_visual_line(self, y: int) -> bool:
        """True when ``y`` is the rendered Overview connector-chip line."""

        if self.active_panel != "overview" or self.help_open:
            return False
        try:
            if self.query_one("#body-scroll", VerticalScroll).scroll_y > 0:
                return False
        except NoMatches:
            pass
        # ``_overview_renderable`` paints the five-line logo, the tagline, and
        # one spacer before the connector chip. The fallback ``body_text`` has
        # a different line layout, so content validation alone misses clicks on
        # the visible chip.
        return y == len(_DEFENSECLAW_LOGO.splitlines()) + 2

    def _sync_signal_connector_filters(self) -> None:
        """Push the shared connector filter + column flag to the signal panes.

        Idempotent and cheap (the model setters early-return when unchanged),
        so it is safe to call on every render. In a single-connector install
        this resets the panes to "All / no column", preserving the original
        presentation.
        """

        multi = len(self._active_connector_names()) > 1
        selected = self._connector_filter()
        for model in (self.alerts_model, self.audit_model, self.logs_model):
            model.show_connector_column = multi
            model.set_connector_filter(selected if multi else "")

    def _multi_connector_tile_details(self) -> tuple[str, str]:
        """Per-connector split lines for the Hook Calls and Blocks tiles.

        Returns ``(calls_detail, blocks_detail)``. Each active connector is
        scored independently via :meth:`_connector_hook_breakdown` so the
        single tile row stays intact (D1=B) while the detail sub-line
        attributes recent activity to the right connector — e.g.
        ``recent codex a12 w0 b3 · cursor a8 w1 b1``. ``blocks_detail`` lists
        only connectors that actually blocked something. Returns ``("", "")``
        when fewer than two connectors are active, leaving the
        single-connector detail lines unchanged.
        """

        connectors = self._active_connector_names()
        if not connectors:
            return "", ""
        call_parts: list[str] = []
        block_parts: list[str] = []
        for connector in connectors:
            since = self._session_start_for_connectors((connector,))
            allow, alert, block, _top = self._connector_hook_breakdown_for_connectors(
                (connector,), since=since
            )
            call_parts.append(
                f"[{TOKENS.text_secondary}]session[/] [{TOKENS.accent_cyan}]{connector}[/] "
                f"[{TOKENS.accent_green}]a{allow}[/] "
                f"[{TOKENS.accent_amber}]w{alert}[/] "
                f"[{TOKENS.accent_red}]b{block}[/]"
            )
            if block:
                block_parts.append(
                    f"[{TOKENS.accent_cyan}]{connector}[/] [{TOKENS.accent_red}]{block}[/]"
                )
        return " · ".join(call_parts), " · ".join(block_parts)

    def _connector_status_map(self) -> dict[str, str]:
        """Map of ``connector_name_lower -> live state`` from ``/health``.

        Sourced from the gateway's ``connectors[]`` array (parsed into
        ``HealthSnapshot.connectors``). Empty when the gateway predates the
        array, in which case the Overview table falls back to the gateway
        state for every connector (they share one process).
        """

        health = self.overview_model.health
        out: dict[str, str] = {}
        if health is not None:
            for conn in health.connectors:
                if conn.name:
                    out[conn.name.strip().lower()] = (conn.state or "").strip()
        return out

    def _connector_last_activity(self, connector: str) -> datetime | None:
        """Most recent audit-event timestamp attributed to ``connector``."""

        want = connector.strip().lower()
        stats_newest = self._connector_hook_event_stats().get(want, {}).get("newest")
        if isinstance(stats_newest, datetime):
            return stats_newest
        latest: datetime | None = None
        for event in self._recent_connector_hook_events():
            if event.timestamp is None:
                continue
            attributed = _parse_kv_details(event.details or "").get("connector", "").strip().lower()
            if attributed != want:
                continue
            if latest is None or event.timestamp > latest:
                latest = event.timestamp
        return latest

    def _overview_connector_rows(self) -> list[ConnectorOverviewRow]:
        """Per-connector rows for the Overview CONNECTORS table.

        One row per active connector with its effective mode + rule pack
        (config), live status (``/health`` connectors[] or a gateway-state
        fallback), last activity, and CALLS/BLOCKS/ALERTS counts derived from
        the audit store. Empty for single-connector installs.
        """

        cfg = self.overview_model.cfg
        if cfg is None or len(cfg.connector_modes) <= 1:
            return []
        packs = dict(cfg.connector_packs)
        status_map = self._connector_status_map()
        # Fallback status when the gateway doesn't expose connectors[] yet:
        # the gateway runs every connector in one process, so the gateway
        # state stands in for each connector.
        gateway_state = self.overview_model.subsystem_state("gateway")
        fallback_status = "active" if gateway_state.strip().lower() == "running" else gateway_state
        now = datetime.now(timezone.utc)
        rows: list[ConnectorOverviewRow] = []
        for connector, mode in cfg.connector_modes:
            if not connector:
                continue
            health_row = self._connector_health_for_metric(connector, use_single=False)
            if health_row is not None and self._connector_health_has_live_window(health_row):
                calls = _coerce_nonnegative_int(getattr(health_row, "requests", 0))
                blocks = (
                    _coerce_nonnegative_int(getattr(health_row, "tool_blocks", 0))
                    + _coerce_nonnegative_int(getattr(health_row, "subprocess_blocks", 0))
                )
                since = _parse_timestamp(getattr(health_row, "since", ""))
                _allow, alerts, audit_blocks, _top = self._connector_hook_breakdown_for_connectors(
                    (connector,), since=since
                )
                if blocks == 0:
                    blocks = audit_blocks
            else:
                allow, alerts, blocks, _newest = self._connector_hook_stats_for_connectors((connector,))
                calls = allow + alerts + blocks
            last = self._connector_last_activity(connector)
            # A guardrail-disabled connector keeps its historical counts (so
            # the row still tells the story) but its STATUS is forced to
            # "disabled" — the gateway drops it from connectors[], so without
            # this override it would inherit the running gateway state and
            # look active.
            if cfg.connector_is_disabled(connector):
                status = "disabled"
            else:
                status = status_map.get(connector.strip().lower(), fallback_status) or "unknown"
            rows.append(
                ConnectorOverviewRow(
                    connector=connector,
                    mode=mode or "",
                    rule_pack=(packs.get(connector) or "").strip(),
                    last_activity=_relative_time_label(last, now),
                    calls=calls,
                    blocks=blocks,
                    alerts=alerts,
                    status=status,
                )
            )
        return rows

    def _hook_event_timestamps(self, connector: str = "") -> list[datetime]:
        """Timestamps of recent connector-hook audit events.

        Each connector-hook event is one hook call (preToolUse,
        afterShellExecution, ...), so this is the authoritative "Hook
        Calls" series even when the gateway's connector ``requests``
        counter stays at zero — hook connectors deliver calls
        out-of-band from proxied LLM requests, so that counter never
        moves for them.
        """

        return self._hook_event_timestamps_for_connectors((connector,) if connector else ())

    def _hook_event_timestamps_for_connectors(self, connectors: Iterable[str] = ()) -> list[datetime]:
        """Timestamps of recent connector-hook audit events for a roster scope."""

        scope = self._normalize_connector_scope(connectors)
        return [
            event.timestamp
            for event in self._recent_connector_hook_events()
            if event.timestamp is not None and self._event_matches_connectors(event, scope)
        ]

    def _recent_connector_hook_events(self) -> list[Any]:
        """Recent connector-hook events, bypassing the Audit panel's noise filter."""

        if self._connector_hook_event_cache_enabled and self._recent_connector_hook_events_cache is not None:
            return self._recent_connector_hook_events_cache
        if self.audit_model is None:
            if self._connector_hook_event_cache_enabled:
                self._recent_connector_hook_events_cache = []
            return []
        events: list[Any]
        store = getattr(self.audit_model, "store", None)
        loader = getattr(store, "list_connector_hook_event_summaries", None)
        if callable(loader):
            try:
                events = list(loader(500))
            except Exception:  # noqa: BLE001 - metric tiles should degrade to cached panel rows.
                events = []
        else:
            events = []
        if not events:
            events = [
                event
                for event in self.audit_model.items
                if getattr(event, "action", "") == "connector-hook"
            ]

        def sort_key(event: Any) -> datetime:
            ts = getattr(event, "timestamp", None)
            if not isinstance(ts, datetime):
                return datetime.min.replace(tzinfo=timezone.utc)
            if ts.tzinfo is None:
                return ts.replace(tzinfo=timezone.utc)
            return ts

        events = sorted(events, key=sort_key)
        if self._connector_hook_event_cache_enabled:
            self._recent_connector_hook_events_cache = events
        return events

    def _recent_block_events(self, connector: str = "") -> list[Any]:
        """Recent block/deny events, including unfiltered connector-hook blocks."""

        return self._recent_block_events_for_connectors((connector,) if connector else ())

    def _recent_block_events_for_connectors(self, connectors: Iterable[str] = ()) -> list[Any]:
        """Recent block/deny events for a connector roster scope."""

        scope = self._normalize_connector_scope(connectors)
        since = self._session_start_for_connectors(scope)
        events: list[Any] = []
        events.extend(self._recent_connector_hook_events())
        if self.audit_model is not None:
            events.extend(self.audit_model.items)
        out: list[Any] = []
        seen: set[str] = set()
        for event in events:
            key = str(getattr(event, "id", "") or id(event))
            if key in seen:
                continue
            seen.add(key)
            if not self._event_in_session(event, since):
                continue
            if not self._event_matches_connectors(event, scope):
                continue
            if self._is_block_event(event):
                out.append(event)
        return out[-200:]

    def _block_event_timestamps(self, connector: str = "") -> list[datetime]:
        """Timestamps of recent block / deny / quarantine audit events."""

        return self._block_event_timestamps_for_connectors((connector,) if connector else ())

    def _block_event_timestamps_for_connectors(self, connectors: Iterable[str] = ()) -> list[datetime]:
        """Timestamps of recent block / deny / quarantine events for a roster scope."""

        return [
            event.timestamp
            for event in self._recent_block_events_for_connectors(connectors)
            if event.timestamp is not None
        ]

    def _finding_event_timestamps(self, connector: str = "") -> list[datetime]:
        """Timestamps of recent severity-bearing alert events."""

        return self._finding_event_timestamps_for_connectors((connector,) if connector else ())

    def _finding_event_timestamps_for_connectors(self, connectors: Iterable[str] = ()) -> list[datetime]:
        """Timestamps of recent severity-bearing alert events for a roster scope."""

        if self.alerts_model is None:
            alert_events: list[Any] = []
        else:
            alert_events = list(self.alerts_model.audit_events)
        scope = self._normalize_connector_scope(connectors)
        since = self._session_start_for_connectors(scope)
        stamps: list[datetime] = []
        seen: set[tuple[str, ...]] = set()
        for event in alert_events:
            if (
                event.timestamp is not None
                and self._event_in_session(event, since)
                and self._event_matches_connectors(event, scope)
                and self._event_metric_severity_bucket(event) in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
            ):
                stamps.append(event.timestamp)
                seen.add(self._event_count_key(event))
        for event in self._recent_connector_hook_events():
            if not self._event_in_session(event, since):
                continue
            if not self._event_matches_connectors(event, scope):
                continue
            key = self._event_count_key(event)
            if key in seen:
                continue
            if self._hook_decision(event) not in {"alert", "warn", "block"}:
                continue
            if self._event_metric_severity_bucket(event) not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                continue
            if event.timestamp is not None:
                stamps.append(event.timestamp)
                seen.add(key)
        return stamps

    def _scan_event_timestamps(self) -> list[datetime]:
        """Timestamps of recent scan / finding audit events."""

        if self.audit_model is None:
            return []
        since = self._session_start_for_connectors(tuple(self._active_connector_names()))
        stamps: list[datetime] = []
        for event in self.audit_model.items:
            action = (event.action or "").lower()
            if (
                ("scan" in action or "finding" in action)
                and event.timestamp is not None
                and self._event_in_session(event, since)
            ):
                stamps.append(event.timestamp)
        return stamps

    def _metric_history(self, timestamps: Iterable[datetime]) -> tuple[float, ...]:
        """Build a per-tile time-bucketed sparkline from event timestamps.

        Anchored on the current wall clock so the rightmost bars are the
        most recent buckets; empty windows render as a flat baseline.
        """

        return _event_histogram(timestamps, now=datetime.now(timezone.utc))

    def _top_block_target(self, connector: str = "") -> tuple[str, int]:
        """Most-frequently blocked audit target across recent events."""

        return self._top_block_target_for_connectors((connector,) if connector else ())

    def _top_block_target_for_connectors(self, connectors: Iterable[str] = ()) -> tuple[str, int]:
        """Most-frequently blocked audit target for a connector roster scope."""

        blocked: dict[str, int] = {}
        for event in self._recent_block_events_for_connectors(connectors):
            target = (event.target or "").strip() or "(unknown)"
            blocked[target] = blocked.get(target, 0) + 1
        if not blocked:
            return "", 0
        top, count = max(blocked.items(), key=lambda kv: kv[1])
        return top, count

    def _top_finding_target(self, connector: str = "") -> tuple[str, str]:
        """Highest-severity recent alert's target + severity letter."""

        return self._top_finding_target_for_connectors((connector,) if connector else ())

    def _top_finding_target_for_connectors(self, connectors: Iterable[str] = ()) -> tuple[str, str]:
        """Highest-severity recent alert target for a connector roster scope."""

        alert_events: list[Any] = [] if self.alerts_model is None else list(self.alerts_model.audit_events[-200:])
        scope = self._normalize_connector_scope(connectors)
        since = self._session_start_for_connectors(scope)
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        best: tuple[int, str, str] = (0, "", "")
        seen: set[tuple[str, ...]] = set()

        def consider(event: Any) -> None:
            nonlocal best
            if not self._event_in_session(event, since):
                return
            if not self._event_matches_connectors(event, scope):
                return
            severity = self._event_metric_severity_bucket(event)
            rank = severity_rank.get(severity, 0)
            if rank <= best[0]:
                return
            target = (event.target or "").strip() or "(unknown)"
            best = (rank, target, severity)

        for event in alert_events:
            seen.add(self._event_count_key(event))
            consider(event)
        for event in self._recent_connector_hook_events():
            key = self._event_count_key(event)
            if key in seen:
                continue
            if self._hook_decision(event) not in {"alert", "warn", "block"}:
                continue
            seen.add(key)
            consider(event)
        return best[1], best[2]

    @staticmethod
    def _compact_llm_provider(provider: str, model: str) -> str:
        """Short ``provider/model-tail`` label for tile details."""

        provider = (provider or "").strip().lower()
        model = (model or "").strip()
        if not provider and not model:
            return ""
        if not model:
            return provider
        # Trim long vendor-prefixed model ids (e.g. ``us.anthropic.claude-3-5-haiku-20241022-v1:0``)
        tail = model.split(".")[-1].split(":")[0]
        if len(tail) > 18:
            tail = tail[:18] + "…"
        return f"{provider}·{tail}" if provider else tail

    @on(MetricTile.Clicked)
    def _on_metric_tile_clicked(self, event: MetricTile.Clicked) -> None:
        """Drill into the panel that backs the clicked tile."""

        event.stop()
        target = event.target_panel
        if not target:
            return
        # The Hook Calls tile drills into the Logs panel pre-filtered to
        # connector-hook events (OTEL stream + Hooks filter) so the click
        # lands directly on the hook calls the tile is counting.
        if event.key == "hook_calls" and target == "logs":
            self.logs_model.set_source("otel")
            self.logs_model.set_filter(FILTER_HOOKS)
        if target == self.active_panel:
            self._render_chrome()
            self._set_status("Logs filtered to connector hooks.")
            return
        self.action_switch_panel(target)
        if event.key == "hook_calls" and target == "logs":
            self._set_status("Opened Logs filtered to connector hooks.")
        else:
            self._set_status(f"Opened {target} (clicked {event.key} tile).")

    # ------------------------------------------------------------------
    # Command-progress strip — single source of truth for command lifecycle
    # ------------------------------------------------------------------
    #
    # The strip is a 5-row Vertical with three lines of content:
    #   row 1: <icon> <label>          <duration> [✕ Cancel]
    #   row 2: live snippet / final summary / error reason
    #   row 3: state-specific hint (press A · q to dismiss · Ctrl+C cancel)
    #
    # State transitions are driven by:
    #   _strip_running(label)   on executor "start"
    #   _strip_output(line)     on each non-empty stdout/stderr line
    #   _strip_finished(...)    on executor "done"
    #   _strip_rejected(reason) on parse-error or already-running
    #   _strip_clear()          on q-dismiss
    #
    # Per user request:
    #   * never auto-hide on success — user must explicitly press q
    #   * snippet on success is a summary, not a raw last line
    #   * strip is hidden when the user is on the Activity panel (live
    #     stream is right there, the strip would be redundant)
    #   * the action button doubles as Cancel during running and Dismiss
    #     after a finish/rejection
    _SPINNER_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")

    def _set_command_progress(self, state: str, label: str, *, progress: float | None = None) -> None:
        """Compatibility shim for the legacy lifecycle entrypoint.

        Older callers (and a couple of tests we haven't migrated yet)
        still invoke ``_set_command_progress`` directly. Forward to the
        state machine so we have one source of truth, ignoring the
        ``progress`` arg — the strip no longer renders a fake percent.
        """

        del progress
        normalized = state.lower().strip()
        if normalized == "running":
            self._strip_running(label)
        elif normalized == "success":
            self._strip_label = label or self._strip_label or "command"
            self._strip_finished(exit_code=0, duration=self._strip_frozen_duration or 0.0)
        elif normalized == "failure":
            self._strip_label = label or self._strip_label or "command"
            self._strip_finished(exit_code=1, duration=self._strip_frozen_duration or 0.0)
        elif normalized == "rejected":
            self._strip_rejected(label)
        else:
            self._strip_clear()

    def _hide_command_progress(self, *, force: bool = False) -> None:
        del force
        self._strip_clear()

    def _tick_command_strip(self) -> None:
        """Periodic tick: advance spinner glyph + live elapsed timer.

        Cheap no-op when the strip is idle. While a setup wizard is mid-run
        we also refresh the panel table so the per-row "running 12s..."
        badge counts up — `_periodic_refresh` is paused while a command
        is running, and without this poke the timer would freeze and look
        like a hang.

        Also drives toast expiry. Toast TTLs (4–8s) are short enough that
        piggy-backing on the existing 250ms strip tick keeps the visible
        list within ~250ms of the manager's notion of "now" without
        adding a second timer.
        """

        if self.toasts.tick():
            self._toasts_dirty = True
        if self._toasts_dirty:
            self._render_toasts()
        if self._strip_state != "running":
            return
        self._strip_spinner_tick = (self._strip_spinner_tick + 1) % len(self._SPINNER_FRAMES)
        self._render_command_strip()
        if (
            self.active_panel == "setup"
            and not self.first_run_model.active
            and self.setup_model.any_wizard_running()
        ):
            self._render_panel_table()
            self._refresh_hint()

    def _strip_running(self, label: str) -> None:
        """Enter the running state. Captures start time for live elapsed."""

        self._strip_state = "running"
        self._strip_label = label or "command"
        self._strip_started_at = monotonic()
        self._strip_frozen_duration = None
        self._strip_last_output = ""
        self._strip_summary = ""
        self._strip_spinner_tick = 0
        self._render_command_strip()

    def _strip_output(self, line: str) -> None:
        """Record the most recent meaningful output line for live snippet."""

        text = _strip_ansi(line).strip()
        if not text:
            return
        self._strip_last_output = text
        if self._strip_state == "running":
            self._render_command_strip()

    def _strip_finished(self, exit_code: int, duration: float) -> None:
        """Move running → success/failure. Strip stays until dismissed."""

        self._strip_state = "success" if exit_code == 0 else "failure"
        self._strip_frozen_duration = duration
        # Build a one-line summary: for success use the last output line if
        # it's short and looks like a result, otherwise just acknowledge
        # exit code; for failure show the last (likely error) line so the
        # user sees the actual reason without leaving the panel.
        if self._strip_state == "success":
            tail = self._strip_last_output
            self._strip_summary = (
                tail if (tail and len(tail) <= 120) else "exit 0 · finished cleanly"
            )
        else:
            tail = self._strip_last_output
            self._strip_summary = tail or f"exit {exit_code} · no output captured"
        # Append a contextual "next thing to try" hint when we have a
        # confident suggestion (e.g. ``rerun readiness`` after `setup
        # guardrail`). Empty string means "no hint" — skip the footer
        # rather than rendering an awkward dangling separator.
        label = self._strip_label or "command"
        hint = suggested_next_action(label, exit_code)
        if hint:
            self._strip_summary = f"{self._strip_summary} · next: {hint}"
        # Fire a transient toast as well so operators on a different
        # panel still notice the result without having to switch back to
        # Activity. Strip is the persistent receipt; toast is the nudge.
        if exit_code == 0:
            self.notify_toast("success", f"{label} finished in {duration:.1f}s")
        else:
            failure_msg = f"{label} failed (exit {exit_code}) — {self._strip_summary}"
            if hint and f"next: {hint}" not in failure_msg:
                # Defensive: keep the toast self-contained when the
                # summary didn't already absorb the hint.
                failure_msg = f"{failure_msg} · next: {hint}"
            self.notify_toast("error", failure_msg)
        self._render_command_strip()

    def _strip_rejected(self, reason: str) -> None:
        """Strip enters rejected state for parse errors or busy-executor."""

        self._strip_state = "rejected"
        self._strip_label = "command rejected"
        self._strip_frozen_duration = None
        self._strip_last_output = ""
        self._strip_summary = reason or "command did not parse"
        self.notify_toast("warn", f"Rejected: {self._strip_summary}")
        self._render_command_strip()

    def _strip_clear(self) -> None:
        """Dismiss the strip and return to idle."""

        self._strip_state = "idle"
        self._strip_label = ""
        self._strip_started_at = 0.0
        self._strip_frozen_duration = None
        self._strip_last_output = ""
        self._strip_summary = ""
        self._render_command_strip()

    def notify_toast(self, level: ToastLevel, message: str) -> None:
        """Push a toast and re-render the stack.

        Mirrors the Go TUI's ``ToastManager.Push``: keep this the single
        funnel so every caller (executor finish, audit export, rerun,
        gateway-restart detector, …) gets the same eviction policy and
        TTL behaviour. Failures are swallowed because a toast that
        can't render must never block a real workflow.
        """

        try:
            self.toasts.push(level, message)
            self._toasts_dirty = True
            self._render_toasts()
        except Exception:  # noqa: BLE001 - cosmetic UI affordance
            pass

    def _render_toasts(self) -> None:
        """Sync the ToastStack widget with the current ToastManager queue."""

        try:
            stack = self.query_one("#toasts", ToastStack)
        except NoMatches:
            return
        stack.render_items(list(self.toasts.items))
        self._toasts_dirty = False

    def _render_command_strip(self) -> None:
        """Push current command-progress state into the DOM.

        Tolerates being invoked before the app is mounted (Textual raises
        ``ScreenStackError`` from ``query_one`` when there's no screen
        yet) and after the panel widget has been removed (``NoMatches``).
        Both cases are non-fatal — we just skip the render.
        """

        try:
            panel = self.query_one("#command-progress", Vertical)
        except Exception:  # noqa: BLE001 - DOM not mounted / panel removed
            return

        # Hide entirely on idle, OR when the user is already on the
        # Activity panel — the live stream there is the strip's content
        # in a richer form, so the strip is just clutter.
        hidden = self._strip_state == "idle" or self.active_panel == "activity"
        panel.set_class(hidden, "hidden")
        panel.display = not hidden
        if hidden:
            return

        # The #command-progress container can briefly exist without its child
        # widgets during a panel-switch re-render: Textual mounts the parent
        # before (re)attaching the composed children, and the 0.25s
        # _tick_command_strip timer can fire inside that window. The child
        # queries below would then raise NoMatches and take down the worker
        # (the parent guard above only covers the container). Probe the first
        # child up front and bail if the inner DOM isn't ready yet — the
        # children compose as one unit and this method is synchronous, so once
        # the probe resolves they all stay mounted for the rest of the render.
        # The next tick repaints cleanly once the DOM settles.
        try:
            self.query_one("#command-progress-icon", Static)
        except NoMatches:
            return

        panel.set_class(self._strip_state == "running", "running")
        panel.set_class(self._strip_state == "success", "success")
        panel.set_class(self._strip_state == "failure", "failure")
        panel.set_class(self._strip_state == "rejected", "rejected")

        icon, icon_color, header_color = {
            "running": (self._SPINNER_FRAMES[self._strip_spinner_tick], TOKENS.accent_amber, TOKENS.accent_amber),
            "success": ("✓", TOKENS.accent_green, TOKENS.accent_green),
            "failure": ("✗", TOKENS.accent_red, TOKENS.accent_red),
            "rejected": ("✗", TOKENS.accent_red, TOKENS.accent_red),
        }.get(self._strip_state, (" ", TOKENS.text_secondary, TOKENS.text_primary))

        # The icon Static cycles through Unicode braille frames during
        # ``running`` (more reliable than Textual's LoadingIndicator in
        # cramped 1-row layouts) and shows a check/cross afterwards.
        self.query_one("#command-progress-icon", Static).update(f"[{icon_color} bold]{icon}[/]")
        self.query_one("#command-progress-label", Static).update(
            f"[{header_color} bold]{self._strip_label}[/]"
        )

        # Elapsed-time tracker replaces the fake progress bar. The bar
        # was meaningless because the executor doesn't emit percent
        # complete; a live timer at least honestly tells the user how
        # long they've been waiting.
        if self._strip_state == "running":
            elapsed = max(0.0, monotonic() - self._strip_started_at)
            duration_text = _format_elapsed(elapsed)
        elif self._strip_frozen_duration is not None:
            duration_text = _format_elapsed(self._strip_frozen_duration)
        else:
            duration_text = ""
        self.query_one("#command-progress-duration", Static).update(
            f"[{TOKENS.text_secondary}]{duration_text}[/]" if duration_text else ""
        )

        action_button = self.query_one("#command-progress-action", Button)
        if self._strip_state == "running":
            action_button.label = "✕ Cancel"
        else:
            action_button.label = "✕ Dismiss"
        action_button.display = True

        # Snippet: live tail during running, summary afterwards.
        if self._strip_state == "running":
            snippet = self._strip_last_output or "started — waiting for output…"
            snippet_color = TOKENS.text_secondary
        elif self._strip_state == "success":
            snippet = self._strip_summary
            snippet_color = TOKENS.accent_green
        else:
            snippet = self._strip_summary
            snippet_color = TOKENS.accent_red
        truncated = _truncate_for_strip(snippet, panel.size.width or 120)
        # ``truncated`` is live subprocess tail (``Selection [3]:`` etc.).
        # Without escaping, a single bracketed token in stdout takes the
        # whole TUI frame down. Escape before letting Rich parse markup.
        self.query_one("#command-progress-snippet", Static).update(
            f"[{snippet_color}]{rich_escape(truncated)}[/]"
        )

        hint = {
            "running": "press A for live output  ·  Ctrl+C or click Cancel to stop",
            "success": "press A for full output  ·  q or click Dismiss to clear",
            "failure": "press A for full output  ·  q or click Dismiss to clear",
            "rejected": "press : to retry  ·  q or click Dismiss to clear",
        }.get(self._strip_state, "")
        self.query_one("#command-progress-hint", Static).update(
            f"[{TOKENS.text_muted}]{hint}[/]"
        )

    @on(Button.Pressed, "#command-progress-action")
    def _on_command_strip_action(self, event: Button.Pressed) -> None:
        """The strip's action button doubles as Cancel and Dismiss."""

        event.stop()
        if self._strip_state == "running":
            self.action_cancel_or_quit()
        else:
            self._strip_clear()

    def _overview_renderable(self) -> RenderableType:
        """Build the multi-panel overview matching the Go TUI layout.

        Renders the ASCII banner, attention notices, a two-column grid of
        bordered Panels (Services + Configuration on the left; Enforcement,
        Scanners, and Doctor on the right), a full-width Discovered AI Agents
        panel, and a quick-action footer. Each panel uses its own accent color
        so sections are visually distinct instead of one cyan wall of text.
        ``self.body_text`` is still populated with the plain-text fallback so
        existing tests that grep substrings out of it keep passing.
        """

        service_cards = self.overview_model.service_cards()
        self.body_text = self._overview_body_text(service_cards)

        notices = self.overview_model.build_notices()
        doctor = self.overview_model.doctor_box()
        ai_box = self.overview_model.ai_discovery_box()
        cfg = self.overview_model.cfg
        counts = self._overview_session_enforcement_counts()
        health = self.overview_model.health
        state_by_key = {card.key: card.state or "unknown" for card in service_cards}
        detail_by_key = {card.key: card.detail or card.last_error for card in service_cards}

        banner = Text(_DEFENSECLAW_LOGO, style=f"bold {TOKENS.accent_cyan}")
        uptime_suffix = ""
        if health is not None and health.uptime_ms:
            uptime_suffix = f"  uptime={health.uptime_ms // 1000}s"
        tagline = Text(
            f"  Enterprise AI Governance  v{__version__}{uptime_suffix}",
            style=f"italic {TOKENS.text_secondary}",
        )
        connector_chip = self._connector_chip_text()
        connector_chip_block: list[RenderableType] = []
        if connector_chip:
            connector_chip_block = [Text.from_markup(connector_chip.rstrip()), Text("")]

        # Build the notice lines via ``Text.append`` rather than
        # ``Text.from_markup``: the icons (``[!]`` / ``[*]`` / ``[>]``)
        # and the literal ``[OK]`` would be parsed as style names ``!`` /
        # ``OK`` etc. and crash the overview the moment any notice is
        # emitted. ``notice.message`` also routinely includes bracketed
        # tokens (``[skill] missing scan``) — same crash class.
        notice_block: list[Text] = []
        for notice in notices[:3]:
            if notice.level == "error":
                icon, color = "[!]", TOKENS.accent_red
            elif notice.level == "warn":
                icon, color = "[*]", TOKENS.accent_amber
            elif notice.level == "info":
                icon, color = "[>]", TOKENS.accent_blue
            else:
                icon, color = "[-]", TOKENS.accent_green
            line = Text(" ")
            line.append(icon, style=f"{color} bold")
            line.append(" ")
            line.append(notice.message)
            notice_block.append(line)
        if not notice_block:
            quiet = Text(" ")
            quiet.append("[OK]", style=f"{TOKENS.accent_green} bold")
            quiet.append(" Runtime signals are quiet.")
            notice_block.append(quiet)

        services_table = Table.grid(padding=(0, 1), expand=True)
        services_table.add_column(no_wrap=True, width=2)
        services_table.add_column(no_wrap=True, width=12)
        services_table.add_column(no_wrap=True, width=10)
        services_table.add_column(overflow="fold")
        services_layout = (
            ("Gateway", "gateway"),
            ("Agent", "agent"),
            ("Watchdog", "watcher"),
            ("Guardrail", "guardrail"),
            ("API", "api"),
            ("Sinks", "sinks"),
            ("Telemetry", "telemetry"),
            ("AI Discovery", "ai_discovery"),
            ("Sandbox", "sandbox"),
        )
        for display_name, key in services_layout:
            state = state_by_key.get(key, "unknown")
            color = state_color(state)
            normalized = (state or "").strip().lower()
            dot = "●" if normalized in {"running", "active", "enabled", "clean", "allowed"} else "○"
            detail = detail_by_key.get(key, "") or ""
            services_table.add_row(
                Text(dot, style=color),
                Text(display_name, style=TOKENS.text_primary),
                Text(state or "unknown", style=color),
                Text(detail, style=TOKENS.text_secondary),
            )

        selected_connector = self._connector_filter()
        selected_scan: dict[str, int] | None = None

        cfg_table = Table.grid(padding=(0, 2), expand=True)
        cfg_table.add_column(width=17, no_wrap=True)
        cfg_table.add_column(overflow="fold")
        if selected_connector:
            cfg_rows: list[tuple[str, RenderableType]] = [
                (label, Text(value)) for label, value in self._connector_configuration_lines(selected_connector)
            ]
        else:
            cfg_rows = [
                ("Agent", Text(self.overview_model.active_connector_name())),
                (
                    "Redaction",
                    Text.from_markup(
                        f"[{TOKENS.accent_green}]ON (redacted)[/]"
                        if cfg and not cfg.privacy_disable_redaction
                        else f"[{TOKENS.accent_red}]OFF (RAW)[/]"
                    ),
                ),
                ("Policy posture", Text(_policy_posture(cfg))),
                ("Enforcement", Text(_enforcement_label(cfg))),
                (
                    "Human approval",
                    Text.from_markup(
                        f"[{TOKENS.accent_green}]ON[/] (min {cfg.hilt_min_severity or 'HIGH'})"
                        if cfg and cfg.hilt_enabled
                        else f"[{TOKENS.text_muted}]OFF[/]"
                    ),
                ),
                ("Environment", Text((cfg.environment if cfg else "") or "unknown")),
                ("Policy dir", Text((cfg.policy_dir if cfg else "") or "—")),
                ("Data dir", Text((cfg.data_dir if cfg else "") or "—")),
            ]
            # 8.13: when more than one connector is active, replace the
            # primary-only "Agent: <connector>" line with a concise
            # "Agents: N active" header. The full per-connector roster (mode,
            # rule pack, status, live counts) now lives in the dedicated
            # CONNECTORS table below, so we don't duplicate it here. No-op for
            # the common single-connector install.
        overview_connector_rows = self._overview_connector_rows()
        if overview_connector_rows and not selected_connector:
            cfg_rows[0] = (
                "Agents",
                Text(f"{len(overview_connector_rows)} active", style=TOKENS.text_secondary),
            )
        llm_provider = (cfg.llm_provider if cfg else "") or (cfg.inspect_llm_provider if cfg else "")
        llm_model = (cfg.llm_model if cfg else "") or (cfg.inspect_llm_model if cfg else "")
        if llm_provider:
            label = f"{llm_provider} (global)" if selected_connector else llm_provider
            cfg_rows.append(("LLM provider", Text(label)))
        if llm_model:
            label = f"{llm_model} (global)" if selected_connector else llm_model
            cfg_rows.append(("LLM model", Text(label)))
        if cfg and cfg.cisco_ai_defense_endpoint:
            label = (
                f"{cfg.cisco_ai_defense_endpoint} (global)"
                if selected_connector
                else cfg.cisco_ai_defense_endpoint
            )
            cfg_rows.append(("AI Defense", Text(label)))
        for label, value in cfg_rows:
            cfg_table.add_row(Text(label, style=TOKENS.text_secondary), value)

        enf_table = Table.grid(padding=(0, 2), expand=True)
        enf_table.add_column(width=12, no_wrap=True)
        enf_table.add_column(overflow="fold")
        # 8.13: when a connector is selected the ENFORCEMENT panel narrows to
        # that connector's real Alerts/Hook calls/Blocks (the connector-
        # attributed hook stream — same source as the CONNECTORS table) plus
        # per-connector inventory scan coverage. "All" keeps the original
        # global numbers.
        enf_selected = selected_connector
        if enf_selected:
            calls_n, alert_n, block_n = self._enforcement_connector_breakdown(enf_selected)
            alerts_color = TOKENS.accent_red if alert_n else TOKENS.accent_green
            enf_table.add_row(
                Text("Alerts", style=TOKENS.text_secondary),
                Text.from_markup(f"[{alerts_color} bold]{alert_n:<3}[/] {_mini_bar(alert_n, 20)}"),
            )
            enf_table.add_row(
                Text("Hook calls", style=TOKENS.text_secondary),
                Text.from_markup(f"[{TOKENS.accent_green}]{calls_n}[/]"),
            )
            blocks_color = TOKENS.accent_red if block_n else TOKENS.text_secondary
            enf_table.add_row(
                Text("Blocks", style=TOKENS.text_secondary),
                Text.from_markup(f"[{blocks_color} bold]{block_n}[/]"),
            )
        else:
            calls_n, _hook_alert_n, block_n = self._enforcement_scope_breakdown(
                self._active_connector_names()
            )
            alerts_color = TOKENS.accent_red if counts.active_alerts else TOKENS.accent_green
            enf_table.add_row(
                Text("Alerts", style=TOKENS.text_secondary),
                Text.from_markup(
                    f"[{alerts_color} bold]{counts.active_alerts:<3}[/] {_mini_bar(counts.active_alerts, 20)}"
                ),
            )
            enf_table.add_row(
                Text("Hook calls", style=TOKENS.text_secondary),
                Text.from_markup(f"[{TOKENS.accent_green}]{calls_n}[/]"),
            )
            blocks_color = TOKENS.accent_red if block_n else TOKENS.text_secondary
            enf_table.add_row(
                Text("Blocks", style=TOKENS.text_secondary),
                Text.from_markup(f"[{blocks_color} bold]{block_n}[/]"),
            )
        if self.overview_model.silent_bypass > 0:
            enf_table.add_row(
                Text("Silent bypass", style=TOKENS.accent_amber),
                Text.from_markup(
                    f"[{TOKENS.accent_red} bold]{self.overview_model.silent_bypass}[/] "
                    f"[{TOKENS.text_muted}](see Alerts -> egress)[/]"
                ),
            )
        if enf_selected:
            # Per-connector Skills/MCPs/scan coverage from that connector's own
            # aibom snapshot (not the gateway-wide audit totals). Loads lazily,
            # so show "scan pending" + trigger a one-shot load until it lands.
            self._request_enforcement_inventory(enf_selected)
            selected_scan = self._connector_scan_metrics(enf_selected)
            if selected_scan is None:
                enf_table.add_row(
                    Text("Skills", style=TOKENS.text_secondary),
                    Text.from_markup(f"[{TOKENS.text_muted}]scan pending — loading inventory…[/]"),
                )
            else:
                enf_table.add_row(
                    Text("Skills", style=TOKENS.text_secondary),
                    Text.from_markup(
                        f"[{TOKENS.text_primary}]{selected_scan['skills']}[/]   "
                        f"[{TOKENS.accent_red}]{selected_scan['skills_blocked']}[/] blocked   "
                        f"[{TOKENS.accent_green}]{selected_scan['skills_allowed']}[/] allowed"
                    ),
                )
                enf_table.add_row(
                    Text("MCPs", style=TOKENS.text_secondary),
                    Text.from_markup(f"[{TOKENS.text_primary}]{selected_scan['mcps']}[/] configured"),
                )
                enf_table.add_row(
                    Text("Scanned", style=TOKENS.text_secondary),
                    Text.from_markup(
                        f"[{TOKENS.accent_green}]{selected_scan['scanned']}[/]/{selected_scan['scannable']} assets"
                    ),
                )
        else:
            enf_table.add_row(
                Text("Total scans", style=TOKENS.text_secondary),
                Text.from_markup(f"[{TOKENS.accent_green}]{counts.total_scans}[/]"),
            )
            enf_table.add_row(
                Text("Skills", style=TOKENS.text_secondary),
                Text.from_markup(
                    f"[{TOKENS.accent_red}]{counts.blocked_skills}[/] blocked   "
                    f"[{TOKENS.accent_green}]{counts.allowed_skills}[/] allowed"
                ),
            )
            enf_table.add_row(
                Text("MCPs", style=TOKENS.text_secondary),
                Text.from_markup(
                    f"[{TOKENS.accent_red}]{counts.blocked_mcps}[/] blocked   "
                    f"[{TOKENS.accent_green}]{counts.allowed_mcps}[/] allowed"
                ),
            )

        keys = self.overview_model.keys_status()
        sc_table = Table.grid(padding=(0, 2), expand=True)
        sc_table.add_column(width=2, no_wrap=True)
        sc_table.add_column(width=14, no_wrap=True)
        sc_table.add_column(overflow="fold")
        # Mirror Go TUI: probe external scanners via PATH each render so
        # an operator who runs `brew install skill-scanner` sees the row
        # flip from "missing" to "installed" on the next 2 s refresh.
        # Built-ins (aibom + codeguard) ship inside the CLI and are
        # always available. Note: the field is named `aibom` (AI Bill
        # Of Materials) — historic copies of this list spelled it
        # "aibon", which is a typo.
        skill_available = bool(shutil.which("skill-scanner"))
        mcp_available = bool(shutil.which("mcp-scanner"))
        scanner_rows: list[tuple[str, str, str, str]] = [
            (
                "skill-scanner",
                "installed" if skill_available else "missing",
                TOKENS.accent_green if skill_available else TOKENS.accent_red,
                "●" if skill_available else "○",
            ),
            (
                "mcp-scanner",
                "installed" if mcp_available else "missing",
                TOKENS.accent_green if mcp_available else TOKENS.accent_red,
                "●" if mcp_available else "○",
            ),
            ("aibom", "built-in", TOKENS.text_secondary, "●"),
            ("codeguard", "built-in", TOKENS.text_secondary, "●"),
            (
                "guardrail",
                detail_by_key.get("guardrail", "") or (state_by_key.get("guardrail", "unknown")),
                state_color(state_by_key.get("guardrail", "unknown")),
                "●" if state_by_key.get("guardrail", "") == "running" else "○",
            ),
        ]
        self.overview_model.set_skill_scanner_available(skill_available)
        if keys.available:
            keys_label = keys.label or "all required set"
            keys_color = TOKENS.accent_green
            keys_dot = "●"
        else:
            keys_label = keys.label or "not checked"
            keys_color = TOKENS.accent_amber
            keys_dot = "●"
        scanner_rows.append(("keys", keys_label, keys_color, keys_dot))
        # 8.13: scanner *binaries* are machine-wide (same for every connector),
        # so the rows above don't change with the filter. What IS per-connector
        # is the enforcement policy the scanners apply — surface that as a
        # context row when a connector is selected.
        if enf_selected:
            context_rows: list[tuple[str, str, str, str]] = []
            policy_label = self._connector_policy_label(enf_selected)
            if policy_label:
                context_rows.append(("policy", policy_label, TOKENS.accent_cyan, "●"))
            if selected_scan is None:
                context_rows.append(("coverage", "scan pending", TOKENS.text_muted, "○"))
            else:
                scannable = selected_scan["scannable"]
                scanned = selected_scan["scanned"]
                complete = scannable > 0 and scanned >= scannable
                context_rows.append(
                    (
                        "coverage",
                        f"{scanned}/{scannable} assets",
                        TOKENS.accent_green if complete else TOKENS.accent_amber,
                        "●" if complete else "○",
                    ),
                )
            scanner_rows = [*context_rows, *scanner_rows]
        for label, value, color, dot in scanner_rows:
            sc_table.add_row(
                Text(dot, style=color),
                Text(label, style=TOKENS.text_primary),
                Text(value, style=color),
            )

        if doctor.empty:
            doctor_body: RenderableType = Text.from_markup(
                f"[{TOKENS.text_secondary}]not yet run — press [/]"
                f"[bold {TOKENS.accent_cyan}]d[/]"
                f"[{TOKENS.text_secondary}] to run doctor.[/]"
            )
        else:
            part_colors = {
                "pass": TOKENS.accent_green,
                "fail": TOKENS.accent_red,
                "warn": TOKENS.accent_amber,
                "stale": TOKENS.accent_blue,
                "skip": TOKENS.text_muted,
            }
            colored_parts: list[str] = []
            for part in doctor.summary_parts:
                bits = part.split()
                color = TOKENS.text_primary
                if len(bits) == 2:
                    color = part_colors.get(bits[1].lower(), TOKENS.text_primary)
                    colored_parts.append(
                        f"[{color} bold]{bits[0]}[/] [{TOKENS.text_secondary}]{bits[1]}[/]"
                    )
                else:
                    colored_parts.append(f"[{color}]{part}[/]")
            header_markup = "  ".join(colored_parts) if colored_parts else f"[{TOKENS.text_secondary}]no data[/]"
            if doctor.age_label:
                header_markup += f"  [{TOKENS.text_muted}]· {doctor.age_label}[/]"
            if doctor.stale:
                header_markup += (
                    f"  [{TOKENS.accent_amber}](stale — [/]"
                    f"[{TOKENS.accent_amber} bold]\\[d][/]"
                    f"[{TOKENS.accent_amber}] to rerun)[/]"
                )
            doctor_lines: list[RenderableType] = [Text.from_markup(header_markup)]
            if doctor.checks:
                doctor_lines.append(
                    Text("─" * 40, style=TOKENS.border_muted)
                )
            for check in doctor.checks[:3]:
                if check.badge == "FAIL":
                    badge_color = TOKENS.accent_red
                elif check.badge == "WARN":
                    badge_color = TOKENS.accent_amber
                elif check.badge == "STALE":
                    badge_color = TOKENS.accent_blue
                else:
                    badge_color = TOKENS.text_secondary
                detail_text = rich_escape(check.detail) if check.detail else ""
                detail = f"  [{TOKENS.text_muted}]{detail_text}[/]" if detail_text else ""
                badge_text = rich_escape(check.badge)
                label_text = rich_escape(check.label)
                doctor_lines.append(
                    Text.from_markup(
                        f"[{badge_color} bold]\\[{badge_text}][/] "
                        f"[{TOKENS.text_primary}]{label_text}[/]{detail}"
                    )
                )
            if doctor.all_green and not doctor.checks:
                doctor_lines.append(
                    Text.from_markup(
                        f"[{TOKENS.accent_green}]All checks passing — nothing to address.[/]"
                    )
                )
            doctor_body = Group(*doctor_lines)

        if ai_box.rows:
            ai_table = Table.grid(padding=(0, 2), expand=True)
            ai_table.add_column(width=4, no_wrap=True)
            ai_table.add_column(width=26, no_wrap=True, overflow="ellipsis")
            ai_table.add_column(width=20, no_wrap=True, overflow="ellipsis")
            ai_table.add_column(width=8, no_wrap=True)
            ai_table.add_column(overflow="ellipsis")
            for row in ai_box.rows[:6]:
                ai_table.add_row(
                    Text(row.state_badge),
                    Text(row.name, style=TOKENS.text_primary),
                    Text(row.vendor, style=TOKENS.text_secondary),
                    Text(row.confidence),
                    Text(row.seen_label, style=TOKENS.text_muted),
                )
            if ai_box.overflow:
                ai_table.add_row(
                    Text(""),
                    Text(f"+{ai_box.overflow} more", style=TOKENS.text_secondary),
                    Text(""),
                    Text(""),
                    Text(""),
                )
            ai_body: RenderableType = ai_table
        else:
            ai_body = Text(
                ai_box.message or "ai discovery offline — run: defenseclaw agent discovery status",
                style=TOKENS.text_secondary,
            )

        services_panel = Panel(
            services_table,
            title=Text("SERVICES", style=f"bold {TOKENS.accent_cyan}"),
            title_align="left",
            border_style=TOKENS.accent_cyan,
            padding=(0, 1),
        )
        cfg_panel = Panel(
            cfg_table,
            title=Text(
                f"CONFIGURATION · {selected_connector}" if selected_connector else "CONFIGURATION",
                style=f"bold {TOKENS.accent_blue}",
            ),
            title_align="left",
            border_style=TOKENS.accent_blue,
            padding=(0, 1),
        )
        enf_panel = Panel(
            enf_table,
            title=Text(
                f"ENFORCEMENT · {enf_selected}" if enf_selected else "ENFORCEMENT",
                style=f"bold {TOKENS.accent_amber}",
            ),
            title_align="left",
            border_style=TOKENS.accent_amber,
            padding=(0, 1),
        )
        sc_panel = Panel(
            sc_table,
            title=Text(
                f"SCANNERS · {selected_connector}" if selected_connector else "SCANNERS",
                style=f"bold {TOKENS.accent_orange}",
            ),
            title_align="left",
            border_style=TOKENS.accent_orange,
            padding=(0, 1),
        )
        doc_panel = Panel(
            doctor_body,
            title=Text("DOCTOR", style=f"bold {TOKENS.accent_pink}"),
            title_align="left",
            border_style=TOKENS.accent_pink,
            padding=(0, 1),
        )
        ai_panel = Panel(
            ai_body,
            title=Text("DISCOVERED AI AGENTS", style=f"bold {TOKENS.accent_violet}"),
            title_align="left",
            border_style=TOKENS.accent_violet,
            padding=(0, 1),
        )

        columns = Table.grid(expand=True, padding=(0, 1))
        columns.add_column(ratio=1)
        columns.add_column(ratio=1)
        columns.add_row(Group(services_panel, cfg_panel), Group(enf_panel, sc_panel, doc_panel))

        # 8.13: dedicated per-connector CONNECTORS table for multi-connector
        # installs. Empty for single-connector (panel omitted from the Group).
        connectors_panel = self._overview_connectors_panel(overview_connector_rows)

        quick_actions = [
            ("s", "Scan all"),
            ("d", "Doctor"),
            ("i", "Inventory"),
            ("g", "Guardrail"),
            ("m", "Mode"),
            ("l", "Logs"),
            ("R", "Redaction"),
            ("N", "Notify"),
            ("u", "Upgrade"),
            ("X", "Uninstall"),
            ("?", "Help"),
        ]
        quick_text = Text()
        for idx, (key, label) in enumerate(quick_actions):
            if idx > 0:
                quick_text.append("  ")
            quick_text.append("[", style=TOKENS.text_secondary)
            quick_text.append(key, style=f"bold {TOKENS.accent_cyan}")
            quick_text.append("] ", style=TOKENS.text_secondary)
            quick_text.append(label, style=TOKENS.text_primary)

        footer_hint = Text(
            "Use the tabs or number keys to drill into Alerts, Audit, Logs, and Setup.",
            style=f"italic {TOKENS.text_muted}",
        )

        connectors_block: list[RenderableType] = []
        if connectors_panel is not None:
            connectors_block = [connectors_panel, Text("")]

        return Group(
            banner,
            tagline,
            Text(""),
            *connector_chip_block,
            *notice_block,
            Text(""),
            columns,
            Text(""),
            *connectors_block,
            ai_panel,
            Text(""),
            quick_text,
            footer_hint,
        )

    def _overview_body_signature(self) -> tuple[object, ...]:
        """Fingerprint Overview content without volatile clock-only labels."""

        stable_text = re.sub(r"\buptime=\d+s\b", "uptime=<live>", self.body_text)
        stable_text = re.sub(r"\b\d+(?:s|m|h|d) ago\b", "<live> ago", stable_text)
        return ("overview", self.help_open, stable_text)

    def _overview_connectors_panel(
        self, rows: list[ConnectorOverviewRow]
    ) -> RenderableType | None:
        """Build the Rich CONNECTORS table panel, or ``None`` for ≤1 connector.

        Columns: CONNECTOR, MODE, RULE PACK, LAST ACTIVITY, CALLS, BLOCKS,
        ALERTS, STATUS. The STATUS cell shows a colored live-health dot;
        BLOCKS/ALERTS are tinted when non-zero so risk pops. Selecting a row
        and pressing Enter drills into Alerts filtered to that connector.
        """

        if not rows:
            return None
        table = Table.grid(padding=(0, 2), expand=True)
        table.add_column(no_wrap=True)  # CONNECTOR
        table.add_column(no_wrap=True)  # MODE
        table.add_column(no_wrap=True)  # RULE PACK
        table.add_column(no_wrap=True)  # LAST ACTIVITY
        table.add_column(justify="right", no_wrap=True)  # CALLS
        table.add_column(justify="right", no_wrap=True)  # BLOCKS
        table.add_column(justify="right", no_wrap=True)  # ALERTS
        table.add_column(no_wrap=True)  # STATUS
        header_style = f"bold {TOKENS.text_secondary}"
        table.add_row(
            Text("CONNECTOR", style=header_style),
            Text("MODE", style=header_style),
            Text("RULE PACK", style=header_style),
            Text("LAST ACTIVITY", style=header_style),
            Text("CALLS", style=header_style),
            Text("BLOCKS", style=header_style),
            Text("ALERTS", style=header_style),
            Text("STATUS", style=header_style),
        )
        selected = self._connector_filter()
        for row in rows:
            normalized = row.status.strip().lower() or "unknown"
            color_dot = state_color(normalized)
            dot = "●" if normalized in {"running", "active", "enabled"} else "○"
            status_cell = Text()
            status_cell.append(f"{dot} ", style=color_dot)
            status_cell.append(row.status or "unknown", style=color_dot)
            name = friendly_connector_name(row.connector)
            # Highlight the row matching the current filter selection.
            name_style = (
                f"bold {TOKENS.accent_cyan}"
                if selected and selected == row.connector.strip().lower()
                else TOKENS.text_primary
            )
            color_blocks = TOKENS.accent_red if row.blocks else TOKENS.text_muted
            color_alerts = TOKENS.accent_amber if row.alerts else TOKENS.text_muted
            table.add_row(
                Text(f"{name} ({row.connector})", style=name_style),
                Text(row.mode or "?", style=TOKENS.text_secondary),
                Text(row.rule_pack or "default", style=TOKENS.text_secondary),
                Text(row.last_activity, style=TOKENS.text_muted),
                Text(str(row.calls), style=TOKENS.text_primary),
                Text(str(row.blocks), style=color_blocks),
                Text(str(row.alerts), style=color_alerts),
                status_cell,
            )
        hint = Text(
            "Press m to filter every view by connector · with one selected, Enter opens its Alerts.",
            style=f"italic {TOKENS.text_muted}",
        )
        return Panel(
            Group(table, hint),
            title=Text("CONNECTORS", style=f"bold {TOKENS.accent_green}"),
            title_align="left",
            border_style=TOKENS.accent_green,
            padding=(0, 1),
        )

    def _overview_connectors_text(self, rows: list[ConnectorOverviewRow]) -> str:
        """Plain-text CONNECTORS section for the fallback body (or "")."""

        if not rows:
            return ""
        lines = [
            f"  [{TOKENS.text_secondary}]"
            f"{'CONNECTOR':<22}{'MODE':<10}{'PACK':<12}{'LAST':<10}"
            f"{'CALLS':>6}{'BLOCKS':>8}{'ALERTS':>8}  STATUS[/]"
        ]
        for row in rows:
            normalized = row.status.strip().lower() or "unknown"
            color_dot = state_color(normalized)
            dot = "●" if normalized in {"running", "active", "enabled"} else "○"
            name = f"{friendly_connector_name(row.connector)} ({row.connector})"
            color_blocks = TOKENS.accent_red if row.blocks else TOKENS.text_muted
            color_alerts = TOKENS.accent_amber if row.alerts else TOKENS.text_muted
            lines.append(
                f"  {name[:21]:<22}{(row.mode or '?'):<10}"
                f"{(row.rule_pack or 'default')[:11]:<12}{row.last_activity:<10}"
                f"{row.calls:>6}"
                f"[{color_blocks}]{row.blocks:>8}[/]"
                f"[{color_alerts}]{row.alerts:>8}[/]"
                f"  [{color_dot}]{dot} {row.status or 'unknown'}[/]"
            )
        body = "\n".join(lines)
        return f"[bold {TOKENS.accent_green}]CONNECTORS[/]\n{body}\n\n"

    def _overview_body_text(self, service_cards: tuple[Any, ...]) -> str:
        notices = self.overview_model.build_notices()
        doctor = self.overview_model.doctor_box()
        ai_box = self.overview_model.ai_discovery_box()
        cfg = self.overview_model.cfg
        counts = self._overview_session_enforcement_counts()
        state_by_key = {card.key: card.state or "unknown" for card in service_cards}
        detail_by_key = {card.key: card.detail or card.last_error for card in service_cards}
        health = self.overview_model.health
        connector_chip = self._connector_chip_text()

        notice_lines = []
        for notice in notices[:3]:
            color = TOKENS.accent_red if notice.level == "error" else TOKENS.accent_amber
            if notice.level == "info":
                color = TOKENS.accent_blue
            # Escape ``notice.message``: notice strings are operator-
            # facing prose (``press [g] to set up``) that may contain
            # bracketed tokens. Without the escape Rich parses them as
            # style tags and silently drops the bracketed text from
            # the rendered overview body.
            notice_lines.append(
                f"[{color}][{notice.level.upper()}][/] {rich_escape(notice.message)}"
            )
        if not notice_lines:
            notice_lines.append(f"[{TOKENS.accent_green}][OK][/] Runtime signals are quiet.")

        enf_selected = self._connector_filter()
        if enf_selected:
            config_lines = list(self._connector_configuration_lines(enf_selected))
        else:
            config_lines = [
                ("Agent", self.overview_model.active_connector_name()),
                (
                    "Redaction",
                    "ON - prompts and outputs are redacted" if cfg and not cfg.privacy_disable_redaction else "OFF",
                ),
                ("Policy posture", _policy_posture(cfg)),
                ("Enforcement", _enforcement_label(cfg)),
                ("Environment", (cfg.environment if cfg else "") or "unknown"),
                ("LLM provider", (cfg.llm_provider if cfg else "") or "-"),
                ("LLM model", (cfg.llm_model if cfg else "") or "-"),
            ]
        overview_connector_rows = self._overview_connector_rows()
        if overview_connector_rows and not enf_selected:
            # Multi: replace the redundant "Agent: <primary>" line (index 0)
            # with a unified "Agents: N active" header. The per-connector
            # detail lives in the CONNECTORS section appended below.
            config_lines[0] = ("Agents", f"{len(overview_connector_rows)} active")
        config_text = "\n".join(f"  {key:<16} {value}" for key, value in config_lines)

        connectors_text = self._overview_connectors_text(overview_connector_rows)

        scanner_lines = [
            ("Gateway", state_by_key.get("gateway", "unknown"), detail_by_key.get("gateway", "")),
            ("Watchdog", state_by_key.get("watcher", "unknown"), detail_by_key.get("watcher", "")),
            ("Guardrail", state_by_key.get("guardrail", "unknown"), detail_by_key.get("guardrail", "")),
            ("API", state_by_key.get("api", "unknown"), detail_by_key.get("api", "")),
            ("Sinks", state_by_key.get("sinks", "unknown"), detail_by_key.get("sinks", "")),
            ("Telemetry", state_by_key.get("telemetry", "unknown"), detail_by_key.get("telemetry", "")),
            ("AI Discovery", state_by_key.get("ai_discovery", "unknown"), detail_by_key.get("ai_discovery", "")),
        ]
        services_text = "\n".join(_overview_state_line(name, state, detail) for name, state, detail in scanner_lines)

        silent_line = (
            f"  Silent bypass   [{TOKENS.accent_red} bold]{self.overview_model.silent_bypass}[/] "
            f"[{TOKENS.text_muted}](see Alerts -> egress)[/]\n"
            if self.overview_model.silent_bypass > 0
            else ""
        )
        selected_scan: dict[str, int] | None = None
        if enf_selected:
            # Per-connector: hook decisions from the audit stream + Skills/MCPs/
            # scan coverage from this connector's own aibom snapshot (loads
            # lazily, so show "scan pending" + trigger a one-shot load).
            self._request_enforcement_inventory(enf_selected)
            calls_n, alert_n, block_n = self._enforcement_connector_breakdown(enf_selected)
            alert_color = TOKENS.accent_red if alert_n else TOKENS.accent_green
            block_color = TOKENS.accent_red if block_n else TOKENS.text_secondary
            selected_scan = self._connector_scan_metrics(enf_selected)
            if selected_scan is None:
                scan_lines = f"  Skills           [{TOKENS.text_muted}]scan pending — loading inventory…[/]\n"
            else:
                scan_lines = (
                    f"  Skills           [{TOKENS.text_primary}]{selected_scan['skills']}[/]   "
                    f"[{TOKENS.accent_red}]{selected_scan['skills_blocked']}[/] blocked   "
                    f"[{TOKENS.accent_green}]{selected_scan['skills_allowed']}[/] allowed\n"
                    f"  MCPs             [{TOKENS.text_primary}]{selected_scan['mcps']}[/] configured\n"
                    f"  Scanned          [{TOKENS.accent_green}]{selected_scan['scanned']}[/]/{selected_scan['scannable']} assets\n"
                )
            enforcement_text = (
                f"  Alerts           [{alert_color} bold]{alert_n}[/]   "
                f"Hook calls [{TOKENS.accent_green}]{calls_n}[/]   "
                f"Blocks [{block_color} bold]{block_n}[/]\n"
                + silent_line
                + scan_lines
            ).rstrip("\n")
        else:
            calls_n, _hook_alert_n, block_n = self._enforcement_scope_breakdown(
                self._active_connector_names()
            )
            alert_color = TOKENS.accent_red if counts.active_alerts else TOKENS.accent_green
            block_color = TOKENS.accent_red if block_n else TOKENS.text_secondary
            enforcement_text = (
                f"  Active alerts    [{alert_color} bold]{counts.active_alerts}[/]   "
                f"Total scans [{TOKENS.accent_green}]{counts.total_scans}[/]\n"
                + silent_line
                + f"  Hook calls       [{TOKENS.accent_green}]{calls_n}[/]   "
                f"Blocks [{block_color} bold]{block_n}[/]\n"
                + f"  Skills           [{TOKENS.accent_red}]{counts.blocked_skills}[/] blocked   "
                f"[{TOKENS.accent_green}]{counts.allowed_skills}[/] allowed\n"
                f"  MCPs             [{TOKENS.accent_red}]{counts.blocked_mcps}[/] blocked   "
                f"[{TOKENS.accent_green}]{counts.allowed_mcps}[/] allowed"
            )

        doctor_summary = "not yet run"
        doctor_lines: list[str] = []
        if not doctor.empty:
            doctor_summary = "  ".join(doctor.summary_parts) or "no data"
            doctor_summary += f"  {doctor.age_label}"
            if doctor.stale:
                doctor_summary += " (stale)"
            for check in doctor.checks[:2]:
                color = TOKENS.accent_red if check.badge == "FAIL" else TOKENS.accent_amber
                if check.badge == "STALE":
                    color = TOKENS.accent_blue
                doctor_lines.append(f"  [{color}][{check.badge}][/] {check.label} {check.detail}".rstrip())
        if not doctor_lines:
            doctor_lines.append("  Press d to run doctor.")

        ai_lines: list[str] = []
        if ai_box.rows:
            ai_lines.extend(
                f"  {row.state_badge} {row.name:<24} {row.vendor:<20} {row.confidence} {row.seen_label}"
                for row in ai_box.rows[:4]
            )
            if ai_box.overflow:
                ai_lines.append(f"  +{ai_box.overflow} more")
        else:
            ai_lines.append(f"  {ai_box.message or 'no AI agents detected yet'}")

        uptime = ""
        if health is not None and health.uptime_ms:
            uptime = f"  uptime={health.uptime_ms // 1000}s"
        keys = self.overview_model.keys_status()
        if keys.available:
            keys_line = keys.label or "all required set"
        else:
            keys_line = "not checked yet - press 0 for Setup, then r to refresh credentials"
        scanner_override_summary = self.overview_model.scanner_overrides_summary()
        scanner_override_line = (
            f"  overrides      {rich_escape(scanner_override_summary)}\n" if scanner_override_summary else ""
        )
        scanner_context = ""
        if enf_selected:
            policy_label = self._connector_policy_label(enf_selected)
            if policy_label:
                scanner_context += f"  policy         {policy_label}\n"
            if selected_scan is None:
                scanner_context += "  coverage       scan pending\n"
            else:
                scanner_context += (
                    f"  coverage       {selected_scan['scanned']}/{selected_scan['scannable']} assets\n"
                )
        # Escape the lowercase hotkey labels: Rich parses ``[s]`` /
        # ``[d]`` / ``[i]`` / ``[g]`` / ``[m]`` / ``[l]`` as opening
        # style tags and silently drops the bracketed text from the
        # rendered overview, so the operator sees ``Scan all`` with
        # no key to press. ``[R]`` is uppercase so Rich already treats
        # it as literal text — escaping is harmless either way.
        quick = (
            "\\[s] Scan all   \\[d] Doctor   \\[i] Inventory   "
            "\\[g] Guardrail   \\[m] Mode   \\[l] Logs   "
            "\\[R] Redaction"
        )
        return (
            "[bold #22D3EE]Overview[/]  [#9FB2CC]Command center for live risk, setup health, and next actions.[/]\n"
            f"[italic]DefenseClaw v{__version__}{uptime}[/]\n\n"
            f"{connector_chip}"
            f"[bold {TOKENS.accent_green}]WHAT NEEDS ATTENTION[/]\n"
            + "\n".join(notice_lines)
            + "\n\n"
            f"[bold {TOKENS.accent_blue}]SERVICES[/]\n{services_text}\n\n"
            + (
                f"[bold {TOKENS.accent_amber}]ENFORCEMENT · {enf_selected}[/]\n"
                if enf_selected
                else f"[bold {TOKENS.accent_amber}]ENFORCEMENT[/]\n"
            )
            + f"{enforcement_text}\n\n"
            + (
                f"[bold {TOKENS.accent_green}]CONFIGURATION · {enf_selected}[/]\n"
                if enf_selected
                else f"[bold {TOKENS.accent_green}]CONFIGURATION[/]\n"
            )
            + f"{config_text}\n\n"
            + connectors_text
            + (
                f"[bold {TOKENS.accent_orange}]SCANNERS · {enf_selected}[/]\n"
                if enf_selected
                else f"[bold {TOKENS.accent_orange}]SCANNERS[/]\n"
            )
            + scanner_context
            + scanner_override_line
            + f"  skill-scanner  {'installed' if self.overview_model.skill_scanner_available else 'missing'}\n"
            f"  credentials    {keys_line}\n\n"
            f"[bold {TOKENS.accent_pink}]DOCTOR[/]  {doctor_summary}\n" + "\n".join(doctor_lines) + "\n\n"
            f"[bold {TOKENS.accent_cyan}]DISCOVERED AI AGENTS[/]\n" + "\n".join(ai_lines) + "\n\n"
            f"[bold {TOKENS.text_primary}]ACTIONS[/]  {quick}\n"
            "[#9FB2CC]Use the tabs or number keys to drill into Alerts, Audit, Logs, and Setup.[/]"
        )

    def _inventory_body_text(self) -> str:
        tabs = "  ".join(
            f"[{TOKENS.accent_violet} bold]{tab.display_label}[/]"
            if tab.active
            else f"[{TOKENS.text_secondary}]{tab.display_label}[/]"
            for tab in self.inventory_model.subtab_info()
        )
        scope = self.inventory_model.scope_state()
        chips = " ".join(
            f"[{TOKENS.accent_violet} bold]{chip.label}[/]"
            if chip.active
            else f"[{TOKENS.text_muted}]{chip.label}[/]"
            for chip in scope.chips
        )
        filter_text = f"  filter={self.inventory_model.filter or 'all'}"
        # 8.13: surface the shared connector filter chip (multi-connector
        # installs) so it's explicit which connector's inventory is shown and
        # how to change it. Empty for single-connector installs.
        connector_chip = self._connector_chip_text()
        return (
            "[bold #22D3EE]Inventory[/]\n"
            f"{connector_chip}"
            f"{tabs}\n"
            f"{scope.label}: {chips} {scope.hint}{filter_text}\n"
            "Keys: h/l sub-tabs, 1 all, 2/3/4 filter Skills or Plugins, r reload, o fast scope, Enter detail."
        )

    def _logs_body_text(self) -> str:
        header = self.logs_model.header_state()
        tabs = "  ".join(
            f"[{TOKENS.accent_violet} bold]{index}:{tab.label}[/]"
            if tab.active
            else f"[{TOKENS.text_secondary}]{index} {tab.label}[/]"
            for index, tab in enumerate(header.tabs, start=1)
        )
        status_color = TOKENS.accent_green if header.status.style_key == "live" else TOKENS.accent_amber
        lines = [
            "[bold #22D3EE]Logs[/]",
            f"{tabs}  [{status_color} bold]{header.status.label}[/]  {header.line_count_label}",
        ]
        if header.search_label:
            lines.append(f"[{TOKENS.accent_cyan}]{header.search_label}[/]")
        if header.search_prompt:
            lines.append(f"[{TOKENS.accent_cyan}]{header.search_prompt}[/]")
        for group in self.logs_model.chip_groups():
            chips = "  ".join(
                f"[{TOKENS.accent_violet} bold]{(chip.shortcut + ' ' if chip.shortcut else '')}{chip.label}[/]"
                if chip.active
                else f"[{TOKENS.text_secondary}]{(chip.shortcut + ' ' if chip.shortcut else '')}{chip.label}[/]"
                for chip in group.chips
            )
            lines.append(f"{group.label} {chips}")
        lines.append(self.logs_model.hint_text())
        return "\n".join(lines)

    def _audit_body_text(self) -> str:
        toolbar = self.audit_model.toolbar_state()
        # Escape the literal brackets around each action key so Rich
        # treats ``[e] export`` as plain text. Without the backslashes
        # the toolbar emitted a string like ``[e] export filter`` that
        # Rich's markup parser interpreted as an opening tag with
        # style ``e``; the renderer then raised
        # ``MissingStyle: 'e' is not a valid color`` and crashed the
        # whole TUI the moment the Audit panel was rendered (which
        # happens on every panel switch, every health poll, and every
        # ``_render_chrome`` call after a setup change like toggling
        # redaction).
        actions = "  ".join(f"\\[{action.key}] {action.label}" for action in toolbar.actions)
        lines = [
            "[bold #22D3EE]Audit Trail[/]  [#9FB2CC]Click common filters above, or search with field:value terms.[/]",
            f"{toolbar.summary_label}  {actions}",
        ]
        # ``filter_label`` and ``search_prompt`` are operator-supplied:
        # the filter chip and the ``/`` search field both echo whatever
        # the user typed (e.g. ``target:[skill]``). Without escaping,
        # ``[skill]`` parses as a style tag named ``skill`` and the
        # render path re-trips the same ``MissingStyle`` /
        # ``StyleSyntaxError`` crash the action-key fix above closed.
        # ``_safe_body_renderable`` catches the fallout defensively,
        # but escaping at source means we never waste a render frame.
        if toolbar.filter_label:
            lines.append(rich_escape(toolbar.filter_label))
        if toolbar.search_prompt:
            lines.append(f"[{TOKENS.accent_cyan}]{rich_escape(toolbar.search_prompt)}[/]")
        lines.append(
            "Search examples: severity:HIGH action:block target:skill run:<id>. "
            "Use Same target or Same run to correlate the selected event."
        )
        return "\n".join(lines)

    def _set_status(self, text: str) -> None:
        self.status_text = text
        strip = render_status_strip(self._hint_status_model())
        # ``text`` is operator-supplied via every ``_set_status`` caller —
        # including ``self.audit_model.active_filter_label()`` and the
        # logs search prompt — both of which echo whatever was typed
        # into the ``/`` field. Without ``_safe_body_renderable`` the
        # f-string below would feed ``Static.update`` markup like
        # ``[red] │ …`` and Textual's renderer would later trip
        # ``MissingStyle`` (same root cause as the audit toolbar
        # crash). Build a Text object via the defensive wrapper so a
        # hostile filter degrades to plain text instead of tearing
        # down the status strip mid-frame.
        self.query_one("#status", Static).update(
            self._safe_body_renderable(f"{text}  [#444444]│[/]  {strip}")
        )

    def _write_activity(self, text: str) -> None:
        self.activity_lines.append(text)
        self.query_one("#activity", RichLog).write(text)

    def _write_activity_safe(self, text: str) -> None:
        """Write subprocess output to the Activity RichLog without ever
        crashing the markup parser AND honouring terminal ANSI colors.

        Two failure modes this closes:

        1. Markup crash. The Activity RichLog is created with
           ``markup=True`` so the intentional-style writes
           (``[#FBBF24]running[/] foo``) light up with color. That
           makes raw subprocess stdout the single biggest source of
           MarkupError / MissingStyle frames in the TUI — a progress
           bar like ``Selection [3]:`` or an installer's ``[INFO]``
           prefix takes down the whole frame and never refreshes
           again until the panel is re-mounted.
        2. ANSI leak. ``defenseclaw`` subprocess output flows through
           ``ux.warn`` / ``ux.ok`` / ``click.style`` etc., all of
           which emit raw ANSI escape sequences (``\\x1b[1;33m``).
           ``rich_escape`` (the previous implementation) preserved
           those bytes verbatim, so the renderer showed them as
           literal text — operators saw ``[1;33m\u25b3 warning:[0m``
           in the panel instead of an actual yellow warning.

        Fix: route the text through :meth:`rich.text.Text.from_ansi`
        which both interprets SGR codes as Rich styles AND treats
        the resulting content as opaque (no further markup parsing
        re-trips the bracket crash). One call covers both problems
        without needing a separate ``rich_escape`` step.
        """

        self.activity_lines.append(text)
        self.query_one("#activity", RichLog).write(Text.from_ansi(text))

    def _export_audit(self, path: Path | None) -> Path:
        target = path or Path("defenseclaw-audit-export.json")
        if not target.is_absolute():
            target = (self.data_dir or Path.cwd()) / target
        rows = []
        store = getattr(self.audit_model, "store", None)
        for event in self.audit_model.filtered:
            full_event = event
            if store is not None and hasattr(store, "get_event"):
                try:
                    full_event = store.get_event(event.id) or event  # type: ignore[attr-defined]
                except Exception:  # noqa: BLE001 - export the visible row if hydration fails.
                    full_event = event
            rows.append(
                {
                    "id": full_event.id,
                    "timestamp": full_event.timestamp.isoformat(),
                    "action": full_event.action,
                    "target": full_event.target,
                    "actor": full_event.actor,
                    "details": full_event.details,
                    "severity": full_event.severity,
                    "run_id": full_event.run_id,
                }
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        # F-0781: audit exports can carry sensitive identifiers (targets,
        # actors, run ids), so the file must be owner-only rather than
        # world-readable under the operator's umask.
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
        return target

    def _refresh_hint(self) -> None:
        hint = self.query_one("#hint", HintBar)
        active_panel = (
            "first-run" if self.active_panel == "setup" and self.first_run_model.active else self.active_panel
        )
        elapsed_secs = (
            int(time.monotonic() - self._command_started_at)
            if self.command_running and self._command_started_at
            else 0
        )
        hint_state = HintState(
            active_panel=active_panel,
            filter_active=self._active_filter_label(),
            critical_alerts=self.alerts_model.critical_count(),
            total_alerts=sum(self.alerts_model.severity_counts().values()),
            commands_run=self.commands_run,
            command_running=self.command_running,
            command_label=self.command_label,
            command_elapsed_secs=elapsed_secs,
            logs_paused=bool(self.logs_model.paused),
            new_lines_since_pause=int(self.logs_model.new_lines_since_pause),
        )
        hint.refresh_hint(hint_state, self._hint_status_model())
        self.hint_text = str(getattr(hint, "content", ""))

    def _active_filter_label(self) -> str:
        if self.active_panel == "alerts":
            return self.alerts_model.active_filter_label()
        if self.active_panel == "audit":
            return self.audit_model.active_filter_label()
        if self.active_panel == "logs":
            return self.logs_model.search_text or self.logs_model.filter_mode
        if self.active_panel == "inventory":
            return self.inventory_model.filter
        if self.active_panel == "ai":
            return self.ai_discovery_model.filter_text
        if self.active_panel in self.catalog_models:
            return self.catalog_models[self.active_panel].filter_text
        return ""

    def _hint_status_model(self) -> StatusModel:
        # Missing required credentials surface on a dedicated "Keys"
        # pill instead of being overlaid onto Guardrail. The previous
        # design lit Guardrail red while the SERVICES box showed
        # Guardrail green, because Guardrail can be live even when
        # the gateway-side ``OPENCLAW_GATEWAY_TOKEN`` is absent. The
        # two pills now report distinct, non-conflicting facts.
        missing_keys: tuple[str, ...] = ()
        if not self.first_run_model.active:
            snapshot = getattr(self.setup_model, "credential_snapshot", None)
            missing_required = tuple(getattr(snapshot, "missing_required", ()) or ())
            missing_keys = tuple(row.env_name for row in missing_required if row.env_name)

        guardrail_state = self.overview_model.subsystem_state("guardrail") or "disabled"
        guardrail_detail = self.overview_model.service_detail("guardrail")
        guardrail = ServiceStatus("Guardrail", guardrail_state, guardrail_detail)

        # Gateway / Watchdog mirror the live /health subsystem state
        # so the strip and the SERVICES box agree.
        gateway_state = self.overview_model.subsystem_state("gateway") or "unknown"
        gateway_detail = self.overview_model.service_detail("gateway")

        # Context pills (connector / redaction / policy) only render
        # when we have a loaded configuration to draw from. Before
        # config is loaded ``cfg`` is None, and claiming "Redaction
        # ON" or a policy posture in that window would be a lie — so
        # we suppress those pills entirely and let the operator see
        # the bare subsystem strip until config loads.
        cfg = self.overview_model.cfg
        connector_name = ""
        redaction_label = ""
        redaction_on = True
        policy_posture = ""
        if cfg is not None:
            connector_name = self.overview_model.active_connector_name() or (cfg.claw_mode or "").strip()
            # E4: in a multi-connector install the single connector pill
            # would name only the primary, hiding the fact that N
            # connectors are live. Surface the active connector filter — the
            # selected connector when filtered, else "All connectors (N)" —
            # so the strip stays honest. Single-connector installs keep the
            # bare name.
            actives = self._active_connector_names()
            if len(actives) > 1:
                selected = self._connector_filter()
                if selected:
                    connector_name = f"{selected} (filtered)"
                else:
                    connector_name = f"All connectors ({len(actives)})"
            redaction_on = not bool(cfg.privacy_disable_redaction)
            redaction_label = "Redaction ON" if redaction_on else "Redaction OFF"
            mode = (cfg.guardrail_mode or "").strip().lower()
            if mode:
                policy_posture = f"policy {mode}"

        return StatusModel(
            gateway=ServiceStatus("Gateway", gateway_state, gateway_detail),
            watchdog=ServiceStatus("Watchdog", self.overview_model.subsystem_state("watcher")),
            guardrail=guardrail,
            missing_keys=missing_keys,
            connector=connector_name,
            redaction_label=redaction_label,
            redaction_on=redaction_on,
            policy_posture=policy_posture,
            commands_run=int(self.commands_run),
            active_alerts=self.alerts_model.critical_count() or self.overview_model.enforcement.active_alerts,
            command_running=self.command_running,
            version=__version__,
        )

    def _render_panel_table(self) -> None:
        table = self.query_one("#panel-table", DataTable)
        if not self._table_columns:
            table.add_class("hidden")
            table.clear(columns=True)
            self._last_table_signature = None
            return

        # Idempotence guard: only tear down and rebuild the DataTable when the
        # panel, columns, rows, or target cursor actually changed. Without this
        # the 2 s refresh ticker cleared every row, reset the cursor, and
        # re-stole focus twice a second — so the Logs/Audit feeds were
        # unreadable (scroll + cursor jumped to the top continuously) and the
        # constant table.focus() read as the UI spontaneously jumping around.
        cursor_row = self._active_table_cursor() if self._table_rows else -1
        signature = (
            self.active_panel,
            self._table_columns,
            self._table_rows,
            cursor_row,
            self.active_panel == "setup" and self.setup_model.form_active,
        )
        if signature == self._last_table_signature:
            return

        table.remove_class("hidden")
        table.clear(columns=True)
        table.add_columns(*self._table_columns)
        for index, row in enumerate(self._table_rows):
            cells = (
                _styled_cell(column, value)
                for column, value in zip(self._table_columns, row, strict=True)
            )
            table.add_row(*cells, key=str(index))

        if self._table_rows:
            # move_cursor fires RowHighlighted; suppress the handler's model
            # write so restoring the cursor here can't pause the Logs stream.
            self._restoring_table_cursor = True
            try:
                table.move_cursor(row=cursor_row, column=0, animate=False)
            finally:
                self._restoring_table_cursor = False
            # Textual's DataTable binds left/right/enter to its own cursor
            # actions, which silently swallows the keys the setup wizard
            # form relies on (cycle choice, toggle bool, Ctrl+R submit).
            # When the wizard form is open we keep the row cursor visible
            # via the CSS rule on `.datatable--cursor` (no focus required)
            # but defocus the table so the app-level key handler — and
            # therefore `_handle_setup_form_key` — actually receives the
            # arrow keys.
            if self.active_panel == "setup" and self.setup_model.form_active:
                if self.focused is table:
                    self.set_focus(None)
            else:
                table.focus()
        self._last_table_signature = signature

    def _render_detail_panel(self) -> None:
        panel = self.query_one("#detail-panel", VerticalScroll)
        body = self.query_one("#detail-panel-body", Static)
        detail = self._detail_text()
        self.detail_text = detail
        if not detail:
            if not panel.has_class("hidden"):
                panel.add_class("hidden")
                body.update("")
            self._last_detail_signature = None
            return
        panel.remove_class("hidden")
        # Same idempotence guard as the body widget. Detail panes are
        # rendered identically every tick when nothing changed (e.g.
        # an alert row is selected and Activity is streaming); the
        # ``Static.update`` was the visible flicker source.
        detail_signature = (self.active_panel, detail)
        if detail_signature != self._last_detail_signature:
            # Detail strings can contain hostile-looking markup the
            # same way bodies do — judge history rows prefix labels
            # with ``[1] Timestamp`` and webhook summaries say
            # ``[enabled] https://…`` — both of which Rich would try
            # to parse as styles ``1`` / ``enabled`` and crash on
            # render. Route every detail update through the same
            # safety wrapper the body uses so a bogus span never
            # tears down the TUI.
            body.update(self._safe_body_renderable(detail))
            # New row / new panel: start at the top so the detail's
            # title and highest-signal lines are visible rather than
            # whatever scroll offset the previous (longer) detail left
            # behind.
            panel.scroll_home(animate=False)
            self._last_detail_signature = detail_signature

    def _detail_text(self) -> str:
        if self.active_panel == "alerts":
            return self.alerts_model.detail_text()
        if self.active_panel == "registries" and self.registries_model.detail_open:
            detail = self.registries_model.selected_detail_info()
            if detail is None:
                return ""
            lines = [f"[bold #A78BFA]{detail.title}[/]"]
            lines.extend(f"{key}: {value}" for key, value in detail.fields)
            return "\n".join(lines)
        if self.active_panel == "audit" and self.audit_model.detail_open:
            pairs = self.audit_model.detail_pairs()
            if not pairs:
                return ""
            return "[bold #A78BFA]EVENT[/]\n" + "\n".join(f"{key}: {value}" for key, value in pairs[:18])
        if self.active_panel == "inventory" and self.inventory_model.detail_open:
            detail = self.inventory_model.detail_info()
            if detail is None:
                return ""
            lines = ["[bold #A78BFA]" + detail.title + "[/]"]
            lines.extend(f"{key}: {value}" for key, value in detail.fields)
            return "\n".join(lines)
        if self.active_panel in self.catalog_models:
            model = self.catalog_models[self.active_panel]
            if model.detail_open:
                return catalog_detail_text(model.selected())
        if self.active_panel == "ai" and self.ai_discovery_model.detail_open:
            return self._ai_discovery_detail_text()
        if self.active_panel == "logs" and self.logs_model.source in {"verdicts", "otel"}:
            pairs = self.logs_model.selected_detail_pairs()
            if pairs:
                return "[bold #A78BFA]LOG DETAIL[/]\n" + "\n".join(
                    f"{key}: {value}" for key, value in pairs[:14]
                )
        return ""

    def _ai_discovery_detail_text(self) -> str:
        lines = [self.ai_discovery_model.detail_header(), *self.ai_discovery_model.detail_lines(limit=8)]
        return "\n".join(line for line in lines if line)

    def _update_body_only(self) -> None:
        body_widget = self.query_one("#body", Static)
        if self.active_panel == "overview" and not self.help_open:
            try:
                current_scroll_y = self.query_one("#body-scroll", VerticalScroll).scroll_y
            except NoMatches:
                current_scroll_y = None
            with self._connector_hook_event_render_cache():
                renderable = self._overview_renderable()
                body_signature = self._overview_body_signature()
                if body_signature != self._last_body_signature:
                    body_widget.update(renderable)
                    self._last_body_signature = body_signature
                self._overview_last_render_scroll_y = current_scroll_y
        else:
            # Same defense-in-depth as ``_render_chrome`` — any panel's
            # body string can contain malformed markup (the audit
            # toolbar's ``[e] export`` was the canonical case) and we
            # must never let a single bad span crash the renderer
            # mid-frame and tear down the TUI.
            text = self._body_text()
            body_signature = (self.active_panel, self.help_open, text)
            if body_signature != self._last_body_signature:
                body_widget.update(self._safe_body_renderable(text))
                self._last_body_signature = body_signature
        self._render_panel_controls()
        self._render_detail_panel()

    def _active_table_cursor(self) -> int:
        if self.active_panel == "alerts":
            return self.alerts_model.cursor
        if self.active_panel == "registries":
            return self.registries_model.cursor
        if self.active_panel in self.catalog_models:
            return self.catalog_models[self.active_panel].cursor
        if self.active_panel == "logs":
            return self.logs_model.cursor[self.logs_model.source]
        if self.active_panel == "audit":
            return self.audit_model.cursor
        if self.active_panel == "inventory":
            return self.inventory_model.cursor
        if self.active_panel == "ai":
            return self.ai_discovery_model.cursor
        if self.active_panel == "setup":
            return self._setup_cursor()
        return 0

    def _handle_active_panel_key(self, event: events.Key) -> bool:
        if self.help_open:
            return False
        key = _panel_key(event)
        # 8.13: the connector filter is shared, so ``m`` opens the filter
        # picker on the signal panes too (Alerts/Audit/Logs). These panes
        # don't otherwise bind ``m``. Catalog/Overview/Inventory route ``m``
        # in their own branches below.
        if (
            key == "m"
            and len(self._active_connector_names()) > 1
            and self.active_panel in {"alerts", "audit", "logs"}
        ):
            self.run_worker(self._open_mode_picker(), exclusive=False, thread=False)
            return True
        if self.active_panel == "alerts":
            action = self.alerts_model.handle_key(key)
            return self._apply_alert_action(action)
        if self.active_panel == "registries":
            action = self.registries_model.handle_key(key)
            return self._apply_registry_action(action)
        if self.active_panel in self.catalog_models:
            # 8.13: the catalog chip advertises "press m to filter". In a
            # multi-connector install route `m` to the shared connector
            # filter picker so it works consistently across panes.
            if key == "m" and len(self._active_connector_names()) > 1:
                self.run_worker(self._open_mode_picker(), exclusive=False, thread=False)
                return True
            catalog_key = _catalog_key(key)
            if catalog_key not in {"j", "k", "up", "down", "esc", "r"}:
                self._sync_catalog_cursor_from_table(self.active_panel)
            action = self.catalog_models[self.active_panel].handle_key(catalog_key)
            return self._apply_catalog_action(self.active_panel, action)
        if self.active_panel == "logs":
            if key == "enter" and not self.logs_model.searching:
                return self._open_logs_detail()
            action = self.logs_model.handle_key(_vim_key(key))
            return self._apply_logs_action(action)
        if self.active_panel == "audit":
            action = self.audit_model.handle_key(_vim_key(key))
            return self._apply_audit_action(action)
        if self.active_panel == "overview":
            if key == "m":
                self.run_worker(self._open_mode_picker(), exclusive=False, thread=False)
                return True
            if self._scroll_overview_body(key):
                return True
            # 8.13 drill-down: with a connector selected in the shared filter,
            # Enter jumps to that connector's Alerts (already pre-filtered).
            # With no selection in a multi-connector install, Enter opens the
            # filter picker first so the operator can choose one.
            if key == "enter" and len(self._active_connector_names()) > 1:
                if self._connector_filter():
                    self.action_switch_panel("alerts")
                else:
                    self.run_worker(self._open_mode_picker(), exclusive=False, thread=False)
                return True
            if key in {"i", "l"}:
                self.action_switch_panel({"i": "inventory", "l": "logs"}[key])
                return True
            if key in {"R", "N", "X"}:
                if key == "R":
                    self.run_worker(self._open_redaction_toggle(), exclusive=False, thread=False)
                elif key == "N":
                    self.run_worker(self._open_notifications_toggle(), exclusive=False, thread=False)
                else:
                    self.run_worker(self._open_uninstall_modal(), exclusive=False, thread=False)
                return True
            intent = self.overview_model.action_intent(key)
            if intent is None:
                return False
            self.run_worker(self._confirm_and_run_intent(intent), exclusive=False, thread=False)
            return True
        if self.active_panel == "inventory":
            # Inventory honors the shared connector filter too, so `m`
            # opens the same filter picker in a multi-connector install.
            if key == "m" and len(self._active_connector_names()) > 1:
                self.run_worker(self._open_mode_picker(), exclusive=False, thread=False)
                return True
            action = self._handle_inventory_key(key)
            return self._apply_inventory_action(action)

        if self.active_panel == "ai":
            action = self.ai_discovery_model.handle_key(_vim_key(key))
            return self._apply_ai_discovery_action(action)
        if self.active_panel == "activity":
            return self._handle_activity_key(key)
        if self.active_panel == "setup":
            if self.first_run_model.active:
                action = self.first_run_model.handle_key(_vim_key(key))
                return self._apply_first_run_action(action)
            action = self._handle_setup_key(_vim_key(key))
            return self._apply_setup_action(action)
        return False

    def _scroll_overview_body(self, key: str) -> bool:
        """Handle fast keyboard scrolling for the dense Overview dashboard."""

        if self.active_panel != "overview" or self.help_open or len(self.screen_stack) > 1:
            return False
        key = key.lower()
        scroll_line_keys = {"down", "j"}
        scroll_up_keys = {"up", "k"}
        page_down_keys = {"pagedown", "page_down", "ctrl+f"}
        page_up_keys = {"pageup", "page_up", "ctrl+b"}
        try:
            scroller = self.query_one("#body-scroll", VerticalScroll)
        except NoMatches:
            return False
        if key in scroll_line_keys:
            self._mark_overview_scroll_activity()
            scroller.scroll_relative(y=6, animate=False, immediate=True)
            return True
        if key in scroll_up_keys:
            self._mark_overview_scroll_activity()
            scroller.scroll_relative(y=-6, animate=False, immediate=True)
            return True
        if key in page_down_keys:
            self._mark_overview_scroll_activity()
            scroller.scroll_page_down(animate=False)
            return True
        if key in page_up_keys:
            self._mark_overview_scroll_activity()
            scroller.scroll_page_up(animate=False)
            return True
        if key == "home":
            self._mark_overview_scroll_activity()
            scroller.scroll_to(y=0, animate=False, immediate=True)
            return True
        if key == "end":
            self._mark_overview_scroll_activity()
            scroller.scroll_to(y=scroller.max_scroll_y, animate=False, immediate=True)
            return True
        return False

    def _apply_alert_action(self, action: AlertPanelAction) -> bool:
        if not action.handled:
            return False
        if action.copy_text:
            # The alerts panel signals "copy this to the clipboard" by
            # populating ``copy_text``. Without this branch the hint
            # said "Alert detail copied." but nothing actually landed
            # in the system clipboard — pure lie. Reusing the shared
            # ``_clipboard_copy`` helper means the alert ``y`` flow
            # benefits from the same pbcopy → wl-copy → xclip → xsel
            # → file fallback chain as the global ``Y`` binding.
            ok, transport = self._clipboard_copy(action.copy_text)
            if ok and not transport.startswith("file:"):
                self.notify_toast("success", f"Copied alert detail ({transport}).")
            elif ok:
                # File fallback — surface where the bytes went.
                self.notify_toast("info", f"Wrote alert detail to {transport[5:]}.")
            else:
                self.notify_toast(
                    "error",
                    "Copy failed — install pbcopy / wl-copy / xclip and try again.",
                )
        if action.hint:
            self._set_status(action.hint)
        if action.intent is not None:
            self.run_worker(self._confirm_and_run_intent(action.intent), exclusive=False, thread=False)
        self._render_chrome()
        return True

    def _apply_registry_action(self, action: RegistryPanelAction) -> bool:
        if not action.handled:
            return False
        if action.hint:
            self._set_status(action.hint)
        if action.intent is not None:
            self.run_worker(self._confirm_and_run_intent(action.intent), exclusive=False, thread=False)
        self._render_chrome()
        return True

    def _apply_catalog_action(self, panel: str, action: CatalogPanelAction) -> bool:
        if not action.handled:
            return False
        if action.hint:
            self._set_status(action.hint)
        if action.registry_focus is not None:
            focus = action.registry_focus
            self.registries_model.focus_entry(focus.entry_type, focus.name)
            self.action_switch_panel("registries")
            self._set_status(f"Focused registry entry {focus.name}.")
            return True
        if action.open_mcp_set_form:
            self.run_worker(self._open_mcp_set_form(), exclusive=False, thread=False)
        elif action.open_action_menu:
            self.run_worker(self._open_catalog_action_menu(panel), exclusive=False, thread=False)
        elif action.reload_requested:
            self.run_worker(self._load_catalog_model(panel), exclusive=False, thread=False)
        elif action.intent is not None:
            self._run_catalog_intent(action.intent)
        self._render_chrome()
        return True

    def _apply_simple_action(self, action: Any) -> bool:
        if not action.handled:
            return False
        if getattr(action, "hint", ""):
            self._set_status(action.hint)
        self._render_chrome()
        return True

    def _apply_logs_action(self, action: Any) -> bool:
        if not action.handled:
            return False
        if getattr(action, "hint", ""):
            self._set_status(action.hint)
        modal = getattr(action, "modal", None)
        if modal == "redaction":
            self.run_worker(self._open_redaction_toggle(), exclusive=False, thread=False)
        elif modal == "notifications":
            self.run_worker(self._open_notifications_toggle(), exclusive=False, thread=False)
        elif modal == "judge-history":
            self.run_worker(self._open_judge_history_detail(), exclusive=False, thread=False)
        self._render_chrome()
        return True

    def _open_logs_detail(self) -> bool:
        pairs = self.logs_model.selected_detail_pairs()
        if not pairs:
            self._set_status("No log row selected.")
            return True
        title_by_source = {
            "gateway": "Gateway log line",
            "watchdog": "Watchdog log line",
            "verdicts": "Gateway event",
            "otel": "OTEL event",
        }
        self.run_worker(
            self._open_detail_screen(title_by_source.get(self.logs_model.source, "Log detail"), pairs),
            exclusive=False,
            thread=False,
        )
        return True

    def _apply_audit_action(self, action: Any) -> bool:
        if not action.handled:
            return False
        if getattr(action, "intent", None) is not None and action.intent.kind == "export":
            path = self._export_audit(action.intent.path)
            self._render_chrome()
            self._set_status(f"Audit exported to {path}.")
            return True
        if getattr(action, "hint", ""):
            self._set_status(action.hint)
        self._render_chrome()
        return True

    def _handle_inventory_key(self, key: str) -> Any:
        return self.inventory_model.handle_key(_vim_key(key))

    def _apply_inventory_action(self, action: Any) -> bool:
        if not action.handled:
            return False
        if getattr(action, "hint", ""):
            self._set_status(action.hint)
        if getattr(action, "intent", None) is not None:
            self.run_worker(self._load_inventory_model(), exclusive=False, thread=False)
        self._render_chrome()
        return True

    def _apply_ai_discovery_action(self, action: Any) -> bool:
        if not action.handled:
            return False
        if getattr(action, "hint", ""):
            self._set_status(action.hint)
        intent = getattr(action, "intent", None)
        if intent is not None:
            if tuple(intent.args) == ("agent", "usage", "--json"):
                self.run_worker(self._load_ai_discovery_model(), exclusive=False, thread=False)
            else:
                self.run_worker(
                    self._run_command(
                        intent.binary,
                        intent.args,
                        display_name=getattr(intent, "label", None),
                    ),
                    exclusive=False,
                    thread=False,
                )
        self._render_chrome()
        return True

    def _apply_setup_action(self, action: SetupPanelAction) -> bool:
        if not action.handled:
            return False
        status_message = action.hint
        if action.hint:
            self._set_status(action.hint)
        if action.clear_restart_queue:
            self.setup_model.clear_restart_queue()
        if action.open_diff:
            self.run_worker(self._open_config_diff(), exclusive=False, thread=False)
        if action.open_resource_editor:
            self.run_worker(
                self._open_setup_resource_editor(action.open_resource_editor),
                exclusive=False,
                thread=False,
            )
        if action.refresh_credentials:
            self.run_worker(self._load_setup_credentials(), exclusive=False, thread=False)
        if action.open_model_picker:
            self.run_worker(self._open_model_picker(), exclusive=False, thread=False)
        if action.intent is not None:
            self.run_worker(self._confirm_and_run_intent(action.intent), exclusive=False, thread=False)
        self._render_chrome()
        if status_message:
            self._set_status(status_message)
        return True

    def _apply_first_run_action(self, action: Any) -> bool:
        if not action.handled:
            return False
        if action.intent is not None:
            self.run_worker(self._confirm_and_run_intent(action.intent), exclusive=False, thread=False)
        self._render_chrome()
        return True

    def _handle_activity_key(self, key: str) -> bool:
        if self.command_running:
            sent = self._forward_activity_stdin(key)
            if sent:
                return True
        if key == "!":
            last = self.activity_model.last_command
            if not last:
                self._set_status("No Activity command to rerun.")
                return True
            try:
                parsed = parse_command_line(last)
            except CommandLineError as exc:
                self._set_status(f"Cannot rerun command: {exc}")
                return True
            if parsed.needs_preview:
                self.run_worker(self._confirm_and_run_parsed(parsed), exclusive=False, thread=False)
            else:
                self.run_worker(
                    self._run_command(parsed.binary, parsed.args, display_name=parsed.display_name),
                    exclusive=False,
                    thread=False,
                )
            return True
        self.activity_model.handle_key(_vim_key(key))
        self._render_chrome()
        return key in {"1", "2", "up", "down", "j", "k", "enter", "t", "q", "esc"}

    def _forward_activity_stdin(self, key: str) -> bool:
        if key in {"up", "down", "j", "k", "esc", "q"}:
            return False
        if key == "enter":
            self.executor.write_stdin("\n")
        elif key == "backspace":
            self.executor.write_stdin("\x7f")
        elif key == "tab":
            self.executor.write_stdin("\t")
        elif key == "space":
            self.executor.write_stdin(" ")
        elif len(key) == 1:
            self.executor.write_stdin(key)
        else:
            return False
        self._set_status("Sent input to running command.")
        return True

    def _setup_table(self) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]:
        if self.first_run_model.active:
            return (
                ("Field", "Value", "Hint"),
                tuple((field.label, field.display_value, field.hint) for field in self.first_run_model.fields),
            )
        if self.setup_model.goal_active:
            return (
                ("Goal", "What it does"),
                tuple((goal.label, goal.summary) for goal in self.setup_model.goals),
            )
        if self.setup_model.form_active:
            return (
                ("Field", "Value", "Kind", "Hint"),
                tuple(
                    (
                        field.label,
                        render_wizard_value(field, reveal=self.setup_model.form_reveal),
                        str(field.kind),
                        field.hint,
                    )
                    for field in self.setup_model.form_fields
                ),
            )
        if self.setup_model.mode == "config":
            if not self.setup_model.sections:
                return ("Field", "Value", "Hint"), ()
            section = self.setup_model.sections[self.setup_model.active_section]
            return (
                ("Field", "Value", "Validation", "Hint"),
                tuple(
                    (
                        field.label,
                        _config_display_value(field),
                        _validation_label(field),
                        field.hint,
                    )
                    for field in section.fields
                ),
            )
        rows = []
        for info in self.setup_model.wizard_infos():
            rows.append((info.name, info.status, "defenseclaw " + " ".join(info.command), info.description))
        return ("Wizard", "Status", "Command", "Description"), tuple(rows)

    def _setup_body_text(self) -> str:
        self._chip_click_segments = []
        if self.first_run_model.active:
            self._chip_click_segments = []
            return (
                "[bold #22D3EE]DefenseClaw first-run setup[/]\n"
                f"{self.first_run_model.empty_state()}\n\n"
                "Keys: up/down select, left/right change, Ctrl+R run init, 0 Setup.\n"
                "This uses the canonical init backend and keeps the full setup wizard available."
            )
        if self.setup_model.goal_active:
            wizard_idx = int(self.setup_model.active_wizard)
            wizard = WIZARD_NAMES[wizard_idx]
            summary = wizard_state_summary(self.setup_model.active_wizard, self.setup_model.config)
            summary_line = f"[{TOKENS.text_secondary}]{rich_escape(summary)}[/]\n" if summary else ""
            return (
                f"[bold #22D3EE]Setup[/] · [bold]{wizard}[/] · What do you want to do?\n"
                f"{summary_line}"
                f"[{TOKENS.text_muted}]Enter choose · ↑/↓ move · Esc back · "
                f"Advanced opens the full form[/]"
            )
        if self.setup_model.form_active:
            wizard_idx = int(self.setup_model.active_wizard)
            wizard = WIZARD_NAMES[wizard_idx]
            description = WIZARD_DESCRIPTIONS[wizard_idx]
            how_to = WIZARD_HOW_TO[wizard_idx]
            error = f"\n[#F87171]{self.setup_model.form_error}[/]" if self.setup_model.form_error else ""
            focused = self.setup_model.focused_row_metadata()
            reveal = "ON" if self.setup_model.form_reveal else "OFF"
            preview = self.setup_model.wizard_command_preview()
            missing = self.setup_model.missing_required_fields()
            missing_line = (
                f"\n[#FBBF24]Required fields still empty:[/] {', '.join(missing)}" if missing else ""
            )
            focused_line = (
                f"[{TOKENS.accent_violet} bold]→ {focused.label}[/] "
                f"[{TOKENS.text_secondary}]({focused.kind})[/]"
            )
            focused_action = (
                f"  [{TOKENS.text_muted}]{focused.action.hotkey} {focused.action.description}[/]"
                if focused.action
                else ""
            )
            return (
                f"[bold #22D3EE]Setup Wizard[/]  [bold]{wizard}[/]   "
                f"[{TOKENS.text_muted}]{description}[/]\n"
                f"[{TOKENS.text_secondary}]{how_to}[/]\n"
                f"[bold]Will run:[/] [{TOKENS.accent_green}]$ {preview}[/]\n"
                f"{focused_line}{focused_action}\n"
                f"[{TOKENS.text_muted}]"
                f"Keys: ↑/↓ move · ←/→ or space cycle choice · type to edit · "
                f"Ctrl+T reveal={reveal} · [bold]Ctrl+R run[/] · Esc cancel"
                f"[/]"
                f"{missing_line}"
                # Escape ``focused.hint`` so a wizard hint that quotes a
                # bracketed identifier (e.g. ``set webhooks[0].url``) can't
                # collapse the styled span via Rich's silent tag-drop.
                f"{focused.hint and chr(10) + '[' + TOKENS.text_secondary + ']' + rich_escape(focused.hint) + '[/]' or ''}"
                f"{error}"
            )
        if self.setup_model.mode == "config":
            section = self.setup_model.sections[self.setup_model.active_section] if self.setup_model.sections else None
            hints = self.setup_model.save_restart_hints()
            focused = self.setup_model.focused_row_metadata()
            sections = "  ".join(
                f"[{TOKENS.accent_violet} bold]{label.name}[/]"
                if label.active
                else f"[{TOKENS.text_secondary}]{label.name}[/]"
                for label in self.setup_model.section_labels()
            )
            return (
                f"[bold #22D3EE]Setup Config[/]  {section.name if section else 'No sections'}\n"
                f"{sections}\n"
                f"Focused: {focused.label}  Key: {focused.key or '-'}  "
                f"Validation: {focused.validation.severity}"
                f"{' - ' + focused.validation.message if focused.validation.message else ''}\n"
                f"{focused.hint}\n"
                f"Changes: {hints.changes}  Validation: {len(hints.validation_errors)}  "
                f"{hints.save_hint}\n"
                f"{hints.restart_hint}\n"
                f"{'  '.join(hints.action_bar)}\n"
                "Keys: tab/shift+tab section, up/down field, enter/space cycle, type/backspace edit, "
                "S save, R revert, w wizards."
            ).strip()
        readiness_rows = self.setup_model.readiness_checks
        readiness = "\n".join(f"{check.status.upper()}: {check.title} - {check.detail}" for check in readiness_rows[:8])
        credentials = self.setup_model.credential_empty_state()
        suffix = f"\n\n{credentials}" if credentials else ""
        info = self.setup_model.active_wizard_info()
        focused = self.setup_model.focused_row_metadata()
        return (
            "[bold #22D3EE]Setup Wizards[/]\n"
            f"Selected workflow: {info.name} - {info.description}\n"
            f"{info.how_to}\n"
            f"Focused action: {focused.action.hotkey if focused.action else 'Enter'} "
            f"{focused.action.description if focused.action else ''}\n"
            "Keys: up/down select, Enter open form, c config editor, r refresh credentials, "
            "credentials wizard: f fill missing, s set selected.\n\n"
            f"{readiness}{suffix}"
        )

    def _setup_cursor(self) -> int:
        if self.first_run_model.active:
            return self.first_run_model.cursor
        if self.setup_model.goal_active:
            return getattr(self.setup_model, "goal_cursor", 0)
        if self.setup_model.form_active:
            return getattr(self.setup_model, "form_cursor", 0)
        if self.setup_model.mode == "config":
            return self.setup_model.active_line
        return int(self.setup_model.active_wizard)

    def _set_setup_cursor(self, row: int) -> None:
        if row < 0:
            return
        if self.first_run_model.active:
            self.first_run_model.cursor = min(row, max(0, len(self.first_run_model.fields) - 1))
        elif self.setup_model.goal_active:
            self.setup_model.goal_cursor = min(row, max(0, len(self.setup_model.goals) - 1))
        elif self.setup_model.form_active:
            self.setup_model.form_cursor = min(row, max(0, len(self.setup_model.form_fields) - 1))
        elif self.setup_model.mode == "config":
            if self.setup_model.sections:
                section = self.setup_model.sections[self.setup_model.active_section]
                self.setup_model.active_line = min(row, max(0, len(section.fields) - 1))
        else:
            self.setup_model.active_wizard = SetupWizard(min(row, len(WIZARD_NAMES) - 1))

    def _move_setup_form_cursor(self, delta: int) -> None:
        fields = self.setup_model.form_fields
        if not fields:
            self.setup_model.form_cursor = 0
            return
        cursor = getattr(self.setup_model, "form_cursor", 0)
        for _ in fields:
            cursor = (cursor + delta) % len(fields)
            if fields[cursor].kind != "section":
                self.setup_model.form_cursor = cursor
                return
        self.setup_model.form_cursor = cursor

    def _replace_setup_form_value(self, index: int, value: str) -> None:
        fields = self.setup_model.form_fields
        if 0 <= index < len(fields):
            field = fields[index]
            fields[index] = field.with_value(value)
            # When a "driver" row (provider / role / action / family)
            # changes, re-derive the conditional field groups so e.g. the
            # Bedrock rows appear the moment provider flips to bedrock.
            wizard = self.setup_model.active_wizard
            driver_flags = _SETUP_DRIVER_FLAGS.get(wizard, frozenset())
            driver_labels = _SETUP_DRIVER_LABELS.get(wizard, frozenset())
            if (field.flag and field.flag in driver_flags) or field.label in driver_labels:
                self.setup_model.recompute_dependent_fields()

    def _move_setup_section(self, delta: int) -> None:
        if not self.setup_model.sections:
            return
        self.setup_model.active_section = (self.setup_model.active_section + delta) % len(self.setup_model.sections)
        self.setup_model.active_line = self.setup_model.first_editable_line()

    def _cycle_setup_config_field(self, delta: int) -> bool:
        field = self._current_setup_field()
        if field is None or not field.interactive:
            return False
        if field.kind == "bool":
            value = "false" if str(field.value).lower() == "true" else "true"
            return self._set_setup_config_text(value)
        if field.options:
            return self._set_setup_config_text(_cycle_value(field.value, field.options, delta))
        return False

    def _append_setup_config_text(self, *, value: str = "", trim: bool = False) -> bool:
        field = self._current_setup_field()
        if field is None or not field.interactive or field.kind in {"bool", "choice", "header"}:
            return False
        next_value = field.value[:-1] if trim else field.value + value
        return self._set_setup_config_text(next_value)

    def _set_setup_config_text(self, value: str) -> bool:
        if not self.setup_model.sections:
            return False
        section_index = self.setup_model.active_section
        section = self.setup_model.sections[section_index]
        field_index = self.setup_model.active_line
        if not (0 <= field_index < len(section.fields)):
            return False
        field = section.fields[field_index]
        if not field.interactive:
            return False
        fields = section.fields[:field_index] + (field.with_value(value),) + section.fields[field_index + 1 :]
        new_section = section.__class__(section.name, fields, section.summary, section.help)
        self.setup_model.sections = (
            self.setup_model.sections[:section_index]
            + (new_section,)
            + self.setup_model.sections[section_index + 1 :]
        )
        return True

    def _current_setup_field(self) -> Any | None:
        if not self.setup_model.sections:
            return None
        section = self.setup_model.sections[self.setup_model.active_section]
        if not (0 <= self.setup_model.active_line < len(section.fields)):
            return None
        return section.fields[self.setup_model.active_line]

    def _active_overlay_blocks_table(self) -> bool:
        if self.active_panel == "setup":
            return self.setup_model.form_active or self.setup_model.goal_active
        return False

    def _handle_setup_key(self, key: str) -> SetupPanelAction:
        if self.setup_model.goal_active:
            return self._handle_setup_goal_key(key)
        if self.setup_model.form_active:
            return self._handle_setup_form_key(key)
        if key == "S":
            return self.setup_model.review_save_action()
        if key == "G":
            intent = self.setup_model.restart_now_intent()
            if intent is None:
                return SetupPanelAction(True, hint="No gateway restart is queued.")
            return SetupPanelAction(True, intent, hint="Restarting queued gateway.")
        if key == "C":
            if self.setup_model.restart_queue.pending:
                return SetupPanelAction(True, hint="Restart queue cleared.", clear_restart_queue=True)
            return SetupPanelAction(True, hint="No restart is queued.")
        if key == "R":
            self.setup_model.set_config(self.config)
            return SetupPanelAction(True, hint="Config reverted from current runtime config.")
        if self.setup_model.mode == "config":
            return self._handle_setup_config_key(key)
        return self._handle_setup_wizard_key(key)

    def _handle_setup_wizard_key(self, key: str) -> SetupPanelAction:
        if key in {"up", "k"}:
            self.setup_model.active_wizard = SetupWizard(max(0, int(self.setup_model.active_wizard) - 1))
            return SetupPanelAction(True)
        if key in {"down", "j"}:
            self.setup_model.active_wizard = SetupWizard(
                min(len(WIZARD_NAMES) - 1, int(self.setup_model.active_wizard) + 1)
            )
            return SetupPanelAction(True)
        if key in {"left", "["}:
            self.setup_model.active_wizard = SetupWizard(
                (int(self.setup_model.active_wizard) + len(WIZARD_NAMES) - 1) % len(WIZARD_NAMES)
            )
            return SetupPanelAction(True)
        if key in {"right", "]"}:
            self.setup_model.active_wizard = SetupWizard((int(self.setup_model.active_wizard) + 1) % len(WIZARD_NAMES))
            return SetupPanelAction(True)
        if key.isdigit():
            value = int(key)
            if value < len(WIZARD_NAMES):
                self.setup_model.active_wizard = SetupWizard(value)
                return SetupPanelAction(True)
        if key in {"enter", "e", "space"}:
            opened = self.setup_model.open_goal_menu(self.setup_model.active_wizard)
            if opened:
                return SetupPanelAction(True, hint="Choose what you want to do.")
            return SetupPanelAction(True, open_form=True, hint="Setup wizard form opened.")
        if key in {"c", "`"}:
            self.setup_model.mode = "config"
            self.setup_model.active_line = self.setup_model.first_editable_line()
            return SetupPanelAction(True, hint="Config editor opened.")
        if key == "r":
            return SetupPanelAction(True, refresh_credentials=True, hint="Refreshing credential snapshot.")
        if self.setup_model.active_wizard == SetupWizard.CREDENTIALS and key in {"f", "s"}:
            return self.setup_model.credential_action(key)
        return SetupPanelAction(False)

    def _handle_setup_goal_key(self, key: str) -> SetupPanelAction:
        goals = self.setup_model.goals
        if not goals:
            self.setup_model.close_wizard_form()
            return SetupPanelAction(True)
        if key in {"esc", "escape", "q", "left"}:
            self.setup_model.goal_active = False
            self.setup_model.goals = ()
            self.setup_model.active_goal = None
            return SetupPanelAction(True, hint="Back to the wizard list.")
        if key in {"up", "k", "shift+tab"}:
            self.setup_model.move_goal_cursor(-1)
            return SetupPanelAction(True)
        if key in {"down", "j", "tab"}:
            self.setup_model.move_goal_cursor(1)
            return SetupPanelAction(True)
        if key.isdigit():
            index = int(key)
            if 0 <= index < len(goals):
                self.setup_model.goal_cursor = index
                self.setup_model.select_active_goal()
                return SetupPanelAction(True, open_form=True, hint="Setup wizard form opened.")
            return SetupPanelAction(True)
        if key in {"enter", "space", "e", "right"}:
            self.setup_model.select_active_goal()
            return SetupPanelAction(True, open_form=True, hint="Setup wizard form opened.")
        return SetupPanelAction(False)

    def _handle_setup_form_key(self, key: str) -> SetupPanelAction:
        fields = self.setup_model.form_fields
        if not fields:
            self.setup_model.close_wizard_form()
            return SetupPanelAction(True)
        cursor = _clamp_int(getattr(self.setup_model, "form_cursor", 0), 0, len(fields) - 1)
        self.setup_model.form_cursor = cursor
        if key in {"esc", "escape", "q"}:
            self.setup_model.close_wizard_form()
            return SetupPanelAction(True, hint="Setup wizard form closed.")
        if key in {"tab", "down"}:
            self._move_setup_form_cursor(1)
            return SetupPanelAction(True)
        if key in {"shift+tab", "up"}:
            self._move_setup_form_cursor(-1)
            return SetupPanelAction(True)
        if key == "ctrl+u":
            self._replace_setup_form_value(cursor, "")
            return SetupPanelAction(True)
        if key == "backspace":
            self._replace_setup_form_value(cursor, fields[cursor].value[:-1])
            return SetupPanelAction(True)
        if key == "ctrl+t":
            if self.setup_model.toggle_form_reveal():
                return SetupPanelAction(True, hint="Secret reveal toggled.")
            return SetupPanelAction(True, hint="No secret field in this setup form.")
        if key == "ctrl+r":
            return self.setup_model.submit_wizard_form()

        field = fields[cursor]
        if key in {"enter", "space", "left", "right"}:
            if field.kind == "bool":
                self._replace_setup_form_value(cursor, "no" if field.value == "yes" else "yes")
                return SetupPanelAction(True)
            if field.options:
                delta = -1 if key == "left" else 1
                self._replace_setup_form_value(cursor, _cycle_value(field.value, field.options, delta))
                return SetupPanelAction(True)
            if key == "enter" and getattr(field, "picker", ""):
                # Searchable model picker instead of submitting the form.
                return SetupPanelAction(True, open_model_picker=True)
            if key == "enter":
                return self.setup_model.submit_wizard_form()
        if len(key) == 1 and field.kind not in {"section", "preset", "whtype", "regid"}:
            self._replace_setup_form_value(cursor, field.value + key)
            return SetupPanelAction(True)
        return SetupPanelAction(True)

    def _handle_setup_config_key(self, key: str) -> SetupPanelAction:
        if key in {"w", "`"}:
            self.setup_model.mode = "wizards"
            return SetupPanelAction(True, hint="Setup wizards opened.")
        if key in {"tab", "right", "]"}:
            self._move_setup_section(1)
            return SetupPanelAction(True)
        if key in {"shift+tab", "left", "["}:
            self._move_setup_section(-1)
            return SetupPanelAction(True)
        if key == "E":
            section = self.setup_model.current_section()
            if section is not None and section.name == "Audit Sinks":
                return SetupPanelAction(True, hint="Opening Audit Sinks editor.", open_resource_editor="audit_sinks")
            if section is not None and section.name == "Webhooks":
                return SetupPanelAction(True, hint="Opening Webhooks editor.", open_resource_editor="webhooks")
            if section is not None and section.name == "Trusted Paths":
                return SetupPanelAction(
                    True, hint="Opening Trusted Paths editor.", open_resource_editor="trusted_paths"
                )
            return SetupPanelAction(True, hint="No list editor is available for this setup section.")
        if key in {"up", "k"}:
            self.setup_model.active_line = max(0, self.setup_model.active_line - 1)
            return SetupPanelAction(True)
        if key in {"down", "j"}:
            section = self.setup_model.sections[self.setup_model.active_section]
            self.setup_model.active_line = min(len(section.fields) - 1, self.setup_model.active_line + 1)
            return SetupPanelAction(True)
        if key in {"enter", "space"}:
            self._cycle_setup_config_field(1)
            return SetupPanelAction(True)
        if key == "backspace":
            self._append_setup_config_text(trim=True)
            return SetupPanelAction(True)
        if key == "ctrl+u":
            self._set_setup_config_text("")
            return SetupPanelAction(True)
        if key == "s":
            return self.setup_model.review_save_action()
        if key == "r":
            self.setup_model.set_config(self.config)
            return SetupPanelAction(True, hint="Config edits reverted.")
        if len(key) == 1:
            changed = self._append_setup_config_text(value=key)
            return SetupPanelAction(True, hint="" if changed else "This field is read-only.")
        return SetupPanelAction(False)

    def _save_setup_config(self, restart_reason: str = "config saved from Textual TUI") -> SetupPanelAction:
        errors = self.setup_model.validation_errors()
        if errors:
            return SetupPanelAction(True, hint=f"Fix config validation: {errors[0]}")
        if not self.setup_model.has_changes():
            return SetupPanelAction(True, hint="No config changes to save.")
        try:
            self.setup_model.apply_changes_to_config()
            save = getattr(self.config, "save", None)
            if callable(save):
                save()
            self.setup_model.queue_restart(restart_reason)
            self.setup_model.mark_saved()
        except Exception as exc:  # noqa: BLE001 - user feedback belongs in status.
            return SetupPanelAction(True, hint=f"Config save failed: {exc}")
        return SetupPanelAction(True, hint="Config changes saved; restart queued if gateway is running.")

    async def _open_config_diff(self) -> None:
        result = await self.push_screen_wait(ConfigDiffScreen(self.setup_model.config_diff()))
        if result is None:
            self._set_status("Config save cancelled.")
            return
        action = self._save_setup_config(result.queue_restart_reason)
        self._render_chrome()
        if action.hint:
            self._set_status(action.hint)

    async def _open_model_picker(self) -> None:
        fields = self.setup_model.form_fields
        cursor = _clamp_int(getattr(self.setup_model, "form_cursor", 0), 0, max(0, len(fields) - 1))
        if not fields or cursor >= len(fields):
            return
        field = fields[cursor]
        if not getattr(field, "picker", ""):
            return
        provider = (wizard_field_value(fields, "Provider") or "provider").strip()
        candidates = llm_model_candidates(fields, self.config)
        choice = await self.push_screen_wait(
            ModelPickerScreen(candidates, current=field.value, provider=provider)
        )
        if choice is None:
            self._set_status("Model selection cancelled.")
            return
        self._replace_setup_form_value(cursor, choice)
        self._render_chrome()
        self._set_status(f"Model set to {choice}.")

    async def _open_mcp_set_form(self) -> None:
        model = self.mcps_model
        selected = model.selected()
        initial_name = selected.name if selected is not None else ""
        # B10: scope the add/update to the focused connector. ``action_connector``
        # prefers the selected row's owning connector (editing an existing MCP)
        # and falls back to the active filter (adding under a filtered view),
        # ultimately "" under the merged "All" view, so the form writes
        # ``--connector`` instead of silently defaulting to the primary.
        connector = model.action_connector(selected)
        result = await self.push_screen_wait(
            MCPSetFormScreen(initial_name=initial_name, connector=connector)
        )
        if result is None:
            self._set_status("MCP set cancelled.")
            return
        parsed = ParsedCommand(
            binary=result.binary,
            args=result.argv,
            display_name=result.display_name,
            category="enforce",
            risk="mutation",
            needs_preview=True,
        )
        await self._confirm_and_run_parsed(parsed)

    async def _open_detail_screen(self, title: str, pairs: tuple[tuple[str, str], ...]) -> None:
        await self.push_screen_wait(DetailScreen(title, pairs))

    async def _open_judge_history_detail(self) -> None:
        rows, error = self._judge_response_history()
        await self.push_screen_wait(JudgeHistoryScreen(rows, error=error))

    async def _open_setup_resource_editor(self, resource_kind: str) -> None:
        if resource_kind == "audit_sinks":
            rows = audit_sink_rows_from_config(self.config)
            screen = SetupResourceEditorScreen("audit_sinks", rows)
        elif resource_kind == "webhooks":
            rows = webhook_rows_from_config(self.config)
            screen = SetupResourceEditorScreen("webhooks", rows)
        elif resource_kind == "trusted_paths":
            screen = TrustedPathsEditorScreen(
                trusted_paths_rows_from_config(self.config),
                data_dir=getattr(self.config, "data_dir", None),
            )
        else:
            self._set_status(f"Unknown setup editor: {resource_kind}")
            return

        result = await self.push_screen_wait(screen)
        if result is None:
            self._set_status("Setup editor closed.")
            return
        self._handle_setup_resource_result(result)

    def _handle_setup_resource_result(self, result: SetupResourceResult) -> None:
        if result.opens_wizard == "observability":
            self.setup_model.mode = "wizards"
            self.setup_model.open_wizard_form(SetupWizard.OBSERVABILITY)
            self._render_chrome()
            self._set_status(result.hint or "Observability setup wizard opened.")
            return
        if result.opens_wizard == "webhooks":
            self.setup_model.mode = "wizards"
            self.setup_model.open_wizard_form(SetupWizard.WEBHOOKS)
            self._render_chrome()
            self._set_status(result.hint or "Webhook setup wizard opened.")
            return
        if not result.args:
            self._set_status(result.hint or "No setup editor command selected.")
            return
        parsed = ParsedCommand(
            binary=result.binary,  # type: ignore[arg-type]
            args=result.args,
            display_name=result.display_name or " ".join(result.args),
            category=result.category,
            risk="setup",
            needs_preview=True,
        )
        self.run_worker(self._confirm_and_run_parsed(parsed), exclusive=False, thread=False)

    async def _route_untrusted_binary_to_panel(self, connector: str) -> bool:
        """Open the Trusted Paths editor when a connector binary is untrusted.

        Returns ``True`` when setup may proceed (binary already trusted, or the
        connector/discovery is unknown), or ``False`` when we routed the
        operator into the editor instead. This is the TUI equivalent of the
        CLI's "trust this directory?" prompt — it surfaces the same decision in
        the panel rather than firing ``click.confirm`` under a full-screen TUI.
        """
        parent = untrusted_connector_dir(connector, getattr(self.config, "data_dir", None))
        if not parent:
            return True
        rows = trusted_paths_rows_from_config(self.config)
        context = (
            f"{friendly_connector_name(connector)} binary is outside a trusted "
            f"prefix ({parent}). Trust it below, then re-run setup."
        )
        result = await self.push_screen_wait(
            TrustedPathsEditorScreen(rows, prefill=parent, context=context)
        )
        if result is None:
            self._set_status(f"{connector} setup paused — '{parent}' was not trusted.")
            return False
        self._handle_setup_resource_result(result)
        label = friendly_connector_name(connector)
        self._set_status(
            f"{label}: trusted-paths command queued — when it finishes, press m again to re-run setup."
        )
        return False

    async def _cancel_running_command(self) -> None:
        # Snapshot the running command before cancellation so we can
        # release the matching wizard's "running…" badge if it was a
        # setup-family run.
        cancelled_label = self.command_label
        await self.executor.cancel()
        self.command_running = False
        self.command_label = ""
        self._command_started_at = 0.0
        self.activity_model.finish_entry(130, cancelled=True)
        self._write_activity("[#FBBF24]cancel requested[/]")
        self._set_status("Cancel requested for running command.")
        # Map back to argv if the label looks like one of the setup
        # commands so the wizard table doesn't keep spinning after the
        # user explicitly cancelled. The label is the same string built
        # by _derive_command_label, e.g. "defenseclaw setup claudecode".
        if cancelled_label.startswith("defenseclaw "):
            argv = tuple(cancelled_label.split()[1:])
            if argv and argv[0] in {"setup", "sandbox", "registry", "keys"}:
                self.setup_model.mark_wizard_complete(argv, success=False)
        self._refresh_hint()

    async def _handle_successful_command(self, binary: str, args: tuple[str, ...]) -> None:
        if binary != "defenseclaw" or not args:
            return
        command = args[0]
        if command == "init":
            self.first_run_model.active = False
            self.active_panel = "overview"
            self._refresh_cached_config()
        elif command == "setup":
            self._refresh_cached_config()
            self.setup_model.clear_restart_queue()
            self.setup_model.mark_wizard_complete(args, success=True)
        elif command == "keys":
            await self._load_setup_credentials()
            self.setup_model.mark_wizard_complete(args, success=True)
        elif command in {"sandbox", "registry"}:
            self._refresh_cached_config()
            self.setup_model.mark_wizard_complete(args, success=True)
        elif command == "doctor":
            self._load_doctor_cache()
        elif panel := _catalog_panel_invalidated_by_command(args):
            await self._refresh_loaded_catalog_after_mutation(panel)

    async def _refresh_loaded_catalog_after_mutation(self, panel: str) -> None:
        """Reload an already-opened catalog after a successful row mutation."""

        model = self.catalog_models.get(panel)
        if model is None or not getattr(model, "loaded", False):
            return
        if panel == "tools":
            self.tools_model.refresh()
            self._render_chrome()
            return
        await self._load_catalog_model(panel)

    def _refresh_cached_config(self) -> None:
        """Full reload-from-disk after ``setup``/``init``/``sandbox``/``registry``.

        Mirrors Go's ``reloadConfigAfterSetupCommand``
        (``internal/tui/app.go::3800-3816``) line-for-line:

        1. Re-read config from disk via ``defenseclaw.config.load()``
           — the file the just-finished wizard wrote is the source of
           truth, not the in-memory snapshot from start-up.
        2. Push the fresh ``cfg`` into every panel that caches one
           (overview, setup, registries).
        3. Re-bind ``data_dir`` on every panel that tails files
           (logs, activity, alerts) so a setup-time relocation of
           ``~/.defenseclaw/data`` doesn't strand the JSONL tail at
           the old path.
        4. Re-open the audit SQLite handle and inject it into the
           alerts + audit panels — setup may have moved the DB to
           a fresh path (e.g. on first-run install).
        5. Re-apply the last known health snapshot so the SERVICES
           tile doesn't briefly flip to "unknown" while waiting for
           the next 3s poll.
        6. Propagate the connector + registry attribution so the
           catalog "Source: …" banners agree with the new cfg.
        7. Run the standard refresh pipeline (alerts/logs/audit/
           tools/doctor/silent-bypass/activity-mutations) and
           rebuild Setup readiness so every row reflects the new
           state immediately.

        Falls back to the prior in-memory ``self.config`` if the
        on-disk reload raises, so a malformed user edit doesn't
        wedge the TUI mid-setup.
        """

        try:
            new_cfg: object | None = config_module.load()
        except Exception as exc:  # noqa: BLE001 — bad YAML must not crash the TUI.
            self._write_activity(
                f"[#FBBF24]config reload failed:[/] {rich_escape(str(exc))}; keeping current snapshot."
            )
            new_cfg = self.config

        self.config = new_cfg
        new_data_dir = _resolve_data_dir(new_cfg, None)
        if new_data_dir is not None:
            self.data_dir = new_data_dir

        # Panels that cache the config snapshot.
        self.setup_model.set_config(new_cfg)
        self.overview_model.set_cfg(_overview_config(new_cfg))
        if hasattr(self.registries_model, "set_config"):
            self.registries_model.set_config(new_cfg)

        # Panels that tail files from data_dir.
        if hasattr(self.logs_model, "set_data_dir"):
            self.logs_model.set_data_dir(new_data_dir)
        if hasattr(self.activity_model, "set_data_dir"):
            self.activity_model.set_data_dir(new_data_dir)
        if hasattr(self.alerts_model, "set_data_dir"):
            self.alerts_model.set_data_dir(new_data_dir)

        # Re-open audit store at the new path. Capture the previous
        # handles *before* the swap so we can close them after — the
        # alerts and audit panels each held a reference and replacing
        # the attribute alone leaked the SQLite file descriptor on
        # every setup-driven reload (which a typical session triggers
        # several times: connector pick, registry add, redaction
        # toggle, etc.). The previous handles can be the same Store
        # instance, so dedupe before closing.
        new_store = _audit_store(new_cfg)
        old_stores: list[object] = []
        for model in (self.alerts_model, self.audit_model):
            prior = getattr(model, "store", None)
            if prior is not None and prior is not new_store and prior not in old_stores:
                old_stores.append(prior)
        if hasattr(self.alerts_model, "set_store"):
            self.alerts_model.set_store(new_store)
        if hasattr(self.audit_model, "set_store"):
            self.audit_model.set_store(new_store)
        for stale in old_stores:
            close = getattr(stale, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:  # noqa: BLE001 — best-effort cleanup; never block the reload.
                    pass

        # Re-apply the known health snapshot so subsystem state stays
        # populated through the reload (next poll overwrites this in 3s).
        self.overview_model.set_health(self.overview_model.health)
        self._propagate_connector(self.overview_model.health)

        # Run the standard refresh pipeline so every panel re-reads
        # against the new paths in a single pass, then rebuild Setup
        # readiness so rows flip on the same tick.
        self._refresh_models_from_disk()
        self._sync_setup_readiness()

    def _schedule_credentials_refresh(self) -> None:
        """Dispatch a credential refresh as a Textual worker.

        Mirrors Go's mount-time + slow-tick ``loadCredentialsCmd``. We
        skip the dispatch when the first-run flow is active, there's
        no config, the app is shutting down, or the gateway has no
        configured API port — the last guard keeps tests that stand
        up a partial config (no ``gateway`` attribute) from spawning
        ``defenseclaw keys list`` subprocesses that outlive the
        Textual event loop and surface as "Event loop is closed"
        flakes in CI.
        """

        if self.config is None or getattr(self, "_app_shutting_down", False):
            return
        if getattr(self, "first_run_model", None) and self.first_run_model.active:
            return
        if _gateway_api_port(self.config) <= 0:
            return
        if self._credentials_refresh_running:
            return
        self._credentials_refresh_running = True
        self.run_worker(
            self._refresh_credentials_once(),
            exclusive=False,
            thread=False,
        )

    async def _refresh_credentials_once(self) -> None:
        try:
            await self._load_setup_credentials()
        finally:
            self._credentials_refresh_running = False

    async def _load_setup_credentials(self) -> None:
        try:
            process = await asyncio.create_subprocess_exec(
                "defenseclaw",
                "keys",
                "list",
                "--json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
        except OSError as exc:
            self.setup_model.set_credential_snapshot((), error=exc)
            self._render_chrome()
            return
        if process.returncode != 0:
            self.setup_model.set_credential_snapshot((), error=stderr.decode(errors="replace").strip())
            self._render_chrome()
            return
        try:
            from defenseclaw.tui.services.setup_state import parse_credential_rows

            rows = parse_credential_rows(stdout)
        except Exception as exc:  # noqa: BLE001 - parser failures should stay in-panel.
            self.setup_model.set_credential_snapshot((), error=exc)
            self._render_chrome()
            return
        self.setup_model.set_credential_snapshot(rows)
        self._render_chrome()

    async def _load_inventory_model(self) -> None:
        names = self._active_connector_names()
        # 8.13 pass 2: a multi-connector install inventories every connector and
        # merges the snapshots into one view with a CONNECTOR column. Single-
        # connector installs keep the original one-shot ``aibom scan``.
        if len(names) > 1:
            self.inventory_model.show_connector_column = True
            await self._load_inventory_merged(names)
            return
        self.inventory_model.show_connector_column = False
        intent = self.inventory_model.load_intent()
        self._set_status(intent.hint or "Loading inventory...")
        try:
            process = await asyncio.create_subprocess_exec(
                intent.binary,
                *intent.args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
        except OSError as exc:
            self.inventory_model.apply_loaded(None, exc)
            self._render_chrome()
            return
        if process.returncode != 0:
            self.inventory_model.apply_loaded(
                None,
                stderr.decode(errors="replace").strip() or f"exit {process.returncode}",
            )
            self._render_chrome()
            return
        try:
            self.inventory_model.apply_json(stdout.decode(errors="replace"))
        except Exception as exc:  # noqa: BLE001 - parser errors are panel state.
            self.inventory_model.apply_loaded(None, exc)
        self._render_chrome()

    async def _load_inventory_merged(self, names: list[str]) -> None:
        """Inventory every active connector and merge the snapshots.

        Each connector's ``aibom scan`` runs with ``--connector <name>`` so its
        entities can be attributed; failures for one connector are skipped
        rather than blanking the whole inventory. The merged view is then
        narrowed to the active connector filter in-memory.
        """

        self._set_status(f"Loading inventory for {len(names)} connectors...")
        results: list[tuple[str, str | None]] = []
        for name in names:
            intent = self.inventory_model.load_intent_for(name)
            try:
                process = await asyncio.create_subprocess_exec(
                    intent.binary,
                    *intent.args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await process.communicate()
            except OSError:
                results.append((name, None))
                continue
            if process.returncode != 0:
                results.append((name, None))
            else:
                results.append((name, stdout.decode(errors="replace")))
        self.inventory_model.apply_merged(results)
        if not any(text for _name, text in results):
            self.inventory_model.message = "Could not load inventory for any connector."
        self.inventory_model.set_connector_filter(self._connector_filter())
        self._render_chrome()

    async def _load_ai_discovery_model(self) -> None:
        intent = self.ai_discovery_model.load_intent()
        self._set_status(intent.hint or "Loading AI discovery...")
        await self._poll_ai_usage(force_render=True)

    async def _open_catalog_action_menu(self, panel: str) -> None:
        model = self.catalog_models[panel]
        actions = model.menu_actions()
        selected = model.selected()
        subtitle = getattr(selected, "name", "") if selected is not None else ""
        choice = await self.push_screen_wait(
            ActionMenuScreen(
                f"{panel.title()} Actions",
                tuple(_menu_action(action) for action in actions),
                subtitle=subtitle,
            )
        )
        if choice is None:
            self._set_status("Action cancelled.")
            return
        intent = model.action_intent(choice, origin="action-menu")
        if intent is None:
            self._set_status("No action available for this row.")
            return
        self._run_catalog_intent(intent)

    async def _open_mode_picker(self) -> None:
        # 8.13: in a multi-connector install all connectors are already
        # active, so "switch mode" makes no sense — ``m`` instead opens the
        # shared connector filter picker (All + each connector).
        # Single-connector installs keep the original behaviour (re-run setup
        # to switch the active connector).
        actives = self._active_connector_names()
        if len(actives) > 1:
            await self._open_connector_filter_picker(actives)
            return
        choice = await self.push_screen_wait(ModePickerScreen(_active_connector(self.config)))
        if choice is None:
            self._set_status("Mode switch cancelled.")
            return
        args, display = connector_setup_command(choice)
        if not args:
            self._set_status(f"No setup command available for connector {choice}.")
            return
        # When the connector binary is outside a trusted prefix, route the
        # operator into the Trusted Paths editor instead of running a setup the
        # trust gate would refuse (the TUI replacement for the CLI prompt).
        if not await self._route_untrusted_binary_to_panel(choice):
            return
        intent = OverviewCommandIntent(
            label=display,
            args=args,
            binary="defenseclaw",
            category="setup",
            hint=f"Switch active connector to {choice}.",
        )
        await self._confirm_and_run_intent(intent)

    async def _open_connector_filter_picker(self, connectors: list[str]) -> None:
        """Pick the shared connector filter: All connectors or a specific one.

        Multi-connector only. Does not re-run setup — every connector is
        already active; it just narrows (or clears) the shared filter via
        :meth:`_set_connector_filter`, which every pane honours.
        """

        current = self._connector_filter()
        selected_index = connectors.index(current) + 1 if current in connectors else 0
        actions: list[MenuAction] = []
        all_marker = "  ← current" if not current else ""
        actions.append(
            MenuAction(
                "0",
                f"All connectors{all_marker}",
                "Show activity across every active connector",
            )
        )
        cfg = self.overview_model.cfg
        for index, conn in enumerate(connectors, start=1):
            label = friendly_connector_name(conn)
            marker = "  ← current" if conn == current else ""
            disabled = cfg is not None and cfg.connector_is_disabled(conn)
            disabled_tag = " — disabled" if disabled else ""
            hint = (
                f"Filter every view to {conn} (enforcement off — history only)"
                if disabled
                else f"Filter every view to {conn}"
            )
            actions.append(
                MenuAction(
                    str(index),
                    f"{label} ({conn}){disabled_tag}{marker}",
                    hint,
                )
            )
        choice = await self.push_screen_wait(
            ActionMenuScreen(
                "Filter by Connector",
                tuple(actions),
                subtitle="Applies across Overview, Alerts, Audit, Logs",
                selected_index=selected_index,
            )
        )
        if choice is None:
            self._set_status("Connector filter unchanged.")
            return
        if not choice.isdigit():
            return
        index = int(choice)
        if index == 0:
            self._set_connector_filter("")
            return
        index -= 1
        if not (0 <= index < len(connectors)):
            return
        self._set_connector_filter(connectors[index])

    async def _open_redaction_toggle(self) -> None:
        currently_disabled = _redaction_currently_disabled(self.config)
        action = await self.push_screen_wait(RedactionToggleScreen(currently_disabled))
        if action is None:
            self._set_status("Redaction toggle cancelled.")
            return
        command = action.command
        if command is None:
            self._set_status("Redaction toggle has no command.")
            return
        _set_redaction_disabled(self.config, command.args[2] == "off")
        self.active_panel = "activity"
        self._render_chrome()
        self.run_worker(
            self._run_command(
                command.binary,
                command.args,
                display_name=getattr(command, "label", "redaction toggle"),
            ),
            exclusive=False,
            thread=False,
        )

    async def _open_notifications_toggle(self) -> None:
        currently_enabled = _notifications_currently_enabled(self.config)
        action = await self.push_screen_wait(NotificationsToggleScreen(currently_enabled))
        if action is None:
            self._set_status("Notifications toggle cancelled.")
            return
        command = action.command
        if command is None:
            self._set_status("Notifications toggle has no command.")
            return
        _set_notifications_enabled(self.config, command.args[2] == "on")
        self.active_panel = "activity"
        self._render_chrome()
        self.run_worker(
            self._run_command(
                command.binary,
                command.args,
                display_name=getattr(command, "label", "notifications toggle"),
            ),
            exclusive=False,
            thread=False,
        )

    async def _open_uninstall_modal(self) -> None:
        action = await self.push_screen_wait(UninstallScreen())
        if action is None:
            self._set_status("Uninstall cancelled.")
            return
        command = action.command
        if command is None:
            self._set_status("Uninstall action has no command.")
            return
        self.active_panel = "activity"
        self._render_chrome()
        self.run_worker(
            self._run_command(
                command.binary,
                command.args,
                display_name=getattr(command, "label", "uninstall"),
            ),
            exclusive=False,
            thread=False,
        )

    def _run_catalog_intent(self, intent: CatalogCommandIntent) -> None:
        if intent.category == "info":
            self.run_worker(
                self._run_command(
                    intent.binary,
                    intent.args,
                    display_name=getattr(intent, "label", None),
                ),
                exclusive=False,
                thread=False,
            )
        else:
            self.run_worker(self._confirm_and_run_intent(intent), exclusive=False, thread=False)

    async def _load_catalog_model(self, panel: str) -> None:
        model = self.catalog_models[panel]
        names = self._active_connector_names()
        # 8.13 pass 2: Skills/MCPs/Plugins merge every active connector's list
        # into one table with a CONNECTOR column. Tools is a process-global
        # enforcement view, so it never merges. Single-connector installs keep
        # the original one-shot load (no column, no per-connector fan-out).
        if len(names) > 1 and panel in {"skills", "mcps", "plugins"}:
            model.show_connector_column = True
            await self._load_catalog_merged(panel, model, names)
            return
        model.show_connector_column = False
        intent = model.load_intent()
        self._set_status(intent.hint or f"Loading {panel}...")
        try:
            process = await asyncio.create_subprocess_exec(
                intent.binary,
                *intent.args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
        except OSError as exc:
            model.apply_loaded([], exc)
            self._render_chrome()
            return

        if process.returncode != 0:
            model.apply_loaded([], stderr.decode(errors="replace").strip() or f"exit {process.returncode}")
        else:
            try:
                model.apply_json(stdout.decode(errors="replace"))  # type: ignore[attr-defined]
            except Exception as exc:  # noqa: BLE001 - parser errors are panel state.
                model.apply_loaded([], exc)
        self._render_chrome()

    async def _load_catalog_merged(
        self, panel: str, model: Any, names: list[str]
    ) -> None:
        """Load ``panel`` once per active connector and merge the rows.

        Each connector's ``list --json`` runs with ``--connector <name>`` so
        rows can be tagged with their origin; failures for one connector are
        skipped (None payload) rather than blanking the whole table. The merged
        rows are then narrowed to the active connector filter in-memory.
        """

        self._set_status(f"Loading {panel} for {len(names)} connectors...")
        results: list[tuple[str, str | None]] = []
        for name in names:
            intent = model.load_intent_for(name)
            try:
                process = await asyncio.create_subprocess_exec(
                    intent.binary,
                    *intent.args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await process.communicate()
            except OSError:
                results.append((name, None))
                continue
            if process.returncode != 0:
                results.append((name, None))
            else:
                results.append((name, stdout.decode(errors="replace")))
        model.apply_merged(results)
        if not any(text for _name, text in results):
            model.message = f"Could not load {panel} for any connector."
        model.set_connector_filter(self._connector_filter())
        self._render_chrome()

    async def _confirm_and_run_intent(self, intent: Any) -> None:
        # N1: a catalog intent that flags itself ``risk="destructive"`` (today
        # only plugin remove, which deletes files from disk) is confirmed
        # through the C1 consequence danger-modal — red border + an explicit
        # second confirm (re-press) — instead of the one-step command preview,
        # so a single keypress/click can't delete. Typed/palette destructive
        # commands keep the standard preview path (they reach
        # ``_confirm_and_run_parsed`` directly, not through here).
        if getattr(intent, "risk", "read-only") == "destructive":
            await self._confirm_and_run_destructive_intent(intent)
            return
        parsed = ParsedCommand(
            binary=intent.binary,
            args=tuple(intent.args),
            display_name=intent.label,
            category=intent.category,
            risk=getattr(intent, "risk", "read-only"),
            needs_preview=True,
        )
        await self._confirm_and_run_parsed(parsed)
        # Setup wizards (currently the Registry wizard) can request
        # follow-up commands that should run only after the primary
        # command finishes. The follow-ups themselves are queued through
        # the same confirm-and-run path so the user still sees the
        # preview screen and live output.
        for follow_up in getattr(intent, "follow_up", ()) or ():
            await self._confirm_and_run_intent(follow_up)

    def _destructive_intent_modal(self, intent: Any) -> ConsequenceModalModel:
        """Build the C1 consequence modal for a destructive catalog intent (N1).

        A single ``danger`` action carries the command; the consequence modal
        paints a red border and requires the danger re-press before it
        dismisses with the action, so the dispatch only fires on an explicit
        second confirm.
        """

        command_line = " ".join((intent.binary, *intent.args))
        return ConsequenceModalModel(
            title=f"Confirm: {intent.label}",
            summary="This is a destructive action and cannot be undone.",
            details=(f"Will run: {command_line}",),
            consequence="This deletes files from disk.",
            actions=(
                ConsequenceAction(
                    action_id="run",
                    hotkey="d",
                    label=intent.label,
                    description="Runs the command and deletes the files from disk.",
                    variant="error",
                    danger=True,
                ),
            ),
            default_action_id="run",
            border_color=TOKENS.accent_red,
        )

    async def _confirm_and_run_destructive_intent(self, intent: Any) -> None:
        chosen = await self.push_screen_wait(
            ConsequenceModalScreen(self._destructive_intent_modal(intent))
        )
        if chosen is None:
            self._write_activity(f"[#FBBF24]Cancelled:[/] {intent.label}")
            self._set_status("Command cancelled.")
            return
        # Confirmed (and danger-re-pressed): jump to Activity where the live
        # output is visible, record the alias in the palette MRU, then run.
        if self.active_panel != "activity":
            self.action_switch_panel("activity")
        try:
            self.state_store.record_command(intent.label)
            self.state = self.state_store.state
            self.state_store.save()
        except Exception:  # noqa: BLE001 - palette MRU is cosmetic
            pass
        self.run_worker(
            self._run_command(intent.binary, tuple(intent.args), display_name=intent.label),
            exclusive=False,
            thread=False,
        )
        for follow_up in getattr(intent, "follow_up", ()) or ():
            await self._confirm_and_run_intent(follow_up)

    async def _confirm_and_run_parsed(self, parsed: ParsedCommand) -> None:
        confirmed = await self.push_screen_wait(CommandPreviewScreen(parsed))
        if not confirmed:
            self._write_activity(f"[#FBBF24]Cancelled:[/] {parsed.display_name}")
            self._set_status("Command cancelled.")
            return
        # Any command that needed a preview is non-read-only (setup,
        # mutation, destructive, …) — most of them are interactive
        # wizards. The user just confirmed they want to run it, so jump
        # to Activity where the live output and stdin prompts are visible.
        # Without this jump the user sat on Overview staring at an empty
        # yellow "running" strip with no clue the wizard was waiting on
        # them.
        if parsed.risk != "read-only" and self.active_panel != "activity":
            self.action_switch_panel("activity")
        # Record the TUI alias in the palette MRU so the next time the
        # operator opens the palette without a query, the things they
        # actually use float to the top. Best-effort: persistence
        # failures (read-only home, missing data dir) never block the
        # actual command.
        try:
            self.state_store.record_command(parsed.display_name)
            self.state = self.state_store.state
            self.state_store.save()
        except Exception:  # noqa: BLE001 - palette MRU is cosmetic
            pass
        self.run_worker(
            self._run_command(parsed.binary, parsed.args, display_name=parsed.display_name),
            exclusive=False,
            thread=False,
        )

    def _periodic_refresh(self) -> None:
        if self._periodic_refresh_running or self.command_running or self.executor.is_running:
            return
        if len(self.screen_stack) > 1:
            return
        self._periodic_refresh_running = True
        try:
            self._refresh_models_from_disk()
            try:
                self._render_chrome()
            except NoMatches:
                return
        finally:
            self._periodic_refresh_running = False

    def _refresh_models_from_disk(self) -> None:
        self._refresh_alerts()
        self.registries_model.refresh()
        self.logs_model.refresh()
        self.audit_model.refresh()
        self.tools_model.refresh()
        self._load_doctor_cache()
        self._load_silent_bypass_count()
        self._load_activity_mutations()

    def _refresh_alerts(self) -> None:
        """Single entry point for refreshing alerts from disk + audit DB.

        Mirrors Go's ``alerts.Refresh(store, dataDir)`` which loads
        gateway scan-blocks (file-backed) and audit alerts (sqlite)
        in one call. Splitting these into two call sites caused at
        least one regression where ``_load_audit_alerts`` was missed
        after a setup-driven config swap; consolidating here keeps
        every refresh path identical.
        """

        self.alerts_model.refresh()
        self._load_audit_alerts()

    def _load_silent_bypass_count(self) -> None:
        """Surface the gateway's silent-bypass count on Overview.

        Mirrors Go's ``LoadGatewayEgress`` + ``CountRecentSilentBypass``
        called from ``app.go::refresh()``. Without this the Overview
        AI Agents / enforcement tiles can't warn an operator when an
        LLM-shaped request slipped past the guardrail's known-host
        list, which is one of the highest-value early signals the
        TUI exposes.
        """

        from defenseclaw.tui.services.gateway_events import (
            count_recent_silent_bypass,
            load_gateway_egress,
        )

        data_dir = self.data_dir or _data_dir_from_config(self.config)
        if data_dir is None:
            return
        events = load_gateway_egress(data_dir / "gateway.jsonl")
        if not events:
            self.overview_model.set_silent_bypass_count(0)
            return
        self.overview_model.set_silent_bypass_count(
            count_recent_silent_bypass(events, window_seconds=300)
        )

    def _load_activity_mutations(self) -> None:
        """Hydrate the Activity panel's Mutations tab from gateway.jsonl.

        Mirrors Go's ``activity.LoadMutations()`` called from ``refresh()``
        every tick. Without this the tab is permanently stuck on
        "No activity events in gateway.jsonl yet." even after the
        gateway has logged dozens of mutation rows.
        """

        data_dir = self.data_dir or _data_dir_from_config(self.config)
        if data_dir is None:
            return
        self.activity_model.set_data_dir(str(data_dir))
        try:
            self.activity_model.load_mutations()
        except Exception as exc:  # noqa: BLE001 - degrade silently.
            self._write_activity(f"[#FBBF24]mutations unavailable:[/] {exc}")

    def _schedule_health_poll(self) -> None:
        """Kick off a non-blocking ``/health`` fetch.

        The Go TUI runs ``fetchHealth`` on a ticker (see
        ``internal/tui/health.go`` + ``app.go`` ``pollHealth``) and
        feeds the result into ``OverviewPanel.SetHealth``. Without an
        equivalent loop the Python TUI's SERVICES box stays pinned at
        "unknown" for every subsystem.

        We dispatch the actual fetch to a worker thread so the 3s
        HTTP timeout never blocks Textual's event loop, and we tolerate
        the gateway being offline by simply leaving ``health=None`` so
        the existing "Gateway is offline" notice continues to render.
        """

        if self.config is None or getattr(self, "_app_shutting_down", False):
            return
        api_port = _gateway_api_port(self.config)
        if api_port <= 0:
            return
        if self._health_poll_running:
            return
        self._health_poll_running = True
        self.run_worker(
            self._poll_health_once(),
            exclusive=False,
            thread=False,
        )

    def _schedule_ai_usage_poll(self) -> None:
        """Kick off a non-blocking ``/api/v1/ai-usage`` fetch."""

        if self.config is None or getattr(self, "_app_shutting_down", False):
            return
        api_port = _gateway_api_port(self.config)
        if api_port <= 0:
            return
        if self._ai_usage_poll_running:
            return
        self._ai_usage_poll_running = True
        self.run_worker(
            self._poll_ai_usage_once(force_render=False),
            exclusive=False,
            thread=False,
        )

    async def _poll_health_once(self) -> None:
        try:
            await self._poll_health()
        finally:
            self._health_poll_running = False

    async def _poll_ai_usage_once(self, *, force_render: bool) -> None:
        try:
            await self._poll_ai_usage(force_render=force_render)
        finally:
            self._ai_usage_poll_running = False

    async def _poll_health(self) -> None:
        # Use the configured token + host so a gateway that requires
        # Authorization (the default when ``OPENCLAW_GATEWAY_TOKEN`` or
        # ``gateway.token`` is set) doesn't 401 us into ``unknown``.
        # The previous urllib fetcher couldn't attach the header and
        # was the root cause of "I did everything but it still shows
        # unknown" — the gateway was up, but the unauthenticated probe
        # bounced.
        snapshot = await asyncio.to_thread(_fetch_gateway_health, self.config)
        # ``snapshot`` is None on connection refused / timeouts. We
        # propagate that as ``set_health(None)`` so subsystem_state()
        # returns "unknown" and the SERVICES rows clearly reflect
        # "we don't know" instead of stale data from a previous run.
        self.overview_model.set_health(snapshot)
        self._propagate_connector(snapshot)
        # Mirror Go: clear the queued-restart banner once the gateway
        # has actually restarted (its StartedAt moved). Without this
        # the banner sticks around forever even though the restart
        # already finished, since we never call mark_restart_started.
        self._mark_restart_if_gateway_restarted(snapshot)
        # Rebuild Setup readiness now that we have a fresh health
        # snapshot (the gateway/api/guardrail rows depend on it).
        self._sync_setup_readiness()
        # Only repaint the chrome when the Overview panel is actually
        # being shown; otherwise we'd churn the screen for nothing.
        if self.active_panel == "overview" and not self.help_open:
            self._render_chrome()

    async def _poll_ai_usage(self, *, force_render: bool) -> None:
        snapshot = await asyncio.to_thread(_fetch_ai_usage, self.config)
        if snapshot is None:
            if self.ai_discovery_model.snapshot is None:
                self.ai_discovery_model.message = "ai discovery offline or unauthorized"
            if force_render or self.active_panel in {"overview", "ai"}:
                self._render_chrome()
            return
        self.overview_model.set_ai_usage(snapshot)
        self.ai_discovery_model.set_snapshot(snapshot)
        self.ai_discovery_model.message = ""
        if force_render or self.active_panel in {"overview", "ai"}:
            self._render_chrome()

    def _sync_setup_readiness(self) -> None:
        """Rebuild the Setup readiness rows from current inputs.

        Mirrors Go's ``syncSetupDerivedState``. Called from every
        upstream change (mount, health poll, doctor load, credential
        load, setup wizard completion) so the rows always reflect the
        latest cfg/health/doctor/credentials in one place.
        """

        try:
            self.setup_model.rebuild_readiness_checks(
                health=self.overview_model.health,
                doctor=self.overview_model.doctor,
                credentials=tuple(
                    getattr(self.setup_model.credential_snapshot, "rows", ()) or ()
                ),
            )
        except AttributeError:
            # Older SetupPanelModel — silently skip; the readiness
            # rows will stay at their __init__ baseline.
            pass

    def _propagate_connector(self, snapshot: HealthSnapshot | None) -> None:
        """Push the live connector name + registry attribution to every catalog model.

        Mirrors Go's ``propagateConnector`` + ``propagateRegistryAttribution``
        (``internal/tui/app.go::313-329, 412-455``). Without it the
        Skills/MCPs/Plugins/Inventory panels keep showing the
        connector name captured at TUI start — stale once the operator
        switches connectors via Setup.
        """

        cfg = self.overview_model.cfg
        mode = (cfg.claw_mode if cfg else "") or ""
        # 8.13: in a multi-connector install the operator can filter every
        # view to a specific connector (via the chip / ``m``); that selection
        # must survive health polls, so it takes precedence over the
        # live/primary connector for the catalog list scoping.
        # ``_connector_filter`` returns "" for single-connector installs and
        # the All state, preserving the original behaviour.
        selected = self._connector_filter()
        connector_name = selected or _resolve_active_connector(snapshot, mode)
        focus_enabled = bool(selected)
        for model in (
            self.skills_model,
            self.mcps_model,
            self.plugins_model,
            self.inventory_model,
        ):
            try:
                model.set_connector(connector_name)
            except AttributeError:
                continue
            if hasattr(model, "connector_focus_enabled"):
                model.connector_focus_enabled = focus_enabled

        skill_attr = _registry_attribution_from_config(self.config, "skill")
        mcp_attr = _registry_attribution_from_config(self.config, "mcp")
        if hasattr(self.skills_model, "set_registry_attribution"):
            self.skills_model.set_registry_attribution(skill_attr)
        if hasattr(self.mcps_model, "set_registry_attribution"):
            self.mcps_model.set_registry_attribution(mcp_attr)

    def _mark_restart_if_gateway_restarted(self, snapshot: HealthSnapshot | None) -> None:
        """If the gateway's ``started_at`` advanced, clear the queued restart.

        Mirrors Go's check in ``internal/tui/app.go::615-618`` where a
        ``healthUpdateMsg`` whose ``StartedAt`` differs from the last
        seen value resets the restart queue and posts a toast. Without
        this the "Restart queued" banner persists across the actual
        restart, confusing operators into clicking restart twice.
        """

        if snapshot is None or not snapshot.started_at:
            return
        last_seen = getattr(self, "_last_gateway_started_at", "")
        if last_seen and snapshot.started_at != last_seen:
            try:
                # SetupPanelModel.mark_restart_started requires the new
                # ``started_at`` so it can compare against the timestamp
                # captured when the restart was queued. Calling it with
                # no args raised ``TypeError`` and crashed the
                # ``_poll_health`` worker on every poll, so the moment
                # the operator changed any setting that triggers a
                # restart (e.g. toggling redaction off via setup) the
                # whole TUI tore down.
                self.setup_model.mark_restart_started(snapshot.started_at)
            except (AttributeError, TypeError):
                # Older SetupPanelModel without this method (or with a
                # different signature) — fall back to clearing the
                # local queue directly so the banner doesn't get stuck.
                if hasattr(self.setup_model, "clear_restart_queue"):
                    self.setup_model.clear_restart_queue()
        self._last_gateway_started_at = snapshot.started_at

    def _doctor_cache_mtime(self) -> float:
        """Return the doctor_cache.json mtime, 0 when missing/unreadable.

        ``_run_command`` snapshots this before/after every execution to
        detect ``doctor`` runs that successfully refreshed the cache
        and surface the ``doctor cache refreshed`` meta footer in the
        Activity panel. Mtime is preferred over content hashing because
        it survives both no-op runs (mtime unchanged) and runs that
        rewrite the same JSON content (mtime advances). Returning 0 on
        any error keeps the caller's diff logic simple — pre == post,
        so we don't claim a refresh that didn't happen.
        """

        data_dir = self.data_dir or _data_dir_from_config(self.config)
        if data_dir is None:
            return 0.0
        try:
            return (data_dir / "doctor_cache.json").stat().st_mtime
        except OSError:
            return 0.0

    def _load_doctor_cache(self) -> None:
        """Hydrate the Overview DOCTOR box from the on-disk cache.

        Mirrors ``internal/tui/doctor_cache.go``: ``defenseclaw doctor``
        writes ``<data_dir>/doctor_cache.json`` after every run, and
        the Go TUI reads it on startup so the dashboard shows a real
        pass/fail/warn/skip summary plus the top failure instead of
        "not yet run — press d to run doctor". Until this loader was
        wired into ``_refresh_models_from_disk`` the panel stayed
        empty even after the user had successfully run doctor.
        """

        data_dir = self.data_dir or _data_dir_from_config(self.config)
        if data_dir is None:
            return
        path = data_dir / "doctor_cache.json"
        if not path.exists():
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        captured_at = _parse_timestamp(raw.get("captured_at"))
        checks = tuple(
            DoctorCheck(
                status=str(item.get("status") or ""),
                label=str(item.get("label") or ""),
                detail=str(item.get("detail") or ""),
            )
            for item in raw.get("checks", ())
            if isinstance(item, dict)
        )
        self.overview_model.set_doctor_cache(
            DoctorCache(
                captured_at=captured_at,
                passed=int(raw.get("passed") or 0),
                failed=int(raw.get("failed") or 0),
                warned=int(raw.get("warned") or 0),
                skipped=int(raw.get("skipped") or 0),
                checks=checks,
            )
        )
        # Doctor results feed several readiness rows (credential
        # presence, registry sync, sandbox check) so rebuild now.
        self._sync_setup_readiness()

    def _judge_response_history(self) -> tuple[tuple[object, ...], str]:
        store = _audit_store(self.config)
        if store is None:
            return (), "Audit DB is unavailable; configure audit_db to view retained judge responses."
        try:
            if hasattr(store, "list_judge_responses"):
                return tuple(store.list_judge_responses(20)), ""  # type: ignore[attr-defined]
            db = getattr(store, "db", None)
            if db is None:
                return (), "Audit store does not expose a judge response reader."
            columns = {row[1] for row in db.execute("PRAGMA table_info(judge_responses)").fetchall()}
            if not columns:
                return (), "judge_responses table is not initialized yet."
            wanted = (
                "timestamp",
                "kind",
                "direction",
                "action",
                "severity",
                "latency_ms",
                "inspected_model",
                "model",
                "request_id",
                "trace_id",
                "run_id",
                "input_hash",
                "confidence",
                "fail_closed_applied",
                "prompt_template_id",
                "parse_error",
                "raw",
            )
            selected = tuple(column for column in wanted if column in columns)
            cursor = db.execute(
                f"SELECT {', '.join(selected)} FROM judge_responses ORDER BY timestamp DESC LIMIT ?",
                (20,),
            )
            rows = tuple(dict(zip(selected, row, strict=True)) for row in cursor.fetchall())
            return rows, ""
        except Exception as exc:  # noqa: BLE001 - error belongs in the modal.
            return (), str(exc)

    def _load_audit_alerts(self) -> None:
        """Mirror loaded alert counts into Overview without heavy DB scans."""

        active_alerts = self.alerts_model.alert_count()
        current = self.overview_model.enforcement
        store = getattr(self.alerts_model, "store", None) or getattr(self.audit_model, "store", None)
        if store is not None and hasattr(store, "get_enforcement_counts"):
            try:
                current = store.get_enforcement_counts()  # type: ignore[attr-defined]
            except Exception as count_exc:  # noqa: BLE001 - degraded counts must not break alerts.
                self._write_activity(
                    f"[#FBBF24]enforcement counts unavailable:[/] {count_exc}"
                )
        self.overview_model.set_enforcement_counts(
            EnforcementCounts(
                blocked_skills=current.blocked_skills,
                allowed_skills=current.allowed_skills,
                blocked_mcps=current.blocked_mcps,
                allowed_mcps=current.allowed_mcps,
                total_scans=current.total_scans,
                active_alerts=active_alerts,
            )
        )


def _resolve_active_connector(snapshot: HealthSnapshot | None, mode: str) -> str:
    """Mirror Go's ``ActiveConnectorName``: live health wins, fall back to mode.

    Kept as a thin module-level helper so the catalog auto-load path
    and the health-poll callback both call the same resolver — the Go
    side has a single ``ActiveConnectorName`` function for exactly the
    same reason.
    """

    if snapshot is not None and snapshot.connector is not None:
        name = snapshot.connector.name.strip()
        if name:
            return name
    if mode and mode.strip():
        return mode.strip()
    return ""


def _registry_attribution_from_config(config: object | None, kind: str) -> dict[str, str] | None:
    """Build a ``name -> source-id`` map for registry-promoted assets.

    Mirrors Go's ``registryAttributionFromRules`` (``internal/tui/app.go:439``).
    Only rules whose ``reason`` looks like ``registry:<id>`` count —
    operator-authored entries are skipped so the badge surfaces *only*
    assets promoted by a registry sync. Returns ``None`` (not an empty
    dict) when there's nothing to attribute so callers can pass the
    result straight to ``set_registry_attribution``.
    """

    asset_policy = getattr(config, "asset_policy", None)
    if asset_policy is None:
        return None
    bucket = getattr(asset_policy, kind, None)
    if bucket is None:
        return None
    rules = getattr(bucket, "registry", None) or ()
    out: dict[str, str] = {}
    for rule in rules:
        reason = (getattr(rule, "reason", "") or "").strip()
        name = (getattr(rule, "name", "") or "").strip()
        if not reason or not name or not reason.startswith("registry:"):
            continue
        source_id = reason[len("registry:") :].strip()
        if source_id:
            out[name] = source_id
    return out or None


def _gateway_api_port(config: object | None) -> int:
    """Return the sidecar API port from config, with the Go default.

    The Go TUI falls back to 9090 in ``pollHealth`` if the config is
    missing, but the Python CLI's ``setup gateway`` defaults to 18970.
    We honor whatever the operator has actually configured; if there
    is no config (very early startup), 0 disables the poll until one
    arrives.
    """

    gw = getattr(config, "gateway", None)
    if gw is None:
        return 0
    try:
        port = int(getattr(gw, "api_port", 0) or 0)
    except (TypeError, ValueError):
        return 0
    return port if port > 0 else 0


def _fetch_gateway_health(config: object | None) -> HealthSnapshot | None:
    """Blocking ``/health`` fetcher, intended for ``asyncio.to_thread``.

    Uses :class:`OrchestratorClient` so the configured token, host, and
    port all flow through automatically — that matters because a gateway
    started with ``OPENCLAW_GATEWAY_TOKEN`` set will 401 any probe that
    forgets the ``Authorization: Bearer …`` header, and the operator's
    SERVICES box would silently stay at ``unknown``.

    Any exception (connection refused, DNS failure, malformed JSON,
    401/403) collapses to ``None`` so the caller can render "unknown"
    without crashing the panel.
    """

    if config is None:
        return None
    gateway_cfg = getattr(config, "gateway", None)
    if gateway_cfg is None:
        return None
    try:
        port = int(getattr(gateway_cfg, "api_port", 0) or 0)
    except (TypeError, ValueError):
        return None
    if port <= 0:
        return None
    host = str(getattr(gateway_cfg, "host", "") or "127.0.0.1") or "127.0.0.1"
    # The gateway's API server binds 127.0.0.1 by default; ``0.0.0.0`` /
    # empty values would resolve fine over the wire but make the client
    # round-trip needlessly slow on macOS. Normalize to loopback.
    if host in ("", "0.0.0.0"):
        host = "127.0.0.1"
    resolve_token = getattr(gateway_cfg, "resolved_token", None)
    token = resolve_token() if callable(resolve_token) else str(getattr(gateway_cfg, "token", "") or "")

    try:
        from defenseclaw.gateway import OrchestratorClient
    except Exception:  # noqa: BLE001 — never let a bad import kill the TUI
        return None

    client = OrchestratorClient(host=host, port=port, token=token, timeout=3)
    try:
        payload = client.health()
    except Exception:  # noqa: BLE001 — offline / unauthenticated gateway is normal
        return None
    return _health_snapshot_from_mapping(payload)


def _fetch_ai_usage(config: object | None) -> AIUsageSnapshot | None:
    """Blocking ``/api/v1/ai-usage`` fetcher for Overview + AI Discovery.

    This mirrors the Go TUI's ``fetchAIUsage`` path: use the configured
    gateway API port and resolved bearer token, request JSON over loopback,
    and return ``None`` on transient gateway/auth failures so the previous
    good snapshot is not cleared during restarts.
    """

    if config is None:
        return None
    gateway_cfg = getattr(config, "gateway", None)
    if gateway_cfg is None:
        return None
    try:
        port = int(getattr(gateway_cfg, "api_port", 0) or 0)
    except (TypeError, ValueError):
        return None
    if port <= 0:
        return None
    host = str(getattr(gateway_cfg, "host", "") or "127.0.0.1") or "127.0.0.1"
    if host in ("", "0.0.0.0"):
        host = "127.0.0.1"
    resolve_token = getattr(gateway_cfg, "resolved_token", None)
    token = resolve_token() if callable(resolve_token) else str(getattr(gateway_cfg, "token", "") or "")

    try:
        from defenseclaw.gateway import OrchestratorClient
    except Exception:  # noqa: BLE001
        return None

    client = OrchestratorClient(host=host, port=port, token=token, timeout=3)
    client._session.headers["Accept"] = "application/json"  # noqa: SLF001 - mirrors Go fetchAIUsage.
    try:
        payload = client.ai_usage()
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(payload, dict):
        return None
    payload = dict(payload)
    payload.setdefault("fetched_at", datetime.now(timezone.utc).isoformat())
    try:
        return AIUsageSnapshot.from_mapping(payload)
    except Exception:  # noqa: BLE001
        return None


def _resolve_data_dir(config: object | None, data_dir: str | Path | None) -> Path | None:
    if data_dir is not None:
        return Path(data_dir)
    return _data_dir_from_config(config)


def _data_dir_from_config(config: object | None) -> Path | None:
    value = getattr(config, "data_dir", "")
    return Path(value) if value else None


def _parse_timestamp(value: object) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _active_connector(config: object | None) -> str:
    if config is None:
        return ""
    active = getattr(config, "active_connector", None)
    if callable(active):
        try:
            return str(active() or "").strip()
        except Exception:  # noqa: BLE001 - connector name is cosmetic in the shell.
            return ""
    guardrail = getattr(config, "guardrail", None)
    connector = str(getattr(guardrail, "connector", "") or "").strip()
    if connector:
        return connector
    claw = getattr(config, "claw", None)
    return str(getattr(claw, "mode", "") or "").strip()


def _redaction_currently_disabled(config: object | None) -> bool:
    if isinstance(config, dict):
        privacy = config.get("privacy")
        if isinstance(privacy, dict):
            return bool(privacy.get("disable_redaction"))
        return False
    privacy = getattr(config, "privacy", None)
    return bool(getattr(privacy, "disable_redaction", False))


def _set_redaction_disabled(config: object | None, disabled: bool) -> None:
    if isinstance(config, dict):
        privacy = config.setdefault("privacy", {})
        if isinstance(privacy, dict):
            privacy["disable_redaction"] = disabled
        return
    privacy = getattr(config, "privacy", None)
    if privacy is not None and hasattr(privacy, "disable_redaction"):
        setattr(privacy, "disable_redaction", disabled)


def _notifications_currently_enabled(config: object | None) -> bool:
    if isinstance(config, dict):
        notifications = config.get("notifications")
        if isinstance(notifications, dict):
            return bool(notifications.get("enabled"))
        return False
    notifications = getattr(config, "notifications", None)
    return bool(getattr(notifications, "enabled", False))


def _set_notifications_enabled(config: object | None, enabled: bool) -> None:
    if isinstance(config, dict):
        notifications = config.setdefault("notifications", {})
        if isinstance(notifications, dict):
            notifications["enabled"] = enabled
        return
    notifications = getattr(config, "notifications", None)
    if notifications is not None and hasattr(notifications, "enabled"):
        setattr(notifications, "enabled", enabled)


def _audit_store(config: object | None) -> object | None:
    if isinstance(config, dict):
        audit_db = str(config.get("audit_db", "") or "")
    else:
        audit_db = str(getattr(config, "audit_db", "") or "")
    if not audit_db or not Path(audit_db).exists():
        return None
    try:
        from defenseclaw.db import Store

        return Store(audit_db)
    except Exception:  # noqa: BLE001 - panels render empty state when audit is unavailable.
        return None


def _flatten_scanner_overrides(
    overrides: object,
) -> tuple[tuple[str, str, str, str], ...]:
    """Flatten a ``data.json`` ``scanner_overrides`` block (N3).

    Input shape: ``{scanner_type: {severity: {install|file|runtime: action}}}``
    (what ``policy show`` reads). Output: ``(scanner_type, severity, surface,
    action)`` tuples for :func:`format_scanner_overrides_summary`. Malformed
    branches are skipped so a bad payload degrades to a partial list, never a
    raise.
    """

    flat: list[tuple[str, str, str, str]] = []
    if not isinstance(overrides, dict):
        return ()
    for scanner_type, sevs in overrides.items():
        if not isinstance(sevs, dict):
            continue
        for severity, surface_actions in sevs.items():
            if not isinstance(surface_actions, dict):
                continue
            for surface in ("install", "file", "runtime"):
                action = surface_actions.get(surface)
                if action:
                    flat.append((str(scanner_type), str(severity), surface, str(action)))
    return tuple(flat)


def _active_policy_scanner_overrides(
    policy_dir: str,
) -> tuple[tuple[str, str, str, str], ...]:
    """Read the active policy's synced ``data.json`` scanner overrides (N3).

    Uses the same reader as the enforcement lane (``rego/data.json``, with the
    flat ``data.json`` fallback). Any read/parse failure degrades to an empty
    tuple so the Overview simply renders nothing.
    """

    try:
        from defenseclaw.enforce.admission import _read_policy_data

        data = _read_policy_data(policy_dir or "")
    except Exception:  # noqa: BLE001 - the override summary is purely informational.
        return ()
    if not isinstance(data, dict):
        return ()
    return _flatten_scanner_overrides(data.get("scanner_overrides", {}))


def _overview_config(config: object | None) -> OverviewConfig | None:
    if config is None:
        return None
    claw = getattr(config, "claw", None)
    guardrail = getattr(config, "guardrail", None)
    llm = getattr(config, "llm", None)
    inspect_llm = getattr(config, "inspect_llm", None)
    cisco = getattr(config, "cisco_ai_defense", None)
    privacy = getattr(config, "privacy", None)
    hilt = getattr(guardrail, "hilt", None)
    # Multi-connector roster (WU10): only when more than one connector is
    # active. Config-derived (mirrors `defenseclaw status`) since /health
    # reports just the primary connector. Defensive — any resolver gap
    # falls back to an empty roster so the single "Agent" line still shows.
    connector_modes: tuple[tuple[str, str], ...] = ()
    connector_packs: tuple[tuple[str, str], ...] = ()
    connector_disabled: tuple[str, ...] = ()
    # A2: resolve the active set in its own guarded step. `active_connectors()`
    # normalizes every key, so a single malformed/alias key can raise — and the
    # previous single broad `except` then collapsed the whole roster to (),
    # silently dropping the connector chip, stopping `m` cycling, and hiding
    # every per-connector tile. Guard the enumeration here; if it fails we
    # degrade to a single-connector view instead of swallowing the roster
    # together with any later error. The TUI subtree has no stderr logger, so
    # rather than fail silently we stash the reason in `OverviewConfig.roster_error`
    # and the Overview surfaces it as a visible error notice (build_notices).
    roster_error = ""
    try:
        actives = config.active_connectors() if hasattr(config, "active_connectors") else []
        actives = [c for c in actives if c]
    except Exception as exc:  # noqa: BLE001 - a bad connector key must not blank the roster.
        actives = []
        roster_error = f"Connector roster unavailable: {exc}"
    if len(actives) > 1:
        pairs: list[tuple[str, str]] = []
        packs: list[tuple[str, str]] = []
        disabled: list[str] = []
        # Build the roster incrementally: each connector is processed in its
        # own guard so one bad connector is skipped, not fatal to the rest
        # (the partial roster survives instead of zeroing).
        for conn in actives:
            try:
                norm = conn.strip().lower()
                # A connector turned off via `guardrail disable --connector X`
                # stays in the roster (so its history is filterable) but is
                # marked DISABLED. effective_enabled honors the per-connector
                # kill switch; unset/True means enforcing.
                is_disabled = False
                if guardrail is not None and hasattr(guardrail, "effective_enabled"):
                    try:
                        is_disabled = not guardrail.effective_enabled(conn)
                    except Exception:
                        is_disabled = False
                mode = ""
                if guardrail is not None and hasattr(guardrail, "effective_mode"):
                    try:
                        mode = (guardrail.effective_mode(conn) or "").strip()
                    except Exception:
                        mode = ""
                # Effective rule-pack label = basename of the per-connector
                # rule_pack_dir (falling back to the global one), so the
                # roster shows "strict"/"permissive"/"default" per connector.
                pack = ""
                if guardrail is not None and hasattr(guardrail, "effective_rule_pack_dir"):
                    try:
                        pack_dir = (guardrail.effective_rule_pack_dir(conn) or "").strip()
                    except Exception:
                        pack_dir = ""
                    pack = os.path.basename(pack_dir.rstrip("/")) if pack_dir else "default"
            except Exception:  # noqa: BLE001 - skip one bad connector, keep the rest.
                continue
            # Append together so connector_modes/packs/disabled stay aligned.
            pairs.append((conn, mode))
            packs.append((conn, pack))
            if is_disabled:
                disabled.append(norm)
        connector_modes = tuple(pairs)
        connector_packs = tuple(packs)
        connector_disabled = tuple(disabled)
    return OverviewConfig(
        data_dir=str(getattr(config, "data_dir", "") or ""),
        environment=str(getattr(config, "environment", "") or ""),
        policy_dir=str(getattr(config, "policy_dir", "") or ""),
        # A1 (display-only, Root R1): pass the real `claw.mode` through — do NOT
        # collapse an empty mode to "openclaw". OverviewPanelModel.active_connector_name()
        # then resolves the genuinely-zero-connector case to "" (no phantom
        # connector) instead of fabricating "openclaw". The Go-parity
        # config.active_connector() contract is deliberately left untouched.
        claw_mode=str(getattr(claw, "mode", "") or ""),
        guardrail_enabled=bool(getattr(guardrail, "enabled", False)),
        guardrail_connector=str(getattr(guardrail, "connector", "") or ""),
        guardrail_mode=str(getattr(guardrail, "mode", "") or "observe"),
        guardrail_rule_pack_dir=str(getattr(guardrail, "rule_pack_dir", "") or ""),
        guardrail_port=int(getattr(guardrail, "port", 0) or 0),
        guardrail_model=str(getattr(guardrail, "model", "") or ""),
        guardrail_strategy=str(getattr(guardrail, "strategy", "") or "default"),
        guardrail_judge_enabled=bool(getattr(guardrail, "judge_enabled", False)),
        guardrail_judge_model=str(getattr(guardrail, "judge_model", "") or ""),
        hilt_enabled=bool(getattr(hilt, "enabled", False)),
        hilt_min_severity=str(getattr(hilt, "min_severity", "") or ""),
        privacy_disable_redaction=bool(getattr(privacy, "disable_redaction", False)),
        llm_provider=str(getattr(llm, "provider", "") or ""),
        llm_model=str(getattr(llm, "model", "") or ""),
        inspect_llm_provider=str(getattr(inspect_llm, "provider", "") or ""),
        inspect_llm_model=str(getattr(inspect_llm, "model", "") or ""),
        cisco_ai_defense_endpoint=str(getattr(cisco, "endpoint", "") or ""),
        connector_modes=connector_modes,
        connector_packs=connector_packs,
        connector_disabled=connector_disabled,
        # A2: visible diagnostic when the roster enumeration failed.
        roster_error=roster_error,
        # N3: active-policy scanner action overrides (data.json), so the
        # Overview/status surface a policy that downgrades a scanner surface.
        scanner_overrides=_active_policy_scanner_overrides(
            str(getattr(config, "policy_dir", "") or "")
        ),
    )


class _HandledAction:
    def __init__(self, handled: bool, hint: str = "") -> None:
        self.handled = handled
        self.hint = hint


def _menu_action(action: CatalogMenuAction) -> MenuAction:
    return MenuAction(
        action_id=action.key,
        label=action.label,
        description=action.description,
        disabled=action.disabled,
    )


def _panel_key(event: events.Key) -> str:
    if event.key == "space":
        return "space"
    if event.key == "enter":
        return "enter"
    if event.key == "escape":
        return "escape"
    if event.key in {"up", "down"}:
        return event.key
    # Normalize backspace/delete BEFORE the event.character branch. Textual
    # delivers the DEL control char (\x7f) as event.character, so without this
    # a backspace in a panel search field appended a literal \x7f instead of
    # deleting (the alerts search showed "critical\x7f\x7f..."). Panels expect
    # the logical key name "backspace".
    if event.key in {"backspace", "delete"} or event.character in {"\x7f", "\x08"}:
        return "backspace"
    if event.character:
        # Capital-letter keys that panels distinguish from their
        # lowercase form (e.g. ``M`` materialize bundled vs ``m`` no-op,
        # ``T`` Tools panel vs ``t`` activity transcript). Anything
        # outside this set is lowercased so global vim-style shortcuts
        # ignore Shift/CapsLock state.
        if event.character in {"A", "C", "E", "G", "J", "M", "N", "R", "S", "T", "V", "X"}:
            return event.character
        return event.character.lower()
    return event.key


def _catalog_key(key: str) -> str:
    return "esc" if key == "escape" else key


def _catalog_panel_invalidated_by_command(args: tuple[str, ...]) -> str | None:
    """Return the catalog panel whose loaded rows are stale after ``args``."""

    if len(args) < 2:
        return None
    command, verb = args[0], args[1]
    catalog_mutations = {
        "skill": (
            "skills",
            {
                "allow",
                "block",
                "disable",
                "enable",
                "install",
                "quarantine",
                "restore",
                "scan",
                "unblock",
            },
        ),
        "mcp": (
            "mcps",
            {"allow", "block", "scan", "set", "unblock", "unset"},
        ),
        "plugin": (
            "plugins",
            {
                "allow",
                "block",
                "disable",
                "enable",
                "quarantine",
                "remove",
                "restore",
                "scan",
            },
        ),
        "tool": (
            "tools",
            {"allow", "block", "unblock"},
        ),
    }
    entry = catalog_mutations.get(command)
    if entry is None:
        return None
    panel, verbs = entry
    return panel if verb in verbs else None


def _vim_key(key: str) -> str:
    return "esc" if key == "escape" else key


def _truncate_display(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    if width <= 3:
        return value[:width]
    return value[: width - 3] + "..."


def _styled_cell(column: str, value: str) -> Text:
    text = Text(value)
    normalized = value.strip().lower()
    column_key = column.strip().lower()
    if column_key in {"state", "status", "active", "enabled"} or normalized in {
        "active",
        "allowed",
        "blocked",
        "clean",
        "disabled",
        "enabled",
        "error",
        "offline",
        "rejected",
        "running",
        "stopped",
        "unknown",
        "warn",
        "warning",
    }:
        text.stylize(state_color(value))
        if normalized in {"running", "active", "enabled", "allowed", "blocked", "error", "stopped"}:
            text.stylize("bold")
    elif column_key == "severity" or normalized in {"critical", "high", "medium", "low", "info"}:
        text.stylize(severity_color(value))
        if normalized in {"critical", "high"}:
            text.stylize("bold")
    elif column_key in {"sel", "selected"} and value.strip():
        text.stylize(TOKENS.accent_violet)
        text.stylize("bold")
    return text


def _relative_time_label(when: datetime | None, now: datetime) -> str:
    """Compact "Ns/Nm/Nh/Nd ago" label, or "—" when there is no activity."""

    if when is None:
        return "—"
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    delta = now - when
    seconds = int(delta.total_seconds())
    if seconds < 0:
        seconds = 0
    if seconds < 60:
        return f"{seconds}s ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    return f"{hours // 24}d ago"


def _overview_state_line(name: str, state: str, detail: str) -> str:
    normalized = state.strip().lower() or "unknown"
    dot = "●" if normalized in {"running", "active", "enabled"} else "○"
    color = state_color(normalized)
    suffix = f" {detail}" if detail else ""
    return f"  [{color}]{dot}[/] {name:<12} [{color}]{state or 'unknown'}[/]{suffix}"


def _coerce_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _coerce_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _coerce_nonnegative_int(value: Any) -> int:
    return max(_coerce_int(value), 0)


def _subsystem_from_mapping(raw: Any) -> SubsystemHealth:
    """Build a SubsystemHealth from a permissive dict payload.

    The gateway's ``/health`` JSON sometimes returns ``null`` for a
    subsystem when it hasn't started yet; we treat that as the default
    empty state instead of raising so the Overview can render a
    consistent table.
    """

    if not isinstance(raw, dict):
        return SubsystemHealth()
    details = raw.get("details") if isinstance(raw.get("details"), dict) else {}
    return SubsystemHealth(
        state=_coerce_str(raw.get("state")),
        since=_coerce_str(raw.get("since")),
        last_error=_coerce_str(raw.get("last_error") or raw.get("lastError")),
        details=dict(details),
    )


def _connector_from_mapping(raw: Any) -> ConnectorHealth | None:
    if not isinstance(raw, dict):
        return None
    return ConnectorHealth(
        name=_coerce_str(raw.get("name")),
        state=_coerce_str(raw.get("state")),
        since=_coerce_str(raw.get("since")),
        tool_inspection_mode=_coerce_str(
            raw.get("tool_inspection_mode") or raw.get("toolInspectionMode")
        ),
        subprocess_policy=_coerce_str(
            raw.get("subprocess_policy") or raw.get("subprocessPolicy")
        ),
        requests=_coerce_int(raw.get("requests")),
        errors=_coerce_int(raw.get("errors")),
        tool_inspections=_coerce_int(
            raw.get("tool_inspections") or raw.get("toolInspections")
        ),
        tool_blocks=_coerce_int(raw.get("tool_blocks") or raw.get("toolBlocks")),
        subprocess_blocks=_coerce_int(
            raw.get("subprocess_blocks") or raw.get("subprocessBlocks")
        ),
    )


def _connectors_from_mapping(raw: Any) -> tuple[ConnectorHealth, ...]:
    """Parse ``/health``'s ``connectors[]`` array into per-connector health.

    The gateway emits one entry per active connector with its own live
    counters (``internal/gateway/health.go``). Tolerant of a missing/null
    array (older gateways) — returns ``()`` so callers fall back to the
    config-derived roster. Entries that don't map cleanly are skipped.
    """

    if not isinstance(raw, list):
        return ()
    out: list[ConnectorHealth] = []
    for item in raw:
        conn = _connector_from_mapping(item)
        if conn is not None and conn.name:
            out.append(conn)
    return tuple(out)


def _health_snapshot_from_mapping(raw: Any) -> HealthSnapshot | None:
    """Convert a ``/health`` JSON payload into a ``HealthSnapshot``.

    Returns ``None`` when the response is unusable. The mapper is
    deliberately tolerant of missing / camelCased fields so a gateway
    that's slightly out of sync with the Python schema still feeds
    *something* into the Overview instead of leaving every row as
    ``unknown``.
    """

    if not isinstance(raw, dict):
        return None
    sandbox_raw = raw.get("sandbox")
    sandbox = _subsystem_from_mapping(sandbox_raw) if isinstance(sandbox_raw, dict) else None
    return HealthSnapshot(
        started_at=_coerce_str(raw.get("started_at") or raw.get("startedAt")),
        uptime_ms=_coerce_int(raw.get("uptime_ms") or raw.get("uptimeMs")),
        gateway=_subsystem_from_mapping(raw.get("gateway")),
        watcher=_subsystem_from_mapping(raw.get("watcher")),
        api=_subsystem_from_mapping(raw.get("api")),
        guardrail=_subsystem_from_mapping(raw.get("guardrail")),
        telemetry=_subsystem_from_mapping(raw.get("telemetry")),
        ai_discovery=_subsystem_from_mapping(raw.get("ai_discovery") or raw.get("aiDiscovery")),
        sinks=_subsystem_from_mapping(raw.get("sinks")),
        sandbox=sandbox,
        connector=_connector_from_mapping(raw.get("connector")),
        connectors=_connectors_from_mapping(raw.get("connectors")),
    )


_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _strip_ansi(value: str) -> str:
    return _ANSI_RE.sub("", value)


def _format_elapsed(seconds: float) -> str:
    seconds = max(0.0, seconds)
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, remaining = divmod(int(seconds), 60)
    return f"{minutes}m{remaining:02d}s"


def _truncate_for_strip(value: str, width: int) -> str:
    limit = max(24, width - 38)
    cleaned = value.replace("\n", " ").strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: max(0, limit - 3)] + "..."


def _palette_row_for_entry(entry: CmdEntry) -> tuple[str, str, str, str]:
    """Return ``(name, badge, preview, hint)`` for a palette row.

    Pure helper so the row layout is unit-testable without spinning
    up Textual. Mirrors the Go TUI's palette visual contract:

    * ``name``    — the operator-facing TUI alias (e.g. ``setup guardrail``)
    * ``badge``   — ``[category/risk]``, computed via
      :func:`infer_command_risk`, so destructive vs read-only is
      visible at a glance.
    * ``preview`` — exact argv that will run when the operator
      presses Enter (``defenseclaw setup guardrail``). Joined with
      spaces; argv tokens are NOT shell-quoted because the registry
      never contains shell metacharacters.
    * ``hint``    — for ``needs_arg`` entries, the ``arg_hint`` string;
      empty string otherwise so the column collapses visually.
    """

    risk = infer_command_risk(entry.category, entry.cli_args)
    badge = f"[{entry.category}/{risk}]"
    preview = entry.cli_binary
    if entry.cli_args:
        preview = preview + " " + " ".join(entry.cli_args)
    hint = entry.arg_hint if entry.needs_arg else ""
    return entry.tui_name, badge, preview, hint


def _diagnose_summary_line(lines: list[str]) -> str:
    """Pick the most informative summary line from ``defenseclaw doctor``.

    The CLI prints a multi-line report; for the toast we want the
    single line that best answers "what's the state?". Preference
    order:
        1. Lines containing the word ``summary`` (matches Go TUI
           parity which keys off the same string).
        2. The last "verdict" line — typically ``All checks passed``
           or ``N issue(s) detected``.
        3. The first non-empty line as a last resort.

    Returns an empty string for empty input so the caller can
    distinguish "no output" from a real summary.
    """

    if not lines:
        return ""
    for line in reversed(lines):
        if "summary" in line.lower():
            return line.strip(": -=").strip()
    for needle in ("checks passed", "issues detected", "issue(s)", "failures", "errors", "OK"):
        for line in reversed(lines):
            if needle.lower() in line.lower():
                return line.strip(": -=").strip()
    return lines[0].strip(": -=").strip()


def _derive_command_label(binary: str, args: tuple[str, ...]) -> str:
    """Best-effort display label for a (binary, args) tuple.

    Used when a caller doesn't supply ``display_name`` to ``_run_command``.
    We trim the binary down to its basename and join the first two
    non-flag args, which is enough for users to recognize what just ran
    (e.g. ``defenseclaw scan all``).
    """

    head = Path(binary).name or binary or "command"
    parts = [head]
    for arg in args:
        if arg.startswith("-"):
            continue
        parts.append(arg)
        if len(parts) >= 3:
            break
    return " ".join(parts)


def _severity_breakdown_markup(critical: int, high: int, medium: int, low: int) -> str:
    """Render a compact ``C0 H3 M5 L2`` breakdown in colored markup.

    Used in metric-tile detail rows so users can see severity context at
    a glance without opening the Alerts panel. Zero counts are dimmed so
    only non-zero values draw the eye.
    """

    def cell(letter: str, count: int, accent: str) -> str:
        if count <= 0:
            return f"[{TOKENS.text_muted}]{letter}0[/]"
        return f"[{accent} bold]{letter}{count}[/]"

    return " ".join(
        (
            cell("C", critical, TOKENS.accent_red),
            cell("H", high, TOKENS.accent_orange),
            cell("M", medium, TOKENS.accent_amber),
            cell("L", low, TOKENS.accent_blue),
        )
    )


def _metric_severity_bucket(severity: str) -> str:
    normalized = (severity or "").strip().upper()
    if normalized == "WARNING":
        return "MEDIUM"
    return normalized


def _metric_trend(value: int, *, invert: bool = False) -> tuple[float, ...]:
    bounded = max(0, min(value, 100))
    if bounded == 0:
        return (2, 1, 3, 2, 1) if invert else (0, 0, 0, 0, 0)
    steps = (0.2, 0.35, 0.5, 0.7, 1.0)
    return tuple(max(1.0, bounded * step) for step in steps)


# Each metric sparkline shows the last ``_METRIC_HISTORY_WINDOW`` of
# activity split into ``_METRIC_HISTORY_BUCKETS`` equal time buckets.
# Bar height is the number of events that landed in that bucket, so the
# tile reads as a live "events per unit of time" histogram rather than a
# decorative ramp. The Sparkline widget auto-scales to the tallest bar.
_METRIC_HISTORY_BUCKETS = 24
_METRIC_HISTORY_WINDOW = timedelta(minutes=5)


def _event_histogram(
    timestamps: Iterable[datetime],
    *,
    now: datetime,
    buckets: int = _METRIC_HISTORY_BUCKETS,
    window: timedelta = _METRIC_HISTORY_WINDOW,
) -> tuple[float, ...]:
    """Bucket event timestamps into a fixed-width time histogram.

    Returns ``buckets`` counts ordered oldest -> newest, each bar
    spanning ``window / buckets`` and ending at ``now``. Events outside
    ``[now - window, now]`` are dropped. Naive datetimes are treated as
    UTC so demo fixtures and live gateway events bucket consistently.
    """

    if buckets <= 0 or window <= timedelta(0):
        return tuple(0.0 for _ in range(max(buckets, 0)))
    counts = [0.0] * buckets
    span = window / buckets
    start = now - window
    for raw in timestamps:
        if raw is None:
            continue
        moment = raw if raw.tzinfo is not None else raw.replace(tzinfo=timezone.utc)
        moment = moment.astimezone(timezone.utc)
        if moment < start or moment > now:
            continue
        index = int((moment - start) / span)
        index = max(0, min(index, buckets - 1))
        counts[index] += 1.0
    return tuple(counts)


def _policy_posture(cfg: OverviewConfig | None) -> str:
    if cfg is None:
        return "unknown"
    mode = cfg.guardrail_mode or "observe"
    scanner = cfg.guardrail_strategy or "default"
    # Multi-connector: each connector can carry its own rule pack (and thus
    # its own block threshold), so naming one global pack would be wrong.
    # Detect whether the connectors actually diverge; if they do, point the
    # operator at the roster instead of asserting a single posture.
    packs = {p for _conn, p in cfg.connector_packs if p}
    if len(cfg.connector_modes) > 1:
        modes = {m for _conn, m in cfg.connector_modes if m}
        if len(packs) > 1 or len(modes) > 1:
            return "per-connector (see roster)"
        only_pack = next(iter(packs)) if packs else scanner
        only_mode = next(iter(modes)) if modes else mode
        return f"all connectors: {only_mode} ({only_pack})"
    if mode == "action":
        return f"action: block CRIT, alert MED+ ({scanner})"
    return f"balanced: block CRIT, alert MED+ ({scanner})"


def _enforcement_label(cfg: OverviewConfig | None) -> str:
    if cfg is None:
        return "not configured"
    # Multi-connector: naming a single primary connector ("antigravity hook
    # observability") hides the other active connectors. Report the count
    # instead; the per-connector modes live in the roster below.
    if len(cfg.connector_modes) > 1:
        n = len(cfg.connector_modes)
        return f"{n} connectors (hook observability)"
    connector = cfg.guardrail_connector or cfg.claw_mode
    mode = cfg.guardrail_mode or "observe"
    if not connector:
        return f"not configured ({mode})"
    if connector in {"openclaw", "zeptoclaw"}:
        return f"{connector} proxy guardrail ({mode})"
    return f"{connector} hook observability ({mode})"


def _cycle_value(current: str, options: tuple[str, ...], delta: int) -> str:
    if not options:
        return current
    try:
        index = options.index(current)
    except ValueError:
        index = 0
    return options[(index + delta) % len(options)]


def _clamp_int(value: int, lower: int, upper: int) -> int:
    if upper < lower:
        return lower
    return max(lower, min(value, upper))


def _config_display_value(field: Any) -> str:
    value = str(getattr(field, "value", "") or "")
    if getattr(field, "kind", "") == "password":
        return "(empty)" if not value else "****"
    return value


def _validation_label(field: Any) -> str:
    result = validate_config_field(field)
    if result.message:
        return f"{result.severity}: {result.message}"
    return result.severity
