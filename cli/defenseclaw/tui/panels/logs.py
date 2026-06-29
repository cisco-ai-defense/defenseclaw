# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Pure Logs panel model for the Textual TUI migration."""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from defenseclaw.tui.panels.audit import split_connector_token
from defenseclaw.tui.services.gateway_log_views import (
    ACTION_FILTERS,
    ACTION_LABELS,
    EVENT_TYPE_FILTERS,
    EVENT_TYPE_LABELS,
    SEVERITY_FILTERS,
    SEVERITY_LABELS,
    GatewayLogRow,
    detail_pairs,
    load_gateway_log_views,
)

LogSource = Literal["gateway", "verdicts", "otel", "watchdog"]

LOG_SOURCES: tuple[LogSource, ...] = ("gateway", "verdicts", "otel", "watchdog")
LOG_SOURCE_LABELS: dict[LogSource, str] = {
    "gateway": "Gateway",
    "verdicts": "Verdicts",
    "otel": "OTEL",
    "watchdog": "Watchdog",
}

FILTER_NONE = ""
FILTER_NO_NOISE = "no-noise"
FILTER_IMPORTANT = "important"
FILTER_ERRORS = "errors"
FILTER_WARNINGS = "warnings+"
FILTER_SCAN = "scan"
FILTER_DRIFT = "drift"
FILTER_GUARDRAIL = "guardrail"
FILTER_HOOKS = "hooks"

FILTER_PRESETS: tuple[str, ...] = (
    FILTER_NONE,
    FILTER_NO_NOISE,
    FILTER_IMPORTANT,
    FILTER_ERRORS,
    FILTER_WARNINGS,
    FILTER_SCAN,
    FILTER_DRIFT,
    FILTER_GUARDRAIL,
    FILTER_HOOKS,
)
FILTER_LABELS: dict[str, str] = {
    FILTER_NONE: "All",
    FILTER_NO_NOISE: "No Noise",
    FILTER_IMPORTANT: "Important",
    FILTER_ERRORS: "Errors",
    FILTER_WARNINGS: "Warnings+",
    FILTER_SCAN: "Scan",
    FILTER_DRIFT: "Drift",
    FILTER_GUARDRAIL: "Guardrail",
    FILTER_HOOKS: "Hooks",
}

# Tokens that mark a line as a connector-hook event. Connector hook
# lifecycle rows render as ``HOOK`` in the OTEL stream and free-form
# gateway lines carry the ``connector-hook`` audit action, so matching
# the ``hook`` substring catches both without a structured event type.
HOOK_PATTERNS: tuple[str, ...] = ("hook",)

NOISE_PATTERNS: tuple[str, ...] = (
    "event tick seq=",
    "event health seq=",
    "payload_len=20",
    "mallocstacklogging",
    "event sessions.changed seq=nil",
    "content-length=0",
)
IMPORTANT_PATTERNS: tuple[str, ...] = (
    "error",
    "fatal",
    "panic",
    "warn",
    "block",
    "allow",
    "reject",
    "quarantine",
    "scan",
    "drift",
    "verdict",
    "guardrail",
    "connected",
    "disconnected",
    "started",
    "stopped",
)
ACTIONABLE_LOG_PATTERNS: tuple[str, ...] = (
    "critical",
    " high ",
    "severity=high",
    "severity:high",
    "error",
    "fatal",
    "panic",
    "warn",
    "block",
    "blocked",
    "deny",
    "denied",
    "reject",
    "rejected",
    "quarantine",
    "fail",
    "failed",
    "failure",
)
LOW_SIGNAL_LOG_PATTERNS: tuple[str, ...] = (
    " info ",
    "severity=info",
    "severity:info",
    " low ",
    "severity=low",
    "severity:low",
    " medium ",
    "severity=medium",
    "severity:medium",
)

REDACTION_ENV_VAR = "DEFENSECLAW_DISABLE_REDACTION"
TRUTHY_REDACTION_VALUES = {"1", "true", "yes", "on"}
_UNSET_SIGNATURE = object()

FILTER_TYPE_ACTION = "action"
FILTER_TYPE_EVENT_TYPE = "event_type"
FILTER_TYPE_PRESET = "preset"
FILTER_TYPE_SEVERITY = "severity"


@dataclass(frozen=True)
class LogCommandIntent:
    """Data-only command intent for shell-owned dispatch."""

    label: str
    args: tuple[str, ...]
    hint: str = ""
    binary: str = "defenseclaw"
    category: str = "logs"

    @property
    def argv(self) -> tuple[str, ...]:
        return (self.binary, *self.args)


@dataclass(frozen=True)
class LogPanelAction:
    """Result of a Logs-panel key/action handler."""

    handled: bool
    intent: LogCommandIntent | None = None
    hint: str = ""
    filter_change: LogFilterChange | None = None
    modal: Literal["redaction", "notifications", "judge-history"] | None = None


@dataclass(frozen=True)
class LogFilterChange:
    """Model-level filter telemetry payload matching the Go TUI shape."""

    panel: str
    filter_type: str
    old: str
    new: str


@dataclass(frozen=True)
class LogTabState:
    """Data-only state for one Go-style Logs source tab."""

    source: LogSource
    label: str
    active: bool
    total_lines: int
    filtered_lines: int
    style_key: str


@dataclass(frozen=True)
class LogChipState:
    """Data-only state for one filter chip."""

    group: str
    value: str
    label: str
    active: bool
    shortcut: str = ""
    style_key: str = ""


@dataclass(frozen=True)
class LogChipGroupState:
    """One rendered chip row from the Go Logs panel."""

    group: str
    label: str
    shortcut: str
    chips: tuple[LogChipState, ...]


@dataclass(frozen=True)
class LogStatusState:
    """Header status badge metadata."""

    label: str
    style_key: str
    hint: str = ""


@dataclass(frozen=True)
class LogRedactionState:
    """Effective Logs redaction indicator state."""

    disabled: bool
    badge_label: str = ""
    style_key: str = ""
    hint: str = ""
    source: str = ""

    @property
    def visible(self) -> bool:
        return self.disabled


@dataclass(frozen=True)
class LogHeaderState:
    """Complete data needed to render the Logs header without app-side duplication."""

    tabs: tuple[LogTabState, ...]
    status: LogStatusState
    line_count_label: str
    redaction: LogRedactionState = LogRedactionState(False)
    search_label: str = ""
    search_prompt: str = ""


@dataclass(frozen=True)
class LogRowView:
    """Visible log row with selected-row and color metadata."""

    index: int
    text: str
    selected: bool
    style_key: str
    detail_title: str


@dataclass(frozen=True)
class LogTableRow:
    """Mouse-selectable DataTable row metadata for the Textual shell."""

    key: str
    cursor_index: int
    source: LogSource
    cells: tuple[str, ...]
    selected: bool
    style_key: str
    detail_title: str
    event_type: str = ""
    raw_line: bool = False


class LogsPanelModel:
    """State and pure helpers for the Logs panel.

    The model mirrors the Go panel's read path: free-form gateway/watchdog
    tails, structured Verdicts and OTEL streams from gateway.jsonl, chip
    filters, search, cursor selection, and scroll clamping.
    """

    def __init__(
        self,
        data_dir: Path | None = None,
        *,
        config: object | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        self.data_dir = data_dir
        self.redaction = log_redaction_state(config=config, env=env)
        self.source: LogSource = "gateway"
        self.lines: dict[LogSource, list[str]] = {source: [] for source in LOG_SOURCES}
        self.error_messages: dict[LogSource, str] = {source: "" for source in LOG_SOURCES}
        self.verdict_rows: list[GatewayLogRow] = []
        self.otel_rows: list[GatewayLogRow] = []
        self._paused = False
        self.filter_mode = FILTER_NO_NOISE
        self.searching = False
        self.search_text = ""
        self.verdict_action = ""
        self.verdict_event_type = ""
        self.verdict_severity = ""
        self.cursor: dict[LogSource, int] = {source: 0 for source in LOG_SOURCES}
        self.cursor_moved: dict[LogSource, bool] = {source: False for source in LOG_SOURCES}
        self.scroll: dict[LogSource, int] = {source: 0 for source in LOG_SOURCES}
        # 8.13 multi-connector: shared connector filter ("" = All) + the
        # CONNECTOR column flag, set by the app from the active connector
        # count. Connector is parsed from ``connector=<name>`` in each line.
        self.connector_filter = ""
        self.show_connector_column = False
        # Per-source baseline captured when the user paused. The
        # difference between current line count and this baseline is
        # what the hint bar should show as "+N since pause" so the
        # operator knows whether anything interesting happened while
        # they were reading. ``None`` = not paused for this source.
        self._pause_baseline: dict[LogSource, int | None] = {source: None for source in LOG_SOURCES}
        # File tails and structured gateway events are polled every two
        # seconds. Most ticks observe identical files; remember their cheap
        # stat signatures so those ticks don't reread/reparse up to 1.5 MiB
        # of logs on Textual's UI thread.
        self._refresh_signatures: dict[str, object] = {}
        # A single render asks for the same filtered source several times
        # (table rows, summary, source tabs, cursor clamping). Cache the pure
        # filter result so a 5,000-line tail is scanned once per content or
        # filter change instead of repeatedly in the same keypress/frame.
        self._filtered_lines_cache: dict[
            LogSource,
            tuple[tuple[str, ...], tuple[str, str, str], tuple[str, ...]],
        ] = {}

    def set_data_dir(self, data_dir: str | Path | None) -> None:
        """Late-bind the data dir so a setup-driven config reload can
        repoint the file tail without rebuilding the whole model.

        Mirrors Go's ``m.logs.dataDir = cfg.DataDir`` in
        ``reloadConfigAfterSetupCommand``. After this call the next
        :meth:`refresh` will read from the new directory; existing
        line buffers stay so the operator's cursor position is
        preserved across the swap.
        """

        next_data_dir = Path(data_dir) if data_dir else None
        if next_data_dir != self.data_dir:
            self._refresh_signatures.clear()
        self.data_dir = next_data_dir

    @property
    def paused(self) -> bool:
        return self._paused

    @paused.setter
    def paused(self, value: bool) -> None:
        previous = self._paused
        self._paused = bool(value)
        # Snapshot the line count whenever pause turns on so the hint
        # bar can render "(+N new)" on resume. Clear it on resume so
        # the next pause starts fresh.
        if self._paused and not previous:
            self._pause_baseline[self.source] = len(self.lines.get(self.source, []))
        elif not self._paused:
            for src in self._pause_baseline:
                self._pause_baseline[src] = None

    @property
    def new_lines_since_pause(self) -> int:
        """How many lines arrived on the active source since pause.

        Returns 0 when not paused or when no baseline has been recorded.
        Mirrors Go's ``logs.NewLinesSincePause`` surfaced on HintState.
        """

        baseline = self._pause_baseline.get(self.source)
        if baseline is None:
            return 0
        current = len(self.lines.get(self.source, []))
        return max(0, current - baseline)

    def header_state(self) -> LogHeaderState:
        """Return the Go header state: source tabs, live badge, counts, and search labels."""

        status = LogStatusState(
            label="PAUSED" if self.paused else "LIVE",
            style_key="paused" if self.paused else "live",
            hint="Space to resume" if self.paused else "",
        )
        search_label = f"search: {self.search_text}" if self.search_text else ""
        search_prompt = f"/ {self.search_text}" if self.searching else ""
        return LogHeaderState(
            tabs=self.source_tabs(),
            status=status,
            line_count_label=self.line_count_label(),
            redaction=self.redaction,
            search_label=search_label,
            search_prompt=search_prompt,
        )

    def source_tabs(self) -> tuple[LogTabState, ...]:
        """Expose the four Go Logs source tabs and their active/count state."""

        return tuple(
            LogTabState(
                source=source,
                label=LOG_SOURCE_LABELS[source],
                active=source == self.source,
                total_lines=len(self.lines[source]),
                filtered_lines=len(self.filtered_lines(source)),
                style_key="active-tab" if source == self.source else "inactive-tab",
            )
            for source in LOG_SOURCES
        )

    def line_count_label(self) -> str:
        """Return the Go header count label for the active source."""

        total = len(self.lines[self.source])
        filtered = len(self.filtered_lines())
        if filtered < total:
            return f"{filtered} / {total} lines"
        return f"{total} lines"

    def chip_groups(self) -> tuple[LogChipGroupState, ...]:
        """Return the visible Go chip rows for the active source."""

        groups = [self.filter_chip_group()]
        if self.source == "verdicts":
            groups.extend(self.verdict_chip_groups())
        return tuple(groups)

    def filter_chip_group(self) -> LogChipGroupState:
        """Return the preset filter row, including number-key shortcuts.

        Only the first eight presets advertise a number shortcut; key 9
        is reserved for the global Audit panel hotkey, so the Hooks
        preset is keyless (reached via click or the f cycle).
        """

        chips = tuple(
            LogChipState(
                group="preset",
                value=preset,
                label=FILTER_LABELS[preset],
                active=preset == self.filter_mode,
                shortcut=str(index) if index <= 8 else "",
                style_key="active-chip" if preset == self.filter_mode else "inactive-chip",
            )
            for index, preset in enumerate(FILTER_PRESETS, start=1)
        )
        return LogChipGroupState(group="preset", label="filter", shortcut="f", chips=chips)

    def verdict_chip_groups(self) -> tuple[LogChipGroupState, ...]:
        """Return the Verdicts-only action, type, and severity chip rows."""

        return (
            _chip_group(
                group="action",
                label="action:",
                shortcut="a",
                values=ACTION_FILTERS,
                labels=ACTION_LABELS,
                active_value=self.verdict_action,
            ),
            _chip_group(
                group="type",
                label="type:",
                shortcut="t",
                values=EVENT_TYPE_FILTERS,
                labels=EVENT_TYPE_LABELS,
                active_value=self.verdict_event_type,
            ),
            _chip_group(
                group="severity",
                label="sev:",
                shortcut="s",
                values=SEVERITY_FILTERS,
                labels=SEVERITY_LABELS,
                active_value=self.verdict_severity,
            ),
        )

    def visible_row_views(self, *, height: int = 24) -> tuple[LogRowView, ...]:
        """Return the currently visible log rows with Go-equivalent selection/style metadata."""

        rows = self.filtered_lines()
        if not rows:
            return ()
        visible = self.visible_lines(height=height)
        start = min(self.scroll[self.source], max(len(rows) - visible, 0))
        end = min(start + visible, len(rows))
        selected = self._selected_index(rows)
        title = self.selected_detail_title()
        return tuple(
            LogRowView(
                index=index,
                text=rows[index],
                selected=index == selected,
                style_key=self.line_style_key(rows[index]),
                detail_title=title,
            )
            for index in range(start, end)
        )

    def line_style_key(self, line: str) -> str:
        """Classify a rendered log line using the Go ``colorLine`` precedence."""

        lower = line.lower()
        if any(token in lower for token in ("error", "fatal", "panic")):
            return "log-error"
        if "warn" in lower:
            return "log-warn"
        if any(token in lower for token in ("block", "allow", "scan", "verdict")):
            return "log-keyword"
        if any(token in lower for token in ("connected", "running", "healthy")):
            return "clean"
        if self.is_noise(lower):
            return "dimmed"
        return ""

    def selected_detail_title(self) -> str:
        """Return the title the shell should use for the selected row detail."""

        if self.source == "verdicts":
            row = self.selected_verdict()
            event_type = row.event_type.upper() if row else "EVENT"
            return f"Gateway event - {event_type}"
        if self.source == "otel":
            row = self.selected_otel_row()
            event_type = row.event_type.upper() if row else "EVENT"
            return f"OTEL event - {event_type}"
        return f"{LOG_SOURCE_LABELS[self.source]} log line"

    def hint_text(self) -> str:
        """Return the Go Logs hint copy for the active source."""

        if self.source == "verdicts":
            return (
                f"Streaming {LOG_SOURCE_LABELS[self.source]}. Up/Down select; Enter detail; "
                "Space pause; / search; a/t/s chips; J judge history; R redaction."
            )
        return (
            f"Streaming {LOG_SOURCE_LABELS[self.source]}. Up/Down select; Enter detail; "
            "Space pause; / search; e errors; w warnings; R redaction."
        )

    def set_connector_filter(self, connector: str) -> None:
        """Set the shared connector filter ("" = All).

        Log lines are filtered on the fly (no cached ``filtered`` list), so
        this only stores the value; the next render re-evaluates
        :meth:`line_matches_current_filter`.
        """

        self.connector_filter = (connector or "").strip().lower()

    def data_table_columns(self) -> tuple[str, ...]:
        """Return a stable table shape for the Textual shell."""

        if self.show_connector_column:
            return ("Connector", "Line")
        return ("Line",)

    def data_table_rows(self) -> tuple[tuple[str, ...], ...]:
        """Return active filtered rows in the table shape consumed by Textual."""

        # The shell only needs cell text here. Building ``LogTableRow``
        # metadata for every line also hashes each row and classifies its
        # style; doing that for a cursor-only repaint cost ~25-30 ms at the
        # 5,000-line tail limit even though the table contents were unchanged.
        lines = self.filtered_lines()
        if self.show_connector_column:
            return tuple(
                (_line_connector(line) or "—", line)
                for line in lines
            )
        return tuple((line,) for line in lines)

    def data_table_row_models(self) -> tuple[LogTableRow, ...]:
        """Return active rows with stable row keys and cursor indexes."""

        rows = self.filtered_lines()
        selected = self._selected_index(rows) if rows else 0
        structured: dict[int, GatewayLogRow] = {}
        if self.source == "verdicts":
            structured = {index: row for index, row in enumerate(self.filtered_verdicts())}
        elif self.source == "otel":
            structured = {index: row for index, row in enumerate(self.filtered_otel_rows())}
        return tuple(
            LogTableRow(
                key=_log_row_key(self.source, index, structured.get(index), line),
                cursor_index=index,
                source=self.source,
                cells=(line,),
                selected=index == selected,
                style_key=self.line_style_key(line),
                detail_title=self._detail_title_for_row(structured.get(index)),
                event_type=structured.get(index).event_type if structured.get(index) else "",
                raw_line=self.source not in {"verdicts", "otel"},
            )
            for index, line in enumerate(rows)
        )

    def refresh(self) -> None:
        """Reload the active log files from ``data_dir``."""

        if self.data_dir is None:
            return
        changed_sources: set[LogSource] = set()
        for source, filename in (("gateway", "gateway.log"), ("watchdog", "watchdog.log")):
            path = self.data_dir / filename
            signature = _file_signature(path)
            if self._refresh_signatures.get(source, _UNSET_SIGNATURE) == signature:
                continue
            self._refresh_signatures[source] = signature
            self._load_file(source, path)
            changed_sources.add(source)

        gateway_events_path = self.data_dir / "gateway.jsonl"
        structured_signature = (
            _file_signature(gateway_events_path),
            self.verdict_action,
            self.verdict_event_type,
            self.verdict_severity,
        )
        if self._refresh_signatures.get("structured", _UNSET_SIGNATURE) != structured_signature:
            self._refresh_signatures["structured"] = structured_signature
            views = load_gateway_log_views(
                gateway_events_path,
                action_filter=self.verdict_action,
                event_type_filter=self.verdict_event_type,
                severity_filter=self.verdict_severity,
            )
            self.error_messages["verdicts"] = views.error
            self.error_messages["otel"] = views.error
            self.verdict_rows = list(views.verdict_rows)
            self.otel_rows = list(views.otel_rows)
            self.lines["verdicts"] = list(views.verdict_lines)
            self.lines["otel"] = list(views.otel_lines)
            changed_sources.update(("verdicts", "otel"))

        if self.source in changed_sources:
            self._clamp_cursor()

    def set_source(self, source: LogSource) -> None:
        self.source = source
        self._clamp_cursor()

    def next_source(self) -> None:
        index = LOG_SOURCES.index(self.source)
        self.source = LOG_SOURCES[min(index + 1, len(LOG_SOURCES) - 1)]
        self._clamp_cursor()

    def previous_source(self) -> None:
        index = LOG_SOURCES.index(self.source)
        self.source = LOG_SOURCES[max(index - 1, 0)]
        self._clamp_cursor()

    def set_filter(self, preset: str) -> None:
        if preset in FILTER_PRESETS:
            self.filter_mode = preset
            self.scroll[self.source] = 0
            self.cursor_moved[self.source] = False
            self._clamp_cursor()

    def cycle_filter(self) -> None:
        index = FILTER_PRESETS.index(self.filter_mode) if self.filter_mode in FILTER_PRESETS else 1
        self.set_filter(FILTER_PRESETS[(index + 1) % len(FILTER_PRESETS)])

    def set_verdict_action(self, action: str) -> None:
        if action in ACTION_FILTERS:
            self.verdict_action = action
            self._reset_structured_source()

    def cycle_verdict_action(self) -> None:
        index = ACTION_FILTERS.index(self.verdict_action) if self.verdict_action in ACTION_FILTERS else 0
        self.set_verdict_action(ACTION_FILTERS[(index + 1) % len(ACTION_FILTERS)])

    def set_verdict_event_type(self, event_type: str) -> None:
        if event_type in EVENT_TYPE_FILTERS:
            self.verdict_event_type = event_type
            self._reset_structured_source()

    def cycle_verdict_event_type(self) -> None:
        if self.verdict_event_type in EVENT_TYPE_FILTERS:
            index = EVENT_TYPE_FILTERS.index(self.verdict_event_type)
        else:
            index = 0
        self.set_verdict_event_type(EVENT_TYPE_FILTERS[(index + 1) % len(EVENT_TYPE_FILTERS)])

    def set_verdict_severity(self, severity: str) -> None:
        if severity in SEVERITY_FILTERS:
            self.verdict_severity = severity
            self._reset_structured_source()

    def cycle_verdict_severity(self) -> None:
        index = SEVERITY_FILTERS.index(self.verdict_severity) if self.verdict_severity in SEVERITY_FILTERS else 0
        self.set_verdict_severity(SEVERITY_FILTERS[(index + 1) % len(SEVERITY_FILTERS)])

    def filtered_lines(self, source: LogSource | None = None) -> list[str]:
        active = source or self.source
        rows = self.lines[active]
        rows_snapshot = tuple(rows)
        filter_signature = (self.filter_mode, self.search_text, self.connector_filter)
        cached = self._filtered_lines_cache.get(active)
        if cached is not None and cached[0] == rows_snapshot and cached[1] == filter_signature:
            return list(cached[2])
        if self.filter_mode == FILTER_NONE and not self.search_text and not self.connector_filter:
            filtered = rows_snapshot
        else:
            filtered = tuple(line for line in rows if self.line_matches_current_filter(line.lower()))
        self._filtered_lines_cache[active] = (rows_snapshot, filter_signature, filtered)
        return list(filtered)

    def filtered_verdicts(self) -> list[GatewayLogRow]:
        if self.source != "verdicts":
            return []
        return self._filtered_structured_rows("verdicts", self.verdict_rows)

    def filtered_otel_rows(self) -> list[GatewayLogRow]:
        if self.source != "otel":
            return []
        return self._filtered_structured_rows("otel", self.otel_rows)

    def selected_verdict(self) -> GatewayLogRow | None:
        return self._selected_structured_row("verdicts", self.filtered_verdicts())

    def selected_otel_row(self) -> GatewayLogRow | None:
        return self._selected_structured_row("otel", self.filtered_otel_rows())

    def selected_raw_line(self) -> str:
        if self.source in {"verdicts", "otel"}:
            return ""
        rows = self.filtered_lines()
        if not rows:
            return ""
        index = self._selected_index(rows)
        return rows[index]

    def selected_detail_pairs(self) -> tuple[tuple[str, str], ...]:
        if self.source == "verdicts":
            row = self.selected_verdict()
            return detail_pairs(row) if row else ()
        if self.source == "otel":
            row = self.selected_otel_row()
            return detail_pairs(row) if row else ()
        line = self.selected_raw_line()
        return (("Line", line),) if line else ()

    def move_cursor(self, delta: int, *, height: int = 24) -> None:
        rows = self.filtered_lines()
        if not rows:
            self.cursor[self.source] = 0
            self.cursor_moved[self.source] = True
            return
        if not self.cursor_moved[self.source]:
            self.cursor[self.source] = len(rows) - 1
        self.cursor[self.source] = max(0, min(self.cursor[self.source] + delta, len(rows) - 1))
        self.cursor_moved[self.source] = True
        self.paused = True
        self._clamp_scroll_to_cursor(height=height)

    def set_cursor(self, filtered_index: int, *, height: int = 24) -> None:
        rows = self.filtered_lines()
        if not rows:
            return
        self.cursor[self.source] = max(0, min(filtered_index, len(rows) - 1))
        self.cursor_moved[self.source] = True
        self.paused = True
        self._clamp_scroll_to_cursor(height=height)

    def scroll_by(self, delta: int, *, height: int = 24) -> None:
        rows = self.filtered_lines()
        visible = self.visible_lines(height=height)
        max_scroll = max(len(rows) - visible, 0)
        self.scroll[self.source] = max(0, min(self.scroll[self.source] + delta, max_scroll))
        if delta:
            self.paused = True

    def visible_lines(self, *, height: int = 24) -> int:
        visible = height - 7
        if self.source == "verdicts":
            visible -= 3
        if self.source == "gateway":
            visible -= 1
        if self.searching:
            visible -= 1
        return max(visible, 5)

    def handle_key(self, key: str) -> LogPanelAction:
        """Handle panel-local keys without executing returned intents."""

        if key == "J" and not self.searching and self.source == "verdicts":
            return LogPanelAction(True, hint="Open the SQLite-backed judge response history.", modal="judge-history")
        if key == "R" and not self.searching:
            return LogPanelAction(True, hint="Open redaction toggle confirmation.", modal="redaction")
        if key == "N" and not self.searching:
            return LogPanelAction(True, hint="Open notifications toggle confirmation.", modal="notifications")
        if key == "space":
            self.paused = not self.paused
            return LogPanelAction(True)
        if key in {"left", "h"} and not self.searching:
            self.previous_source()
            return LogPanelAction(True)
        if key in {"right", "l"} and not self.searching:
            self.next_source()
            return LogPanelAction(True)
        if key in {"up", "k"}:
            self.move_cursor(-1)
            return LogPanelAction(True)
        if key in {"down", "j"}:
            self.move_cursor(1)
            return LogPanelAction(True)
        if key == "pgup":
            self.move_cursor(-self.visible_lines())
            return LogPanelAction(True)
        if key == "pgdown":
            self.move_cursor(self.visible_lines())
            return LogPanelAction(True)
        if key == "G":
            rows = self.filtered_lines()
            if rows:
                self.cursor[self.source] = len(rows) - 1
                self.cursor_moved[self.source] = True
            self.paused = False
            self._clamp_scroll_to_cursor()
            return LogPanelAction(True)
        if key == "g":
            self.cursor[self.source] = 0
            self.cursor_moved[self.source] = True
            self.scroll[self.source] = 0
            self.paused = True
            return LogPanelAction(True)
        if key == "f" and not self.searching:
            old = self.filter_mode
            self.cycle_filter()
            return LogPanelAction(True, filter_change=_filter_change(FILTER_TYPE_PRESET, old, self.filter_mode))
        if key == "a" and not self.searching and self.source == "verdicts":
            old = self.verdict_action
            self.cycle_verdict_action()
            return LogPanelAction(True, filter_change=_filter_change(FILTER_TYPE_ACTION, old, self.verdict_action))
        if key == "t" and not self.searching and self.source == "verdicts":
            old = self.verdict_event_type
            self.cycle_verdict_event_type()
            return LogPanelAction(
                True,
                filter_change=_filter_change(FILTER_TYPE_EVENT_TYPE, old, self.verdict_event_type),
            )
        if key == "s" and not self.searching and self.source == "verdicts":
            old = self.verdict_severity
            self.cycle_verdict_severity()
            return LogPanelAction(True, filter_change=_filter_change(FILTER_TYPE_SEVERITY, old, self.verdict_severity))
        # Filters are bound to number keys 1-8 only. The 9 key is the
        # global hotkey for the Audit panel, so the Hooks preset (the 9th
        # entry) is reached via its chip, the f cycle, or the Hook Calls
        # tile deep-link instead of a conflicting number shortcut.
        if key in {str(i) for i in range(1, 9)} and not self.searching and int(key) <= len(FILTER_PRESETS):
            old = self.filter_mode
            self.set_filter(FILTER_PRESETS[int(key) - 1])
            return LogPanelAction(True, filter_change=_filter_change(FILTER_TYPE_PRESET, old, self.filter_mode))
        if key == "e" and not self.searching:
            old = self.filter_mode
            self.set_filter(FILTER_NONE if self.filter_mode == FILTER_ERRORS else FILTER_ERRORS)
            return LogPanelAction(True, filter_change=_filter_change(FILTER_TYPE_PRESET, old, self.filter_mode))
        if key == "w" and not self.searching:
            old = self.filter_mode
            self.set_filter(FILTER_NONE if self.filter_mode == FILTER_WARNINGS else FILTER_WARNINGS)
            return LogPanelAction(True, filter_change=_filter_change(FILTER_TYPE_PRESET, old, self.filter_mode))
        if key == "/" and not self.searching:
            self.searching = True
            self.search_text = ""
            return LogPanelAction(True)
        if key == "enter" and self.searching:
            self.searching = False
            return LogPanelAction(True)
        if key == "esc" and self.searching:
            self.searching = False
            self.search_text = ""
            self._clamp_cursor()
            return LogPanelAction(True)
        if key == "backspace" and self.searching:
            self.search_text = self.search_text[:-1]
            self._clamp_cursor()
            return LogPanelAction(True)
        if self.searching and len(key) == 1:
            self.search_text += key
            self._clamp_cursor()
            return LogPanelAction(True)
        return LogPanelAction(False)

    def render_text(self, *, height: int = 24) -> str:
        """Render a compact text view for tests and placeholder integration."""

        header = self._header_text()
        if self.error_messages[self.source] and not self.lines[self.source]:
            return f"{header}\n\n  {self.error_messages[self.source]}"

        rows = self.filtered_lines()
        if not rows and self.lines[self.source]:
            return f"{header}\n\n  No lines match the current filter. Press f to cycle or 1 for All."
        if not self.lines[self.source]:
            return f"{header}\n\n  Log file is empty or not yet created. Start the gateway with : then start."

        visible = self.visible_lines(height=height)
        start = min(self.scroll[self.source], max(len(rows) - visible, 0))
        end = min(start + visible, len(rows))
        selected = self._selected_index(rows)
        body: list[str] = []
        for index in range(start, end):
            prefix = "-> " if index == selected else "   "
            body.append(f"{prefix}{rows[index]}")
        if len(rows) > visible:
            body.append(f"   {start + 1}-{end} of {len(rows)}")
        return f"{header}\n\n" + "\n".join(body)

    def summary_text(self) -> str:
        """Render the Go-like source/filter chip header without row duplication."""

        rows = self.filtered_lines()
        total = len(self.lines[self.source])
        visible = len(rows)
        error = f"\n[#F87171]{self.error_messages[self.source]}[/]" if self.error_messages[self.source] else ""
        return (
            f"{self._header_text()}  {visible} / {total} lines\n"
            "Keys: h/l source, 1-8 filter, Space pause, / search, e errors, w warnings, Enter detail."
            f"{error}"
        )

    def line_matches_current_filter(self, lower_line: str) -> bool:
        # 8.13: the shared connector filter (from the chip) narrows lines to a
        # single connector. Lines carry ``connector=<name>``; lines without
        # any connector tag are hidden under an explicit filter.
        if self.connector_filter:
            if (
                f"connector={self.connector_filter}" not in lower_line
                and self.connector_filter not in lower_line
            ):
                return False
        if self.search_text:
            # E5: recognize the same ``connector:<name>`` token as the Audit
            # and Alerts panels. Connector-hook log lines carry the connector
            # as ``connector=<name>`` (gateway.jsonl / OTEL render), so match
            # that form first and fall back to a bare substring; the remaining
            # free text keeps the legacy substring search.
            connector_value, remaining = split_connector_token(self.search_text.lower())
            if connector_value:
                if (
                    f"connector={connector_value}" not in lower_line
                    and connector_value not in lower_line
                ):
                    return False
            if remaining and remaining not in lower_line:
                return False
        if self.filter_mode == FILTER_NONE:
            return True
        if self.filter_mode == FILTER_NO_NOISE:
            return (
                not any(pattern in lower_line for pattern in NOISE_PATTERNS)
                and _line_has_actionable_signal(lower_line)
            )
        if self.filter_mode == FILTER_IMPORTANT:
            return any(pattern in lower_line for pattern in IMPORTANT_PATTERNS)
        if self.filter_mode == FILTER_ERRORS:
            return any(pattern in lower_line for pattern in ("error", "fatal", "panic"))
        if self.filter_mode == FILTER_WARNINGS:
            return any(pattern in lower_line for pattern in ("error", "fatal", "panic", "warn"))
        if self.filter_mode == FILTER_SCAN:
            return "scan" in lower_line or "finding" in lower_line
        if self.filter_mode == FILTER_DRIFT:
            return "drift" in lower_line or "rescan" in lower_line
        if self.filter_mode == FILTER_GUARDRAIL:
            return "guardrail" in lower_line or "guard" in lower_line
        if self.filter_mode == FILTER_HOOKS:
            return any(pattern in lower_line for pattern in HOOK_PATTERNS)
        return True

    def is_noise(self, lower_line: str) -> bool:
        """Return true when a lowercased line matches the Go noise filter."""

        return any(pattern in lower_line for pattern in NOISE_PATTERNS)

    def _filtered_structured_rows(self, source: LogSource, rows: list[GatewayLogRow]) -> list[GatewayLogRow]:
        rendered = self.lines[source]
        if len(rendered) != len(rows):
            return []
        if self.filter_mode == FILTER_NONE and not self.search_text:
            return list(rows)
        return [row for row, line in zip(rows, rendered, strict=True) if self.line_matches_current_filter(line.lower())]

    def _selected_structured_row(self, source: LogSource, rows: list[GatewayLogRow]) -> GatewayLogRow | None:
        if self.source != source or not rows:
            return None
        return rows[self._selected_index(rows)]

    def _selected_index(self, rows: list[object]) -> int:
        index = self.cursor[self.source]
        if not self.cursor_moved[self.source]:
            index = len(rows) - 1
        return max(0, min(index, len(rows) - 1))

    def _clamp_cursor(self) -> None:
        rows = self.filtered_lines()
        if not rows:
            self.cursor[self.source] = 0
            self.scroll[self.source] = 0
            return
        self.cursor[self.source] = max(0, min(self.cursor[self.source], len(rows) - 1))
        self._clamp_scroll_to_cursor()

    def _clamp_scroll_to_cursor(self, *, height: int = 24) -> None:
        rows = self.filtered_lines()
        if not rows:
            self.scroll[self.source] = 0
            return
        visible = self.visible_lines(height=height)
        index = self._selected_index(rows)
        if index < self.scroll[self.source]:
            self.scroll[self.source] = index
        if index >= self.scroll[self.source] + visible:
            self.scroll[self.source] = index - visible + 1
        max_scroll = max(len(rows) - visible, 0)
        self.scroll[self.source] = max(0, min(self.scroll[self.source], max_scroll))

    def _reset_structured_source(self) -> None:
        self.scroll["verdicts"] = 0
        self.cursor_moved["verdicts"] = False
        if self.data_dir is not None:
            self.refresh()
        else:
            self._clamp_cursor()

    def _load_file(self, source: LogSource, path: Path) -> None:
        try:
            self.lines[source] = list(_tail_text_file(path))
            self.error_messages[source] = ""
        except OSError as exc:
            self.lines[source] = []
            self.error_messages[source] = f"Cannot open: {exc}"

    def _header_text(self) -> str:
        state = "PAUSED" if self.paused else "LIVE"
        filter_label = FILTER_LABELS.get(self.filter_mode, self.filter_mode)
        source_label = LOG_SOURCE_LABELS[self.source]
        chips = ""
        if self.source == "verdicts":
            chips = (
                f" action={ACTION_LABELS[self.verdict_action]}"
                f" type={EVENT_TYPE_LABELS[self.verdict_event_type]}"
                f" severity={SEVERITY_LABELS[self.verdict_severity]}"
            )
        search = f" search={self.search_text}" if self.search_text else ""
        raw = "  RAW redaction off" if self.redaction.disabled else ""
        return f"{source_label}  {state}  filter={filter_label}{chips}{search}{raw}"

    def sync_redaction_state(self, *, config: object | None = None, env: Mapping[str, str] | None = None) -> None:
        """Refresh the model's effective redaction badge state."""

        self.redaction = log_redaction_state(config=config, env=env)

    def _detail_title_for_row(self, row: GatewayLogRow | None) -> str:
        if self.source == "verdicts":
            event_type = row.event_type.upper() if row else "EVENT"
            return f"Gateway event - {event_type}"
        if self.source == "otel":
            event_type = row.event_type.upper() if row else "EVENT"
            return f"OTEL event - {event_type}"
        return f"{LOG_SOURCE_LABELS[self.source]} log line"


def _chip_group(
    *,
    group: str,
    label: str,
    shortcut: str,
    values: tuple[str, ...],
    labels: dict[str, str],
    active_value: str,
) -> LogChipGroupState:
    chips = tuple(
        LogChipState(
            group=group,
            value=value,
            label=labels[value],
            active=value == active_value,
            style_key="active-chip" if value == active_value else "inactive-chip",
        )
        for value in values
    )
    return LogChipGroupState(group=group, label=label, shortcut=shortcut, chips=chips)


def redaction_disabled_for_logs_badge(
    *,
    config: object | None = None,
    env: Mapping[str, str] | None = None,
) -> bool:
    """Return true when Logs should show the foreground RAW badge."""

    return log_redaction_state(config=config, env=env).disabled


def log_redaction_state(
    *,
    config: object | None = None,
    env: Mapping[str, str] | None = None,
) -> LogRedactionState:
    """Resolve effective redaction state from config plus env override."""

    source = ""
    disabled = False
    privacy = getattr(config, "privacy", None)
    if bool(getattr(privacy, "disable_redaction", False)):
        disabled = True
        source = "privacy.disable_redaction=true"
    environ = os.environ if env is None else env
    env_value = str(environ.get(REDACTION_ENV_VAR, "")).strip()
    if env_value.lower() in TRUTHY_REDACTION_VALUES:
        disabled = True
        env_source = f"{REDACTION_ENV_VAR}={env_value}"
        source = f"{source}, {env_source}" if source else env_source
    if not disabled:
        return LogRedactionState(False)
    return LogRedactionState(
        disabled=True,
        badge_label="RAW",
        style_key="raw",
        hint="redaction off - `defenseclaw setup redaction on` to re-enable",
        source=source,
    )


def _filter_change(filter_type: str, old: str, new: str) -> LogFilterChange | None:
    if old == new:
        return None
    return LogFilterChange(panel="logs", filter_type=filter_type, old=old, new=new)


def _line_has_actionable_signal(lower_line: str) -> bool:
    if any(pattern in lower_line for pattern in ACTIONABLE_LOG_PATTERNS):
        return True
    return not any(pattern in lower_line for pattern in LOW_SIGNAL_LOG_PATTERNS)


_CONNECTOR_LINE_RE = re.compile(r"connector[=:]\s*\"?([A-Za-z0-9._-]+)\"?", re.IGNORECASE)


def _line_connector(line: str) -> str:
    """Extract the connector name from a ``connector=<name>`` log line.

    Returns "" when the line has no connector tag (rendered as ``—`` in the
    CONNECTOR column). Handles both ``connector=foo`` (text logs) and
    ``"connector":"foo"`` style JSON via the ``[=:]`` alternation.
    """

    match = _CONNECTOR_LINE_RE.search(line or "")
    return match.group(1) if match else ""


def _log_row_key(source: LogSource, index: int, row: GatewayLogRow | None, line: str) -> str:
    if row is None:
        return f"{source}:{index}:{_short_digest(line)}"
    identity = row.request_id or row.run_id or row.session_id or row.scan_id or row.raw
    return f"{source}:{index}:{_short_digest(identity)}"


def _short_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]


def _file_signature(path: Path) -> tuple[int, int, int, int] | None:
    """Return a rotation-safe, nanosecond file identity for polling.

    ``None`` deliberately represents missing/unreadable files. The caller
    keeps a separate unset sentinel, so the first miss still flows through
    the normal loader and records its operator-facing error state.
    """

    try:
        stat = path.stat()
    except OSError:
        return None
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)


def _tail_text_file(path: Path, *, max_bytes: int = 512 * 1024, max_lines: int = 5000) -> tuple[str, ...]:
    with path.open("rb") as file:
        file.seek(0, 2)
        size = file.tell()
        read_size = min(size, max_bytes)
        file.seek(size - read_size)
        data = file.read(read_size)
    if size > read_size:
        _, _, data = data.partition(b"\n")
    lines = data.decode("utf-8", errors="replace").splitlines()
    if len(lines) > max_lines:
        lines = lines[-max_lines:]
    return tuple(lines)
