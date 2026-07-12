# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Pure Audit panel model for the Textual TUI migration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from defenseclaw.models import ActionEntry, Event
from defenseclaw.tui.services.event_models import parse_timestamp, timestamp_label

AuditIntentKind = Literal["export"]
AuditCommonFilter = Literal["", "risk", "blocks", "scans", "credentials"]
AUDIT_ACTIONABLE_SEVERITIES = {"CRITICAL", "HIGH", "ERROR"}
AUDIT_LOW_SIGNAL_SEVERITIES = {"INFO", "LOW", "MEDIUM", "WARNING", ""}
AUDIT_ACTIONABLE_TOKENS = (
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
    "error",
    "fatal",
    "panic",
)
AUDIT_TABLE_COLUMNS: tuple[str, ...] = ("TIME", "ACTION", "TYPE", "TARGET", "SEVERITY", "RUN", "DETAILS")
# Multi-connector variant: a CONNECTOR column is inserted after TYPE so the
# operator can attribute each event without opening the detail pane.
AUDIT_TABLE_COLUMNS_MULTI: tuple[str, ...] = (
    "TIME",
    "ACTION",
    "TYPE",
    "CONNECTOR",
    "TARGET",
    "SEVERITY",
    "RUN",
    "DETAILS",
)

AUDIT_COMMON_FILTER_LABELS: dict[AuditCommonFilter, str] = {
    "": "All",
    "risk": "Risk",
    "blocks": "Blocks",
    "scans": "Scans",
    "credentials": "Credentials",
}


@dataclass(frozen=True)
class AuditActionIntent:
    """Data-only action intent for shell-owned audit operations."""

    kind: AuditIntentKind
    label: str
    path: Path | None = None
    category: str = "audit"


@dataclass(frozen=True)
class AuditPanelAction:
    """Result of a panel-local key/action handler."""

    handled: bool
    intent: AuditActionIntent | None = None
    hint: str = ""


@dataclass(frozen=True)
class AuditToolbarActionState:
    """Data-only toolbar action metadata for the Audit header."""

    key: str
    label: str
    intent: AuditActionIntent | None = None


@dataclass(frozen=True)
class AuditToolbarState:
    """Go-style summary, filter/search labels, and toolbar actions."""

    summary_label: str
    filter_label: str = ""
    filtered_label: str = ""
    search_prompt: str = ""
    actions: tuple[AuditToolbarActionState, ...] = ()


@dataclass(frozen=True)
class AuditRowView:
    """Audit table row plus Textual style metadata."""

    index: int
    event: Event
    selected: bool
    time_label: str
    action_label: str
    action_style_key: str
    target_type: str
    target_label: str
    severity_label: str
    severity_style_key: str
    run_label: str
    details_label: str
    connector_label: str = ""

    @property
    def table_key(self) -> str:
        return f"audit:{self.event.id or self.index}"

    @property
    def cells(self) -> tuple[str, ...]:
        return (
            self.time_label,
            self.action_label,
            self.target_type,
            self.target_label,
            self.severity_label,
            self.run_label,
            self.details_label,
        )

    def cells_with_connector(self) -> tuple[str, ...]:
        """Cells with a CONNECTOR column inserted after TYPE (multi-connector)."""

        return (
            self.time_label,
            self.action_label,
            self.target_type,
            self.connector_label or "—",
            self.target_label,
            self.severity_label,
            self.run_label,
            self.details_label,
        )


@dataclass(frozen=True)
class AuditFinding:
    """Finding row attached to a selected audit event by run_id."""

    id: str
    scan_id: str
    severity: str
    title: str
    description: str = ""
    location: str = ""
    remediation: str = ""
    scanner: str = ""


@dataclass(frozen=True)
class AuditDetailInfo:
    """Expanded detail data for the selected audit row."""

    event: Event
    findings: tuple[AuditFinding, ...] = ()
    related: tuple[Event, ...] = ()
    action: ActionEntry | None = None


@dataclass(frozen=True)
class AuditDetailRow:
    """One mouse/selectable detail row for the detail surface."""

    key: str
    label: str
    value: str
    style_key: str = ""


@dataclass(frozen=True)
class AuditExportRow:
    """JSON export row shape shared with the app-level writer."""

    id: str
    timestamp: str
    action: str
    target: str
    actor: str
    details: str
    severity: str
    run_id: str

    def as_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "action": self.action,
            "target": self.target,
            "actor": self.actor,
            "details": self.details,
            "severity": self.severity,
            "run_id": self.run_id,
        }


class AuditPanelModel:
    """State and pure helpers for SQLite audit history."""

    def __init__(self, store: object | None = None) -> None:
        self.store = store
        self.items: list[Event] = []
        self.filtered: list[Event] = []
        self.cursor = 0
        self.filter_text = ""
        self.filtering = False
        self.common_filter: AuditCommonFilter = ""
        self.show_all_events = False
        self.correlation_target = ""
        self.correlation_run_id = ""
        self.detail_open = False
        self.error_message = ""
        # 8.13 multi-connector: the shared connector filter ("" = All) and
        # whether the table should surface a CONNECTOR column. Both are set
        # by the app from the active connector count; single-connector
        # installs leave them at the defaults so the table is unchanged.
        self.connector_filter = ""
        self.show_connector_column = False
        self._detail_cache: AuditDetailInfo | None = None
        self._detail_cache_cursor = -1

    def set_store(self, store: object | None) -> None:
        """Late-bind the audit DB so a setup-driven reopen takes effect.

        Mirrors Go's ``m.audit.SetStore(m.store)`` inside
        ``reloadConfigAfterSetupCommand``. The next :meth:`refresh`
        call will query the new handle; cursors and filters are
        preserved across the swap.
        """

        self.store = store

    def toolbar_state(self) -> AuditToolbarState:
        """Return the Go Audit summary/export/filter/search header state."""

        filter_label = self.active_filter_label()
        filtered_label = ""
        if filter_label:
            filtered_label = filter_label
            filter_label = f"Showing {len(self.filtered)} of {len(self.items)}: {filter_label}"
        return AuditToolbarState(
            summary_label=f"{len(self.filtered)} shown of {len(self.items)} events",
            filter_label=filter_label,
            filtered_label=filtered_label,
            search_prompt=f"/ {self.filter_text}" if self.filtering else "",
            actions=(
                AuditToolbarActionState("e", "export", export_audit_intent()),
                AuditToolbarActionState("/", "filter"),
            ),
        )

    def selected_detail_title(self) -> str:
        """Return a one-line title for the selected event's detail pane.

        For ``connector-hook`` events we promote the connector and hook
        phase into the title (e.g. ``EVENT: claudecode preToolUse``)
        because plain ``EVENT: connector-hook`` told operators nothing
        useful — every hook row had the same title. Other actions keep
        the legacy ``EVENT: <action>`` format the Go TUI used.
        """

        event = self.selected()
        if event is None:
            return ""
        if event.action == "connector-hook":
            details = _parse_kv_details(event.details)
            connector = details.get("connector", "")
            hook_phase = event.target or ""
            if connector and hook_phase:
                return f"EVENT: {connector} {hook_phase}"
            if connector:
                return f"EVENT: {connector} hook"
            if hook_phase:
                return f"EVENT: {hook_phase}"
        return f"EVENT: {event.action}"

    def row_views(self) -> tuple[AuditRowView, ...]:
        """Return all filtered Audit rows with Go-equivalent display and style metadata."""

        return tuple(self._row_view(index, event) for index, event in enumerate(self.filtered))

    def visible_row_views(self, *, height: int = 24) -> tuple[AuditRowView, ...]:
        """Return rows visible in the Go viewport math."""

        visible = max(self.list_height(height=height), 5)
        start = self.scroll_offset(height=height)
        end = min(start + visible, len(self.filtered))
        return tuple(self._row_view(index, self.filtered[index]) for index in range(start, end))

    def data_table_columns(self) -> tuple[str, ...]:
        """Return the Audit table columns, with CONNECTOR in multi-connector."""

        if self.show_connector_column:
            return AUDIT_TABLE_COLUMNS_MULTI
        return AUDIT_TABLE_COLUMNS

    def data_table_rows(self) -> tuple[tuple[str, ...], ...]:
        """Return filtered Audit rows in the active column shape."""

        if self.show_connector_column:
            return tuple(row.cells_with_connector() for row in self.row_views())
        return tuple(row.cells for row in self.row_views())

    def data_table_row_models(self) -> tuple[AuditRowView, ...]:
        """Return filtered rows with table keys and style metadata."""

        return self.row_views()

    def export_rows(self) -> tuple[AuditExportRow, ...]:
        """Return the exact rows the Audit export action should write."""

        return tuple(
            AuditExportRow(
                id=event.id,
                timestamp=event.timestamp.isoformat(),
                action=event.action,
                target=event.target,
                actor=event.actor,
                details=event.details,
                severity=event.severity,
                run_id=event.run_id,
            )
            for event in self.filtered
        )

    def export_payload(self) -> tuple[dict[str, str], ...]:
        """Return JSON-serializable Audit export payload rows."""

        return tuple(row.as_dict() for row in self.export_rows())

    def refresh(self) -> None:
        """Load the latest audit events from the configured store."""

        if self.store is None:
            return
        try:
            if not self.show_all_events and not self.filter_text and not self.common_filter and hasattr(
                self.store, "list_actionable_event_summaries"
            ):
                self.items = list(self.store.list_actionable_event_summaries(500))  # type: ignore[attr-defined]
            elif hasattr(self.store, "list_event_summaries"):
                self.items = list(self.store.list_event_summaries(500))  # type: ignore[attr-defined]
            else:
                self.items = list(self.store.list_events(500))  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001 - store failures are panel error state.
            self.error_message = f"Audit refresh failed: {exc}"
            self.items = []
            self.filtered = []
            self.cursor = 0
            self._clear_detail_cache()
            return
        self.error_message = ""
        self.apply_filter()

    def set_events(self, events: list[Event]) -> None:
        self.items = list(events)
        self.apply_filter()

    def set_connector_filter(self, connector: str) -> None:
        """Set the shared connector filter ("" = All) and re-apply filters.

        Recomputes :attr:`filtered` so the row count, cursor, and detail
        cache stay consistent with the narrowed view.
        """

        connector = (connector or "").strip().lower()
        if connector == self.connector_filter:
            return
        self.connector_filter = connector
        self.apply_filter()

    def apply_filter(self) -> None:
        self.filtered = [event for event in self.items if self._matches_active_filters(event)]
        if self.filtered:
            self.cursor = max(0, min(self.cursor, len(self.filtered) - 1))
        else:
            self.cursor = 0
        self._clear_detail_cache()

    def set_filter(self, text: str) -> None:
        self.filter_text = text
        if text:
            self.show_all_events = True
        self.apply_filter()

    def clear_filter(self) -> None:
        self.filter_text = ""
        self.filtering = False
        self.common_filter = ""
        self.show_all_events = True
        self.correlation_target = ""
        self.correlation_run_id = ""
        self.apply_filter()

    def set_common_filter(self, preset: AuditCommonFilter) -> None:
        self.common_filter = preset
        if preset:
            self.show_all_events = True
        self.correlation_target = ""
        self.correlation_run_id = ""
        if preset and self.store is not None:
            self.refresh()
            return
        self.apply_filter()

    def filter_same_target(self) -> bool:
        event = self.selected()
        if event is None or not event.target:
            return False
        self.common_filter = ""
        self.correlation_target = event.target
        self.correlation_run_id = ""
        self.apply_filter()
        return True

    def filter_same_run(self) -> bool:
        event = self.selected()
        if event is None or not event.run_id:
            return False
        self.common_filter = ""
        self.correlation_run_id = event.run_id
        self.correlation_target = ""
        self.apply_filter()
        return True

    def active_filter_label(self) -> str:
        parts: list[str] = []
        if self.common_filter:
            parts.append(AUDIT_COMMON_FILTER_LABELS[self.common_filter])
        if self.correlation_target:
            parts.append(f"target:{self.correlation_target}")
        if self.correlation_run_id:
            parts.append(f"run:{self.correlation_run_id}")
        if self.filter_text:
            parts.append(f"search '{self.filter_text}'")
        return ", ".join(parts)

    def selected(self) -> Event | None:
        if 0 <= self.cursor < len(self.filtered):
            return self.filtered[self.cursor]
        return None

    def cursor_up(self) -> None:
        if self.cursor > 0:
            self.cursor -= 1
            self._clear_detail_cache()

    def cursor_down(self) -> None:
        if self.cursor < len(self.filtered) - 1:
            self.cursor += 1
            self._clear_detail_cache()

    def set_cursor(self, index: int) -> None:
        if not self.filtered:
            self.cursor = 0
        else:
            self.cursor = max(0, min(index, len(self.filtered) - 1))
        self._clear_detail_cache()

    def scroll_by(self, delta: int) -> None:
        self.set_cursor(self.cursor + delta)

    def scroll_offset(self, *, height: int = 24) -> int:
        max_visible = self.list_height(height=height)
        if self.cursor >= max_visible:
            return self.cursor - max_visible + 1
        return 0

    def list_height(self, *, height: int = 24) -> int:
        size = height - self.filter_bar_height() - 3 - self.detail_height(height=height)
        return max(size, 3)

    def detail_height(self, *, height: int = 24) -> int:
        if not self.detail_open:
            return 0
        return min(max(height // 2, 8), 26)

    def filter_bar_height(self) -> int:
        height = 0
        if self.filter_text:
            height += 1
        if self.filtering:
            height += 1
        return height

    def toggle_detail(self) -> None:
        if self.selected() is None:
            return
        self.detail_open = not self.detail_open
        self._clear_detail_cache()

    @property
    def count(self) -> int:
        return len(self.items)

    @property
    def filtered_count(self) -> int:
        return len(self.filtered)

    def get_detail_info(self) -> AuditDetailInfo | None:
        selected = self.selected()
        if selected is None:
            return None
        if self._detail_cache is not None and self._detail_cache_cursor == self.cursor:
            return self._detail_cache

        event = _get_event_by_id(self.store, selected.id) or selected
        findings = _list_findings_by_run_id(self.store, event.run_id)
        related = _list_related_events(self.store, event, 12)
        action = _get_current_action(self.store, event)
        info = AuditDetailInfo(event=event, findings=findings, related=related, action=action)
        self._detail_cache = info
        self._detail_cache_cursor = self.cursor
        return info

    def detail_pairs(self) -> tuple[tuple[str, str], ...]:
        """Return ordered (label, value) rows for the selected event.

        Connector-hook and other gateway events ship with a structured
        ``details`` string of the form ``key=value key=value …``. Showing
        that as one giant blob (the Go TUI does) is unreadable — users
        on hook connectors see "observe connector=claudecode action=allow
        severity=NONE would_block=false elapsed=…" with no obvious
        primary signal. We parse and surface those fields as their own
        labelled rows, hide the ones that are pure noise (``would_block``
        in observe mode, ``severity=NONE``), and rewrite raw payload
        digests into something a human can interpret. Events without
        kv-style details fall back to the single ``Details`` row so
        non-hook actions (block-plugin, scan, etc.) still render.
        """

        info = self.get_detail_info()
        if info is None:
            return ()
        event = info.event
        pairs: list[tuple[str, str]] = [
            ("Time", event.timestamp.isoformat()),
            ("Event ID", event.id),
            ("Action", event.action),
            ("Target", event.target),
            ("Severity", event.severity),
            ("Actor", event.actor),
        ]
        if event.details:
            structured = _structured_detail_rows(event.details)
            if structured:
                pairs.extend(structured)
            else:
                pairs.append(("Details", event.details))
        if event.run_id:
            pairs.append(("Run ID", event.run_id))
        if info.action is not None:
            pairs.append(("Current State", info.action.actions.summary()))
        for index, finding in enumerate(info.findings, start=1):
            value = f"{finding.severity} {finding.title}"
            if finding.location:
                value += f" @ {finding.location}"
            pairs.append((f"Finding {index}", value))
        related = tuple(item for item in info.related if item.id != event.id)
        for index, item in enumerate(related[:5], start=1):
            pairs.append((f"Related {index}", f"{timestamp_label(item.timestamp)} {item.action} {item.severity}"))
        return tuple(pairs)

    def detail_rows(self) -> tuple[AuditDetailRow, ...]:
        """Return detail rows with stable keys and semantic style buckets."""

        return tuple(
            AuditDetailRow(
                key=f"detail:{index}:{_slug(label)}",
                label=label,
                value=value,
                style_key=_detail_style_key(label, value),
            )
            for index, (label, value) in enumerate(self.detail_pairs())
        )

    def handle_key(self, key: str) -> AuditPanelAction:
        """Handle panel-local keys without executing returned intents."""

        if self.filtering:
            return self._handle_filter_key(key)
        if key in {"j", "down"}:
            self.cursor_down()
            return AuditPanelAction(True)
        if key in {"k", "up"}:
            self.cursor_up()
            return AuditPanelAction(True)
        if key == "enter":
            self.toggle_detail()
            return AuditPanelAction(True)
        if key in {"esc", "escape"}:
            if self.detail_open:
                self.toggle_detail()
                return AuditPanelAction(True, hint="Closed audit detail.")
            if self.active_filter_label():
                self.clear_filter()
                return AuditPanelAction(True, hint="Audit filters cleared.")
            return AuditPanelAction(False)
        if key == "r":
            self.refresh()
            return AuditPanelAction(True, hint="Refreshed audit history.")
        if key == "/":
            self.filtering = True
            self.filter_text = ""
            self.show_all_events = True
            if self.store is not None:
                self.refresh()
            self.apply_filter()
            return AuditPanelAction(
                True,
                hint="Type search. Use field:value like severity:HIGH, action:block, target:skill.",
            )
        if key == "1":
            self.show_all_events = True
            self.set_common_filter("")
            if self.store is not None:
                self.refresh()
            return AuditPanelAction(True, hint="Showing all audit events.")
        if key == "2":
            self.set_common_filter("risk")
            return AuditPanelAction(True, hint="Showing high-risk audit events.")
        if key == "3":
            self.set_common_filter("blocks")
            return AuditPanelAction(True, hint="Showing block/deny/quarantine events.")
        if key == "4":
            self.set_common_filter("scans")
            return AuditPanelAction(True, hint="Showing scan and finding events.")
        if key == "5":
            self.set_common_filter("credentials")
            return AuditPanelAction(True, hint="Showing credential/key related events.")
        if key == "t":
            if self.filter_same_target():
                return AuditPanelAction(True, hint="Correlated audit view by selected target.")
            return AuditPanelAction(True, hint="Selected event has no target to correlate.")
        if key == "u":
            if self.filter_same_run():
                return AuditPanelAction(True, hint="Correlated audit view by selected run.")
            return AuditPanelAction(True, hint="Selected event has no run id to correlate.")
        if key == "e":
            return AuditPanelAction(True, export_audit_intent())
        return AuditPanelAction(False)

    def render_text(self, *, height: int = 24) -> str:
        """Render a compact text view for tests and placeholder integration."""

        prefix: list[str] = []
        if self.error_message:
            return self.error_message
        if self.active_filter_label():
            prefix.append(f"Filter: {self.active_filter_label()} ({len(self.filtered)} of {len(self.items)})")
        if self.filtering:
            prefix.append(f"/ {self.filter_text}")
        header = "\n".join(prefix)
        if not self.filtered and not self.filter_text:
            body = "No audit events yet. Events are recorded when you scan, block, allow, or configure DefenseClaw."
            return f"{header}\n{body}".strip()
        if not self.filtered:
            return f"{header}\nNo events match the filter.".strip()

        # Escape both bracketed tokens: ``[e]`` would be parsed as
        # a Rich style tag (and Style.parse('e') would fail in the
        # safety wrapper, forcing the panel to plain-text fallback),
        # and ``[/]`` is a closing tag with nothing to close — that's
        # an outright MarkupError that the wrapper has to swallow.
        lines = [
            f"{len(self.items)} events recorded  \\[e] export  \\[/] filter"
        ]
        visible = max(self.list_height(height=height), 5)
        start = self.scroll_offset(height=height)
        end = min(start + visible, len(self.filtered))
        for index, event in enumerate(self.filtered[start:end], start=start):
            marker = "->" if index == self.cursor else "  "
            target_type = _target_type_from_action(event.action)
            details = _truncate(event.details, 20)
            target = _truncate(event.target, 32)
            lines.append(
                f"{marker} {timestamp_label(event.timestamp)} {event.action:<14} "
                f"{target_type:<10} {target:<32} {event.severity:<10} {details}"
            )
        if len(self.filtered) > visible:
            lines.append(f"   {start + 1}-{end} of {len(self.filtered)}")
        if self.detail_open:
            lines.append("")
            lines.extend(f"{key}: {value}" for key, value in self.detail_pairs())
        return f"{header}\n".join(("", "\n".join(lines))).strip() if header else "\n".join(lines)

    def summary_text(self) -> str:
        """Render the Go-like audit header without duplicating table rows."""

        if self.error_message:
            return self.error_message
        filter_part = f"  filter={self.active_filter_label()!r}" if self.active_filter_label() else ""
        input_part = f"\n/ {self.filter_text}" if self.filtering else ""
        count = f"{len(self.filtered)} / {len(self.items)}" if self.filter_text else str(len(self.items))
        # Same escape as ``render_text`` above — ``[e]`` is a tag
        # and ``[/]`` is an unmatched close. Escape both.
        return (
            f"{count} events recorded  \\[e] export  \\[/] filter"
            f"{filter_part}{input_part}"
        )

    def _row_view(self, index: int, event: Event) -> AuditRowView:
        action_label, action_style = audit_action_display(event.action)
        target_label = _row_target_label(event)
        details_label = _row_details_label(event)
        return AuditRowView(
            index=index,
            event=event,
            selected=index == self.cursor,
            time_label=timestamp_label(event.timestamp),
            action_label=action_label,
            action_style_key=action_style,
            target_type=_target_type_from_action(event.action),
            target_label=target_label,
            severity_label=event.severity,
            severity_style_key=audit_severity_style_key(event.severity),
            run_label=_truncate(event.run_id, 14),
            details_label=details_label,
            connector_label=_truncate(event_connector(event), 14),
        )

    def _handle_filter_key(self, key: str) -> AuditPanelAction:
        if key == "enter":
            self.filtering = False
            return AuditPanelAction(True, hint=self.active_filter_label() or "Search applied.")
        if key in {"esc", "escape"}:
            self.clear_filter()
            return AuditPanelAction(True, hint="Audit search cleared.")
        if key == "backspace":
            self.set_filter(self.filter_text[:-1])
            return AuditPanelAction(True)
        if len(key) == 1:
            self.set_filter(self.filter_text + key)
            return AuditPanelAction(True)
        return AuditPanelAction(False)

    def _clear_detail_cache(self) -> None:
        self._detail_cache = None
        self._detail_cache_cursor = -1

    def _matches_active_filters(self, event: Event) -> bool:
        if not self.show_all_events and not self.common_filter and not self.filter_text and _is_low_signal_event(event):
            return False
        if self.common_filter and not _matches_common_filter(event, self.common_filter):
            return False
        if self.correlation_target and event.target != self.correlation_target:
            return False
        if self.correlation_run_id and event.run_id != self.correlation_run_id:
            return False
        if self.filter_text and not _matches_search_query(event, self.filter_text):
            return False
        if self.connector_filter and self.connector_filter not in event_connector(event).lower():
            return False
        return True


def export_audit_intent(path: Path | None = None) -> AuditActionIntent:
    """Return the data-only intent matching the Go panel export action."""

    return AuditActionIntent(
        kind="export",
        label="export audit",
        path=path or Path("defenseclaw-audit-export.json"),
    )


def audit_action_display(action: str) -> tuple[str, str]:
    """Return the Go Audit action label and theme-style key."""

    lower = action.lower()
    if "block" in lower:
        return "BLOCK", "blocked"
    if "allow" in lower:
        return "ALLOW", "allowed"
    if "scan" in lower:
        return "SCAN", "low"
    if "quarantine" in lower:
        return "QUARANTINE", "quarantined"
    if "config" in lower or "init" in lower:
        return "CONFIG", "medium"
    if "dismiss" in lower:
        return "DISMISS", "dimmed"
    return action.upper(), "info"


def audit_severity_style_key(severity: str) -> str:
    """Return the Go severity style bucket for a severity value."""

    normalized = severity.upper()
    if normalized in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return normalized.lower()
    return "info"


def _list_findings_by_run_id(store: object | None, run_id: str) -> tuple[AuditFinding, ...]:
    if store is None or not run_id:
        return ()
    db = getattr(store, "db", None)
    if db is None:
        return ()
    rows = db.execute(
        """SELECT id, scan_id, severity, title, description, location, remediation, scanner
           FROM findings WHERE scan_id = ? ORDER BY severity DESC""",
        (run_id,),
    ).fetchall()
    return tuple(
        AuditFinding(
            id=row[0],
            scan_id=row[1],
            severity=row[2],
            title=row[3],
            description=row[4] or "",
            location=row[5] or "",
            remediation=row[6] or "",
            scanner=row[7],
        )
        for row in rows
    )


def _list_events_by_target(store: object | None, target: str, limit: int) -> tuple[Event, ...]:
    if store is None or not target:
        return ()
    if hasattr(store, "list_events_by_target"):
        return tuple(store.list_events_by_target(target, limit))  # type: ignore[attr-defined]
    db = getattr(store, "db", None)
    if db is None:
        return ()
    rows = db.execute(
        """SELECT id, timestamp, action, target, actor, details, severity, run_id
           FROM audit_events WHERE target = ? ORDER BY timestamp DESC LIMIT ?""",
        (target, max(limit, 1)),
    ).fetchall()
    return tuple(_event_from_row(row) for row in rows)


def _get_event_by_id(store: object | None, event_id: str) -> Event | None:
    if store is None or not event_id or not hasattr(store, "get_event"):
        return None
    try:
        event = store.get_event(event_id)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - detail hydration is best-effort.
        return None
    return event if isinstance(event, Event) else None


def _list_events_by_run_id(store: object | None, run_id: str, limit: int) -> tuple[Event, ...]:
    if store is None or not run_id:
        return ()
    db = getattr(store, "db", None)
    if db is None:
        return ()
    rows = db.execute(
        """SELECT id, timestamp, action, target, actor, details, severity, run_id
           FROM audit_events WHERE run_id = ? ORDER BY timestamp DESC LIMIT ?""",
        (run_id, max(limit, 1)),
    ).fetchall()
    return tuple(_event_from_row(row) for row in rows)


def _list_related_events(store: object | None, event: Event, limit: int) -> tuple[Event, ...]:
    related: list[Event] = []
    seen: set[str] = set()
    candidates = (
        *_list_events_by_run_id(store, event.run_id, limit),
        *_list_events_by_target(store, event.target, limit),
    )
    for candidate in candidates:
        key = candidate.id or f"{candidate.timestamp.isoformat()}:{candidate.action}:{candidate.target}"
        if key in seen:
            continue
        related.append(candidate)
        seen.add(key)
        if len(related) >= limit:
            break
    return tuple(related)


def _get_current_action(store: object | None, event: Event) -> ActionEntry | None:
    if store is None or not hasattr(store, "get_action"):
        return None
    target_type = _target_type_from_action(event.action)
    if not target_type:
        return None
    try:
        return store.get_action(target_type, event.target)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - detail enrichment should not break the row.
        return None


def _target_type_from_action(action: str) -> str:
    lower = action.lower()
    if "skill" in lower:
        return "skill"
    if "mcp" in lower:
        return "mcp"
    if "plugin" in lower:
        return "plugin"
    if "tool" in lower:
        return "tool"
    if "scan" in lower or "finding" in lower:
        return "scan"
    if "credential" in lower or "key" in lower or "token" in lower or "secret" in lower:
        return "credential"
    if "alert" in lower:
        return "alert"
    if "config" in lower or "setup" in lower or "init" in lower:
        return "config"
    return ""


def _matches_common_filter(event: Event, preset: AuditCommonFilter) -> bool:
    action = event.action.lower()
    severity = event.severity.upper()
    haystack = _event_haystack(event)
    if preset == "risk":
        return severity in {"CRITICAL", "HIGH", "ERROR"} or any(
            token in action or token in haystack
            for token in ("block", "deny", "quarantine", "fail", "error", "panic", "timeout")
        )
    if preset == "blocks":
        return any(token in action for token in ("block", "deny", "quarantine", "reject"))
    if preset == "scans":
        return any(token in action for token in ("scan", "finding", "analyze"))
    if preset == "credentials":
        return any(token in haystack for token in ("credential", "api key", "apikey", "token", "secret", "key"))
    return True


def _is_low_signal_event(event: Event) -> bool:
    severity = event.severity.strip().upper()
    if severity in AUDIT_ACTIONABLE_SEVERITIES:
        return False
    if severity not in AUDIT_LOW_SIGNAL_SEVERITIES:
        return False
    haystack = _event_haystack(event)
    return not any(token in haystack for token in AUDIT_ACTIONABLE_TOKENS)


def _matches_search_query(event: Event, query: str) -> bool:
    terms = tuple(term for term in query.lower().split() if term)
    if not terms:
        return True
    for term in terms:
        field, separator, value = term.partition(":")
        if separator and field in {"action", "actor", "connector", "details", "id", "run", "run_id", "severity", "target", "type"}:
            if value not in _event_field(event, field):
                return False
            continue
        if term not in _event_haystack(event):
            return False
    return True


def _event_field(event: Event, field: str) -> str:
    if field == "id":
        return event.id.lower()
    if field == "run" or field == "run_id":
        return event.run_id.lower()
    if field == "action":
        return event.action.lower()
    if field == "actor":
        return event.actor.lower()
    if field == "connector":
        return _parse_kv_details(event.details).get("connector", "").lower()
    if field == "details":
        return event.details.lower()
    if field == "severity":
        return event.severity.lower()
    if field == "target":
        return event.target.lower()
    if field == "type":
        return _target_type_from_action(event.action).lower()
    return ""


def _event_haystack(event: Event) -> str:
    return " ".join(
        (
            event.id,
            event.action,
            event.target,
            event.actor,
            event.severity,
            event.details,
            event.run_id,
            _target_type_from_action(event.action),
        )
    ).lower()


def _event_from_row(row: tuple[Any, ...]) -> Event:
    return Event(
        id=row[0],
        timestamp=_parse_db_timestamp(row[1]),
        action=row[2],
        target=row[3] or "",
        actor=row[4],
        details=row[5] or "",
        severity=row[6] or "",
        run_id=row[7] or "",
    )


def _parse_db_timestamp(raw: object) -> datetime:
    if isinstance(raw, datetime):
        return raw
    parsed = parse_timestamp(raw)
    if parsed is not None:
        return parsed
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    if limit <= 3:
        return "." * limit
    return value[: limit - 3] + "..."


# Map raw kv keys onto human-friendly labels for the detail pane. Keys
# that aren't in this map fall back to the raw key (Title-Cased), so we
# only need to register the ones whose raw form is opaque.
_DETAIL_KEY_LABELS: dict[str, str] = {
    "connector": "Connector",
    "action": "Decision",
    "raw_action": "Decision (raw)",
    "severity": "Severity (decision)",
    "mode": "Enforcement mode",
    "would_block": "Would block",
    "elapsed": "Elapsed",
    "duration_ms": "Elapsed (ms)",
    "tool": "Tool",
    "raw_args": "Tool args",
    "raw_payload": "Raw payload",
    "raw_content": "Raw content",
    "request_id": "Request ID",
    "reason": "Reason",
    "result": "Result",
    "bytes": "Bytes",
    "source": "Source",
    "event": "Hook event",
    "hook": "Hook event",
    "decision": "Decision",
    "registry_status": "Registry status",
    "registry_configured": "Registry configured",
    "skill_name_raw": "Skill name (raw)",
    "source_path": "Source path",
    "surface": "Surface",
}

# Order in which we surface known kv pairs. Anything not listed here is
# appended afterwards in the order it appeared in the raw details.
_DETAIL_KEY_ORDER: tuple[str, ...] = (
    "connector",
    "tool",
    "action",
    "raw_action",
    "severity",
    "mode",
    "decision",
    "reason",
    "would_block",
    "elapsed",
    "duration_ms",
    "result",
    "bytes",
    "source",
    "raw_args",
    "raw_content",
    "raw_payload",
    "request_id",
)


def _parse_kv_details(value: str) -> dict[str, str]:
    """Parse ``key=value key=value`` strings into a dict.

    The gateway emits audit detail strings as space-separated ``key=value``
    pairs, with quoted values when content might contain spaces (e.g.
    ``raw_args="ls -la"``). Values can also contain angle-bracketed
    placeholders like ``<redacted len=8 sha=84ed0c96>`` — we keep those
    intact and let the renderer prettify them.

    Returns an empty dict if no pairs are found, which is the signal that
    the legacy single ``Details`` row should be used instead.
    """

    pairs: dict[str, str] = {}
    if not value:
        return pairs
    text = value.strip()
    i = 0
    n = len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        key_start = i
        while i < n and text[i] != "=" and not text[i].isspace():
            i += 1
        if i >= n or text[i] != "=":
            break
        key = text[key_start:i]
        i += 1
        if i < n and text[i] == '"':
            i += 1
            val_start = i
            while i < n and text[i] != '"':
                if text[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                i += 1
            val = text[val_start:i]
            if i < n:
                i += 1
        elif i < n and text[i] == "<":
            depth = 0
            val_start = i
            while i < n:
                if text[i] == "<":
                    depth += 1
                elif text[i] == ">":
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                i += 1
            val = text[val_start:i]
        else:
            val_start = i
            while i < n and not text[i].isspace():
                i += 1
            val = text[val_start:i]
        if key:
            pairs[key] = val
    return pairs


def _prettify_kv_value(key: str, value: str) -> str:
    """Make raw kv values readable in the detail pane.

    The big offender is ``raw_payload=<redacted len=8 sha=84ed0c96>`` —
    operators have no idea what that means. Translate it into ``8 bytes
    (sha:84ed0c96)`` so they can at least cross-reference the digest
    when correlating with the gateway log. ``would_block=true|false``
    becomes ``yes|no``.
    """

    if value.startswith("<") and value.endswith(">"):
        inner = value[1:-1].strip()
        if inner.startswith("redacted"):
            attrs = _parse_kv_details(inner[len("redacted") :])
            length = attrs.get("len")
            digest = attrs.get("sha")
            parts: list[str] = []
            if length:
                parts.append(f"{length} bytes")
            if digest:
                parts.append(f"sha:{digest}")
            if parts:
                return "redacted · " + " · ".join(parts)
            return value
        return inner
    if key in {"would_block", "registry_configured"}:
        if value == "true":
            return "yes"
        if value == "false":
            return "no"
    return value


def _structured_detail_rows(details: str) -> tuple[tuple[str, str], ...]:
    """Project a kv-style ``details`` string into ordered detail rows.

    Returns an empty tuple when the string doesn't look kv-shaped so the
    caller falls back to the legacy single ``Details`` row.
    """

    parsed = _parse_kv_details(details)
    if not parsed:
        return ()
    is_observe = parsed.get("mode", "") == "observe"
    rows: list[tuple[str, str]] = []
    for key in _DETAIL_KEY_ORDER:
        if key not in parsed:
            continue
        value = parsed[key]
        # Drop fields that are pure noise for hook connectors. ``severity
        # =NONE`` and ``would_block=false`` while in observe mode are the
        # default for every passing hook call — surfacing them just
        # buries the actually interesting fields.
        if key == "severity" and value.upper() == "NONE":
            continue
        if key == "would_block" and value == "false" and is_observe:
            continue
        label = _DETAIL_KEY_LABELS.get(key, key.replace("_", " ").title())
        rows.append((label, _prettify_kv_value(key, value)))
    seen = set(_DETAIL_KEY_ORDER)
    for key, value in parsed.items():
        if key in seen:
            continue
        label = _DETAIL_KEY_LABELS.get(key, key.replace("_", " ").title())
        rows.append((label, _prettify_kv_value(key, value)))
    return tuple(rows)


def _row_target_label(event: Event) -> str:
    """Return the table's TARGET cell value, hook-aware.

    For ``connector-hook`` events we surface ``<connector> · <hook>``
    (e.g. ``claudecode · preToolUse``) — without that, the column is
    just a wall of identical ``preToolUse``/``postToolUse`` strings and
    you can't tell which framework emitted the event without opening
    the detail pane.
    """

    if event.action == "connector-hook":
        connector = _parse_kv_details(event.details).get("connector", "")
        hook_phase = event.target or ""
        if connector and hook_phase:
            return _truncate(f"{connector} · {hook_phase}", 32)
        if connector:
            return _truncate(connector, 32)
    return _truncate(event.target, 32)


def _row_details_label(event: Event) -> str:
    """Return the table's DETAILS cell value with hook-aware summary.

    Truncating ``connector=claudecode action=allow severity=NONE
    mode=observe …`` to 20 chars yields ``connector=claudecod`` —
    useless. Pull out the high-signal pieces (decision, severity if
    elevated, elapsed) into a compact ``allow · 320ms`` string instead.
    Falls back to the legacy truncated raw string for non-hook events.
    """

    if event.action != "connector-hook":
        return _truncate(event.details, 20)
    parsed = _parse_kv_details(event.details)
    decision = parsed.get("action", "") or parsed.get("decision", "")
    severity = parsed.get("severity", "")
    elapsed = parsed.get("elapsed", "") or parsed.get("duration_ms", "")
    parts: list[str] = []
    if decision:
        parts.append(decision)
    if severity and severity.upper() != "NONE":
        parts.append(severity.upper())
    if elapsed:
        parts.append(elapsed)
    if not parts:
        return _truncate(event.details, 20)
    return _truncate(" · ".join(parts), 20)


# Public aliases — re-exported so the Alerts panel (which surfaces
# audit events too) can reuse the connector-hook formatting without
# duplicating the parser. We deliberately keep the underscored names
# intact so the audit panel's call sites stay unchanged.
def split_connector_token(query: str) -> tuple[str, str]:
    """Split a ``connector:<name>`` token out of a (lowercased) query.

    E5: the Audit panel recognizes a structured ``connector:`` search
    token (see ``_matches_search_query``). This helper exposes the same
    extraction so the Alerts and Logs panels can offer identical syntax.
    Returns ``(connector_value, remaining_query)`` where the remainder is
    the free-text portion to be matched however the caller normally does.
    """

    connector = ""
    rest: list[str] = []
    for tok in query.split():
        field, sep, value = tok.partition(":")
        if sep and field == "connector":
            connector = value
        else:
            rest.append(tok)
    return connector, " ".join(rest)


def event_connector(event: Event) -> str:
    """Best-effort connector attribution for an audit event.

    The gateway tags every emitted event with ``connector=<name>`` in the
    detail blob, so that is the primary source. Returns "" when no connector
    is recorded (e.g. synthetic scan/egress alerts that predate attribution),
    which the CONNECTOR column renders as ``—``.
    """

    return _parse_kv_details(event.details).get("connector", "").strip()


parse_kv_details = _parse_kv_details
prettify_kv_value = _prettify_kv_value
structured_detail_rows = _structured_detail_rows


def _slug(value: str) -> str:
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in value).strip("-")
    return slug or "row"


def _detail_style_key(label: str, value: str) -> str:
    if label == "Severity":
        return audit_severity_style_key(value)
    if label.startswith("Finding"):
        return "finding"
    if label.startswith("Related"):
        return "related"
    if label == "Current State":
        return "state"
    return ""
