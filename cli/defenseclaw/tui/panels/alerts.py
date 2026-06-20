# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Alerts panel model and helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from rich.markup import escape as rich_escape

from defenseclaw.tui.panels.audit import (
    parse_kv_details,
    split_connector_token,
    structured_detail_rows,
)
from defenseclaw.tui.services.gateway_events import (
    EgressEvent,
    ScanBlock,
    load_gateway_egress,
    load_gateway_scan_blocks,
    parse_timestamp,
)

SeverityFilter = Literal["", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
AlertRowKind = Literal["audit", "scan", "scan_finding", "egress"]

SEVERITY_FILTERS: tuple[SeverityFilter, ...] = ("", "CRITICAL", "HIGH", "MEDIUM", "LOW")


@dataclass(frozen=True)
class AlertEvent:
    """Normalized alert row."""

    id: str
    severity: str
    action: str
    target: str
    details: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str = ""
    run_id: str = ""
    trace_id: str = ""
    request_id: str = ""
    session_id: str = ""


@dataclass(frozen=True)
class AlertRow:
    """One row in the flattened alerts list."""

    kind: AlertRowKind
    event: AlertEvent
    scan_id: str = ""
    finding_index: int = -1


@dataclass(frozen=True)
class AlertCommandIntent:
    """A mutation command the app shell can preview and dispatch."""

    label: str
    args: tuple[str, ...]
    hint: str = ""
    binary: str = "defenseclaw"
    category: str = "alerts"

    @property
    def argv(self) -> tuple[str, ...]:
        return (self.binary, *self.args)


@dataclass(frozen=True)
class AlertPanelAction:
    """Result of a panel-local key/action handler."""

    handled: bool
    intent: AlertCommandIntent | None = None
    hint: str = ""
    copy_text: str = ""
    filter_change: AlertFilterChange | None = None


@dataclass(frozen=True)
class AlertFilterChange:
    """Model-level filter telemetry payload for Alerts severity chips."""

    panel: str
    filter_type: str
    old: str
    new: str


@dataclass(frozen=True)
class AlertFinding:
    """Finding row attached to an alert detail by run id."""

    id: str
    scan_id: str
    severity: str
    title: str
    description: str = ""
    location: str = ""
    remediation: str = ""
    scanner: str = ""


@dataclass(frozen=True)
class GatewayFindingDetail:
    """Gateway scan finding detail attached to a synthetic row."""

    finding: dict[str, Any]
    scan: ScanBlock


@dataclass(frozen=True)
class AlertDetailInfo:
    """Expanded detail data for the selected alert row."""

    event: AlertEvent
    findings: tuple[AlertFinding, ...] = ()
    history: tuple[AlertEvent, ...] = ()
    gateway_finding: GatewayFindingDetail | None = None


@dataclass(frozen=True)
class AlertTableRow:
    """Mouse-selectable DataTable row metadata for the Textual shell."""

    key: str
    cursor_index: int
    kind: AlertRowKind
    alert_id: str
    cells: tuple[str, ...]
    selected: bool
    selectable: bool
    opens_detail: bool
    expands: bool
    scan_id: str = ""
    finding_index: int = -1


def humanize_alert_details(raw: str) -> str:
    """Port of the Go TUI/CLI alert detail humanizer."""

    if not raw:
        return ""
    tokens = raw.split()
    if not any("=" in token for token in tokens):
        return raw

    ordered: list[tuple[str, str]] = []
    plain: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        if "=" not in token:
            plain.append(token)
            continue
        key, value = token.split("=", 1)
        if key not in seen:
            ordered.append((key, value))
            seen.add(key)

    def take(key: str) -> str | None:
        for index, pair in enumerate(ordered):
            if pair[0] == key:
                ordered.pop(index)
                seen.discard(key)
                return pair[1]
        return None

    parts: list[str] = []
    host = take("host")
    port = take("port")
    if host and port:
        parts.append(f"{host}:{port}")
    elif port:
        parts.append(f":{port}")
    elif host:
        parts.append(host)

    for key in ("mode", "environment", "status", "protocol", "scanner_mode"):
        if value := take(key):
            parts.append(value)

    model = take("model")
    if model:
        slash = model.rfind("/")
        if slash >= 0 and slash < len(model) - 1:
            model = model[slash + 1 :]
        parts.append(model)

    for key in ("max_severity", "scanner", "findings"):
        take(key)

    parts.extend(f"{key}={value}" for key, value in ordered)
    parts.extend(plain)
    return " ".join(parts)


class AlertsPanelModel:
    """Pure alerts panel state with Go-compatible filtering and selection."""

    def __init__(self, data_dir: Path | None = None, *, store: object | None = None) -> None:
        self.data_dir = data_dir
        self.store = store
        self.audit_events: list[AlertEvent] = []
        self.scan_blocks: list[ScanBlock] = []
        self.egress_events: list[EgressEvent] = []
        self.expanded: set[str] = set()
        self.filter_text = ""
        self.filtering = False
        self.severity_filter: SeverityFilter = ""
        self.selected_ids: set[str] = set()
        self.detail_open = False
        self.cursor = 0
        self.filtered: list[AlertRow] = []
        # 8.13 multi-connector: shared connector filter ("" = All) and the
        # CONNECTOR column flag. Set by the app from the active connector
        # count; single-connector installs keep defaults (no filter/column).
        self.connector_filter = ""
        self.show_connector_column = False

    def set_data_dir(self, data_dir: Path | str | None) -> None:
        """Late-bind the gateway.jsonl source after a config reload."""

        self.data_dir = Path(data_dir) if data_dir else None

    def set_store(self, store: object | None) -> None:
        """Late-bind the audit DB so a setup-driven reopen takes effect.

        Mirrors Go's ``m.alerts.SetStore(m.store)`` inside
        ``reloadConfigAfterSetupCommand``. Without this the panel keeps
        querying the old SQLite handle even after setup rewrites the
        audit_db path.
        """

        self.store = store

    def set_events(self, events: list[AlertEvent]) -> None:
        self.audit_events = events
        self.apply_filter()
        self.selected_ids.intersection_update(event.id for event in events)

    def refresh_gateway_scans(self) -> None:
        if self.data_dir is None:
            return
        gateway_path = self.data_dir / "gateway.jsonl"
        self.scan_blocks = list(load_gateway_scan_blocks(gateway_path))
        self.egress_events = list(load_gateway_egress(gateway_path))
        self.apply_filter()

    def refresh(self) -> None:
        """Refresh external data sources owned by the model."""

        if self.store is not None and hasattr(self.store, "list_alerts"):
            reader = (
                self.store.list_alert_summaries
                if hasattr(self.store, "list_alert_summaries")
                else self.store.list_alerts
            )
            self.audit_events = [
                _coerce_alert_event(event)
                for event in reader(500)  # type: ignore[misc]
            ]
        if self.data_dir is None:
            self.apply_filter()
        else:
            self.refresh_gateway_scans()

    def flat_rows(self) -> list[AlertRow]:
        groups: list[tuple[datetime, list[AlertRow]]] = [
            (event.timestamp, [AlertRow("audit", event)]) for event in self.audit_events
        ]
        for block in self.scan_blocks:
            parent = AlertRow("scan", synthetic_scan_event(block), scan_id=block.scan_id)
            rows = [parent]
            if block.scan_id in self.expanded:
                rows.extend(
                    AlertRow(
                        "scan_finding",
                        synthetic_finding_event(block, index),
                        scan_id=block.scan_id,
                        finding_index=index,
                    )
                    for index in range(len(block.findings))
                )
            groups.append((parent.event.timestamp, rows))
        for egress in self.egress_events:
            event = synthetic_egress_event(egress)
            groups.append((event.timestamp, [AlertRow("egress", event)]))
        groups.sort(key=lambda group: group[0], reverse=True)
        return [row for _timestamp, rows in groups for row in rows]

    def apply_filter(self) -> None:
        query = self.filter_text.lower()
        # E5: support the same ``connector:<name>`` token the Audit panel
        # uses, so operators filter alerts by connector with one syntax
        # across panels. The token is pulled out and matched against the
        # event's kv connector; the remainder keeps the legacy substring
        # search so existing free-text queries behave unchanged.
        connector_value, remaining = split_connector_token(query)
        filtered: list[AlertRow] = []
        for row in self.flat_rows():
            event = row.event
            if self.severity_filter and _severity_bucket(event.severity) != self.severity_filter:
                continue
            ev_connector = parse_kv_details(event.details).get("connector", "").lower()
            # 8.13: the shared connector filter (from the chip) is ANDed with
            # the typed ``connector:`` token so both narrow the same way.
            if self.connector_filter and self.connector_filter not in ev_connector:
                continue
            if connector_value and connector_value not in ev_connector:
                continue
            if remaining:
                haystack = f"{event.severity} {event.action} {event.target} {event.details}".lower()
                if remaining not in haystack:
                    continue
            filtered.append(row)
        self.filtered = filtered
        self.cursor = min(self.cursor, max(len(self.filtered) - 1, 0))

    def set_connector_filter(self, connector: str) -> None:
        """Set the shared connector filter ("" = All) and re-apply filters."""

        connector = (connector or "").strip().lower()
        if connector == self.connector_filter:
            return
        self.connector_filter = connector
        self.apply_filter()

    def set_filter(self, text: str) -> None:
        self.filter_text = text
        self.apply_filter()

    def clear_filter(self) -> None:
        self.filter_text = ""
        self.filtering = False
        self.apply_filter()

    def set_severity_filter_exact(self, severity: SeverityFilter) -> None:
        self.severity_filter = severity
        self.apply_filter()

    def set_severity_filter(self, severity: SeverityFilter) -> None:
        self.severity_filter = "" if self.severity_filter == severity else severity
        self.apply_filter()

    def active_filter_label(self) -> str:
        parts: list[str] = []
        if self.severity_filter:
            parts.append(self.severity_filter.title())
        if self.filter_text:
            parts.append(f"search '{self.filter_text}'")
        return ", ".join(parts)

    def selected(self) -> AlertRow | None:
        if 0 <= self.cursor < len(self.filtered):
            return self.filtered[self.cursor]
        return None

    def set_cursor(self, index: int) -> None:
        self.cursor = max(0, min(index, max(len(self.filtered) - 1, 0)))

    def toggle_expand_or_detail(self) -> None:
        row = self.selected()
        if row is None:
            return
        if row.kind == "scan":
            if row.scan_id in self.expanded:
                self.expanded.remove(row.scan_id)
            else:
                self.expanded.add(row.scan_id)
            self.apply_filter()
            return
        self.detail_open = not self.detail_open

    def toggle_select(self) -> None:
        row = self.selected()
        if row is None or row.event.id.startswith("gw:"):
            return
        if row.event.id in self.selected_ids:
            self.selected_ids.remove(row.event.id)
        else:
            self.selected_ids.add(row.event.id)

    def select_all(self) -> None:
        for row in self.filtered:
            if not row.event.id.startswith("gw:"):
                self.selected_ids.add(row.event.id)

    def deselect_all(self) -> None:
        self.selected_ids.clear()

    def filtered_ids(self) -> list[str]:
        return [row.event.id for row in self.filtered if not row.event.id.startswith("gw:")]

    def severity_counts(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for row in self.flat_rows():
            if row.kind == "scan_finding":
                continue
            bucket = _severity_bucket(row.event.severity)
            if bucket in counts:
                counts[bucket] += 1
        return counts

    def critical_count(self) -> int:
        counts = self.severity_counts()
        return counts["CRITICAL"] + counts["HIGH"]

    def handle_key(self, key: str) -> AlertPanelAction:
        if self.filtering:
            return self._handle_filter_key(key)
        if key in {"j", "down"}:
            self.set_cursor(self.cursor + 1)
            return AlertPanelAction(True)
        if key in {"k", "up"}:
            self.set_cursor(self.cursor - 1)
            return AlertPanelAction(True)
        if key == "enter":
            self.toggle_expand_or_detail()
            return AlertPanelAction(True)
        if key == "escape":
            if self.detail_open:
                self.detail_open = False
                return AlertPanelAction(True, hint="Closed alert detail.")
            if self.filter_text or self.filtering:
                self.clear_filter()
                return AlertPanelAction(True, hint="Filter cleared.")
            return AlertPanelAction(False)
        if key == "space":
            self.toggle_select()
            self.set_cursor(self.cursor + 1)
            return AlertPanelAction(True)
        if key == "a":
            self.select_all()
            return AlertPanelAction(True, hint=f"Selected {len(self.selected_ids)} alert(s).")
        if key in {"A", "X"}:
            self.deselect_all()
            return AlertPanelAction(True, hint="Selection cleared.")
        if key == "r":
            self.refresh()
            return AlertPanelAction(True, hint="Alerts refreshed.")
        if key == "/":
            self.filtering = True
            self.filter_text = ""
            self.apply_filter()
            return AlertPanelAction(True, hint="Type to search alerts. Enter applies; Esc clears.")
        if key == "1":
            old = self.severity_filter
            self.set_severity_filter("")
            return AlertPanelAction(True, filter_change=_alert_filter_change(old, self.severity_filter))
        if key == "2":
            old = self.severity_filter
            self.set_severity_filter("CRITICAL")
            return AlertPanelAction(True, filter_change=_alert_filter_change(old, self.severity_filter))
        if key == "3":
            old = self.severity_filter
            self.set_severity_filter("HIGH")
            return AlertPanelAction(True, filter_change=_alert_filter_change(old, self.severity_filter))
        if key == "4":
            old = self.severity_filter
            self.set_severity_filter("MEDIUM")
            return AlertPanelAction(True, filter_change=_alert_filter_change(old, self.severity_filter))
        if key == "5":
            old = self.severity_filter
            self.set_severity_filter("LOW")
            return AlertPanelAction(True, filter_change=_alert_filter_change(old, self.severity_filter))
        if key == "y":
            copied = self.copy_detail_text()
            if not copied:
                return AlertPanelAction(True, hint="No alert detail to copy.")
            return AlertPanelAction(True, hint="Alert detail copied.", copy_text=copied)
        if key == "d":
            row = self.selected()
            if row is None or row.event.id.startswith("gw:"):
                return AlertPanelAction(True, hint="No audit alert selected to dismiss.")
            severity = row.event.severity or self.severity_filter or "all"
            return AlertPanelAction(
                True,
                AlertCommandIntent(
                    label="alerts dismiss selected",
                    args=("alerts", "dismiss", "--severity", severity),
                    hint=f"Dismissing selected alert {row.event.id}.",
                ),
            )
        if key == "x":
            if not self.selected_ids:
                return AlertPanelAction(True, hint="Select alerts before acknowledging them.")
            return AlertPanelAction(
                True,
                AlertCommandIntent(
                    label=f"alerts acknowledge {len(self.selected_ids)} selected",
                    args=("alerts", "acknowledge", "--severity", self.severity_filter or "all"),
                    hint=f"Acknowledging {len(self.selected_ids)} selected alert(s).",
                ),
            )
        if key == "c":
            if not self.filtered_ids():
                return AlertPanelAction(True, hint="No filtered alerts to clear.")
            return AlertPanelAction(
                True,
                AlertCommandIntent(
                    label="alerts dismiss filtered",
                    args=("alerts", "dismiss", "--severity", self.severity_filter or "all"),
                    hint=f"Clearing {len(self.filtered_ids())} filtered alert(s).",
                ),
            )
        if key == "C":
            return AlertPanelAction(
                True,
                AlertCommandIntent(
                    label="alerts dismiss all",
                    args=("alerts", "dismiss", "--severity", "all"),
                    hint="Clearing all active alerts.",
                ),
            )
        return AlertPanelAction(False)

    def _handle_filter_key(self, key: str) -> AlertPanelAction:
        if key == "enter":
            self.filtering = False
            return AlertPanelAction(True, hint=self.active_filter_label() or "Search applied.")
        if key in {"esc", "escape"}:
            self.clear_filter()
            return AlertPanelAction(True, hint="Alert search cleared.")
        if key == "backspace":
            self.set_filter(self.filter_text[:-1])
            return AlertPanelAction(True)
        if len(key) == 1:
            self.set_filter(self.filter_text + key)
            return AlertPanelAction(True)
        return AlertPanelAction(False)

    def summary_text(self) -> str:
        counts = self.severity_counts()
        active = self.severity_filter or "All"
        selected = len(self.selected_ids)
        filter_label = f"  search={self.filter_text!r}" if self.filter_text else ""
        # ``filter_text`` is operator-typed search input that may
        # contain bracketed tokens (``target:[skill]``). Escape so the
        # markup parser can't drop the bracketed substring or, worse,
        # leave the span unclosed when the user types a stray ``[``.
        search_prompt = (
            f"\n[#22D3EE]/ {rich_escape(self.filter_text)}[/]"
            if self.filtering
            else ""
        )
        return (
            "[bold #22D3EE]Alerts[/]  [#9FB2CC]Alert queue. Click a severity chip above or press 1-5.[/]\n"
            f"[bold]All {sum(counts.values())}[/]  "
            f"[#F87171]Critical {counts['CRITICAL']}[/]  [#FB923C]High {counts['HIGH']}[/]  "
            f"[#FBBF24]Medium {counts['MEDIUM']}[/]  [#60A5FA]Low {counts['LOW']}[/]  "
            f"active={active}  selected={selected}"
            f"{filter_label}{search_prompt}\n"
            "Next: Enter opens detail, Space selects a row, Ack selected marks chosen alerts, "
            "Dismiss filtered clears the active view, / searches target/action/details."
        )

    def data_table_columns(self) -> tuple[str, ...]:
        if self.show_connector_column:
            return ("Sel", "Severity", "Time", "Action", "Connector", "Target", "Details")
        return ("Sel", "Severity", "Time", "Action", "Target", "Details")

    def data_table_rows(self) -> tuple[tuple[str, ...], ...]:
        return tuple(row.cells for row in self.data_table_row_models())

    def data_table_row_models(self) -> tuple[AlertTableRow, ...]:
        """Return alert rows with stable keys and click-selection metadata."""

        rows: list[AlertTableRow] = []
        for index, row in enumerate(self.filtered):
            event = row.event
            marker = "*" if event.id in self.selected_ids else ""
            if row.kind == "scan":
                marker = "+" if row.scan_id not in self.expanded else "-"
            if row.kind == "scan_finding":
                marker = ">"
            target_cell = _alert_target_label(event)
            details_cell = _alert_details_label(event)
            if self.show_connector_column:
                connector_cell = parse_kv_details(event.details).get("connector", "").strip() or "—"
                cells = (
                    marker,
                    event.severity,
                    event.timestamp.strftime("%b %d %H:%M"),
                    event.action,
                    connector_cell,
                    target_cell,
                    details_cell,
                )
            else:
                cells = (
                    marker,
                    event.severity,
                    event.timestamp.strftime("%b %d %H:%M"),
                    event.action,
                    target_cell,
                    details_cell,
                )
            rows.append(
                AlertTableRow(
                    key=_alert_row_key(row),
                    cursor_index=index,
                    kind=row.kind,
                    alert_id=event.id,
                    cells=cells,
                    selected=index == self.cursor,
                    selectable=not event.id.startswith("gw:"),
                    opens_detail=row.kind != "scan",
                    expands=row.kind == "scan",
                    scan_id=row.scan_id,
                    finding_index=row.finding_index,
                )
            )
        return tuple(rows)

    def empty_state(self) -> str:
        if self.filtered:
            return ""
        if self.filter_text or self.severity_filter:
            return "No alerts match the current filters."
        return "No active alerts."

    def detail_text(self) -> str:
        if not self.detail_open:
            return ""
        info = self.get_detail_info()
        if info is None:
            return ""
        event = info.event
        # Connector-hook rows are nearly identical without enrichment
        # (every row says ``INFO connector-hook`` with the same
        # ``preToolUse``/``postToolUse`` target), so we promote the
        # connector + hook phase into the title and split the kv
        # ``details`` blob into discrete labelled lines. Other alert
        # kinds keep the legacy two-line Summary/Details rendering.
        if _is_hook_event(event):
            lines = _hook_detail_lines(event)
        else:
            lines = [
                f"[bold #22D3EE]{event.severity} {event.action}[/]",
                f"Target: {event.target}",
                f"Time: {event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            ]
            if event.details:
                human = humanize_alert_details(event.details)
                if human and human != event.details:
                    lines.append(f"Summary: {human}")
                lines.append(f"Details: {event.details}")
        if event.run_id:
            lines.append(f"RunID: {event.run_id}")
        if event.trace_id:
            lines.append(f"TraceID: {event.trace_id}")
        if event.request_id:
            lines.append(f"ReqID: {event.request_id}")
        if event.session_id:
            lines.append(f"SessionID: {event.session_id}")
        if info.gateway_finding is not None:
            lines.extend(_gateway_finding_lines(info.gateway_finding))
        for finding in info.findings:
            value = f"{finding.severity} {finding.title}".strip()
            if finding.scanner:
                # Escape ``[{scanner}]``: scanner names are lowercase
                # identifiers (``trivy``, ``semgrep``, …) that Rich
                # would parse as style tags, dropping the badge from
                # the detail line.
                value += f" \\[{finding.scanner}]"
            if finding.location:
                value += f" @ {finding.location}"
            lines.append(f"Finding: {value}")
            if finding.remediation:
                lines.append(f"Remediation: {finding.remediation}")
        history = tuple(item for item in info.history if item.id != event.id)
        for item in history[:5]:
            lines.append(f"History: {item.timestamp.strftime('%b %d %H:%M')} {item.action} {item.severity}")
        lines.append("[Enter] close detail  [Esc] close")
        return "\n".join(lines)

    def get_detail_info(self) -> AlertDetailInfo | None:
        """Return the selected row's enriched detail payload."""

        row = self.selected()
        if row is None:
            return None
        event = row.event
        if row.kind == "scan_finding":
            block = self._scan_block(row.scan_id)
            if block is not None and 0 <= row.finding_index < len(block.findings):
                return AlertDetailInfo(
                    event=event,
                    gateway_finding=GatewayFindingDetail(
                        finding=dict(block.findings[row.finding_index]),
                        scan=block,
                    ),
                )
        event = _get_alert_event_by_id(self.store, event.id) or event
        return AlertDetailInfo(
            event=event,
            findings=_list_findings_by_run_id(self.store, event.run_id),
            history=_list_events_by_target(self.store, event.target, 10),
        )

    def detail_pairs(self) -> tuple[tuple[str, str], ...]:
        """Return ordered detail rows for shared detail rendering.

        Connector-hook events expand the kv-shaped ``details`` blob
        into discrete labelled rows (Connector, Decision, Enforcement
        mode, Elapsed, …) the same way the Audit panel does. Other
        kinds (scan, egress, generic audit) keep the legacy
        ``Summary``/``Details`` rows so existing callers and tests
        depending on those labels still work.
        """

        info = self.get_detail_info()
        if info is None:
            return ()
        event = info.event
        pairs: list[tuple[str, str]] = [
            ("Severity", event.severity),
            ("Action", event.action),
            ("Target", event.target),
            ("Timestamp", event.timestamp.isoformat()),
        ]
        if _is_hook_event(event):
            structured = structured_detail_rows(event.details)
            if structured:
                pairs.extend(structured)
            elif event.details:
                pairs.append(("Details", event.details))
        else:
            human = humanize_alert_details(event.details)
            if human and human != event.details:
                pairs.append(("Summary", human))
            if event.details:
                pairs.append(("Details", event.details))
        for label, value in (
            ("Run ID", event.run_id),
            ("Trace ID", event.trace_id),
            ("Request ID", event.request_id),
            ("Session ID", event.session_id),
        ):
            if value:
                pairs.append((label, value))
        if info.gateway_finding is not None:
            for line in _gateway_finding_lines(info.gateway_finding):
                label, _, value = line.partition(": ")
                pairs.append((label, value))
        for index, finding in enumerate(info.findings, start=1):
            value = f"{finding.severity} {finding.title}".strip()
            if finding.scanner:
                # Same escape as ``detail_text`` above; scanner names
                # are lowercase tag-shapes that Rich would silently
                # consume as styles.
                value += f" \\[{finding.scanner}]"
            if finding.location:
                value += f" @ {finding.location}"
            pairs.append((f"Finding {index}", value))
            if finding.remediation:
                pairs.append((f"Remediation {index}", finding.remediation))
        related = tuple(item for item in info.history if item.id != event.id)
        for index, item in enumerate(related[:5], start=1):
            pairs.append((f"History {index}", f"{item.timestamp.isoformat()} {item.action} {item.severity}"))
        return tuple(pairs)

    def copy_detail_text(self) -> str:
        """Return clipboard text for the selected alert, matching `y` parity."""

        info = self.get_detail_info()
        if info is None:
            return ""
        event = info.event
        lines = [
            f"Severity: {event.severity}",
            f"Action: {event.action}",
            f"Target: {event.target}",
            f"Timestamp: {event.timestamp.isoformat()}",
        ]
        if _is_hook_event(event):
            structured = structured_detail_rows(event.details)
            if structured:
                for label, value in structured:
                    lines.append(f"{label}: {value}")
            elif event.details:
                lines.append(f"Details: {event.details}")
        else:
            human = humanize_alert_details(event.details)
            if human and human != event.details:
                lines.append(f"Summary: {human}")
            if event.details:
                lines.append(f"Details: {event.details}")
        for label, value in (
            ("Run ID", event.run_id),
            ("Trace ID", event.trace_id),
            ("Request ID", event.request_id),
            ("Session ID", event.session_id),
        ):
            if value:
                lines.append(f"{label}: {value}")
        return "\n".join(lines)

    def _scan_block(self, scan_id: str) -> ScanBlock | None:
        for block in self.scan_blocks:
            if block.scan_id == scan_id:
                return block
        return None


def synthetic_scan_event(block: ScanBlock) -> AlertEvent:
    details = (
        f"scan_id={block.scan_id} scanner={block.scanner} findings={len(block.findings)} "
        f"verdict={block.verdict} duration_ms={block.duration_ms}"
    )
    if block.total_count > 0:
        details += f" total={block.total_count}"
    counts = _format_severity_counts(block.counts)
    if counts:
        details += f" counts={counts}"
    return AlertEvent(
        id=f"gw:scan:{block.scan_id}",
        severity=block.severity or "INFO",
        action="scan",
        target=block.target,
        details=details,
        timestamp=block.timestamp or datetime.now(timezone.utc),
    )


def synthetic_finding_event(block: ScanBlock, index: int) -> AlertEvent:
    if index < 0 or index >= len(block.findings):
        return AlertEvent(id="gw:finding:invalid", severity="INFO", action="scan-finding", target="")
    finding = block.findings[index]
    rule = finding.get("rule_id") or finding.get("category") or ""
    line = finding.get("line_number") or 0
    title = finding.get("title") or ""
    return AlertEvent(
        id=f"gw:finding:{block.scan_id}:{index}",
        severity=str(finding.get("severity") or block.severity or "INFO"),
        action="scan-finding",
        target=str(finding.get("target") or block.target),
        details=f"scan_id={block.scan_id} rule_id={rule} line={line} title={title}",
        timestamp=block.timestamp or datetime.now(timezone.utc),
    )


def synthetic_egress_event(event: EgressEvent) -> AlertEvent:
    severity = "INFO"
    if event.decision == "block" or (event.branch == "shape" and event.looks_like_llm):
        severity = "WARNING"
    host = event.target_host or "(unknown)"
    details = (
        f"host={host} path={event.target_path} branch={event.branch} decision={event.decision} "
        f"shape={event.body_shape} looks_like_llm={str(event.looks_like_llm).lower()} source={event.source}"
    )
    if event.reason:
        details += f" reason={event.reason}"
    stamp = (event.timestamp or datetime.now(timezone.utc)).isoformat()
    return AlertEvent(
        id=f"gw:egress:{host}:{event.branch}:{stamp}",
        severity=severity,
        action="egress",
        target=host,
        details=details,
        timestamp=event.timestamp or datetime.now(timezone.utc),
    )


def _severity_bucket(severity: str) -> str:
    normalized = severity.strip().upper()
    if normalized == "WARNING":
        return "MEDIUM"
    return normalized


def _truncate(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    if width <= 3:
        return value[:width]
    return value[: width - 3] + "..."


def _alert_filter_change(old: str, new: str) -> AlertFilterChange | None:
    if old == new:
        return None
    return AlertFilterChange(panel="alerts", filter_type="severity", old=old, new=new)


def _alert_row_key(row: AlertRow) -> str:
    if row.kind == "scan":
        return f"scan:{row.scan_id}"
    if row.kind == "scan_finding":
        return f"finding:{row.scan_id}:{row.finding_index}"
    if row.kind == "egress":
        return f"egress:{row.event.id}"
    return f"audit:{row.event.id}"


def _format_severity_counts(counts: dict[str, int]) -> str:
    if not counts:
        return ""
    return ",".join(f"{key}={counts[key]}" for key in sorted(counts))


def _gateway_finding_lines(detail: GatewayFindingDetail) -> list[str]:
    finding = detail.finding
    lines = [
        f"Scan: {detail.scan.scan_id}",
        f"Scanner: {finding.get('scanner') or detail.scan.scanner}",
        f"Target: {finding.get('target') or detail.scan.target}",
    ]
    if finding.get("rule_id"):
        lines.append(f"Rule: {finding['rule_id']}")
    if finding.get("line_number") not in {"", None}:
        lines.append(f"Line: {finding.get('line_number')}")
    if finding.get("location"):
        lines.append(f"Loc: {finding['location']}")
    if finding.get("title"):
        lines.append(f"Title: {finding['title']}")
    if finding.get("description"):
        lines.append(f"Desc: {finding['description']}")
    return lines


def _coerce_alert_event(event: object) -> AlertEvent:
    timestamp = _event_attr(event, "timestamp") or datetime.now(timezone.utc)
    if not isinstance(timestamp, datetime):
        timestamp = _parse_timestamp(timestamp)
    return AlertEvent(
        id=str(_event_attr(event, "id") or ""),
        severity=str(_event_attr(event, "severity") or ""),
        action=str(_event_attr(event, "action") or ""),
        target=str(_event_attr(event, "target") or ""),
        details=str(_event_attr(event, "details") or ""),
        timestamp=timestamp,
        actor=str(_event_attr(event, "actor") or ""),
        run_id=str(_event_attr(event, "run_id", "runID") or ""),
        trace_id=str(_event_attr(event, "trace_id", "traceID") or ""),
        request_id=str(_event_attr(event, "request_id", "requestID") or ""),
        session_id=str(_event_attr(event, "session_id", "sessionID") or ""),
    )


def _list_findings_by_run_id(store: object | None, run_id: str) -> tuple[AlertFinding, ...]:
    if store is None or not run_id:
        return ()
    if hasattr(store, "list_findings_by_run_id"):
        return tuple(_coerce_finding(item) for item in store.list_findings_by_run_id(run_id))  # type: ignore[attr-defined]
    db = getattr(store, "db", None)
    if db is None:
        return ()
    rows = db.execute(
        """SELECT id, scan_id, severity, title, description, location, remediation, scanner
           FROM findings WHERE scan_id = ? ORDER BY severity DESC""",
        (run_id,),
    ).fetchall()
    return tuple(
        AlertFinding(
            id=str(row[0]),
            scan_id=str(row[1]),
            severity=str(row[2]),
            title=str(row[3]),
            description=str(row[4] or ""),
            location=str(row[5] or ""),
            remediation=str(row[6] or ""),
            scanner=str(row[7] or ""),
        )
        for row in rows
    )


def _list_events_by_target(store: object | None, target: str, limit: int) -> tuple[AlertEvent, ...]:
    if store is None or not target:
        return ()
    if hasattr(store, "list_events_by_target"):
        return tuple(_coerce_alert_event(item) for item in store.list_events_by_target(target, limit))  # type: ignore[attr-defined]
    db = getattr(store, "db", None)
    if db is None:
        return ()
    rows = db.execute(
        """SELECT id, timestamp, action, target, actor, details, severity, run_id
           FROM audit_events WHERE target = ? ORDER BY timestamp DESC LIMIT ?""",
        (target, max(limit, 1)),
    ).fetchall()
    return tuple(_alert_event_from_row(row) for row in rows)


def _get_alert_event_by_id(store: object | None, event_id: str) -> AlertEvent | None:
    if store is None or not event_id or event_id.startswith("gw:") or not hasattr(store, "get_event"):
        return None
    try:
        event = store.get_event(event_id)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - detail hydration is best-effort.
        return None
    return _coerce_alert_event(event) if event is not None else None


def _coerce_finding(item: object) -> AlertFinding:
    return AlertFinding(
        id=str(_event_attr(item, "id") or ""),
        scan_id=str(_event_attr(item, "scan_id", "scanID") or ""),
        severity=str(_event_attr(item, "severity") or ""),
        title=str(_event_attr(item, "title") or ""),
        description=str(_event_attr(item, "description") or ""),
        location=str(_event_attr(item, "location") or ""),
        remediation=str(_event_attr(item, "remediation") or ""),
        scanner=str(_event_attr(item, "scanner") or ""),
    )


def _alert_event_from_row(row: tuple[Any, ...]) -> AlertEvent:
    return AlertEvent(
        id=str(row[0]),
        timestamp=_parse_timestamp(row[1]),
        action=str(row[2]),
        target=str(row[3] or ""),
        actor=str(row[4] or ""),
        details=str(row[5] or ""),
        severity=str(row[6] or ""),
        run_id=str(row[7] or ""),
    )


def _parse_timestamp(raw: object) -> datetime:
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


def _event_attr(event: object, *names: str) -> object:
    for name in names:
        if hasattr(event, name):
            return getattr(event, name)
        if isinstance(event, dict) and name in event:
            return event[name]
    return ""


def _is_hook_event(event: AlertEvent) -> bool:
    return event.action == "connector-hook"


def _alert_target_label(event: AlertEvent) -> str:
    """Pretty TARGET cell text.

    For connector-hook rows the audit ``target`` field holds only the
    hook phase (``preToolUse``); the connector name lives buried in
    the kv ``details`` blob. Surfacing both as
    ``claudecode · preToolUse`` makes the row self-describing without
    forcing the user into the detail pane. Other alert kinds keep the
    existing 42-char target truncation so the proxy/scan/egress
    layout is untouched.
    """

    if _is_hook_event(event):
        parsed = parse_kv_details(event.details)
        connector = parsed.get("connector", "")
        phase = event.target or ""
        if connector and phase:
            return _truncate(f"{connector} · {phase}", 42)
        if connector:
            return _truncate(connector, 42)
        if phase:
            return _truncate(phase, 42)
    return _truncate(event.target, 42)


def _alert_details_label(event: AlertEvent) -> str:
    """Pretty DETAILS cell text.

    Connector-hook details look like
    ``connector=claudecode action=allow severity=NONE mode=observe …``;
    truncating that to 58 chars yields a useless prefix. Pull the
    high-signal pieces (decision, severity if elevated, elapsed) into
    a compact ``allow · 320ms`` summary instead. All other kinds run
    through the legacy host/port/mode humanizer so the existing
    proxy/scan/egress rendering and its tests still pass.
    """

    if _is_hook_event(event):
        parsed = parse_kv_details(event.details)
        decision = parsed.get("action", "") or parsed.get("decision", "")
        severity = parsed.get("severity", "")
        elapsed = parsed.get("elapsed", "") or parsed.get("duration_ms", "")
        parts: list[str] = []
        if decision:
            parts.append(decision)
        if severity and severity.upper() not in {"", "NONE"}:
            parts.append(severity.upper())
        if elapsed:
            parts.append(elapsed)
        if parts:
            return _truncate(" · ".join(parts), 58)
    return _truncate(humanize_alert_details(event.details) or event.details, 58)


def _hook_detail_lines(event: AlertEvent) -> list[str]:
    """Hook-aware top section of the detail pane.

    Replaces the generic ``INFO connector-hook`` title with
    ``CLAUDECODE preToolUse`` and renders each kv field on its own
    line via :func:`structured_detail_rows`. Empty details fall back
    to the legacy two-line title so we never silently drop the raw
    body.
    """

    parsed = parse_kv_details(event.details)
    connector = parsed.get("connector", "")
    phase = event.target or ""
    if connector and phase:
        title = f"[bold #22D3EE]{connector} {phase}[/]"
    elif connector:
        title = f"[bold #22D3EE]{connector} hook[/]"
    elif phase:
        title = f"[bold #22D3EE]{phase}[/]"
    else:
        title = f"[bold #22D3EE]{event.severity} {event.action}[/]"
    lines = [
        title,
        f"Time: {event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    if event.severity and event.severity.upper() not in {"", "NONE", "INFO"}:
        lines.append(f"Severity: {event.severity}")
    rows = structured_detail_rows(event.details)
    if rows:
        for label, value in rows:
            lines.append(f"{label}: {value}")
    elif event.details:
        lines.append(f"Details: {event.details}")
    return lines
