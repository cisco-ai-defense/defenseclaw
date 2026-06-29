# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Shared catalog/list panel state for the Textual TUI migration."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Generic, Literal, TypeVar

from defenseclaw.tui.panels.registries import registry_badge
from defenseclaw.tui.services import connector_filter as connector_filter_svc

CatalogKind = Literal["skill", "mcp", "plugin", "tool"]


@dataclass(frozen=True)
class CatalogActionState:
    """Install/file/runtime decision attached to catalog rows."""

    file: str = ""
    runtime: str = ""
    install: str = ""

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> CatalogActionState:
        if not raw:
            return cls()
        return cls(
            file=str(raw.get("file") or ""),
            runtime=str(raw.get("runtime") or ""),
            install=str(raw.get("install") or ""),
        )

    def is_empty(self) -> bool:
        return not self.file and not self.runtime and not self.install

    def summary(self) -> str:
        parts: list[str] = []
        if self.install == "block":
            parts.append("blocked")
        if self.install == "allow":
            parts.append("allowed")
        if self.file == "quarantine":
            parts.append("quarantined")
        if self.runtime == "disable":
            parts.append("disabled")
        return ", ".join(parts) if parts else "-"


SEVERITY_BUCKETS: tuple[str, ...] = ("critical", "high", "medium", "low", "info")


def _parse_severity_counts(raw: Any) -> dict[str, int]:
    """Normalize a ``{severity: count}`` payload into the canonical buckets.

    E4i: ``skill/mcp/plugin list --json`` carries a per-severity breakdown
    (emitted by the CLI lane). The scanner stores severities upper-cased
    (``CRITICAL``/``HIGH``/...) while the TUI buckets are lower-cased, so
    fold case and drop anything outside the five known buckets. A missing
    or malformed payload yields ``{}`` so callers degrade to the legacy
    ``max_severity``-only line.
    """

    if not isinstance(raw, Mapping):
        return {}
    counts: dict[str, int] = {}
    for key, value in raw.items():
        bucket = str(key or "").strip().lower()
        if bucket not in SEVERITY_BUCKETS:
            continue
        try:
            count = int(value)
        except (TypeError, ValueError):
            continue
        if count > 0:
            counts[bucket] = counts.get(bucket, 0) + count
    return counts


@dataclass(frozen=True)
class CatalogScanSummary:
    """Small scan summary projected into Skills/MCP rows."""

    target: str = ""
    clean: bool = True
    max_severity: str = ""
    total_findings: int = 0
    # E4i: per-severity finding counts ({"critical": 1, "high": 2, ...}).
    # Empty when the CLI payload predates the severity breakdown (the
    # ``_build_scan_map`` emit is a separate CLI lane), so the detail line
    # falls back to the ``max_severity`` summary alone.
    severity_counts: Mapping[str, int] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> CatalogScanSummary | None:
        if not raw:
            return None
        return cls(
            target=str(raw.get("target") or ""),
            clean=bool(raw.get("clean")),
            max_severity=str(raw.get("max_severity") or ""),
            total_findings=int(raw.get("total_findings") or 0),
            severity_counts=_parse_severity_counts(raw.get("severity_counts")),
        )


@dataclass(frozen=True)
class PluginScanSummary:
    """Plugin scan payload from `defenseclaw plugin list --json`."""

    clean: bool = True
    max_severity: str = ""
    total_findings: int = 0
    # E4i: per-severity breakdown (see CatalogScanSummary.severity_counts).
    severity_counts: Mapping[str, int] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> PluginScanSummary | None:
        if not raw:
            return None
        return cls(
            clean=bool(raw.get("clean")),
            max_severity=str(raw.get("max_severity") or ""),
            total_findings=int(raw.get("total_findings") or 0),
            severity_counts=_parse_severity_counts(raw.get("severity_counts")),
        )


@dataclass(frozen=True)
class CatalogCommandIntent:
    """Command the app shell can preview and dispatch later."""

    label: str
    args: tuple[str, ...]
    origin: str
    binary: str = "defenseclaw"
    category: str = "enforce"
    hint: str = ""
    # N1: self-described risk so the dispatcher can route a known-destructive
    # action (e.g. plugin remove, which deletes files from disk) through the
    # strong consequence/danger confirm instead of relying solely on the
    # ``infer_command_risk`` keyword heuristic. ``"read-only"`` (the default)
    # preserves existing behaviour: the command preview re-classifies the risk
    # from the argv, so every other intent is unchanged. The app dispatch that
    # upgrades a ``"destructive"`` catalog intent to the C1 consequence modal
    # lives in ``app.py`` (the ``tui/app`` lane).
    risk: str = "read-only"

    @property
    def argv(self) -> tuple[str, ...]:
        return (self.binary, *self.args)


@dataclass(frozen=True)
class CatalogMenuAction:
    """Action-menu row with Go-compatible shortcut key."""

    key: str
    label: str
    description: str
    disabled: bool = False


@dataclass(frozen=True)
class RegistryFocus:
    """Registries panel deep-link request for a selected catalog row."""

    entry_type: Literal["skill", "mcp"]
    name: str
    source_id: str = ""


@dataclass(frozen=True)
class CatalogPanelAction:
    """Result of a panel-local key/action handler."""

    handled: bool
    intent: CatalogCommandIntent | None = None
    hint: str = ""
    open_action_menu: bool = False
    reload_requested: bool = False
    detail_opened: bool = False
    detail_closed: bool = False
    open_mcp_set_form: bool = False
    registry_focus: RegistryFocus | None = None


@dataclass(frozen=True)
class SkillRow:
    name: str
    status: str = "inactive"
    actions: str = "-"
    reason: str = ""
    time: str = ""
    description: str = ""
    source: str = ""
    verdict: str = ""
    severity: str = ""
    registry_source: str = ""
    # Denormalized scan / decision data so the detail pane can render
    # the same context the JSON payload carries without re-parsing
    # the original mapping. Defaults keep existing call sites that
    # build SkillRow directly (tests, sample data) working unchanged.
    total_findings: int = 0
    scan_clean: bool = True
    scan_target: str = ""
    # E4i: per-severity finding counts denormalized from the scan summary so
    # the detail pane can show the breakdown without re-parsing the payload.
    severity_counts: Mapping[str, int] = field(default_factory=dict)
    file_action: str = ""
    install_action: str = ""
    runtime_action: str = ""
    # 8.13 pass 2: connector this row was loaded from. Empty for single-
    # connector installs (the CONNECTOR column stays hidden); set when the
    # app merges ``skill list --json`` across every active connector.
    connector: str = ""

    @property
    def registry_badge(self) -> str:
        return registry_badge(self.registry_source)


@dataclass(frozen=True)
class MCPRow:
    name: str
    status: str = "active"
    actions: str = "-"
    reason: str = ""
    time: str = ""
    transport: str = ""
    command: str = ""
    server_url: str = ""
    severity: str = ""
    verdict: str = ""
    registry_source: str = ""
    # Same denormalization as SkillRow so the detail pane can show
    # the file/runtime/install state without re-parsing the JSON.
    total_findings: int = 0
    scan_clean: bool = True
    scan_target: str = ""
    # E4i: per-severity finding counts (see SkillRow.severity_counts).
    severity_counts: Mapping[str, int] = field(default_factory=dict)
    file_action: str = ""
    install_action: str = ""
    runtime_action: str = ""
    # 8.13 pass 2: connector this row was loaded from (see SkillRow.connector).
    connector: str = ""

    @property
    def url(self) -> str:
        """Go compatibility: the old field name held the server name."""

        return self.name

    @property
    def registry_badge(self) -> str:
        return registry_badge(self.registry_source)


@dataclass(frozen=True)
class PluginRow:
    id: str
    name: str = ""
    description: str = ""
    version: str = ""
    origin: str = ""
    status: str = ""
    enabled: bool = False
    verdict: str = ""
    scan: PluginScanSummary | None = None
    # 8.13 pass 2: connector this row was loaded from (see SkillRow.connector).
    connector: str = ""

    @property
    def display_name(self) -> str:
        return self.name or self.id


@dataclass(frozen=True)
class ToolRow:
    name: str
    scope: str = ""
    status: str = "active"
    reason: str = ""
    time: str = ""
    target_name: str = ""
    connector: str = ""

    @property
    def display_scope(self) -> str:
        return self.scope or "(global)"

    @property
    def dispatch_target(self) -> str:
        if self.connector and self.target_name.startswith("@"):
            return self.name
        return self.target_name or self.name


RowT = TypeVar("RowT", SkillRow, MCPRow, PluginRow, ToolRow)


class CatalogListModel(Generic[RowT]):
    """Shared cursor, filtering, selection, and error/loading state."""

    def __init__(self, *, filter_fields: tuple[str, ...] = ()) -> None:
        self.items: tuple[RowT, ...] = ()
        self.filtered: tuple[RowT, ...] = ()
        self.cursor = 0
        self.width = 0
        self.height = 0
        self.filter_text = ""
        self.filtering = False
        self.loaded = False
        self.loading = False
        self.message = ""
        self.detail_open = False
        self._filter_fields = filter_fields
        # WU13: when the TUI is focused on a non-primary connector in a
        # multi-connector install, the app sets this True so the list
        # command targets that connector via ``--connector <name>``.
        # False (the default) keeps single-connector behaviour unchanged
        # — no flag is appended and the active connector is listed.
        self.connector_focus_enabled = False
        # 8.13 pass 2: when the app merges this catalog across every active
        # connector it sets ``show_connector_column = True`` and tags rows with
        # their connector. ``connector_filter`` ("" = All) then narrows the
        # merged rows in-memory, mirroring the Alerts/Audit/Logs panes — no
        # reload needed when the operator cycles the shared chip.
        self.show_connector_column = False
        self.connector_filter = ""

    def set_connector_filter(self, connector: str) -> None:
        """Narrow the merged rows to one connector ("" = All); re-filters."""

        connector = (connector or "").strip().lower()
        if connector == self.connector_filter:
            return
        self.connector_filter = connector
        self.apply_filter()

    @staticmethod
    def row_connector(row: object) -> str:
        return str(getattr(row, "connector", "") or "")

    def _parse_rows(self, text: str) -> Sequence[RowT]:
        """Parse a single connector's list JSON into rows (subclass hook)."""

        raise NotImplementedError

    def apply_merged(self, results: Sequence[tuple[str, str | None]]) -> None:
        """Merge per-connector list payloads, tagging each row's connector.

        ``results`` is ``[(connector, json_text_or_None)]``; a ``None`` payload
        means that connector's list command failed and is skipped. Rows are
        concatenated in roster order so the CONNECTOR column groups naturally.
        """

        rows: list[RowT] = []
        for connector, text in results:
            if not text:
                continue
            try:
                parsed = self._parse_rows(text)
            except Exception:  # noqa: BLE001 - a bad payload skips one connector.
                continue
            for row in parsed:
                try:
                    rows.append(replace(row, connector=connector))  # type: ignore[arg-type]
                except TypeError:
                    rows.append(row)
        self.apply_loaded(rows)

    def focus_connector(self) -> str:
        """The focused connector name, or ``""`` when focus is inactive.

        Mutation intents thread this through only when the underlying CLI
        subcommand accepts ``--connector``. A blank connector preserves the
        legacy active/global CLI behavior."""
        connector = getattr(self, "connector", "")
        if self.connector_focus_enabled and connector:
            return connector
        return ""

    def action_connector(self, row: object | None) -> str:
        """Connector a per-row action should target.

        R5 (A3/E2/E3): under the merged "All" view ``focus_connector()`` is
        ``""`` even though every row is tagged with its owning connector, so
        scan/info/install/unset would silently hit the active/primary
        connector instead of the row's owner ("could not resolve skill" /
        "No MCP servers configured"). Prefer the selected row's owner; fall
        back to the focused connector, and ultimately ``""`` (CLI active or
        global) for untagged single-connector rows so existing behaviour is
        unchanged. Intent builders still gate ``--connector`` per verb.
        """
        return self.row_connector(row) or self.focus_connector()

    def _connector_focus_args(self) -> tuple[str, ...]:
        """Return ``("--connector", <name>)`` when multi-connector focus is
        active, else ``()``. Subclasses that carry a ``connector`` append
        this to their list command so the catalog reflects the focused
        connector instead of the active one."""
        connector = self.focus_connector()
        if connector:
            return ("--connector", connector)
        return ()

    def set_size(self, width: int, height: int) -> None:
        self.width = width
        self.height = height

    def apply_loaded(self, rows: Sequence[RowT], error: Exception | str | None = None) -> None:
        self.loading = False
        if error is not None:
            self.message = str(error)
            return
        self.items = tuple(rows)
        self.loaded = True
        self.message = ""
        self.apply_filter()

    def start_loading(self) -> CatalogCommandIntent:
        self.loading = True
        return self.load_intent()

    def load_intent(self) -> CatalogCommandIntent:
        raise NotImplementedError

    def load_intent_for(self, connector: str) -> CatalogCommandIntent:
        """``load_intent`` forced to a specific connector (merged loads).

        Temporarily pins ``connector`` + focus so the subclass's existing
        ``_connector_focus_args`` appends ``--connector <name>``, then restores
        the prior state so single-connector behaviour is untouched.
        """

        saved_connector = getattr(self, "connector", "")
        saved_focus = self.connector_focus_enabled
        try:
            if hasattr(self, "connector"):
                self.connector = connector  # type: ignore[attr-defined]
            self.connector_focus_enabled = bool(connector)
            return self.load_intent()
        finally:
            if hasattr(self, "connector"):
                self.connector = saved_connector  # type: ignore[attr-defined]
            self.connector_focus_enabled = saved_focus

    def refresh(self) -> None:
        self.apply_filter()

    def set_filter(self, text: str) -> None:
        self.filter_text = text
        self.apply_filter()

    def start_filter(self) -> None:
        self.filtering = True

    def stop_filter(self) -> None:
        self.filtering = False

    def clear_filter(self) -> None:
        self.filter_text = ""
        self.filtering = False
        self.apply_filter()

    def apply_filter(self) -> None:
        rows: tuple[RowT, ...] = self.items
        if self.connector_filter:
            rows = tuple(row for row in rows if self._row_matches_connector_filter(row))
        if self.filter_text and self._filter_fields:
            query = self.filter_text.lower()
            rows = tuple(row for row in rows if query in self._haystack(row))
        self.filtered = rows
        self._clamp_cursor()

    def _row_matches_connector_filter(self, row: RowT) -> bool:
        return connector_filter_svc.filter_allows(self.connector_filter, self.row_connector(row))

    def selected(self) -> RowT | None:
        if 0 <= self.cursor < len(self.filtered):
            return self.filtered[self.cursor]
        return None

    def action_key_available(self, key: str) -> bool:
        """Whether the selected row currently advertises ``key`` as an action."""

        actions = getattr(self, "menu_actions", None)
        if not callable(actions):
            return False
        return any(action.key == key and not action.disabled for action in actions())

    def select_row(self, index: int) -> RowT | None:
        self.set_cursor(index)
        return self.selected()

    def cursor_up(self) -> None:
        if self.cursor > 0:
            self.cursor -= 1

    def cursor_down(self) -> None:
        if self.cursor < len(self.filtered) - 1:
            self.cursor += 1

    def set_cursor(self, index: int) -> None:
        self.cursor = index
        self._clamp_cursor()

    def scroll_by(self, delta: int) -> None:
        self.cursor += delta
        self._clamp_cursor()

    def scroll_offset(self) -> int:
        max_visible = self.list_height()
        if max_visible < 1:
            max_visible = 10
        if self.cursor >= max_visible:
            return self.cursor - max_visible + 1
        return 0

    def list_height(self) -> int:
        height = self.height - self.filter_bar_height() - 1 - self.detail_height()
        return max(height, 3)

    def detail_height(self) -> int:
        if not self.detail_open:
            return 0
        return min(max(self.height // 2, 8), 26)

    def filter_bar_height(self) -> int:
        height = 2
        if self.filter_text:
            height += 1
        if self.filtering:
            height += 1
        return height

    def toggle_detail(self) -> None:
        self.detail_open = not self.detail_open

    def count(self) -> int:
        return len(self.items)

    def filtered_count(self) -> int:
        return len(self.filtered)

    def cursor_at(self) -> int:
        return self.cursor

    def empty_state(self) -> str:
        return ""

    def data_table_columns(self) -> tuple[str, ...]:
        base = ("Name", "Status", "Source", "Actions", "Details")
        if self.show_connector_column:
            return ("Connector", *base)
        return base

    def data_table_rows(self) -> tuple[tuple[str, ...], ...]:
        if self.show_connector_column:
            return tuple(
                (self.connector_cell(row), *catalog_row_cells(row)) for row in self.filtered
            )
        return tuple(catalog_row_cells(row) for row in self.filtered)

    def connector_cell(self, row: RowT) -> str:
        return self.row_connector(row) or "—"

    def summary_text(self, title: str) -> str:
        filter_text = f" filter={self.filter_text!r}" if self.filter_text else ""
        detail = " detail=open" if self.detail_open else ""
        # Group navigation vs. action keys on separate lines so the
        # eye lands on the action set (which is what operators reach
        # for) instead of getting buried in the navigation primer.
        # The legacy single-line hint hid ``o`` between ``Enter`` and
        # ``r`` so operators couldn't tell that pressing ``o`` opens
        # the per-row action menu.
        return (
            f"[bold #22D3EE]{title}[/]\n"
            f"{len(self.filtered)} of {len(self.items)} rows{filter_text}{detail}\n"
            "[dim]Navigate:[/] j/k move  ·  Enter detail  ·  / filter  ·  Esc close  ·  r refresh\n"
            "[dim]Actions:[/]  o open menu  ·  s scan  ·  b block  ·  a allow  ·  R reveal in registry"
        )

    def _haystack(self, row: RowT) -> str:
        parts = [str(getattr(row, field_name, "")) for field_name in self._filter_fields]
        return " ".join(parts).lower()

    def _clamp_cursor(self) -> None:
        max_cursor = len(self.filtered) - 1
        if max_cursor < 0:
            self.cursor = 0
        elif self.cursor < 0:
            self.cursor = 0
        elif self.cursor > max_cursor:
            self.cursor = max_cursor


class SkillsPanelModel(CatalogListModel[SkillRow]):
    """Pure Skills panel state and action-intent mapping."""

    def __init__(self, *, connector: str = "") -> None:
        super().__init__(filter_fields=("name", "status", "reason", "description", "source"))
        self.connector = connector
        self.registry_by_name: dict[str, str] = {}

    def load_intent(self) -> CatalogCommandIntent:
        return CatalogCommandIntent(
            label="skill list --json",
            args=("skill", "list", "--json", *self._connector_focus_args()),
            origin="skills",
            category="info",
            hint="Loading skills...",
        )

    def apply_loaded(self, rows: Sequence[SkillRow], error: Exception | str | None = None) -> None:
        if error is not None:
            super().apply_loaded(rows, f"Error loading skills: {error}")
            return
        super().apply_loaded(_apply_skill_registry(rows, self.registry_by_name), None)

    def apply_json(self, text: str) -> None:
        self.apply_loaded(parse_skill_list_json(text))

    def _parse_rows(self, text: str) -> Sequence[SkillRow]:
        return parse_skill_list_json(text)

    def set_connector(self, connector: str) -> None:
        self.connector = connector

    def set_registry_attribution(self, attribution: Mapping[str, str] | None) -> None:
        self.registry_by_name = dict(attribution or {})
        self.items = _apply_skill_registry(self.items, self.registry_by_name)
        self.filtered = _apply_skill_registry(self.filtered, self.registry_by_name)

    def blocked_count(self) -> int:
        return sum(1 for row in self.items if row.status == "blocked")

    def menu_actions(self) -> tuple[CatalogMenuAction, ...]:
        row = self.selected()
        return skill_actions(row.status if row else "")

    def action_intent(self, key: str, *, origin: str = "action-menu") -> CatalogCommandIntent | None:
        row = self.selected()
        if row is None:
            return None
        return skill_action_intent(key, row, origin=origin, connector=self.action_connector(row))

    def registry_focus(self) -> RegistryFocus | None:
        row = self.selected()
        if row is None:
            return None
        return RegistryFocus("skill", row.name, row.registry_source)

    def handle_key(self, key: str) -> CatalogPanelAction:
        if key in {"j", "down"}:
            self.cursor_down()
            return CatalogPanelAction(True)
        if key in {"k", "up"}:
            self.cursor_up()
            return CatalogPanelAction(True)
        if key == "esc" and self.detail_open:
            self.toggle_detail()
            return CatalogPanelAction(True, detail_closed=True)
        if key == "enter":
            if self.selected() is None:
                return CatalogPanelAction(True, hint="(no skill selected)")
            self.detail_open = True
            return CatalogPanelAction(True, detail_opened=True)
        if key == "o":
            return CatalogPanelAction(True, open_action_menu=self.selected() is not None)
        if key in {"s", "b", "a", "u"}:
            intent = (
                self.action_intent(key, origin="skills")
                if self.selected() and self.action_key_available(key)
                else None
            )
            return CatalogPanelAction(True, intent)
        if key == "r":
            return CatalogPanelAction(True, self.load_intent(), reload_requested=True)
        if key == "R":
            return CatalogPanelAction(True, registry_focus=self.registry_focus())
        return CatalogPanelAction(False)

    def empty_state(self) -> str:
        if self.filter_text:
            return "No skills match the filter."
        if not self.loaded:
            return 'Press "r" to load skills. Runs "defenseclaw skill list --json".'
        return (
            f"No skills found in {connector_source_label(self.connector, 'skills')} "
            f"(active connector: {friendly_connector_name(self.connector)})."
        )


class MCPsPanelModel(CatalogListModel[MCPRow]):
    """Pure MCPs panel state and action-intent mapping."""

    def __init__(self, *, connector: str = "") -> None:
        super().__init__(filter_fields=("name", "status", "reason", "server_url", "command"))
        self.connector = connector
        self.registry_by_name: dict[str, str] = {}

    def load_intent(self) -> CatalogCommandIntent:
        return CatalogCommandIntent(
            label="mcp list --json",
            args=("mcp", "list", "--json", *self._connector_focus_args()),
            origin="mcps",
            category="info",
            hint="Loading MCP servers...",
        )

    def apply_loaded(self, rows: Sequence[MCPRow], error: Exception | str | None = None) -> None:
        if error is not None:
            super().apply_loaded(rows, f"Error loading MCPs: {error}")
            return
        super().apply_loaded(_apply_mcp_registry(rows, self.registry_by_name), None)

    def apply_json(self, text: str) -> None:
        self.apply_loaded(parse_mcp_list_json(text))

    def _parse_rows(self, text: str) -> Sequence[MCPRow]:
        return parse_mcp_list_json(text)

    def set_connector(self, connector: str) -> None:
        self.connector = connector

    def active_connector(self) -> str:
        return self.connector

    def set_registry_attribution(self, attribution: Mapping[str, str] | None) -> None:
        self.registry_by_name = dict(attribution or {})
        self.items = _apply_mcp_registry(self.items, self.registry_by_name)
        self.filtered = _apply_mcp_registry(self.filtered, self.registry_by_name)

    def blocked_count(self) -> int:
        return sum(1 for row in self.items if row.status == "blocked")

    def menu_actions(self) -> tuple[CatalogMenuAction, ...]:
        row = self.selected()
        return mcp_actions(row.status if row else "", self.connector)

    def action_intent(self, key: str, *, origin: str = "action-menu") -> CatalogCommandIntent | None:
        row = self.selected()
        if row is None:
            return None
        return mcp_action_intent(key, row, origin=origin, connector=self.action_connector(row))

    def registry_focus(self) -> RegistryFocus | None:
        row = self.selected()
        if row is None:
            return None
        return RegistryFocus("mcp", row.name, row.registry_source)

    def handle_key(self, key: str) -> CatalogPanelAction:
        if key in {"j", "down"}:
            self.cursor_down()
            return CatalogPanelAction(True)
        if key in {"k", "up"}:
            self.cursor_up()
            return CatalogPanelAction(True)
        if key == "esc" and self.detail_open:
            self.toggle_detail()
            return CatalogPanelAction(True, detail_closed=True)
        if key == "enter":
            if self.selected() is None:
                return CatalogPanelAction(True, hint="(no MCP selected)")
            self.detail_open = True
            return CatalogPanelAction(True, detail_opened=True)
        if key == "o":
            return CatalogPanelAction(True, open_action_menu=self.selected() is not None)
        if key in {"s", "b", "a", "u"}:
            intent = (
                self.action_intent(key, origin="mcps")
                if self.selected() and self.action_key_available(key)
                else None
            )
            return CatalogPanelAction(True, intent)
        if key in {"n", "+"}:
            return CatalogPanelAction(True, open_mcp_set_form=True)
        if key == "r":
            return CatalogPanelAction(True, self.load_intent(), reload_requested=True)
        if key == "R":
            return CatalogPanelAction(True, registry_focus=self.registry_focus())
        return CatalogPanelAction(False)

    def empty_state(self) -> str:
        if self.filter_text:
            return "No MCP servers match the filter."
        if not self.loaded:
            return 'Press "r" to load MCP servers. Runs "defenseclaw mcp list --json".'
        return (
            f"No MCP servers configured in {connector_source_label(self.connector, 'mcps')} "
            f"(active connector: {friendly_connector_name(self.connector)})."
        )


class PluginsPanelModel(CatalogListModel[PluginRow]):
    """Pure Plugins panel state and action-intent mapping."""

    def __init__(self, *, connector: str = "") -> None:
        super().__init__()
        self.connector = connector

    def load_intent(self) -> CatalogCommandIntent:
        return CatalogCommandIntent(
            label="plugin list --json",
            args=("plugin", "list", "--json", *self._connector_focus_args()),
            origin="plugins",
            category="info",
            hint="Loading plugins...",
        )

    def apply_loaded(self, rows: Sequence[PluginRow], error: Exception | str | None = None) -> None:
        if error is not None:
            super().apply_loaded(rows, f"Error loading plugins: {error}")
            return
        super().apply_loaded(rows, None)

    def apply_json(self, text: str) -> None:
        self.apply_loaded(parse_plugin_list_json(text))

    def _parse_rows(self, text: str) -> Sequence[PluginRow]:
        return parse_plugin_list_json(text)

    def set_connector(self, connector: str) -> None:
        self.connector = connector

    def is_visible_for_connector(self) -> bool:
        return normalized_connector(self.connector) == "openclaw"

    def openclaw_only_notice(self) -> str:
        return (
            "DefenseClaw plugins are an OpenClaw-only concept. "
            f"Active connector: {friendly_connector_name(self.connector)}."
        )

    def menu_actions(self) -> tuple[CatalogMenuAction, ...]:
        row = self.selected()
        if row is None:
            return plugin_actions("", "", False)
        return plugin_actions(row.verdict, row.status, row.enabled)

    def action_intent(self, key: str, *, origin: str = "action-menu") -> CatalogCommandIntent | None:
        row = self.selected()
        if row is None:
            return None
        return plugin_action_intent(key, row, origin=origin, connector=self.action_connector(row))

    def list_height(self) -> int:
        height = self.height - 1 - self.detail_height()
        return max(height, 3)

    def handle_key(self, key: str) -> CatalogPanelAction:
        if key in {"j", "down"}:
            self.cursor_down()
            return CatalogPanelAction(True)
        if key in {"k", "up"}:
            self.cursor_up()
            return CatalogPanelAction(True)
        if key == "esc" and self.detail_open:
            self.toggle_detail()
            return CatalogPanelAction(True, detail_closed=True)
        if key == "enter":
            if self.selected() is None:
                return CatalogPanelAction(True, hint="(no plugin selected)")
            self.detail_open = True
            return CatalogPanelAction(True, detail_opened=True)
        if key == "s":
            row = self.selected()
            if row is None:
                return CatalogPanelAction(True)
            return CatalogPanelAction(True, plugin_direct_scan_intent(row, self.action_connector(row)))
        if key == "o":
            return CatalogPanelAction(True, open_action_menu=self.selected() is not None)
        if key in {"b", "a", "u"}:
            intent = (
                self.action_intent(key, origin="plugins")
                if self.selected() and self.action_key_available(key)
                else None
            )
            return CatalogPanelAction(True, intent)
        if key == "r":
            return CatalogPanelAction(True, self.load_intent(), reload_requested=True)
        return CatalogPanelAction(False)

    def empty_state(self) -> str:
        if not self.loaded:
            return 'Press "r" to load plugins. Runs "defenseclaw plugin list --json".'
        return (
            f"No plugins detected. Plugins extend {friendly_connector_name(self.connector)} with tools and hooks. "
            'Use : then "plugin install <name>" to add one.'
        )


class ToolsPanelModel(CatalogListModel[ToolRow]):
    """Pure Tools panel state backed by audit-store tool action rows."""

    def __init__(self, store: object | None = None, *, connector: str = "") -> None:
        super().__init__()
        self.store = store
        self.connector = connector

    def load_intent(self) -> CatalogCommandIntent:
        return CatalogCommandIntent(
            label="tool list --json",
            args=("tool", "list", "--json", *self._connector_focus_args()),
            origin="tools",
            category="info",
            hint="Loading tools...",
        )

    def apply_json(self, text: str) -> None:
        self.apply_loaded(parse_tool_list_json(text))

    def _parse_rows(self, text: str) -> Sequence[ToolRow]:
        return parse_tool_list_json(text)

    def refresh(self) -> None:
        if self.store is None:
            self.apply_filter()
            return
        self.items = ()
        self.filtered = ()
        try:
            entries = self.store.list_actions_by_type("tool")
        except Exception as exc:  # noqa: BLE001 - panel state renders store errors.
            self.message = f"Error loading tools: {exc}"
            self._clamp_cursor()
            return
        self.items = tools_from_action_entries(entries)
        self.loaded = True
        self.message = ""
        self.apply_filter()

    def blocked_count(self) -> int:
        return sum(1 for row in self.items if row.status == "blocked")

    def allowed_count(self) -> int:
        return sum(1 for row in self.items if row.status == "allowed")

    def _row_matches_connector_filter(self, row: ToolRow) -> bool:
        connector = self.row_connector(row)
        if connector:
            return connector_filter_svc.filter_allows(self.connector_filter, connector)
        return not row.scope

    def connector_cell(self, row: ToolRow) -> str:
        connector = self.row_connector(row)
        if connector:
            return connector
        return "source" if row.scope else "all"

    def action_connector(self, row: object | None) -> str:
        return self.row_connector(row) or self.connector_filter or self.focus_connector()

    def menu_actions(self) -> tuple[CatalogMenuAction, ...]:
        row = self.selected()
        return tool_actions(row.status if row else "")

    def action_intent(self, key: str, *, origin: str = "action-menu") -> CatalogCommandIntent | None:
        row = self.selected()
        if row is None:
            return None
        return tool_action_intent(key, row, origin=origin, connector=self.action_connector(row))

    def list_height(self) -> int:
        height = self.height - 4
        if self.detail_open:
            height -= 8
        return max(height, 3)

    def handle_key(self, key: str) -> CatalogPanelAction:
        if key in {"j", "down"}:
            self.cursor_down()
            return CatalogPanelAction(True)
        if key in {"k", "up"}:
            self.cursor_up()
            return CatalogPanelAction(True)
        if key == "esc" and self.detail_open:
            self.toggle_detail()
            return CatalogPanelAction(True, detail_closed=True)
        if key == "enter":
            if self.selected() is None:
                return CatalogPanelAction(True, hint="(no tool selected)")
            self.detail_open = True
            return CatalogPanelAction(True, detail_opened=True)
        if key == "o":
            return CatalogPanelAction(True, open_action_menu=self.selected() is not None)
        if key in {"b", "a", "u"}:
            intent = (
                self.action_intent(key, origin="tools")
                if self.selected() and self.action_key_available(key)
                else None
            )
            return CatalogPanelAction(True, intent)
        if key == "r":
            self.refresh()
            return CatalogPanelAction(True, hint="Refreshed.")
        return CatalogPanelAction(False)

    def summary_text(self, title: str) -> str:
        filter_text = f" filter={self.filter_text!r}" if self.filter_text else ""
        detail = " detail=open" if self.detail_open else ""
        return (
            f"[bold #22D3EE]{title}[/]\n"
            f"{len(self.filtered)} of {len(self.items)} policy rows{filter_text}{detail}\n"
            "[dim]Rows:[/] block/allow policy only; unblocked tools disappear from this table.\n"
            "[dim]Navigate:[/] j/k move  ·  Enter detail  ·  / filter  ·  Esc close  ·  r refresh\n"
            "[dim]Actions:[/]  o open menu  ·  b block  ·  a allow  ·  u unblock"
        )

    def empty_state(self) -> str:
        return (
            "No tool policy rows. This table only shows block/allow entries; "
            "unblocked tools disappear here."
        )


def parse_skill_list_json(text: str) -> tuple[SkillRow, ...]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"parse skill list: {exc}") from exc

    def _rows_from_group(group: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        connector = str(group.get("connector") or "")
        raw_skills = group.get("skills")
        if not isinstance(raw_skills, list):
            raise ValueError("parse skill list: expected skills list")
        rows: list[Mapping[str, Any]] = []
        for skill in raw_skills:
            if not isinstance(skill, Mapping):
                raise ValueError("parse skill list: expected skills objects")
            if connector and not skill.get("connector"):
                rows.append({**skill, "connector": connector})
            else:
                rows.append(skill)
        return rows

    raw: list[Mapping[str, Any]] = []
    if isinstance(payload, Mapping):
        raw.extend(_rows_from_group(payload))
    elif isinstance(payload, list):
        for item in payload:
            if not isinstance(item, Mapping):
                raise ValueError("parse skill list: expected list objects")
            if "skills" in item:
                raw.extend(_rows_from_group(item))
            else:
                raw.append(item)
    else:
        raise ValueError("parse skill list: expected a JSON list or connector group")
    return tuple(skill_list_to_row(item) for item in raw)


def skill_list_to_row(raw: Mapping[str, Any]) -> SkillRow:
    scan = CatalogScanSummary.from_mapping(_mapping_or_none(raw.get("scan")))
    actions = CatalogActionState.from_mapping(_mapping_or_none(raw.get("actions")))
    severity = scan.max_severity if scan is not None else ""
    scan_mismatch = ""
    if scan is not None and not scan.clean:
        severity_upper = severity.upper()
        if severity_upper in {"CRITICAL", "HIGH"}:
            scan_mismatch = "rejected"
        elif severity_upper in {"MEDIUM", "LOW"}:
            scan_mismatch = "warning"

    status_field = str(raw.get("status") or "")
    source = str(raw.get("source") or "")
    if bool(raw.get("disabled")):
        status = "disabled"
    elif actions.file == "quarantine":
        status = "quarantined"
    elif actions.install == "block":
        status = "blocked"
    elif actions.runtime == "disable":
        status = "disabled"
    elif actions.install == "allow":
        status = "allowed"
    elif status_field == "blocked":
        status = "blocked"
    elif status_field == "disabled":
        status = "disabled"
    elif scan_mismatch:
        status = scan_mismatch
    elif bool(raw.get("eligible")):
        status = "active"
    elif source in {"enforcement", "scan-history"}:
        status = "removed"
    else:
        status = "inactive"

    return SkillRow(
        name=str(raw.get("name") or ""),
        status=status,
        actions=actions.summary(),
        description=str(raw.get("description") or ""),
        source=source,
        verdict=str(raw.get("verdict") or ""),
        severity=severity,
        total_findings=scan.total_findings if scan is not None else 0,
        scan_clean=scan.clean if scan is not None else True,
        scan_target=scan.target if scan is not None else "",
        severity_counts=scan.severity_counts if scan is not None else {},
        file_action=actions.file,
        install_action=actions.install,
        runtime_action=actions.runtime,
        connector=str(raw.get("connector") or ""),
    )


def parse_mcp_list_json(text: str) -> tuple[MCPRow, ...]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"parse mcp list: {exc}") from exc

    def _rows_from_group(group: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        connector = str(group.get("connector") or "")
        raw_servers = group.get("mcp_servers")
        if not isinstance(raw_servers, list):
            raise ValueError("parse mcp list: expected mcp_servers list")
        rows: list[Mapping[str, Any]] = []
        for server in raw_servers:
            if not isinstance(server, Mapping):
                raise ValueError("parse mcp list: expected mcp_servers objects")
            if connector and not server.get("connector"):
                rows.append({**server, "connector": connector})
            else:
                rows.append(server)
        return rows

    raw: list[Mapping[str, Any]] = []
    if isinstance(payload, Mapping):
        raw.extend(_rows_from_group(payload))
    elif isinstance(payload, list):
        for item in payload:
            if not isinstance(item, Mapping):
                raise ValueError("parse mcp list: expected list objects")
            if "mcp_servers" in item:
                raw.extend(_rows_from_group(item))
            else:
                raw.append(item)
    else:
        raise ValueError("parse mcp list: expected a JSON list or connector group")
    return tuple(mcp_list_to_row(item) for item in raw)


def mcp_list_to_row(raw: Mapping[str, Any]) -> MCPRow:
    actions = CatalogActionState.from_mapping(_mapping_or_none(raw.get("actions")))
    scan = CatalogScanSummary.from_mapping(_mapping_or_none(raw.get("scan")))
    status = "active"
    if actions.file == "quarantine":
        status = "quarantined"
    elif actions.install == "block":
        status = "blocked"
    elif actions.runtime == "disable":
        status = "disabled"
    elif actions.install == "allow":
        status = "allowed"
    return MCPRow(
        name=str(raw.get("name") or ""),
        connector=str(raw.get("connector") or ""),
        status=status,
        actions=actions.summary(),
        transport=str(raw.get("transport") or ""),
        command=str(raw.get("command") or ""),
        server_url=str(raw.get("url") or ""),
        severity=str(raw.get("severity") or scan.max_severity if scan else ""),
        verdict=str(raw.get("verdict") or ""),
        total_findings=scan.total_findings if scan is not None else 0,
        scan_clean=scan.clean if scan is not None else True,
        scan_target=scan.target if scan is not None else "",
        severity_counts=scan.severity_counts if scan is not None else {},
        file_action=actions.file,
        install_action=actions.install,
        runtime_action=actions.runtime,
    )


def parse_plugin_list_json(text: str) -> tuple[PluginRow, ...]:
    raw = _decode_json_list(text, "plugin list")
    return tuple(plugin_list_to_row(item) for item in raw)


def plugin_list_to_row(raw: Mapping[str, Any]) -> PluginRow:
    return PluginRow(
        id=str(raw.get("id") or ""),
        name=str(raw.get("name") or ""),
        description=str(raw.get("description") or ""),
        version=str(raw.get("version") or ""),
        origin=str(raw.get("origin") or ""),
        status=str(raw.get("status") or ""),
        enabled=bool(raw.get("enabled")),
        verdict=str(raw.get("verdict") or ""),
        scan=PluginScanSummary.from_mapping(_mapping_or_none(raw.get("scan"))),
    )


def parse_tool_list_json(text: str) -> tuple[ToolRow, ...]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"parse tool list: {exc}") from exc

    def _rows_from_group(group: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        connector = str(group.get("connector") or "")
        raw_tools = group.get("tools")
        if not isinstance(raw_tools, list):
            raise ValueError("parse tool list: expected tools list")
        rows: list[Mapping[str, Any]] = []
        for tool in raw_tools:
            if not isinstance(tool, Mapping):
                raise ValueError("parse tool list: expected tools objects")
            if connector and not tool.get("connector"):
                rows.append({**tool, "connector": connector})
            else:
                rows.append(tool)
        return rows

    raw: list[Mapping[str, Any]] = []
    if isinstance(payload, Mapping):
        raw.extend(_rows_from_group(payload))
    elif isinstance(payload, list):
        for item in payload:
            if not isinstance(item, Mapping):
                raise ValueError("parse tool list: expected list objects")
            if "tools" in item:
                raw.extend(_rows_from_group(item))
            else:
                raw.append(item)
    else:
        raise ValueError("parse tool list: expected a JSON list or connector group")
    return tuple(tool_list_to_row(item) for item in raw)


def tool_list_to_row(raw: Mapping[str, Any]) -> ToolRow:
    raw_name = str(raw.get("name") or "")
    raw_scope = str(raw.get("scope") or "")
    connector = normalized_connector(str(raw.get("connector") or ""))
    target_name = str(raw.get("target_name") or "")

    name = raw_name
    scope = raw_scope
    if not target_name:
        if raw_scope == "connector" and connector:
            target_name = f"@{connector}/{raw_name}"
        else:
            target_name = raw_name

    if raw_scope == "source":
        parsed_name, parsed_scope, parsed_connector = parse_tool_target(target_name)
        name = parsed_name
        scope = parsed_scope
        if parsed_connector and not connector:
            connector = parsed_connector
    elif raw_scope == "global":
        scope = "global"
    elif raw_scope == "connector":
        scope = "connector"
    elif target_name:
        parsed_name, parsed_scope, parsed_connector = parse_tool_target(target_name)
        name = parsed_name
        scope = parsed_scope
        if parsed_connector and not connector:
            connector = parsed_connector

    raw_status = str(raw.get("status") or "")
    if raw_status == "block":
        status = "blocked"
    elif raw_status == "allow":
        status = "allowed"
    else:
        status = raw_status or "active"

    return ToolRow(
        name=name,
        scope=scope,
        status=status,
        reason=str(raw.get("reason") or ""),
        time=format_tool_time(raw.get("updated_at")),
        target_name=target_name,
        connector=connector,
    )


def tools_from_action_entries(entries: Sequence[object]) -> tuple[ToolRow, ...]:
    rows: list[ToolRow] = []
    for entry in entries:
        target_name = str(_get_attr(entry, "target_name", "TargetName"))
        name, scope, target_connector = parse_tool_target(target_name)
        actions = _get_attr(entry, "actions", "Actions", default=None)
        install = str(_get_attr(actions, "install", "Install", default=""))
        if install == "block":
            status = "blocked"
        elif install == "allow":
            status = "allowed"
        else:
            status = "active"
        updated_at = _get_attr(entry, "updated_at", "UpdatedAt", default=None)
        rows.append(
            ToolRow(
                name=name,
                scope=scope,
                status=status,
                reason=str(_get_attr(entry, "reason", "Reason")),
                time=format_tool_time(updated_at),
                target_name=target_name,
                connector=normalized_connector(
                    str(_get_attr(entry, "connector", "Connector", default="") or target_connector)
                ),
            )
        )
    return tuple(rows)


def split_tool_target(target_name: str) -> tuple[str, str]:
    name, scope, _connector = parse_tool_target(target_name)
    return name, scope


def parse_tool_target(target_name: str) -> tuple[str, str, str]:
    if target_name.startswith("@") and "/" in target_name:
        connector, _, name = target_name[1:].partition("/")
        if connector and name:
            return name, "connector", normalized_connector(connector)
    if "@" in target_name and not target_name.startswith("@"):
        name, scope = target_name.rsplit("@", 1)
        return name, scope, ""
    if "/" in target_name and not target_name.startswith("/") and not target_name.endswith("/"):
        scope, name = target_name.split("/", 1)
        return name, scope, ""
    return target_name, "", ""


def format_tool_time(value: object) -> str:
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M")
    if isinstance(value, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(value, fmt).strftime("%Y-%m-%d %H:%M")
            except ValueError:
                continue
    return ""


def skill_actions(status: str) -> tuple[CatalogMenuAction, ...]:
    actions = [
        CatalogMenuAction("s", "Scan", "Run security scan"),
        CatalogMenuAction("i", "Info", "Show full details"),
    ]
    if status == "blocked":
        actions.extend(
            [
                CatalogMenuAction("u", "Unblock", "Remove from block list"),
                CatalogMenuAction("a", "Allow", "Pin as allow-listed"),
            ]
        )
    elif status == "allowed":
        actions.extend(
            [
                CatalogMenuAction("b", "Block", "Add to block list"),
                CatalogMenuAction("d", "Disable", "Disable at runtime"),
            ]
        )
    elif status == "quarantined":
        actions.append(CatalogMenuAction("r", "Restore", "Restore from quarantine"))
    elif status == "disabled":
        actions.extend(
            [
                CatalogMenuAction("e", "Enable", "Enable at runtime"),
                CatalogMenuAction("b", "Block", "Add to block list"),
            ]
        )
    else:
        actions.extend(
            [
                CatalogMenuAction("b", "Block", "Add to block list"),
                CatalogMenuAction("a", "Allow", "Add to allow list"),
                CatalogMenuAction("d", "Disable", "Disable at runtime"),
                CatalogMenuAction("q", "Quarantine", "Move to quarantine"),
                CatalogMenuAction("n", "Install", "Install via ClawHub"),
            ]
        )
    return tuple(actions)


def mcp_actions(status: str, connector: str) -> tuple[CatalogMenuAction, ...]:
    actions = [
        CatalogMenuAction("s", "Scan", "Run security scan"),
        CatalogMenuAction("i", "Info", "Show full details"),
    ]
    connector = normalized_connector(connector)
    target = mcp_unset_target_for_connector(connector)
    unset_desc = f"Remove from {target}"
    if connector == "zeptoclaw":
        unset_desc = f"Read-only - edit {target} manually"

    if status == "blocked":
        actions.extend(
            [
                CatalogMenuAction("u", "Unblock", "Remove from block list"),
                CatalogMenuAction("x", "Unset", unset_desc),
            ]
        )
    elif status == "allowed":
        actions.extend(
            [
                CatalogMenuAction("b", "Block", "Add to block list"),
                CatalogMenuAction("x", "Unset", unset_desc),
            ]
        )
    else:
        actions.extend(
            [
                CatalogMenuAction("b", "Block", "Add to block list"),
                CatalogMenuAction("a", "Allow", "Add to allow list"),
            ]
        )
    return tuple(actions)


def plugin_actions(verdict: str, status: str, enabled: bool) -> tuple[CatalogMenuAction, ...]:
    actions = [
        CatalogMenuAction("s", "Scan", "Run security scan"),
        CatalogMenuAction("i", "Info", "Show full details"),
    ]
    if verdict == "blocked":
        actions.append(CatalogMenuAction("u", "Unblock", "Remove from block list (runs plugin allow)"))
    elif verdict == "allowed":
        actions.append(CatalogMenuAction("b", "Block", "Add to install block list"))
    else:
        actions.extend(
            [
                CatalogMenuAction("b", "Block", "Add to install block list"),
                CatalogMenuAction("a", "Allow", "Add to install allow list"),
            ]
        )

    if enabled:
        actions.append(CatalogMenuAction("d", "Disable", "Disable at runtime (gateway RPC)"))
    else:
        actions.append(CatalogMenuAction("e", "Enable", "Enable at runtime (gateway RPC)"))

    if "quarantine" in status.lower():
        actions.append(CatalogMenuAction("r", "Restore", "Restore from quarantine"))
    else:
        actions.append(CatalogMenuAction("q", "Quarantine", "Move files to quarantine dir"))

    actions.append(CatalogMenuAction("x", "Remove", "Delete plugin files from disk"))
    return tuple(actions)


def tool_actions(status: str) -> tuple[CatalogMenuAction, ...]:
    actions = [CatalogMenuAction("i", "Info", "Show full details")]
    if status == "blocked":
        actions.extend(
            [
                CatalogMenuAction("u", "Unblock", "Remove from block/allow list"),
                CatalogMenuAction("a", "Allow", "Pin as allow-listed"),
            ]
        )
    elif status == "allowed":
        actions.extend(
            [
                CatalogMenuAction("u", "Unblock", "Remove from block/allow list"),
                CatalogMenuAction("b", "Block", "Add to tool block list"),
            ]
        )
    else:
        actions.extend(
            [
                CatalogMenuAction("b", "Block", "Add to tool block list"),
                CatalogMenuAction("a", "Allow", "Pin as allow-listed"),
            ]
        )
    return tuple(actions)


# Verb keys whose CLI subcommand accepts ``--connector``. In a filtered or
# merged multi-connector table, row actions should target the selected
# connector instead of writing an accidental global policy row.
_SKILL_CONNECTOR_VERBS = frozenset(
    {"s", "i", "b", "a", "u", "d", "e", "q", "r", "n"}
)
_MCP_CONNECTOR_VERBS = frozenset({"s", "i", "b", "a", "u", "x"})
_PLUGIN_CONNECTOR_VERBS = frozenset({"s", "i", "b", "a", "u", "d", "e", "q", "r", "x"})


def skill_action_intent(
    key: str, row: SkillRow, *, origin: str, connector: str = ""
) -> CatalogCommandIntent | None:
    verbs = {
        "s": ("scan", "scan skill"),
        "i": ("info", "info skill"),
        "b": ("block", "block skill"),
        "a": ("allow", "allow skill"),
        "u": ("unblock", "unblock skill"),
        "d": ("disable", "disable skill"),
        "e": ("enable", "enable skill"),
        "q": ("quarantine", "quarantine skill"),
        "r": ("restore", "restore skill"),
        "n": ("install", "install skill"),
    }
    if key not in verbs:
        return None
    verb, label_prefix = verbs[key]
    args = ["skill", verb, row.name]
    if connector and key in _SKILL_CONNECTOR_VERBS:
        args.extend(("--connector", connector))
    return CatalogCommandIntent(
        label=f"{label_prefix} {row.name}",
        args=tuple(args),
        origin=origin,
    )


def mcp_action_intent(
    key: str, row: MCPRow, *, origin: str, connector: str = ""
) -> CatalogCommandIntent | None:
    verbs = {
        "s": ("scan", "scan mcp"),
        "i": ("list", "list mcp"),
        "b": ("block", "block mcp"),
        "a": ("allow", "allow mcp"),
        "u": ("unblock", "unblock mcp"),
        "x": ("unset", "unset mcp"),
    }
    if key not in verbs:
        return None
    verb, label_prefix = verbs[key]
    args = ["mcp", "list"] if key == "i" else ["mcp", verb, row.name]
    label = label_prefix if key == "i" else f"{label_prefix} {row.name}"
    if connector and key in _MCP_CONNECTOR_VERBS:
        args.extend(("--connector", connector))
    return CatalogCommandIntent(label=label, args=tuple(args), origin=origin)


def plugin_direct_scan_intent(row: PluginRow, connector: str = "") -> CatalogCommandIntent:
    target = row.id
    args = ["plugin", "scan", target]
    if connector:
        args.extend(("--connector", connector))
    return CatalogCommandIntent(
        label=f"scan plugin {target}",
        args=tuple(args),
        origin="plugins",
    )


def plugin_action_intent(
    key: str, row: PluginRow, *, origin: str, connector: str = ""
) -> CatalogCommandIntent | None:
    verbs = {
        "s": ("scan", "scan plugin"),
        "i": ("info", "info plugin"),
        "b": ("block", "block plugin"),
        "a": ("allow", "allow plugin"),
        "u": ("allow", "unblock plugin"),
        "d": ("disable", "disable plugin"),
        "e": ("enable", "enable plugin"),
        "q": ("quarantine", "quarantine plugin"),
        "r": ("restore", "restore plugin"),
        "x": ("remove", "remove plugin"),
    }
    if key not in verbs:
        return None
    verb, label_prefix = verbs[key]
    target = row.id
    args = ["plugin", verb, target]
    if connector and key in _PLUGIN_CONNECTOR_VERBS:
        args.extend(("--connector", connector))
    return CatalogCommandIntent(
        label=f"{label_prefix} {target}",
        args=tuple(args),
        origin=origin,
        # N1: plugin remove (``x``) deletes files from disk — flag it so the
        # dispatcher routes it through the destructive/consequence confirm.
        risk="destructive" if key == "x" else "read-only",
    )


def tool_action_intent(
    key: str, row: ToolRow, *, origin: str, connector: str = ""
) -> CatalogCommandIntent | None:
    verbs = {
        "i": ("status", "info tool"),
        "b": ("block", "block tool"),
        "a": ("allow", "allow tool"),
        "u": ("unblock", "unblock tool"),
    }
    if key not in verbs:
        return None
    verb, label_prefix = verbs[key]
    target = row.dispatch_target
    args = ["tool", verb, target]
    if connector:
        args.extend(("--connector", normalized_connector(connector)))
    return CatalogCommandIntent(
        label=f"{label_prefix} {target}",
        args=tuple(args),
        origin=origin,
    )


def mcp_unset_target_for_connector(connector: str) -> str:
    match normalized_connector(connector):
        case "claudecode":
            return "~/.claude/settings.json"
        case "codex":
            return "./.mcp.json"
        case "zeptoclaw":
            return "~/.zeptoclaw/config.json"
        case "hermes":
            return "~/.hermes/config.yaml"
        case "cursor":
            return "./.cursor/mcp.json"
        case "windsurf":
            return "~/.codeium/windsurf/mcp_config.json"
        case "geminicli":
            return "~/.gemini/settings.json"
        case "copilot":
            return "./.github/mcp.json"
        case "openhands":
            return "~/.openhands/mcp.json"
        case "antigravity":
            return "~/.gemini/config/mcp_config.json / <workspace>/.agents/mcp_config.json"
        case "omnigent":
            return "unsupported (OmniGent manages MCP configuration)"
        case _:
            return "OpenClaw config" if normalized_connector(connector) == "openclaw" else "connector MCP config"


def registry_attribution_from_rules(rules: Sequence[object] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for rule in rules or ():
        name = str(_get_attr(rule, "name", "Name"))
        source_id = parse_registry_source_id(str(_get_attr(rule, "reason", "Reason")))
        if name and source_id:
            out[name] = source_id
    return out


def parse_registry_source_id(reason: str) -> str:
    reason = reason.strip()
    prefix = "registry:"
    if not reason.startswith(prefix):
        return ""
    return reason.removeprefix(prefix).strip()


def friendly_connector_name(connector: str) -> str:
    match normalized_connector(connector):
        case "openclaw":
            return "OpenClaw"
        case "zeptoclaw":
            return "ZeptoClaw"
        case "claudecode":
            return "Claude Code"
        case "codex":
            return "Codex"
        case "hermes":
            return "Hermes"
        case "cursor":
            return "Cursor"
        case "windsurf":
            return "Windsurf"
        case "geminicli":
            return "Gemini CLI"
        case "copilot":
            return "GitHub Copilot CLI"
        case "openhands":
            return "OpenHands"
        case "antigravity":
            return "Antigravity"
        case "opencode":
            return "OpenCode"
        case "omnigent":
            return "OmniGent"
        case value:
            return value[:1].upper() + value[1:] if value else "No connector"


def connector_source_label(connector: str, category: str) -> str:
    connector = normalized_connector(connector)
    sources = {
        ("openclaw", "skills"): ("./skills", "~/.openclaw/skills"),
        ("claudecode", "skills"): ("~/.claude/skills", "./.claude/skills"),
        ("codex", "skills"): ("~/.codex/skills", "./.codex/skills"),
        ("zeptoclaw", "skills"): ("~/.zeptoclaw/skills", "./.zeptoclaw/skills"),
        ("antigravity", "skills"): (
            "~/.gemini/config/skills/<skill>/SKILL.md",
            "<workspace>/.agents/skills/<skill>/SKILL.md",
            "~/.gemini/antigravity-cli/skills/*.md (discovery-only)",
        ),
        ("omnigent", "skills"): ("unsupported by the OmniGent connector",),
        ("openclaw", "mcps"): ("openclaw config get mcp.servers", "openclaw.json (mcp.servers)"),
        ("claudecode", "mcps"): ("~/.claude/settings.json (mcpServers)", "./.mcp.json"),
        ("codex", "mcps"): ("~/.codex/config.toml ([mcp_servers])", "./.mcp.json"),
        ("zeptoclaw", "mcps"): ("~/.zeptoclaw/config.json (mcp.servers)", "./.mcp.json"),
        ("antigravity", "mcps"): (
            "~/.gemini/config/mcp_config.json",
            "<workspace>/.agents/mcp_config.json",
            "<plugin>/mcp_config.json (discovery-only)",
        ),
        ("omnigent", "mcps"): ("managed by OmniGent; not modified by DefenseClaw",),
        ("openclaw", "plugins"): ("~/.openclaw/extensions",),
        ("antigravity", "plugins"): (
            "~/.gemini/config/plugins/<plugin>/ (discovery-only)",
            "~/.gemini/antigravity-cli/plugins/<plugin>/ (discovery-only)",
            "<workspace>/.agents/plugins/<plugin>/ (discovery-only)",
        ),
        ("omnigent", "plugins"): ("unsupported by the OmniGent connector",),
        ("omnigent", "config"): ("$OMNIGENT_CONFIG_HOME/config.yaml or ~/.omnigent/config.yaml",),
    }
    return ", ".join(sources.get((connector, category), ()))


def normalized_connector(connector: str) -> str:
    return (connector or "").strip().lower()


def load_rows_from_command(
    args: Sequence[str],
    parser: Callable[[str], tuple[RowT, ...]],
    *,
    timeout: float = 15,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[RowT, ...]:
    """Run a Go-parity list command and parse its JSON output."""

    result = runner(
        ("defenseclaw", *args),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=True,
    )
    return parser(result.stdout)


def catalog_row_cells(row: object) -> tuple[str, str, str, str, str]:
    if isinstance(row, SkillRow):
        source = " ".join(part for part in (row.source, row.registry_badge) if part)
        detail = row.reason or row.description or row.verdict or row.severity
        return (row.name, row.status, source, row.actions, _truncate(detail, 72))
    if isinstance(row, MCPRow):
        source = " ".join(part for part in (row.transport, row.registry_badge) if part)
        detail = row.server_url or row.command or row.verdict or row.severity
        return (row.name, row.status, source, row.actions, _truncate(detail, 72))
    if isinstance(row, PluginRow):
        status = row.status or ("enabled" if row.enabled else "disabled")
        detail = row.description or row.origin or row.verdict
        return (row.display_name, status, row.origin, row.verdict or "-", _truncate(detail, 72))
    if isinstance(row, ToolRow):
        return (row.name, row.status, row.display_scope, "-", _truncate(row.reason, 72))
    return ("", "", "", "", "")


def catalog_detail_text(row: object | None) -> str:
    """Render the richer per-row detail pane shown below catalog tables.

    The layout groups facts into named sections so an operator can scan
    the pane top-to-bottom: identity → enforcement decisions → scan
    posture → provenance → quick action keys. Status, finding count,
    and severity are colorized so the eye lands on the riskiest rows
    first. The renderer keeps the contract narrow (input is the
    dataclass row, output is a Rich-markup string), so app.py and
    tests can both render without touching the screen.
    """

    if row is None:
        return ""
    if isinstance(row, SkillRow):
        return _format_skill_detail(row)
    if isinstance(row, MCPRow):
        return _format_mcp_detail(row)
    if isinstance(row, PluginRow):
        return _format_plugin_detail(row)
    if isinstance(row, ToolRow):
        return _format_tool_detail(row)
    return ""


# Severity → Rich color so HIGH/CRITICAL rows pop in the detail pane.
# Mirrors the palette used by the Alerts panel for consistency.
_SEVERITY_COLOR: Mapping[str, str] = {
    "CRITICAL": "#F87171",
    "HIGH": "#F87171",
    "MEDIUM": "#FBBF24",
    "LOW": "#22D3EE",
    "CLEAN": "#34D399",
    "": "",
}

# Status → Rich color. Anything outside this table renders in default
# color so we never bury unknown statuses behind a misleading badge.
_STATUS_COLOR: Mapping[str, str] = {
    "blocked": "#F87171",
    "rejected": "#F87171",
    "quarantined": "#F87171",
    "warning": "#FBBF24",
    "disabled": "#94A3B8",
    "removed": "#94A3B8",
    "inactive": "#94A3B8",
    "allowed": "#34D399",
    "active": "#34D399",
    "enabled": "#34D399",
}


def _colored(value: str, palette: Mapping[str, str]) -> str:
    """Return ``value`` wrapped in Rich color markup when the key is
    known. Unknown values fall through unstyled so we never emit an
    empty ``[#]`` tag (which Rich would render as a literal).
    """

    if not value:
        return "-"
    color = palette.get(value.upper(), palette.get(value, ""))
    return f"[{color}]{value}[/]" if color else value


def _format_severity(severity: str) -> str:
    return _colored(severity, _SEVERITY_COLOR)


def _format_status(status: str) -> str:
    return _colored(status, _STATUS_COLOR)


def _format_decisions(file_action: str, install_action: str, runtime_action: str) -> str:
    """Build a one-line summary of the three enforcement decisions.

    Each axis renders as ``axis=value`` (``-`` when the policy hasn't
    spoken) so the operator sees at a glance which knob is driving
    the current status, instead of guessing from the Actions column.
    """

    return (
        f"install={install_action or '-'}  "
        f"runtime={runtime_action or '-'}  "
        f"file={file_action or '-'}"
    )


_SEVERITY_BUCKET_LABEL: Mapping[str, str] = {
    "critical": "crit",
    "high": "high",
    "medium": "med",
    "low": "low",
    "info": "info",
}


def _format_severity_breakdown(counts: Mapping[str, int] | None) -> str:
    """Render a per-severity breakdown like ``crit 1 · high 2 · low 3``.

    E4i: only non-zero buckets are shown, in descending-severity order, each
    colored by its severity so a CRITICAL count pops the same way the
    ``max_severity`` badge does. Returns ``""`` when no counts are available
    (older CLI payloads) so ``_scan_line`` keeps its legacy shape.
    """

    if not counts:
        return ""
    segments: list[str] = []
    for bucket in SEVERITY_BUCKETS:
        count = int(counts.get(bucket, 0) or 0)
        if count <= 0:
            continue
        label = _SEVERITY_BUCKET_LABEL[bucket]
        color = _SEVERITY_COLOR.get(bucket.upper(), "")
        text = f"{label} {count}"
        segments.append(f"[{color}]{text}[/]" if color else text)
    return " ".join(segments)


def _scan_line(
    severity: str,
    total_findings: int,
    clean: bool,
    target: str,
    counts: Mapping[str, int] | None = None,
) -> str:
    """Render the scan posture as ``<severity> · N findings · <breakdown> · target=…``.

    ``CLEAN`` skips the findings count because there's nothing to
    surface; a dirty scan with zero findings (defensive) shows
    ``0 findings`` so the operator notices the inconsistency. When the
    payload carries a per-severity breakdown (E4i) it is rendered between
    the total and the target so the operator sees the severity mix at a
    glance instead of just the worst finding.
    """

    sev = (severity or "").upper() or ("CLEAN" if clean else "UNKNOWN")
    parts = [_format_severity(sev)]
    if not clean or total_findings > 0:
        suffix = "finding" if total_findings == 1 else "findings"
        parts.append(f"{total_findings} {suffix}")
    breakdown = _format_severity_breakdown(counts)
    if breakdown:
        parts.append(breakdown)
    if target:
        parts.append(f"target={target}")
    return " · ".join(parts)


def _format_skill_detail(row: SkillRow) -> str:
    lines = [
        f"[bold #22D3EE]Skill[/] {row.name}",
        f"  Status     {_format_status(row.status)}    Actions  {row.actions}",
        f"  Decisions  {_format_decisions(row.file_action, row.install_action, row.runtime_action)}",
        f"  Scan       {_scan_line(row.severity, row.total_findings, row.scan_clean, row.scan_target, row.severity_counts)}",
    ]
    if row.source:
        lines.append(f"  Source     {row.source}")
    if row.registry_badge:
        lines.append(f"  Registry   {row.registry_badge}")
    if row.description:
        lines.append("")
        lines.append(f"  {row.description}")
    if row.verdict and row.verdict not in {row.status, row.severity}:
        lines.append(f"  Verdict    {row.verdict}")
    if row.reason:
        lines.append(f"  Reason     {row.reason}")
    lines.append("")
    lines.append(_skill_action_legend(row.status))
    return "\n".join(lines)


def _format_mcp_detail(row: MCPRow) -> str:
    lines = [
        f"[bold #22D3EE]MCP[/] {row.name}",
        f"  Status     {_format_status(row.status)}    Actions  {row.actions}",
        f"  Decisions  {_format_decisions(row.file_action, row.install_action, row.runtime_action)}",
        f"  Transport  {row.transport or '-'}",
    ]
    if row.server_url:
        lines.append(f"  URL        {row.server_url}")
    if row.command:
        lines.append(f"  Command    {row.command}")
    if row.total_findings > 0 or row.severity or row.scan_target:
        lines.append(
            f"  Scan       {_scan_line(row.severity, row.total_findings, row.scan_clean, row.scan_target, row.severity_counts)}"
        )
    if row.registry_badge:
        lines.append(f"  Registry   {row.registry_badge}")
    if row.verdict and row.verdict not in {row.status, row.severity}:
        lines.append(f"  Verdict    {row.verdict}")
    if row.reason:
        lines.append(f"  Reason     {row.reason}")
    lines.append("")
    lines.append(_mcp_action_legend(row.status))
    return "\n".join(lines)


def _format_plugin_detail(row: PluginRow) -> str:
    status = row.status or ("enabled" if row.enabled else "disabled")
    enabled_label = "yes" if row.enabled else "no"
    lines = [
        f"[bold #22D3EE]Plugin[/] {row.display_name}",
        f"  Status     {_format_status(status)}    Enabled  {enabled_label}",
    ]
    if row.version:
        lines.append(f"  Version    {row.version}")
    if row.origin:
        lines.append(f"  Origin     {row.origin}")
    if row.scan is not None:
        # E4i: plugin scans carry the same per-severity breakdown; reuse
        # ``_scan_line`` (no target for plugins) so the rendering matches
        # skills/MCPs and surfaces the severity mix.
        lines.append(
            "  Scan       "
            + _scan_line(
                row.scan.max_severity,
                row.scan.total_findings,
                row.scan.clean,
                "",
                row.scan.severity_counts,
            )
        )
    if row.verdict and row.verdict not in {status, row.scan.max_severity if row.scan else ""}:
        lines.append(f"  Verdict    {row.verdict}")
    if row.description:
        lines.append("")
        lines.append(f"  {row.description}")
    lines.append("")
    lines.append(_plugin_action_legend(row.verdict, status, row.enabled))
    return "\n".join(lines)


def _format_tool_detail(row: ToolRow) -> str:
    lines = [
        f"[bold #22D3EE]Tool[/] {row.name}",
        f"  Status     {_format_status(row.status)}",
        f"  Scope      {row.display_scope}",
    ]
    if row.reason:
        lines.append(f"  Reason     {row.reason}")
    if row.target_name and row.target_name != row.name:
        lines.append(f"  Target     {row.target_name}")
    return "\n".join(lines)


def _action_legend(actions: tuple[CatalogMenuAction, ...]) -> str:
    """Return a one-line ``[s] Scan · [b] Block · …`` hint.

    Replaces the Go-era "press o for actions" mystery with the actual
    shortcut keys for the *current* row, so operators can act without
    opening the menu first. Disabled actions are dimmed so they read
    as "available but currently a no-op".
    """

    if not actions:
        return "  [dim]No actions available for this row.[/]"
    chunks: list[str] = []
    for action in actions:
        label = f"[{action.key}] {action.label}"
        chunks.append(f"[dim]{label}[/]" if action.disabled else label)
    return "  [dim]Actions:[/] " + "  ·  ".join(chunks)


def _skill_action_legend(status: str) -> str:
    return _action_legend(skill_actions(status))


def _mcp_action_legend(status: str) -> str:
    # Connector-specific labels (e.g. ``Unset`` target) need the active
    # connector. The caller passes "" here because the row doesn't
    # carry it; the model's ``menu_actions`` is still the source of
    # truth at action-menu open time, but the legend stays accurate
    # for the connector-independent keys (Scan / Info / Block / Allow).
    return _action_legend(mcp_actions(status, ""))


def _plugin_action_legend(verdict: str, status: str, enabled: bool) -> str:
    return _action_legend(plugin_actions(verdict, status, enabled))


def _truncate(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    if width <= 3:
        return value[:width]
    return value[: width - 3] + "..."


def _apply_skill_registry(rows: Sequence[SkillRow], attribution: Mapping[str, str]) -> tuple[SkillRow, ...]:
    return tuple(replace(row, registry_source=attribution.get(row.name, "")) for row in rows)


def _apply_mcp_registry(rows: Sequence[MCPRow], attribution: Mapping[str, str]) -> tuple[MCPRow, ...]:
    return tuple(replace(row, registry_source=attribution.get(row.name, "")) for row in rows)


def _decode_json_list(text: str, source: str) -> list[Mapping[str, Any]]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"parse {source}: {exc}") from exc
    if not isinstance(payload, list):
        raise ValueError(f"parse {source}: expected a JSON list")
    rows: list[Mapping[str, Any]] = []
    for item in payload:
        if not isinstance(item, Mapping):
            raise ValueError(f"parse {source}: expected list objects")
        rows.append(item)
    return rows


def _mapping_or_none(value: object) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _get_attr(obj: object | None, *names: str, default: Any = "") -> Any:
    if obj is None:
        return default
    if isinstance(obj, Mapping):
        for name in names:
            if name in obj:
                return obj[name]
        return default
    for name in names:
        if hasattr(obj, name):
            return getattr(obj, name)
    return default
