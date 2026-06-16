# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Pure Registries panel model for the Textual TUI migration."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any

from defenseclaw.tui.services.registry_cache import (
    RegistryEntryRow,
    SourceIndex,
    load_registry_index,
    registry_index_path,
)


class RegistriesTab(IntEnum):
    """Registries sub-tab indices, matching the Go TUI panel."""

    SOURCES = 0
    ENTRIES = 1
    APPROVED = 2


TAB_NAMES: tuple[str, ...] = ("Sources", "Entries", "Approved")


@dataclass(frozen=True)
class RegistryCommandIntent:
    """A mutation command the app shell can preview and dispatch."""

    label: str
    args: tuple[str, ...]
    hint: str = ""
    binary: str = "defenseclaw"
    category: str = "registries"

    @property
    def argv(self) -> tuple[str, ...]:
        return (self.binary, *self.args)


@dataclass(frozen=True)
class RegistryPanelAction:
    """Result of a panel-local key/action handler."""

    handled: bool
    intent: RegistryCommandIntent | None = None
    hint: str = ""


@dataclass(frozen=True)
class RegistryDetailInfo:
    """Full selected source/entry details for Textual detail panes."""

    title: str
    fields: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class RegistrySourceRow:
    """Source table row with cached index summary attached."""

    id: str
    kind: str = ""
    content: str = ""
    url: str = ""
    enabled: bool = True
    last_sync: str = ""
    last_status: str = ""
    fetched_at: str = ""
    publisher: str = ""
    entry_count: int = 0
    clean_count: int = 0
    warning_count: int = 0
    blocked_count: int = 0
    error_count: int = 0
    index_error: str = ""

    @property
    def enabled_label(self) -> str:
        return "yes" if self.enabled else "no"

    @property
    def status_label(self) -> str:
        if self.index_error:
            return f"cache error: {self.index_error}"
        return self.last_status or "-"


class RegistriesPanelModel:
    """State and parity helpers for the Registries panel.

    The full Textual widget can consume this model without owning any
    command execution. Key handlers return command intents as data.
    """

    def __init__(
        self,
        config: object | None = None,
        *,
        data_dir: str | Path | None = None,
        sources: tuple[object, ...] | list[object] | None = None,
    ) -> None:
        self.config = config
        self._explicit_sources = tuple(sources) if sources is not None else None
        self._explicit_data_dir = str(data_dir) if data_dir is not None else None
        self.data_dir = self._explicit_data_dir or _config_data_dir(config)
        self.current_tab = RegistriesTab.SOURCES
        self.cursor = 0
        self._filter_entry_key: tuple[str, str] | None = None
        self.sources: tuple[RegistrySourceRow, ...] = ()
        self.indexes: dict[str, SourceIndex] = {}
        self.index_errors: dict[str, str] = {}
        self.detail_open = False
        self.refresh()

    def set_config(self, config: object | None) -> None:
        """Late-bind the cached config after a setup-driven reload.

        Mirrors Go's ``m.registries.SetConfig(cfg)`` — without it the
        Sources tab keeps showing rows from the snapshot captured at
        startup even after ``defenseclaw setup registry add`` writes
        a new entry. The next :meth:`refresh` resolves the data_dir
        from the new config (unless explicitly overridden in __init__).
        """

        self.config = config
        if self._explicit_data_dir is None:
            self.data_dir = _config_data_dir(config)
        self.refresh()

    def refresh(self) -> None:
        """Reload source config and registry cache indexes."""

        if self._explicit_data_dir is None:
            self.data_dir = _config_data_dir(self.config)
        source_rows = tuple(sorted((_source_row(source) for source in self._source_objects()), key=lambda row: row.id))

        indexes: dict[str, SourceIndex] = {}
        errors: dict[str, str] = {}
        for row in source_rows:
            if not self.data_dir:
                errors[row.id] = "missing data_dir"
                continue
            try:
                indexes[row.id] = load_registry_index(self.data_dir, row.id)
            except FileNotFoundError:
                continue
            except Exception as exc:  # noqa: BLE001 - cache errors are rendered as panel state.
                errors[row.id] = str(exc)

        self.indexes = indexes
        self.index_errors = errors
        self.sources = tuple(_attach_index(row, indexes.get(row.id), errors.get(row.id, "")) for row in source_rows)
        self._clamp_cursor()

    def set_tab(self, tab: RegistriesTab | int) -> None:
        next_tab = RegistriesTab(tab)
        if next_tab != self.current_tab:
            self.cursor = 0
            self._filter_entry_key = None
            self.detail_open = False
        self.current_tab = next_tab
        self._clamp_cursor()

    def cursor_up(self) -> None:
        if self.cursor > 0:
            self.cursor -= 1

    def cursor_down(self) -> None:
        if self.cursor < self.row_count() - 1:
            self.cursor += 1

    def scroll_by(self, delta: int) -> None:
        self.cursor += delta
        self._clamp_cursor()

    def set_cursor(self, cursor: int) -> None:
        self.cursor = cursor
        self._clamp_cursor()

    def row_count(self) -> int:
        if self.current_tab == RegistriesTab.SOURCES:
            return len(self.sources)
        return len(self.visible_entries())

    def selected_source(self) -> RegistrySourceRow | None:
        if self.current_tab != RegistriesTab.SOURCES:
            return None
        if self.cursor < 0 or self.cursor >= len(self.sources):
            return None
        return self.sources[self.cursor]

    def selected_entry(self) -> RegistryEntryRow | None:
        if self.current_tab == RegistriesTab.SOURCES:
            return None
        rows = self.visible_entries()
        if self.cursor < 0 or self.cursor >= len(rows):
            return None
        return rows[self.cursor]

    def focus_entry(self, entry_type: str, name: str) -> bool:
        """Switch to Entries and focus a registry-backed Skills/MCP row."""

        self.current_tab = RegistriesTab.ENTRIES
        self._filter_entry_key = None
        for row in self._entry_rows(apply_focus_filter=False):
            if row.type == entry_type and row.name == name:
                self._filter_entry_key = (entry_type, name)
                filtered = self.visible_entries()
                for index, filtered_row in enumerate(filtered):
                    if filtered_row.type == entry_type and filtered_row.name == name:
                        self.cursor = index
                        return True
                self.cursor = 0
                return True
        self.cursor = 0
        return False

    def visible_entries(self) -> tuple[RegistryEntryRow, ...]:
        rows = self._entry_rows(apply_focus_filter=True)
        if self.current_tab == RegistriesTab.APPROVED:
            rows = tuple(row for row in rows if row.approved)
        return rows

    def handle_key(self, key: str) -> RegistryPanelAction:
        if key == "1":
            self.set_tab(RegistriesTab.SOURCES)
            return RegistryPanelAction(True)
        if key == "2":
            self.set_tab(RegistriesTab.ENTRIES)
            return RegistryPanelAction(True)
        if key == "3":
            self.set_tab(RegistriesTab.APPROVED)
            return RegistryPanelAction(True)
        if key == "enter":
            if self.row_count() == 0:
                return RegistryPanelAction(True, hint="(no registry row selected)")
            self.detail_open = True
            return RegistryPanelAction(True)
        if key in {"esc", "escape", "q"} and self.detail_open:
            self.detail_open = False
            return RegistryPanelAction(True)
        if key == "r":
            self.refresh()
            return RegistryPanelAction(True, hint="Refreshed.")
        if key == "s":
            source_id = self._cursor_source_id()
            if not source_id:
                return RegistryPanelAction(True, hint="(no source selected)")
            return RegistryPanelAction(True, sync_source_intent(source_id))
        if key == "S":
            return RegistryPanelAction(True, sync_all_intent())
        if key == "a":
            row = self.selected_entry()
            if row is None:
                return RegistryPanelAction(True, hint="(no entry selected)")
            return RegistryPanelAction(True, approve_entry_intent(row))
        if key == "x":
            row = self.selected_entry()
            if row is None:
                return RegistryPanelAction(True, hint="(no entry selected)")
            return RegistryPanelAction(True, reject_entry_intent(row))
        if key == "R":
            # E4h: toggle asset_policy.<type>.registry_required for the
            # selected entry's asset type (parity with `registry require`).
            row = self.selected_entry()
            if row is None:
                return RegistryPanelAction(True, hint="(no entry selected)")
            if row.type not in {"skill", "mcp"}:
                return RegistryPanelAction(True, hint="(registry require supports skill/mcp only)")
            return RegistryPanelAction(
                True,
                require_entry_intent(row, currently_required=self._registry_required(row.type)),
            )
        if key == "d":
            if self.current_tab != RegistriesTab.SOURCES:
                return RegistryPanelAction(False)
            source = self.selected_source()
            if source is None:
                return RegistryPanelAction(True, hint="(no source selected)")
            return RegistryPanelAction(True, remove_source_intent(source.id))
        return RegistryPanelAction(False)

    def data_table_columns(self) -> tuple[str, ...]:
        if self.current_tab == RegistriesTab.SOURCES:
            return ("ID", "Kind", "Content", "On", "Last Sync", "Status", "Entries", "Clean", "Warn", "Block", "Error")
        return ("Source", "Name", "Type", "Status", "Severity", "A/R", "Location")

    def data_table_rows(self) -> tuple[tuple[str, ...], ...]:
        if self.current_tab == RegistriesTab.SOURCES:
            return tuple(
                (
                    row.id,
                    row.kind,
                    row.content,
                    row.enabled_label,
                    row.last_sync or "(never)",
                    row.status_label,
                    str(row.entry_count),
                    str(row.clean_count),
                    str(row.warning_count),
                    str(row.blocked_count),
                    str(row.error_count),
                )
                for row in self.sources
            )
        return tuple(
            (
                row.source_id,
                row.name,
                row.type,
                row.status or "-",
                row.severity or "-",
                row.approval_marker,
                row.location,
            )
            for row in self.visible_entries()
        )

    def empty_state(self) -> str:
        if self.row_count() > 0:
            return ""
        if self.current_tab == RegistriesTab.SOURCES:
            return "No registry sources configured. Run `defenseclaw registry add` or use the Setup wizard."
        if self.current_tab == RegistriesTab.APPROVED:
            return "No entries approved yet. Press 'a' on the Entries tab to approve one."
        return "Sync a source to populate this view."

    def selected_detail_info(self) -> RegistryDetailInfo | None:
        if self.current_tab == RegistriesTab.SOURCES:
            source = self.selected_source()
            return source_detail_info(source, self.data_dir) if source is not None else None
        entry = self.selected_entry()
        return entry_detail_info(entry) if entry is not None else None

    def _entry_rows(self, *, apply_focus_filter: bool) -> tuple[RegistryEntryRow, ...]:
        rows: list[RegistryEntryRow] = []
        for source in self.sources:
            index = self.indexes.get(source.id)
            if index is None:
                continue
            rows.extend(index.verdicts)
        if apply_focus_filter and self._filter_entry_key is not None:
            entry_type, name = self._filter_entry_key
            rows = [row for row in rows if row.type == entry_type and row.name == name]
        return tuple(rows)

    def _registry_required(self, asset_type: str) -> bool:
        """Read ``asset_policy.<type>.registry_required`` from the cached config.

        Tolerant of a missing/partial config (None → False) so the require
        toggle still produces a sensible ``--enabled`` intent on a fresh
        install where the asset-policy block hasn't been materialized yet.
        """
        asset_policy = _get_attr(self.config, "asset_policy", "AssetPolicy", default=None)
        target = _get_attr(asset_policy, asset_type, asset_type.capitalize(), default=None)
        return bool(_get_attr(target, "registry_required", "RegistryRequired", default=False))

    def _cursor_source_id(self) -> str:
        if self.current_tab == RegistriesTab.SOURCES:
            source = self.selected_source()
            return source.id if source is not None else ""
        entry = self.selected_entry()
        return entry.source_id if entry is not None else ""

    def _clamp_cursor(self) -> None:
        max_cursor = self.row_count() - 1
        if max_cursor < 0:
            self.cursor = 0
            return
        if self.cursor < 0:
            self.cursor = 0
        elif self.cursor > max_cursor:
            self.cursor = max_cursor

    def _source_objects(self) -> tuple[object, ...]:
        if self._explicit_sources is not None:
            return self._explicit_sources
        registries = _get_attr(self.config, "registries", "Registries")
        sources = _get_attr(registries, "sources", "Sources", default=())
        return tuple(sources or ())


def sync_source_intent(source_id: str) -> RegistryCommandIntent:
    return RegistryCommandIntent(
        label=f"registry sync {source_id}",
        args=("registry", "sync", source_id, "--json"),
        hint=f"Syncing {source_id} ...",
    )


def sync_all_intent() -> RegistryCommandIntent:
    return RegistryCommandIntent(
        label="registry sync --all",
        args=("registry", "sync", "--all", "--json"),
        hint="Syncing all enabled sources ...",
    )


def approve_entry_intent(row: RegistryEntryRow) -> RegistryCommandIntent:
    return RegistryCommandIntent(
        label=f"registry approve {row.source_id} {row.name}",
        args=("registry", "approve", row.source_id, row.name, "--type", row.type, "--json"),
        hint=f"Approving {row.name}",
    )


def reject_entry_intent(row: RegistryEntryRow) -> RegistryCommandIntent:
    return RegistryCommandIntent(
        label=f"registry reject {row.source_id} {row.name}",
        args=("registry", "reject", row.source_id, row.name, "--type", row.type, "--json"),
        hint=f"Rejecting {row.name}",
    )


def remove_source_intent(source_id: str) -> RegistryCommandIntent:
    return RegistryCommandIntent(
        label=f"registry remove {source_id}",
        args=("registry", "remove", source_id, "--non-interactive", "--json"),
        hint=f"Removing {source_id}",
    )


def require_entry_intent(row: RegistryEntryRow, *, currently_required: bool) -> RegistryCommandIntent:
    """Toggle ``asset_policy.<type>.registry_required`` for the row's asset type (E4h).

    Parity with the ``registry require`` CLI (``cmd_registry.py``): the TUI
    already exposes approve (``a``) / reject (``x``) but had no way to arm or
    relax the registry-required default-deny — a security-relevant lever. The
    flag mirrors the row's current state so the key acts as a toggle:
    ``--disabled`` when the requirement is already armed, ``--enabled``
    otherwise. ``registry require`` only supports skill/mcp (the sync/promote
    pipeline never populates the plugin registry), so the caller gates on the
    asset type before building this intent.
    """
    flag = "--disabled" if currently_required else "--enabled"
    state = "optional" if currently_required else "required"
    return RegistryCommandIntent(
        label=f"registry require --type {row.type} {flag}",
        args=("registry", "require", "--type", row.type, flag, "--json"),
        hint=f"Marking {row.type} registry {state}",
    )


def registry_badge(source_id: str, *, max_id_chars: int = 18) -> str:
    source = source_id.strip()
    if not source:
        return ""
    if len(source) > max_id_chars:
        source = source[: max(0, max_id_chars - 3)] + "..."
    return f"registry:{source}"


def source_detail_info(source: RegistrySourceRow, data_dir: str | Path | None = None) -> RegistryDetailInfo:
    fields: list[tuple[str, str]] = [
        ("Source ID", source.id),
        ("Kind", source.kind),
        ("Content", source.content),
        ("Enabled", source.enabled_label),
    ]
    if source.url:
        fields.append(("URL", source.url))
    fields.extend(
        (
            ("Last Sync", source.last_sync or "(never)"),
            ("Status", source.status_label),
            ("Fetched At", source.fetched_at or "-"),
            ("Publisher", source.publisher or "-"),
            ("Entries", str(source.entry_count)),
            ("Clean", str(source.clean_count)),
            ("Warnings", str(source.warning_count)),
            ("Blocked", str(source.blocked_count)),
            ("Errors", str(source.error_count)),
        )
    )
    if source.index_error:
        fields.append(("Index Error", source.index_error))
    if data_dir:
        try:
            fields.append(("Cache Path", str(registry_index_path(data_dir, source.id))))
        except Exception as exc:  # noqa: BLE001 - detail view should surface unsafe configured IDs.
            fields.append(("Cache Safety", str(exc)))
    return RegistryDetailInfo(f"SOURCE: {source.id}", tuple(fields))


def entry_detail_info(entry: RegistryEntryRow) -> RegistryDetailInfo:
    fields: list[tuple[str, str]] = [
        ("Source ID", entry.source_id),
        ("Name", entry.name),
        ("Type", entry.type),
        ("Status", entry.status or "-"),
        ("Severity", entry.severity or "-"),
        ("Findings", str(entry.findings)),
        ("Approved", "yes" if entry.approved else "no"),
        ("Rejected", "yes" if entry.rejected else "no"),
        ("Transport", entry.transport or "-"),
    ]
    if entry.command:
        fields.append(("Command", entry.command))
    if entry.args:
        fields.append(("Args", " ".join(entry.args)))
    if entry.url:
        fields.append(("URL", entry.url))
    if entry.source_url:
        fields.append(("Source URL", entry.source_url))
    if entry.location:
        fields.append(("Location", entry.location))
    return RegistryDetailInfo(f"{entry.type.upper()}: {entry.name}", tuple(fields))


def _attach_index(row: RegistrySourceRow, index: SourceIndex | None, index_error: str) -> RegistrySourceRow:
    if index is None:
        return RegistrySourceRow(
            id=row.id,
            kind=row.kind,
            content=row.content,
            url=row.url,
            enabled=row.enabled,
            last_sync=row.last_sync,
            last_status=row.last_status,
            index_error=index_error,
        )
    return RegistrySourceRow(
        id=row.id,
        kind=row.kind,
        content=row.content,
        url=row.url,
        enabled=row.enabled,
        last_sync=row.last_sync,
        last_status=row.last_status,
        fetched_at=index.fetched_at,
        publisher=index.publisher,
        entry_count=index.entry_count,
        clean_count=index.clean_count,
        warning_count=index.warning_count,
        blocked_count=index.blocked_count,
        error_count=index.error_count,
        index_error=index_error,
    )


def _source_row(source: object) -> RegistrySourceRow:
    return RegistrySourceRow(
        id=str(_get_attr(source, "id", "ID")),
        kind=str(_get_attr(source, "kind", "Kind")),
        content=str(_get_attr(source, "content", "Content")),
        url=str(_get_attr(source, "url", "URL")),
        enabled=bool(_get_attr(source, "enabled", "Enabled", default=True)),
        last_sync=str(_get_attr(source, "last_sync", "LastSync")),
        last_status=str(_get_attr(source, "last_status", "LastStatus")),
    )


def _config_data_dir(config: object | None) -> str:
    return str(_get_attr(config, "data_dir", "DataDir"))


def _get_attr(obj: object | None, *names: str, default: Any = "") -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        for name in names:
            if name in obj:
                return obj[name]
        return default
    for name in names:
        if hasattr(obj, name):
            return getattr(obj, name)
    return default
