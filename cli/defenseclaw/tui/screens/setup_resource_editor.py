# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Native Setup editors for canonical destinations and webhooks."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Static

from defenseclaw.observability.v8_status import V8OperatorStatus
from defenseclaw.tui.theme import DEFAULT_TOKENS

TOKENS = DEFAULT_TOKENS
ResourceKind = Literal["observability", "webhooks"]


@dataclass(frozen=True)
class SetupResourceRow:
    """One editable setup resource row."""

    name: str
    kind: str
    endpoint: str
    enabled: bool
    signals: str = ""
    buckets: str = ""
    redaction: str = ""


@dataclass(frozen=True)
class SetupResourceResult:
    """Action returned by the setup resource editor."""

    action: str
    binary: str = "defenseclaw"
    args: tuple[str, ...] = ()
    display_name: str = ""
    category: str = "setup"
    opens_wizard: str = ""
    hint: str = ""


class SetupResourceEditorScreen(ModalScreen[SetupResourceResult | None]):
    """Rounded native editor for resource-list Setup sections."""

    CSS = f"""
    SetupResourceEditorScreen {{
        align: center middle;
    }}

    #resource-editor-dialog {{
        width: 116;
        height: 30;
        padding: 1 2;
        border: round {TOKENS.border_active};
        background: {TOKENS.surface_panel};
        color: {TOKENS.text_primary};
    }}

    #resource-editor-title {{
        height: 1;
        margin-bottom: 1;
        color: {TOKENS.accent_cyan};
        text-style: bold;
    }}

    #resource-editor-table {{
        height: 18;
        margin-bottom: 1;
    }}

    #resource-editor-status {{
        height: 2;
        color: {TOKENS.text_secondary};
    }}

    #resource-editor-buttons {{
        height: 3;
        align-horizontal: right;
    }}

    #resource-editor-buttons Button {{
        margin-left: 1;
    }}
    """

    BINDINGS = [
        Binding("escape,q", "cancel", "Close", show=False),
        Binding("a", "add", "Add", show=False),
        Binding("e", "enable", "Enable", show=False),
        Binding("d", "disable", "Disable", show=False),
        Binding("r", "remove", "Remove", show=False),
        Binding("t", "test", "Test", show=False),
        Binding("s", "show", "Show", show=False),
        Binding("enter", "default", "Default", show=False),
    ]

    def __init__(self, resource_kind: ResourceKind, rows: Sequence[SetupResourceRow]) -> None:
        super().__init__()
        self.resource_kind = resource_kind
        self.rows = tuple(rows)
        self.cursor = 0

    @property
    def dialog_title(self) -> str:
        if self.resource_kind == "observability":
            return "Observability Destinations"
        return "Webhooks Editor"

    def compose(self) -> ComposeResult:
        with Vertical(id="resource-editor-dialog"):
            yield Static(self.dialog_title, id="resource-editor-title")
            yield DataTable(id="resource-editor-table", cursor_type="row", zebra_stripes=True)
            yield Static(self._status_text(), id="resource-editor-status")
            with Horizontal(id="resource-editor-buttons"):
                yield Button("Add", id="resource-add", variant="primary")
                yield Button("Enable", id="resource-enable", variant="success")
                yield Button("Disable", id="resource-disable", variant="warning")
                yield Button("Test", id="resource-test", variant="default")
                if self.resource_kind == "webhooks":
                    yield Button("Show", id="resource-show", variant="default")
                yield Button("Remove", id="resource-remove", variant="error")
                yield Button("Close", id="resource-close", variant="default")

    def on_mount(self) -> None:
        table = self.query_one("#resource-editor-table", DataTable)
        table.add_columns("Name", "Kind", "State", "Signals", "Redaction", "Buckets", "Endpoint")
        for row in self.rows:
            table.add_row(
                row.name,
                row.kind,
                "enabled" if row.enabled else "disabled",
                row.signals or "—",
                row.redaction or "—",
                row.buckets or "—",
                row.endpoint,
            )
        if self.rows:
            table.move_cursor(row=0, column=0, animate=False)
        table.focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_add(self) -> None:
        wizard = "observability" if self.resource_kind == "observability" else "webhooks"
        label = "Observability" if wizard == "observability" else "Webhook"
        self.dismiss(SetupResourceResult("add", opens_wizard=wizard, hint=f"{label} setup wizard opened."))

    def action_enable(self) -> None:
        self._dispatch_row_action("enable")

    def action_disable(self) -> None:
        self._dispatch_row_action("disable")

    def action_remove(self) -> None:
        self._dispatch_row_action("remove")

    def action_test(self) -> None:
        self._dispatch_row_action("test")

    def action_show(self) -> None:
        if self.resource_kind != "webhooks":
            self._set_status("Destination details are shown in the table.")
            return
        self._dispatch_row_action("show")

    def action_default(self) -> None:
        if self.resource_kind == "webhooks":
            # Webhooks default to a read-only ``show`` — safe on Enter/click.
            self.action_show()
            return
        # Destinations: Enter / row-click must NOT fire a live outbound test
        # (that's a real network call). Activating only selects; testing
        # stays behind the explicit ``t`` / Test button so a reflexive Enter
        # can't trigger an outbound request.
        self._set_status("Press t (or the Test button) to send a test event to the selected sink.")

    @on(DataTable.RowHighlighted, "#resource-editor-table")
    def _on_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self.cursor = event.cursor_row

    @on(DataTable.RowSelected, "#resource-editor-table")
    def _on_row_selected(self, event: DataTable.RowSelected) -> None:
        self.cursor = event.cursor_row
        self.action_default()

    @on(Button.Pressed)
    def _on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        match event.button.id:
            case "resource-add":
                self.action_add()
            case "resource-enable":
                self.action_enable()
            case "resource-disable":
                self.action_disable()
            case "resource-test":
                self.action_test()
            case "resource-show":
                self.action_show()
            case "resource-remove":
                self.action_remove()
            case "resource-close":
                self.action_cancel()

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:
            event.stop()
            self.dismiss(None)

    def _dispatch_row_action(self, action: str) -> None:
        row = self._selected_row()
        if row is None:
            self._set_status("No resource is selected.")
            return
        if action == "enable" and row.enabled:
            self._set_status(f"{row.name} is already enabled.")
            return
        if action == "disable" and not row.enabled:
            self._set_status(f"{row.name} is already disabled.")
            return

        args = _command_args(self.resource_kind, action, row.name)
        display = " ".join(args)
        self.dismiss(SetupResourceResult(action, args=args, display_name=display))

    def _selected_row(self) -> SetupResourceRow | None:
        if not self.rows:
            return None
        return self.rows[max(0, min(self.cursor, len(self.rows) - 1))]

    def _set_status(self, message: str) -> None:
        self.query_one("#resource-editor-status", Static).update(message)

    def _status_text(self) -> str:
        if self.resource_kind == "observability":
            return "a add · e enable · d disable · t test · r remove · Enter select · Esc close"
        return "a add · e enable · d disable · s show · t test · r remove · Enter show · Esc close"


def observability_rows_from_status(status: V8OperatorStatus | None) -> tuple[SetupResourceRow, ...]:
    """Build secret-free destination rows from the compiler-owned v8 plan."""

    if status is None:
        return ()
    return tuple(
        SetupResourceRow(
            name=destination.name,
            kind=destination.kind,
            endpoint=destination.endpoint,
            enabled=destination.enabled,
            signals=",".join(destination.selected_signals),
            buckets=",".join(destination.buckets),
            redaction=destination.redaction_label,
        )
        for destination in status.destinations
    )


def webhook_rows_from_config(config: object | Mapping[str, Any] | None) -> tuple[SetupResourceRow, ...]:
    """Build Webhook editor rows from the loaded config object."""

    rows: list[SetupResourceRow] = []
    for index, hook in enumerate(_sequence(_config_value(config, "webhooks", ()))):
        kind = str(_value(hook, "type", "webhook") or "webhook")
        name = str(_value(hook, "name", "") or f"{kind}[{index}]")
        rows.append(
            SetupResourceRow(
                name=name,
                kind=kind,
                endpoint=str(_value(hook, "url", "") or ""),
                enabled=bool(_value(hook, "enabled", False)),
            )
        )
    return tuple(rows)


def _command_args(resource_kind: ResourceKind, action: str, name: str) -> tuple[str, ...]:
    if resource_kind == "observability":
        args = ("setup", "observability", action, name)
    else:
        args = ("setup", "webhook", action, name)
    if action == "remove":
        return (*args, "--yes")
    return args


def _config_value(config: object | Mapping[str, Any] | None, path: str, default: object = None) -> object:
    current: object = config if config is not None else {}
    for part in path.split("."):
        if isinstance(current, Mapping):
            current = current.get(part, default)
        else:
            current = getattr(current, part, default)
        if current is default:
            return default
    return current


def _sequence(value: object) -> tuple[object, ...]:
    if value is None:
        return ()
    if isinstance(value, tuple):
        return value
    if isinstance(value, list):
        return tuple(value)
    return ()


def _value(item: object, key: str, default: object = "") -> object:
    if isinstance(item, Mapping):
        return item.get(key, default)
    return getattr(item, key, default)
