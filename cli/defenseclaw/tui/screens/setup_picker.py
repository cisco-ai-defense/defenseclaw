# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""A short, scrolling picker for the Setup config editor.

``g`` shows every config section under its group and ``/`` finds a field
by name or key across all sections. Both use :class:`SetupPickerScreen`:
rows are :class:`~defenseclaw.tui.panels.setup_catalog.PickerRow` values,
group headers are skipped by the cursor, only a window of rows around the
cursor is drawn so the dialog fits an 80x24 terminal, and the screen
dismisses with the chosen row id (or None).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from rich.markup import escape as rich_escape
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, Static

from defenseclaw.tui.panels.setup_catalog import PickerRow
from defenseclaw.tui.theme import DEFAULT_TOKENS

RowSource = Callable[[str], Sequence[PickerRow]]


def first_selectable(rows: Sequence[PickerRow], start: int = 0, step: int = 1) -> int | None:
    """Index of the first selectable row from ``start`` going ``step``."""

    index = start
    while 0 <= index < len(rows):
        if rows[index].selectable:
            return index
        index += step
    return None


def move_selection(rows: Sequence[PickerRow], current: int | None, delta: int) -> int | None:
    """Next selectable row in direction ``delta``, wrapping at the ends."""

    selectable = [index for index, row in enumerate(rows) if row.selectable]
    if not selectable:
        return None
    if current not in selectable:
        return selectable[0] if delta >= 0 else selectable[-1]
    position = selectable.index(current)
    return selectable[(position + delta) % len(selectable)]


def visible_window(total: int, selected: int | None, height: int) -> tuple[int, int]:
    """``(start, end)`` of the rows to draw so ``selected`` stays in view."""

    height = max(1, height)
    if total <= height:
        return (0, total)
    anchor = selected or 0
    start = max(0, min(anchor - height // 2, total - height))
    return (start, start + height)


class SetupPickerScreen(ModalScreen[str | None]):
    """Pick one row; with ``filterable`` a text box narrows the rows."""

    CSS = f"""
    SetupPickerScreen {{
        align: center middle;
    }}

    #setup-picker-dialog {{
        width: 76;
        max-width: 96%;
        height: auto;
        max-height: 96%;
        padding: 0 2;
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_panel};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #setup-picker-title {{
        height: 1;
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    #setup-picker-input {{
        margin: 0;
        border: tall {DEFAULT_TOKENS.border_active};
    }}

    #setup-picker-list {{
        height: auto;
    }}

    #setup-picker-hint {{
        height: 1;
        color: {DEFAULT_TOKENS.text_secondary};
    }}
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
        Binding("up", "cursor_up", "Up", show=False),
        Binding("down", "cursor_down", "Down", show=False),
        Binding("enter", "choose", "Choose", show=False),
    ]

    def __init__(
        self,
        title: str,
        rows: RowSource | Sequence[PickerRow],
        *,
        filterable: bool = False,
        placeholder: str = "Type to filter…",
        selected_id: str = "",
        hint: str = "",
    ) -> None:
        super().__init__()
        self._title = title
        self._source: RowSource = rows if callable(rows) else (lambda _query, _rows=tuple(rows): _rows)
        self._filterable = filterable
        self._placeholder = placeholder
        self._hint = hint or (
            "↑/↓ move · Enter open · Esc close · type to filter" if filterable else "↑/↓ move · Enter open · Esc close"
        )
        self.rows: tuple[PickerRow, ...] = tuple(self._source(""))
        self.selected: int | None = next(
            (index for index, row in enumerate(self.rows) if row.selectable and row.row_id == selected_id),
            first_selectable(self.rows),
        )
        self._window: tuple[int, int] = (0, 0)

    def compose(self) -> ComposeResult:
        with Vertical(id="setup-picker-dialog"):
            yield Static(rich_escape(self._title), id="setup-picker-title")
            if self._filterable:
                yield Input(placeholder=self._placeholder, id="setup-picker-input")
            yield Static("", id="setup-picker-list")
            yield Static(rich_escape(self._hint), id="setup-picker-hint")

    def on_mount(self) -> None:
        self._refresh_list()
        if self._filterable:
            self.query_one(Input).focus()

    def _list_height(self) -> int:
        # Title, hint, borders and (when filtering) the input box.
        chrome = 4 + (3 if self._filterable else 0)
        return max(3, int(self.app.size.height * 0.96) - chrome)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "setup-picker-input":
            return
        self.rows = tuple(self._source(event.value))
        self.selected = first_selectable(self.rows)
        self._refresh_list()

    def on_key(self, event: events.Key) -> None:
        # Without a filter box, j/k move too.
        if not self._filterable and event.key in {"j", "k"}:
            event.stop()
            self._move(1 if event.key == "j" else -1)

    def action_cursor_up(self) -> None:
        self._move(-1)

    def action_cursor_down(self) -> None:
        self._move(1)

    def _move(self, delta: int) -> None:
        self.selected = move_selection(self.rows, self.selected, delta)
        self._refresh_list()

    def action_choose(self) -> None:
        if self.selected is None or not (0 <= self.selected < len(self.rows)):
            return
        self.dismiss(self.rows[self.selected].row_id)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:
            event.stop()
            self.dismiss(None)
            return
        try:
            target = self.query_one("#setup-picker-list", Static)
        except Exception:  # noqa: BLE001 - dialog tearing down
            return
        if event.widget is not target:
            return
        offset = event.get_content_offset(target)
        if offset is None:
            return
        index = self._window[0] + offset.y
        if 0 <= index < len(self.rows) and self.rows[index].selectable:
            event.stop()
            self.selected = index
            self.action_choose()

    def _refresh_list(self) -> None:
        target = self.query_one("#setup-picker-list", Static)
        if not self.rows:
            target.update(f"[{DEFAULT_TOKENS.text_muted}]Nothing matches.[/]")
            self._window = (0, 0)
            return
        start, end = visible_window(len(self.rows), self.selected, self._list_height())
        self._window = (start, end)
        lines: list[str] = []
        for index in range(start, end):
            row = self.rows[index]
            if not row.selectable:
                lines.append(f"[bold {DEFAULT_TOKENS.accent_amber}]{rich_escape(row.label)}[/]")
                continue
            marker = "›" if index == self.selected else " "
            style = f"bold {DEFAULT_TOKENS.accent_cyan}" if index == self.selected else DEFAULT_TOKENS.text_primary
            detail = f"  [{DEFAULT_TOKENS.text_muted}]{rich_escape(row.detail)}[/]" if row.detail else ""
            lines.append(f"{marker} " + "[" + style + "]" + rich_escape(row.label) + f"[/]{detail}")
        target.update("\n".join(lines))


__all__ = ["SetupPickerScreen", "first_selectable", "move_selection", "visible_window"]
