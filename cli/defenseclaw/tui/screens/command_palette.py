# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Phase 12: Ctrl+K command palette modal.

Pure presentation layer. The catalogue lives in
``creator/command_palette.py``; the dispatch (turning a returned
Command into a state mutation) lives in the parent
``PlaygroundScreen``. We only render and accept input.
"""

from __future__ import annotations

from rich.markup import escape as rich_escape
from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, Static

from defenseclaw.tui.creator.command_palette import (
    Command,
    filter_commands,
)
from defenseclaw.tui.theme import DEFAULT_TOKENS


class CommandPaletteScreen(ModalScreen[Command | None]):
    """A small modal that lets the operator search-and-run a command.

    Returns the selected ``Command`` on Enter or ``None`` on Esc.
    """

    CSS = f"""
    CommandPaletteScreen {{
        align: center middle;
    }}

    #cp-dialog {{
        width: 80;
        height: 22;
        padding: 1 2;
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_panel};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #cp-title {{
        height: 1;
        margin-bottom: 1;
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    #cp-input {{
        height: 3;
        background: {DEFAULT_TOKENS.surface_raised};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #cp-list {{
        height: 1fr;
        margin-top: 1;
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #cp-footer {{
        height: 1;
        color: {DEFAULT_TOKENS.text_secondary};
    }}
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
        Binding("enter", "run", "Run", show=False),
        Binding("up", "cursor_up", "Up", show=False),
        Binding("down", "cursor_down", "Down", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._cursor: int = 0
        self._matches: list[Command] = []

    # --- lifecycle --------------------------------------------------------

    def compose(self) -> ComposeResult:
        with Vertical(id="cp-dialog"):
            yield Static("Command palette", id="cp-title")
            yield Input(placeholder="search commands...", id="cp-input")
            yield Static(self._render_list(""), id="cp-list")
            yield Static("enter run | up/down navigate | esc cancel", id="cp-footer")

    def on_mount(self) -> None:
        self._matches = filter_commands("")
        self._cursor = 0
        self.query_one("#cp-input", Input).focus()
        self._refresh_list()

    # --- event handlers ---------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        self._matches = filter_commands(event.value)
        self._cursor = 0
        self._refresh_list()

    def on_key(self, event: events.Key) -> None:
        # The Input absorbs character keys. We only need to handle
        # navigation here so up/down skip lines without inserting
        # control codes into the search box.
        if event.key == "up":
            self._cursor = max(0, self._cursor - 1)
            event.stop()
            self._refresh_list()
            return
        if event.key == "down":
            if self._matches:
                self._cursor = min(len(self._matches) - 1, self._cursor + 1)
            event.stop()
            self._refresh_list()
            return

    def action_cursor_up(self) -> None:
        self._cursor = max(0, self._cursor - 1)
        self._refresh_list()

    def action_cursor_down(self) -> None:
        if self._matches:
            self._cursor = min(len(self._matches) - 1, self._cursor + 1)
        self._refresh_list()

    def action_run(self) -> None:
        if not self._matches:
            self.dismiss(None)
            return
        cmd = self._matches[self._cursor]
        self.dismiss(cmd)

    def action_cancel(self) -> None:
        self.dismiss(None)

    # --- rendering --------------------------------------------------------

    def _refresh_list(self) -> None:
        self.query_one("#cp-list", Static).update(self._render_list(""))

    def _render_list(self, _query: str) -> Text:
        out = Text()
        if not self._matches:
            out.append("  (no matches)\n", style="dim")
            return out
        # Show up to 14 results to fit the dialog without scrolling.
        visible = self._matches[:14]
        for i, cmd in enumerate(visible):
            cursor = ">" if i == self._cursor else " "
            line_style = "bold" if i == self._cursor else ""
            out.append(f" {cursor} ", style=line_style)
            out.append(f"{rich_escape(cmd.label)}", style=line_style)
            if cmd.hint:
                out.append(f"  - {rich_escape(cmd.hint)}\n", style="dim")
            else:
                out.append("\n", style=line_style)
        if len(self._matches) > 14:
            out.append(
                f"  ... +{len(self._matches) - 14} more (refine query)\n",
                style="dim",
            )
        return out
