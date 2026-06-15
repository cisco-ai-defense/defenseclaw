# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Shared detail modal for Go-parity drill-down surfaces."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from rich.markup import escape as rich_escape
from rich.table import Table
from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from defenseclaw.tui.theme import DEFAULT_TOKENS


@dataclass(frozen=True)
class DetailModalModel:
    """Title and label/value pairs rendered in the detail modal."""

    title: str
    pairs: tuple[tuple[str, str], ...]

    @classmethod
    def from_pairs(cls, title: str, pairs: Iterable[tuple[str, str]]) -> DetailModalModel:
        return cls(title, tuple((str(label), str(value)) for label, value in pairs))

    def table(self) -> Table:
        """Render a no-truncation detail table."""

        table = Table.grid(padding=(0, 2), expand=True)
        table.add_column(width=22, no_wrap=True)
        table.add_column(overflow="fold")
        for label, value in self.pairs:
            if not label and not value:
                table.add_row("", "")
                continue
            # Both ``label`` and ``value`` come from arbitrary panel
            # state — audit details, log lines, alert findings, scan
            # raw output — any of which may contain ``[token]`` that
            # Rich would parse as a style name and crash the table
            # render. Escape both halves before they reach markup parsing.
            table.add_row(
                f"[{DEFAULT_TOKENS.text_secondary}]{rich_escape(label)}[/]",
                f"[{DEFAULT_TOKENS.text_primary}]{rich_escape(value)}[/]",
            )
        return table


class DetailScreen(ModalScreen[None]):
    """Rounded modal used by logs, audit, alerts, and catalog drill-downs."""

    CSS = f"""
    DetailScreen {{
        align: center middle;
    }}

    #detail-dialog {{
        width: 92;
        max-height: 85%;
        padding: 1 2;
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_panel};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #detail-title {{
        height: 1;
        margin-bottom: 1;
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    #detail-body {{
        height: auto;
        max-height: 26;
        margin-bottom: 1;
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #detail-close {{
        width: 100%;
        height: 3;
    }}
    """

    BINDINGS = [
        Binding("escape,q,enter", "close", "Close", show=False),
    ]

    def __init__(self, model: DetailModalModel | str, pairs: Iterable[tuple[str, str]] = ()) -> None:
        super().__init__()
        if isinstance(model, DetailModalModel):
            self.model = model
        else:
            self.model = DetailModalModel.from_pairs(model, pairs)

    def compose(self) -> ComposeResult:
        with Vertical(id="detail-dialog"):
            yield Static(self.model.title, id="detail-title")
            yield Static(self.model.table(), id="detail-body")
            yield Button("Close", id="detail-close", variant="default")

    def action_close(self) -> None:
        self.dismiss(None)

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:
            event.stop()
            self.action_close()

    @on(Button.Pressed, "#detail-close")
    def _on_close_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_close()
