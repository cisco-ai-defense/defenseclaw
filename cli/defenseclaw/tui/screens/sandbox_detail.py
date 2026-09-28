# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The Sandboxes panel's detail and review window.

Like :class:`~defenseclaw.tui.screens.detail.DetailScreen`, but the body
scrolls (a review can list dozens of files and still end with a scan
warning), and the panel keys the detail advertises (``u`` unblock, ``a``
approve, ...) close it and return the key, so the panel runs that action on
the row the detail showed.
"""

from __future__ import annotations

from collections.abc import Iterable

from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from defenseclaw.tui.screens.detail import DetailModalModel
from defenseclaw.tui.theme import DEFAULT_TOKENS


class SandboxDetailScreen(ModalScreen[str | None]):
    """Scrollable detail modal; dismisses with the action key pressed, or None."""

    CSS = f"""
    SandboxDetailScreen {{
        align: center middle;
    }}

    #sandbox-detail-dialog {{
        width: 100%;
        max-width: 96;
        height: auto;
        max-height: 90%;
        padding: 1 2;
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_panel};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #sandbox-detail-title {{
        height: 1;
        margin-bottom: 1;
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    #sandbox-detail-scroll {{
        height: auto;
    }}

    #sandbox-detail-keys {{
        height: auto;
        margin-top: 1;
        color: {DEFAULT_TOKENS.text_secondary};
    }}

    #sandbox-detail-close {{
        width: 100%;
        height: 3;
        margin-top: 1;
    }}
    """

    BINDINGS = [
        Binding("escape,q,enter", "close", "Close", show=False),
    ]

    def __init__(
        self,
        title: str,
        pairs: Iterable[tuple[str, str]],
        *,
        keys: Iterable[str] = (),
        keys_hint: str = "",
    ) -> None:
        super().__init__()
        self.model = DetailModalModel.from_pairs(title, pairs)
        self.keys = frozenset(keys)
        self.keys_hint = keys_hint

    def compose(self) -> ComposeResult:
        with Vertical(id="sandbox-detail-dialog"):
            yield Static(self.model.title, id="sandbox-detail-title", markup=False)
            with VerticalScroll(id="sandbox-detail-scroll"):
                yield Static(self.model.table(), id="sandbox-detail-body")
            if self.keys_hint:
                yield Static(self.keys_hint, id="sandbox-detail-keys", markup=False)
            yield Button("Close", id="sandbox-detail-close", variant="default")

    def on_mount(self) -> None:
        self._fit_body()
        # Up/Down/PageUp/PageDown scroll the body.
        self.query_one("#sandbox-detail-scroll", VerticalScroll).focus()

    def on_resize(self, _event: events.Resize) -> None:
        self._fit_body()

    def _fit_body(self) -> None:
        # The dialog may take 90% of the screen; the title, key line, Close
        # button, padding and border keep their rows and the body scrolls.
        chrome = 13 if self.keys_hint else 10
        room = self.app.size.height * 9 // 10 - chrome
        self.query_one("#sandbox-detail-scroll", VerticalScroll).styles.max_height = max(3, room)

    def on_key(self, event: events.Key) -> None:
        # Match the typed character: U (undo) and u (unblock) differ.
        if event.character and event.character in self.keys:
            event.stop()
            event.prevent_default()
            self.dismiss(event.character)

    def action_close(self) -> None:
        self.dismiss(None)

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:
            event.stop()
            self.action_close()

    @on(Button.Pressed, "#sandbox-detail-close")
    def _on_close_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_close()
