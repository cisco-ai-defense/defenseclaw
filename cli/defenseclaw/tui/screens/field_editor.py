# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""One-field text editor modal for Setup wizard forms and the config editor.

Setup rows used to take keystrokes straight from the panel key handler, which
lowercases letters, drops spaces and treats ``q``/``j``/``s`` as commands.
Text now goes through this modal instead: a real :class:`Input` that
receives raw keys (the app's own key handler stands aside while a modal is
on the stack). Enter commits, Esc cancels, and an optional validator keeps
the modal open with an inline error until the value is acceptable.
"""

from __future__ import annotations

from collections.abc import Callable

from rich.markup import escape as rich_escape
from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, Static

from defenseclaw.tui.theme import DEFAULT_TOKENS

TOKENS = DEFAULT_TOKENS

# Returns an error message for an unacceptable value, or None to accept it.
FieldValidator = Callable[[str], str | None]


class FieldEditorScreen(ModalScreen[str | None]):
    """Edit one text value. Dismisses with the new value, or None on cancel."""

    CSS = f"""
    FieldEditorScreen {{
        align: center middle;
    }}

    #field-editor-dialog {{
        width: 72;
        max-width: 100%;
        height: auto;
        padding: 1 2;
        border: round {TOKENS.border_active};
        background: {TOKENS.surface_panel};
        color: {TOKENS.text_primary};
    }}

    #field-editor-title {{
        height: auto;
        color: {TOKENS.accent_cyan};
        text-style: bold;
    }}

    #field-editor-hint {{
        height: auto;
        color: {TOKENS.text_secondary};
    }}

    #field-editor-input {{
        margin-top: 1;
        border: tall {TOKENS.border_active};
    }}

    #field-editor-error {{
        height: auto;
        color: {TOKENS.accent_red};
    }}

    #field-editor-keys {{
        height: 1;
        margin-top: 1;
        color: {TOKENS.text_muted};
    }}
    """

    # Focus the input as soon as the screen is active, so keys typed right
    # after the key that opened the editor land in it.
    AUTO_FOCUS = "#field-editor-input"

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
        Binding("ctrl+t", "toggle_reveal", "Reveal", show=False),
    ]

    def __init__(
        self,
        title: str,
        *,
        value: str = "",
        hint: str = "",
        password: bool = False,
        validator: FieldValidator | None = None,
    ) -> None:
        super().__init__()
        self._title = title
        self._value = value
        self._hint = hint
        self._password = password
        self._validator = validator
        # Last inline error (mirrors the error line for callers and tests).
        self.error = ""

    def compose(self) -> ComposeResult:
        keys = "Enter save · Esc cancel" + (" · Ctrl+T show/hide" if self._password else "")
        with Vertical(id="field-editor-dialog"):
            yield Static(rich_escape(self._title), id="field-editor-title")
            if self._hint:
                yield Static(rich_escape(self._hint), id="field-editor-hint")
            # No select-all on focus: the editor often opens seeded with the
            # key that was just pressed, and the next key must not replace it.
            yield Input(
                value=self._value,
                password=self._password,
                select_on_focus=False,
                id="field-editor-input",
            )
            yield Static("", id="field-editor-error")
            yield Static(keys, id="field-editor-keys")

    def on_mount(self) -> None:
        field_input = self.query_one("#field-editor-input", Input)
        field_input.focus()
        field_input.cursor_position = len(field_input.value)

    @on(Input.Submitted, "#field-editor-input")
    def _on_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        self.action_commit()

    def action_commit(self) -> None:
        value = self.query_one("#field-editor-input", Input).value
        if self._validator is not None:
            try:
                error = self._validator(value)
            except Exception as exc:  # noqa: BLE001 - a bad validator must not eat the edit.
                error = str(exc) or "invalid value"
            if error:
                self._set_error(error)
                return
        self.dismiss(value)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_toggle_reveal(self) -> None:
        if not self._password:
            return
        field_input = self.query_one("#field-editor-input", Input)
        field_input.password = not field_input.password

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:
            event.stop()
            self.dismiss(None)

    def _set_error(self, message: str) -> None:
        self.error = message
        self.query_one("#field-editor-error", Static).update(rich_escape(message))
