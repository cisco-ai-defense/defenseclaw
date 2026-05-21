# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Config diff/save modal for Setup config edits."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from defenseclaw.tui.services.setup_state import ConfigDiffEntry
from defenseclaw.tui.theme import DEFAULT_TOKENS

DEFAULT_RESTART_REASON = "config saved from Textual TUI"


@dataclass(frozen=True)
class ConfigDiffResult:
    """Result returned when an operator confirms config save."""

    save: bool
    queue_restart_reason: str = DEFAULT_RESTART_REASON


@dataclass(frozen=True)
class ConfigDiffModalModel:
    """Display model for a config diff modal."""

    entries: tuple[ConfigDiffEntry, ...]
    restart_reason: str = DEFAULT_RESTART_REASON

    @classmethod
    def from_entries(
        cls,
        entries: Iterable[ConfigDiffEntry],
        *,
        restart_reason: str = DEFAULT_RESTART_REASON,
    ) -> ConfigDiffModalModel:
        return cls(tuple(entries), restart_reason)

    @property
    def has_changes(self) -> bool:
        return bool(self.entries)

    def result(self) -> ConfigDiffResult:
        return ConfigDiffResult(save=True, queue_restart_reason=self.restart_reason)

    def preview_text(self, *, max_entries: int = 8, value_width: int = 72) -> str:
        """Render diff text with Go-compatible labels and truncation."""

        if not self.entries:
            return "No pending changes."

        lines: list[str] = []
        for index, entry in enumerate(self.entries):
            if index >= max_entries:
                lines.append(f"... {len(self.entries) - index} more changes")
                break
            key = f"{entry.key} (masked)" if entry.secret else entry.key
            lines.append(key)
            lines.append(f"  before: {_truncate(entry.before, value_width)}")
            lines.append(f"  after:  {_truncate(entry.after, value_width)}")
        return "\n".join(lines)


class ConfigDiffScreen(ModalScreen[ConfigDiffResult | None]):
    """Rounded config diff modal returning a save intent."""

    CSS = f"""
    ConfigDiffScreen {{
        align: center middle;
    }}

    #config-diff-dialog {{
        width: 92;
        height: auto;
        padding: 1 2;
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_panel};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #config-diff-title {{
        height: 1;
        margin-bottom: 1;
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    #config-diff-preview,
    #config-diff-status {{
        height: auto;
        margin-bottom: 1;
        color: {DEFAULT_TOKENS.text_secondary};
    }}

    #config-diff-status {{
        color: {DEFAULT_TOKENS.accent_amber};
    }}

    #config-diff-buttons {{
        height: 3;
        align-horizontal: right;
    }}

    #config-diff-save {{
        margin-left: 1;
    }}
    """

    BINDINGS = [
        Binding("escape,q", "cancel", "Cancel", show=False),
        Binding("enter", "save", "Save", show=False),
    ]

    def __init__(self, model: ConfigDiffModalModel | Iterable[ConfigDiffEntry]) -> None:
        super().__init__()
        if isinstance(model, ConfigDiffModalModel):
            self.model = model
        else:
            self.model = ConfigDiffModalModel.from_entries(model)

    def compose(self) -> ComposeResult:
        with Vertical(id="config-diff-dialog"):
            yield Static("Review Config Changes", id="config-diff-title")
            yield Static(self.model.preview_text(), id="config-diff-preview")
            yield Static("", id="config-diff-status")
            with Horizontal(id="config-diff-buttons"):
                yield Button("Cancel", id="config-diff-cancel", variant="default")
                yield Button(
                    "Save and queue restart",
                    id="config-diff-save",
                    variant="success",
                    disabled=not self.model.has_changes,
                )

    def on_mount(self) -> None:
        target = "#config-diff-save" if self.model.has_changes else "#config-diff-cancel"
        self.query_one(target, Button).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_save(self) -> None:
        if not self.model.has_changes:
            self.query_one("#config-diff-status", Static).update("No pending changes.")
            return
        self.dismiss(self.model.result())

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:
            event.stop()
            self.dismiss(None)

    @on(Button.Pressed, "#config-diff-cancel")
    def _on_cancel_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_cancel()

    @on(Button.Pressed, "#config-diff-save")
    def _on_save_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_save()


def _truncate(value: str, width: int) -> str:
    if width <= 1:
        return ""
    if len(value) <= width:
        return value
    return value[: width - 1] + "..."
