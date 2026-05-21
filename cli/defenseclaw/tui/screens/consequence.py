# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Generic consequence confirmation modal primitives."""

from __future__ import annotations

from dataclasses import dataclass

from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from defenseclaw.tui.theme import DEFAULT_TOKENS


@dataclass(frozen=True)
class CommandSpec:
    """Command argv a confirmed modal action should dispatch later."""

    binary: str
    args: tuple[str, ...]
    display_name: str

    @property
    def command_line(self) -> str:
        """Return display-ready command text."""

        return " ".join((self.binary, *self.args))


@dataclass(frozen=True)
class ConsequenceAction:
    """A selectable modal action."""

    action_id: str
    label: str
    description: str
    command: CommandSpec | None = None
    hotkey: str = ""
    variant: str = "default"
    danger: bool = False

    @property
    def display_label(self) -> str:
        """Return the label with a hotkey prefix when one exists."""

        if self.hotkey:
            return f"[{self.hotkey}] {self.label}"
        return self.label


@dataclass(frozen=True)
class ConsequenceModalModel:
    """Display and behavior contract for a consequence modal."""

    title: str
    summary: str
    details: tuple[str, ...]
    actions: tuple[ConsequenceAction, ...]
    default_action_id: str
    consequence: str = ""
    border_color: str = DEFAULT_TOKENS.border_active

    def __post_init__(self) -> None:
        if not self.actions:
            raise ValueError("consequence modal requires at least one action")
        self.default_action()

    def default_action(self) -> ConsequenceAction:
        """Return the action selected by Enter."""

        for action in self.actions:
            if action.action_id == self.default_action_id:
                return action
        raise ValueError(f"default action {self.default_action_id!r} is not in actions")

    def default_index(self) -> int:
        """Return the zero-based default action index."""

        for index, action in enumerate(self.actions):
            if action.action_id == self.default_action_id:
                return index
        return 0

    def action_for_hotkey(self, hotkey: str) -> ConsequenceAction | None:
        """Return the action selected by a hotkey, if any."""

        normalized = hotkey.lower()
        for action in self.actions:
            if action.hotkey.lower() == normalized:
                return action
        return None

    def action_index(self, action_id: str) -> int | None:
        """Return an action index by id."""

        for index, action in enumerate(self.actions):
            if action.action_id == action_id:
                return index
        return None


class ConsequenceModalScreen(ModalScreen[ConsequenceAction | None]):
    """Rounded modal that returns the selected consequence action."""

    CSS = f"""
    ConsequenceModalScreen {{
        align: center middle;
    }}

    #consequence-dialog {{
        width: 82;
        height: auto;
        padding: 1 2;
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_panel};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #consequence-title {{
        height: 1;
        margin-bottom: 1;
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    #consequence-summary,
    #consequence-details,
    #consequence-warning,
    #consequence-hint {{
        height: auto;
        margin-bottom: 1;
    }}

    #consequence-summary,
    #consequence-details,
    #consequence-hint {{
        color: {DEFAULT_TOKENS.text_secondary};
    }}

    #consequence-warning {{
        color: {DEFAULT_TOKENS.accent_amber};
    }}

    .consequence-action-row {{
        width: 100%;
        height: 3;
        margin-bottom: 1;
        content-align: left middle;
        border: round {DEFAULT_TOKENS.border_muted};
        background: {DEFAULT_TOKENS.surface_raised};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    .consequence-action-row.-selected {{
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_selected};
    }}

    #consequence-cancel {{
        width: 100%;
        height: 3;
        margin-top: 1;
    }}
    """

    BINDINGS = [
        Binding("up,k", "cursor_up", "Previous", show=False),
        Binding("down,j", "cursor_down", "Next", show=False),
        Binding("enter", "choose", "Choose", show=False),
        Binding("escape,q", "cancel", "Cancel", show=False),
    ]

    def __init__(self, model: ConsequenceModalModel) -> None:
        super().__init__()
        self.model = model
        self.selected_index = model.default_index()

    def compose(self) -> ComposeResult:
        details = "\n".join(self.model.details)
        with Vertical(id="consequence-dialog"):
            yield Static(self.model.title, id="consequence-title")
            yield Static(self.model.summary, id="consequence-summary")
            if details:
                yield Static(details, id="consequence-details")
            if self.model.consequence:
                yield Static(self.model.consequence, id="consequence-warning")
            for index, action in enumerate(self.model.actions):
                label = action.display_label
                if action.description:
                    label = f"{label}\n{action.description}"
                yield Button(
                    label,
                    id=f"consequence-action-{index}",
                    classes="consequence-action-row",
                    variant=action.variant,
                )
            yield Button("Cancel", id="consequence-cancel", variant="default")
            yield Static("up/down choose  enter confirm  esc cancel", id="consequence-hint")

    def on_mount(self) -> None:
        self._sync_selection()

    def on_key(self, event: events.Key) -> None:
        if not event.character:
            return
        action = self.model.action_for_hotkey(event.character)
        if action is None:
            return
        index = self.model.action_index(action.action_id)
        if index is None:
            return
        event.stop()
        self.selected_index = index
        self._sync_selection()

    def action_cursor_up(self) -> None:
        self.selected_index = (self.selected_index - 1) % len(self.model.actions)
        self._sync_selection()

    def action_cursor_down(self) -> None:
        self.selected_index = (self.selected_index + 1) % len(self.model.actions)
        self._sync_selection()

    def action_choose(self) -> None:
        self.dismiss(self.model.actions[self.selected_index])

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:
            event.stop()
            self.dismiss(None)

    @on(Button.Pressed, ".consequence-action-row")
    def _on_action_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        index = _button_index(event.button.id)
        if index is None:
            return
        self.selected_index = index
        self._sync_selection()
        self.action_choose()

    @on(Button.Pressed, "#consequence-cancel")
    def _on_cancel_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_cancel()

    def _sync_selection(self) -> None:
        for index, button in enumerate(self.query(Button)):
            if "consequence-action-row" not in button.classes:
                continue
            selected = index == self.selected_index
            button.set_class(selected, "-selected")
            if selected:
                button.focus()


def _button_index(button_id: str | None) -> int | None:
    if not button_id:
        return None
    prefix = "consequence-action-"
    if not button_id.startswith(prefix):
        return None
    try:
        return int(button_id.removeprefix(prefix))
    except ValueError:
        return None
