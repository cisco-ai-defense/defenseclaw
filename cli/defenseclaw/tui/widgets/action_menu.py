# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Reusable Textual action menu primitives."""

from __future__ import annotations

from dataclasses import dataclass

from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from defenseclaw.tui.theme import DEFAULT_TOKENS


@dataclass(frozen=True)
class MenuAction:
    """Pure action model for menu rows and modal buttons."""

    action_id: str
    label: str
    description: str = ""
    disabled: bool = False
    variant: str = "default"


class ActionMenu(Vertical):
    """Focusable list of actions with keyboard and mouse parity."""

    DEFAULT_CSS = f"""
    ActionMenu {{
        width: 100%;
        height: auto;
    }}

    ActionMenu Button {{
        width: 100%;
        height: 3;
        margin-bottom: 1;
        content-align: left middle;
        border: round {DEFAULT_TOKENS.border_muted};
        background: {DEFAULT_TOKENS.surface_raised};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    ActionMenu Button.-selected {{
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_selected};
        color: {DEFAULT_TOKENS.text_primary};
    }}
    """

    class Selected(Message):
        """Posted when the selected action is activated."""

        def __init__(self, action: MenuAction) -> None:
            super().__init__()
            self.action = action

    def __init__(
        self,
        actions: tuple[MenuAction, ...],
        *,
        selected_index: int | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)
        self.actions = actions
        self.selected_index = self._initial_selected_index(selected_index)

    def compose(self) -> ComposeResult:
        for index, action in enumerate(self.actions):
            label = action.label if not action.description else f"{action.label}\n{action.description}"
            yield Button(
                label,
                id=f"action-menu-row-{index}",
                classes="action-menu-row",
                disabled=action.disabled,
                variant=action.variant,
            )

    def on_mount(self) -> None:
        self._sync_selection()

    def select_next(self) -> None:
        self._move_selection(1)

    def select_previous(self) -> None:
        self._move_selection(-1)

    def activate_selected(self) -> None:
        if self.selected_index is None:
            return
        action = self.actions[self.selected_index]
        if not action.disabled:
            self.post_message(self.Selected(action))

    @on(Button.Pressed, ".action-menu-row")
    def _on_action_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        index = _row_index(event.button.id)
        if index is None:
            return
        self.selected_index = index
        self._sync_selection()
        self.activate_selected()

    def _move_selection(self, direction: int) -> None:
        if self.selected_index is None or not self.actions:
            return

        index = self.selected_index
        for _ in self.actions:
            index = (index + direction) % len(self.actions)
            if not self.actions[index].disabled:
                self.selected_index = index
                self._sync_selection()
                return

    def _sync_selection(self) -> None:
        for index, row in enumerate(self.query(Button)):
            row.set_class(index == self.selected_index, "-selected")
            if index == self.selected_index:
                row.focus()

    def _first_enabled_index(self) -> int | None:
        for index, action in enumerate(self.actions):
            if not action.disabled:
                return index
        return None

    def _initial_selected_index(self, selected_index: int | None) -> int | None:
        if selected_index is not None and 0 <= selected_index < len(self.actions):
            if not self.actions[selected_index].disabled:
                return selected_index
        return self._first_enabled_index()


class ActionMenuScreen(ModalScreen[str | None]):
    """Rounded action menu modal returning the chosen action id."""

    CSS = f"""
    ActionMenuScreen {{
        align: center middle;
    }}

    #action-menu-dialog {{
        width: 64;
        height: auto;
        padding: 1 2;
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_panel};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #action-menu-title {{
        height: 1;
        margin-bottom: 1;
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    #action-menu-subtitle {{
        height: auto;
        margin-bottom: 1;
        color: {DEFAULT_TOKENS.text_secondary};
    }}
    """

    BINDINGS = [
        Binding("up,k", "cursor_up", "Previous", show=False),
        Binding("down,j", "cursor_down", "Next", show=False),
        Binding("enter", "choose", "Choose", show=False),
        Binding("escape,q", "cancel", "Cancel", show=False),
    ]

    def __init__(
        self,
        title: str,
        actions: tuple[MenuAction, ...],
        subtitle: str = "",
        *,
        selected_index: int | None = None,
    ) -> None:
        super().__init__()
        self.title = title
        self.subtitle = subtitle
        self.actions = actions
        self.selected_index = selected_index

    def compose(self) -> ComposeResult:
        with Vertical(id="action-menu-dialog"):
            yield Static(self.title, id="action-menu-title")
            if self.subtitle:
                yield Static(self.subtitle, id="action-menu-subtitle")
            yield ActionMenu(self.actions, selected_index=self.selected_index, id="action-menu")

    def action_cursor_up(self) -> None:
        self.query_one(ActionMenu).select_previous()

    def action_cursor_down(self) -> None:
        self.query_one(ActionMenu).select_next()

    def action_choose(self) -> None:
        self.query_one(ActionMenu).activate_selected()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:
            event.stop()
            self.dismiss(None)

    @on(ActionMenu.Selected)
    def _on_action_selected(self, event: ActionMenu.Selected) -> None:
        event.stop()
        self.dismiss(event.action.action_id)


def _row_index(row_id: str | None) -> int | None:
    if row_id is None:
        return None
    prefix = "action-menu-row-"
    if not row_id.startswith(prefix):
        return None
    try:
        return int(row_id.removeprefix(prefix))
    except ValueError:
        return None
