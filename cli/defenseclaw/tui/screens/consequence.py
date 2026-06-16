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

# Footer hint text. The armed variant is shown once a ``danger`` action has
# been chosen a first time and is waiting for the explicit second confirm.
_HINT_DEFAULT = "up/down choose  enter confirm  esc cancel"
_HINT_ARMED = "⚠ danger — press enter / click again to confirm  ·  esc cancel"


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
        """Return the label with a hotkey prefix when one exists.

        The bracket around the hotkey is escaped (``\\[a]``) so Rich
        treats ``[a] Apply`` as literal text. Without the backslash
        the markup parser interprets the single-letter hotkey as a
        style name and the modal render explodes with
        ``MissingStyle: 'a' is not a valid color`` — same bug class
        that took down the audit panel before we hardened that path.
        """

        if self.hotkey:
            return f"\\[{self.hotkey}] {self.label}"
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

    # Don't auto-focus an action button. With a button focused, Textual's
    # button binding swallows a *second* Enter (the button stays ``-active``
    # for its effect window), which would defeat the danger re-press confirm.
    # With nothing focused, Enter routes through the screen ``enter`` binding
    # every time; selection stays a purely visual ``-selected`` class.
    AUTO_FOCUS = ""

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
        # Index of a ``danger`` action that has been chosen once and is
        # awaiting its explicit second confirmation. ``None`` means nothing
        # is armed; moving the selection, pressing a hotkey, or cancelling
        # clears it. This is the gate that the destructive flows (uninstall
        # wipe, redaction-off) inherit so a single keypress/click can't run
        # them.
        self._armed_index: int | None = None

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
                button = Button(
                    label,
                    id=f"consequence-action-{index}",
                    classes="consequence-action-row",
                    variant=action.variant,
                )
                # Drop the transient ``-active`` click flash: it suppresses a
                # second click within its window, which would swallow the
                # confirming second click of a danger action.
                button.active_effect_duration = 0
                yield button
            yield Button("Cancel", id="consequence-cancel", variant="default")
            yield Static(_HINT_DEFAULT, id="consequence-hint")

    def on_mount(self) -> None:
        self._sync_selection()
        self._apply_border()
        self._update_hint()

    def _apply_border(self) -> None:
        # The dialog border color is baked into the class-level CSS f-string,
        # which can't see the per-instance model, so paint the model's
        # border_color on at mount. This is what makes the destructive
        # modals (uninstall-wipe, redaction-off) render with the red frame.
        dialog = self.query_one("#consequence-dialog", Vertical)
        dialog.styles.border = ("round", self.model.border_color)

    def _update_hint(self) -> None:
        hint = _HINT_ARMED if self._armed_index is not None else _HINT_DEFAULT
        self.query_one("#consequence-hint", Static).update(hint)

    def _disarm(self) -> None:
        self._armed_index = None
        self._update_hint()

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
        self._disarm()
        self._sync_selection()

    def action_cursor_up(self) -> None:
        self.selected_index = (self.selected_index - 1) % len(self.model.actions)
        self._disarm()
        self._sync_selection()

    def action_cursor_down(self) -> None:
        self.selected_index = (self.selected_index + 1) % len(self.model.actions)
        self._disarm()
        self._sync_selection()

    def action_choose(self) -> None:
        self._choose_index(self.selected_index)

    def _choose_index(self, index: int) -> None:
        action = self.model.actions[index]
        if action.danger and self._armed_index != index:
            # First commit on a danger action only arms it; require an
            # explicit second confirm (Enter again, or a second click on the
            # same row) before dismissing.
            self._armed_index = index
            self.selected_index = index
            self._sync_selection()
            self._update_hint()
            return
        self.dismiss(action)

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
        self._choose_index(index)

    @on(Button.Pressed, "#consequence-cancel")
    def _on_cancel_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_cancel()

    def _sync_selection(self) -> None:
        # Selection is shown via the ``-selected`` class only; we deliberately
        # do NOT focus the button (see AUTO_FOCUS) so Enter keeps routing
        # through the screen binding and the danger re-press confirm works.
        for index, button in enumerate(self.query(Button)):
            if "consequence-action-row" not in button.classes:
                continue
            button.set_class(index == self.selected_index, "-selected")


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
