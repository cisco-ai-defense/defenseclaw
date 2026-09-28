# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Pick one posture level: block at, alert at, or human approval.

A short numbered list (the current value marked, weaker choices flagged) with
a preview of what the highlighted choice means at each severity. The screen
only returns the chosen value; the app confirms and runs the command.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from rich.markup import escape as rich_escape
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Static

from defenseclaw.tui.services.policy_state import (
    ALERT_LEVELS,
    BLOCK_LEVELS,
    HILT_LEVELS,
    hilt_weakens,
    threshold_weakens,
)
from defenseclaw.tui.theme import DEFAULT_TOKENS

_BLOCK_WORDS = {
    "CRITICAL": "Block CRITICAL findings only",
    "HIGH+": "Block HIGH and CRITICAL",
    "MEDIUM+": "Block MEDIUM, HIGH and CRITICAL",
}
_ALERT_WORDS = {
    "HIGH+": "Alert on HIGH and above",
    "MEDIUM+": "Alert on MEDIUM and above",
    "LOW+": "Alert on everything down to LOW",
}
_HILT_WORDS = {
    "off": "Never ask; findings block, alert or pass",
    "CRITICAL": "Ask for CRITICAL if the block level lets it by",
    "HIGH+": "Ask for HIGH and up, below the block level",
    "MEDIUM+": "Ask for MEDIUM and up, below the block level",
    "LOW+": "Ask for every finding below the block level",
}


@dataclass(frozen=True)
class LevelChoice:
    """One row: ``value`` is what the screen returns."""

    value: str
    description: str
    current: bool = False
    weaker: bool = False


def threshold_choices(kind: str, current: str) -> tuple[LevelChoice, ...]:
    """Block-at (``kind="block"``) or alert-at choices, the current one marked."""
    levels, words = (BLOCK_LEVELS, _BLOCK_WORDS) if kind == "block" else (ALERT_LEVELS, _ALERT_WORDS)
    now = (current or "").strip().upper()
    return tuple(
        LevelChoice(level, words[level], current=level == now, weaker=threshold_weakens(now, level)) for level in levels
    )


def approval_choices(current: str) -> tuple[LevelChoice, ...]:
    """Human-approval choices (off, CRITICAL, HIGH+, MEDIUM+, LOW+)."""
    now = (current or "off").strip()
    now = now if now == "off" else now.upper()
    return tuple(
        LevelChoice(level, _HILT_WORDS[level], current=level == now, weaker=hilt_weakens(now, level))
        for level in HILT_LEVELS
    )


def level_lines(choices: tuple[LevelChoice, ...], selected: int) -> list[str]:
    """One markup line per choice: cursor, number, value, description, marks."""
    width = max((len(choice.value) for choice in choices), default=8)
    lines: list[str] = []
    for index, choice in enumerate(choices):
        cursor = ">" if index == selected else " "
        color = f"bold {DEFAULT_TOKENS.accent_cyan}" if index == selected else DEFAULT_TOKENS.text_primary
        marks = ""
        if choice.current:
            marks += f"  [{DEFAULT_TOKENS.accent_green}]← current[/]"
        elif choice.weaker:
            marks += f"  [{DEFAULT_TOKENS.accent_red}]weaker[/]"
        lines.append(
            f"{cursor} \\[{index + 1}] [{color}]{rich_escape(choice.value.ljust(width))}[/]  "
            f"[{DEFAULT_TOKENS.text_muted}]{rich_escape(choice.description)}[/]{marks}"
        )
    return lines


class LevelPickerScreen(ModalScreen[str | None]):
    """Numbered level list with a per-choice preview."""

    CSS = f"""
    LevelPickerScreen {{
        align: center middle;
    }}

    #level-picker-dialog {{
        width: 78;
        max-width: 100%;
        height: auto;
        max-height: 100%;
        padding: 0 1;
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_panel};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #level-picker-title {{
        height: auto;
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    #level-picker-subtitle,
    #level-picker-preview,
    #level-picker-hint {{
        height: auto;
        margin-top: 1;
        color: {DEFAULT_TOKENS.text_secondary};
    }}

    #level-picker-list {{
        height: auto;
        margin-top: 1;
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
        choices: tuple[LevelChoice, ...],
        *,
        subtitle: str = "",
        previews: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__()
        self.title_text = title
        self.subtitle = subtitle
        self.choices = tuple(choices)
        self.previews = dict(previews or {})
        self.selected_index = next((i for i, c in enumerate(self.choices) if c.current), 0)

    def compose(self) -> ComposeResult:
        with Vertical(id="level-picker-dialog"):
            yield Static(rich_escape(self.title_text), id="level-picker-title")
            if self.subtitle:
                yield Static(rich_escape(self.subtitle), id="level-picker-subtitle")
            yield Static("", id="level-picker-list")
            yield Static("", id="level-picker-preview")
            yield Static(f"up/down move  1-{len(self.choices)} jump  enter choose  esc close", id="level-picker-hint")

    def on_mount(self) -> None:
        self._refresh()

    @property
    def highlighted(self) -> LevelChoice | None:
        if not self.choices:
            return None
        return self.choices[self.selected_index]

    def _refresh(self) -> None:
        self.query_one("#level-picker-list", Static).update("\n".join(level_lines(self.choices, self.selected_index)))
        choice = self.highlighted
        preview = self.previews.get(choice.value, "") if choice is not None else ""
        widget = self.query_one("#level-picker-preview", Static)
        widget.update(rich_escape(preview))
        widget.display = bool(preview)

    def action_cursor_up(self) -> None:
        if self.choices:
            self.selected_index = (self.selected_index - 1) % len(self.choices)
            self._refresh()

    def action_cursor_down(self) -> None:
        if self.choices:
            self.selected_index = (self.selected_index + 1) % len(self.choices)
            self._refresh()

    def action_choose(self) -> None:
        choice = self.highlighted
        self.dismiss(choice.value if choice is not None else None)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_key(self, event: events.Key) -> None:
        character = event.character or ""
        if character.isdigit() and character != "0":
            index = int(character) - 1
            if index < len(self.choices):
                event.stop()
                self.selected_index = index
                self._refresh()

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:
            event.stop()
            self.dismiss(None)


__all__ = [
    "LevelChoice",
    "LevelPickerScreen",
    "approval_choices",
    "level_lines",
    "threshold_choices",
]
