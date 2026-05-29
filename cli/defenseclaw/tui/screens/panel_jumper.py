# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Fuzzy panel jumper modal (Ctrl+P).

A single-input modal that lets operators jump to any panel by typing
a fragment of its name. Mirrors the "Quick Open" affordance from
modern editors: type, see the filtered list narrow, press Enter, the
selected panel becomes active.

Kept as a tiny self-contained module so the fuzzy-match logic can be
unit-tested without spinning up Textual. ``DefenseClawTUI`` pushes
:class:`PanelJumperScreen` on ``Ctrl+P`` and switches to the panel
name the screen dismisses with.
"""

from __future__ import annotations

from dataclasses import dataclass

from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Input, Static

from defenseclaw.tui.theme import DEFAULT_TOKENS


@dataclass(frozen=True)
class PanelChoice:
    """One row in the jumper modal."""

    name: str  # internal panel id (e.g. "alerts")
    label: str  # human label (e.g. "Alerts")
    hotkey: str  # digit/letter (e.g. "2")


def _score_match(query: str, choice: PanelChoice) -> tuple[bool, int]:
    """Return ``(match, score)`` for ``choice`` against ``query``.

    Lower score == better match. Negative-position priority means
    "panel name starts with the query" beats "query appears later
    in the label". Returns ``(False, 0)`` for non-matches so callers
    can filter them out cheaply.

    Matching rules (case-insensitive):
        1. Empty query  → match everything (score 0).
        2. Hotkey exact → score 0 (highest priority; ``5`` jumps to
           the panel mapped to digit 5).
        3. ``name`` startswith → score 1.
        4. ``label`` startswith → score 2.
        5. Substring in ``label`` → score 3 + position in label.
        6. Initials (e.g. "ad" matches "AI Discovery") → score 6.
        7. No match → ``(False, 0)``.
    """

    if not query:
        return True, 0
    q = query.strip().lower()
    if not q:
        return True, 0
    if q == choice.hotkey.lower():
        return True, 0
    name = choice.name.lower()
    label = choice.label.lower()
    if name.startswith(q):
        return True, 1
    if label.startswith(q):
        return True, 2
    idx = label.find(q)
    if idx >= 0:
        return True, 3 + idx
    # Initials: take the first letter of each whitespace-separated
    # word in the label and see if the query is a prefix of that.
    initials = "".join(word[0] for word in label.split() if word)
    if initials.startswith(q):
        return True, 6
    return False, 0


def filter_choices(query: str, choices: tuple[PanelChoice, ...]) -> list[PanelChoice]:
    """Return ``choices`` filtered + sorted by match score.

    Stable within the same score so identical matches keep their
    declared (PANELS) order — predictable for operator muscle memory.
    """

    scored: list[tuple[int, int, PanelChoice]] = []
    for index, choice in enumerate(choices):
        ok, score = _score_match(query, choice)
        if not ok:
            continue
        scored.append((score, index, choice))
    scored.sort(key=lambda item: (item[0], item[1]))
    return [c for _, _, c in scored]


class PanelJumperScreen(ModalScreen[str | None]):
    """Fuzzy picker over all visible panels."""

    CSS = f"""
    PanelJumperScreen {{
        align: center middle;
    }}

    #panel-jumper-dialog {{
        width: 60;
        height: auto;
        padding: 1 2;
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_panel};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #panel-jumper-title {{
        height: 1;
        margin-bottom: 1;
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    #panel-jumper-input {{
        margin-bottom: 1;
        border: tall {DEFAULT_TOKENS.border_active};
    }}

    #panel-jumper-list {{
        height: auto;
        max-height: 14;
    }}

    .panel-jumper-row {{
        height: 1;
        padding: 0 1;
    }}

    .panel-jumper-row.selected {{
        background: {DEFAULT_TOKENS.surface_raised};
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    #panel-jumper-hint {{
        margin-top: 1;
        color: {DEFAULT_TOKENS.text_secondary};
    }}
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
        Binding("up", "cursor_up", "Up", show=False),
        Binding("down", "cursor_down", "Down", show=False),
        Binding("enter", "choose", "Choose", show=False),
    ]

    selected_index: reactive[int] = reactive(0)

    def __init__(self, choices: tuple[PanelChoice, ...]) -> None:
        super().__init__()
        self._choices = choices
        self._filtered: list[PanelChoice] = list(choices)

    def compose(self) -> ComposeResult:
        with Vertical(id="panel-jumper-dialog"):
            yield Static("Jump to panel", id="panel-jumper-title")
            yield Input(
                placeholder="Type to filter (name, hotkey, or initials)…",
                id="panel-jumper-input",
            )
            yield Static("", id="panel-jumper-list", markup=True)
            yield Static(
                "Up/Down move · Enter jump · Esc cancel",
                id="panel-jumper-hint",
            )

    def on_mount(self) -> None:
        self._refresh_list()
        self.query_one(Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "panel-jumper-input":
            return
        self._filtered = filter_choices(event.value, self._choices)
        self.selected_index = 0
        self._refresh_list()

    def action_cursor_up(self) -> None:
        if not self._filtered:
            return
        self.selected_index = (self.selected_index - 1) % len(self._filtered)
        self._refresh_list()

    def action_cursor_down(self) -> None:
        if not self._filtered:
            return
        self.selected_index = (self.selected_index + 1) % len(self._filtered)
        self._refresh_list()

    def action_choose(self) -> None:
        if not self._filtered:
            self.dismiss(None)
            return
        # Clamp defensively: if a key sequence sneaks in between an
        # ``Input.Changed`` event and the next ``_refresh_list``, the
        # reactive ``selected_index`` can briefly point past the
        # newly-shortened ``_filtered`` list. Indexing that directly
        # would IndexError and crash the modal mid-dismiss.
        index = max(0, min(self.selected_index, len(self._filtered) - 1))
        choice = self._filtered[index]
        self.dismiss(choice.name)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_key(self, event: events.Key) -> None:
        # Forward Enter regardless of where focus sits so typing in
        # the Input still commits without first Tab-ing away.
        if event.key == "enter":
            event.stop()
            self.action_choose()

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:
            event.stop()
            self.dismiss(None)

    def _refresh_list(self) -> None:
        target = self.query_one("#panel-jumper-list", Static)
        if not self._filtered:
            target.update("[#94A3B8]no matches[/]")
            return
        lines: list[str] = []
        for index, choice in enumerate(self._filtered):
            marker = ">" if index == self.selected_index else " "
            row = (
                f"{marker} [#22D3EE]\\[{choice.hotkey}][/] {choice.label}"
                f"  [#475569]({choice.name})[/]"
            )
            lines.append(row)
        target.update("\n".join(lines))


__all__ = [
    "PanelChoice",
    "PanelJumperScreen",
    "filter_choices",
]
