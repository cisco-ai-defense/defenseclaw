# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Searchable LLM model picker modal.

A single-input modal that lets operators pick a model id for the
selected provider by typing a fragment. The candidate list is the
curated catalog for the provider (or a custom-provider instance's
``available_models``); operators can always type a full model id the
catalog has not shipped yet and press Enter to use it verbatim — the
same "type a custom model id" fall-through the interactive
``defenseclaw setup llm`` picker offers.

The fuzzy-match + free-form logic lives in pure functions
(:func:`filter_models`, :func:`picker_rows`) so it can be unit-tested
without spinning up Textual. ``DefenseClawTUI`` pushes
:class:`ModelPickerScreen` from the LLM/guardrail wizard "Model" row
and writes back the model id the screen dismisses with.
"""

from __future__ import annotations

from rich.markup import escape as rich_escape
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Input, Static

from defenseclaw.tui.theme import DEFAULT_TOKENS


def filter_models(query: str, models: tuple[str, ...]) -> list[str]:
    """Return ``models`` filtered + sorted by match score against ``query``.

    Lower score == better. Empty query returns every model in declared
    order. Case-insensitive. Stable within a score so the catalog order
    is preserved for predictable muscle memory.
    """

    q = (query or "").strip().lower()
    if not q:
        return list(models)
    scored: list[tuple[int, int, str]] = []
    for index, model in enumerate(models):
        lowered = model.lower()
        if lowered == q:
            score = 0
        elif lowered.startswith(q):
            score = 1
        else:
            pos = lowered.find(q)
            if pos < 0:
                continue
            score = 2 + pos
        scored.append((score, index, model))
    scored.sort(key=lambda item: (item[0], item[1]))
    return [m for _, _, m in scored]


def picker_rows(query: str, models: tuple[str, ...]) -> list[str]:
    """Filtered models, with a free-form row prepended when warranted.

    When the operator types a model id the catalog does not contain,
    the first row becomes that exact typed value so Enter always has a
    sensible target — mirroring the CLI's ``[c] type a custom model
    id`` fall-through. The free-form row is never duplicated when the
    typed text already matches a catalog model exactly.
    """

    filtered = filter_models(query, models)
    typed = (query or "").strip()
    if typed and typed not in models:
        return [typed, *filtered]
    return filtered


class ModelPickerScreen(ModalScreen[str | None]):
    """Searchable picker over the catalog models for one provider."""

    CSS = f"""
    ModelPickerScreen {{
        align: center middle;
    }}

    #model-picker-dialog {{
        width: 70;
        height: auto;
        padding: 1 2;
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_panel};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #model-picker-title {{
        height: 1;
        margin-bottom: 1;
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    #model-picker-input {{
        margin-bottom: 1;
        border: tall {DEFAULT_TOKENS.border_active};
    }}

    #model-picker-list {{
        height: auto;
        max-height: 16;
    }}

    #model-picker-hint {{
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

    def __init__(self, models: tuple[str, ...], *, current: str = "", provider: str = "") -> None:
        super().__init__()
        self._models = tuple(models)
        self._current = current
        self._provider = provider or "provider"
        self._rows: list[str] = picker_rows("", self._models)

    def compose(self) -> ComposeResult:
        with Vertical(id="model-picker-dialog"):
            yield Static(f"Pick a model for {self._provider}", id="model-picker-title")
            yield Input(
                value=self._current,
                placeholder="Type to filter or enter a custom model id…",
                id="model-picker-input",
            )
            yield Static("", id="model-picker-list", markup=True)
            yield Static(
                "Up/Down move · Enter use · Esc cancel · type a full id to use it verbatim",
                id="model-picker-hint",
            )

    def on_mount(self) -> None:
        self._rows = picker_rows(self._current, self._models)
        self._refresh_list()
        self.query_one(Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "model-picker-input":
            return
        self._rows = picker_rows(event.value, self._models)
        self.selected_index = 0
        self._refresh_list()

    def action_cursor_up(self) -> None:
        if not self._rows:
            return
        self.selected_index = (self.selected_index - 1) % len(self._rows)
        self._refresh_list()

    def action_cursor_down(self) -> None:
        if not self._rows:
            return
        self.selected_index = (self.selected_index + 1) % len(self._rows)
        self._refresh_list()

    def action_choose(self) -> None:
        if not self._rows:
            typed = self.query_one(Input).value.strip()
            self.dismiss(typed or None)
            return
        index = max(0, min(self.selected_index, len(self._rows) - 1))
        self.dismiss(self._rows[index])

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_key(self, event: events.Key) -> None:
        if event.key == "enter":
            event.stop()
            self.action_choose()

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:
            event.stop()
            self.dismiss(None)

    def _refresh_list(self) -> None:
        target = self.query_one("#model-picker-list", Static)
        if not self._rows:
            target.update("[#94A3B8]no models — type an id and press Enter[/]")
            return
        lines: list[str] = []
        for index, model in enumerate(self._rows):
            marker = ">" if index == self.selected_index else " "
            suffix = "  [#475569](custom)[/]" if model not in self._models else ""
            # Escape the model id before interpolating into markup: a free-text
            # id containing ``[`` (e.g. ``gpt[4``) would otherwise crash the
            # Rich render on the keystroke after the bracket.
            lines.append(f"{marker} [#22D3EE]{rich_escape(model)}[/]{suffix}")
        target.update("\n".join(lines))


__all__ = [
    "ModelPickerScreen",
    "filter_models",
    "picker_rows",
]
