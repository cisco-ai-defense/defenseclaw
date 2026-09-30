# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Switch the guardrail rule pack for every connector or for one.

Step 1 picks the scope (Global, or one active connector); step 2 picks the
pack (a preset, a pack found on disk, or a custom folder). The pack is then
checked with the injected validator (the app runs ``guardrail validate-pack
PATH --json``): an invalid pack stays here with the reason; when the validator
is unavailable only presets may continue. The screen returns a
:class:`RulePackChoice`; the app confirms and runs ``guardrail use-pack``.
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from rich.markup import escape as rich_escape
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, Static

from defenseclaw.tui.services.policy_state import PackValidation, fit
from defenseclaw.tui.theme import DEFAULT_TOKENS

CUSTOM_FOLDER = "__custom__"


@dataclass(frozen=True)
class PackScope:
    """``connector`` "" means global."""

    connector: str
    label: str
    current: str = ""


@dataclass(frozen=True)
class PackOption:
    """``pack`` is what ``use-pack`` takes: a preset name or a folder path."""

    name: str
    pack: str
    path: str
    preset: bool


@dataclass(frozen=True)
class RulePackChoice:
    connector: str
    pack: str
    name: str
    path: str
    preset: bool
    validation: PackValidation


Validator = Callable[[str], Awaitable[PackValidation]]


def scope_lines(scopes: tuple[PackScope, ...], selected: int) -> list[str]:
    lines = []
    for index, scope in enumerate(scopes):
        cursor = ">" if index == selected else " "
        number = str(index + 1) if index < 9 else " "
        color_style = f"bold {DEFAULT_TOKENS.accent_cyan}" if index == selected else DEFAULT_TOKENS.text_primary
        current = f"  [{DEFAULT_TOKENS.text_muted}]now {rich_escape(scope.current)}[/]" if scope.current else ""
        lines.append(f"{cursor} \\[{number}] [{color_style}]{rich_escape(scope.label)}[/]{current}")
    return lines


def option_lines(options: tuple[PackOption, ...], selected: int, current: str) -> list[str]:
    width = min(28, max((len(option.name) for option in options), default=8))
    lines = []
    for index, option in enumerate(options):
        cursor = ">" if index == selected else " "
        number = str(index + 1) if index < 9 else " "
        color_style = f"bold {DEFAULT_TOKENS.accent_cyan}" if index == selected else DEFAULT_TOKENS.text_primary
        if option.pack == CUSTOM_FOLDER:
            tail = "type a folder path"
        else:
            tail = ("preset" if option.preset else "custom") + (" · current" if option.name == current else "")
        lines.append(
            f"{cursor} \\[{number}] [{color_style}]{rich_escape(fit(option.name, width).ljust(width))}[/]  "
            f"[{DEFAULT_TOKENS.text_muted}]{rich_escape(tail)}[/]"
        )
    return lines


class RulePackPickerScreen(ModalScreen[RulePackChoice | None]):
    """Scope, then pack, then validation."""

    # The folder Input is hidden until "Custom folder…"; auto-focusing it
    # would swallow the digit and Enter keys of the list steps.
    AUTO_FOCUS = ""

    CSS = f"""
    RulePackPickerScreen {{
        align: center middle;
    }}

    #rule-pack-dialog {{
        width: 76;
        max-width: 100%;
        height: auto;
        max-height: 100%;
        padding: 0 1;
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_panel};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #rule-pack-title {{
        height: 1;
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    #rule-pack-list {{
        height: auto;
        max-height: 12;
        margin-top: 1;
    }}

    #rule-pack-input {{
        margin-top: 1;
    }}

    #rule-pack-input.hidden {{
        display: none;
    }}

    #rule-pack-status,
    #rule-pack-hint {{
        height: auto;
        margin-top: 1;
        color: {DEFAULT_TOKENS.text_secondary};
    }}
    """

    BINDINGS = [
        Binding("up", "cursor_up", "Previous", show=False),
        Binding("down", "cursor_down", "Next", show=False),
        Binding("escape", "back", "Back", show=False),
    ]

    def __init__(
        self,
        scopes: tuple[PackScope, ...] | list[PackScope],
        options: tuple[PackOption, ...] | list[PackOption],
        *,
        validate: Validator,
        selected_scope: str = "",
    ) -> None:
        super().__init__()
        self.scopes = tuple(scopes)
        self.options = (*tuple(options), PackOption("Custom folder…", CUSTOM_FOLDER, "", False))
        self.validate = validate
        self.step = "scope"
        self.scope_index = next((i for i, s in enumerate(self.scopes) if s.connector == selected_scope), 0)
        self.option_index = 0
        self.status = ""
        self.validating = False

    def compose(self) -> ComposeResult:
        with Vertical(id="rule-pack-dialog"):
            yield Static("", id="rule-pack-title")
            yield Static("", id="rule-pack-list")
            yield Input(placeholder="Folder that holds the pack's rules/", id="rule-pack-input", classes="hidden")
            yield Static("", id="rule-pack-status")
            yield Static("", id="rule-pack-hint")

    def on_mount(self) -> None:
        self._refresh()

    # ---- state ------------------------------------------------------------

    @property
    def scope(self) -> PackScope:
        return self.scopes[self.scope_index]

    def _refresh(self) -> None:
        title = self.query_one("#rule-pack-title", Static)
        listing = self.query_one("#rule-pack-list", Static)
        hint = self.query_one("#rule-pack-hint", Static)
        if self.step == "scope":
            title.update("Switch the rule pack: where?")
            listing.update("\n".join(scope_lines(self.scopes, self.scope_index)))
            hint.update("up/down move  1-9 jump  enter next  esc close")
        else:
            where = "every connector" if not self.scope.connector else self.scope.connector
            title.update(f"Rule pack for {rich_escape(where)}")
            listing.update("\n".join(option_lines(self.options, self.option_index, self.scope.current)))
            if self.step == "custom":
                hint.update("type a folder  enter check it  esc back")
            else:
                hint.update("up/down move  1-9 jump  enter check and choose  esc back")
        status = self.query_one("#rule-pack-status", Static)
        status.update(self.status)
        status.display = bool(self.status)
        folder = self.query_one("#rule-pack-input", Input)
        folder.set_class(self.step != "custom", "hidden")
        folder.disabled = self.step != "custom"

    # ---- keys -------------------------------------------------------------

    def action_cursor_up(self) -> None:
        self._move(-1)

    def action_cursor_down(self) -> None:
        self._move(1)

    def _move(self, delta: int) -> None:
        if self.validating:
            return
        if self.step == "scope":
            self.scope_index = (self.scope_index + delta) % len(self.scopes)
        elif self.step == "pack":
            self.option_index = (self.option_index + delta) % len(self.options)
            self.status = ""
        self._refresh()

    def action_back(self) -> None:
        if self.validating:
            return
        if self.step == "custom":
            self.step = "pack"
            self.status = ""
            self._refresh()
            self.set_focus(None)
            return
        if self.step == "pack":
            self.step = "scope"
            self.status = ""
            self._refresh()
            return
        self.dismiss(None)

    def on_key(self, event: events.Key) -> None:
        if self.step == "custom" or self.validating:
            return
        if event.key == "enter":
            event.stop()
            self._choose()
            return
        character = event.character or ""
        if character in {"j", "k"}:
            event.stop()
            self._move(1 if character == "j" else -1)
            return
        if character.isdigit() and character != "0":
            index = int(character) - 1
            items = self.scopes if self.step == "scope" else self.options
            if index < len(items):
                event.stop()
                if self.step == "scope":
                    self.scope_index = index
                else:
                    self.option_index = index
                    self.status = ""
                self._refresh()

    def _choose(self) -> None:
        if self.step == "scope":
            self.step = "pack"
            current = self.scope.current
            self.option_index = next((i for i, o in enumerate(self.options) if o.name == current), 0)
            self._refresh()
            return
        option = self.options[self.option_index]
        if option.pack == CUSTOM_FOLDER:
            self.step = "custom"
            self.status = ""
            self._refresh()
            self.query_one("#rule-pack-input", Input).focus()
            return
        self._start_validation(option)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        if self.step != "custom" or self.validating:
            return
        folder = os.path.expanduser(event.value.strip())
        if not folder:
            self.status = f"[{DEFAULT_TOKENS.accent_amber}]Type the folder that holds the pack.[/]"
            self._refresh()
            return
        name = os.path.basename(os.path.normpath(folder)) or folder
        self._start_validation(PackOption(name, folder, folder, False))

    # ---- validation -------------------------------------------------------

    def _start_validation(self, option: PackOption) -> None:
        self.validating = True
        self.status = f"[{DEFAULT_TOKENS.text_muted}]Checking {rich_escape(option.name)}…[/]"
        self._refresh()
        self.run_worker(self._validate(option), exclusive=True)

    async def _validate(self, option: PackOption) -> None:
        try:
            result = await self.validate(option.path or option.pack)
        except Exception as exc:  # noqa: BLE001 - a crashed validator reads as unavailable
            result = PackValidation("unavailable", str(exc))
        self.validating = False
        if result.state == "valid" or (result.state == "unavailable" and option.preset):
            self.dismiss(
                RulePackChoice(
                    connector=self.scope.connector,
                    pack=option.pack,
                    name=option.name,
                    path=option.path,
                    preset=option.preset,
                    validation=result,
                )
            )
            return
        color = DEFAULT_TOKENS.accent_red if result.state == "invalid" else DEFAULT_TOKENS.accent_amber
        message = rich_escape(result.summary)
        if result.state == "unavailable":
            message += " · only the presets can be used until the validator is installed"
        self.status = f"[{color}]{message}[/]"
        self._refresh()

    def on_click(self, event: events.Click) -> None:
        if event.widget is self and not self.validating:
            event.stop()
            self.dismiss(None)


__all__ = [
    "CUSTOM_FOLDER",
    "PackOption",
    "PackScope",
    "RulePackChoice",
    "RulePackPickerScreen",
    "option_lines",
    "scope_lines",
]
