# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Pick a named security policy, with a preview of what activating it changes.

The list marks the active policy; the preview compares the active policy with
the highlighted one (block, alert and install thresholds, firewall default,
human approval, and side effects such as replacing webhooks). The screen only
returns the chosen name; the app confirms and runs ``policy activate``.
"""

from __future__ import annotations

from typing import Any

from rich.markup import escape as rich_escape
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Static

from defenseclaw.tui.services.policy_state import (
    fit,
    policy_comparison,
    policy_side_effects,
    policy_weakenings,
)
from defenseclaw.tui.theme import DEFAULT_TOKENS

_HINT = "up/down move  1-9 jump  enter choose  esc close"


def picker_lines(policies: tuple[Any, ...], selected: int) -> list[str]:
    """One markup line per policy: cursor, number, active marker, name, thresholds."""
    width = max((len(p.name) for p in policies), default=8)
    width = min(max(width, 8), 20)
    lines: list[str] = []
    for index, policy in enumerate(policies):
        cursor = ">" if index == selected else " "
        number = str(index + 1) if index < 9 else " "
        active = "●" if policy.active else " "
        kind = "built-in" if policy.builtin else "custom  "
        name = rich_escape(fit(policy.name, width).ljust(width))
        color_style = f"bold {DEFAULT_TOKENS.accent_cyan}" if index == selected else DEFAULT_TOKENS.text_primary
        lines.append(
            f"{cursor} \\[{number}] [{DEFAULT_TOKENS.accent_green}]{active}[/] [{color_style}]{name}[/]  "
            f"[{DEFAULT_TOKENS.text_muted}]{kind}  block {rich_escape(policy.block_at)} · "
            f"alert {rich_escape(policy.alert_at)}[/]"
        )
    return lines


def preview_text(active: Any | None, candidate: Any | None) -> str:
    """The active → highlighted comparison as markup."""
    if candidate is None:
        return ""
    color_muted = DEFAULT_TOKENS.text_muted
    if active is not None and active.name == candidate.name:
        head = f"[{color_muted}]{rich_escape(candidate.name)} is active; choosing it applies it again.[/]"
    else:
        before = rich_escape(active.name) if active is not None else "(none)"
        head = f"[{color_muted}]{'':<18}{before:<14}→  [/][bold]{rich_escape(candidate.name)}[/]"
    lines = [head]
    for label, old, new in policy_comparison(active, candidate):
        changed = old != new and active is not None
        color = DEFAULT_TOKENS.accent_amber if changed else DEFAULT_TOKENS.text_secondary
        lines.append(f"{label:<18}{rich_escape(old):<14}→  [{color}]{rich_escape(new)}[/]")
    notes: list[str] = []
    weaker = policy_weakenings(active, candidate)
    if weaker:
        notes.append(f"[{DEFAULT_TOKENS.accent_red}]Weaker: {rich_escape('; '.join(weaker))}[/]")
    effects = policy_side_effects(candidate)
    if effects:
        notes.append(f"[{DEFAULT_TOKENS.accent_amber}]Also: {rich_escape(' · '.join(effects))}[/]")
    if candidate.description:
        notes.append(f"[{color_muted}]{rich_escape(fit(candidate.description, 74))}[/]")
    return "\n".join(lines + notes)


class PolicyPickerScreen(ModalScreen[str | None]):
    """List of named policies with an active → highlighted preview."""

    CSS = f"""
    PolicyPickerScreen {{
        align: center middle;
    }}

    #policy-picker-dialog {{
        width: 80;
        max-width: 100%;
        height: auto;
        max-height: 100%;
        padding: 0 1;
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_panel};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #policy-picker-title {{
        height: 1;
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    #policy-picker-list {{
        height: auto;
        max-height: 9;
        margin-top: 1;
    }}

    #policy-picker-preview,
    #policy-picker-hint {{
        height: auto;
        margin-top: 1;
        color: {DEFAULT_TOKENS.text_secondary};
    }}
    """

    BINDINGS = [
        Binding("up,k", "cursor_up", "Previous", show=False),
        Binding("down,j", "cursor_down", "Next", show=False),
        Binding("enter", "choose", "Choose", show=False),
        Binding("escape,q", "cancel", "Cancel", show=False),
    ]

    def __init__(self, policies: tuple[Any, ...] | list[Any], *, selected: str = "") -> None:
        super().__init__()
        self.policies = tuple(policies)
        self.active = next((p for p in self.policies if p.active), None)
        self.selected_index = next((i for i, p in enumerate(self.policies) if p.name == selected), 0)

    def compose(self) -> ComposeResult:
        with Vertical(id="policy-picker-dialog"):
            yield Static("Activate a named policy", id="policy-picker-title")
            yield Static("", id="policy-picker-list")
            yield Static("", id="policy-picker-preview")
            yield Static(_HINT, id="policy-picker-hint")

    def on_mount(self) -> None:
        self._refresh()

    @property
    def highlighted(self) -> Any | None:
        if not self.policies:
            return None
        return self.policies[self.selected_index]

    def _refresh(self) -> None:
        if not self.policies:
            self.query_one("#policy-picker-list", Static).update("No named policies were found.")
            return
        self.query_one("#policy-picker-list", Static).update(
            "\n".join(picker_lines(self.policies, self.selected_index))
        )
        self.query_one("#policy-picker-preview", Static).update(preview_text(self.active, self.highlighted))

    def action_cursor_up(self) -> None:
        if self.policies:
            self.selected_index = (self.selected_index - 1) % len(self.policies)
            self._refresh()

    def action_cursor_down(self) -> None:
        if self.policies:
            self.selected_index = (self.selected_index + 1) % len(self.policies)
            self._refresh()

    def action_choose(self) -> None:
        policy = self.highlighted
        self.dismiss(policy.name if policy is not None else None)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_key(self, event: events.Key) -> None:
        character = event.character or ""
        if character.isdigit() and character != "0":
            index = int(character) - 1
            if index < len(self.policies):
                event.stop()
                self.selected_index = index
                self._refresh()

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:
            event.stop()
            self.dismiss(None)


__all__ = ["PolicyPickerScreen", "picker_lines", "preview_text"]
