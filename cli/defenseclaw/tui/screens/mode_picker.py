# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Connector mode picker for the Textual Overview panel."""

from __future__ import annotations

from dataclasses import dataclass

from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Static

from defenseclaw.platform_support import supported_connectors
from defenseclaw.tui.theme import DEFAULT_TOKENS
from defenseclaw.tui.widgets.action_menu import ActionMenu, MenuAction


@dataclass(frozen=True)
class ModeChoice:
    wire: str
    label: str
    hotkey: str
    guardrail_ok: bool
    tagline: str


MODE_PICKER_CHOICES: tuple[ModeChoice, ...] = (
    ModeChoice("openclaw", "OpenClaw", "o", True, "fetch interceptor + before_tool_call plugin (full guardrail)"),
    ModeChoice("zeptoclaw", "ZeptoClaw", "z", True, "api_base redirect + proxy response-scan (full guardrail)"),
    ModeChoice("claudecode", "Claude Code", "k", False, "PreToolUse hooks + native OTel + CodeGuard plugin"),
    ModeChoice("codex", "Codex", "c", False, "hook scripts + native OTel + notify + CodeGuard skill"),
    ModeChoice("hermes", "Hermes", "h", False, "shell hooks + vendor-native block events"),
    ModeChoice("cursor", "Cursor", "u", False, "command hooks + event-scoped ask/block"),
    ModeChoice("windsurf", "Windsurf", "w", False, "Cascade hooks + fail-open block decisions"),
    ModeChoice("geminicli", "Gemini CLI", "g", False, "settings.json hooks + structured deny responses"),
    ModeChoice("copilot", "Copilot", "p", False, "workspace hooks + native pre-tool approval"),
    ModeChoice("openhands", "OpenHands", "n", False, "command hooks via ~/.openhands/hooks.json"),
    ModeChoice("antigravity", "Antigravity", "a", False, "PreToolUse hooks via ~/.gemini/config/hooks.json"),
    ModeChoice("opencode", "OpenCode", "e", False, "auto-loaded JS bridge plugin; tool.execute.before blocking"),
    ModeChoice("omnigent", "OmniGent", "m", False, "custom policy ALLOW/ASK/DENY + optional native OTLP"),
)


def visible_mode_picker_choices(os_name: str | None = None) -> tuple[ModeChoice, ...]:
    """Mode-picker rows supported on *os_name*.

    On Windows the proxy connectors (openclaw/zeptoclaw) are dropped because
    DefenseClaw is hook-only there; on macOS/Linux this is a no-op.
    """
    supported = set(supported_connectors([c.wire for c in MODE_PICKER_CHOICES], os_name))
    return tuple(c for c in MODE_PICKER_CHOICES if c.wire in supported)


class ModePickerScreen(ModalScreen[str | None]):
    """Rounded connector switcher with keyboard hotkeys and mouse rows."""

    CSS = f"""
    ModePickerScreen {{
        align: center middle;
    }}

    #mode-picker-dialog {{
        width: 82;
        height: auto;
        padding: 1 2;
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_panel};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #mode-picker-title {{
        height: 1;
        margin-bottom: 1;
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    #mode-picker-preview,
    #mode-picker-hint {{
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

    def __init__(self, current_wire: str = "", *, os_name: str | None = None) -> None:
        super().__init__()
        # Hide proxy connectors on Windows; no-op on macOS/Linux. Resolve
        # once so compose() and _sync_preview() share the same row order.
        self.choices = visible_mode_picker_choices(os_name)
        self.current_wire = self._resolve_current_wire(current_wire)

    def _resolve_current_wire(self, wire: str) -> str:
        """Pick the row to land on, never fabricating a hidden connector.

        ``normalize_connector`` collapses an empty/unknown wire to the
        ``"openclaw"`` sentinel; honoring that would surface a connector the
        picker isn't even showing (openclaw on Windows, or a hook-only/empty
        state). So resolve against the *visible* rows and fall back to the
        first one instead of the hardcoded openclaw default.
        """
        candidate = wire.strip().lower().replace("_", "-")
        if candidate in {"claude-code", "claudecode"}:
            candidate = "claudecode"
        if any(choice.wire == candidate for choice in self.choices):
            return candidate
        return self.choices[0].wire if self.choices else candidate

    def compose(self) -> ComposeResult:
        current = choice_for_wire(self.current_wire)
        actions = tuple(_choice_action(choice, current_wire=self.current_wire) for choice in self.choices)
        selected = next(
            (i for i, c in enumerate(self.choices) if c.wire == current.wire),
            0,
        )
        with Vertical(id="mode-picker-dialog"):
            yield Static("Switch active claw connector", id="mode-picker-title")
            yield ActionMenu(actions, selected_index=selected, id="mode-picker-menu")
            yield Static(preview_for_switch(self.current_wire, current.wire), id="mode-picker-preview")
            yield Static(self._hint_text(), id="mode-picker-hint")

    def _hint_text(self) -> str:
        # Built from the visible rows so the advertised jump keys match what
        # the picker actually shows (drops o/z on Windows; always includes
        # e/a, which the old hardcoded literal omitted).
        jump_keys = "/".join(choice.hotkey for choice in self.choices)
        return f"up/down move  {jump_keys} jump  enter confirm  esc close"

    def _visible_choice_for_hotkey(self, hotkey: str) -> ModeChoice | None:
        for choice in self.choices:
            if choice.hotkey == hotkey:
                return choice
        return None

    def on_key(self, event: events.Key) -> None:
        if not event.character:
            return
        # Resolve against the *visible* rows so a hidden connector's hotkey
        # (e.g. ``o``/``z`` on Windows) is a no-op instead of selecting a
        # connector that can't run here.
        choice = self._visible_choice_for_hotkey(event.character.lower())
        if choice is None:
            return
        event.stop()
        self.dismiss(choice.wire)

    def action_cursor_up(self) -> None:
        menu = self.query_one(ActionMenu)
        menu.select_previous()
        self._sync_preview()

    def action_cursor_down(self) -> None:
        menu = self.query_one(ActionMenu)
        menu.select_next()
        self._sync_preview()

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

    def _sync_preview(self) -> None:
        menu = self.query_one(ActionMenu)
        index = menu.selected_index if menu.selected_index is not None else 0
        choice = self.choices[index]
        self.query_one("#mode-picker-preview", Static).update(preview_for_switch(self.current_wire, choice.wire))


def normalize_connector(value: str) -> str:
    normalized = value.strip().lower().replace("_", "-")
    if normalized in {"claude-code", "claudecode"}:
        return "claudecode"
    if any(choice.wire == normalized for choice in MODE_PICKER_CHOICES):
        return normalized
    return "openclaw"


def choice_for_wire(wire: str) -> ModeChoice:
    normalized = normalize_connector(wire)
    for choice in MODE_PICKER_CHOICES:
        if choice.wire == normalized:
            return choice
    return MODE_PICKER_CHOICES[0]


def choice_for_hotkey(hotkey: str) -> ModeChoice | None:
    for choice in MODE_PICKER_CHOICES:
        if choice.hotkey == hotkey:
            return choice
    return None


def choice_index(wire: str) -> int:
    normalized = normalize_connector(wire)
    for index, choice in enumerate(MODE_PICKER_CHOICES):
        if choice.wire == normalized:
            return index
    return 0


def preview_for_switch(current_wire: str, dest_wire: str) -> str:
    current = normalize_connector(current_wire)
    dest = normalize_connector(dest_wire)
    label = choice_for_wire(dest).label
    if current == dest:
        return f"{label}: setup will re-run to refresh hooks, config, and runtime files."
    if choice_for_wire(dest).guardrail_ok:
        return (
            f"{label}: runs proxy-backed connector setup and pins claw.mode plus guardrail.connector; "
            "preserves the existing guardrail.mode."
        )
    if dest == "omnigent":
        return (
            "OmniGent: installs the custom Python policy runtime, maps all six phases "
            "to ALLOW/ASK/DENY, and honors per-connector policy mode."
        )
    return (
        f"{label}: runs hook-driven connector setup, wires hooks and native OTel where supported, "
        "and honors guardrail.mode for PreToolUse deny verdicts."
    )


def _choice_action(choice: ModeChoice, *, current_wire: str) -> MenuAction:
    active = " (active)" if normalize_connector(current_wire) == choice.wire else ""
    guardrail = "guardrail" if choice.guardrail_ok else ("policy" if choice.wire == "omnigent" else "hooks")
    return MenuAction(
        action_id=choice.wire,
        # Escape the opening bracket so Rich treats ``[c] Codex`` as
        # literal text. Without the leading backslash the markup parser
        # interprets the single-letter token as a style name and the
        # menu render crashes with ``MissingStyle: 'c' is not a valid
        # color`` the moment the picker is shown.
        label=f"\\[{choice.hotkey}] {choice.label}{active}",
        description=f"{guardrail}: {choice.tagline}",
    )
