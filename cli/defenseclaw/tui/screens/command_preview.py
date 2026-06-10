# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Command preview modal for mutating TUI commands."""

from __future__ import annotations

from dataclasses import dataclass

from rich.markup import escape as rich_escape
from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from defenseclaw.tui.command_line import ParsedCommand, infer_command_risk
from defenseclaw.tui.theme import DEFAULT_TOKENS

SECRET_FLAG_FRAGMENTS = ("key", "token", "secret", "password", "credential")
# ``--env KEY=VALUE`` pairs routinely carry API tokens; the flag name
# itself contains no secret fragment, so it needs dedicated handling that
# redacts the value while keeping the key visible for context.
ENV_FLAGS = ("--env", "-e")


@dataclass(frozen=True)
class CommandPreview:
    """Display-ready command preview data."""

    title: str
    masked_argv: tuple[str, ...]
    category: str
    risk: str
    origin: str
    restart: str
    summary: str

    @property
    def masked_display(self) -> str:
        return " ".join(self.masked_argv)


def build_command_preview(command: ParsedCommand) -> CommandPreview:
    """Build preview copy for a parsed command."""

    argv = (command.binary, *command.args)
    risk = command.risk if command.risk != "read-only" else classify_risk(command.category, command.args)
    return CommandPreview(
        title=command.display_name,
        masked_argv=mask_argv(argv),
        category=command.category,
        risk=risk,
        origin=command.category,
        restart=_restart_effect(risk, command.args),
        summary=_risk_summary(risk, command.category),
    )


def classify_risk(category: str, args: tuple[str, ...]) -> str:
    """Classify command risk using the same vocabulary as the Go preview.

    Delegates to the shared :func:`infer_command_risk` so that intents
    coming from the Overview quick actions — which set ``category="overview"``
    and leave ``risk`` defaulted — still get the right risk label
    (e.g. ``defenseclaw setup guardrail`` resolves to ``setup``, not
    ``read-only``). The old hand-coded classifier never saw the
    ``"overview"`` category and so fell through to ``read-only`` for
    every quick-action command, which is unsafe.
    """

    return infer_command_risk(category, args)


def mask_argv(argv: tuple[str, ...]) -> tuple[str, ...]:
    """Mask likely secret values in argv before rendering them."""

    masked: list[str] = []
    mask_next = False
    mask_next_env = False
    for arg in argv:
        if mask_next:
            masked.append("<redacted>")
            mask_next = False
            continue
        if mask_next_env:
            masked.append(_redact_env_pair(arg))
            mask_next_env = False
            continue

        if arg.startswith("-") and "=" in arg:
            flag, value = arg.split("=", 1)
            if _flag_is_env(flag):
                masked.append(f"{flag}={_redact_env_pair(value)}")
                continue
            if _flag_is_secret(flag):
                masked.append(f"{flag}=<redacted>")
                continue

        masked.append(arg)
        if _flag_is_env(arg):
            mask_next_env = True
        elif arg.startswith("--") and _flag_is_secret(arg):
            mask_next = True
    return tuple(masked)


def _flag_is_secret(flag: str) -> bool:
    normalized = flag.lower().replace("-", "_")
    return any(fragment in normalized for fragment in SECRET_FLAG_FRAGMENTS) or normalized == "__value"


def _flag_is_env(flag: str) -> bool:
    return flag in ENV_FLAGS


def _redact_env_pair(pair: str) -> str:
    """Redact the value of a ``KEY=VALUE`` env assignment, keeping the key."""

    if "=" in pair:
        key, _value = pair.split("=", 1)
        return f"{key}=<redacted>"
    return "<redacted>"


def _risk_summary(risk: str, category: str) -> str:
    if risk == "destructive":
        return "Destructive command. Review carefully before running."
    if risk == "secret":
        return "Secret-bearing command. Values are redacted before display."
    if risk == "restart":
        return "Restart command. Runtime traffic may briefly pause."
    if risk in {"setup", "mutation"}:
        return f"This {category} command can change DefenseClaw state."
    return "Read-only command."


def _restart_effect(risk: str, args: tuple[str, ...]) -> str:
    lowered = tuple(arg.lower() for arg in args)
    if risk == "restart" or any(arg in {"restart", "rotate-token"} for arg in lowered):
        return "yes"
    if lowered and lowered[0] == "setup" and "--no-restart" not in lowered:
        return "possible"
    return "no"


class CommandPreviewScreen(ModalScreen[bool]):
    """Rounded command confirmation modal."""

    CSS = f"""
    CommandPreviewScreen {{
        align: center middle;
    }}

    #preview-dialog {{
        width: 76;
        height: auto;
        padding: 1 2;
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_panel};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #preview-title {{
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
        height: 1;
        margin-bottom: 1;
    }}

    #preview-risk {{
        height: auto;
        margin-bottom: 1;
    }}

    #preview-argv {{
        height: auto;
        color: {DEFAULT_TOKENS.text_secondary};
        margin-bottom: 1;
    }}

    #preview-buttons {{
        height: 3;
        align-horizontal: right;
    }}

    #preview-run {{
        margin-left: 1;
    }}
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
        Binding("q", "cancel", "Cancel", show=False),
        Binding("enter", "run", "Run", show=False),
    ]

    def __init__(self, command: ParsedCommand) -> None:
        super().__init__()
        self.preview = build_command_preview(command)

    def compose(self) -> ComposeResult:
        color = _risk_color(self.preview.risk)
        # Every interpolated preview field comes from the parsed
        # command — argv tokens, origin paths, risk labels, restart
        # status — and any of them may include bracketed substrings
        # the user just typed (``defenseclaw scan skill[0]``). Escape
        # all of them so the confirm-modal can't crash mid-render.
        summary = rich_escape(self.preview.summary)
        masked = rich_escape(self.preview.masked_display)
        origin = rich_escape(self.preview.origin)
        risk = rich_escape(self.preview.risk)
        restart = rich_escape(self.preview.restart)
        with Vertical(id="preview-dialog"):
            yield Static("Confirm Command", id="preview-title")
            yield Static(f"[{color}]{summary}[/]", id="preview-risk")
            yield Static(
                "[bold]Command[/]\n"
                f"{masked}\n\n"
                f"[bold]Origin[/] {origin}    "
                f"[bold]Risk[/] {risk}    "
                f"[bold]Restart[/] {restart}",
                id="preview-argv",
            )
            with Horizontal(id="preview-buttons"):
                yield Button("Cancel", id="preview-cancel", variant="default")
                yield Button("Run", id="preview-run", variant="success")

    def on_mount(self) -> None:
        self.query_one("#preview-run", Button).focus()

    def action_cancel(self) -> None:
        self.dismiss(False)

    def action_run(self) -> None:
        self.dismiss(True)

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:
            event.stop()
            self.dismiss(False)

    @on(Button.Pressed, "#preview-cancel")
    def _on_cancel_pressed(self) -> None:
        self.action_cancel()

    @on(Button.Pressed, "#preview-run")
    def _on_run_pressed(self) -> None:
        self.action_run()


def _risk_color(risk: str) -> str:
    if risk in {"destructive", "secret"}:
        return DEFAULT_TOKENS.accent_red
    if risk in {"setup", "mutation", "restart"}:
        return DEFAULT_TOKENS.accent_amber
    return DEFAULT_TOKENS.accent_green
