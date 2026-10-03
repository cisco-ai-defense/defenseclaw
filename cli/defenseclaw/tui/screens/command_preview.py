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

from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from defenseclaw.tui.command_line import (
    ParsedCommand,
    display_argv,
    env_name_value_in_clear,
    infer_command_risk,
)
from defenseclaw.tui.markup_safe import escape as rich_escape
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
    # What the command receives besides argv, with every value hidden:
    # "Secret: sent on stdin (hidden)" and "Environment: NAME=<hidden>".
    hidden_inputs: tuple[str, ...] = ()
    # What running it changes, in plain words, when the intent says
    # (e.g. "any mcp not approved in a registry will be refused").
    consequence: str = ""

    @property
    def masked_display(self) -> str:
        return display_argv(self.masked_argv)

    @property
    def cancel_by_default(self) -> bool:
        """Whether Cancel, not Run, takes the initial focus.

        Destructive, secret-bearing and restart commands, and
        upgrade/rollback (they replace the binaries and restart the gateway,
        GAP-2090), so a reflexive Enter cancels instead of running them. One
        rule for every origin: palette "restart" focused Run while Overview
        "u" focused Cancel (GAP-2251).
        """

        if self.risk in {"destructive", "secret", "restart"}:
            return True
        args = tuple(arg.lower() for arg in self.masked_argv[1:])
        if args[:2] == ("registry", "require"):
            # It turns registry approval on or off for every connector; a
            # stray Enter ran it from Run (GAP-2438).
            return True
        return bool(_upgrade_summary(self.masked_argv[1:]))


def build_command_preview(command: ParsedCommand) -> CommandPreview:
    """Build preview copy for a parsed command."""

    argv = (command.binary, *command.args)
    inferred = classify_risk(command.category, command.args)
    risk = command.risk if command.risk != "read-only" else inferred
    if risk == "mutation" and inferred == "destructive":
        # Registries "d remove source" said "Risk mutation" and focused Run,
        # so one Enter removed the source (GAP-2309).
        risk = inferred
    restart = _restart_effect(risk, command.args)
    summary = (
        _upgrade_summary(command.args)
        or _gateway_lifecycle_summary(command.binary, command.args)
        or _risk_summary(risk, command.category)
    )
    changes_state = risk in {"setup", "mutation"}
    if changes_state and restart != "no" and command.args[:1] == ("registry",):
        # Sync and remove restart only when they change policy; a sync that
        # promotes nothing new keeps the gateway up (GAP-2542).
        when = "" if restart == "yes" else " only if it changes policy,"
        summary = (
            f"This registries command restarts a running gateway{when} so agent hooks use the new policy. "
            "Runtime traffic may briefly pause."
        )
    elif changes_state and restart == "yes":
        summary = f"This {command.category} command restarts the gateway. Runtime traffic may briefly pause."
    return CommandPreview(
        title=command.display_name,
        masked_argv=mask_argv(argv),
        category=command.category,
        risk=risk,
        origin=command.category,
        restart=restart,
        summary=summary,
        hidden_inputs=hidden_input_lines(command),
        consequence=command.consequence,
    )


def hidden_input_lines(command: ParsedCommand) -> tuple[str, ...]:
    """Describe stdin/env payloads without revealing their values."""

    lines: list[str] = []
    if command.stdin_input is not None:
        lines.append("Secret: sent on stdin (hidden)")
    names = [name for name, _value in command.env_overrides if name]
    if names:
        lines.append("Environment: " + ", ".join(f"{name}=<hidden>" for name in names))
    return tuple(lines)


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
    for index, arg in enumerate(argv):
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
                # ``--api-key-env=NAME`` shows the name (GAP-2540).
                masked.append(arg if env_name_value_in_clear(flag, value) else f"{flag}=<redacted>")
                continue

        masked.append(arg)
        if _flag_is_env(arg):
            mask_next_env = True
        elif arg.startswith("--") and _flag_is_secret(arg):
            following = argv[index + 1] if index + 1 < len(argv) else ""
            mask_next = not env_name_value_in_clear(arg, following)
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


def _upgrade_summary(args: tuple[str, ...]) -> str:
    """What ``upgrade``/``rollback`` change, which the generic summaries miss (GAP-1422)."""

    verb = args[0].lower() if args else ""
    if verb == "upgrade":
        # It read as if a new release were certain, with no versions, even
        # when the install was already up to date (GAP-2250).
        try:
            from defenseclaw import __version__ as installed
        except ImportError:  # pragma: no cover - the package always has it.
            installed = ""
        current = f"DefenseClaw {installed}" if installed else "the installed DefenseClaw"
        lowered = [arg.lower() for arg in args]
        if "--version" in lowered and lowered.index("--version") + 1 < len(args):
            target = args[lowered.index("--version") + 1]
            return (
                f"Upgrade command. Installs release {target} over {current}: "
                "replaces the DefenseClaw binaries and restarts the gateway."
            )
        return (
            f"Upgrade command. Checks the latest release first. If it is newer than {current}, "
            "installs it, replaces the DefenseClaw binaries and restarts the gateway; "
            "if you are up to date, nothing changes."
        )
    if verb == "rollback":
        return "Rollback command. Restores the previous release's binaries and restarts the gateway."
    return ""


def _gateway_lifecycle_summary(binary: str, args: tuple[str, ...]) -> str:
    """What gateway ``stop``/``start`` change; both said only "can change DefenseClaw state" (GAP-2607)."""

    if not binary.lower().removesuffix(".exe").endswith("defenseclaw-gateway"):
        return ""
    verbs = tuple(arg.lower() for arg in args if not arg.startswith("-"))
    if verbs == ("stop",):
        return (
            "Stops the gateway and its watchdog. Hooks are not checked until you start it again: "
            "fail-open connectors run unchecked and fail-closed connectors refuse tool calls."
        )
    if verbs == ("start",):
        return "Starts the gateway (and its watchdog, if enabled). Agent hooks are checked again."
    return ""


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
    if risk == "read-only":
        # ``setup observability list`` read "Risk read-only  Restart
        # possible" (GAP-2186).
        return "no"
    if lowered[:2] == ("agent", "discovery") and "--no-restart" not in lowered:
        # ``agent discovery enable|disable|setup`` and ``agent discovery
        # runtime enable|disable`` restart the gateway by default
        # (GAP-2269).
        verbs = {arg for arg in lowered[2:4] if not arg.startswith("-")}
        if verbs & {"enable", "disable", "setup"}:
            return "yes"
    if lowered[:1] == ("registry",):
        # A registry command that changes asset_policy restarts a running
        # gateway (GAP-2422); approve/reject/require always change it, sync
        # and remove only when they promote or drop rules (GAP-2499).
        verb = lowered[1] if len(lowered) > 1 else ""
        if verb in {"approve", "reject", "require"} and "--no-repromote" not in lowered:
            return "yes"
        if verb in {"sync", "remove"} and "--no-promote" not in lowered:
            return "possible"
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
        # Left/Right move between Cancel and Run like the forms' arrows;
        # only Tab did (GAP-2251).
        Binding("left", "move_focus(-1)", "Previous button", show=False),
        Binding("right", "move_focus(1)", "Next button", show=False),
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
        hidden = "".join(f"\n{rich_escape(line)}" for line in self.preview.hidden_inputs)
        with Vertical(id="preview-dialog"):
            yield Static("Confirm Command", id="preview-title")
            consequence = f"\n{rich_escape(self.preview.consequence)}" if self.preview.consequence else ""
            yield Static(f"[{color}]{summary}[/]{consequence}", id="preview-risk")
            yield Static(
                "[bold]Command[/]\n"
                f"{masked}{hidden}\n\n"
                f"[bold]Origin[/] {origin}    "
                f"[bold]Risk[/] {risk}    "
                f"[bold]Restart[/] {restart}",
                id="preview-argv",
            )
            with Horizontal(id="preview-buttons"):
                yield Button("Cancel", id="preview-cancel", variant="default")
                yield Button("Run", id="preview-run", variant="success")

    def on_mount(self) -> None:
        # Risky commands focus Cancel so a reflexive Enter cancels instead of
        # running them. Benign commands keep Run focused for fast confirmation.
        target = "#preview-cancel" if self.preview.cancel_by_default else "#preview-run"
        self.query_one(target, Button).focus()

    def action_move_focus(self, step: int) -> None:
        buttons = list(self.query("#preview-buttons Button").results(Button))
        if not buttons:
            return
        current = self.focused
        index = buttons.index(current) if current in buttons else 0
        buttons[max(0, min(len(buttons) - 1, index + step))].focus()

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
