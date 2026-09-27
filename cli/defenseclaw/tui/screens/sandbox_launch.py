# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The Sandboxes panel's launch dialog: start a new sandboxed harness run.

The dialog collects the run flags and the project folder; the app then hands
the terminal to ``defenseclaw-gateway sandbox run`` (``App.suspend``) in that
folder, so the harness owns the terminal exactly as on the command line.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Select, Static

from defenseclaw.tui.theme import DEFAULT_TOKENS

# The harnesses the Go tree runs today, by command name (sandboxcli.ResolveHarness
# accepts both the connector and the command name).
SANDBOX_HARNESSES: tuple[tuple[str, str], ...] = (("claudecode", "Claude Code"), ("codex", "Codex"))
SANDBOX_PROFILES: tuple[str, ...] = ("open", "balanced", "strict")
_PACK_DEFAULT = "(pack default)"


class SandboxLaunchError(ValueError):
    """The launch dialog cannot build a run."""


@dataclass(frozen=True)
class SandboxLaunch:
    """A validated run: argv after the gateway binary, and its working folder."""

    argv: tuple[str, ...]
    cwd: str
    display: str


@dataclass(frozen=True)
class SandboxLaunchValues:
    harness: str = "claudecode"
    folder: str = ""
    name: str = ""
    copy: bool = False
    safe: bool = False
    profile: str = ""

    def build(self) -> SandboxLaunch:
        harness = self.harness.strip()
        if not harness:
            raise SandboxLaunchError("choose a harness")
        folder = os.path.abspath(os.path.expanduser(self.folder.strip() or os.getcwd()))
        if not os.path.isdir(folder):
            raise SandboxLaunchError(f"{folder} is not a folder")
        # The daemon refuses these too (workspace.ValidateSource); saying so
        # here keeps the operator in the dialog.
        home = os.path.abspath(os.path.expanduser("~"))
        if folder == home or home.startswith(folder.rstrip(os.sep) + os.sep):
            raise SandboxLaunchError("run in a project folder inside your home folder, not the home folder itself")
        argv: list[str] = ["sandbox", "run", harness]
        name = self.name.strip()
        if name:
            argv += ["--name", name]
        if self.copy:
            argv.append("--copy")
        if self.safe:
            argv.append("--safe")
        profile = self.profile.strip()
        if profile and profile != _PACK_DEFAULT:
            if profile not in SANDBOX_PROFILES:
                raise SandboxLaunchError(f"unknown profile {profile!r}")
            argv += ["--profile", profile]
        return SandboxLaunch(tuple(argv), folder, f"sandbox run {harness} in {folder}")


def harness_choices(configured: tuple[str, ...], allowed: tuple[str, ...] = ()) -> tuple[tuple[str, str], ...]:
    """The harnesses to offer: the configured ones first, filtered by the admin allowlist."""
    known = dict(SANDBOX_HARNESSES)
    names = [name for name in configured if name in known] or [name for name, _label in SANDBOX_HARNESSES]
    for name, _label in SANDBOX_HARNESSES:
        if name not in names:
            names.append(name)
    if allowed:
        names = [name for name in names if name in allowed]
    return tuple((known[name], name) for name in names)


class SandboxLaunchScreen(ModalScreen[SandboxLaunch | None]):
    """Launch dialog returning a validated :class:`SandboxLaunch`."""

    CSS = f"""
    SandboxLaunchScreen {{
        align: center middle;
    }}

    #sandbox-launch-dialog {{
        width: 84;
        height: auto;
        max-height: 95%;
        padding: 1 2;
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_panel};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #sandbox-launch-title {{
        height: 1;
        margin-bottom: 1;
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    .sandbox-launch-label {{
        height: 1;
        margin-top: 1;
        color: {DEFAULT_TOKENS.text_secondary};
    }}

    #sandbox-launch-status {{
        height: auto;
        margin-top: 1;
        color: {DEFAULT_TOKENS.accent_amber};
    }}

    #sandbox-launch-buttons {{
        height: 3;
        margin-top: 1;
        align-horizontal: right;
    }}

    #sandbox-launch-submit {{
        margin-left: 1;
    }}
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
        Binding("ctrl+s", "submit", "Start", show=False),
    ]

    def __init__(
        self,
        harnesses: tuple[tuple[str, str], ...] = (),
        *,
        folder: str = "",
    ) -> None:
        super().__init__()
        self.harnesses = harnesses or tuple((label, name) for name, label in SANDBOX_HARNESSES)
        self.folder = folder or os.getcwd()

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="sandbox-launch-dialog"):
            yield Static("New sandboxed run", id="sandbox-launch-title")
            yield Static(
                "The harness gets this terminal; the TUI comes back when it exits.",
                classes="sandbox-launch-label",
            )
            yield Static("Harness", classes="sandbox-launch-label")
            yield Select(self.harnesses, value=self.harnesses[0][1], allow_blank=False, id="sandbox-launch-harness")
            yield Static("Project folder (the agent sees only this folder)", classes="sandbox-launch-label")
            yield Input(value=self.folder, id="sandbox-launch-folder")
            yield Static("Name (optional)", classes="sandbox-launch-label")
            yield Input(placeholder="dc-<harness>-<folder>-<random>", id="sandbox-launch-name")
            yield Static("Network profile", classes="sandbox-launch-label")
            yield Select(
                tuple((option, option) for option in (_PACK_DEFAULT, *SANDBOX_PROFILES)),
                value=_PACK_DEFAULT,
                allow_blank=False,
                id="sandbox-launch-profile",
            )
            yield Checkbox("Work on a copy (untrusted repository or task)", id="sandbox-launch-copy")
            yield Checkbox("Keep the harness's own permission prompts (--safe)", id="sandbox-launch-safe")
            yield Static("", id="sandbox-launch-status")
            with Horizontal(id="sandbox-launch-buttons"):
                yield Button("Cancel", id="sandbox-launch-cancel")
                yield Button("Start", id="sandbox-launch-submit", variant="success")

    def values(self) -> SandboxLaunchValues:
        harness = self.query_one("#sandbox-launch-harness", Select).value
        profile = self.query_one("#sandbox-launch-profile", Select).value
        return SandboxLaunchValues(
            harness=str(harness) if harness not in (None, Select.BLANK) else "",
            folder=self.query_one("#sandbox-launch-folder", Input).value,
            name=self.query_one("#sandbox-launch-name", Input).value,
            copy=self.query_one("#sandbox-launch-copy", Checkbox).value,
            safe=self.query_one("#sandbox-launch-safe", Checkbox).value,
            profile=str(profile) if profile not in (None, Select.BLANK) else "",
        )

    def action_submit(self) -> None:
        try:
            launch = self.values().build()
        except SandboxLaunchError as exc:
            self.query_one("#sandbox-launch-status", Static).update(str(exc))
            return
        self.dismiss(launch)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:
            event.stop()
            self.dismiss(None)

    @on(Button.Pressed, "#sandbox-launch-submit")
    def _on_submit(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_submit()

    @on(Button.Pressed, "#sandbox-launch-cancel")
    def _on_cancel(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_cancel()

    @on(Input.Submitted)
    def _on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        self.action_submit()
