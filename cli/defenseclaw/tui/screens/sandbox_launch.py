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

from defenseclaw.tui.services.sandbox_state import SANDBOX_HARNESS_SPECS, harness_command
from defenseclaw.tui.theme import DEFAULT_TOKENS

# The harnesses the Go tree runs, as (connector name, display name). A run
# names the harness by its command (sandboxcli.ResolveHarness accepts both),
# so the line the TUI prints is the one a user would type.
SANDBOX_HARNESSES: tuple[tuple[str, str], ...] = tuple((name, label) for name, label, _command in SANDBOX_HARNESS_SPECS)
SANDBOX_PROFILES: tuple[str, ...] = ("open", "balanced", "strict")
_PACK_DEFAULT = "(pack default)"


class SandboxLaunchError(ValueError):
    """The launch dialog cannot build a run."""


def _within(path: str, root: str) -> bool:
    root = root.rstrip(os.sep) or os.sep
    return path == root or path.startswith(root if root.endswith(os.sep) else root + os.sep)


def launch_folder_problem(folder: str) -> str:
    """Why a run would refuse ``folder``, in Go's words (workspace.ValidateSource), or "".

    The daemon checks again (and more: system and credential folders); this
    keeps the common mistakes in the dialog.
    """
    if not folder:
        return "choose a project folder"
    path = os.path.abspath(os.path.expanduser(folder))
    if not os.path.isdir(path):
        return f"{path} is not a folder"
    real = os.path.realpath(path)
    refusing = f"refusing to share {real} with a sandbox: "
    if real == os.sep or real.count(os.sep) < 2:
        return refusing + "it is a top-level system directory"
    home = os.path.realpath(os.path.expanduser("~"))
    if home and real == home:
        return refusing + "it is your home directory (launch from a project folder inside it)"
    if home and _within(home, real):
        return refusing + "it contains your home directory"
    return ""


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
        problem = launch_folder_problem(self.folder.strip())
        if problem:
            raise SandboxLaunchError(problem)
        folder = os.path.abspath(os.path.expanduser(self.folder.strip()))
        command = harness_command(harness)
        argv: list[str] = ["sandbox", "run", command]
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
        return SandboxLaunch(tuple(argv), folder, f"sandbox run {command} in {folder}")


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
        width: 100%;
        max-width: 84;
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
        color: {DEFAULT_TOKENS.accent_amber};
    }}

    #sandbox-launch-status.-empty {{
        display: none;
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
        self.folder = folder

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="sandbox-launch-dialog"):
            yield Static("New sandboxed run", id="sandbox-launch-title")
            # At the top: a refusal must be visible without scrolling.
            yield Static("", id="sandbox-launch-status", classes="-empty", markup=False)
            yield Static(
                "The harness gets this terminal; the TUI comes back when it exits.",
                classes="sandbox-launch-label",
            )
            yield Static("Harness", classes="sandbox-launch-label")
            yield Select(self.harnesses, value=self.harnesses[0][1], allow_blank=False, id="sandbox-launch-harness")
            yield Static("Project folder (the agent sees only this folder)", classes="sandbox-launch-label")
            yield Input(
                value=self.folder, placeholder="a project folder, e.g. ~/code/myapp", id="sandbox-launch-folder"
            )
            yield Static("Name (optional)", classes="sandbox-launch-label")
            yield Input(placeholder="<folder>-<random>", id="sandbox-launch-name")
            yield Static("Network profile", classes="sandbox-launch-label")
            yield Select(
                tuple((option, option) for option in (_PACK_DEFAULT, *SANDBOX_PROFILES)),
                value=_PACK_DEFAULT,
                allow_blank=False,
                id="sandbox-launch-profile",
            )
            yield Checkbox("Work on a copy (untrusted repository or task)", id="sandbox-launch-copy")
            yield Checkbox("Keep the harness's own permission prompts (--safe)", id="sandbox-launch-safe")
            with Horizontal(id="sandbox-launch-buttons"):
                yield Button("Cancel", id="sandbox-launch-cancel")
                yield Button("Start", id="sandbox-launch-submit", variant="success")

    def on_mount(self) -> None:
        self.query_one("#sandbox-launch-harness", Select).focus()
        if not self.folder:
            self._show_status("Choose the project folder the agent may see (not your home folder).")

    def _show_status(self, text: str) -> None:
        status = self.query_one("#sandbox-launch-status", Static)
        status.update(text)
        status.set_class(not text, "-empty")
        if text:
            self.query_one("#sandbox-launch-dialog", VerticalScroll).scroll_home(animate=False)

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
            message = str(exc)
            self._show_status(message[:1].upper() + message[1:] + ".")
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
