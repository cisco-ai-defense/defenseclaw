# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""MCP add/update form screen and argv model."""

from __future__ import annotations

from dataclasses import dataclass

from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Static

from defenseclaw.tui.theme import DEFAULT_TOKENS

MCP_FIELD_ORDER: tuple[str, ...] = ("name", "command", "args", "url", "transport", "env", "skip_scan")
MCP_FIELD_LABELS: tuple[str, ...] = (
    "Name (required)",
    "Command (e.g. npx, uvx) - at least one of Command/URL",
    "Args (JSON array or comma-separated)",
    "URL (for SSE/HTTP transport)",
    "Transport (stdio, sse; blank = auto)",
    "Env vars (KEY=VAL, comma-separated)",
    "Skip scan",
)


class MCPSetValidationError(ValueError):
    """Raised when the MCP set form cannot build safe argv."""


@dataclass(frozen=True)
class MCPSetResult:
    """Command result emitted by the MCP set form."""

    binary: str
    argv: tuple[str, ...]
    display_name: str


@dataclass(frozen=True)
class MCPSetFormValues:
    """Pure MCP set form state."""

    name: str = ""
    command: str = ""
    args: str = ""
    url: str = ""
    transport: str = ""
    env: str = ""
    skip_scan: bool | str = False

    def build_result(self) -> MCPSetResult:
        """Validate and render the form values into `defenseclaw mcp set` argv."""

        name = self.name.strip()
        if not name:
            raise MCPSetValidationError("name is required")

        command = self.command.strip()
        url = self.url.strip()
        if not command and not url:
            raise MCPSetValidationError("one of Command or URL is required")

        argv: list[str] = ["mcp", "set", name]
        if command:
            argv.extend(("--command", command))
        if args := self.args.strip():
            argv.extend(("--args", args))
        if url:
            argv.extend(("--url", url))
        if transport := self.transport.strip():
            argv.extend(("--transport", transport))
        for pair in parse_env_pairs(self.env):
            argv.extend(("--env", pair))
        if skip_scan_truthy(self.skip_scan):
            argv.append("--skip-scan")
        return MCPSetResult(
            binary="defenseclaw",
            argv=tuple(argv),
            display_name=f"mcp set {name}",
        )


class MCPSetFormScreen(ModalScreen[MCPSetResult | None]):
    """Textual MCP set form with validation before dispatch."""

    CSS = f"""
    MCPSetFormScreen {{
        align: center middle;
    }}

    #mcp-set-dialog {{
        width: 90;
        height: auto;
        padding: 1 2;
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_panel};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #mcp-set-title {{
        height: 1;
        margin-bottom: 1;
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    .mcp-set-label {{
        height: 1;
        margin-top: 1;
        color: {DEFAULT_TOKENS.text_secondary};
    }}

    #mcp-set-status {{
        height: 1;
        margin-top: 1;
        color: {DEFAULT_TOKENS.accent_amber};
    }}

    #mcp-set-buttons {{
        height: 3;
        margin-top: 1;
        align-horizontal: right;
    }}

    #mcp-set-submit {{
        margin-left: 1;
    }}
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
        Binding("ctrl+s", "submit", "Submit", show=False),
    ]

    def __init__(self, initial_name: str = "") -> None:
        super().__init__()
        self.initial_name = initial_name

    def compose(self) -> ComposeResult:
        with Vertical(id="mcp-set-dialog"):
            yield Static("Add/Update MCP Server", id="mcp-set-title")
            yield Static(MCP_FIELD_LABELS[0], classes="mcp-set-label")
            yield Input(value=self.initial_name, id="mcp-name")
            yield Static(MCP_FIELD_LABELS[1], classes="mcp-set-label")
            yield Input(id="mcp-command")
            yield Static(MCP_FIELD_LABELS[2], classes="mcp-set-label")
            yield Input(id="mcp-args")
            yield Static(MCP_FIELD_LABELS[3], classes="mcp-set-label")
            yield Input(id="mcp-url")
            yield Static(MCP_FIELD_LABELS[4], classes="mcp-set-label")
            yield Input(id="mcp-transport")
            yield Static(MCP_FIELD_LABELS[5], classes="mcp-set-label")
            yield Input(id="mcp-env")
            yield Static(MCP_FIELD_LABELS[6], classes="mcp-set-label")
            yield Checkbox("Skip scan before adding", id="mcp-skip-scan")
            yield Static("", id="mcp-set-status")
            with Horizontal(id="mcp-set-buttons"):
                yield Button("Cancel", id="mcp-set-cancel", variant="default")
                yield Button("Set MCP", id="mcp-set-submit", variant="success")

    def on_mount(self) -> None:
        self.query_one("#mcp-name", Input).focus()

    def values(self) -> MCPSetFormValues:
        """Collect current widget values into a pure model."""

        return MCPSetFormValues(
            name=self.query_one("#mcp-name", Input).value,
            command=self.query_one("#mcp-command", Input).value,
            args=self.query_one("#mcp-args", Input).value,
            url=self.query_one("#mcp-url", Input).value,
            transport=self.query_one("#mcp-transport", Input).value,
            env=self.query_one("#mcp-env", Input).value,
            skip_scan=self.query_one("#mcp-skip-scan", Checkbox).value,
        )

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_submit(self) -> None:
        try:
            result = self.values().build_result()
        except MCPSetValidationError as exc:
            self.query_one("#mcp-set-status", Static).update(str(exc))
            return
        self.dismiss(result)

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:
            event.stop()
            self.dismiss(None)

    @on(Button.Pressed, "#mcp-set-cancel")
    def _on_cancel_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_cancel()

    @on(Button.Pressed, "#mcp-set-submit")
    def _on_submit_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_submit()


def parse_env_pairs(value: str) -> tuple[str, ...]:
    """Parse comma-separated KEY=VAL pairs into repeated --env values."""

    pairs: list[str] = []
    for raw_pair in value.split(","):
        pair = raw_pair.strip()
        if not pair:
            continue
        if "=" not in pair:
            raise MCPSetValidationError(f'env "{pair}" is not KEY=VAL')
        pairs.append(pair)
    return tuple(pairs)


def skip_scan_truthy(value: bool | str) -> bool:
    """Return true for Go-compatible skip-scan truthy spellings."""

    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"y", "yes", "true", "1"}


def apply_text_key(value: str, key: str) -> str:
    """Apply the Go form's minimal text editing keys to a field value."""

    if key == "backspace":
        return value[:-1]
    if key == "ctrl+u":
        return ""
    if len(key) == 1:
        return value + key
    return value
