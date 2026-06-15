# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Command preview modal parity tests."""

from __future__ import annotations

import pytest
from defenseclaw.tui.command_line import ParsedCommand
from defenseclaw.tui.screens.command_preview import CommandPreviewScreen, build_command_preview, mask_argv
from textual.app import App, ComposeResult
from textual.widgets import Static


def _parsed(args: tuple[str, ...], *, category: str = "setup") -> ParsedCommand:
    return ParsedCommand(
        binary="defenseclaw",
        args=args,
        display_name=" ".join(args),
        category=category,
        needs_preview=True,
    )


def test_command_preview_masks_secret_flags() -> None:
    masked = mask_argv(("defenseclaw", "keys", "set", "OPENAI_API_KEY", "--value", "sk-test"))

    assert masked == ("defenseclaw", "keys", "set", "OPENAI_API_KEY", "--value", "<redacted>")


def test_command_preview_classifies_destructive_commands_as_high_risk() -> None:
    preview = build_command_preview(_parsed(("uninstall", "--all", "--yes"), category="other"))

    assert preview.risk == "destructive"
    assert "Destructive" in preview.summary


def test_command_preview_shows_origin_and_restart_effect() -> None:
    preview = build_command_preview(_parsed(("setup", "codex", "--yes"), category="setup"))

    assert preview.origin == "setup"
    assert preview.restart == "possible"


class PreviewHarness(App[bool | None]):
    def __init__(self, command: ParsedCommand) -> None:
        super().__init__()
        self.command = command
        self.result: bool | None = None

    def compose(self) -> ComposeResult:
        yield Static("preview harness")

    def on_mount(self) -> None:
        self.push_screen(CommandPreviewScreen(self.command), self._set_result)

    def _set_result(self, result: bool) -> None:
        self.result = result


@pytest.mark.asyncio
async def test_command_preview_enter_confirms() -> None:
    app = PreviewHarness(_parsed(("setup", "mode", "codex")))

    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press("enter")
        await pilot.pause()

        assert app.result is True


@pytest.mark.asyncio
async def test_command_preview_run_button_confirms() -> None:
    app = PreviewHarness(_parsed(("setup", "mode", "codex")))

    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.click("#preview-run")
        await pilot.pause()

        assert app.result is True


@pytest.mark.asyncio
async def test_command_preview_cancel_button_dismisses() -> None:
    app = PreviewHarness(_parsed(("setup", "mode", "codex")))

    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.click("#preview-cancel")
        await pilot.pause()

        assert app.result is False
