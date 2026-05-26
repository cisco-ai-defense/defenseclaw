# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""MCP set form screen and model tests."""

from __future__ import annotations

import pytest
from defenseclaw.tui.screens.mcp_set_form import (
    MCP_FIELD_LABELS,
    MCP_FIELD_ORDER,
    MCPSetFormScreen,
    MCPSetFormValues,
    MCPSetResult,
    MCPSetValidationError,
    apply_text_key,
    parse_env_pairs,
    skip_scan_truthy,
)
from textual.app import App, ComposeResult
from textual.widgets import Checkbox, Input, Static


class MCPSetHarness(App[MCPSetResult | None]):
    def __init__(self, initial_name: str = "") -> None:
        super().__init__()
        self.initial_name = initial_name
        self.result: MCPSetResult | None = None

    def compose(self) -> ComposeResult:
        yield Static("mcp set harness")

    def on_mount(self) -> None:
        self.push_screen(MCPSetFormScreen(self.initial_name), self._set_result)

    def _set_result(self, result: MCPSetResult | None) -> None:
        self.result = result


def test_mcp_set_form_field_order_matches_go_oracle() -> None:
    assert MCP_FIELD_ORDER == ("name", "command", "args", "url", "transport", "env", "skip_scan")
    assert MCP_FIELD_LABELS[0].startswith("Name")
    assert "Command" in MCP_FIELD_LABELS[1]
    assert "Skip scan" in MCP_FIELD_LABELS[-1]


def test_mcp_set_form_builds_cli_argv_shape() -> None:
    result = MCPSetFormValues(
        name="context7",
        command="uvx",
        args="context7-mcp",
        url="https://example.com/mcp",
        transport="sse",
        env="API_KEY=xxx, REGION=us-east-1",
        skip_scan="y",
    ).build_result()

    assert result.binary == "defenseclaw"
    assert result.display_name == "mcp set context7"
    assert result.argv == (
        "mcp",
        "set",
        "context7",
        "--command",
        "uvx",
        "--args",
        "context7-mcp",
        "--url",
        "https://example.com/mcp",
        "--transport",
        "sse",
        "--env",
        "API_KEY=xxx",
        "--env",
        "REGION=us-east-1",
        "--skip-scan",
    )


def test_mcp_set_form_validates_required_fields_and_env_pairs() -> None:
    with pytest.raises(MCPSetValidationError, match="name is required"):
        MCPSetFormValues(command="uvx").build_result()
    with pytest.raises(MCPSetValidationError, match="one of Command or URL"):
        MCPSetFormValues(name="context7").build_result()
    with pytest.raises(MCPSetValidationError, match='env "NO_EQUALS" is not KEY=VAL'):
        parse_env_pairs("TOKEN=ok, NO_EQUALS")


def test_mcp_set_form_skip_scan_truthy_and_text_editing() -> None:
    truthy = {"y", "Y", "yes", "YES", "true", "1", True}
    falsey = {"", "n", "no", "false", "0", False}

    assert all(skip_scan_truthy(value) for value in truthy)
    assert not any(skip_scan_truthy(value) for value in falsey)
    assert apply_text_key("cafe", "backspace") == "caf"
    assert apply_text_key("cafe", "ctrl+u") == ""
    assert apply_text_key("caf", "e") == "cafe"
    assert apply_text_key("cafe", "home") == "cafe"
    assert apply_text_key("cafe\N{LATIN SMALL LETTER E WITH ACUTE}", "backspace") == "cafe"


def _fill_screen(screen: MCPSetFormScreen) -> None:
    screen.query_one("#mcp-name", Input).value = "context7"
    screen.query_one("#mcp-command", Input).value = "uvx"
    screen.query_one("#mcp-args", Input).value = "context7-mcp"
    screen.query_one("#mcp-url", Input).value = "https://example.com/mcp"
    screen.query_one("#mcp-transport", Input).value = "sse"
    screen.query_one("#mcp-env", Input).value = "API_KEY=xxx, REGION=us-east-1"
    screen.query_one("#mcp-skip-scan", Checkbox).value = True


@pytest.mark.asyncio
async def test_mcp_set_form_submit_button_returns_cli_result() -> None:
    app = MCPSetHarness()

    async with app.run_test(size=(120, 44)) as pilot:
        screen = app.screen
        assert isinstance(screen, MCPSetFormScreen)
        _fill_screen(screen)
        await pilot.click("#mcp-set-submit")
        await pilot.pause()

        assert app.result is not None
        assert app.result.argv[-1] == "--skip-scan"
        assert app.result.argv[:3] == ("mcp", "set", "context7")


@pytest.mark.asyncio
async def test_mcp_set_form_ctrl_s_returns_cli_result() -> None:
    app = MCPSetHarness(initial_name="context7")

    async with app.run_test(size=(120, 44)) as pilot:
        screen = app.screen
        assert isinstance(screen, MCPSetFormScreen)
        screen.query_one("#mcp-command", Input).value = "uvx"
        await pilot.press("ctrl+s")
        await pilot.pause()

        assert app.result is not None
        assert app.result.argv == ("mcp", "set", "context7", "--command", "uvx")


@pytest.mark.asyncio
async def test_mcp_set_form_invalid_submit_keeps_modal_open_with_status() -> None:
    app = MCPSetHarness()

    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.click("#mcp-set-submit")
        await pilot.pause()

        assert app.result is None
        assert isinstance(app.screen, MCPSetFormScreen)
        assert "name is required" in app.screen.query_one("#mcp-set-status", Static).content
