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
    MCPSetFormValues,
    MCPSetValidationError,
    apply_text_key,
    parse_env_pairs,
    skip_scan_truthy,
)


def test_mcp_set_form_field_order_matches_go_oracle() -> None:
    assert MCP_FIELD_ORDER == ("name", "command", "args", "url", "transport", "env", "skip_scan")
    assert MCP_FIELD_LABELS[0].startswith("Name")
    assert "Command" in MCP_FIELD_LABELS[1]
    assert "Skip scan" in MCP_FIELD_LABELS[-1]


def test_mcp_set_form_builds_cli_argv_shape() -> None:
    # F-1821: Command and URL are mutually exclusive. A local command and a
    # remote URL are scanned differently by the CLI (scanner uses
    # ``is_local = command and not url``), so a mixed entry would scan the URL
    # while installing/running the command. Build a single-flag (local) entry.
    result = MCPSetFormValues(
        name="context7",
        command="uvx",
        args="context7-mcp",
        transport="stdio",
        env="API_KEY=xxx, REGION=us-east-1",
        skip_scan="y",
    ).build_result()

    assert result.binary == "defenseclaw"
    assert result.display_name == "mcp set context7"
    # F-0803: env pairs must NOT be placed in argv (they leak secrets in
    # process listings). They travel via ``result.env`` and are injected
    # into the child process environment by the executor.
    assert result.argv == (
        "mcp",
        "set",
        "context7",
        "--command",
        "uvx",
        "--args",
        "context7-mcp",
        "--transport",
        "stdio",
        "--skip-scan",
    )
    # The mixed entry never produces both flags.
    assert not ("--command" in result.argv and "--url" in result.argv)
    assert "--env" not in result.argv
    assert all("API_KEY=xxx" not in arg for arg in result.argv)
    assert result.env == (("API_KEY", "xxx"), ("REGION", "us-east-1"))


def test_mcp_set_form_rejects_mixed_command_and_url() -> None:
    # F-1821: A mixed command+url entry is scanned remotely (URL) but the local
    # command is what gets installed/run, so reject it instead of silently
    # building a both-flags argv.
    with pytest.raises(MCPSetValidationError, match="exactly one of Command or URL"):
        MCPSetFormValues(
            name="context7",
            command="uvx",
            args="context7-mcp",
            url="https://example.com/mcp",
        ).build_result()


def test_mcp_set_form_threads_connector_into_argv() -> None:
    # B10: an MCP added from a filtered connector view must write to that
    # connector's config via ``--connector``, not the default/primary one.
    result = MCPSetFormValues(
        name="context7",
        command="uvx",
        connector="hermes",
    ).build_result()
    assert result.argv == (
        "mcp",
        "set",
        "context7",
        "--command",
        "uvx",
        "--connector",
        "hermes",
    )


def test_mcp_set_form_omits_connector_when_unfocused() -> None:
    # Empty connector (single-connector install / merged "All" view) keeps the
    # legacy argv shape so the active connector is targeted exactly as before.
    result = MCPSetFormValues(name="context7", command="uvx").build_result()
    assert "--connector" not in result.argv


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
