# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Platform truth for connector commands in the Textual command palette."""

from __future__ import annotations

from defenseclaw.tui.registry import build_registry


def _setup_connectors(os_name: str) -> dict[str, str]:
    return {
        entry.cli_args[1]: entry.description
        for entry in build_registry(os_name)
        if len(entry.cli_args) >= 2 and entry.cli_args[0] == "setup"
    }


def test_windows_palette_hides_unsupported_connector_setup_commands() -> None:
    commands = _setup_connectors("windows")

    assert {"openclaw", "zeptoclaw", "openhands", "geminicli"}.isdisjoint(commands)
    assert {
        "amp",
        "antigravity",
        "claude-code",
        "codex",
        "copilot",
        "cursor",
        "hermes",
        "omnigent",
        "opencode",
        "devin",
    } <= commands.keys()


def test_non_windows_palette_retains_all_connector_setup_commands() -> None:
    for os_name in ("darwin", "linux"):
        commands = _setup_connectors(os_name)
        assert {"openclaw", "zeptoclaw", "openhands"} <= commands.keys()
        assert "geminicli" not in commands
