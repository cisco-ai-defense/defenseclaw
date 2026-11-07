# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""The per-user column of the managed command-availability table.

internal/cli/testdata/managed_commands.json is generated from the Go table
that decides what a managed computer offers (internal/cli/managed_commands.go).
Its per-user column says the command exists in the per-user install, which is
this Python CLI. Every command path the table names must resolve here.
"""

from __future__ import annotations

import json
from pathlib import Path

import click
import pytest
from defenseclaw.main import cli

TABLE = Path(__file__).resolve().parents[2] / "internal" / "cli" / "testdata" / "managed_commands.json"


def _rows() -> list[dict]:
    return json.loads(TABLE.read_text(encoding="utf-8"))["commands"]


def _resolve(path: list[str]) -> click.Command:
    path_text = " ".join(path)
    command: click.Command = cli
    ctx = click.Context(cli)
    for word in path:
        assert isinstance(command, click.Group), f"{path_text}: {word} follows a command that has no subcommands"
        child = command.get_command(ctx, word)
        assert child is not None, f"the per-user CLI has no command {path_text!r}"
        command = child
    return command


@pytest.mark.parametrize("row", [r for r in _rows() if r.get("per_user_path")], ids=lambda r: r["command"])
def test_the_per_user_column_names_commands_the_per_user_cli_has(row: dict) -> None:
    _resolve(row["per_user_path"].split())
