# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Parity checks for the Textual command registry port."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from defenseclaw.tui.registry import build_registry
from defenseclaw.tui.registry_data import GO_PARITY_ENTRY_COUNT

ROOT = Path(__file__).resolve().parents[3]


def _go_registry_entries() -> dict[str, tuple[str, tuple[str, ...], str, str, bool, str]]:
    source = ROOT / "internal/tui/command.go"
    text = source.read_text(encoding="utf-8")
    block = text.split("func BuildRegistry() []CmdEntry {", 1)[1].split("// MatchCommand", 1)[0]
    pattern = re.compile(
        r'\{TUIName:\s*("(?:\\.|[^"])*"),\s*'
        r"CLIBinary:\s*([^,]+),\s*"
        r'CLIArgs:\s*\[\]string\{([^}]*)\},\s*'
        r'Description:\s*("(?:\\.|[^"])*"),\s*'
        r'Category:\s*("(?:\\.|[^"])*")'
        r"(?:,\s*NeedsArg:\s*(true|false))?"
        r'(?:,\s*ArgHint:\s*("(?:\\.|[^"])*"))?\},'
    )

    entries: dict[str, tuple[str, tuple[str, ...], str, str, bool, str]] = {}
    for match in pattern.finditer(block):
        binary_token = match.group(2).strip()
        if binary_token == "dc":
            binary = "defenseclaw"
        elif binary_token == "gw":
            binary = "defenseclaw-gateway"
        else:
            binary = ast.literal_eval(binary_token)
        args = tuple(ast.literal_eval(s.group(0)) for s in re.finditer(r'"(?:\\.|[^"])*"', match.group(3)))
        entries[ast.literal_eval(match.group(1))] = (
            binary,
            args,
            ast.literal_eval(match.group(4)),
            ast.literal_eval(match.group(5)),
            match.group(6) == "true",
            ast.literal_eval(match.group(7)) if match.group(7) else "",
        )

    assert len(entries) == block.count("{TUIName:")
    return entries


def test_textual_registry_has_exact_go_command_palette_mappings() -> None:
    go_entries = _go_registry_entries()
    py_entries = {
        entry.tui_name: (
            entry.cli_binary,
            entry.cli_args,
            entry.description,
            entry.category,
            entry.needs_arg,
            entry.arg_hint,
        )
        for entry in build_registry()
    }

    assert GO_PARITY_ENTRY_COUNT == len(go_entries) == 224
    assert sorted(set(go_entries) - set(py_entries)) == []
    assert {name: py_entries[name] for name in go_entries} == go_entries
