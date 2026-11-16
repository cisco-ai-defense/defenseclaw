# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The Python readers read the Windows hook commands Go writes (g072 review 3 M3).

Go's TestWindowsHookCommandsMatchThePythonReadersGolden writes the golden
file from the real builders (internal/gateway/connector) and fails when a
builder's output drifts from it; these tests feed the same file to the Python
readers and to the doctor test fixtures. A row exists for every PowerShell
single quote: the apostrophe and U+2018 to U+201B.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path, PureWindowsPath

import pytest
from defenseclaw.cursor_contract import _call_operator_literals_current, split_cursor_hook_command
from defenseclaw.doctor_hooks import (
    _COPILOT_ADAPTER_HOOK_BINARY,
    _command_target,
    _copilot_powershell_binding,
    _powershell_literals_current,
    copilot_setup_command,
)
from defenseclaw.winquote import (
    powershell_command_line,
    powershell_literal,
    powershell_literal_before_typographic_quotes,
    powershell_literal_is_current,
    powershell_literal_value,
    run_instruction,
    split_windows_words,
)

from tests.test_cmd_doctor_windows_copilot import _adapter_body, _powershell_command
from tests.test_cmd_doctor_windows_hooks import WindowsHookDoctorTests

_GOLDEN = Path(__file__).resolve().parents[2] / "testdata" / "powershell_quotes" / "windows_hook_commands.json"
_ROWS = json.loads(_GOLDEN.read_text(encoding="utf-8"))["rows"]
_LINES = json.loads((_GOLDEN.parent / "command_lines.json").read_text(encoding="utf-8"))["rows"]
_TYPOGRAPHIC = [row for row in _ROWS if row["quote"] != "U+0027"]


def test_the_golden_has_every_powershell_single_quote() -> None:
    assert [row["quote"] for row in _ROWS] == ["U+0027", "U+2018", "U+2019", "U+201A", "U+201B"]
    for row in _ROWS:
        quote = chr(int(row["quote"][2:], 16))
        assert f"O{quote}Brien" in row["hook"]
        assert f"O{quote}{quote}Brien" in row["hook_literal"], row


@pytest.mark.parametrize("row", _ROWS, ids=[row["quote"] for row in _ROWS])
def test_python_quotes_and_reads_a_literal_as_go_does(row: dict[str, str]) -> None:
    assert powershell_literal(row["hook"]) == row["hook_literal"]
    body = row["hook_literal"][1:-1]
    assert powershell_literal_value(body) == row["hook"]
    assert powershell_literal_is_current(body)


@pytest.mark.parametrize("row", _ROWS, ids=[row["quote"] for row in _ROWS])
def test_copilot_readers_own_the_go_command(row: dict[str, str]) -> None:
    command, adapter, event = row["copilot_command"], row["copilot_adapter"], row["copilot_event"]
    assert copilot_setup_command(adapter, event) == command
    assert _powershell_command(PureWindowsPath(adapter), event) == command
    assert _copilot_powershell_binding(command) == (adapter, event)
    line = _COPILOT_ADAPTER_HOOK_BINARY.search(row["copilot_adapter_hook_line"])
    assert line and powershell_literal_value(line.group(1)) == row["hook"]
    assert row["copilot_adapter_hook_line"] in _adapter_body(PureWindowsPath(row["hook"])).splitlines()


@pytest.mark.parametrize("row", _ROWS, ids=[row["quote"] for row in _ROWS])
def test_bridge_readers_own_the_go_command(row: dict[str, str]) -> None:
    for command in (row["codex_bridge"], row["codex_direct"]):
        target, args, _kind = _command_target(command, "codex")
        assert target == row["hook"], command
        assert args == ["hook", "--connector", "codex"]
        assert _powershell_literals_current(command)
    assert WindowsHookDoctorTests._encoded_hook_command(PureWindowsPath(row["hook"])) == row["codex_bridge"]


@pytest.mark.parametrize("row", _ROWS, ids=[row["quote"] for row in _ROWS])
def test_cursor_reader_owns_the_go_command(row: dict[str, str]) -> None:
    assert split_cursor_hook_command(row["cursor_command"], platform_name="nt") == [row["cursor_adapter"]]
    assert _call_operator_literals_current(row["cursor_command"])


@pytest.mark.parametrize("row", _TYPOGRAPHIC, ids=[row["quote"] for row in _TYPOGRAPHIC])
def test_the_pre_1_0_9_render_is_owned_and_stale(row: dict[str, str]) -> None:
    """Releases before 1.0.9 doubled only the apostrophe: the same path, not a current command."""
    bridge = row["codex_bridge_before_1_0_9"]
    script = base64.b64decode(bridge.rsplit(" ", 1)[1]).decode("utf-16-le")
    current = base64.b64decode(row["codex_bridge"].rsplit(" ", 1)[1]).decode("utf-16-le")
    assert script == powershell_literal_before_typographic_quotes(current)
    for command in (bridge, row["codex_direct_before_1_0_9"]):
        target, _args, _kind = _command_target(command, "codex")
        assert target == row["hook"], command
        assert not _powershell_literals_current(command)
    copilot = row["copilot_command_before_1_0_9"]
    assert copilot == powershell_literal_before_typographic_quotes(row["copilot_command"])
    assert _copilot_powershell_binding(copilot) == (row["copilot_adapter"], row["copilot_event"])
    cursor = row["cursor_command_before_1_0_9"]
    assert split_cursor_hook_command(cursor, platform_name="nt") == [row["cursor_adapter"]]
    assert not _call_operator_literals_current(cursor)


def test_a_lone_quote_is_kept_and_not_current() -> None:
    for quote in "\u2018\u2019\u201a\u201b":
        assert powershell_literal_value(f"O{quote}Brien") == f"O{quote}Brien"
        assert not powershell_literal_is_current(f"O{quote}Brien")
        assert powershell_literal_value(f"O{quote}{quote}Brien") == f"O{quote}Brien"
    assert powershell_literal_value("O''Brien") == "O'Brien"


@pytest.mark.parametrize("row", _LINES, ids=[str(index) for index in range(len(_LINES))])
def test_python_renders_a_command_line_as_go_does(row: dict) -> None:
    """g072 review 3 M2: winquote.powershell_command_line is managed.WindowsCommandLine."""
    line = powershell_command_line(row["executable"], *row["args"])
    assert line == row["line"]
    if any(" " in arg for arg in row["args"] if arg[:1] == "<"):
        return  # a <placeholder> the reader replaces is not one word yet
    words = split_windows_words(line)
    assert words[0] == "&"
    read = [powershell_literal_value(word[1:-1]) if word[:1] == "'" else word for word in words[1:]]
    assert read == [row["executable"], *row["args"]]


def test_the_command_line_golden_has_every_powershell_single_quote() -> None:
    lines = " ".join(row["line"] for row in _LINES)
    for quote in "'\u2018\u2019\u201a\u201b":
        assert f"O{quote}{quote}Brien" in lines, quote


def test_run_instruction_names_powershell_on_windows() -> None:
    assert run_instruction("& 'x' status", windows=True) == "in PowerShell, run & 'x' status"
    assert run_instruction("defenseclaw status", windows=False) == "run defenseclaw status"
