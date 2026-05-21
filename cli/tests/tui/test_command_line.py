# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Initial command-line parser contract for the Python Textual TUI."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))


FIXTURES = Path(__file__).parent / "fixtures"


def _command_line_module() -> ModuleType:
    try:
        from defenseclaw.tui import command_line
    except ModuleNotFoundError as exc:
        pytest.xfail(f"planned Textual migration contract: defenseclaw.tui.command_line is not present yet ({exc})")
    return command_line


def _parser():
    module = _command_line_module()
    parser = getattr(module, "parse_command_line", None)
    if parser is None:
        pytest.xfail("planned Textual migration contract: parse_command_line(text) is not present yet")
    return parser


def _validation_error() -> type[Exception]:
    module = _command_line_module()
    error = getattr(module, "CommandValidationError", None) or getattr(module, "CommandLineError", None)
    if error is None:
        pytest.xfail("planned Textual migration contract: command-line validation error is not present yet")
    return error


def _argv(parsed) -> list[str]:
    argv = getattr(parsed, "argv", None)
    if argv is not None:
        return list(argv)
    binary = getattr(parsed, "binary", None)
    args = getattr(parsed, "args", None)
    if binary is not None and args is not None:
        return [binary, *list(args)]
    pytest.fail("parse_command_line(text) should return structured command argv data")


@pytest.mark.parametrize(
    ("text", "expected_argv"),
    [
        ("defenseclaw version", ["defenseclaw", "version"]),
        ("defenseclaw doctor", ["defenseclaw", "doctor"]),
    ],
)
def test_textual_command_parser_accepts_safe_defenseclaw_commands(text: str, expected_argv: list[str]) -> None:
    parsed = _parser()(text)

    assert _argv(parsed) == expected_argv


@pytest.mark.parametrize(
    "text",
    [
        "ls -la",
        "python -c 'print(1)'",
        "curl https://example.invalid",
        "FOO=bar defenseclaw doctor",
    ],
)
def test_textual_command_parser_rejects_arbitrary_host_commands(text: str) -> None:
    with pytest.raises(_validation_error()):
        _parser()(text)


@pytest.mark.parametrize(
    "text",
    [
        "defenseclaw doctor && rm -rf /",
        "defenseclaw version | cat",
        "defenseclaw doctor > out.txt",
        "defenseclaw doctor < in.txt",
        "defenseclaw doctor; defenseclaw version",
        "defenseclaw doctor $(whoami)",
        "defenseclaw doctor `whoami`",
    ],
)
def test_textual_command_parser_rejects_shell_operators(text: str) -> None:
    with pytest.raises(_validation_error()):
        _parser()(text)


def test_textual_command_parser_accepts_go_palette_aliases() -> None:
    parsed = _parser()("scan skill example-skill")

    assert _argv(parsed) == ["defenseclaw", "skill", "scan", "example-skill"]
    assert parsed.category == "scan"
    assert parsed.risk == "read-only"
    assert parsed.needs_preview is False


@pytest.mark.parametrize(
    "text",
    [
        "scan skill",
        "defenseclaw skill scan",
        "setup redaction",
        "defenseclaw setup redaction",
        "setup observability enable",
        "policy activate",
    ],
)
def test_textual_command_parser_rejects_go_registry_entries_missing_required_args(text: str) -> None:
    with pytest.raises(_validation_error()):
        _parser()(text)


@pytest.mark.parametrize(
    ("text", "risk"),
    [
        ("block skill bad", "mutation"),
        ("policy activate prod", "mutation"),
        ("plugin remove x", "destructive"),
        ("allow mcp https://example.invalid/mcp", "mutation"),
        ("defenseclaw doctor --fix --yes", "setup"),
        ("defenseclaw keys set OPENAI_API_KEY --value sk-test-123456", "secret"),
    ],
)
def test_textual_command_parser_previews_go_mutation_risk_classes(text: str, risk: str) -> None:
    parsed = _parser()(text)

    assert parsed.risk == risk
    assert parsed.needs_preview is True


@pytest.mark.parametrize(
    "text",
    [
        "setup redaction status",
        "defenseclaw setup local-observability status",
        "defenseclaw keys check",
        "policy validate",
    ],
)
def test_textual_command_parser_keeps_go_read_only_special_cases_unpreviewed(text: str) -> None:
    parsed = _parser()(text)

    assert parsed.risk == "read-only"
    assert parsed.needs_preview is False


def test_textual_command_parser_preserves_go_longest_prefix_matching() -> None:
    parsed = _parser()("scan skillexample-skill")

    assert _argv(parsed) == ["defenseclaw", "skill", "scan", "example-skill"]


def test_textual_command_parser_keeps_raw_read_only_commands_unblocked() -> None:
    parsed = _parser()("defenseclaw skill list --json")

    assert _argv(parsed) == ["defenseclaw", "skill", "list", "--json"]
    assert parsed.category == "info"
    assert parsed.needs_preview is False


def test_textual_command_parser_previews_raw_setup_commands() -> None:
    parsed = _parser()("defenseclaw setup mode codex")

    assert _argv(parsed) == ["defenseclaw", "setup", "mode", "codex"]
    assert parsed.category == "setup"
    assert parsed.needs_preview is True


def test_textual_command_parser_previews_bare_defenseclaw_setup() -> None:
    """Bare ``defenseclaw setup`` launches the interactive connector
    picker, which blocks on stdin and is impossible to drive cleanly
    from inside the TUI. The risk classifier used to mark it
    "read-only" (because ``len(args) == 1``) so the drawer skipped the
    preview screen and dropped operators straight into a
    ``Selection [3]:`` prompt with no way out. Lock the corrected
    classification in so a future change can't regress us back into
    that trap.
    """

    parsed = _parser()("defenseclaw setup")

    assert _argv(parsed) == ["defenseclaw", "setup"]
    assert parsed.category == "setup"
    assert parsed.risk == "setup"
    assert parsed.needs_preview is True


def test_textual_command_parser_accepts_go_gateway_registry_commands() -> None:
    parsed = _parser()("defenseclaw-gateway status")

    assert _argv(parsed) == ["defenseclaw-gateway", "status"]
    assert parsed.category == "daemon"
    assert parsed.needs_preview is False


def test_migration_ledger_fixture_skeleton_is_well_formed() -> None:
    payload = json.loads((FIXTURES / "migration_ledger_skeleton.json").read_text(encoding="utf-8"))

    assert payload["schema_version"] == 1
    assert payload["migration"] == "python-textual-tui"
    assert payload["expected_interfaces"]["backend_option"] == "--backend"
    assert payload["expected_interfaces"]["backend_env"] == "DEFENSECLAW_TUI_BACKEND"
    assert "defenseclaw.tui.command_line.parse_command_line" in payload["expected_interfaces"]["parser"]
    assert payload["expected_interfaces"]["parser_error"] == "defenseclaw.tui.command_line.CommandLineError"
    assert payload["expected_interfaces"]["command_registry_count"] == 224
