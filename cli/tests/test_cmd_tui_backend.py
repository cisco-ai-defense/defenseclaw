# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Planned backend-selection contract for ``defenseclaw tui``.

These tests describe the Textual migration surface before the production
implementation is complete. Missing backend options are reported as xfail
so the suite can carry the migration contract without blocking unrelated
work.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

import pytest
from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_tui


def _xfail_if_backend_option_missing(result) -> None:
    if result.exit_code == 2 and "No such option: --backend" in result.output:
        pytest.xfail("planned Textual migration contract: cmd_tui.tui does not accept --backend yet")


def test_tui_help_advertises_backend_selector() -> None:
    result = CliRunner().invoke(cmd_tui.tui, ["--help"])

    if "--backend" not in result.output:
        pytest.xfail("planned Textual migration contract: cmd_tui.tui help does not advertise --backend yet")

    assert result.exit_code == 0, result.output
    assert "--backend" in result.output
    assert "go" in result.output
    assert "textual" in result.output


def test_tui_backend_go_execs_gateway_tui() -> None:
    runner = CliRunner()
    with patch("defenseclaw.commands.cmd_tui.resolve_gateway_binary", return_value="/tmp/defenseclaw-gateway"), patch(
        "defenseclaw.commands.cmd_tui.os.execvp"
    ) as execvp:
        result = runner.invoke(cmd_tui.tui, ["--backend", "go"])

    _xfail_if_backend_option_missing(result)
    assert result.exit_code == 0, result.output
    execvp.assert_called_once_with("/tmp/defenseclaw-gateway", ["/tmp/defenseclaw-gateway", "tui"])


def test_tui_backend_env_selects_textual_launcher() -> None:
    runner = CliRunner()
    try:
        import defenseclaw.tui as textual_tui
    except ModuleNotFoundError as exc:
        pytest.xfail(f"planned Textual migration contract: defenseclaw.tui is not present yet ({exc})")
    if not hasattr(textual_tui, "run_textual_tui"):
        pytest.xfail("planned Textual migration contract: defenseclaw.tui.run_textual_tui is not present yet")

    with patch("defenseclaw.tui.run_textual_tui") as launch_textual, patch(
        "defenseclaw.commands.cmd_tui.os.execvp"
    ) as execvp:
        result = runner.invoke(cmd_tui.tui, [], env={"DEFENSECLAW_TUI_BACKEND": "textual"})

    assert result.exit_code == 0, result.output
    launch_textual.assert_called_once_with()
    execvp.assert_not_called()


def test_tui_backend_defaults_to_textual_launcher() -> None:
    runner = CliRunner()
    with patch("defenseclaw.tui.run_textual_tui") as launch_textual, patch(
        "defenseclaw.commands.cmd_tui.os.execvp"
    ) as execvp:
        result = runner.invoke(cmd_tui.tui, [])

    assert result.exit_code == 0, result.output
    launch_textual.assert_called_once_with()
    execvp.assert_not_called()


def test_tui_backend_flag_overrides_env() -> None:
    runner = CliRunner()
    with patch("defenseclaw.commands.cmd_tui.resolve_gateway_binary", return_value="/tmp/defenseclaw-gateway"), patch(
        "defenseclaw.commands.cmd_tui.os.execvp"
    ) as execvp:
        result = runner.invoke(
            cmd_tui.tui,
            ["--backend", "go"],
            env={"DEFENSECLAW_TUI_BACKEND": "textual"},
        )

    _xfail_if_backend_option_missing(result)
    assert result.exit_code == 0, result.output
    execvp.assert_called_once_with("/tmp/defenseclaw-gateway", ["/tmp/defenseclaw-gateway", "tui"])
