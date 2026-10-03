# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Gateway stop/start confirm copy and the uninstall chooser header (final-cert fix-only batch 1)."""

from __future__ import annotations

import dataclasses

from defenseclaw.tui.command_line import ParsedCommand
from defenseclaw.tui.screens.command_preview import build_command_preview
from defenseclaw.tui.screens.uninstall import build_uninstall_model


def _gateway_preview(verb: str):
    command = ParsedCommand(binary="defenseclaw-gateway", args=(verb,), display_name=verb, category="daemon")
    return build_command_preview(dataclasses.replace(command, risk="mutation"))


def test_gateway_stop_and_start_confirms_say_what_happens_to_hooks() -> None:
    # GAP-2607: both said only "This daemon command can change DefenseClaw state."
    stop = _gateway_preview("stop")
    assert "can change DefenseClaw state" not in stop.summary
    assert "watchdog" in stop.summary
    assert "fail-closed connectors refuse tool calls" in stop.summary
    start = _gateway_preview("start")
    assert "can change DefenseClaw state" not in start.summary
    assert "hooks are checked again" in start.summary
    # Restart keeps its own summary.
    assert "watchdog" not in _gateway_preview("restart").summary


def test_uninstall_chooser_header_matches_rows_without_flag_internals() -> None:
    # GAP-2608: "Choose what the TUI should run" and "passes --yes" though
    # rows a and e only show a terminal command.
    model = build_uninstall_model()
    header = "\n".join((model.summary, *model.details, model.consequence))
    assert "--yes" not in header
    assert "Choose what the TUI should run" not in header
    assert "rows a and e show the command" in header
    assert "hooks and plugin integration" in model.consequence
    assert "binaries" not in model.consequence
