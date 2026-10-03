# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert 80-column observability wrapping, batch 35 (GAP-2566, GAP-2567)."""

from __future__ import annotations

from types import SimpleNamespace

import click
from defenseclaw.observability.custody_status import NativeDeliverySummary
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.services.overview_state import ObservabilityStorageStatus
from rich.console import Console


def _continuation_hangs(lines: list[str], hang: int) -> None:
    for line in lines[1:]:
        assert len(line) <= 80 and line[:hang].strip() == "" and line[hang] != " ", line


def test_status_long_lines_wrap_at_spaces_under_their_text(capsys, monkeypatch) -> None:
    # GAP-2566: "...does not prove a" / "ccepted delivery):" at column 1, and
    # "tool blocks: 0  s" / "ubprocess blocks: 0".
    from defenseclaw.commands import cmd_status
    from defenseclaw.commands.cmd_status import (
        _echo_wrapped,
        _print_agent_counters,
        _print_native_delivery_status,
    )

    monkeypatch.setenv("COLUMNS", "80")
    monkeypatch.setattr(cmd_status, "_status_columns", lambda: 80)
    _print_native_delivery_status(NativeDeliverySummary("unavailable", "database_missing", 24, ()))
    header = capsys.readouterr().out.splitlines()[:2]
    assert header[0].startswith("    native OTLP delivery (bounded 24h;"), header
    assert header[1] == "      accepted delivery):", header

    _print_agent_counters({"requests": 0}, indent=" " * 18)
    counters = capsys.readouterr().out.splitlines()
    assert counters[0].rstrip().endswith("tool blocks: 0"), counters
    assert counters[1] == " " * 18 + "subprocess blocks: 0", counters

    # Width counts visible text only, so styled spans wrap at the same place.
    _echo_wrapped("    " + click.style(" ".join(["mode=action"] * 12), fg="red"), 6)
    styled = [click.unstyle(line) for line in capsys.readouterr().out.splitlines()]
    assert len(styled) == 2 and styled[0].startswith("    mode=action"), styled
    _continuation_hangs(styled, 6)

    # Piped output keeps one line per item.
    monkeypatch.setattr(cmd_status, "_status_columns", lambda: 0)
    _print_agent_counters({"requests": 0}, indent=" " * 18)
    assert len(capsys.readouterr().out.splitlines()) == 1


def test_overview_local_sqlite_line_wraps_under_its_text() -> None:
    # GAP-2567: "capture=enabled" started at the panel edge.
    storage = ObservabilityStorageStatus(
        retention="7 days",
        judge_capture="enabled",
        local_path="C:\\Users\\u\\.defenseclaw\\audit.db",
        judge_bodies_path="C:\\Users\\u\\.defenseclaw\\judge",
        retention_health="healthy",
    )
    row = SimpleNamespace(
        name="local-sqlite",
        kind="sqlite",
        policy_state="enabled",
        health_label="healthy",
        state="healthy",
        signals="logs",
        buckets="1/1",
        redaction="none",
        queue="n/a",
        limits="n/a",
        activity="ok",
        endpoint="db",
    )
    model = SimpleNamespace(
        observability_destination_rows=lambda: (row,),
        observability_storage_status=lambda: storage,
        observability_status_error="",
    )
    view = SimpleNamespace(overview_model=model, _overview_native_delivery_renderables=lambda: ())
    console = Console(width=76, record=True, color_system=None)  # the 80-col body
    console.print(DefenseClawTUI._overview_observability_panel(view))  # noqa: SLF001
    lines = console.export_text().splitlines()
    first = next(i for i, line in enumerate(lines) if "Local SQLite ·" in line)
    tail_col = lines[first].index("retention=7 days")
    assert lines[first + 1][:tail_col].strip("│ ") == "", lines[first : first + 2]
    assert "capture=enabled" in lines[first + 1], lines[first : first + 2]
