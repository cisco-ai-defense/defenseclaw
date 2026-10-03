# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI/status fixes, batch 20 (GAP-2549, GAP-2550, GAP-2551)."""

from __future__ import annotations

import io
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw.observability.custody_status import NativeDeliveryStatus, NativeDeliverySummary
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.panels.overview import OverviewConfig, OverviewPanelModel
from rich.console import Console, Group

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import snapshot_app  # noqa: E402
from test_final_cert_tui_fcz_b32 import _standard_account_runtime  # noqa: E402

_CLAUDE = NativeDeliveryStatus(
    connector="claudecode",
    default=True,
    state="accepted",
    normalized_batches=117,
    drop_only_batches=96,
    detail="accepted native delivery observed (117 batches; 96 held only log/metric records that "
    "DefenseClaw does not map, skipped by design)",
)
_CODEX = NativeDeliveryStatus(
    connector="codex",
    default=True,
    state="partial_drop_only",
    normalized_batches=237,
    drop_only_batches=1,
    detail="partial drop-only evidence (1/237 batches dropped whole; dropped signals: logs; reason: "
    "no mapped records); accepted native delivery observed in remaining batches",
)


def _summary() -> NativeDeliverySummary:
    return NativeDeliverySummary(
        state="available", reason="", observation_window_hours=24, connectors=(_CLAUDE, _CODEX)
    )


def test_status_native_delivery_line_names_the_state_once_and_hangs(capsys, monkeypatch) -> None:
    # GAP-2549: "claudecode  accepted - accepted native delivery observed",
    # and the codex detail wrapped to column 1.
    from defenseclaw.commands.cmd_status import _print_native_delivery_status

    monkeypatch.setenv("COLUMNS", "80")
    _print_native_delivery_status(_summary())
    lines = capsys.readouterr().out.splitlines()
    claude = next(i for i, line in enumerate(lines) if "claudecode" in line)
    assert lines[claude].strip().startswith("claudecode  accepted native delivery observed (117 batches;")
    codex = next(i for i, line in enumerate(lines) if line.strip().startswith("codex"))
    assert lines[codex].strip().startswith("codex  partial drop-only evidence (1/237")
    assert "accepted —" not in "\n".join(lines) and "partial-drop-only" not in "\n".join(lines)
    detail_col = lines[codex].index("partial")
    rest = lines[codex + 1 :]
    assert rest, "the codex detail wraps at 80 columns"
    for line in rest:
        assert len(line) <= 80 and line[:detail_col].strip() == "", line


def test_overview_observability_header_wraps_under_its_text() -> None:
    # GAP-2550: "health does not prove accepted delivery" started at the
    # panel edge like a separate row.
    model = OverviewPanelModel(OverviewConfig(data_dir="/tmp/dc", claw_mode="codex"), version="test")
    model.set_native_delivery_summary(_summary())
    view = SimpleNamespace(overview_model=model)
    console = Console(width=76, record=True, color_system=None)
    console.print(Group(*DefenseClawTUI._overview_native_delivery_renderables(view)))  # noqa: SLF001
    lines = [line for line in console.export_text().splitlines() if line.strip()]
    assert lines[0].startswith("Native connector OTLP delivery · bounded 24h ·")
    tail_col = lines[0].index("bounded")
    assert lines[1][:tail_col].strip() == "" and "not prove accepted delivery" in lines[1], lines[:2]


def test_overview_runtime_notice_keeps_its_key_hint_at_80x24(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    # GAP-2551: "Runtime is DEGRADED (shadow egress partially covered): 217 process…"
    # lost "no findings; N for details" at 80x24.
    app = snapshot_app(tmp_path)
    app.overview_model.runtime = _standard_account_runtime().overview()
    size = SimpleNamespace(width=80, height=24)
    monkeypatch.setattr(DefenseClawTUI, "size", property(lambda _self: size))
    console = Console(file=io.StringIO(), width=80, color_system=None)
    console.print(app._overview_renderable())  # noqa: SLF001
    lines = console.file.getvalue().splitlines()
    notice = next(line for line in lines if "[>] Runtime is" in line)
    assert "Runtime is DEGRADED (shadow egress" in notice and "…" in notice, notice
    assert notice.rstrip().endswith(", no findings; N for details"), notice
    assert len(notice) <= 80
