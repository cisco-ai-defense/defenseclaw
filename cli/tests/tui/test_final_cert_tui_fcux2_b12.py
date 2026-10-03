# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI UX batch 12: Overview uptime and Sandbox rows, config group headers."""

from __future__ import annotations

import io
import sys
from pathlib import Path
from types import SimpleNamespace

from defenseclaw.tui.app import _config_label_cells
from defenseclaw.tui.services.overview_state import HealthSnapshot, OverviewConfig, OverviewPanelModel
from rich.console import Console

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import snapshot_app  # noqa: E402

_UNIFIED = ".. Unified LLM (shared by scanners + guardrail) .."


def _plain(renderable: object) -> str:
    console = Console(file=io.StringIO(), width=160, color_system=None)
    console.print(renderable)
    return console.file.getvalue()


def test_overview_header_uptime_reads_like_the_services_row(tmp_path) -> None:
    # GAP-2360: the header said "uptime=445s" beside "Gateway running up 7m".
    app = snapshot_app(tmp_path)
    app.overview_model.set_health(HealthSnapshot(uptime_ms=445_000))
    app.overview_model.set_gateway_probe("running")
    text = _plain(app._overview_renderable())  # noqa: SLF001
    assert "up 7m" in text and "uptime=" not in text


def test_sandbox_not_set_up_reads_disabled_with_the_gateway_down() -> None:
    # GAP-2361: "Sandbox offline" when stopped, "Sandbox disabled" when running.
    for enabled, want in ((False, "disabled"), (True, "offline")):
        model = OverviewPanelModel(OverviewConfig(sandbox_enabled=enabled))
        model.set_gateway_probe("stopped")
        assert model.gateway_down()
        assert model.subsystem_state("sandbox") == want
        assert model.subsystem_state("api") == "offline"


def test_group_header_continues_in_the_value_cell() -> None:
    # GAP-2362: ".. Unified LLM (sha…" with the Value cell empty.
    header = SimpleNamespace(label=_UNIFIED, kind="header", value="")
    label, value = _config_label_cells(header, 20, 34)
    assert (label, value) == (".. Unified LLM", "(shared by scanners + guardrail) ..")
    assert _config_label_cells(SimpleNamespace(label=".. Paths ..", kind="header", value=""), 20, 34) == (
        ".. Paths ..",
        "",
    )
    field = SimpleNamespace(label="Data Dir", kind="text", value="/x")
    assert _config_label_cells(field, 20, 34) == ("Data Dir", "/x")


async def test_config_editor_group_header_readable_at_80x24(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / ".defenseclaw"))
    from defenseclaw.config import default_config

    app = snapshot_app(tmp_path, setup_config=default_config())
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("0", "c")
        await pilot.pause()
        assert app.setup_model.sections[app.setup_model.active_section].name == "General"
        _columns, rows = app._setup_table()  # noqa: SLF001
        row = next(row for row in rows if row[0].startswith(".. Unified LLM"))
        assert " ".join(cell for cell in row[:2] if cell) == _UNIFIED
