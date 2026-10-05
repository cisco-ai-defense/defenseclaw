# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fix batch 11: Overview SERVICES and DISCOVERED AI AGENTS at 80 columns."""

from __future__ import annotations

import io
import sys
from pathlib import Path
from unittest.mock import PropertyMock, patch

from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.services.overview_state import OverviewAIDiscoveryBoxState, OverviewAIDiscoveryRow
from rich.console import Console
from textual.geometry import Size

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import snapshot_app  # noqa: E402

# At an 80-column terminal the Overview body is 71 cells wide (live capture).
_BODY_80 = 71


def _render(app: DefenseClawTUI) -> list[str]:
    console = Console(width=_BODY_80, record=True, color_system=None, file=io.StringIO())
    with patch.object(DefenseClawTUI, "size", new_callable=PropertyMock, return_value=Size(80, 24)):
        console.print(app._overview_renderable())  # noqa: SLF001
    return console.export_text().splitlines()


def test_services_api_address_is_whole_at_80_columns(tmp_path) -> None:
    # GAP-2412: label width 13 left 14 cells and cut the address to "127.0.0.1:193…".
    app = snapshot_app(tmp_path)
    app.overview_model.set_gateway_probe("running")
    real = app.overview_model.service_detail
    with patch.object(
        app.overview_model,
        "service_detail",
        side_effect=lambda key: "127.0.0.1:19350" if key == "api" else real(key),
    ):
        lines = _render(app)
    assert any("127.0.0.1:19350" in line for line in lines), "\n".join(lines)
    discovery = next(line for line in lines if "AI Discovery" in line)
    assert "AI Discovery " in discovery


def test_discovered_agents_rows_stay_one_line_at_80_columns(tmp_path) -> None:
    # GAP-2414: fixed column widths overflowed, so "[OK…" and the seen time
    # wrapped over three lines; vendor and confidence are dropped first.
    rows = tuple(
        OverviewAIDiscoveryRow("active", "[OK ]", name, vendor, " 98%", "seen 38s ago")
        for name, vendor in (
            ("Claude Code", "Anthropic (claudecode)"),
            ("Hermes Agent", "Nous Research (hermes)"),
        )
    ) + (OverviewAIDiscoveryRow("gone", "[GONE]", "a-very-long-discovered-agent-name", "x", " 60%", "seen 2h ago"),)
    app = snapshot_app(tmp_path)
    box = OverviewAIDiscoveryBoxState("ready", rows=rows, overflow=3)
    with patch.object(app.overview_model, "ai_discovery_box", return_value=box):
        lines = _render(app)
    start = next(i for i, line in enumerate(lines) if "DISCOVERED AI AGENTS" in line)
    body = lines[start + 1 : start + 5]
    assert "[OK ]" in body[0] and "Claude Code" in body[0] and "seen 38s ago" in body[0], body
    assert "Hermes Agent" in body[1] and "seen 38s ago" in body[1], body
    assert "[GONE]" in body[2] and "seen 2h ago" in body[2], body
    assert "+3 more" in body[3], body
