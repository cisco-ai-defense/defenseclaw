# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fix batch 16 (GAP-2491, GAP-2492, GAP-2493)."""

from __future__ import annotations

import io
import sys
from pathlib import Path
from types import SimpleNamespace

from defenseclaw.tui.app import PANELS, DefenseClawTUI, _agents_summary, _config_label_cells
from defenseclaw.tui.services.overview_state import OverviewConfig, OverviewPanelModel
from defenseclaw.tui.widgets import tab_fit
from rich.console import Console
from textual.geometry import Size

sys.path.insert(0, str(Path(__file__).parent))
from fixtures import snapshot_app  # noqa: E402

_UNREAD = {"alerts": 87, "audit": 10}


def _bare(labels: dict[str, str]) -> int:
    return sum(" " not in label for label in labels.values())


def test_tab_strip_names_every_tab_from_158_columns_and_drops_the_brand_first(tmp_path, monkeypatch) -> None:
    # GAP-2491: at 158-160 columns "R" was bare beside 13-17 free cells, and at
    # 170 the brand came back while "R" went bare again (165 named it).
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    app = snapshot_app(tmp_path)
    app._panel_unread_count = lambda name: _UNREAD.get(name, 0)  # type: ignore[method-assign]
    previous = len(PANELS)
    for width in range(140, 201):
        monkeypatch.setattr(type(app), "size", property(lambda _self, width=width: Size(width, 45)))
        strip = app._tab_strip_width()  # noqa: SLF001
        labels = tab_fit.fit_tab_labels(PANELS, "overview", _UNREAD, strip)
        assert tab_fit.strip_width(tuple(labels.values())) <= strip
        assert _bare(labels) <= previous, (width, labels)
        previous = _bare(labels)
        if width >= 158:
            assert _bare(labels) == 0, (width, labels)
            for name, key, title in PANELS:
                opened = tab_fit.fit_tab_labels(PANELS, name, {**_UNREAD, name: 0}, strip)
                assert opened[name].startswith(f"{key} {title}"), (width, opened[name])
    # The brand shows only once every tab keeps its full name beside it, so it
    # never shortens a name a narrower screen showed (GAP-2517).
    for width, brand in ((165, False), (170, False), (180, False), (240, True)):
        monkeypatch.setattr(type(app), "size", property(lambda _self, width=width: Size(width, 45)))
        assert bool(app._header_title()) is brand, width  # noqa: SLF001


def test_overview_agents_row_says_configured_with_the_gateway_stopped(monkeypatch) -> None:
    # GAP-2492: CONFIGURATION read "Agents  9 active" beside "Agent offline".
    assert _agents_summary(OverviewConfig(guardrail_enabled=True), 9, True) == "9 configured (gateway not running)"
    assert _agents_summary(OverviewConfig(guardrail_enabled=True), 9) == "9 active"
    cfg = OverviewConfig(
        guardrail_enabled=True,
        guardrail_mode="action",
        connector_modes=(("codex", "action"), ("claudecode", "action")),
    )
    app = DefenseClawTUI(overview_model=OverviewPanelModel(cfg, version="test"))
    assert len(app._overview_connector_rows()) == 2  # noqa: SLF001
    monkeypatch.setattr(type(app), "size", property(lambda _self: Size(160, 45)))
    app.overview_model.set_gateway_probe("stopped")
    console = Console(file=io.StringIO(), width=160, record=True)
    console.print(app._overview_renderable())  # noqa: SLF001
    text = console.export_text()
    row = next(line for line in text.splitlines() if "Agents" in line)
    assert "2 configured (gateway not running)" in row and "active" not in row, row
    assert "2 active" not in text


def test_long_group_header_keeps_its_note_whole() -> None:
    # GAP-2493: ".. Unified LLM      (shared by scanners + guardrail) .." at
    # 160 columns and "(shared by  scanners" at 80x24.
    header = SimpleNamespace(label=".. Unified LLM (for scanners + guardrail) ..", kind="header", value="")
    for room in (20, 30):
        assert _config_label_cells(header, room, 34) == (".. Unified LLM ..", "for scanners + guardrail")
