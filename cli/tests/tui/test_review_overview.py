# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Overview banner and metric tiles fit narrow terminals."""

from __future__ import annotations

import io

from defenseclaw.tui.app import _DEFENSECLAW_LOGO_WIDTH, _overview_banner_lines, _OverviewBanner
from defenseclaw.tui.widgets.native_metrics import MetricDatum, MetricTile
from rich.console import Console


def _render(renderable: object, width: int) -> list[str]:
    console = Console(width=width, file=io.StringIO(), color_system=None, record=True)
    console.print(renderable)
    return [line for line in console.export_text().splitlines() if line.strip()]


def test_banner_is_a_single_wordmark_line_when_the_logo_would_wrap() -> None:
    lines = _render(_OverviewBanner("bold"), 74)

    assert lines == ["DEFENSECLAW"]
    assert _overview_banner_lines(74) == 1


def test_banner_keeps_the_block_logo_when_it_fits() -> None:
    lines = _render(_OverviewBanner("bold"), _DEFENSECLAW_LOGO_WIDTH + 4)

    assert len(lines) == 6
    assert all(len(line.rstrip()) <= _DEFENSECLAW_LOGO_WIDTH for line in lines)
    assert _overview_banner_lines(_DEFENSECLAW_LOGO_WIDTH) == 6


def test_status_words_are_not_drawn_with_digit_glyphs() -> None:
    assert MetricTile.digits_renderable("42")
    assert not MetricTile.digits_renderable("ON")
    assert not MetricTile.digits_renderable("OFF")

    tile = MetricTile(
        MetricDatum(key="guardrail", label="Guardrail", value=0, progress=0.0, detail="", value_text="OFF")
    )
    tile.refresh_metric(tile.metric)

    assert tile._word.display and not tile._digits.display


def test_scanner_path_probe_is_cached_between_repaints(monkeypatch) -> None:
    import defenseclaw.tui.app as app_module

    calls: list[str] = []
    monkeypatch.setattr(app_module.shutil, "which", lambda name: calls.append(name) or "/bin/x")
    monkeypatch.setattr(app_module, "_on_path_cache", {})

    assert app_module._on_path("skill-scanner", now=100.0)
    assert app_module._on_path("skill-scanner", now=105.0)
    assert calls == ["skill-scanner"]
    app_module._on_path("skill-scanner", now=100.0 + app_module._ON_PATH_TTL_SECONDS + 1)
    assert calls == ["skill-scanner", "skill-scanner"]


async def test_service_details_read_as_words_at_80_columns(tmp_path, monkeypatch) -> None:
    import sys
    from pathlib import Path

    from defenseclaw.tui.services.overview_state import OverviewPanelModel

    sys.path.insert(0, str(Path(__file__).parent))
    from fixtures import screen_text, settle_panel, snapshot_app

    # The same long detail on every platform (the live one depends on how far
    # the observability status has loaded).
    monkeypatch.setattr(OverviewPanelModel, "telemetry_detail", lambda _self: "canonical destination plan loading")
    app = snapshot_app(tmp_path)
    # Tall enough that the Services card is on screen without scrolling, even
    # with the extra notices some platforms show above it.
    async with app.run_test(size=(80, 120)) as pilot:
        await settle_panel(app, pilot)  # the Overview body renders after the first frame
        text = screen_text(app)
    # Read the Services card's own column (the text between its borders),
    # so the check holds wherever the detail wraps.
    lines = text.splitlines()
    top = next(index for index, line in enumerate(lines) if "SERVICES" in line)
    column: list[str] = []
    for line in lines[top + 1 :]:
        cells = line.split("│")
        if len(cells) < 3 or "╰" in cells[0]:
            break
        column.append(cells[1])
    services = " ".join(" ".join(column).split())
    # The Telemetry detail used to fold four letters a line ("cano", "nica").
    assert "canonical destination plan loading" in services, services
