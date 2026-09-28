# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Picker lists keep the selection on screen and open on the full list."""

from __future__ import annotations

from defenseclaw.tui.screens.model_picker import opening_rows
from defenseclaw.tui.screens.panel_jumper import PanelChoice, PanelJumperScreen
from defenseclaw.tui.widgets.list_window import rows_that_fit, window_lines
from textual.app import App
from textual.widgets import Static


def test_short_lists_are_drawn_whole() -> None:
    assert window_lines(["a", "b"], 1, 5) == ["a", "b"]


def test_window_follows_the_selection_and_counts_hidden_rows() -> None:
    lines = [f"row{i}" for i in range(20)]

    top = window_lines(lines, 0, 5)
    middle = window_lines(lines, 10, 5)
    bottom = window_lines(lines, 19, 5)

    assert top[:4] == ["row0", "row1", "row2", "row3"] and "16 more" in top[-1]
    assert "row10" in middle and "9 more" in middle[0] and "8 more" in middle[-1]
    assert bottom[-1] == "row19" and "16 more" in bottom[0]
    assert all(len(window) == 5 for window in (top, middle, bottom))


def test_rows_that_fit_leaves_room_for_the_modal_chrome() -> None:
    assert rows_that_fit(24, 14, cap=14) == 10
    assert rows_that_fit(60, 14, cap=14) == 14
    assert rows_that_fit(10, 14, cap=14) == 3


def test_model_picker_opens_on_the_full_catalog_with_the_current_model_highlighted() -> None:
    assert opening_rows("gpt-5", ("gpt-4", "gpt-5", "o3")) == (["gpt-4", "gpt-5", "o3"], 1)
    assert opening_rows("my-custom", ("gpt-4",)) == (["my-custom", "gpt-4"], 0)
    assert opening_rows("", ("gpt-4",)) == (["gpt-4"], 0)


async def test_panel_jumper_keeps_the_last_panel_reachable_at_80x24() -> None:
    choices = tuple(PanelChoice(name=f"p{i}", label=f"Panel {i}", hotkey=str(i % 10)) for i in range(15))
    results: list[str | None] = []

    class Harness(App[None]):
        def on_mount(self) -> None:
            self.push_screen(PanelJumperScreen(choices), results.append)

    app = Harness()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press(*["down"] * 14)
        listing = str(app.screen.query_one("#panel-jumper-list", Static).render())
        assert "> " in listing and "Panel 14" in listing
        await pilot.press("enter")
        await pilot.pause()
    assert results == ["p14"]


async def test_ctrl_p_opens_the_panel_jumper(tmp_path) -> None:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent))
    from fixtures import snapshot_app

    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("ctrl+p")
        await pilot.pause()
        assert isinstance(app.screen, PanelJumperScreen)
