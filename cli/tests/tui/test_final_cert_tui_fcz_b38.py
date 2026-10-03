# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fix batch fcz-b38: Registries detail scroll, uninstall modal footer."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from defenseclaw.tui.screens.uninstall import UninstallOption, UninstallScreen
from textual.app import App

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import screen_text, settle_panel, snapshot_app  # noqa: E402


@pytest.mark.parametrize("size", [(80, 24), (200, 50)])
async def test_registries_source_detail_scrolls_with_page_down(tmp_path, size) -> None:
    # GAP-2591: the detail cut Blocked/Errors/Rejected and PgDn did nothing.
    from textual.containers import VerticalScroll

    app = snapshot_app(tmp_path)
    async with app.run_test(size=size) as pilot:
        app.action_switch_panel("registries")
        await settle_panel(app, pilot)
        await pilot.press("enter")
        await pilot.pause()
        detail = app.query_one("#detail-panel", VerticalScroll)
        assert app.registries_model.detail_open and detail.max_scroll_y > 0
        assert "Rejected" not in screen_text(app)
        # At 80x24 the box shows five lines, so a few pages reach the end.
        await pilot.press("pagedown", "pagedown", "pagedown")
        await pilot.pause()
        assert detail.scroll_y > 0 and app.registries_model.detail_open
        assert "Rejected" in screen_text(app)
        await pilot.press("pageup", "pageup", "pageup")
        await pilot.pause()
        assert detail.scroll_y == 0


async def test_uninstall_wipe_row_shows_its_command_after_one_key() -> None:
    # GAP-2595: a/e only name a terminal command, yet the footer said
    # "enter twice runs" and a asked for a danger confirm.
    results: list[object] = []

    class Harness(App[None]):
        def on_mount(self) -> None:
            self.push_screen(UninstallScreen(), results.append)

    app = Harness()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        text = screen_text(app)
        assert "a/e show the command to run after quitting" in text
        assert "enter twice runs" not in text
        assert "The TUI cannot do this. Quit, then `defenseclaw uninstall --all` deletes" in text
        await pilot.press("a")
        await pilot.pause()
    assert [getattr(action, "action_id", None) for action in results] == [UninstallOption.WIPE_DATA.value]
