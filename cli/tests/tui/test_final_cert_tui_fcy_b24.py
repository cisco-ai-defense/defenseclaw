# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fix batch fcy-b24: an open detail box refits on a terminal resize."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import screen_text, settle_layout, settle_panel, snapshot_app  # noqa: E402


async def test_registries_detail_refits_at_once_on_resize(tmp_path) -> None:
    # GAP-2603: after a resize the open detail kept its old height until the
    # next refresh tick (~15 s): 200x50 -> 80x24 clipped the box under KEYS,
    # 80x24 -> 200x50 left a 5-row box under ~27 blank rows.
    from textual.containers import VerticalScroll

    app = snapshot_app(tmp_path)
    async with app.run_test(size=(200, 50)) as pilot:
        app.action_switch_panel("registries")
        await settle_panel(app, pilot)
        await pilot.press("enter")
        await pilot.pause()
        detail = app.query_one("#detail-panel", VerticalScroll)
        main = app.query_one("#panel-main")
        assert app.registries_model.detail_open and "Cache Path" in screen_text(app)

        await pilot.resize_terminal(80, 24)
        await settle_layout(pilot, lambda: detail.max_scroll_y > 0)
        assert detail.has_class("compact")
        assert detail.region.bottom <= main.region.bottom
        assert detail.max_scroll_y > 0

        await pilot.resize_terminal(200, 50)
        await settle_layout(pilot, lambda: detail.max_scroll_y == 0)
        assert not detail.has_class("compact")
        assert detail.max_scroll_y == 0 and "Cache Path" in screen_text(app)
