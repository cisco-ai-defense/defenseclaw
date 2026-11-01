# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-0153: check the Overview keys through the mounted, scrolled widget."""

from __future__ import annotations

from fixtures import screen_text, settle_panel, snapshot_app
from textual.containers import VerticalScroll


async def test_overview_gateway_and_discovery_keys_are_visible_after_scrolling(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / ".defenseclaw"))
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("1")
        await settle_panel(app, pilot)
        scroller = app.query_one("#body-scroll", VerticalScroll)
        scroller.scroll_end(animate=False)
        await pilot.pause()
        text = screen_text(app)
        assert "[G]" in text and "[z]" in text, text
