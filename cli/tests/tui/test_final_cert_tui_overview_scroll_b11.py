# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fix: Overview keyboard scroll at 80x24 (GAP-2270)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


async def test_overview_line_scroll_never_skips_rows_at_80x24(tmp_path, monkeypatch) -> None:
    # GAP-2270: j/Down moved 6 rows while only ~4 dashboard rows were
    # visible, so the same rows were skipped on every pass.
    from fixtures import snapshot_app
    from textual.containers import VerticalScroll

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / ".defenseclaw"))
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("1")
        await pilot.pause()
        scroller = app.query_one("#body-scroll", VerticalScroll)
        visible = scroller.scrollable_content_region.height
        assert scroller.max_scroll_y > visible
        await pilot.press("j")
        await pilot.pause()
        step = scroller.scroll_y
        assert 0 < step < visible
        await pilot.press("down")
        await pilot.pause()
        assert scroller.scroll_y == 2 * step
        await pilot.press("k")
        await pilot.pause()
        assert scroller.scroll_y == step
