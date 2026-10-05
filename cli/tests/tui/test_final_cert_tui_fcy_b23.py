# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fix batch fcy-b23: the Registries detail box on a tall terminal."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import screen_text, settle_panel, snapshot_app  # noqa: E402


async def test_registries_detail_grows_into_free_rows_and_hint_names_pgdn(tmp_path) -> None:
    # GAP-2600: at 200x50 the detail stopped at "Warnings: 0" under ~17 empty
    # rows, with no visible cue, and the KEYS hint never named PgUp/PgDn.
    from textual.containers import VerticalScroll

    app = snapshot_app(tmp_path)
    async with app.run_test(size=(200, 50)) as pilot:
        app.action_switch_panel("registries")
        await settle_panel(app, pilot)
        assert "PgUp/PgDn" not in app.hint_text
        await pilot.press("enter")
        await pilot.pause()
        detail = app.query_one("#detail-panel", VerticalScroll)
        assert app.registries_model.detail_open and detail.max_scroll_y == 0
        assert "Rejected: 0" in screen_text(app) and "Cache Path" in screen_text(app)
        assert app.hint_text.startswith("KEYS  PgUp/PgDn scroll detail | Esc close")
        await pilot.press("escape")
        await pilot.pause()
        assert "PgUp/PgDn" not in app.hint_text
