# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The command palette shows each command's risk badge."""

from __future__ import annotations

import sys
from pathlib import Path

from defenseclaw.tui.app import _palette_risk_style
from textual.widgets import DataTable

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import screen_text, snapshot_app  # noqa: E402


def test_destructive_badges_are_styled_differently_from_read_only() -> None:
    assert _palette_risk_style("[other/destructive]") != _palette_risk_style("[diagnostics/read-only]")
    assert "bold" in _palette_risk_style("[other/destructive]")


async def test_palette_risk_column_is_not_blank(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press(":", "d", "o", "c")
        await pilot.pause()
        palette = app.query_one("#command-palette", DataTable)
        assert palette.row_count > 0
        assert "/read-only]" in screen_text(app)


async def test_typing_a_burst_keeps_the_palette_columns_readable(tmp_path) -> None:
    from textual import events

    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press(":")
        await pilot.pause()
        # A terminal delivers pasted or fast typing as one burst of keys.
        for character in "guardrail":
            app.post_message(events.Key(character, character))
        await pilot.pause()
        await pilot.pause()
        text = screen_text(app)
        assert "guardrail mode" in text and "[policy/mutation]" in text
