# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Judge response history modal tests."""

from __future__ import annotations

import pytest
from defenseclaw.tui.screens.judge_history import (
    JudgeHistoryScreen,
    judge_response_detail_pairs,
)
from textual.app import App, ComposeResult
from textual.widgets import Static


def _confidence_values(rows) -> list[str]:
    return [value for key, value in judge_response_detail_pairs(rows) if key.endswith("Confidence")]


def test_zero_confidence_is_rendered_not_dropped() -> None:
    # 0.0 is a meaningful verdict -> it must render as 0.000, not vanish.
    assert _confidence_values([{"confidence": 0.0}]) == ["0.000"]
    assert _confidence_values([{"confidence": 0}]) == ["0.000"]


def test_absent_confidence_is_omitted() -> None:
    assert _confidence_values([{"confidence": None}]) == []
    assert _confidence_values([{"confidence": ""}]) == []
    assert _confidence_values([{}]) == []


class _Harness(App[None]):
    def __init__(self, rows=()) -> None:
        super().__init__()
        self._rows = rows
        self.dismissed = False

    def compose(self) -> ComposeResult:
        yield Static("judge history harness")

    def on_mount(self) -> None:
        self.push_screen(JudgeHistoryScreen(rows=self._rows), self._captured)

    def _captured(self, result) -> None:
        self.dismissed = True


@pytest.mark.asyncio
async def test_close_button_dismisses_modal() -> None:
    app = _Harness(rows=({"kind": "prompt", "confidence": 0.0},))

    async with app.run_test(size=(130, 36)) as pilot:
        await pilot.pause()
        app.screen.query_one("#judge-history-close")  # exists
        await pilot.click("#judge-history-close")
        await pilot.pause()

    assert app.dismissed is True
