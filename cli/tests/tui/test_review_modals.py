# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Confirmation modals fit an 80x24 terminal."""

from __future__ import annotations

import sys
from pathlib import Path

from defenseclaw.tui.screens.uninstall import UninstallScreen
from textual.app import App

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import screen_text  # noqa: E402


async def test_uninstall_wipe_shows_its_second_confirmation_at_80x24() -> None:
    results: list[object] = []

    class Harness(App[None]):
        def on_mount(self) -> None:
            self.push_screen(UninstallScreen(), results.append)

    app = Harness()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("a", "enter")
        await pilot.pause()
        text = screen_text(app)
        # The armed hint and the row being confirmed (with what it deletes)
        # are both visible, and the dialog's right border is on screen.
        assert "press enter / click again to confirm" in text
        assert "Uninstall and wipe data" in text and "deletes ~/.defenseclaw" in text
        assert all(len(line.rstrip()) <= 80 for line in text.splitlines())
        assert any(line.rstrip().endswith("╮") for line in text.splitlines()[:3])
    assert results == []
