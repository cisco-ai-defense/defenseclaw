# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""At 80x24 each list panel shows its first row, not just instructions."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import screen_text, snapshot_app  # noqa: E402

# (panel, keys to press, text from the first table row of the fake data)
CASES = (
    ("alerts", (), "skill://alpha"),
    ("skills", (), "math helper"),
    ("mcps", (), "uvx context7"),
    ("plugins", (), "teaches operators"),
    ("inventory", ("l",), "alpha"),
    ("logs", (), "error failed"),
    ("audit", (), "token found"),
    ("ai", (), "Codex"),
    ("registries", (), "corp-skills"),
)


@pytest.mark.parametrize(("panel", "keys", "row_text"), CASES, ids=[case[0] for case in CASES])
async def test_first_row_is_on_screen_at_80x24(tmp_path, panel: str, keys: tuple[str, ...], row_text: str) -> None:
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.action_switch_panel(panel)
        await pilot.pause()
        for key in keys:
            await pilot.press(key)
            await pilot.pause()
        assert row_text in screen_text(app)
