# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Activity shows command text and output literally and fits 80x24."""

from __future__ import annotations

import sys
from pathlib import Path

from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.panels.activity import ActivityPanelModel

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import screen_text, settle_panel, snapshot_app  # noqa: E402


def test_command_output_with_markup_is_shown_literally() -> None:
    model = ActivityPanelModel()
    model.add_entry("skill scan [red]x")
    model.append_output("Selection [/] done [bold]ok")
    model.finish_entry(1)

    terminal = model.render_text()
    model.handle_key("esc")  # back to the command history view
    history = model.render_text()

    assert terminal != history
    for render in (terminal, history):
        plain = DefenseClawTUI._safe_body_renderable(render).plain
        assert "skill scan [red]x" in plain
        assert "Selection [/] done [bold]ok" in plain


async def test_activity_history_is_visible_at_80x24(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.action_switch_panel("activity")
        await settle_panel(app, pilot)
        text = screen_text(app)
        assert "Mutations (gateway activity)   h/l switch" in text
        assert "$ doctor" in text
        assert "--backend go" not in text
