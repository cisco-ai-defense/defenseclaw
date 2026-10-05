# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fix: the Setup task detail at 80x24 (GAP-1999)."""

from __future__ import annotations

import sys
from pathlib import Path

from rich.console import Console
from rich.text import Text

sys.path.insert(0, str(Path(__file__).resolve().parent))

from defenseclaw.tui.widgets.panel_split import fit_rows  # noqa: E402


def test_fit_rows_marks_a_cut_and_names_the_key() -> None:
    console = Console(width=40)
    body = Text("Runs: defenseclaw setup guardrail. Need mode, scanner mode, and a judge model.")
    assert fit_rows(body, console, 40, 3, "i details") is body
    cut = fit_rows(body, console, 40, 1, "i details").plain
    assert cut == "Runs: defenseclaw setup … i details"
    assert len(cut) <= 40


async def test_setup_task_detail_uses_the_free_rows_at_80x24(tmp_path, monkeypatch) -> None:
    # GAP-1999: the box kept 3 text rows ("... Need webhook URL,") with
    # 6-7 empty rows above it, and gave no sign that it had more.
    from fixtures import snapshot_app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / ".defenseclaw"))
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        for key in ("0", "right", "right", "down"):
            await pilot.press(key)
            await pilot.pause()
        await pilot.pause()
        detail = app.query_one("#detail-panel")
        body = str(app.query_one("#detail-panel-body").render())
        assert detail.border_title == "Chat & paging webhooks"
        assert "and event filters." in body
        assert detail.max_scroll_y == 0
        # Guardrail's group has nine tasks: the rest of its detail is cut,
        # and the cut says where to read it.
        await pilot.press("left")
        await pilot.pause()
        await pilot.pause()
        body = str(app.query_one("#detail-panel-body").render())
        assert detail.border_title == "Guardrail"
        assert body.rstrip().endswith("… i details")
        assert detail.max_scroll_y == 0
