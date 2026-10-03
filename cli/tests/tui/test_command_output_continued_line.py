# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""A progress line shown before its newline gets its rest on the same line (GAP-2284)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from defenseclaw.tui.executor import CommandEvent
from textual.widgets import RichLog

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import snapshot_app  # noqa: E402


async def _restart_output(binary: str, args: tuple[str, ...], **_kwargs: Any):
    yield CommandEvent("start", " ".join((binary, *args)))
    yield CommandEvent("output", "  defenseclaw-gateway: restarting...")
    yield CommandEvent("output", " ✓", continues=True)
    yield CommandEvent("output", "  next step")
    yield CommandEvent("done", exit_code=0, duration=0.01)


@pytest.mark.parametrize("log_shown", [True, False], ids=["log-shown", "log-hidden-during-run"])
async def test_restart_mark_stays_on_the_restarting_line(tmp_path, log_shown: bool) -> None:
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        app.executor.run = _restart_output  # type: ignore[method-assign]
        # The session log shows beside the history list; a finished command's
        # own output view hides it (GAP-2326).
        app.activity_model.term_mode = False
        if log_shown:
            app.action_switch_panel("activity")
            await pilot.pause()
        assert await app._run_command("defenseclaw", ("agent", "discovery", "enable", "--yes")) == 0
        app.activity_model.term_mode = False
        app.action_switch_panel("activity")
        await pilot.pause()
        log_text = [strip.text.strip() for strip in app.query_one("#activity", RichLog).lines]

    joined = "defenseclaw-gateway: restarting... ✓"
    assert app.activity_model.entries[-1].output == ["  " + joined, "  next step"]
    assert app._strip_output_lines == [joined, "next step"]
    assert joined in log_text
    assert "✓" not in log_text
