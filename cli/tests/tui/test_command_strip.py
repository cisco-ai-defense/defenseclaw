# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The command-progress strip clears itself after a success, not a failure."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixtures  # noqa: E402
from defenseclaw.tui import app as app_module  # noqa: E402


@pytest.mark.parametrize(("exit_code", "hidden"), [(0, True), (1, False)])
async def test_success_strip_hides_itself_and_failure_stays(tmp_path, monkeypatch, exit_code, hidden) -> None:
    monkeypatch.setattr(app_module, "STRIP_SUCCESS_SECONDS", 0.05)
    app = fixtures.snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app._strip_label = "policy activate strict"  # noqa: SLF001
        app._strip_state = "running"  # noqa: SLF001
        app._strip_finished(exit_code=exit_code, duration=0.1)  # noqa: SLF001
        # Wait on an app timer due after the strip's hide timer, not the wall
        # clock: Windows Textual timers sleep on executor threads and can fire
        # late.
        hide_timer_passed = asyncio.Event()
        app.set_timer(0.2, hide_timer_passed.set)
        await asyncio.wait_for(hide_timer_passed.wait(), timeout=10)
        await pilot.pause()
        assert app.query_one("#command-progress").has_class("hidden") is hidden


async def test_registry_json_run_shows_a_readable_result(tmp_path) -> None:
    """A registry --json run ends on "}"; the card names the result (GAP-1681)."""
    app = fixtures.snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app._strip_running("registry reject corp wiki")  # noqa: SLF001
        for line in ('{', '"action": "reject",', '"verdict": {', '"name": "wiki",', '"type": "mcp"', '}', '}'):
            app._strip_output(line)  # noqa: SLF001
        app._strip_finished(exit_code=0, duration=0.1)  # noqa: SLF001
        assert app._strip_summary.startswith("mcp:wiki rejected")  # noqa: SLF001
        app._strip_running("policy show")  # noqa: SLF001
        app._strip_output("}")  # noqa: SLF001
        app._strip_finished(exit_code=0, duration=0.1)  # noqa: SLF001
        assert app._strip_summary.startswith("exit 0 · finished cleanly")  # noqa: SLF001
