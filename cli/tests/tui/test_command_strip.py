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
        await asyncio.sleep(0.2)
        await pilot.pause()
        assert app.query_one("#command-progress").has_class("hidden") is hidden
