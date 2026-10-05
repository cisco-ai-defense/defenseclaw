# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Follow-up intents run one at a time, and only after a successful command."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

from defenseclaw.tui.executor import CommandAlreadyRunningError, CommandEvent
from defenseclaw.tui.services.setup_state import SetupCommandIntent

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import snapshot_app  # noqa: E402


def _chain() -> SetupCommandIntent:
    # Neutral argv: no post-success refresh handler reacts to these.
    return SetupCommandIntent(
        "step one",
        ("step", "one"),
        follow_up=(
            SetupCommandIntent("step two", ("step", "two")),
            SetupCommandIntent("step three", ("step", "three")),
        ),
    )


class FakeExecutor:
    """Single-flight like the real executor; exit codes by args[0:2]."""

    def __init__(self, exit_codes: dict[tuple[str, ...], int] | None = None) -> None:
        self.exit_codes = exit_codes or {}
        self.started: list[tuple[str, ...]] = []
        self.running = False

    async def run(self, binary: str, args: tuple[str, ...], **_kwargs: Any):
        if self.running:
            raise CommandAlreadyRunningError("A command is already running.")
        self.running = True
        try:
            self.started.append(tuple(args))
            yield CommandEvent("start", " ".join((binary, *args)))
            # Hand the loop to anything that would race this command.
            for _ in range(5):
                await asyncio.sleep(0)
            yield CommandEvent("done", exit_code=self.exit_codes.get(tuple(args[:2]), 0), duration=0.01)
        finally:
            self.running = False


async def _confirm(_screen: Any) -> bool:
    return True


async def test_follow_ups_run_in_order_after_each_command_finishes(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    executor = FakeExecutor()
    async with app.run_test(size=(80, 24)) as pilot:
        app.executor.run = executor.run  # type: ignore[method-assign]
        app.push_screen_wait = _confirm  # type: ignore[method-assign]
        exit_code = await app._confirm_and_run_intent(_chain())
        await pilot.pause()

    assert exit_code == 0
    assert executor.started == [("step", "one"), ("step", "two"), ("step", "three")]


async def test_follow_ups_are_skipped_when_the_first_command_fails(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    executor = FakeExecutor({("step", "one"): 1})
    async with app.run_test(size=(80, 24)) as pilot:
        app.executor.run = executor.run  # type: ignore[method-assign]
        app.push_screen_wait = _confirm  # type: ignore[method-assign]
        exit_code = await app._confirm_and_run_intent(_chain())
        await pilot.pause()

    assert exit_code == 1
    assert executor.started == [("step", "one")]


async def test_cancelled_preview_runs_nothing(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    ran: list[Any] = []
    logged: list[str] = []

    async def cancelled(_parsed: Any, **_kwargs: Any) -> None:
        ran.append(_parsed.args)
        return None

    app._confirm_and_run_parsed = cancelled  # type: ignore[method-assign]
    app._write_activity = logged.append  # type: ignore[method-assign]
    assert await app._confirm_and_run_intent(_chain()) is None
    assert ran == [("step", "one")]
    assert logged  # the skipped follow-ups are reported
