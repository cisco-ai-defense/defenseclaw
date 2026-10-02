# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""On Windows the TUI loop keeps executor threads free beside Textual's timer sleeps."""

from __future__ import annotations

import asyncio
import threading

from defenseclaw.tui import app as app_module


def _thread_name() -> str:
    return threading.current_thread().name


async def test_parked_timer_threads_leave_room_for_work_on_windows() -> None:
    loop = asyncio.get_running_loop()
    app_module._widen_windows_default_executor(loop, platform="nt")
    release = threading.Event()
    # Textual's Windows sleep parks one executor thread per timer; park more
    # than the stock executor's 32-worker ceiling.
    parked = [loop.run_in_executor(None, release.wait, 30) for _ in range(40)]
    try:
        name = await asyncio.wait_for(loop.run_in_executor(None, _thread_name), timeout=5)
    finally:
        release.set()
        await asyncio.gather(*parked)
    assert name.startswith("defenseclaw-tui")


async def test_other_platforms_keep_the_stock_executor() -> None:
    loop = asyncio.get_running_loop()
    app_module._widen_windows_default_executor(loop, platform="posix")
    assert not (await loop.run_in_executor(None, _thread_name)).startswith("defenseclaw-tui")
