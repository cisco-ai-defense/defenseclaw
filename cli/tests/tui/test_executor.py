# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Command executor parity tests for Textual Activity."""

from __future__ import annotations

import sys

import pytest
from defenseclaw.tui.executor import CommandExecutor


@pytest.mark.asyncio
async def test_executor_pty_forwards_interactive_stdin() -> None:
    executor = CommandExecutor(use_pty=True)
    events: list[str] = []
    exit_codes: list[int | None] = []

    async def collect() -> None:
        async for event in executor.run(
            sys.executable,
            (
                "-c",
                "name=input('Name? '); print('hello ' + name)",
            ),
        ):
            events.append(event.text)
            if event.kind == "output" and "Name?" in event.text:
                executor.write_stdin("Ada\n")
            if event.kind == "done":
                exit_codes.append(event.exit_code)

    await collect()

    output = "\n".join(events)
    assert "Name?" in output
    assert "hello Ada" in output
    assert exit_codes == [0]
