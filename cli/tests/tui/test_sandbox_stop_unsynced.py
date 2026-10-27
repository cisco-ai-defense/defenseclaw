# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-1595: after a stop held for a failed MicroVM disk sync, the TUI offers stop --yes."""

from __future__ import annotations

import contextlib
import io
import os
from types import SimpleNamespace
from typing import Any

import pytest
from defenseclaw.tui import sandbox_panel
from defenseclaw.tui.app import DefenseClawTUI

NAME = "myapp-claude-7f3a"
HELD = (
    f"sandbox {NAME} keeps running: DefenseClaw could not sync its MicroVM's disk before\n"
    "the stop (sync: input/output error), and the stop of a MicroVM loses what was not synced\n"
)


def _config() -> SimpleNamespace:
    return SimpleNamespace(
        gateway=SimpleNamespace(api_port=18970, host="127.0.0.1", token="token"),
        openshell=SimpleNamespace(enabled=True, harnesses=["claudecode"], wrappers=[], admin=None),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("said", "answers", "expected"),
    [
        # Held: the modal is offered; on confirm the TUI runs stop --yes.
        (HELD, ["stop", "stop_unsynced"], [("sandbox", "stop", NAME), ("sandbox", "stop", NAME, "--yes")]),
        # Held, the user keeps it running: no second stop.
        (HELD, ["stop", "cancel"], [("sandbox", "stop", NAME)]),
        # Any other failure: no --yes offer.
        ("sandbox daemon is not running\n", ["stop"], [("sandbox", "stop", NAME)]),
    ],
)
async def test_held_unsynced_stop_offers_stop_anyway(monkeypatch, said: str, answers: list[str], expected) -> None:
    monkeypatch.setattr(sandbox_panel, "fetch_sandbox_snapshot", lambda _c: sandbox_panel.SandboxFetch(error="offline"))
    monkeypatch.setattr(DefenseClawTUI, "_ensure_sandbox_stream", lambda self: None)
    monkeypatch.setattr(sandbox_panel, "openshell_sandboxes_supported", lambda os_name=None: True)
    app = DefenseClawTUI(config=_config())
    ran: list[tuple[str, ...]] = []

    @contextlib.contextmanager
    def suspend():
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            yield

    def run(argv, cwd=None, check=False, stderr=None):
        ran.append(tuple(argv[1:]))
        if stderr is not None and argv[-1] != "--yes":
            os.write(stderr, said.encode())
            return SimpleNamespace(returncode=1)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(app, "suspend", suspend)
    monkeypatch.setattr(sandbox_panel.subprocess, "run", run)
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: "/opt/dc/defenseclaw-gateway")
    monkeypatch.setattr("builtins.input", lambda _prompt="": "")
    queue = list(answers)
    titles: list[str] = []

    async def answer(screen: Any) -> Any:
        titles.append(getattr(screen, "_title", "") or getattr(screen, "title", ""))
        return queue.pop(0)

    monkeypatch.setattr(app, "push_screen_wait", answer)
    async with app.run_test(size=(80, 24)):
        await app._sandbox_stop(NAME)  # noqa: SLF001
    assert ran == expected
    assert queue == []
