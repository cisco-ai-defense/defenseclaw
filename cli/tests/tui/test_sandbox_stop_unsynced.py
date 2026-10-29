# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-1595: a MicroVM stop refused because its disk could not be synced.

`sandbox stop` runs in the TUI's terminal and asks there whether to stop it
anyway (--discard-unsynced). A stop it kept running says why in the TUI, in
the words of that refusal, never the full-disk words of #1144, and the TUI
never stops it again on its own.
"""

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
UNSYNCED = (
    f"sandbox {NAME} was not stopped: its MicroVM's disk could not be synced\n"
    "first (sync: input/output error), so a stop now would lose what it wrote since its last sync; it keeps running\n"
)
FULL = f"{NAME} keeps running: its own disk is full\n"


def _config() -> SimpleNamespace:
    return SimpleNamespace(
        gateway=SimpleNamespace(api_port=18970, host="127.0.0.1", token="token"),
        openshell=SimpleNamespace(enabled=True, harnesses=["claudecode"], wrappers=[], admin=None),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("said", "code", "status"),
    [
        (UNSYNCED, sandbox_panel.SANDBOX_STOP_KEPT_EXIT, sandbox_panel.sandbox_stop_unsynced_text(NAME)),
        (FULL, sandbox_panel.SANDBOX_STOP_KEPT_EXIT, sandbox_panel.sandbox_stop_kept_text(NAME)),
        ("sandbox daemon is not running\n", 1, None),
    ],
)
async def test_unsynced_stop_is_asked_by_the_command_and_explained(monkeypatch, said: str, code: int, status) -> None:
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
        if stderr is not None:
            os.write(stderr, said.encode())
        return SimpleNamespace(returncode=code)

    monkeypatch.setattr(app, "suspend", suspend)
    monkeypatch.setattr(sandbox_panel.subprocess, "run", run)
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: "/opt/dc/defenseclaw-gateway")
    monkeypatch.setattr("builtins.input", lambda _prompt="": "")
    statuses: list[str] = []
    monkeypatch.setattr(app, "_set_status", lambda text: statuses.append(text))
    monkeypatch.setattr(app, "notify_toast", lambda *_a, **_k: None)
    queue = ["stop"]

    async def answer(screen: Any) -> Any:
        return queue.pop(0)

    monkeypatch.setattr(app, "push_screen_wait", answer)
    async with app.run_test(size=(80, 24)):
        await app._sandbox_stop(NAME)  # noqa: SLF001
    # One stop, run in the terminal, which asks itself; the TUI never adds
    # --yes or --discard-unsynced on its own.
    assert ran == [("sandbox", "stop", NAME)]
    assert queue == []
    if status is not None:
        assert status in statuses
    assert "--discard-unsynced" in sandbox_panel.sandbox_stop_unsynced_text(NAME)
