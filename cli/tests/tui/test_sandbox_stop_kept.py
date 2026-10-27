# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""#1144: the TUI says why ``sandbox stop`` kept a full-disk MicroVM running."""

from __future__ import annotations

import contextlib
import io
from types import SimpleNamespace
from typing import Any

import pytest
from defenseclaw.tui import sandbox_panel
from defenseclaw.tui.app import DefenseClawTUI

NAME = "myapp-claude-7f3a"


def _config() -> SimpleNamespace:
    return SimpleNamespace(
        gateway=SimpleNamespace(api_port=18970, host="127.0.0.1", token="token"),
        openshell=SimpleNamespace(enabled=True, harnesses=["claudecode"], wrappers=[], admin=None),
    )


def _quiet_panel(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sandbox_panel, "fetch_sandbox_snapshot", lambda _config: sandbox_panel.SandboxFetch(error="offline"))
    monkeypatch.setattr(DefenseClawTUI, "_ensure_sandbox_stream", lambda self: None)
    monkeypatch.setattr(sandbox_panel, "openshell_sandboxes_supported", lambda os_name=None: True)


def _terminal(monkeypatch: pytest.MonkeyPatch, app: DefenseClawTUI, returncode: int) -> list[list[str]]:
    ran: list[list[str]] = []

    @contextlib.contextmanager
    def suspend():
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            yield

    def run(argv, cwd=None, check=False, stderr=None):
        ran.append(argv)
        return SimpleNamespace(returncode=returncode)

    monkeypatch.setattr(app, "suspend", suspend)
    monkeypatch.setattr(sandbox_panel.subprocess, "run", run)
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: "/opt/dc/defenseclaw-gateway")
    monkeypatch.setattr("builtins.input", lambda _prompt="": "")
    return ran


@pytest.mark.asyncio
@pytest.mark.parametrize("returncode", [sandbox_panel.SANDBOX_STOP_KEPT_EXIT, 0, 1])
async def test_sandbox_stop_shows_why_a_full_disk_microvm_keeps_running(monkeypatch, returncode: int) -> None:
    _quiet_panel(monkeypatch)
    app = DefenseClawTUI(config=_config())
    ran = _terminal(monkeypatch, app, returncode)
    toasts: list[tuple[str, str]] = []
    statuses: list[str] = []

    async def confirm_stop(_screen: Any) -> Any:
        return "stop"

    monkeypatch.setattr(app, "push_screen_wait", confirm_stop)
    async with app.run_test(size=(160, 44)):
        monkeypatch.setattr(app, "notify_toast", lambda level, message: toasts.append((level, message)))
        monkeypatch.setattr(app, "_set_status", statuses.append)
        await app._sandbox_stop(NAME)  # noqa: SLF001
    assert ran == [["/opt/dc/defenseclaw-gateway", "sandbox", "stop", NAME]]
    kept = sandbox_panel.sandbox_stop_kept_text(NAME)
    if returncode == sandbox_panel.SANDBOX_STOP_KEPT_EXIT:
        # The refusal, with the way on, stays on screen after the terminal
        # comes back: the command line's own words scrolled away with it.
        assert toasts == [("warn", kept)]
        assert statuses[-1] == kept
        assert "keeps running" in kept and "delete it (d)" in kept and "df -h /" in kept
    else:
        assert toasts == []
        assert kept not in statuses


def test_sandbox_stop_kept_exit_matches_the_command_line() -> None:
    # sandboxcli.ExitStopKept (internal/openshell/sandboxcli/lifecycle.go).
    assert sandbox_panel.SANDBOX_STOP_KEPT_EXIT == 5
