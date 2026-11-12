# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Agent Substrate agents in the Sandboxes panel: the 80x24 render, the loader and the row actions."""

from __future__ import annotations

import contextlib
import io
import json
import os
from types import SimpleNamespace
from typing import Any

import pytest
from defenseclaw.tui import sandbox_panel
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.services.substrate_state import (
    SIGNED_OUT_NOTE,
    SUBSTRATE_REFRESH_SECONDS,
    SubstrateList,
    parse_substrate_list,
)
from fixtures import screen_text

STATUS = {
    "enabled": True,
    "available": True,
    "gateway": {"name": "openshell", "version": "0.1.1", "healthy": True},
    "sandboxes": 1,
    "running": 1,
}
SANDBOX = {
    "name": "myapp-claude-7f3a",
    "harness": "claudecode",
    "harness_name": "Claude Code",
    "phase": "ready",
    "uptime_seconds": 3725,
    "egress": {"destinations": 23, "blocked": 1},
}
AGENTS = json.dumps(
    {
        "actors": [
            {
                "atespace": "team-a",
                "name": "fix-tests-7f3a",
                "profile": "standard",
                "connector": "claude",
                "state": "running",
                "created_at": "2026-11-12T10:00:00Z",
                "owner": "user@example.test",
            },
            {
                "atespace": "team-a",
                "name": "docs-b21c",
                "profile": "standard",
                "connector": "claude",
                "state": "suspended",
                "created_at": "2026-11-12T08:30:00Z",
                "owner": "user@example.test",
            },
        ]
    }
)


def _config() -> SimpleNamespace:
    return SimpleNamespace(
        gateway=SimpleNamespace(api_port=18970, host="127.0.0.1", token="token"),
        openshell=SimpleNamespace(enabled=True, harnesses=["claudecode"], wrappers=[], admin=None),
    )


@pytest.fixture
def panel(monkeypatch: pytest.MonkeyPatch):
    payload = sandbox_panel.SandboxFetch(status=STATUS, sandboxes=[SANDBOX], approvals=[])
    monkeypatch.setattr(sandbox_panel, "fetch_sandbox_snapshot", lambda _config: payload)
    monkeypatch.setattr(DefenseClawTUI, "_ensure_sandbox_stream", lambda self: None)
    monkeypatch.setattr(sandbox_panel, "openshell_sandboxes_supported", lambda os_name=None: True)


def _fake_terminal(monkeypatch: pytest.MonkeyPatch, app: DefenseClawTUI) -> list[tuple[list[str], str]]:
    ran: list[tuple[list[str], str]] = []

    @contextlib.contextmanager
    def suspend():
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            yield

    def run(argv, cwd=None, check=False, stderr=None):
        ran.append((argv, cwd))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(app, "suspend", suspend)
    monkeypatch.setattr(sandbox_panel.subprocess, "run", run)
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: "/opt/dc/defenseclaw-gateway")
    monkeypatch.setattr("builtins.input", lambda _prompt="": "")
    return ran


@pytest.mark.asyncio
async def test_the_panel_lists_agents_next_to_sandboxes_at_80x24(panel, monkeypatch) -> None:
    async def listed() -> SubstrateList:
        return parse_substrate_list(0, AGENTS)

    monkeypatch.setattr(sandbox_panel, "load_substrate_list", listed)
    app = DefenseClawTUI(config=_config())
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("sandboxes")
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        text = screen_text(app)
    print(text)
    assert "myapp-claude-7f3a" in text and "openshell" in text
    assert "fix-tests-7f3a" in text and "docs-b21c" in text and "substrate" in text
    assert "Runtime" in text


@pytest.mark.asyncio
async def test_a_signed_out_launcher_is_one_dim_line_not_an_error(panel) -> None:
    app = DefenseClawTUI(config=_config())
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("sandboxes")
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        text = screen_text(app)
    print(text)
    assert SIGNED_OUT_NOTE in text and "myapp-claude-7f3a" in text


def test_the_list_runs_at_most_once_every_15_seconds(monkeypatch) -> None:
    clock = [1000.0]
    monkeypatch.setattr(sandbox_panel.time, "monotonic", lambda: clock[0])
    started: list[Any] = []

    def run_worker(coro: Any, **_kwargs: Any) -> None:
        started.append(coro)
        coro.close()

    async def noop() -> None:
        return None

    app = SimpleNamespace(
        _substrate_last=None, _substrate_running=False, run_worker=run_worker, _load_substrate_once=noop
    )
    schedule = sandbox_panel.SandboxPanelMixin._schedule_substrate_load  # noqa: SLF001
    schedule(app)
    schedule(app)  # one is in flight
    app._substrate_running = False
    clock[0] += SUBSTRATE_REFRESH_SECONDS - 1
    schedule(app)  # too soon
    assert len(started) == 1
    clock[0] += 2
    schedule(app)
    assert len(started) == 2


@pytest.mark.asyncio
async def test_connect_and_pull_hand_the_terminal_to_the_launcher(panel, monkeypatch) -> None:
    app = DefenseClawTUI(config=_config())
    ran = _fake_terminal(monkeypatch, app)
    async with app.run_test(size=(80, 24)) as pilot:
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        app.sandbox_model.set_substrate(parse_substrate_list(0, AGENTS))
        app.sandbox_model.cursor = 1  # first agent (docs-b21c) after the one sandbox
        assert app._apply_sandbox_action(app.sandbox_model.handle_key("c"))  # noqa: SLF001
        assert app._apply_sandbox_action(app.sandbox_model.handle_key("P"))  # noqa: SLF001
        await pilot.pause()
    gateway = "/opt/dc/defenseclaw-gateway"
    assert ran == [
        ([gateway, "substrate", "connect", "docs-b21c"], os.getcwd()),
        ([gateway, "substrate", "pull", "docs-b21c"], os.getcwd()),
    ]


@pytest.mark.asyncio
async def test_delete_asks_once_then_runs_with_yes(panel, monkeypatch) -> None:
    app = DefenseClawTUI(config=_config())
    shown: list[Any] = []
    answers = [SimpleNamespace(action_id="back"), SimpleNamespace(action_id="run")]

    async def push_screen_wait(screen: Any) -> Any:
        shown.append(screen)
        return answers.pop(0)

    commands: list[tuple[str, tuple[str, ...]]] = []

    async def run_command(binary: str, args: tuple[str, ...], **_kwargs: Any) -> int:
        commands.append((binary, tuple(args)))
        return 0

    monkeypatch.setattr(app, "push_screen_wait", push_screen_wait)
    monkeypatch.setattr(app, "_run_command", run_command)
    async with app.run_test(size=(80, 24)):
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        app.sandbox_model.set_substrate(parse_substrate_list(0, AGENTS))
        assert await app._substrate_delete("docs-b21c") is False  # noqa: SLF001
        assert commands == []
        assert await app._substrate_delete("docs-b21c") is True  # noqa: SLF001
    assert commands == [("defenseclaw", ("substrate", "delete", "docs-b21c", "--yes"))]
    assert "defenseclaw substrate delete docs-b21c --yes" in shown[0].model.details[0]
    assert [row.ref for row in app.sandbox_model.substrate_rows] == ["fix-tests-7f3a"]


@pytest.mark.asyncio
async def test_a_palette_substrate_login_runs_on_the_terminal(panel, monkeypatch) -> None:
    from defenseclaw.tui.command_line import ParsedCommand

    app = DefenseClawTUI(config=_config())
    ran = _fake_terminal(monkeypatch, app)

    async def confirmed(_screen: Any) -> bool:
        return True

    monkeypatch.setattr(app, "push_screen_wait", confirmed)
    parsed = ParsedCommand(
        binary="defenseclaw",
        args=("substrate", "login"),
        display_name="substrate login",
        category="setup",
        risk="setup",
        needs_preview=True,
    )
    async with app.run_test(size=(80, 24)):
        assert await app._confirm_and_run_parsed(parsed) == 0  # noqa: SLF001
    assert ran == [(["/opt/dc/defenseclaw-gateway", "substrate", "login"], os.getcwd())]
