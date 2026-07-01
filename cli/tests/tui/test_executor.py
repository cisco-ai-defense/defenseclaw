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

import ast
import asyncio
import inspect
import os
import subprocess
import sys

import defenseclaw.tui.app as app_module
import pytest
from defenseclaw.tui.executor import (
    CommandExecutor,
    captured_subprocess_kwargs,
    resolve_subprocess_argv,
)


@pytest.mark.skipif(os.name != "posix", reason="stdlib PTYs are POSIX-only")
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
    # macOS PTYs are a finite system resource. When the full TUI
    # suite runs concurrently we sometimes exhaust the kernel's
    # /dev/pty pool and ``posix_openpt`` fails with ENXIO ("out of
    # pty devices"). That's an environmental failure, not a bug in
    # the executor — skip rather than fail loudly so CI signal stays
    # crisp and we still cover the happy path on dev machines.
    if "out of pty devices" in output or ("Failed to start" in output and "pty" in output):
        pytest.skip("PTY device pool exhausted; environmental flake, not a regression.")
    assert "Name?" in output
    assert "hello Ada" in output
    assert exit_codes == [0]


def test_executor_default_pty_mode_matches_platform() -> None:
    assert CommandExecutor().use_pty is (os.name == "posix")


@pytest.mark.skipif(os.name == "posix", reason="non-POSIX platform behavior")
def test_executor_rejects_forced_pty_on_windows() -> None:
    with pytest.raises(ValueError, match="only supported on POSIX"):
        CommandExecutor(use_pty=True)


def test_self_cli_resolves_via_current_python_not_path_shim() -> None:
    argv = resolve_subprocess_argv("defenseclaw", ("keys", "list", "--json"))

    assert argv == (
        os.path.abspath(sys.executable),
        "-m",
        "defenseclaw.main",
        "keys",
        "list",
        "--json",
    )
    assert not argv[0].lower().endswith((".cmd", ".bat"))

    shim_argv = resolve_subprocess_argv(
        r"C:\Users\test\.local\bin\defenseclaw.cmd",
        ("doctor",),
    )
    assert shim_argv[:3] == argv[:3]
    assert shim_argv[3:] == ("doctor",)


def test_captured_subprocess_flags_match_platform() -> None:
    kwargs = captured_subprocess_kwargs()

    if os.name == "nt":
        assert kwargs == {"creationflags": subprocess.CREATE_NO_WINDOW}
    else:
        assert kwargs == {}


@pytest.mark.skipif(os.name != "nt", reason="Windows console allocation behavior")
@pytest.mark.asyncio
async def test_executor_captured_child_has_no_windows_console() -> None:
    events = [
        event
        async for event in CommandExecutor(use_pty=False).run(
            sys.executable,
            (
                "-c",
                "import ctypes; print(int(bool(ctypes.windll.kernel32.GetConsoleWindow())))",
            ),
        )
    ]

    output = [event.text.strip() for event in events if event.kind == "output"]
    assert output == ["0"]
    assert events[-1].exit_code == 0


@pytest.mark.asyncio
async def test_executor_launches_self_cli_with_resolved_argv(monkeypatch) -> None:
    seen: list[tuple[str, ...]] = []
    seen_kwargs: list[dict[str, object]] = []

    class EmptyStdout:
        @staticmethod
        async def readline() -> bytes:
            return b""

    class Process:
        stdin = None
        stdout = EmptyStdout()
        returncode = 0

        @staticmethod
        async def wait() -> int:
            return 0

    async def fake_exec(*argv: str, **kwargs: object) -> Process:
        seen.append(argv)
        seen_kwargs.append(kwargs)
        return Process()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    events = [
        event
        async for event in CommandExecutor(use_pty=False).run(
            "defenseclaw",
            ("doctor",),
        )
    ]

    assert seen == [
        (
            os.path.abspath(sys.executable),
            "-m",
            "defenseclaw.main",
            "doctor",
        )
    ]
    assert seen_kwargs[0].get("creationflags") == captured_subprocess_kwargs().get(
        "creationflags"
    )
    assert events[-1].exit_code == 0


@pytest.mark.asyncio
async def test_credentials_loader_uses_resolved_self_cli(monkeypatch, tmp_path) -> None:
    seen: list[tuple[str, ...]] = []

    class Process:
        returncode = 0

        @staticmethod
        async def communicate() -> tuple[bytes, bytes]:
            return b"[]", b""

    async def fake_exec(*argv: str, **_kwargs) -> Process:
        seen.append(argv)
        return Process()

    app = app_module.DefenseClawTUI(data_dir=tmp_path)
    monkeypatch.setattr(app_module.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(app, "_render_chrome", lambda: None)

    await app._load_setup_credentials()  # noqa: SLF001 - focused subprocess wiring.

    assert seen == [
        (
            os.path.abspath(sys.executable),
            "-m",
            "defenseclaw.main",
            "keys",
            "list",
            "--json",
        )
    ]


def test_every_direct_app_subprocess_uses_central_argv_resolution() -> None:
    tree = ast.parse(inspect.getsource(app_module))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "create_subprocess_exec"
    ]

    assert calls, "expected direct TUI subprocess call sites"
    for call in calls:
        assert call.args and isinstance(call.args[0], ast.Starred)
        resolver_call = call.args[0].value
        assert isinstance(resolver_call, ast.Call)
        assert isinstance(resolver_call.func, ast.Name)
        assert resolver_call.func.id == "resolve_subprocess_argv"
        assert any(
            keyword.arg is None
            and isinstance(keyword.value, ast.Call)
            and isinstance(keyword.value.func, ast.Name)
            and keyword.value.func.id == "captured_subprocess_kwargs"
            for keyword in call.keywords
        ), "captured TUI subprocess must suppress transient Windows consoles"
