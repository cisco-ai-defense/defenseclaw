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
import signal
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import defenseclaw.tui.app as app_module
import defenseclaw.tui.windows_process as windows_process
import pytest
from defenseclaw.tui.executor import (
    CommandExecutor,
    captured_subprocess_kwargs,
    managed_subprocess_kwargs,
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


def test_gateway_resolves_to_installed_binary() -> None:
    with patch(
        "defenseclaw.tui.executor.resolve_gateway_binary",
        return_value=r"C:\Program Files\DefenseClaw\defenseclaw-gateway.exe",
    ):
        argv = resolve_subprocess_argv("defenseclaw-gateway", ("status",))

    assert argv == (
        r"C:\Program Files\DefenseClaw\defenseclaw-gateway.exe",
        "status",
    )


def test_gateway_resolution_fails_clearly_when_missing() -> None:
    with patch("defenseclaw.tui.executor.resolve_gateway_binary", return_value=None):
        with pytest.raises(RuntimeError, match="gateway executable"):
            resolve_subprocess_argv("defenseclaw-gateway", ("status",))


def test_captured_subprocess_flags_match_platform() -> None:
    kwargs = captured_subprocess_kwargs()

    if os.name == "nt":
        assert kwargs == {"creationflags": subprocess.CREATE_NO_WINDOW}
    else:
        assert kwargs == {}


def test_managed_subprocess_is_suspended_only_on_windows() -> None:
    kwargs = managed_subprocess_kwargs()

    if os.name == "nt":
        assert kwargs == {"creationflags": subprocess.CREATE_NO_WINDOW | 0x00000004}
    else:
        assert kwargs == {}


def test_windows_job_allows_only_explicit_managed_breakaway() -> None:
    baseline = windows_process._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE  # noqa: SLF001
    explicit = baseline | windows_process._JOB_OBJECT_LIMIT_BREAKAWAY_OK  # noqa: SLF001

    assert windows_process._TUI_JOB_LIMIT_FLAGS == baseline  # noqa: SLF001
    assert windows_process._job_limit_flags(allow_breakaway=False) == baseline  # noqa: SLF001
    assert windows_process._job_limit_flags(allow_breakaway=True) == explicit  # noqa: SLF001
    assert explicit & 0x00001000 == 0  # no silent breakaway.


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
        pid = 1
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

    class NoopProcessTree:
        @staticmethod
        async def cancel(_process, _grace: float, _force: float) -> None:
            return None

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    process_tree_factory = lambda _pid: NoopProcessTree() if os.name == "nt" else None  # noqa: E731
    events = [
        event
        async for event in CommandExecutor(use_pty=False, process_tree_factory=process_tree_factory).run(
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
    assert seen_kwargs[0].get("creationflags") == managed_subprocess_kwargs().get("creationflags")
    assert events[-1].exit_code == 0


async def _collect(executor: CommandExecutor, args: tuple[str, ...]):
    return [event async for event in executor.run(sys.executable, args)]


async def _wait_until_running(executor: CommandExecutor) -> None:
    for _ in range(200):
        if executor.is_running:
            return
        await asyncio.sleep(0.01)
    raise AssertionError("subprocess did not start")


@pytest.mark.asyncio
async def test_cancel_is_idempotent_and_emits_one_cancelled_completion() -> None:
    executor = CommandExecutor(use_pty=False, cancel_grace=0.05)
    collect = asyncio.create_task(_collect(executor, ("-u", "-c", "import time; print('ready'); time.sleep(60)")))
    await _wait_until_running(executor)

    await asyncio.gather(executor.cancel(), executor.cancel(), executor.cancel())
    events = await asyncio.wait_for(collect, timeout=5)

    done = [event for event in events if event.kind == "done"]
    assert len(done) == 1
    assert done[0].cancelled is True
    assert done[0].exit_code == 130
    assert executor.is_running is False


@pytest.mark.asyncio
async def test_cancel_after_exit_is_a_noop() -> None:
    executor = CommandExecutor(use_pty=False)
    events = await _collect(executor, ("-c", "print('finished')"))

    accepted = await executor.cancel()

    assert accepted is False
    assert len([event for event in events if event.kind == "done"]) == 1
    assert events[-1].cancelled is False
    assert events[-1].exit_code == 0


@pytest.mark.asyncio
async def test_redirected_subprocess_output_is_decoded_as_utf8() -> None:
    payload = "café — 防御 🛡️"
    encoded_line = (payload + "\n").encode("utf-8")
    executor = CommandExecutor(use_pty=False)

    events = await _collect(
        executor,
        ("-c", f"import sys; sys.stdout.buffer.write({encoded_line!r}); sys.stdout.buffer.flush()"),
    )

    assert [event.text for event in events if event.kind == "output"] == [payload]
    assert events[-1].exit_code == 0


@pytest.mark.asyncio
async def test_cancel_natural_exit_race_has_one_terminal_result() -> None:
    executor = CommandExecutor(use_pty=False, cancel_grace=0.05)
    collect = asyncio.create_task(_collect(executor, ("-c", "import time; time.sleep(0.03)")))
    await _wait_until_running(executor)
    await asyncio.sleep(0.02)

    await executor.cancel()
    events = await collect

    done = [event for event in events if event.kind == "done"]
    assert len(done) == 1
    assert (done[0].cancelled, done[0].exit_code) in {(True, 130), (False, 0)}


@pytest.mark.asyncio
async def test_injected_process_tree_uses_bounded_forced_path() -> None:
    calls: list[tuple[float, float]] = []

    class ForcedTree:
        async def cancel(self, process, grace: float, force: float) -> None:
            calls.append((grace, force))
            process.kill()
            await process.wait()

        def close(self) -> None:
            calls.append((-1.0, -1.0))

    executor = CommandExecutor(
        use_pty=False,
        cancel_grace=0.01,
        cancel_force=0.25,
        process_tree_factory=lambda _pid: ForcedTree(),
    )
    collect = asyncio.create_task(_collect(executor, ("-c", "import time; time.sleep(60)")))
    await _wait_until_running(executor)

    await executor.cancel()
    events = await collect

    assert calls == [(0.01, 0.25), (-1.0, -1.0)]
    assert events[-1].cancelled is True


@pytest.mark.asyncio
async def test_process_tree_setup_failure_stops_command_without_side_effect() -> None:
    def fail_tree(_pid: int):
        raise OSError("job setup unavailable")

    executor = CommandExecutor(use_pty=False, process_tree_factory=fail_tree)
    events = await _collect(executor, ("-c", "import time; time.sleep(60)"))

    assert [event.kind for event in events] == ["start", "output", "done"]
    assert events[1].text.startswith("Failed to secure process tree:")
    assert events[-1].exit_code == 1
    assert events[-1].cancelled is False
    assert executor.is_running is False


@pytest.mark.asyncio
async def test_windows_process_tree_none_stops_suspended_command(monkeypatch) -> None:
    calls: list[str] = []

    class Process:
        pid = 1
        stdin = None
        stdout = None

        @staticmethod
        def kill() -> None:
            calls.append("kill")

        @staticmethod
        async def wait() -> int:
            calls.append("wait")
            return 1

    async def fake_exec(*_argv: str, **_kwargs: object) -> Process:
        return Process()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr("defenseclaw.tui.executor.managed_subprocess_kwargs", lambda: {})
    monkeypatch.setattr("defenseclaw.tui.executor.os.name", "nt")
    executor = CommandExecutor(use_pty=False, process_tree_factory=lambda _pid: None)

    events = [event async for event in executor.run("defenseclaw", ("doctor",))]

    assert calls == ["kill", "wait"]
    assert [event.kind for event in events] == ["start", "output", "done"]
    assert events[1].text == "Failed to secure process tree: Windows process tree setup returned no job object"
    assert events[-1].exit_code == 1
    assert executor.is_running is False


@pytest.mark.asyncio
async def test_signal_cancellation_preserves_sigint_without_process_tree() -> None:
    signals: list[int] = []

    class Process:
        returncode = None
        stdin = None

        def send_signal(self, sent: int) -> None:
            signals.append(sent)
            self.returncode = 42

        async def wait(self) -> int:
            return 42

        def kill(self) -> None:
            raise AssertionError("SIGINT graceful exit should not use kill fallback")

    executor = CommandExecutor(use_pty=False, process_tree_factory=lambda _pid: None)
    executor._process = Process()  # type: ignore[assignment]  # noqa: SLF001

    accepted = await executor.cancel()

    assert accepted is True
    assert signals == [signal.SIGINT]


@pytest.mark.skipif(os.name != "posix", reason="POSIX SIGINT regression")
@pytest.mark.asyncio
async def test_posix_cancel_preserves_sigint_before_fallback() -> None:
    code = (
        "import signal,sys,time; "
        "signal.signal(signal.SIGINT, lambda *_: (print('got-sigint', flush=True), sys.exit(42))); "
        "print('ready', flush=True); time.sleep(60)"
    )
    executor = CommandExecutor(use_pty=False, cancel_grace=1.0)
    collect = asyncio.create_task(_collect(executor, ("-u", "-c", code)))
    await _wait_until_running(executor)
    await asyncio.sleep(0.05)

    await executor.cancel()
    events = await collect

    assert "got-sigint" in [event.text for event in events if event.kind == "output"]
    assert events[-1].cancelled is True
    assert events[-1].exit_code == 130


def _windows_pid_is_active(pid: int) -> bool:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(0x00100000 | 0x1000, False, pid)
    if not handle:
        return False
    try:
        exit_code = wintypes.DWORD()
        assert kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
        return exit_code.value == 259
    finally:
        kernel32.CloseHandle(handle)


@pytest.mark.skipif(os.name != "nt", reason="native Windows graceful cancellation")
@pytest.mark.asyncio
async def test_windows_cancel_first_attempts_graceful_stdin_close() -> None:
    executor = CommandExecutor(use_pty=False, cancel_grace=1.0, cancel_force=1.0)
    collect = asyncio.create_task(
        _collect(
            executor,
            (
                "-u",
                "-c",
                "import sys; print('ready',flush=True); sys.stdin.buffer.read(); print('eof',flush=True)",
            ),
        )
    )
    await _wait_until_running(executor)
    await asyncio.sleep(0.05)

    await executor.cancel()
    events = await collect

    output = [event.text.strip() for event in events if event.kind == "output"]
    assert output == ["ready", "eof"]
    assert events[-1].cancelled is True
    assert events[-1].exit_code == 130


@pytest.mark.skipif(os.name != "nt", reason="native Windows Job Object regression")
@pytest.mark.asyncio
async def test_windows_cancel_reaps_child_and_grandchild_tree(tmp_path: Path) -> None:
    pid_file = tmp_path / "tree-pids.txt"
    grandchild = "import time; time.sleep(60)"
    child = (
        "import pathlib,subprocess,sys,time; "
        "time.sleep(0.1); "
        f"p=subprocess.Popen([sys.executable,'-c',{grandchild!r}]); "
        "pathlib.Path(sys.argv[1]).open('a').write(f'grandchild={p.pid}\\n'); "
        "print('tree-ready',flush=True); time.sleep(60)"
    )
    root = (
        "import pathlib,subprocess,sys,time; "
        f"p=subprocess.Popen([sys.executable,'-u','-c',{child!r},sys.argv[1]]); "
        "pathlib.Path(sys.argv[1]).write_text(f'root={__import__(\"os\").getpid()}\\nchild={p.pid}\\n'); "
        "p.wait()"
    )
    executor = CommandExecutor(use_pty=False, cancel_grace=0.05, cancel_force=2.0)
    collect = asyncio.create_task(_collect(executor, ("-u", "-c", root, str(pid_file))))
    await _wait_until_running(executor)
    for _ in range(300):
        if pid_file.exists() and "grandchild=" in pid_file.read_text():
            break
        await asyncio.sleep(0.01)
    else:
        raise AssertionError("child/grandchild tree did not become ready")

    await asyncio.gather(executor.cancel(), executor.cancel())
    events = await asyncio.wait_for(collect, timeout=5)
    pids = [int(line.split("=", 1)[1]) for line in pid_file.read_text().splitlines()]

    assert len([event for event in events if event.kind == "done"]) == 1
    assert events[-1].cancelled is True
    assert events[-1].exit_code == 130
    assert all(not _windows_pid_is_active(pid) for pid in pids)


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
