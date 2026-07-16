# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Native Windows coverage for persistent children launched by the TUI job."""

from __future__ import annotations

import asyncio
import ctypes
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from ctypes import wintypes
from pathlib import Path

import pytest
from defenseclaw.tui.executor import CommandEvent, CommandExecutor

pytestmark = [
    pytest.mark.skipif(os.name != "nt", reason="native Windows Job Object lifecycle"),
    pytest.mark.allow_subprocess,
]

_TOKEN = "win-aud-038-native-test-token"


async def _run_tui_command(binary: str, args: tuple[str, ...]) -> list[CommandEvent]:
    events = [event async for event in CommandExecutor(use_pty=False).run(binary, args)]
    done = [event for event in events if event.kind == "done"]
    assert len(done) == 1, events
    output = "\n".join(event.text for event in events if event.kind == "output")
    assert done[0].exit_code == 0, output
    assert done[0].cancelled is False
    return events


def _reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _pid_is_active(pid: int) -> bool:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(0x00100000 | 0x1000, False, pid)
    if not handle:
        return False
    try:
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return False
        return exit_code.value == 259
    finally:
        kernel32.CloseHandle(handle)


async def _wait_for_pid(path: Path, *, different_from: int | None = None) -> int:
    deadline = time.monotonic() + 10
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            pid = int(payload["pid"])
            if pid > 0 and pid != different_from and _pid_is_active(pid):
                return pid
        except (OSError, ValueError, KeyError, TypeError) as exc:
            last_error = exc
        await asyncio.sleep(0.05)
    raise AssertionError(f"managed PID did not become active at {path}: {last_error}")


async def _wait_for_inactive(pid: int) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if not _pid_is_active(pid):
            return
        await asyncio.sleep(0.05)
    raise AssertionError(f"PID {pid} remained active")


def _gateway_status(port: int) -> dict[str, object]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/status",
        headers={"Authorization": f"Bearer {_TOKEN}"},
    )
    with urllib.request.urlopen(request, timeout=2) as response:  # noqa: S310 - fixed loopback test URL.
        return json.load(response)


async def _assert_listener_owned(port: int, pid: int, data_dir: Path) -> None:
    status = await asyncio.to_thread(_gateway_status, port)
    runtime = status.get("runtime")
    assert isinstance(runtime, dict)
    assert runtime.get("pid") == pid
    assert os.path.normcase(os.path.realpath(str(runtime.get("data_dir")))) == os.path.normcase(
        os.path.realpath(data_dir)
    )


async def _cleanup(binary: Path, env: dict[str, str]) -> None:
    await asyncio.to_thread(
        subprocess.run,
        [str(binary), "stop"],
        env=env,
        capture_output=True,
        check=False,
        timeout=30,
    )


@pytest.mark.asyncio
async def test_tui_gateway_and_watchdog_survive_parent_exit_and_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    current_windows_gateway: Path,
) -> None:
    binary = current_windows_gateway

    data_dir = tmp_path / "home"
    data_dir.mkdir()
    port = _reserve_port()
    (data_dir / "config.yaml").write_text(
        f"""config_version: 8
data_dir: {json.dumps(str(data_dir))}
gateway:
  api_bind: 127.0.0.1
  api_port: {port}
  token: {_TOKEN}
  fleet_mode: disabled
  watcher:
    enabled: false
  watchdog:
    enabled: true
    interval: 30
    debounce: 2
guardrail:
  enabled: false
observability: {{}}
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("DEFENSECLAW_HOME", str(data_dir))
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_BIN", str(binary))
    child_env = os.environ.copy()

    gateway_pid_path = data_dir / "gateway.pid"
    watchdog_pid_path = data_dir / "watchdog.pid"
    tracked_pids: list[int] = []
    try:
        # Direct gateway start: closing the successful command's TUI job must
        # retain both explicitly managed persistent children.
        await _run_tui_command("defenseclaw-gateway", ("start",))
        first_gateway = await _wait_for_pid(gateway_pid_path)
        first_watchdog = await _wait_for_pid(watchdog_pid_path)
        tracked_pids.extend((first_gateway, first_watchdog))
        await _assert_listener_owned(port, first_gateway, data_dir)

        # Direct restart must replace both managed generations and preserve
        # the same listener/PID-file ownership contract after its parent exits.
        await _run_tui_command("defenseclaw-gateway", ("restart",))
        second_gateway = await _wait_for_pid(gateway_pid_path, different_from=first_gateway)
        second_watchdog = await _wait_for_pid(watchdog_pid_path, different_from=first_watchdog)
        tracked_pids.extend((second_gateway, second_watchdog))
        await _wait_for_inactive(first_gateway)
        await _wait_for_inactive(first_watchdog)
        await _assert_listener_owned(port, second_gateway, data_dir)

        # Setup/configuration commands use this nested subprocess shape: the
        # Python command remains in the TUI job, while only the Go-managed
        # daemon requests breakaway during the restart handoff.
        restart_wrapper = (
            "import subprocess,sys; "
            "raise SystemExit(subprocess.run([sys.argv[1], 'restart'], check=False).returncode)"
        )
        await _run_tui_command(sys.executable, ("-c", restart_wrapper, str(binary)))
        third_gateway = await _wait_for_pid(gateway_pid_path, different_from=second_gateway)
        third_watchdog = await _wait_for_pid(watchdog_pid_path, different_from=second_watchdog)
        tracked_pids.extend((third_gateway, third_watchdog))
        await _wait_for_inactive(second_gateway)
        await _wait_for_inactive(second_watchdog)
        await _assert_listener_owned(port, third_gateway, data_dir)

        # Exercise the standalone watchdog lifecycle through the executor too.
        await _run_tui_command("defenseclaw-gateway", ("watchdog", "stop"))
        await _wait_for_inactive(third_watchdog)
        assert not watchdog_pid_path.exists()
        await _run_tui_command("defenseclaw-gateway", ("watchdog", "start"))
        fourth_watchdog = await _wait_for_pid(watchdog_pid_path, different_from=third_watchdog)
        tracked_pids.append(fourth_watchdog)
        await _run_tui_command("defenseclaw-gateway", ("watchdog", "status"))
        await _run_tui_command("defenseclaw-gateway", ("status",))

        await _run_tui_command("defenseclaw-gateway", ("stop",))
        await _wait_for_inactive(third_gateway)
        await _wait_for_inactive(fourth_watchdog)
        assert not gateway_pid_path.exists()
        assert not watchdog_pid_path.exists()
        with pytest.raises(urllib.error.URLError):
            await asyncio.to_thread(_gateway_status, port)
    finally:
        await _cleanup(binary, child_env)
        for pid in tracked_pids:
            await _wait_for_inactive(pid)
