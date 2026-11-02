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

"""A stdio scan ends the server's process group on success or timeout."""

from __future__ import annotations

import asyncio
import errno
import inspect
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from defenseclaw.config import MCPScannerConfig, MCPServerEntry
from defenseclaw.scanner.mcp import MCPScannerWrapper

_STDIO_SERVER = """import json, os, signal, subprocess, sys, time
child = subprocess.Popen(
    [sys.executable, '-c', 'import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(300)'],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    start_new_session=os.environ.get('MCP_FIXTURE_DETACHED') == '1',
)
with open(os.environ['MCP_FIXTURE_CHILD_PID'], 'w') as output:
    output.write(str(child.pid))
with open(os.environ['MCP_FIXTURE_SERVER_PID'], 'w') as output:
    output.write(str(os.getpid()))
for line in sys.stdin:
    message = json.loads(line)
    if 'id' not in message:
        continue
    if message.get('method') == 'initialize':
        result = {'protocolVersion': '2024-11-05', 'capabilities': {'tools': {}},
                  'serverInfo': {'name': 'fixture', 'version': '1.0'}}
    elif message.get('method') == 'server/discover':
        print(json.dumps({'jsonrpc': '2.0', 'id': message['id'],
                          'error': {'code': -32601, 'message': 'Method not found'}}), flush=True)
        continue
    elif message.get('method') == 'tools/list':
        if os.environ.get('MCP_FIXTURE_DELAY'):
            time.sleep(float(os.environ['MCP_FIXTURE_DELAY']))
        result = {'tools': [{'name': 'echo', 'description': 'Echo text',
                            'inputSchema': {'type': 'object', 'properties': {}}}]}
    else:
        result = {}
    print(json.dumps({'jsonrpc': '2.0', 'id': message['id'], 'result': result}), flush=True)
if os.environ.get('MCP_FIXTURE_IGNORE_STDIN'):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        signal.pause()
"""


def _fixture_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, stuck: bool = False, detached: bool = False,
) -> tuple[MCPServerEntry, Path]:
    server = tmp_path / "server.py"
    server.write_text(_STDIO_SERVER, encoding="utf-8")
    launcher = tmp_path / "uvx"
    launcher.write_text(f"#!/bin/sh\nexec '{sys.executable}' '{server}'\n", encoding="utf-8")
    launcher.chmod(0o700)
    child_pid_file = tmp_path / "child.pid"
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    entry = MCPServerEntry(
        name="fixture", command="uvx", args=["fixture-package"],
        env={
            "MCP_FIXTURE_CHILD_PID": str(child_pid_file),
            "MCP_FIXTURE_SERVER_PID": str(tmp_path / "server.pid"),
            "MCP_FIXTURE_IGNORE_STDIN": "1" if stuck else "",
            "MCP_FIXTURE_DETACHED": "1" if detached else "",
        },
    )
    return entry, child_pid_file


def _running(pid: int) -> bool:
    if sys.platform == "linux":
        try:
            stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        except FileNotFoundError:
            return False
        return stat.rsplit(") ", 1)[1][0] != "Z"
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


@pytest.mark.skipif(os.name == "nt", reason="Windows uses a Job Object")
@pytest.mark.parametrize("pgid", [0, 1])
def test_cleanup_rejects_reserved_process_groups(
    monkeypatch: pytest.MonkeyPatch, pgid: int,
) -> None:
    from defenseclaw.scanner import mcp

    signals: list[tuple[int, int]] = []
    monkeypatch.setattr(mcp.os, "killpg", lambda group, sig: signals.append((group, sig)))
    mcp._signal_owned_mcp_posix_group(pgid, signal.SIGTERM, lambda _message: None)
    assert signals == []


@pytest.mark.skipif(os.name == "nt", reason="Windows uses a Job Object")
def test_cleanup_rejects_scanner_process_group(monkeypatch: pytest.MonkeyPatch) -> None:
    from defenseclaw.scanner import mcp

    signals: list[tuple[int, int]] = []
    monkeypatch.setattr(mcp.os, "killpg", lambda group, sig: signals.append((group, sig)))
    mcp._signal_owned_mcp_posix_group(
        mcp._MCP_POSIX_SCANNER_PGID, signal.SIGTERM, lambda _message: None,
    )
    assert signals == []


@pytest.mark.skipif(os.name == "nt", reason="Windows uses a Job Object")
def test_cleanup_skips_reused_group_before_kill(monkeypatch: pytest.MonkeyPatch) -> None:
    from defenseclaw.scanner import mcp

    pgid = 424242
    groups = iter((pgid, pgid + 1))
    signals: list[int] = []
    monkeypatch.setattr(mcp.os, "getpgid", lambda _pid: next(groups))
    monkeypatch.setattr(mcp.os, "killpg", lambda _group, sig: signals.append(sig))
    mcp._signal_owned_mcp_posix_group(pgid, signal.SIGTERM, lambda _message: None)
    mcp._signal_owned_mcp_posix_group(pgid, signal.SIGKILL, lambda _message: None)
    assert signals == [signal.SIGTERM]


@pytest.mark.skipif(os.name == "nt", reason="Windows uses a Job Object")
@pytest.mark.parametrize("error_type", [PermissionError, ProcessLookupError, OSError])
@pytest.mark.parametrize("failed_signal", [signal.SIGTERM, signal.SIGKILL])
def test_cleanup_signal_error_does_not_escape(
    monkeypatch: pytest.MonkeyPatch, failed_signal: int, error_type: type[OSError],
) -> None:
    from defenseclaw.scanner import mcp

    pgid = 424242
    signals: list[int] = []
    reports: list[str] = []
    monkeypatch.setattr(mcp.os, "getpgid", lambda _pid: pgid)

    def signal_group(_group: int, sig: int) -> None:
        signals.append(sig)
        if sig == failed_signal:
            raise error_type("simulated cleanup error")

    monkeypatch.setattr(mcp.os, "killpg", signal_group)
    term_needs_kill = mcp._signal_owned_mcp_posix_group(
        pgid, signal.SIGTERM, reports.append,
    )
    if term_needs_kill:
        mcp._signal_owned_mcp_posix_group(pgid, signal.SIGKILL, reports.append)
    assert len(reports) == 1
    assert signal.Signals(failed_signal).name in reports[0]
    if failed_signal == signal.SIGTERM and error_type is ProcessLookupError:
        assert signals == [signal.SIGTERM]
    else:
        assert signals == [signal.SIGTERM, signal.SIGKILL]


@pytest.mark.skipif(os.name == "nt", reason="Windows uses a Job Object")
@pytest.mark.parametrize("mode", ["normal-exit", "detached-normal-exit", "scan-timeout", "server-stuck"])
def test_local_stdio_scan_ends_child_on_success_or_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str,
) -> None:
    mcpscanner = pytest.importorskip("mcpscanner")
    from mcpscanner.core.models import AnalyzerEnum

    entry, child_pid_file = _fixture_entry(
        tmp_path, monkeypatch, stuck=mode == "server-stuck", detached=mode == "detached-normal-exit",
    )
    if mode == "scan-timeout":
        class TimedOutScanner:
            async def scan_mcp_config_file(self, **_kwargs):
                from mcp import StdioServerParameters
                from mcp.client.stdio import stdio_client

                params = StdioServerParameters(
                    command="uvx", args=["fixture-package"],
                    env={"MCP_FIXTURE_CHILD_PID": str(child_pid_file)},
                )
                async with stdio_client(params):
                    deadline = time.monotonic() + 3
                    while not child_pid_file.exists() and time.monotonic() < deadline:
                        await asyncio.sleep(0.02)
                    assert child_pid_file.exists()
                    raise TimeoutError("fixture scan timed out")

        scanner = TimedOutScanner()
    else:
        scanner = mcpscanner.Scanner(mcpscanner.Config())
    wrapper = MCPScannerWrapper(MCPScannerConfig(analyzers="yara"))
    outside = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    try:
        if mode == "scan-timeout":
            with pytest.raises(BaseException) as caught:
                wrapper._scan_local(scanner, entry, [AnalyzerEnum.YARA])
            assert any(
                isinstance(exc, TimeoutError) and str(exc) == "fixture scan timed out"
                for exc in getattr(caught.value, "exceptions", (caught.value,))
            )
        else:
            findings = wrapper._scan_local(scanner, entry, [AnalyzerEnum.YARA])
            assert findings == []
        child_pid = int(child_pid_file.read_text(encoding="ascii"))
        deadline = time.monotonic() + 3
        while _running(child_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _running(child_pid), f"stdio server child {child_pid} survived the scan"
        assert outside.poll() is None
    finally:
        outside.kill()
        outside.wait()
        if child_pid_file.exists():
            child_pid = int(child_pid_file.read_text(encoding="ascii"))
            if _running(child_pid):
                os.kill(child_pid, signal.SIGKILL)


@pytest.mark.skipif(os.name == "nt", reason="Windows uses a Job Object")
def test_local_stdio_scan_allows_long_valid_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    mcpscanner = pytest.importorskip("mcpscanner")
    from mcpscanner.core.models import AnalyzerEnum

    entry, child_pid_file = _fixture_entry(tmp_path, monkeypatch)
    entry.env["MCP_FIXTURE_DELAY"] = "3.2"
    wrapper = MCPScannerWrapper(MCPScannerConfig(analyzers="yara"))
    try:
        assert wrapper._scan_local(
            mcpscanner.Scanner(mcpscanner.Config()), entry, [AnalyzerEnum.YARA],
        ) == []
        child_pid = int(child_pid_file.read_text(encoding="ascii"))
        deadline = time.monotonic() + 3
        while _running(child_pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not _running(child_pid)
    finally:
        if child_pid_file.exists():
            child_pid = int(child_pid_file.read_text(encoding="ascii"))
            if _running(child_pid):
                os.kill(child_pid, signal.SIGKILL)


@pytest.mark.skipif(os.name == "nt", reason="Windows uses a Job Object")
def test_group_signal_eperm_warns_once_and_keeps_scan_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:
    mcpscanner = pytest.importorskip("mcpscanner")
    from defenseclaw.scanner import mcp
    from mcpscanner.core.models import AnalyzerEnum

    # Run the normal guardian code with group signals unavailable.
    monkeypatch.setattr(
        mcp, "_MCP_POSIX_GUARDIAN_SCRIPT",
        "kill() { printf 'injected EPERM\\n'; return 1; }\n"
        + mcp._MCP_POSIX_GUARDIAN_SCRIPT,
    )
    entry, child_pid_file = _fixture_entry(tmp_path, monkeypatch)
    wrapper = MCPScannerWrapper(MCPScannerConfig(analyzers="yara"))
    try:
        with caplog.at_level(logging.WARNING, logger="defenseclaw.scanner.mcp"):
            result = wrapper._scan_local(
                mcpscanner.Scanner(mcpscanner.Config()), entry, [AnalyzerEnum.YARA],
            )
            assert result == []
            deadline = time.monotonic() + 3
            while not any("a child may still be running" in m for m in caplog.messages):
                assert time.monotonic() < deadline, caplog.messages
                time.sleep(0.02)
        warnings = [m for m in caplog.messages if "a child may still be running" in m]
        assert len(warnings) == 1
        assert "fixture" in warnings[0] and "EPERM" in warnings[0]
        child_pid = int(child_pid_file.read_text(encoding="ascii"))
        if sys.platform == "linux":
            # The child outlived the exited server, so the scanner adopted
            # it as subreaper and ended it although group signals failed.
            assert not _running(child_pid)
        else:
            assert _running(child_pid)
    finally:
        for pid_file in (child_pid_file, tmp_path / "server.pid"):
            if pid_file.exists():
                pid = int(pid_file.read_text(encoding="ascii"))
                if _running(pid):
                    os.kill(pid, signal.SIGKILL)


@pytest.mark.skipif(os.name == "nt", reason="Windows uses a Job Object")
@pytest.mark.parametrize("write_fails", [False, True])
def test_control_close_error_cannot_retain_child_or_reaper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, write_fails: bool,
) -> None:
    mcpscanner = pytest.importorskip("mcpscanner")
    from defenseclaw.scanner import mcp
    from mcpscanner.core.models import AnalyzerEnum

    entry, child_pid_file = _fixture_entry(tmp_path, monkeypatch)
    wrapper = MCPScannerWrapper(MCPScannerConfig(analyzers="yara"))
    def reaper_count() -> int:
        return sum(t.name == "mcp-stdio-guardian-reaper" for t in threading.enumerate())
    def watcher_count() -> int:
        return sum(t.name == "mcp-stdio-descendants" for t in threading.enumerate())

    before_reapers = reaper_count()
    before_watchers = watcher_count()
    original_pipe, original_write, original_close = os.pipe, os.write, os.close
    control_fd: int | None = None
    close_failed = False
    guardians: list[subprocess.Popen[bytes]] = []
    original_reap = mcp._reap_mcp_posix_guardian

    def tracked_pipe() -> tuple[int, int]:
        nonlocal control_fd
        pipe = original_pipe()
        if inspect.currentframe().f_back.f_code.co_name == "create":
            control_fd = pipe[1]
        return pipe

    def fail_write(fd: int, data: bytes) -> int:
        if write_fails and fd == control_fd:
            raise OSError(errno.EIO, "injected control write error")
        return original_write(fd, data)

    def fail_close(fd: int) -> None:
        nonlocal close_failed
        if fd == control_fd:
            close_failed = True
            raise OSError(errno.EIO, "injected control close error")
        original_close(fd)

    def tracked_reap(guardian: subprocess.Popen[bytes], *args: object, **kwargs: object) -> None:
        guardians.append(guardian)
        original_reap(guardian, *args, **kwargs)

    try:
        with monkeypatch.context() as fault:
            fault.setattr(mcp.os, "pipe", tracked_pipe)
            fault.setattr(mcp.os, "write", fail_write)
            fault.setattr(mcp.os, "close", fail_close)
            fault.setattr(mcp, "_reap_mcp_posix_guardian", tracked_reap)
            result = wrapper._scan_local(
                mcpscanner.Scanner(mcpscanner.Config()), entry, [AnalyzerEnum.YARA],
            )
        assert result == [] and close_failed and control_fd is not None
        child_pid = int(child_pid_file.read_text(encoding="ascii"))
        deadline = time.monotonic() + 1.5
        while (_running(child_pid) or any(g.poll() is None for g in guardians)
               or reaper_count() > before_reapers or watcher_count() > before_watchers) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not _running(child_pid)
        assert all(g.poll() is not None for g in guardians)
        assert reaper_count() <= before_reapers
        assert watcher_count() <= before_watchers
    finally:
        if control_fd is not None:
            try:
                original_close(control_fd)
            except OSError:
                pass
        for pid_file in (child_pid_file, tmp_path / "server.pid"):
            if pid_file.exists():
                pid = int(pid_file.read_text(encoding="ascii"))
                if _running(pid):
                    os.kill(pid, signal.SIGKILL)


@pytest.mark.skipif(os.name == "nt", reason="Windows uses a Job Object")
def test_failed_launch_close_error_reaps_guardian_synchronously(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mcp.client.stdio as sdk
    from defenseclaw.scanner import mcp

    original_pipe, original_close = os.pipe, os.close
    control_fds: set[int] = set()
    guardians: list[subprocess.Popen[bytes]] = []
    original_reap = mcp._reap_mcp_posix_guardian

    def tracked_pipe() -> tuple[int, int]:
        pair = original_pipe()
        if inspect.currentframe().f_back.f_code.co_name == "create":
            control_fds.add(pair[1])
        return pair

    def fail_close(fd: int) -> None:
        if fd in control_fds:
            raise OSError(errno.EIO, "injected close error leaving descriptor open")
        original_close(fd)

    def tracked_reap(guardian: subprocess.Popen[bytes], *args: object, **kwargs: object) -> None:
        guardians.append(guardian)
        original_reap(guardian, *args, **kwargs)

    async def launch() -> None:
        with mcp._contained_mcp_posix_process_factory("missing fixture"):
            await sdk._create_platform_compatible_process(
                "/cf499/nonexistent-mcp-server", [], errlog=subprocess.DEVNULL,
            )

    try:
        with monkeypatch.context() as fault:
            fault.setattr(mcp.os, "pipe", tracked_pipe)
            fault.setattr(mcp.os, "close", fail_close)
            fault.setattr(mcp, "_reap_mcp_posix_guardian", tracked_reap)
            with pytest.raises(FileNotFoundError):
                asyncio.run(launch())
        assert len(guardians) == 1
        assert guardians[0].poll() is not None
    finally:
        for fd in control_fds:
            try:
                original_close(fd)
            except OSError:
                pass
        for guardian in guardians:
            if guardian.poll() is None:
                guardian.kill()
            guardian.wait(timeout=2)


@pytest.mark.skipif(os.name == "nt", reason="Windows uses a Job Object")
def test_reaper_ends_guardian_that_misses_its_deadline(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from defenseclaw.scanner import mcp

    guardian = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(300)"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        process_group=0,
    )
    try:
        session_closed = threading.Event()
        session_closed.set()
        with caplog.at_level(logging.WARNING, logger="defenseclaw.scanner.mcp"):
            mcp._reap_mcp_posix_guardian(
                guardian, "fixture", session_closed, cleanup_seconds=0.01,
            )
            deadline = time.monotonic() + 4
            while guardian.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            assert guardian.poll() is not None
            while not any("guardian exceeded cleanup deadline" in m for m in caplog.messages):
                assert time.monotonic() < deadline, caplog.messages
                time.sleep(0.02)
        assert any("server 'fixture'" in m for m in caplog.messages)
    finally:
        if guardian.poll() is None:
            guardian.kill()
        guardian.wait(timeout=2)


_SHORT_HELPER = """import os, signal, sys, time
child = os.fork()
if child:
    os._exit(0)
os.setsid()
signal.signal(signal.SIGTERM, signal.SIG_IGN)
with open(sys.argv[1], "w") as output:
    output.write(str(os.getpid()))
time.sleep(300)
"""

_SHORT_HELPER_SERVER = """import json, os, subprocess, sys, time
pidfile, helperfile = sys.argv[1:]
helper = subprocess.Popen(
    [sys.executable, helperfile, pidfile],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    start_new_session=True,
)
helper.wait(timeout=2)
deadline = time.monotonic() + 2
while not os.path.exists(pidfile) and time.monotonic() < deadline:
    time.sleep(0.005)
for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    method = message.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "fixture", "version": "1.0"}}
    elif method == "server/discover":
        print(json.dumps({"jsonrpc": "2.0", "id": message["id"],
                          "error": {"code": -32601, "message": "Method not found"}}), flush=True)
        continue
    elif method == "tools/list":
        result = {"tools": [{"name": "echo", "description": "Echo text",
                            "inputSchema": {"type": "object", "properties": {}}}]}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
"""


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="needs a child subreaper; macOS keeps the descendant tracker (documented limit)",
)
def test_local_stdio_scan_ends_short_helper_descendant(tmp_path: Path) -> None:
    """rel-1-0-6:GAP-0499 review 3: a helper in its own session forks a
    child that calls setsid, ignores SIGTERM and outlives the helper. The
    parent link is gone before any tree capture; the scan still ends it."""
    mcpscanner = pytest.importorskip("mcpscanner")
    from mcpscanner.core.models import AnalyzerEnum

    server = tmp_path / "server.py"
    helper = tmp_path / "helper.py"
    pidfile = tmp_path / "child.pid"
    server.write_text(_SHORT_HELPER_SERVER, encoding="utf-8")
    helper.write_text(_SHORT_HELPER, encoding="utf-8")
    entry = MCPServerEntry(
        name="short-helper", command=sys.executable,
        args=[str(server), str(pidfile), str(helper)], env={},
    )
    outside = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        wrapper = MCPScannerWrapper(MCPScannerConfig(analyzers="yara"))
        assert wrapper._scan_local(
            mcpscanner.Scanner(mcpscanner.Config()), entry, [AnalyzerEnum.YARA],
        ) == []
        child_pid = int(pidfile.read_text(encoding="ascii"))
        # The scan ends and reaps the orphan before it returns.
        assert not _running(child_pid), f"short-helper descendant {child_pid} survived the scan"
        assert outside.poll() is None, "a process the scan did not start was ended"
    finally:
        outside.kill()
        outside.wait()
        if pidfile.exists():
            child_pid = int(pidfile.read_text(encoding="ascii"))
            if _running(child_pid):
                os.kill(child_pid, signal.SIGKILL)
