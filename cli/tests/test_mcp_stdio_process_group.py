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
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
from defenseclaw.config import MCPScannerConfig, MCPServerEntry
from defenseclaw.scanner.mcp import MCPScannerWrapper


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
    mcp._terminate_mcp_posix_group(pgid)
    assert signals == []


@pytest.mark.skipif(os.name == "nt", reason="Windows uses a Job Object")
def test_cleanup_rejects_scanner_process_group(monkeypatch: pytest.MonkeyPatch) -> None:
    from defenseclaw.scanner import mcp

    signals: list[tuple[int, int]] = []
    monkeypatch.setattr(mcp.os, "killpg", lambda group, sig: signals.append((group, sig)))
    mcp._terminate_mcp_posix_group(mcp._MCP_POSIX_SCANNER_PGID)
    assert signals == []


@pytest.mark.skipif(os.name == "nt", reason="Windows uses a Job Object")
def test_cleanup_skips_reused_group_before_kill(monkeypatch: pytest.MonkeyPatch) -> None:
    from defenseclaw.scanner import mcp

    pgid = 424242
    groups = iter((pgid, pgid + 1))
    signals: list[int] = []
    monkeypatch.setattr(mcp.os, "getpid", lambda: pgid)
    monkeypatch.setattr(mcp.os, "getpgrp", lambda: next(groups))
    monkeypatch.setattr(mcp.os, "killpg", lambda _group, sig: signals.append(sig))
    monkeypatch.setattr(mcp.time, "sleep", lambda _seconds: None)
    mcp._terminate_mcp_posix_group(pgid)
    assert signals == [signal.SIGTERM]


@pytest.mark.skipif(os.name == "nt", reason="Windows uses a Job Object")
@pytest.mark.parametrize("error_type", [PermissionError, ProcessLookupError])
@pytest.mark.parametrize("failed_signal", [signal.SIGTERM, signal.SIGKILL])
def test_cleanup_signal_error_does_not_escape(
    monkeypatch: pytest.MonkeyPatch, failed_signal: int, error_type: type[OSError],
) -> None:
    from defenseclaw.scanner import mcp

    pgid = 424242
    signals: list[int] = []
    monkeypatch.setattr(mcp.os, "getpid", lambda: pgid)
    monkeypatch.setattr(mcp.os, "getpgrp", lambda: pgid)
    monkeypatch.setattr(mcp.time, "sleep", lambda _seconds: None)

    def signal_group(_group: int, sig: int) -> None:
        signals.append(sig)
        if sig == failed_signal:
            raise error_type("simulated cleanup error")

    monkeypatch.setattr(mcp.os, "killpg", signal_group)
    mcp._terminate_mcp_posix_group(pgid)
    if failed_signal == signal.SIGTERM and error_type is ProcessLookupError:
        assert signals == [signal.SIGTERM]
    else:
        assert signals == [signal.SIGTERM, signal.SIGKILL]


@pytest.mark.skipif(os.name == "nt", reason="Windows uses a Job Object")
@pytest.mark.parametrize("mode", ["normal-exit", "scan-timeout", "server-stuck"])
def test_local_stdio_scan_ends_child_on_success_or_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str,
) -> None:
    mcpscanner = pytest.importorskip("mcpscanner")
    from mcpscanner.core.models import AnalyzerEnum

    server = tmp_path / "server.py"
    server.write_text(
        """import json, os, signal, subprocess, sys
child = subprocess.Popen(
    [sys.executable, '-c', 'import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(300)'],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
with open(os.environ['MCP_FIXTURE_CHILD_PID'], 'w') as output:
    output.write(str(child.pid))
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
        result = {'tools': [{'name': 'echo', 'description': 'Echo text',
                            'inputSchema': {'type': 'object', 'properties': {}}}]}
    else:
        result = {}
    print(json.dumps({'jsonrpc': '2.0', 'id': message['id'], 'result': result}), flush=True)
if os.environ.get('MCP_FIXTURE_IGNORE_STDIN'):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        signal.pause()
""",
        encoding="utf-8",
    )
    launcher = tmp_path / "uvx"
    launcher.write_text(f"#!/bin/sh\nexec '{sys.executable}' '{server}'\n", encoding="utf-8")
    launcher.chmod(0o700)
    child_pid_file = tmp_path / "child.pid"
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    entry = MCPServerEntry(
        name="fixture", command="uvx", args=["fixture-package"],
        env={
            "MCP_FIXTURE_CHILD_PID": str(child_pid_file),
            "MCP_FIXTURE_IGNORE_STDIN": "1" if mode == "server-stuck" else "",
        },
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
