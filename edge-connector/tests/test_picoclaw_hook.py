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

"""Tests for the PicoClaw hook (picoclaw_hook.py)."""
from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import generic_hook  # noqa: E402
import picoclaw_hook  # noqa: E402


class _FakeDaemon:
    """Minimal daemon socket that answers every evaluate with *action*."""

    def __init__(self, action: str):
        self.dir = tempfile.mkdtemp(dir="/tmp", prefix="dclaw-")
        self.path = os.path.join(self.dir, "d.sock")
        self.action = action
        self.requests: list[dict] = []
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)
        self.sock.listen(8)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                data = b""
                while b"\n" not in data:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                if not data:
                    continue  # liveness probe
                req = json.loads(data)
                self.requests.append(req)
                reply = {"jsonrpc": "2.0", "id": req["id"],
                         "result": {"action": self.action, "reason": 1}}
                conn.sendall(json.dumps(reply).encode() + b"\n")

    def close(self):
        self.sock.close()
        os.unlink(self.path)
        os.rmdir(self.dir)


@pytest.fixture
def fresh_engine(monkeypatch):
    monkeypatch.setattr(picoclaw_hook, "_engine", None)
    yield
    picoclaw_hook._engine = None


def test_picoclaw_uses_daemon_socket(fresh_engine, monkeypatch):
    daemon = _FakeDaemon("block")
    try:
        monkeypatch.setenv("DCLAW_SOCKET_PATH", daemon.path)
        monkeypatch.delenv("DCLAW_ALLOW_FFI", raising=False)
        with patch.object(generic_hook._FFIBackend, "__init__", return_value=None) as ffi:
            result = picoclaw_hook.handle_before_tool(
                {"tool": "mcp_roboclaw_drive", "arguments": {"speed": 1},
                 "channel_id": "c1"})
        ffi.assert_not_called()
        assert result["action"] == "deny_tool"
        params = daemon.requests[0]["params"]
        assert params["tool_name"] == "drive"
        assert params["capabilities"] == picoclaw_hook.CAP_ACTUATE
        assert params["session_id"] == picoclaw_hook.get_session_id({"channel_id": "c1"})
    finally:
        daemon.close()


def test_picoclaw_without_daemon_fails_closed(fresh_engine, monkeypatch):
    monkeypatch.setenv("DCLAW_SOCKET_PATH", "/nonexistent/dclaw.sock")
    monkeypatch.delenv("DCLAW_ALLOW_FFI", raising=False)
    with patch.object(generic_hook._FFIBackend, "__init__", return_value=None) as ffi:
        with pytest.raises(ConnectionError):
            picoclaw_hook.get_engine()
    ffi.assert_not_called()


def test_picoclaw_destination_keeps_ipv6_brackets():
    dest = picoclaw_hook.extract_destination(
        "web_fetch", {"url": "http://[2606:4700:4700::1111]/x"})
    assert dest == "[2606:4700:4700::1111]"


def _run_main(monkeypatch, capsys, lines):
    import io
    monkeypatch.setattr(picoclaw_hook, "log", lambda _msg: None)
    monkeypatch.setattr(picoclaw_hook, "get_engine", lambda: object())
    monkeypatch.setattr(picoclaw_hook, "_engine", None)
    monkeypatch.setattr(sys, "stdin", io.StringIO("".join(l + "\n" for l in lines)))
    assert picoclaw_hook.main() == 0
    return [json.loads(l) for l in capsys.readouterr().out.splitlines()]


def test_picoclaw_echoes_string_and_numeric_ids(monkeypatch, capsys):
    hello = {"jsonrpc": "2.0", "method": "hook.hello", "params": {}}
    out = _run_main(monkeypatch, capsys, [
        json.dumps({**hello, "id": "abc"}),
        json.dumps({**hello, "id": 6}),
        json.dumps({**hello, "id": 0}),
        json.dumps({**hello}),                     # notification: no reply
        json.dumps({**hello, "id": None}),         # notification: no reply
        json.dumps({"jsonrpc": "2.0", "id": "x-1", "method": "nope"}),
        json.dumps({**hello, "id": [1]}),          # invalid id
    ])
    assert [r["id"] for r in out] == ["abc", 6, 0, "x-1", None]
    assert out[0]["result"]["ok"] is True
    assert "error" in out[3] and "error" in out[4]
