# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Integration coverage for MCP transport DNS pinning."""

from __future__ import annotations

import asyncio
import os
import socket
import sys
import threading
import time
from contextlib import contextmanager
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import anyio
import pytest
import uvicorn
from defenseclaw.config import CiscoAIDefenseConfig, MCPScannerConfig
from defenseclaw.scanner.mcp import MCPScannerWrapper
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 11),
    reason="cisco-ai-mcp-scanner requires Python 3.11 or newer",
)


@contextmanager
def _serve_mcp(transport: str):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]

    app = FastMCP(
        "dns-pin-test",
        log_level="ERROR",
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False,
        ),
    )

    @app.tool()
    def ping() -> str:
        return "pong"

    @app.tool()
    def status() -> str:
        return "ready"

    asgi = app.sse_app() if transport == "sse" else app.streamable_http_app()
    server = uvicorn.Server(
        uvicorn.Config(
            asgi,
            host="127.0.0.1",
            port=port,
            log_level="error",
            access_log=False,
            lifespan="on",
            timeout_graceful_shutdown=1,
            loop="asyncio",
        )
    )
    thread = threading.Thread(
        target=server.run,
        kwargs={"sockets": [listener]},
        daemon=True,
    )
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not server.started:
            if not thread.is_alive():
                raise RuntimeError("MCP test server exited during startup")
            if time.monotonic() >= deadline:
                raise TimeoutError("MCP test server did not start")
            time.sleep(0.01)
        yield port
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()
        if thread.is_alive():
            raise RuntimeError("MCP test server did not stop")


@pytest.mark.parametrize(
    ("transport", "path"),
    [
        pytest.param("streamable-http", "/mcp", id="streamable-http"),
        pytest.param("sse", "/sse", id="sse"),
    ],
)
def test_real_sdk_remote_scan_uses_pinned_dns(
    monkeypatch,
    transport,
    path,
):
    monkeypatch.setenv("LITELLM_LOCAL_MODEL_COST_MAP", "True")
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("no_proxy", "*")
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "DEFENSECLAW_LLM_KEY",
    ):
        monkeypatch.delenv(name, raising=False)

    with _serve_mcp(transport) as port:
        real_getaddrinfo = socket.getaddrinfo
        target_calls: list[str] = []
        pinned_calls: list[str] = []
        analyzer_calls: list[str] = []
        unexpected_calls: list[str] = []
        analyzers_started = 0
        both_analyzers_started = asyncio.Event()

        def rebinding_resolver(host, service, *args, **kwargs):
            node = host.decode("ascii") if isinstance(host, bytes) else str(host)
            if node == "rebind.invalid":
                target_calls.append(node)
                ip = "127.0.0.1" if len(target_calls) == 1 else "127.0.0.2"
                return real_getaddrinfo(ip, service, *args, **kwargs)
            if node == "127.0.0.1":
                pinned_calls.append(node)
                return real_getaddrinfo(node, service, *args, **kwargs)
            if node == "analyzer.invalid":
                analyzer_calls.append(node)
                return real_getaddrinfo("8.8.8.8", service, *args, **kwargs)
            unexpected_calls.append(node)
            raise AssertionError(f"unexpected DNS lookup: {node}")

        async def analyze_with_public_dns(self, content, context=None):
            nonlocal analyzers_started
            analyzers_started += 1
            if analyzers_started == 2:
                both_analyzers_started.set()
            await asyncio.wait_for(both_analyzers_started.wait(), timeout=5)
            infos = await anyio.getaddrinfo("analyzer.invalid", 443)
            assert {info[4][0] for info in infos} == {"8.8.8.8"}
            return []

        wrapper = MCPScannerWrapper(
            MCPScannerConfig(analyzers="api"),
            cisco_ai_defense=CiscoAIDefenseConfig(api_key="test-key"),
        )
        url = f"http://rebind.invalid:{port}{path}"
        with (
            patch.object(socket, "getaddrinfo", rebinding_resolver),
            patch(
                "mcpscanner.core.analyzers.api_analyzer.ApiAnalyzer.analyze",
                analyze_with_public_dns,
            ),
        ):
            result = wrapper.scan(url, allow_private=True)
            assert socket.getaddrinfo is rebinding_resolver

        assert result.target == url
        assert target_calls == ["rebind.invalid"]
        assert pinned_calls
        assert analyzer_calls == ["analyzer.invalid", "analyzer.invalid"]
        assert unexpected_calls == []
