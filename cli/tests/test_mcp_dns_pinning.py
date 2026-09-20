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

import os
import socket
import sys
import threading
import time
from contextlib import asynccontextmanager, contextmanager
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import anyio
import pytest
import uvicorn
from defenseclaw.config import CiscoAIDefenseConfig, LLMConfig, MCPScannerConfig
from defenseclaw.registries.ssrf import SSRFError, pinned_getaddrinfo
from defenseclaw.scanner.mcp import (
    MCPScannerWrapper,
    _run_with_pinned_dns,
    _scope_network_analyzer_dns,
)
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 11),
    reason="cisco-ai-mcp-scanner requires Python 3.11 or newer",
)


def test_pinned_dns_enters_before_scan_coroutine_is_created():
    factory_called = False

    def make_scan():
        nonlocal factory_called
        factory_called = True

        async def scan():
            return []

        return scan()

    @asynccontextmanager
    async def fail_on_entry():
        raise RuntimeError("pin entry failed")
        yield  # pragma: no cover

    with (
        patch(
            "defenseclaw.scanner.mcp.pinned_async_getaddrinfo",
            fail_on_entry,
        ),
        pytest.raises(RuntimeError, match="pin entry failed"),
    ):
        anyio.run(_run_with_pinned_dns, make_scan)

    assert not factory_called


@pytest.mark.parametrize(
    ("provider", "localhost_address", "allows_loopback_default"),
    [
        pytest.param(
            "ollama",
            "127.0.0.1",
            True,
            id="local-provider-loopback",
        ),
        pytest.param(
            "ollama",
            "169.254.169.254",
            False,
            id="local-provider-poisoned-localhost",
        ),
        pytest.param(
            "anthropic",
            "127.0.0.1",
            False,
            id="cloud-provider-loopback",
        ),
    ],
)
def test_only_local_provider_default_can_resolve_loopback(
    provider,
    localhost_address,
    allows_loopback_default,
):
    calls: list[str] = []

    def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):  # noqa: A002
        node = host.decode("ascii") if isinstance(host, bytes) else str(host)
        calls.append(node)
        address = {
            "localhost": localhost_address,
            "redirect.invalid": "127.0.0.1",
        }.get(node, node)
        return [
            (
                socket.AF_INET,
                type or socket.SOCK_STREAM,
                proto,
                "",
                (address, port),
            )
        ]

    class LocalAnalyzer:
        async def analyze(self):
            with pytest.raises(SSRFError):
                await anyio.getaddrinfo("redirect.invalid", 11434)
            return await anyio.getaddrinfo("localhost", 11434)

    scanner = SimpleNamespace(
        _api_analyzer=None,
        _llm_analyzer=LocalAnalyzer(),
    )
    llm = LLMConfig(provider=provider, model="test-model")
    _scope_network_analyzer_dns(
        scanner,
        api_endpoint="",
        llm_base_url=llm.base_url,
        llm_uses_local_default=llm.is_local_provider(),
    )

    with patch.object(socket, "getaddrinfo", fake_getaddrinfo):
        with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
            if allows_loopback_default:
                results = anyio.run(
                    _run_with_pinned_dns,
                    scanner._llm_analyzer.analyze,
                )
            else:
                with pytest.raises(SSRFError):
                    anyio.run(
                        _run_with_pinned_dns,
                        scanner._llm_analyzer.analyze,
                    )

    if allows_loopback_default:
        assert {info[4][0] for info in results} == {"127.0.0.1"}
    assert calls == ["redirect.invalid", "localhost"]


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
            print("warning: MCP test server did not stop", file=sys.stderr)


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
        analyzer_redirect_calls: list[str] = []
        unexpected_calls: list[str] = []

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
                return real_getaddrinfo("127.0.0.1", service, *args, **kwargs)
            if node == "redirect.invalid":
                analyzer_redirect_calls.append(node)
                return real_getaddrinfo("127.0.0.1", service, *args, **kwargs)
            unexpected_calls.append(node)
            raise AssertionError(f"unexpected DNS lookup: {node}")

        async def analyze_with_public_dns(self, content, context=None):
            with pytest.raises(SSRFError):
                await anyio.getaddrinfo("redirect.invalid", 443)
            infos = await anyio.getaddrinfo("analyzer.invalid", 443)
            assert {info[4][0] for info in infos} == {"127.0.0.1"}
            return []

        wrapper = MCPScannerWrapper(
            MCPScannerConfig(analyzers="api"),
            cisco_ai_defense=CiscoAIDefenseConfig(
                endpoint="https://analyzer.invalid",
                api_key="test-key",
            ),
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
        assert analyzer_redirect_calls == ["redirect.invalid", "redirect.invalid"]
        assert unexpected_calls == []
