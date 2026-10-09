"""MCP (Model Context Protocol) proxy for the DefenseClaw Edge Connector.

Sits between an LLM client and a real MCP server, intercepting every
``tools/call`` request and evaluating it through the 8-stage policy
pipeline.  All other MCP messages (``tools/list``, ``resources/read``,
``prompts/get``, etc.) are forwarded transparently.

Architecture:

    LLM Client (Claude, Codex, etc.)
        | MCP (stdio / HTTP SSE)
        v
    MCP Proxy  (this file)
        | evaluates via EdgeConnector.evaluate()
        | MCP (stdio / HTTP SSE)
        v
    Real MCP Server (ESP-Claw, HA-MCP, etc.)

Usage (stdio transport — most common):

    # Proxy an MCP server that speaks stdio
    DCLAW_MCP_UPSTREAM='["python3", "-m", "esp_claw.mcp_server"]' \
    python3 -m mcp_proxy

    # Or with a config file
    python3 -m mcp_proxy --config mcp_proxy_config.yaml

Usage (HTTP SSE transport):

    DCLAW_MCP_UPSTREAM="http://192.168.1.100:8088/mcp" \
    DCLAW_MCP_TRANSPORT=http \
    python3 -m mcp_proxy

Environment variables:

    DCLAW_MCP_UPSTREAM    Target server — JSON array (stdio) or URL (HTTP)
    DCLAW_MCP_TRANSPORT   "stdio" (default) or "http"
    DCLAW_MCP_PORT        HTTP port when proxy itself serves HTTP (default: 8089)
    DCLAW_MCP_CONFIG      Path to YAML config file
    DCLAW_LIB_PATH        Passed through to EdgeConnector
    DCLAW_SOCKET_PATH     Passed through to EdgeConnector
    DCLAW_FAIL_OPEN       "1" = allow on engine error; "0" (default) = block
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from generic_hook import EdgeConnector, Verdict

logger = logging.getLogger("defenseclaw.mcp_proxy")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class ProxyConfig:
    """Runtime configuration for the MCP proxy."""

    upstream_transport: str = "stdio"
    upstream_command: Optional[List[str]] = None
    upstream_url: Optional[str] = None

    lib_path: Optional[str] = None
    socket_path: Optional[str] = None
    fail_mode: str = "closed"  # "closed" or "open"

    http_port: int = 8089

    @classmethod
    def from_env(cls) -> "ProxyConfig":
        """Build configuration from environment variables."""
        cfg = cls()
        cfg.upstream_transport = os.environ.get("DCLAW_MCP_TRANSPORT", "stdio")

        raw_upstream = os.environ.get("DCLAW_MCP_UPSTREAM", "")
        if cfg.upstream_transport == "http":
            cfg.upstream_url = raw_upstream or None
        else:
            if raw_upstream:
                try:
                    cfg.upstream_command = json.loads(raw_upstream)
                except json.JSONDecodeError:
                    cfg.upstream_command = raw_upstream.split()
            else:
                cfg.upstream_command = None

        cfg.lib_path = os.environ.get("DCLAW_LIB_PATH")
        cfg.socket_path = os.environ.get("DCLAW_SOCKET_PATH")
        cfg.fail_mode = "open" if os.environ.get("DCLAW_FAIL_OPEN") == "1" else "closed"
        cfg.http_port = int(os.environ.get("DCLAW_MCP_PORT", "8089"))
        return cfg

    @classmethod
    def from_yaml(cls, path: str) -> "ProxyConfig":
        """Load from a YAML config file."""
        import yaml  # optional dependency

        with open(path) as fh:
            raw = yaml.safe_load(fh)

        cfg = cls()
        upstream = raw.get("upstream", {})
        cfg.upstream_transport = upstream.get("transport", "stdio")
        cfg.upstream_command = upstream.get("command")
        cfg.upstream_url = upstream.get("url")

        ec = raw.get("edge_connector", {})
        cfg.lib_path = ec.get("lib_path")
        cfg.socket_path = ec.get("socket_path")
        cfg.fail_mode = ec.get("fail_mode", "closed")

        cfg.http_port = raw.get("proxy", {}).get("http_port", 8089)
        return cfg


# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------

def _make_error(req_id: Any, code: int, message: str,
                data: Optional[Dict] = None) -> Dict:
    """Build a JSON-RPC 2.0 error response."""
    err: Dict[str, Any] = {"code": code, "message": message}
    if data:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _encode(msg: Dict) -> bytes:
    """Encode a JSON-RPC message for stdio transport (newline-delimited)."""
    return json.dumps(msg, separators=(",", ":")).encode() + b"\n"


# ---------------------------------------------------------------------------
# Upstream transports
# ---------------------------------------------------------------------------

class _StdioUpstream:
    """Manage a child process that speaks MCP over stdio."""

    def __init__(self, command: List[str]):
        self._command = command
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._read_lock = asyncio.Lock()

    async def start(self) -> None:
        self._proc = await asyncio.create_subprocess_exec(
            *self._command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        logger.info("Upstream started: %s (pid=%s)", self._command, self._proc.pid)

    async def send(self, msg: Dict) -> Dict:
        """Send a JSON-RPC message and wait for the response."""
        assert self._proc and self._proc.stdin and self._proc.stdout
        self._proc.stdin.write(_encode(msg))
        await self._proc.stdin.drain()

        async with self._read_lock:
            line = await self._proc.stdout.readline()
            if not line:
                raise ConnectionError("Upstream process closed stdout")
            return json.loads(line)

    async def stop(self) -> None:
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self._proc.kill()
            logger.info("Upstream stopped")


class _HttpUpstream:
    """Proxy to a remote MCP server over HTTP (simple POST-based)."""

    def __init__(self, url: str):
        # H-6 fix: In production mode, require HTTPS for upstream URLs.
        # Reject plaintext http:// URLs to prevent credential/data leakage.
        is_production = os.environ.get("DCLAW_PRODUCTION", "").lower() in ("1", "true", "yes")
        if is_production and url and url.startswith("http://"):
            raise ValueError(
                f"H-6: DCLAW_PRODUCTION is set but upstream URL uses plaintext HTTP: {url}. "
                f"Use https:// for production upstream connections."
            )
        if is_production and url and not url.startswith("https://"):
            logger.warning(
                "H-6: DCLAW_PRODUCTION is set and upstream URL scheme is not https: %s", url
            )
        self._url = url
        self._session: Any = None  # aiohttp.ClientSession

    async def start(self) -> None:
        try:
            import aiohttp
            self._session = aiohttp.ClientSession()
        except ImportError:
            raise ImportError(
                "HTTP upstream requires aiohttp: pip install aiohttp"
            )
        logger.info("Upstream HTTP: %s", self._url)

    async def send(self, msg: Dict) -> Dict:
        assert self._session is not None
        async with self._session.post(
            self._url,
            json=msg,
            headers={"Content-Type": "application/json"},
        ) as resp:
            return await resp.json()

    async def stop(self) -> None:
        if self._session:
            await self._session.close()


# ---------------------------------------------------------------------------
# Security gate
# ---------------------------------------------------------------------------

class SecurityGate:
    """Wraps EdgeConnector for async-friendly tool-call evaluation."""

    def __init__(self, config: ProxyConfig):
        self._ec = EdgeConnector(
            lib_path=config.lib_path,
            socket_path=config.socket_path,
            fail_open=(config.fail_mode == "open"),
        )

    def evaluate_tool_call(self, tool_name: str,
                           arguments: Dict[str, Any]) -> Verdict:
        """Evaluate a single MCP tools/call through the 8-stage pipeline."""
        return self._ec.evaluate(
            tool_name=tool_name,
            arguments=arguments,
        )

    def shutdown(self) -> None:
        self._ec.shutdown()


# ---------------------------------------------------------------------------
# MCP Proxy core
# ---------------------------------------------------------------------------

class MCPProxy:
    """Transparent MCP proxy with security interception on tools/call.

    Intercepts ``tools/call`` requests, evaluates them through the Edge
    Connector pipeline, and either forwards them to the upstream server
    or returns an MCP error with the block reason.  All other MCP
    messages pass through unchanged.
    """

    # MCP methods that are forwarded without interception
    _PASSTHROUGH_METHODS = frozenset({
        "initialize",
        "initialized",
        "ping",
        "tools/list",
        "resources/list",
        "resources/read",
        "resources/subscribe",
        "resources/unsubscribe",
        "prompts/list",
        "prompts/get",
        "logging/setLevel",
        "completion/complete",
        "notifications/cancelled",
        "notifications/progress",
        "notifications/resources/updated",
        "notifications/resources/list_changed",
        "notifications/tools/list_changed",
        "notifications/prompts/list_changed",
    })

    def __init__(self, config: ProxyConfig):
        self._config = config
        self._gate = SecurityGate(config)

        if config.upstream_transport == "http" and config.upstream_url:
            self._upstream: _StdioUpstream | _HttpUpstream = _HttpUpstream(
                config.upstream_url,
            )
        elif config.upstream_command:
            self._upstream = _StdioUpstream(config.upstream_command)
        else:
            raise ValueError(
                "No upstream configured. Set DCLAW_MCP_UPSTREAM or provide a "
                "config file with upstream.command or upstream.url."
            )

    # -- lifecycle ----------------------------------------------------------

    async def start(self) -> None:
        await self._upstream.start()

    async def stop(self) -> None:
        self._gate.shutdown()
        await self._upstream.stop()

    # -- message handling ---------------------------------------------------

    async def handle_message(self, msg: Dict) -> Optional[Dict]:
        """Process one JSON-RPC message from the client.

        Returns a response dict, or None for notifications (no ``id``).
        """
        method = msg.get("method", "")
        req_id = msg.get("id")

        # tools/call — ALWAYS intercept, regardless of whether an id is present.
        # A tools/call without an id is invalid JSON-RPC (cannot correlate a
        # response) so we reject it rather than forwarding unexamined.
        if method == "tools/call":
            if req_id is None:
                logger.warning(
                    "Rejecting tools/call with no JSON-RPC id (tool=%s)",
                    msg.get("params", {}).get("name", ""),
                )
                return _make_error(
                    None,
                    code=-32600,
                    message="Invalid Request: tools/call requires an id",
                )
            return await self._handle_tool_call(msg)

        # Notifications (no id) — fire-and-forget to upstream (don't wait
        # for a response that will never arrive).
        if req_id is None:
            try:
                await self._send_notification(msg)
            except Exception:
                pass  # best-effort for notifications
            return None

        # Everything else — passthrough
        if method in self._PASSTHROUGH_METHODS or method.startswith("notifications/"):
            return await self._forward(msg)

        # Unknown method — still forward (MCP may evolve)
        logger.debug("Forwarding unknown method: %s", method)
        return await self._forward(msg)

    async def _handle_tool_call(self, msg: Dict) -> Dict:
        """Intercept a tools/call, evaluate, and allow or block."""
        req_id = msg.get("id")
        params = msg.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        # Evaluate through the 8-stage pipeline
        verdict = self._gate.evaluate_tool_call(tool_name, arguments)

        if verdict.blocked:
            logger.warning(
                "BLOCKED tools/call: tool=%s reason=%s",
                tool_name, verdict.reason,
            )
            return _make_error(
                req_id,
                code=-32001,
                message=f"DefenseClaw: tool call blocked ({verdict.reason})",
                data={
                    "tool": tool_name,
                    "reason": verdict.reason,
                    "action": "block",
                },
            )

        logger.info(
            "ALLOWED tools/call: tool=%s reason=%s",
            tool_name, verdict.reason,
        )

        # Forward to real server
        return await self._forward(msg)

    async def _send_notification(self, msg: Dict) -> None:
        """Fire-and-forget: send a notification to the upstream without
        waiting for a response (notifications never receive one)."""
        assert self._upstream is not None
        if isinstance(self._upstream, _StdioUpstream):
            proc = self._upstream._proc
            if proc and proc.stdin:
                proc.stdin.write(_encode(msg))
                await proc.stdin.drain()
        elif isinstance(self._upstream, _HttpUpstream):
            session = self._upstream._session
            if session:
                async with session.post(
                    self._upstream._url,
                    json=msg,
                    headers={"Content-Type": "application/json"},
                ) as resp:
                    pass  # discard response if server sends one
        else:
            # Fallback: best-effort via send() but don't block callers
            await self._upstream.send(msg)

    async def _forward(self, msg: Dict) -> Dict:
        """Forward a message to the upstream and return its response.

        TODO(M-13): Validate the upstream response before returning it to the
        client.  Currently the response is forwarded as-is, which means a
        compromised or buggy upstream MCP server could inject arbitrary
        JSON-RPC fields (e.g., fake tool results, manipulated resource data).
        Add schema validation or at minimum verify the response has the
        expected JSON-RPC structure and matching id.
        """
        try:
            return await self._upstream.send(msg)
        except Exception as exc:
            logger.error("Upstream error: %s", exc)
            return _make_error(
                msg.get("id"),
                code=-32603,
                message=f"Upstream unavailable: {exc}",
            )


# ---------------------------------------------------------------------------
# Stdio server loop (LLM client <-> proxy via stdin/stdout)
# ---------------------------------------------------------------------------

async def _run_stdio(proxy: MCPProxy) -> None:
    """Serve MCP over stdin/stdout (the standard MCP stdio transport)."""
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)

    writer_transport, writer_protocol = await asyncio.get_event_loop().connect_write_pipe(
        asyncio.streams.FlowControlMixin, sys.stdout.buffer,
    )
    writer = asyncio.StreamWriter(
        writer_transport, writer_protocol, None, asyncio.get_event_loop(),
    )

    logger.info("MCP proxy ready (stdio transport)")

    while True:
        line = await reader.readline()
        if not line:
            break

        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Ignoring non-JSON line: %s", line[:100])
            continue

        response = await proxy.handle_message(msg)
        if response is not None:
            writer.write(_encode(response))
            await writer.drain()


# ---------------------------------------------------------------------------
# HTTP SSE server loop (LLM client <-> proxy via HTTP)
# ---------------------------------------------------------------------------

async def _run_http(proxy: MCPProxy, port: int) -> None:
    """Serve MCP over HTTP (simple JSON-RPC POST endpoint).

    POST /mcp  — JSON-RPC request/response
    GET  /health — health check
    """
    try:
        from aiohttp import web
    except ImportError:
        raise ImportError(
            "HTTP transport requires aiohttp: pip install aiohttp"
        )

    # Optional bearer-token auth: when DCLAW_MCP_PROXY_TOKEN is set,
    # every request (except /health) must carry a matching
    # Authorization: Bearer <token> header.
    proxy_token = os.environ.get("DCLAW_MCP_PROXY_TOKEN", "")

    @web.middleware
    async def _auth_middleware(request: web.Request, handler):
        if proxy_token and request.path != "/health":
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer ") or auth[7:] != proxy_token:
                return web.json_response(
                    {"error": "unauthorized"}, status=401,
                )
        return await handler(request)

    async def handle_mcp(request: web.Request) -> web.Response:
        try:
            msg = await request.json()
        except Exception:
            return web.json_response(
                _make_error(None, -32700, "Parse error"), status=400,
            )

        response = await proxy.handle_message(msg)
        if response is None:
            return web.json_response({"ok": True})
        return web.json_response(response)

    async def handle_health(_: web.Request) -> web.Response:
        return web.json_response({"status": "ok", "service": "defenseclaw-mcp-proxy"})

    app = web.Application(middlewares=[_auth_middleware])
    app.router.add_post("/mcp", handle_mcp)
    app.router.add_get("/health", handle_health)

    bind_addr = os.environ.get("DCLAW_MCP_PROXY_BIND", "127.0.0.1")
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, bind_addr, port)
    await site.start()
    logger.info("MCP proxy ready (HTTP transport, %s:%d)", bind_addr, port)

    # Block until cancelled
    stop_event = asyncio.Event()
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_event.set)
    await stop_event.wait()
    await runner.cleanup()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-5s [%(name)s] %(message)s",
        stream=sys.stderr,
    )


def main() -> None:
    """CLI entry point."""
    _setup_logging()

    # Load config
    config_path = None
    args = sys.argv[1:]
    if "--config" in args:
        idx = args.index("--config")
        if idx + 1 < len(args):
            config_path = args[idx + 1]

    if config_path:
        config = ProxyConfig.from_yaml(config_path)
    else:
        config = ProxyConfig.from_env()

    proxy = MCPProxy(config)

    async def _run() -> None:
        await proxy.start()
        try:
            if config.upstream_transport == "http" or "--http" in args:
                await _run_http(proxy, config.http_port)
            else:
                await _run_stdio(proxy)
        finally:
            await proxy.stop()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
