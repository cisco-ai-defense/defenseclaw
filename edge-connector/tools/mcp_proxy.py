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

"""MCP (Model Context Protocol) proxy for the DefenseClaw Edge Connector.

Sits between an LLM client and a real MCP server, intercepting every
``tools/call`` request and evaluating it through the local policy
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
    python3 tools/mcp_proxy.py

    # Or with a config file
    python3 tools/mcp_proxy.py --config tools/mcp_proxy_config.yaml

Usage (HTTP SSE transport):

    DCLAW_MCP_UPSTREAM="https://approved-public.example.com/mcp" \
    DCLAW_MCP_TRANSPORT=http \
    python3 tools/mcp_proxy.py

Environment variables:

    DCLAW_MCP_UPSTREAM    Target server — JSON array (stdio) or URL (HTTP)
    DCLAW_MCP_TRANSPORT   "stdio" (default) or "http"
    DCLAW_MCP_PORT        HTTP port when proxy itself serves HTTP (default: 8089)
    DCLAW_LIB_PATH        Passed through to EdgeConnector
    DCLAW_SOCKET_PATH     Passed through to EdgeConnector
    DCLAW_FAIL_OPEN       "1" = allow on engine error; "0" (default) = block
"""
from __future__ import annotations

import asyncio
import hmac as _hmac_mod
import ipaddress
import json
import logging
import os
import re
import shlex
import signal
import sys
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from generic_hook import EdgeConnector, Verdict

logger = logging.getLogger("defenseclaw.mcp_proxy")


# ---------------------------------------------------------------------------
# SSRF protection for upstream URLs
# ---------------------------------------------------------------------------

def _validate_upstream_url(url: str) -> str:
    """Validate upstream URL is not targeting private/internal networks."""
    # Backslashes can bypass URL authority parsing in some libraries
    if '\\' in url:
        raise ValueError("URL contains backslash (potential authority bypass)")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("HTTP upstream must use http:// or https://")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("HTTP upstream URL must not contain credentials")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid upstream URL (no hostname)")
    # A hostname spelling of loopback previously bypassed the safe resolver.
    normalized = hostname.lower().rstrip(".")
    if normalized in ("localhost", "localhost.localdomain") or normalized.endswith(".localhost"):
        raise ValueError(f"Upstream URL targets loopback hostname: {hostname}")

    # Block cloud metadata endpoints
    _BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal", "fd00:ec2::254"}
    if hostname.lower() in _BLOCKED_HOSTS:
        raise ValueError(f"Upstream URL targets blocked metadata endpoint: {hostname}")

    # Check if hostname is an IP address in a private range
    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            raise ValueError(f"Upstream URL targets private/reserved address: {hostname}")
    except ValueError as exc:
        # Re-raise our own ValueError (from the checks above)
        if "Upstream URL targets" in str(exc):
            raise
        # Reject noncanonical decimal, octal and hexadecimal IP spellings;
        # some HTTP stacks treat them as literals and skip a DNS resolver.
        if all(re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", label)
               for label in normalized.split(".")):
            raise ValueError(f"Upstream URL uses an ambiguous numeric address: {hostname}")
        # Ordinary DNS names are checked again by _SafeResolver at connect time.

    return url


# ---------------------------------------------------------------------------
# Anti-DNS-rebinding resolver for HTTP upstream
# ---------------------------------------------------------------------------

def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private, loopback, link-local, or reserved."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast)
    except ValueError:
        return True  # fail-closed on unparseable


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class ProxyConfig:
    """Runtime configuration for the MCP proxy."""

    upstream_transport: str = "stdio"
    upstream_command: list[str] | None = None
    upstream_url: str | None = None

    lib_path: str | None = None
    socket_path: str | None = None
    fail_mode: str = "closed"  # "closed" or "open"

    http_port: int = 8089

    @classmethod
    def from_env(cls) -> ProxyConfig:
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
                    cfg.upstream_command = shlex.split(raw_upstream)
            else:
                cfg.upstream_command = None

        cfg.lib_path = os.environ.get("DCLAW_LIB_PATH")
        cfg.socket_path = os.environ.get("DCLAW_SOCKET_PATH")
        cfg.fail_mode = "open" if os.environ.get("DCLAW_FAIL_OPEN") == "1" else "closed"
        cfg.http_port = int(os.environ.get("DCLAW_MCP_PORT", "8089"))
        return cfg

    @classmethod
    def from_yaml(cls, path: str) -> ProxyConfig:
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
                data: dict | None = None) -> dict:
    """Build a JSON-RPC 2.0 error response."""
    err: dict[str, Any] = {"code": code, "message": message}
    if data:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _encode(msg: dict) -> bytes:
    """Encode a JSON-RPC message for stdio transport (newline-delimited)."""
    return json.dumps(msg, separators=(",", ":")).encode() + b"\n"


# ---------------------------------------------------------------------------
# Upstream transports
# ---------------------------------------------------------------------------

_SHELL_METACHARACTERS = set(";|&$`\\\n")


class _StdioUpstream:
    """Manage a child process that speaks MCP over stdio."""

    def __init__(self, command: list[str]):
        # DCLAW_MCP_UPSTREAM is attacker-controlled if env-write is compromised,
        # so verify the executable exists and reject shell metacharacters.
        if not isinstance(command, list) or not command:
            raise ValueError("upstream command must be a non-empty list")
        # Validate ALL arguments for shell metacharacters, not just command[0]
        for i, arg in enumerate(command):
            if not isinstance(arg, str):
                raise ValueError(f"Upstream command argument {i} must be a string")
            if i == 0 and not arg:
                raise ValueError("upstream executable must be non-empty")
            if any(c in arg for c in _SHELL_METACHARACTERS):
                raise ValueError(
                    f"Upstream command argument {i} contains shell metacharacter"
                )
        cmd_path = command[0]
        # Resolve via PATH for bare command names (e.g. "python3")
        import shutil
        resolved = shutil.which(cmd_path)
        if resolved is None:
            raise FileNotFoundError("upstream command not found")
        if not os.path.isfile(resolved):
            raise ValueError("upstream command is not a file")
        if not os.access(resolved, os.X_OK):
            raise PermissionError("upstream command is not executable")

        self._command = command
        self._proc: asyncio.subprocess.Process | None = None
        self._read_lock = asyncio.Lock()

    async def start(self) -> None:
        self._proc = await asyncio.create_subprocess_exec(
            *self._command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        logger.info("Upstream started (pid=%s)", self._proc.pid)

    async def send(self, msg: dict) -> dict:
        """Send a JSON-RPC message and wait for the response."""
        assert self._proc and self._proc.stdin and self._proc.stdout
        async with self._read_lock:
            self._proc.stdin.write(_encode(msg))
            await self._proc.stdin.drain()
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
        _validate_upstream_url(url)

        # Reject plaintext HTTP in production to prevent credential leakage
        is_production = os.environ.get("DCLAW_PRODUCTION", "").lower() in ("1", "true", "yes")
        if is_production and url and url.startswith("http://"):
            raise ValueError(
                "DCLAW_PRODUCTION is set but upstream URL uses plaintext HTTP. "
                "Use https:// for production upstream connections."
            )
        self._url = url
        self._session: Any = None  # aiohttp.ClientSession

    async def start(self) -> None:
        try:
            import aiohttp
            import aiohttp.resolver
        except ImportError:
            raise ImportError(
                "HTTP upstream requires aiohttp: pip install aiohttp"
            )

        class _SafeResolver(aiohttp.resolver.DefaultResolver):
            """Reject private/reserved DNS answers on every connection."""
            async def resolve(self, host, port=0, family=0):
                results = await super().resolve(host, port, family)
                safe = [r for r in results if not _is_private_ip(r["host"])]
                if not safe:
                    raise OSError(f"DNS resolved to private/reserved IP for {host}")
                return safe

        connector = aiohttp.TCPConnector(resolver=_SafeResolver())
        self._session = aiohttp.ClientSession(connector=connector)

        parsed = urllib.parse.urlparse(self._url)
        logger.info("Upstream HTTP: %s://%s", parsed.scheme, parsed.hostname)

    async def send(self, msg: dict) -> dict:
        assert self._session is not None
        # Redirects disabled so bearer tokens are not forwarded to redirect targets
        async with self._session.post(
            self._url,
            json=msg,
            headers={"Content-Type": "application/json"},
            allow_redirects=False,
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
                           arguments: dict[str, Any],
                           direction: str = "request") -> Verdict:
        """Evaluate a single MCP tools/call through the local policy pipeline."""
        return self._ec.evaluate(
            tool_name=tool_name,
            arguments=arguments,
            direction=direction,
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

    async def handle_message(self, msg: Any) -> dict | None:
        """Process one JSON-RPC message from the client.

        Returns a response dict, or None for notifications (no ``id``).
        """
        if not isinstance(msg, dict):
            return _make_error(None, -32600, "Invalid Request")

        req_id = msg.get("id")
        if (isinstance(req_id, bool)
                or (req_id is not None and not isinstance(req_id, (int, str)))
                or (isinstance(req_id, str) and len(req_id) > 128)):
            return _make_error(None, -32600, "Invalid Request")

        raw_method = msg.get("method")
        if not isinstance(raw_method, str) or not raw_method.strip() or len(raw_method) > 128:
            return _make_error(req_id, -32600, "Invalid Request")
        method = raw_method.strip().lower()
        # Normalize so downstream sees the same method string the proxy evaluated
        msg["method"] = method
        # tools/call — ALWAYS intercept, regardless of whether an id is present.
        # A tools/call without an id is invalid JSON-RPC (cannot correlate a
        # response) so we reject it rather than forwarding unexamined.
        if method == "tools/call":
            if req_id is None:
                logger.warning("Rejecting tools/call with no JSON-RPC id")
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

        if method in self._PASSTHROUGH_METHODS or method.startswith("notifications/"):
            return await self._forward(msg)

        # Unknown method — block to prevent method smuggling
        logger.warning("Blocking unknown method")
        return _make_error(
            req_id,
            code=-32601,
            message="Method not allowed",
        )

    async def _handle_tool_call(self, msg: dict) -> dict:
        """Intercept a tools/call, evaluate, and allow or block."""
        req_id = msg.get("id")
        params = msg.get("params", {})
        if not isinstance(params, dict):
            return _make_error(req_id, -32600, "Invalid Request: tools/call params must be an object")
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        # Tool name must be a non-empty string within the C-side DCLAW_TOOL_NAME_MAX (64)
        if not isinstance(tool_name, str) or not tool_name.strip():
            logger.warning("BLOCKED tools/call: empty or invalid tool name")
            return _make_error(
                req_id,
                code=-32602,
                message="DefenseClaw: tool name is required and must be a non-empty string",
            )
        if len(tool_name) > 63:
            logger.warning("BLOCKED tools/call: tool name too long (%d chars)", len(tool_name))
            return _make_error(
                req_id,
                code=-32602,
                message="DefenseClaw: tool name exceeds maximum length (63)",
            )
        if not isinstance(arguments, dict):
            return _make_error(req_id, -32602, "Invalid params: tool arguments must be an object")

        # Evaluate through the local policy pipeline
        verdict = self._gate.evaluate_tool_call(tool_name, arguments)

        if verdict.blocked:
            logger.warning(
                "BLOCKED tools/call: tool=%r reason=%s",
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
            "ALLOWED tools/call: tool=%r reason=%s",
            tool_name, verdict.reason,
        )

        # Forward to real server
        resp = await self._forward(msg)

        # Scan response content for data exfiltration / prompt injection before returning to client
        if resp and self._gate:
            resp_content = ""
            if isinstance(resp, dict):
                result = resp.get("result", {})
                if isinstance(result, dict):
                    content_items = result.get("content", [])
                    if isinstance(content_items, list):
                        resp_content = " ".join(
                            str(c.get("text", "")) for c in content_items if isinstance(c, dict)
                        )
            if resp_content:
                resp_verdict = self._gate.evaluate_tool_call(
                    tool_name + "/response", {"content": resp_content},
                    direction="response",
                )
                if resp_verdict and resp_verdict.blocked:
                    return _make_error(req_id, -32001,
                        f"Response blocked: {resp_verdict.reason}")

        return resp

    async def _send_notification(self, msg: dict) -> None:
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
                # Redirects disabled to prevent credential forwarding
                async with session.post(
                    self._upstream._url,
                    json=msg,
                    headers={"Content-Type": "application/json"},
                    allow_redirects=False,
                ) as resp:
                    pass  # discard response if server sends one
        else:
            # Fallback: best-effort via send() but don't block callers
            await self._upstream.send(msg)

    async def _forward(self, msg: dict) -> dict:
        """Forward a message to the upstream and return its response.

        Validates the upstream response is valid JSON-RPC 2.0 to prevent a
        compromised upstream from injecting arbitrary fields.
        """
        try:
            resp = await self._upstream.send(msg)
        except Exception as exc:
            # Transport exceptions may embed configured URLs, command paths,
            # or upstream payloads. Their type is enough for diagnostics.
            transport = "HTTP" if isinstance(self._upstream, _HttpUpstream) else "stdio"
            logger.error("Upstream %s error: %s", transport, type(exc).__name__)
            return _make_error(
                msg.get("id"),
                code=-32603,
                message="Upstream unavailable",
            )

        valid = (
            isinstance(resp, dict)
            and resp.get("jsonrpc") == "2.0"
            and "id" in resp
            and ("result" in resp or "error" in resp)
        )
        if not valid:
            # Upstream payloads can contain credentials or agent output.
            logger.warning("Upstream returned malformed JSON-RPC response")
            return _make_error(
                msg.get("id"),
                code=-32603,
                message="Upstream returned invalid response",
            )

        return resp


# ---------------------------------------------------------------------------
# Stdio server loop (LLM client <-> proxy via stdin/stdout)
# ---------------------------------------------------------------------------

def _log_non_json_stdio_line(line: bytes) -> None:
    """Report invalid input without copying its contents into logs."""
    logger.warning("Ignoring non-JSON stdio message (%d bytes)", len(line))


async def _handle_stdio_line(proxy: MCPProxy, line: bytes) -> bytes | None:
    """Parse one stdio frame and encode its response, if any."""
    try:
        msg = json.loads(line)
    except (ValueError, RecursionError):
        # Includes JSONDecodeError, invalid UTF-8, oversized numeric literals,
        # and excessive nesting. All can fit under the stdio byte limit.
        _log_non_json_stdio_line(line)
        return _encode(_make_error(None, -32700, "Parse error"))
    response = await proxy.handle_message(msg)
    return _encode(response) if response is not None else None


async def _run_stdio(proxy: MCPProxy) -> None:
    """Serve MCP over stdin/stdout (the standard MCP stdio transport)."""
    reader = asyncio.StreamReader(limit=4 * 1024 * 1024)
    protocol = asyncio.StreamReaderProtocol(reader)
    await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)

    writer_transport, writer_protocol = await asyncio.get_event_loop().connect_write_pipe(
        asyncio.streams.FlowControlMixin, sys.stdout.buffer,
    )
    writer = asyncio.StreamWriter(
        writer_transport, writer_protocol, None, asyncio.get_event_loop(),
    )

    logger.info("MCP proxy ready (stdio transport)")

    MAX_LINE_SIZE = 4 * 1024 * 1024  # 4 MB per message
    while True:
        try:
            line = await reader.readuntil(b"\n")
        except asyncio.IncompleteReadError as e:
            if e.partial:
                line = e.partial
            else:
                break
        except asyncio.LimitOverrunError:
            logger.warning("Dropping oversized stdio message (>%d bytes)", MAX_LINE_SIZE)
            while True:
                chunk = await reader.read(65536)
                if not chunk or chunk.endswith(b"\n"):
                    break
            continue
        if not line:
            break
        if len(line) > MAX_LINE_SIZE:
            logger.warning("Dropping oversized stdio message (%d bytes)", len(line))
            continue

        response_line = await _handle_stdio_line(proxy, line)
        if response_line is not None:
            writer.write(response_line)
            await writer.drain()


# ---------------------------------------------------------------------------
# HTTP rate limiter
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Simple sliding-window rate limiter keyed by client identifier."""

    def __init__(self, max_requests: int = 100, window_secs: float = 60.0):
        self._max = max_requests
        self._window = window_secs
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._cleanup_counter = 0

    def check(self, client_id: str) -> bool:
        """Return True if the request is within the rate limit, False otherwise."""
        now = time.monotonic()
        reqs = self._requests[client_id]
        reqs[:] = [t for t in reqs if now - t < self._window]
        if len(reqs) >= self._max:
            return False
        reqs.append(now)

        # Prune stale entries to prevent unbounded memory growth from defaultdict
        self._cleanup_counter += 1
        if self._cleanup_counter % 100 == 0:
            cutoff = now - self._window
            stale = [k for k, v in self._requests.items() if not v or v[-1] < cutoff]
            for k in stale:
                del self._requests[k]

        return True


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
    rate_limiter = _RateLimiter(max_requests=100, window_secs=60.0)

    @web.middleware
    async def _auth_middleware(request: web.Request, handler):
        if proxy_token and request.path != "/health":
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer ") or not _hmac_mod.compare_digest(auth[7:], proxy_token):
                return web.json_response(
                    {"error": "unauthorized"}, status=401,
                )
        return await handler(request)

    async def handle_mcp(request: web.Request) -> web.Response:
        # Rate limit by client IP
        client_ip = request.remote or "unknown"
        if not rate_limiter.check(client_ip):
            logger.warning("Rate limit exceeded for client %s", client_ip)
            return web.json_response(
                _make_error(None, -32000, "Rate limit exceeded"), status=429,
            )

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

    app = web.Application(client_max_size=1024 * 1024, middlewares=[_auth_middleware])
    app.router.add_post("/mcp", handle_mcp)
    app.router.add_get("/health", handle_health)

    bind_addr = os.environ.get("DCLAW_MCP_PROXY_BIND", "127.0.0.1")
    if bind_addr not in ("127.0.0.1", "::1", "localhost"):
        if not os.environ.get("DCLAW_MCP_PROXY_TOKEN"):
            logger.error(
                "DCLAW_MCP_PROXY_TOKEN is required when binding to non-loopback "
                "address %s. Set DCLAW_MCP_PROXY_TOKEN or bind to 127.0.0.1.",
                bind_addr,
            )
            sys.exit(1)
        # Bearer tokens travel in plaintext over HTTP; block non-loopback in production
        _production = os.environ.get("DCLAW_PRODUCTION", "") in ("true", "1")
        if _production:
            logger.critical(
                "SECURITY: MCP proxy binding to non-loopback address %s in production mode. "
                "Bearer token will be transmitted in CLEARTEXT over HTTP. "
                "Use a TLS-terminating reverse proxy or set DCLAW_MCP_PROXY_BIND=127.0.0.1",
                bind_addr,
            )
            # In production, refuse to bind non-loopback without explicit opt-in
            if os.environ.get("DCLAW_MCP_ALLOW_CLEARTEXT_BIND") != "1":
                raise SystemExit(
                    "Refusing to bind MCP proxy to non-loopback address in production without TLS. "
                    "Set DCLAW_MCP_ALLOW_CLEARTEXT_BIND=1 to override (NOT RECOMMENDED)."
                )
        logger.warning("MCP proxy binding to %s — ensure firewall is configured", bind_addr)
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
    import argparse as _argparse

    _setup_logging()

    parser = _argparse.ArgumentParser(description="DefenseClaw MCP Proxy")
    parser.add_argument("--config", default=None, help="Path to config YAML")
    parser.add_argument("--http", action="store_true", help="Use HTTP transport")
    parsed = parser.parse_args()

    config_path = parsed.config

    if config_path:
        config = ProxyConfig.from_yaml(config_path)
    else:
        config = ProxyConfig.from_env()

    proxy = MCPProxy(config)

    async def _run() -> None:
        await proxy.start()
        try:
            if config.upstream_transport == "http" or parsed.http:
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
