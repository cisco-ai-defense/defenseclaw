"""HTTP middleware that gates tool calls through the Edge Connector.

Intercepts POST requests to tool-execution endpoints and evaluates them
through the DefenseClaw Edge Connector before the request reaches the handler.

Usage with FastAPI:
    from http_middleware import EdgeConnectorMiddleware

    app = FastAPI()
    app.add_middleware(EdgeConnectorMiddleware)

Usage with Flask:
    from http_middleware import flask_edge_connector

    app = Flask(__name__)
    flask_edge_connector(app)

Requirements:
    For FastAPI: pip install starlette  (included with fastapi)
    For Flask:   pip install flask
"""
from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from typing import Any

from generic_hook import EdgeConnector

logger = logging.getLogger("defenseclaw.http")

# Default URL patterns that look like tool-execution endpoints
# Word boundaries (\b) on short patterns prevent matching /runway, /invoice, etc.
DEFAULT_TOOL_PATTERNS: list[str] = [
    r"/v\d+/tools?/",
    r"/v\d+/function_call\b",
    r"/api/tools?/",
    r"/api/v\d+/tools?/",
    r"/execute\b",
    r"/invoke\b",
    r"/run\b",
    r"/mcp/",
]

# JSON body keys that typically hold the tool name
_NAME_KEYS = ("tool_name", "name", "function", "tool", "action")
# JSON body keys that typically hold tool arguments
_ARGS_KEYS = ("arguments", "args", "parameters", "params", "input")


def _extract_tool_info(body: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Best-effort extraction of tool name and arguments from a request body."""
    tool_name = ""
    for key in _NAME_KEYS:
        val = body.get(key)
        if isinstance(val, str) and val:
            tool_name = val
            break
        if isinstance(val, dict):
            nested = val.get("name", "")
            if nested:
                tool_name = nested
                break

    arguments: dict[str, Any] = {}
    for key in _ARGS_KEYS:
        val = body.get(key)
        if isinstance(val, dict):
            arguments = val
            break
        if isinstance(val, str):
            try:
                arguments = json.loads(val)
            except (json.JSONDecodeError, TypeError):
                arguments = {"raw": val}
            break

    return tool_name, arguments


# ---------------------------------------------------------------------------
# FastAPI / Starlette middleware
# ---------------------------------------------------------------------------
class EdgeConnectorMiddleware:
    """ASGI middleware for FastAPI/Starlette.

    Intercepts POST requests whose path matches ``tool_patterns`` and
    evaluates them through the Edge Connector.  Blocked requests get a
    ``403`` response.

    Args:
        app: The ASGI application.
        connector: An :class:`EdgeConnector` instance (created automatically
                   with ``fail_open=False`` if not provided).
        tool_patterns: Regex patterns for paths to intercept.
        excluded_paths: Exact paths to skip (e.g., health checks).
    """

    def __init__(
        self,
        app: Any,
        connector: EdgeConnector | None = None,
        tool_patterns: list[str] | None = None,
        excluded_paths: set[str] | None = None,
    ):
        self.app = app
        self._connector = connector or EdgeConnector(fail_open=False)
        self._patterns = [
            re.compile(p) for p in (tool_patterns or DEFAULT_TOOL_PATTERNS)
        ]
        self._excluded = excluded_paths or set()

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        path = scope.get("path", "")

        if '\\' in path:
            resp_body = json.dumps({
                "error": "EdgeConnector: URL contains backslash (potential authority bypass)",
                "reason": "BACKSLASH_REJECTED",
            }).encode()
            await send({
                "type": "http.response.start",
                "status": 400,
                "headers": [[b"content-type", b"application/json"]],
            })
            await send({"type": "http.response.body", "body": resp_body})
            return

        if method != "POST" or path in self._excluded:
            await self.app(scope, receive, send)
            return

        if not any(p.search(path) for p in self._patterns):
            await self.app(scope, receive, send)
            return

        body_parts: list[bytes] = []
        total_size = 0
        while True:
            msg = await receive()
            chunk = msg.get("body", b"")
            total_size += len(chunk)
            if total_size > 10 * 1024 * 1024:
                await send({"type": "http.response.start", "status": 413, "headers": [[b"content-type", b"application/json"]]})
                await send({"type": "http.response.body", "body": b'{"error":"request body too large"}'})
                return
            body_parts.append(chunk)
            if not msg.get("more_body", False):
                break
        raw_body = b"".join(body_parts)

        try:
            body_json = json.loads(raw_body) if raw_body else {}
        except (json.JSONDecodeError, TypeError):
            body_json = {}

        tool_name, arguments = _extract_tool_info(body_json)

        if tool_name:
            # Full body required: _evaluate_chunked() handles large content via overlapping windows.
            raw_content = raw_body.decode("utf-8", errors="replace")
            verdict = self._connector.evaluate(
                tool_name=tool_name,
                arguments=arguments,
                content=raw_content,
            )
            if verdict.blocked:
                logger.warning(
                    "HTTP middleware: blocked %s %s (%s)", method, path, verdict.reason
                )
                resp_body = json.dumps({
                    "error": "EdgeConnector: tool call blocked",
                    "reason": verdict.reason,
                    "tool": tool_name,
                }).encode()
                await send({
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        [b"content-type", b"application/json"],
                        [b"x-defenseclaw-action", b"block"],
                        [b"x-defenseclaw-reason", verdict.reason.encode()],
                    ],
                })
                await send({
                    "type": "http.response.body",
                    "body": resp_body,
                })
                return
        elif not self._connector.fail_open:
            # Unextractable tool names must be blocked in fail-closed mode to prevent bypass.
            logger.warning(
                "HTTP middleware: tool_name extraction failed for %s %s — blocking (fail_closed)",
                method, path,
            )
            resp_body = json.dumps({
                "error": "EdgeConnector: tool name could not be extracted",
                "reason": "EXTRACTION_FAILED",
            }).encode()
            await send({
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    [b"content-type", b"application/json"],
                    [b"x-defenseclaw-action", b"block"],
                    [b"x-defenseclaw-reason", b"EXTRACTION_FAILED"],
                ],
            })
            await send({
                "type": "http.response.body",
                "body": resp_body,
            })
            return

        # Replay the body for the downstream app and scan the response before returning it.
        body_sent = False

        async def replay_receive() -> dict:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": raw_body, "more_body": False}
            return await receive()

        # Capture response to scan it
        response_started = False
        response_status = 0
        response_headers: list = []
        response_body_parts: list[bytes] = []

        async def capture_send(message: dict) -> None:
            nonlocal response_started, response_status, response_headers
            if message["type"] == "http.response.start":
                response_started = True
                response_status = message.get("status", 0)
                response_headers = message.get("headers", [])
            elif message["type"] == "http.response.body":
                response_body_parts.append(message.get("body", b""))

        await self.app(scope, replay_receive, capture_send)

        # Scan response if status 200 and content type is JSON
        should_scan = (
            response_status == 200
            and tool_name
            and any(
                h[0] == b"content-type" and b"json" in h[1]
                for h in response_headers
                if len(h) == 2
            )
        )
        resp_body = b"".join(response_body_parts)

        if should_scan and resp_body:
            try:
                resp_text = resp_body.decode("utf-8", errors="replace")
                resp_verdict = self._connector.evaluate(
                    tool_name=tool_name + "/response",
                    arguments={"content": resp_text},
                    content=resp_text,
                    direction="response",
                )
                if resp_verdict.blocked:
                    logger.warning(
                        "HTTP middleware: response blocked for %s %s (%s)",
                        method, path, resp_verdict.reason,
                    )
                    blocked_body = json.dumps({
                        "error": "EdgeConnector: response blocked",
                        "reason": resp_verdict.reason,
                        "tool": tool_name,
                    }).encode()
                    await send({
                        "type": "http.response.start",
                        "status": 403,
                        "headers": [
                            [b"content-type", b"application/json"],
                            [b"x-defenseclaw-action", b"block"],
                            [b"x-defenseclaw-reason", resp_verdict.reason.encode()],
                        ],
                    })
                    await send({"type": "http.response.body", "body": blocked_body})
                    return
            except Exception as exc:
                logger.debug("Response scan error: %s", exc)

        # Forward the captured response to the client
        await send({
            "type": "http.response.start",
            "status": response_status,
            "headers": response_headers,
        })
        await send({"type": "http.response.body", "body": resp_body})


# ---------------------------------------------------------------------------
# Flask integration
# ---------------------------------------------------------------------------
def flask_edge_connector(
    app: Any,
    connector: EdgeConnector | None = None,
    tool_patterns: list[str] | None = None,
    excluded_paths: set[str] | None = None,
) -> None:
    """Register a ``before_request`` hook on a Flask app.

    Blocked requests get a 403 JSON response.  Non-tool requests and
    non-POST methods pass through untouched.

    Args:
        app: A Flask application instance.
        connector: An :class:`EdgeConnector` (created with ``fail_open=False``
                   if not provided).
        tool_patterns: Regex patterns for paths to intercept.
        excluded_paths: Exact paths to skip.
    """
    ec = connector or EdgeConnector(fail_open=False)
    patterns = [re.compile(p) for p in (tool_patterns or DEFAULT_TOOL_PATTERNS)]
    excluded = excluded_paths or set()

    @app.before_request
    def _edge_connector_gate():
        from flask import jsonify, request

        if request.method != "POST":
            return None
        if request.path in excluded:
            return None
        if not any(p.search(request.path) for p in patterns):
            return None

        if request.content_length and request.content_length > 10 * 1024 * 1024:
            return jsonify({"error": "request body too large"}), 413

        try:
            body = request.get_json(silent=True) or {}
        except Exception:
            body = {}

        tool_name, arguments = _extract_tool_info(body)
        if not tool_name:
            # Unextractable tool names must be blocked in fail-closed mode to prevent bypass.
            if not ec.fail_open:
                logger.warning(
                    "Flask middleware: tool_name extraction failed for %s — blocking (fail_closed)",
                    request.path,
                )
                resp = jsonify({
                    "error": "EdgeConnector: tool name could not be extracted",
                    "reason": "EXTRACTION_FAILED",
                })
                resp.status_code = 403
                resp.headers["X-DefenseClaw-Action"] = "block"
                resp.headers["X-DefenseClaw-Reason"] = "EXTRACTION_FAILED"
                return resp
            return None

        # Full body required: _evaluate_chunked() handles large content via overlapping windows.
        verdict = ec.evaluate(
            tool_name=tool_name,
            arguments=arguments,
            content=json.dumps(body, default=str),
        )
        if verdict.blocked:
            logger.warning(
                "Flask middleware: blocked %s (%s)", tool_name, verdict.reason
            )
            resp = jsonify({
                "error": "EdgeConnector: tool call blocked",
                "reason": verdict.reason,
                "tool": tool_name,
            })
            resp.status_code = 403
            resp.headers["X-DefenseClaw-Action"] = "block"
            resp.headers["X-DefenseClaw-Reason"] = verdict.reason
            return resp

        return None
