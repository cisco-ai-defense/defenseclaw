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
from typing import Any, Callable, Dict, List, Optional, Set

from generic_hook import EdgeConnector, Verdict

logger = logging.getLogger("defenseclaw.http")

# Default URL patterns that look like tool-execution endpoints
DEFAULT_TOOL_PATTERNS: List[str] = [
    r"/v\d+/tools?/",
    r"/v\d+/function_call",
    r"/api/tools?/",
    r"/api/v\d+/tools?/",
    r"/execute",
    r"/invoke",
    r"/run",
    r"/mcp/",
]

# JSON body keys that typically hold the tool name
_NAME_KEYS = ("tool_name", "name", "function", "tool", "action")
# JSON body keys that typically hold tool arguments
_ARGS_KEYS = ("arguments", "args", "parameters", "params", "input")


def _extract_tool_info(body: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    """Best-effort extraction of tool name and arguments from a request body."""
    tool_name = ""
    for key in _NAME_KEYS:
        val = body.get(key)
        if isinstance(val, str) and val:
            tool_name = val
            break
        if isinstance(val, dict):
            tool_name = val.get("name", "")
            break

    arguments: Dict[str, Any] = {}
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
                   with ``fail_open=True`` if not provided).
        tool_patterns: Regex patterns for paths to intercept.
        excluded_paths: Exact paths to skip (e.g., health checks).
    """

    def __init__(
        self,
        app: Any,
        connector: Optional[EdgeConnector] = None,
        tool_patterns: Optional[List[str]] = None,
        excluded_paths: Optional[Set[str]] = None,
    ):
        self.app = app
        self._connector = connector or EdgeConnector(fail_open=False)
        self._patterns = [
            re.compile(p) for p in (tool_patterns or DEFAULT_TOOL_PATTERNS)
        ]
        self._excluded = excluded_paths or set()

    async def __call__(self, scope: Dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        path = scope.get("path", "")

        if method != "POST" or path in self._excluded:
            await self.app(scope, receive, send)
            return

        if not any(p.search(path) for p in self._patterns):
            await self.app(scope, receive, send)
            return

        # Read the request body
        body_parts: list[bytes] = []
        while True:
            msg = await receive()
            body_parts.append(msg.get("body", b""))
            if not msg.get("more_body", False):
                break
        raw_body = b"".join(body_parts)

        try:
            body_json = json.loads(raw_body) if raw_body else {}
        except (json.JSONDecodeError, TypeError):
            body_json = {}

        tool_name, arguments = _extract_tool_info(body_json)

        if tool_name:
            verdict = self._connector.evaluate(
                tool_name=tool_name,
                arguments=arguments,
                content=raw_body.decode("utf-8", errors="replace")[:512],
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

        # Replay the body for the downstream app
        body_sent = False

        async def replay_receive() -> Dict:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": raw_body, "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)


# ---------------------------------------------------------------------------
# Flask integration
# ---------------------------------------------------------------------------
def flask_edge_connector(
    app: Any,
    connector: Optional[EdgeConnector] = None,
    tool_patterns: Optional[List[str]] = None,
    excluded_paths: Optional[Set[str]] = None,
) -> None:
    """Register a ``before_request`` hook on a Flask app.

    Blocked requests get a 403 JSON response.  Non-tool requests and
    non-POST methods pass through untouched.

    Args:
        app: A Flask application instance.
        connector: An :class:`EdgeConnector` (created with ``fail_open=True``
                   if not provided).
        tool_patterns: Regex patterns for paths to intercept.
        excluded_paths: Exact paths to skip.
    """
    ec = connector or EdgeConnector(fail_open=False)
    patterns = [re.compile(p) for p in (tool_patterns or DEFAULT_TOOL_PATTERNS)]
    excluded = excluded_paths or set()

    @app.before_request
    def _edge_connector_gate():
        from flask import request, jsonify

        if request.method != "POST":
            return None
        if request.path in excluded:
            return None
        if not any(p.search(request.path) for p in patterns):
            return None

        try:
            body = request.get_json(silent=True) or {}
        except Exception:
            body = {}

        tool_name, arguments = _extract_tool_info(body)
        if not tool_name:
            return None

        verdict = ec.evaluate(
            tool_name=tool_name,
            arguments=arguments,
            content=json.dumps(body, default=str)[:512],
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
