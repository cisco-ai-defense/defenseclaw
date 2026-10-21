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

"""Tests for the HTTP middleware (http_middleware.py)."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from generic_hook import Verdict  # noqa: E402
from http_middleware import (  # noqa: E402
    AmbiguousToolName,
    EdgeConnectorMiddleware,
    _extract_tool_info,
    flask_edge_connector,
)


def _connector(fail_open: bool = False) -> MagicMock:
    ec = MagicMock()
    ec.fail_open = fail_open

    def evaluate(tool_name, **_kwargs):
        if tool_name == "exec_shell":
            return Verdict.error("POLICY_TABLE")
        return Verdict.allow()

    ec.evaluate.side_effect = evaluate
    return ec


def _run_asgi(body: dict, connector: MagicMock) -> tuple[int, list[str]]:
    executed: list[str] = []

    async def app(scope, receive, send):
        msg = await receive()
        req = json.loads(msg["body"])
        # The application dispatches on "tool", not on the first key the
        # middleware happens to look at.
        executed.append(req.get("tool") or req.get("name"))
        await send({"type": "http.response.start", "status": 200,
                    "headers": [[b"content-type", b"text/plain"]]})
        await send({"type": "http.response.body", "body": b"done"})

    mw = EdgeConnectorMiddleware(app, connector=connector)
    raw = json.dumps(body).encode()
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": raw, "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": "/api/tools/run"}
    asyncio.run(mw(scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    return status, executed


class TestExtractToolInfo:
    def test_single_key(self):
        assert _extract_tool_info({"name": "adc_read", "args": {"a": 1}}) == (
            "adc_read", {"a": 1})

    def test_agreeing_keys(self):
        name, _ = _extract_tool_info({"name": "adc_read", "tool": "adc_read"})
        assert name == "adc_read"

    @pytest.mark.parametrize("body", [
        {"name": "adc_read", "tool": "exec_shell"},
        {"tool_name": "adc_read", "action": "exec_shell"},
        {"function": {"name": "adc_read"}, "name": "exec_shell"},
    ])
    def test_conflicting_keys_rejected(self, body):
        with pytest.raises(AmbiguousToolName):
            _extract_tool_info(body)

    def test_non_object_body(self):
        assert _extract_tool_info([1, 2]) == ("", {})


class TestAsgiToolNameConflict:
    def test_conflicting_names_blocked_before_app(self):
        ec = _connector()
        status, executed = _run_asgi({"name": "adc_read", "tool": "exec_shell"}, ec)
        assert status == 403
        assert executed == []
        ec.evaluate.assert_not_called()

    def test_conflicting_names_blocked_even_when_fail_open(self):
        ec = _connector(fail_open=True)
        status, executed = _run_asgi({"name": "adc_read", "tool": "exec_shell"}, ec)
        assert status == 403
        assert executed == []

    def test_single_name_allowed(self):
        status, executed = _run_asgi({"tool": "adc_read"}, _connector())
        assert status == 200
        assert executed == ["adc_read"]


class TestFlaskToolNameConflict:
    def test_conflicting_names_blocked(self):
        flask = pytest.importorskip("flask")
        app = flask.Flask(__name__)
        executed: list[str] = []

        @app.post("/api/tools/run")
        def run():
            executed.append(flask.request.get_json()["tool"])
            return "done"

        flask_edge_connector(app, connector=_connector())
        resp = app.test_client().post(
            "/api/tools/run", json={"name": "adc_read", "tool": "exec_shell"})
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "AMBIGUOUS_TOOL_NAME"
        assert executed == []
