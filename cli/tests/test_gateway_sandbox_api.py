# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""OrchestratorClient's sandbox API methods against a fake daemon.

The fake speaks the wire contract of internal/gateway/api_sandbox.go and
internal/openshell/sandboxapi: JSON bodies, the {"code","error"} error body,
and the server-sent activity stream.
"""

from __future__ import annotations

import json
import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
import requests
from defenseclaw.gateway import (
    SANDBOX_ADMIN_MESSAGE,
    OrchestratorClient,
    SandboxAPIError,
    parse_sse_events,
)

SANDBOX = {
    "name": "myapp-claude-7f3a",
    "harness": "claudecode",
    "harness_name": "Claude Code",
    "phase": "ready",
    "pack": "open",
    "profile": "open",
    "workdir_mode": "mount",
    "yolo": True,
    "uptime_seconds": 120,
    "egress": {"destinations": 23, "blocked": 1, "bytes_up": 0, "bytes_down": 0},
    "hooks": {"hook_requests": 60, "tool_calls": 57, "tool_blocked": 1},
    "pending_approvals": 0,
    "launch": {"yolo": True},
}


class FakeDaemon:
    """Records requests and answers from a route table."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.routes: dict[tuple[str, str], tuple[int, Any]] = {}
        self.sse_chunks: list[bytes] = []
        # A non-200 answer for ?follow=true (status, JSON body).
        self.stream_refusal: tuple[int, dict[str, Any]] | None = None
        daemon = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                parsed = urlparse(self.path)
                record = {
                    "method": self.command,
                    "path": parsed.path,
                    "query": parse_qs(parsed.query),
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": json.loads(raw) if raw else None,
                }
                daemon.requests.append(record)
                if (
                    parsed.path == "/api/v1/sandbox/activity"
                    and "follow" in record["query"]
                    and daemon.stream_refusal is None
                ):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    for chunk in daemon.sse_chunks:
                        self.wfile.write(chunk)
                        self.wfile.flush()
                    self.close_connection = True
                    return
                default = (404, {"code": "not_found", "error": "no route"})
                status, body = daemon.routes.get((self.command, parsed.path), default)
                if parsed.path == "/api/v1/sandbox/activity" and daemon.stream_refusal is not None:
                    status, body = daemon.stream_refusal
                payload = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                if status in (301, 302, 307):
                    self.send_header("Location", "http://127.0.0.1:9/elsewhere")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = do_POST = do_DELETE = _handle  # noqa: N815 - BaseHTTPRequestHandler's method names

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return self.server.server_port

    def client(self) -> OrchestratorClient:
        return OrchestratorClient(host="127.0.0.1", port=self.port, token="master-token", timeout=3)

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


@pytest.fixture
def daemon() -> Iterator[FakeDaemon]:
    fake = FakeDaemon()
    try:
        yield fake
    finally:
        fake.stop()


def test_reads_carry_the_token_and_decode_the_payloads(daemon: FakeDaemon) -> None:
    daemon.routes[("GET", "/api/v1/sandbox/status")] = (200, {"enabled": True, "available": True, "sandboxes": 1})
    daemon.routes[("GET", "/api/v1/sandbox/sandboxes")] = (200, {"sandboxes": [SANDBOX, "junk"]})
    daemon.routes[("GET", "/api/v1/sandbox/sandboxes/myapp-claude-7f3a")] = (200, SANDBOX)
    daemon.routes[("GET", "/api/v1/sandbox/approvals")] = (200, {"approvals": [{"id": "a1", "sandbox": "x"}]})
    daemon.routes[("GET", "/api/v1/sandbox/activity")] = (200, {"events": [{"seq": 3, "kind": "egress.allowed"}]})
    client = daemon.client()

    assert client.sandbox_status()["sandboxes"] == 1
    assert [row["name"] for row in client.list_sandboxes()] == ["myapp-claude-7f3a"]
    assert client.get_sandbox("myapp-claude-7f3a")["harness"] == "claudecode"
    assert client.sandbox_approvals(sandbox="x")[0]["id"] == "a1"
    assert client.sandbox_activity(since=2, sandbox="x")[0]["seq"] == 3

    for request in daemon.requests:
        assert request["method"] == "GET"
        assert request["headers"]["authorization"] == "Bearer master-token"
        assert request["headers"]["x-defenseclaw-client"] == "python-cli"
    assert daemon.requests[3]["query"] == {"sandbox": ["x"]}
    assert daemon.requests[4]["query"] == {"since": ["2"], "sandbox": ["x"]}


def test_the_gateways_driver_and_the_image_reach_the_panel(daemon: FakeDaemon) -> None:
    from defenseclaw.tui.services.sandbox_state import decode_sandbox, decode_status

    image = "defenseclaw/sandbox:codex-0123456789ab-u501"
    status = {"enabled": True, "available": True, "gateway": {"name": "openshell", "version": "0.1.1", "driver": "vm"}}
    daemon.routes[("GET", "/api/v1/sandbox/status")] = (200, status)
    daemon.routes[("GET", "/api/v1/sandbox/sandboxes")] = (
        200,
        {"sandboxes": [{**SANDBOX, "workdir_mode": "copy", "image": image}]},
    )
    client = daemon.client()

    decoded = decode_status(client.sandbox_status())
    assert decoded.driver == "vm" and decoded.gateway == "OpenShell 0.1.1 gateway openshell (MicroVM)"
    assert decoded.copy_only_note.startswith("MicroVM sandboxes work on a copy")
    row = decode_sandbox(client.list_sandboxes()[0])
    assert row is not None and row.image == image and row.copy_mode
    # A daemon older than the fields: docker, mount mode possible, no image.
    older = decode_status({"enabled": True, "gateway": {"name": "openshell"}})
    assert older.driver == "" and older.copy_only_note == "" and older.gateway == "OpenShell gateway openshell"
    assert decode_sandbox(SANDBOX).image == ""


def test_mutations_post_json_bodies_the_go_api_decodes_strictly(daemon: FakeDaemon) -> None:
    name = "my app/1"
    escaped = "/api/v1/sandbox/sandboxes/my%20app%2F1"
    for verb in ("stop", "start", "undo", "review", "accept"):
        daemon.routes[("POST", f"{escaped}/{verb}")] = (200, {"name": name})
    daemon.routes[("DELETE", escaped)] = (200, {"name": name, "deleted": True})
    daemon.routes[("POST", "/api/v1/sandbox/approvals/ask%2F1")] = (
        200,
        {"approval": {"id": "ask/1"}, "message": "queued"},
    )
    daemon.routes[("POST", "/api/v1/sandbox/egress/unblock")] = (200, {"host": "webhook.site", "scope": "sandbox"})
    client = daemon.client()

    client.stop_sandbox(name)
    client.start_sandbox(name, no_snapshot=True)
    client.start_sandbox(name, new_snapshot=True)
    client.undo_sandbox(name, preview=True, stop=True)
    client.review_sandbox(name, diff=True)
    client.accept_sandbox_changes(name, snapshot_created_at="2026-09-30T10:00:00Z", session=2)
    client.accept_sandbox_changes(name)
    assert client.delete_sandbox(name, keep_snapshot=True)["deleted"] is True
    assert client.decide_sandbox_approval("ask/1", approve=True, always=True, reason="ok")["message"] == "queued"
    client.decide_sandbox_approval("ask/1", approve=False)
    client.unblock_sandbox_egress("webhook.site", sandbox=name)
    client.unblock_sandbox_egress("example.com", always=True)

    bodies = [(r["method"], r["path"], r["body"]) for r in daemon.requests]
    assert bodies == [
        ("POST", f"{escaped}/stop", {}),
        ("POST", f"{escaped}/start", {"no_snapshot": True}),
        ("POST", f"{escaped}/start", {"new_snapshot": True}),
        ("POST", f"{escaped}/undo", {"preview": True, "stop": True}),
        ("POST", f"{escaped}/review", {"diff": True}),
        ("POST", f"{escaped}/accept", {"snapshot_created_at": "2026-09-30T10:00:00Z", "session": 2}),
        ("POST", f"{escaped}/accept", {}),
        ("DELETE", escaped, {"keep_snapshot": True}),
        ("POST", "/api/v1/sandbox/approvals/ask%2F1", {"decision": "approve", "always": True, "reason": "ok"}),
        ("POST", "/api/v1/sandbox/approvals/ask%2F1", {"decision": "reject"}),
        ("POST", "/api/v1/sandbox/egress/unblock", {"host": "webhook.site", "sandbox": name}),
        ("POST", "/api/v1/sandbox/egress/unblock", {"host": "example.com", "always": True}),
    ]
    for request in daemon.requests:
        # The CSRF gate needs the client header and a JSON content type.
        assert request["headers"]["content-type"] == "application/json"
        assert request["headers"]["x-defenseclaw-client"]


def test_the_kept_run_log_of_a_stopped_sandbox(daemon: FakeDaemon) -> None:
    path = "/api/v1/sandbox/sandboxes/myapp-claude-7f3a/logs"
    kept = {
        "name": "myapp-claude-7f3a",
        "state": "interrupted",
        "kept_at": "2026-09-30T10:00:00Z",
        "log": "still working\n",
    }
    daemon.routes[("GET", path)] = (200, kept)
    client = daemon.client()
    assert client.sandbox_run_log("myapp-claude-7f3a", lines=1)["log"] == "still working\n"
    assert client.sandbox_run_log("myapp-claude-7f3a")["state"] == "interrupted"
    assert [r["query"] for r in daemon.requests] == [{"lines": ["1"]}, {}]
    daemon.routes[("GET", path)] = (
        404,
        {"code": "not_found", "error": "no log of a detached run of sandbox x was kept"},
    )
    with pytest.raises(SandboxAPIError) as exc:
        client.sandbox_run_log("myapp-claude-7f3a")
    assert exc.value.code == "not_found"


def test_policy_explain_encodes_the_query_like_the_go_client(daemon: FakeDaemon) -> None:
    daemon.routes[("GET", "/api/v1/sandbox/policy/explain")] = (200, {"pack": "open", "settings": []})
    daemon.client().sandbox_policy_explain(harness="codex", copy=True, unmask=("a", "b"))
    assert daemon.requests[0]["query"] == {"harness": ["codex"], "copy": ["true"], "unmask": ["a", "b"]}


def test_an_admin_refusal_reads_as_the_organization_policy(daemon: FakeDaemon) -> None:
    daemon.routes[("POST", "/api/v1/sandbox/egress/unblock")] = (
        403,
        {
            "code": "admin_violation",
            "error": f"{SANDBOX_ADMIN_MESSAGE}: unblocking is not allowed",
            "violation": {"key": "egress.unblock", "admin": True},
        },
    )
    with pytest.raises(SandboxAPIError) as info:
        daemon.client().unblock_sandbox_egress("webhook.site", sandbox="x")
    err = info.value
    assert err.code == "admin_violation" and err.admin and err.status == 403
    assert err.plain() == f"{SANDBOX_ADMIN_MESSAGE}: unblocking is not allowed"


def test_a_policy_violation_flagged_admin_gets_the_organization_prefix(daemon: FakeDaemon) -> None:
    daemon.routes[("POST", "/api/v1/sandbox/approvals/a1")] = (
        403,
        {"code": "policy_violation", "error": "approve-always is off", "violation": {"admin": True}},
    )
    with pytest.raises(SandboxAPIError) as info:
        daemon.client().decide_sandbox_approval("a1", approve=True, always=True)
    assert info.value.plain() == f"{SANDBOX_ADMIN_MESSAGE}: approve-always is off"


@pytest.mark.parametrize(
    ("status", "body", "code"),
    [
        (503, {"code": "disabled", "error": "OpenShell sandboxes are disabled"}, "disabled"),
        (409, b"conflict text", "conflict"),
        (500, b"", "internal"),
        (404, {"error": "no such sandbox"}, "not_found"),
    ],
)
def test_error_bodies_decode_with_codes(daemon: FakeDaemon, status: int, body: Any, code: str) -> None:
    daemon.routes[("GET", "/api/v1/sandbox/status")] = (status, body)
    with pytest.raises(SandboxAPIError) as info:
        daemon.client().sandbox_status()
    assert info.value.code == code
    assert info.value.plain()
    assert "Traceback" not in info.value.plain()


def test_a_redirect_is_refused_and_never_followed(daemon: FakeDaemon) -> None:
    daemon.routes[("GET", "/api/v1/sandbox/sandboxes")] = (302, {})
    with pytest.raises(SandboxAPIError) as info:
        daemon.client().list_sandboxes()
    assert info.value.code == "internal"
    assert len(daemon.requests) == 1


def test_a_malformed_list_is_an_error_not_an_empty_list(daemon: FakeDaemon) -> None:
    daemon.routes[("GET", "/api/v1/sandbox/sandboxes")] = (200, {"sandboxes": "nope"})
    with pytest.raises(SandboxAPIError, match="malformed"):
        daemon.client().list_sandboxes()


def test_an_unreachable_daemon_is_unavailable() -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    client = OrchestratorClient(host="127.0.0.1", port=port, token="t", timeout=1)
    with pytest.raises(SandboxAPIError) as info:
        client.sandbox_status()
    assert info.value.code == "unavailable"
    assert info.value.plain() == "the DefenseClaw daemon is not reachable"


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        # Windows reports a stopped daemon's closed port this way.
        (requests.ConnectTimeout, "the DefenseClaw daemon is not reachable"),
        (requests.ReadTimeout, "the DefenseClaw daemon did not answer in time"),
    ],
)
def test_a_connect_timeout_is_unreachable_and_a_read_timeout_is_slow(
    monkeypatch: pytest.MonkeyPatch, failure: type[requests.Timeout], message: str
) -> None:
    client = OrchestratorClient(host="127.0.0.1", port=1, token="t", timeout=1)

    def fail(*_args: Any, **_kwargs: Any) -> None:
        raise failure("timed out")

    monkeypatch.setattr(client._session, "request", fail)
    with pytest.raises(SandboxAPIError) as info:
        client.sandbox_status()
    assert info.value.code == "unavailable"
    assert info.value.plain() == message


def test_the_activity_stream_replays_and_follows(daemon: FakeDaemon) -> None:
    daemon.sse_chunks = [
        b'id: 7\nevent: activity\ndata: {"seq":7,"kind":"egress.blocked","host":"webhook.site","unblockable":true}\n\n',
        b": keepalive\n\n",
        b'id: 8\nevent: activity\ndata: {"seq":8,\ndata: "kind":"tool.blocked"}\n\n',
        b"data: not json\n\n",
        b'data: {"seq":9,"kind":"finding","reason":"nested_repo"}\n\n',
    ]
    stream = daemon.client().open_sandbox_activity_stream(since=6, sandbox="myapp")
    events = list(stream)
    assert [event["seq"] for event in events] == [7, 8, 9]
    assert events[1]["kind"] == "tool.blocked"
    request = daemon.requests[0]
    assert request["query"] == {"follow": ["true"], "since": ["6"], "sandbox": ["myapp"]}
    assert request["headers"]["accept"] == "text/event-stream"
    assert stream.closed


def test_a_refused_stream_raises_before_iterating(daemon: FakeDaemon) -> None:
    daemon.stream_refusal = (429, {"code": "unavailable", "error": "too many activity streams are open"})
    with pytest.raises(SandboxAPIError) as info:
        daemon.client().open_sandbox_activity_stream()
    assert info.value.status == 429
    assert info.value.plain() == "too many activity streams are open"


def test_parse_sse_events_matches_go_read_events() -> None:
    lines = [
        ": comment",
        "id: 1",
        'data: {"seq":1,"kind":"egress.allowed"}',
        "",
        'data:{"seq":2,',
        'data: "kind":"dropped"}',
        "",
        "",
        'data: {"seq":3,"kind":"finding"}',
    ]
    assert [event["seq"] for event in parse_sse_events(lines)] == [1, 2, 3]
    assert list(parse_sse_events([b'data: {"seq": 4}\r\n', b"\r\n"])) == [{"seq": 4}]
    assert list(parse_sse_events(["data: [1,2]", ""])) == []
