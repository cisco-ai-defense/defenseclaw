# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw agent identities`` command surface."""

from __future__ import annotations

import json
from typing import Any

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_agent
from defenseclaw.gateway import OrchestratorClient
from defenseclaw.main import cli

_ROW = {
    "agent_id": "agt-0123456789abcdef",
    "user_id": "1001",
    "user_name": "alice",
    "connector": "claudecode",
    "install_fp": "/home/alice/.claude",
    "install_hint": "/srv/other/.claude",
    "machine_hash": "f" * 64,
    "first_seen": "2026-10-05T12:00:00Z",
    "last_seen": "2026-10-05T12:30:00Z",
    "last_session_id": "s-2",
    "sessions_seen": 2,
}


_ROW2 = {**_ROW, "agent_id": "agt-fedcba9876543210", "last_seen": "2026-10-05T12:00:00Z"}


class _StubClient:
    agent_identities_all = OrchestratorClient.agent_identities_all

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def agent_identities(
        self, *, user: str | None = None, connector: str | None = None, cursor: str = "",
    ) -> dict[str, Any]:
        # Two pages; the second repeats _ROW, as when a new identity pushes it down between the reads.
        self.calls.append({"user": user, "connector": connector, "cursor": cursor})
        if cursor:
            return {"enabled": True, "persisted": True, "identities": [_ROW, _ROW2], "total": 2, "next_cursor": ""}
        return {"enabled": True, "persisted": True, "identities": [_ROW], "total": 2, "next_cursor": "1"}


@pytest.fixture()
def stub_client(monkeypatch: pytest.MonkeyPatch) -> _StubClient:
    client = _StubClient()
    monkeypatch.setattr(cmd_agent, "_usage_client", lambda *a, **k: client)
    return client


def test_identities_forwards_filters_and_renders_rows(stub_client: _StubClient) -> None:
    result = CliRunner().invoke(cli, ["agent", "identities", "--user", "alice", "--connector", "claudecode"])
    assert result.exit_code == 0, result.output
    assert stub_client.calls == [
        {"user": "alice", "connector": "claudecode", "cursor": ""},
        {"user": "alice", "connector": "claudecode", "cursor": "1"},
    ]
    assert "agt-0123456789abcdef" in result.output
    assert "agent claims /srv/other/.claude" in result.output

    # GAP-0152: every page is listed, each identity once.
    as_json = CliRunner().invoke(cli, ["agent", "identities", "--json"])
    assert as_json.exit_code == 0, as_json.output
    assert json.loads(as_json.output) == {"enabled": True, "identities": [_ROW, _ROW2], "total": 2, "next_cursor": ""}
