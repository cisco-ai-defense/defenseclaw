# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert Claude Code MCP unset batch 35 (GAP-2570)."""

from __future__ import annotations

import json

import pytest
from defenseclaw import connector_paths
from defenseclaw.connector_paths import set_mcp_server, unset_mcp_server


def test_unset_of_a_changed_entry_beside_a_managed_one_is_not_reported_removed(tmp_path, monkeypatch):
    # GAP-2570: another DefenseClaw-written entry is still managed, so the
    # last-entry path that raises was skipped and the unset returned "removed".
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
    settings = tmp_path / ".claude.json"
    set_mcp_server("claudecode", "b35keep", {"type": "http", "url": "https://mcp.example.invalid/mcp"})
    set_mcp_server("claudecode", "b35multi", {"type": "http", "url": "https://mcp.example.invalid/mcp"})
    data = json.loads(settings.read_text(encoding="utf-8"))
    data["mcpServers"]["b35multi"]["url"] = "https://mcp.example.invalid/sse"
    settings.write_text(json.dumps(data, indent=2), encoding="utf-8")

    for _ in range(2):  # the repeat unset says so too
        with pytest.raises(connector_paths.MCPServerNotRemovedError) as exc:
            unset_mcp_server("claudecode", "b35multi")
        msg = str(exc.value)
        assert "the entry changed after DefenseClaw wrote it" in msg
        assert "remove it with: claude mcp remove b35multi -s user" in msg
    servers = json.loads(settings.read_text(encoding="utf-8"))["mcpServers"]
    assert servers["b35multi"]["url"] == "https://mcp.example.invalid/sse"

    # The entry DefenseClaw still owns is removed as before.
    unset_mcp_server("claudecode", "b35keep")
    servers = json.loads(settings.read_text(encoding="utf-8"))["mcpServers"]
    assert "b35keep" not in servers
    assert "b35multi" in servers
