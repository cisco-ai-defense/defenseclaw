# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert cli-mcp batch 25 (GAP-2553, GAP-2554)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from defenseclaw import connector_paths
from defenseclaw.connector_paths import set_mcp_server, unset_mcp_server
from defenseclaw.models import ScanResult

from tests.test_cmd_mcp import MCPCommandTestBase


def test_unset_of_a_changed_claude_entry_names_the_change(tmp_path, monkeypatch):
    # GAP-2553: only the entry's url changed (no Claude Code run); the message
    # must not blame a Claude Code rewrite.
    monkeypatch.setenv("HOME", str(tmp_path))
    # On Windows the conftest points CLAUDE_CONFIG_DIR under HOME; keep the
    # file at ~/.claude.json on every OS.
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
    settings = tmp_path / ".claude.json"
    set_mcp_server("claudecode", "r4chg", {"type": "http", "url": "https://mcp.example.invalid/mcp"})
    data = json.loads(settings.read_text(encoding="utf-8"))
    data["mcpServers"]["r4chg"]["url"] = "https://mcp.example.invalid/sse"
    settings.write_text(json.dumps(data, indent=2), encoding="utf-8")

    for _ in range(2):  # the repeat unset says so too
        with pytest.raises(connector_paths.MCPServerNotRemovedError) as exc:
            unset_mcp_server("claudecode", "r4chg")
        msg = str(exc.value)
        assert "the entry changed after DefenseClaw wrote it" in msg
        assert "rewrote the file" not in msg
        assert "remove it with: claude mcp remove r4chg -s user" in msg
    assert "r4chg" in json.loads(settings.read_text(encoding="utf-8"))["mcpServers"]


class TestFinalCertB25McpSet(MCPCommandTestBase):
    @patch("defenseclaw.commands.hint")
    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    @patch("defenseclaw.commands.cmd_mcp._run_scan")
    def test_scanned_set_does_not_ask_for_another_scan(self, mock_scan, _mock_set, mock_hint):
        # GAP-2554: set already scanned the server clean before adding it.
        self.app.cfg.active_connectors = lambda: ["claudecode"]  # type: ignore[method-assign]
        mock_scan.return_value = ScanResult(
            scanner="mcp-scanner",
            target="https://mcp.example.invalid/mcp",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )
        result = self.invoke(
            ["set", "r4wiki", "--url", "https://mcp.example.invalid/mcp", "--connector", "claudecode"]
        )
        self.assertEqual(result.exit_code, 0, result.output)
        mock_scan.assert_called_once()
        self.assertIn("[mcp] Added 'r4wiki' (claudecode).", result.output)
        mock_hint.assert_not_called()
