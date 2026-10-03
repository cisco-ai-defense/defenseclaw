# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-2514: a Claude Code url entry without "type" is flagged as not loaded."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from defenseclaw import connector_paths
from defenseclaw.config import MCPServerEntry

from tests.test_cmd_mcp import MCPCommandTestBase

URL = "https://mcp.example.invalid/mcp"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    return tmp_path


def test_claude_url_without_type_is_flagged_not_loaded(home):
    (home / ".claude.json").write_text(json.dumps({"mcpServers": {
        "deepwiki": {"url": URL},
        "typed": {"type": "http", "url": URL},
        "local": {"command": "uvx"},
    }}), encoding="utf-8")
    found = {s.name: s.load_problem for s in connector_paths.mcp_servers("claudecode")}
    assert found["deepwiki"].startswith('has a "url" but no "type" in ')
    assert found["typed"] == "" and found["local"] == ""
    # The repair (mcp set writes type) clears the flag.
    connector_paths.set_mcp_server("claudecode", "deepwiki", {"url": URL})
    found = {s.name: s.load_problem for s in connector_paths.mcp_servers("claudecode")}
    assert found["deepwiki"] == ""


class TestMcpNotLoaded(MCPCommandTestBase):
    def setUp(self):
        super().setUp()
        entry = MCPServerEntry(
            name="deepwiki", url=URL, transport="http",
            load_problem='has a "url" but no "type" in /h/.claude.json',
        )
        self.app.cfg.active_connectors = lambda: ["claudecode"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = lambda connector=None, **_: [entry]  # type: ignore[method-assign]
        self.app.cfg.mcp_source_locations = lambda connector=None, **_: ["/h/.claude.json"]  # type: ignore[method-assign]

    def test_list_marks_it_not_loaded_with_the_repair(self):
        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("not loaded", result.output)
        self.assertIn(
            f"defenseclaw mcp set deepwiki --url {URL} --connector claudecode",
            " ".join(result.output.split()),
        )
        items = json.loads(self.invoke(["list", "--json"]).output)
        self.assertEqual(items[0]["verdict"], "not loaded")

    def test_scan_all_skips_it(self):
        with patch("defenseclaw.commands.cmd_mcp._run_scan") as run_scan:
            result = self.invoke(["scan", "--all"])
        run_scan.assert_not_called()
        self.assertIn("NOT LOADED: deepwiki", result.output)
