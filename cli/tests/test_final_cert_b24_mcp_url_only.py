# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-2530/2531: url-only Claude Code entries the agent skips."""

from __future__ import annotations

import json

from defenseclaw import connector_paths
from defenseclaw.commands.cmd_mcp import _mcp_not_loaded_next_step
from defenseclaw.tui.app import _catalog_loaded_text
from defenseclaw.tui.services.catalog_state import MCPsPanelModel, catalog_detail_text

URL = "https://mcp.example.invalid/mcp"


def test_local_scope_repair_names_the_project_key(tmp_path, monkeypatch):
    """GAP-2530: the per-project entry lives under projects[<ws>] in ~/.claude.json."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    ws = tmp_path / "ws"
    ws.mkdir()
    (tmp_path / ".claude.json").write_text(json.dumps({
        "projects": {str(ws): {"mcpServers": {"locurl": {"url": URL}}}},
    }), encoding="utf-8")
    monkeypatch.chdir(ws)
    entry = next(
        s for s in connector_paths.mcp_servers("claudecode", infer_workspace_from_cwd=True)
        if s.name == "locurl"
    )
    hint = _mcp_not_loaded_next_step(entry, "claudecode")
    assert f'projects["{ws}"].mcpServers' in hint
    assert "mcp set" not in hint and '"type": "http"' in hint


def test_tui_marks_skipped_entries_not_loaded_with_the_repair():
    """GAP-2531: the MCPs panel no longer calls a skipped entry active/loaded."""
    model = MCPsPanelModel(connector="claudecode")
    model.apply_json(json.dumps([
        {"name": "okhttp", "url": URL, "transport": "http", "verdict": "-"},
        {
            "name": "emptytype", "url": URL, "transport": "http", "verdict": "not loaded",
            "not_loaded": 'has a "url" but no "type" in /h/.claude.json',
            "not_loaded_repair": "Claude Code skips it: Repair it with: defenseclaw mcp set emptytype",
        },
    ]))
    rows = {row.name: row for row in model.items}
    assert rows["okhttp"].status == "active"
    assert rows["emptytype"].status == "not loaded"
    detail = catalog_detail_text(rows["emptytype"])
    assert "Not loaded" in detail and "defenseclaw mcp set emptytype" in detail
    assert _catalog_loaded_text("mcps", model) == (
        "MCPs: 2 listed, 1 not loaded by the agent (see the row's detail)."
    )
