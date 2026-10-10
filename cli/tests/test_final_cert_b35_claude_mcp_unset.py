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
    # On Windows the conftest points CLAUDE_CONFIG_DIR under HOME; keep the
    # file at ~/.claude.json on every OS.
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
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
def test_set_moves_a_0_8_settings_json_entry_and_unset_clears_every_copy(tmp_path, monkeypatch, capsys):
    # GAP-1340: 0.8.x wrote `mcp set` entries into ~/.claude/settings.json. The
    # printed fix (mcp set --connector claudecode) wrote ~/.claude.json but left
    # that copy, which list and doctor kept reading, and unset left it too.
    import os
    from types import SimpleNamespace

    from defenseclaw.commands import cmd_doctor

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({
        "env": {"OTEL_EXPORTER_OTLP_HEADERS": "b35-secret-value"},
        "hooks": {"PreToolUse": []},
        "mcpServers": {"u33a-mcp": {"command": "/usr/bin/true"}, "keep": {"command": "npx", "args": ["k"]}},
    }), encoding="utf-8")
    state = tmp_path / ".claude.json"
    state.write_text(json.dumps({"numStartups": 3}), encoding="utf-8")
    for path in (settings, state):
        os.chmod(path, 0o600)

    cfg = SimpleNamespace(
        active_connectors=lambda: ["claudecode"],
        mcp_servers=connector_paths.mcp_servers,
        gateway=SimpleNamespace(watcher=SimpleNamespace(mcp=SimpleNamespace(take_action=True))),
    )
    record = {"unscannable_mcp": [{"name": "u33a-mcp", "connector": "claudecode", "command": "/usr/bin/true"}]}

    def doctor_warnings():
        result = cmd_doctor._DoctorResult()
        cmd_doctor._check_unscannable_mcp(cfg, record, result)
        return [c["label"] for c in result.checks if c["status"] == "warn"]

    assert doctor_warnings() == ["MCP server u33a-mcp (claudecode)"]

    set_mcp_server("claudecode", "u33a-mcp", {"command": "npx", "args": ["-y", "pkg"]})
    legacy = json.loads(settings.read_text(encoding="utf-8"))
    assert legacy["mcpServers"] == {"keep": {"command": "npx", "args": ["k"]}}
    assert legacy["hooks"] == {"PreToolUse": []} and "env" in legacy
    written = json.loads(state.read_text(encoding="utf-8"))
    assert written["numStartups"] == 3
    assert written["mcpServers"]["u33a-mcp"]["command"] == "npx"
    if os.name != "nt":
        assert oct(os.stat(state).st_mode & 0o777) == oct(0o600)
        assert oct(os.stat(settings).st_mode & 0o777) == oct(0o600)
    assert doctor_warnings() == []

    # A stale copy in both files counts once and follows Claude Code's file.
    legacy["mcpServers"]["u33a-mcp"] = {"command": "/usr/bin/true"}
    settings.write_text(json.dumps(legacy), encoding="utf-8")
    named = [e for e in connector_paths.mcp_servers("claudecode") if e.name == "u33a-mcp"]
    assert [(e.command, e.source_scope) for e in named] == [("npx", "")]
    assert doctor_warnings() == []

    unset_mcp_server("claudecode", "u33a-mcp")
    assert "u33a-mcp" not in json.loads(settings.read_text(encoding="utf-8"))["mcpServers"]
    assert "u33a-mcp" not in json.loads(state.read_text(encoding="utf-8")).get("mcpServers", {})
    assert "b35-secret-value" not in capsys.readouterr().err
