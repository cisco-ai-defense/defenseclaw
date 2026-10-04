"""GAP-2625 / GAP-2627: MCP inventory readers must not invent or fail on
harmless agent config files."""

from __future__ import annotations

import json

from defenseclaw import connector_paths


def test_devin_config_json_without_mcp_servers_lists_no_servers(tmp_path, monkeypatch):
    config_root = tmp_path / "devin"
    config_root.mkdir()
    monkeypatch.setattr(connector_paths, "devin_config_home", lambda: str(config_root))
    monkeypatch.setattr(
        connector_paths, "devin_user_config_path", lambda: str(config_root / "config.json")
    )
    (config_root / "config.json").write_text(
        json.dumps(
            {
                "hooks": {"PreToolUse": [{"command": "defenseclaw hook"}]},
                "shell": {"path": "/bin/bash"},
                "theme_mode": "dark",
                "version": 1,
            }
        ),
        encoding="utf-8",
    )
    (config_root / "mcp_config.json").write_text('{"mcpServers": {}}', encoding="utf-8")

    sink: list = []
    assert connector_paths._devin_mcp_servers(diagnostic_sink=sink) == []
    assert sink == []


def test_devin_mcp_config_top_level_mapping_still_reads(tmp_path, monkeypatch):
    config_root = tmp_path / "devin"
    config_root.mkdir()
    monkeypatch.setattr(connector_paths, "devin_config_home", lambda: str(config_root))
    monkeypatch.setattr(
        connector_paths, "devin_user_config_path", lambda: str(config_root / "config.json")
    )
    (config_root / "mcp_config.json").write_text(
        json.dumps({"docs": {"command": "docs-mcp"}}), encoding="utf-8"
    )

    entries = connector_paths._devin_mcp_servers()
    assert [(e.name, e.command) for e in entries] == [("docs", "docs-mcp")]


def test_antigravity_empty_mcp_config_is_no_servers_not_malformed(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    cfg = tmp_path / ".gemini" / "config" / "mcp_config.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_bytes(b"")

    sink: list = []
    assert connector_paths._antigravity_mcp_servers(diagnostic_sink=sink) == []
    assert sink == []

    cfg.write_text("{not json", encoding="utf-8")
    assert connector_paths._antigravity_mcp_servers(diagnostic_sink=sink) == []
    assert [d.problem for d in sink] == ["malformed"]
