# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import json

import pytest
from defenseclaw import connector_paths
from defenseclaw.config import default_config
from defenseclaw.connector_contracts import resolve_connector_contract
from defenseclaw.inventory.claw_inventory import (
    _agents_from_opencode,
    _commands_from_opencode_config,
    _opencode_config_plugin_rows,
)


@pytest.mark.parametrize(
    ("version", "contract"),
    [("2.0.0", "opencode-hooks-v2"), ("2.1.4", "opencode-hooks-v2"),
     ("2.2.0", "opencode-hooks-v2")],
)
def test_opencode_version_selects_its_own_api(version, contract):
    resolved = resolve_connector_contract("opencode", version)
    assert resolved.status == "known"
    assert resolved.contract.contract_id == contract


@pytest.mark.parametrize("version", ["1.18.10", "1.18.33", "1.19.0", "3.0.0", "vgit.5bba024"])
def test_opencode_only_v2_is_admitted(version):
    assert resolve_connector_contract("opencode", version).status == "unknown"


def test_v2_native_inventory_and_mcp_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "dc"))
    for name in ("OPENCODE_CONFIG", "OPENCODE_CONFIG_DIR", "OPENCODE_CONFIG_CONTENT", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(name, raising=False)
    config = tmp_path / ".config/opencode/opencode.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({
        "plugins": ["company-audit", {"package": "./local-plugin", "options": {"enabled": True}}],
        "agents": {"review": {"description": "Review changes", "disabled": True}},
        "commands": {"review": {"description": "Run review", "template": "Review changes"}},
        "mcp": {"timeout": {"execution": 1000}, "servers": {
            "docs": {"type": "remote", "url": "https://example.test/mcp", "disabled": True},
        }},
    }))
    entries = connector_paths._opencode_mcp_servers(infer_from_cwd=False)
    assert [(entry.name, entry.disabled, entry.url) for entry in entries] == [
        ("docs", True, "https://example.test/mcp"),
    ]
    rows = _opencode_config_plugin_rows("")
    assert {row["id"] for row in rows} == {"company-audit", "./local-plugin"}
    agents = _agents_from_opencode(default_config())
    assert [(agent["id"], agent["enabled"]) for agent in agents] == [("review", False)]
    commands = _commands_from_opencode_config(json.loads(config.read_text()), str(config))
    assert [command["id"] for command in commands] == ["review"]
    connector_paths._set_opencode_mcp_server("local", {"command": "echo", "args": ["ok"]})
    data = json.loads(config.read_text())
    assert data["mcp"]["servers"]["local"]["command"] == ["echo", "ok"]
    assert data["mcp"]["servers"]["local"]["disabled"] is False
    assert "local" not in data["mcp"]
    assert connector_paths._unset_opencode_mcp_server("local")
    data = json.loads(config.read_text())
    assert "local" not in data["mcp"]["servers"]
    assert data["mcp"]["timeout"] == {"execution": 1000}
    assert data["mcp"]["servers"]["docs"]["disabled"] is True


@pytest.mark.parametrize("native", [True, False])
def test_mcp_optional_servers_and_legacy_reserved_names(tmp_path, monkeypatch, native):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "dc"))
    for name in ("OPENCODE_CONFIG", "OPENCODE_CONFIG_DIR", "OPENCODE_CONFIG_CONTENT", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(name, raising=False)
    config = tmp_path / ".config/opencode/opencode.json"
    config.parent.mkdir(parents=True)
    mcp = {"timeout": {"execution": 1000}} if native else {
        "servers": {"type": "local", "command": ["echo", "servers"]},
        "timeout": {"type": "local", "command": ["echo", "timeout"]},
    }
    config.write_text(json.dumps({"mcp": mcp}))
    entries = connector_paths._opencode_mcp_servers(infer_from_cwd=False)
    assert {entry.name for entry in entries} == (set() if native else {"servers", "timeout"})
    connector_paths._set_opencode_mcp_server("local", {"command": "echo", "args": ["ok"]})
    actual = json.loads(config.read_text())["mcp"]
    assert actual["timeout"] == mcp["timeout"]
    assert "local" in (actual["servers"] if native else actual)
    assert connector_paths._unset_opencode_mcp_server("local")
    remaining = json.loads(config.read_text())["mcp"]
    assert remaining == ({**mcp, "servers": {}} if native else mcp)
