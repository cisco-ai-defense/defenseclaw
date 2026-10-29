# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import json

import pytest
from defenseclaw import connector_paths
from defenseclaw.config import default_config
from defenseclaw.connector_contracts import opencode_requires_v2_upgrade, resolve_connector_contract
from defenseclaw.inventory.claw_inventory import (
    _agents_from_opencode,
    _commands_from_opencode_config,
    _opencode_config_plugin_rows,
)


@pytest.mark.parametrize(
    ("version", "contract"),
    [("2.0.0", "opencode-hooks-v2"), ("2.1.4", "opencode-hooks-v2"), ("2.2.0", "opencode-hooks-v2")],
)
def test_opencode_version_selects_its_own_api(version, contract):
    resolved = resolve_connector_contract("opencode", version)
    assert resolved.status == "known"
    assert resolved.contract.contract_id == contract


@pytest.mark.parametrize(
    "version", ["1.18.10", "1.18.33", "1.19.0", "3.0.0", "vgit.5bba024", "vgit.2fa91c0", "vgit.1a2b3c4"]
)
def test_opencode_only_v2_is_admitted(version):
    assert resolve_connector_contract("opencode", version).status == "unknown"
    assert opencode_requires_v2_upgrade(version)


def test_v2_native_inventory_and_mcp_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "dc"))
    for name in ("OPENCODE_CONFIG", "OPENCODE_CONFIG_DIR", "OPENCODE_CONFIG_CONTENT", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(name, raising=False)
    config = tmp_path / ".config/opencode/opencode.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps(
            {
                "plugins": ["company-audit", {"package": "./local-plugin", "options": {"enabled": True}}],
                "agents": {"review": {"description": "Review changes", "disabled": True}},
                "commands": {"review": {"description": "Run review", "template": "Review changes"}},
                "mcp": {
                    "timeout": {"execution": 1000},
                    "servers": {
                        "docs": {"type": "remote", "url": "https://example.test/mcp", "disabled": True},
                    },
                },
            }
        )
    )
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
    mcp = (
        {"timeout": {"execution": 1000}}
        if native
        else {
            "servers": {"type": "local", "command": ["echo", "servers"]},
            "timeout": {"type": "local", "command": ["echo", "timeout"]},
        }
    )
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


@pytest.fixture
def opencode_config_path(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "dc"))
    for name in ("OPENCODE_CONFIG", "OPENCODE_CONFIG_DIR", "OPENCODE_CONFIG_CONTENT", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(name, raising=False)
    path = tmp_path / ".config/opencode/opencode.json"
    path.parent.mkdir(parents=True)
    return path


def test_mcp_mixed_entries_are_visible_and_unset_cannot_resurface_a_direct_entry(opencode_config_path):
    opencode_config_path.write_text(
        json.dumps(
            {
                "mcp": {
                    "legacy": {"type": "local", "command": ["echo", "legacy"]},
                    "docs": {
                        "type": "remote",
                        "url": "https://old.example.test",
                        "headers": {"X-Fixture": "lower layer fixture"},
                    },
                    "timeout": {"execution": 1000},
                    "servers": {"docs": {"type": "remote", "url": "https://new.example.test"}},
                }
            }
        )
    )
    entries = {entry.name: entry for entry in connector_paths._opencode_mcp_servers()}
    assert set(entries) == {"docs", "legacy"}
    assert entries["docs"].url == "https://new.example.test"
    assert entries["docs"].headers == {}
    assert connector_paths._unset_opencode_mcp_server("legacy")
    assert connector_paths._unset_opencode_mcp_server("docs")
    assert connector_paths._opencode_mcp_servers() == []
    assert json.loads(opencode_config_path.read_text())["mcp"]["timeout"] == {"execution": 1000}


@pytest.mark.parametrize("native", [False, True])
def test_v2_replaces_whole_mcp_server_across_layers(opencode_config_path, tmp_path, native):
    opencode_config_path.write_text(
        json.dumps(
            {
                "mcp": {
                    "docs": {
                        "type": "remote",
                        "url": "https://global.example.test",
                        "headers": {"X-Fixture": "lower layer fixture"},
                    },
                    "local": {
                        "type": "local",
                        "command": ["global-tool"],
                        "environment": {"LOWER_LAYER_FIXTURE": "global value"},
                    },
                }
            }
        )
    )
    project = tmp_path / "project"
    project.mkdir()
    upper = {
        "docs": {"type": "remote", "url": "https://project.example.test"},
        "local": {"type": "local", "command": ["project-tool"]},
    }
    (project / "opencode.json").write_text(json.dumps({"mcp": {"servers": upper} if native else upper}))
    entries = {entry.name: entry for entry in connector_paths._opencode_mcp_servers(str(project))}
    assert entries["docs"].headers == {}
    assert entries["docs"].url == "https://project.example.test"
    assert entries["local"].env == {}
    assert entries["local"].command == "project-tool"
    assert entries["local"].source == str(project / "opencode.json")


def test_mcp_write_preserves_valid_and_malformed_native_members(opencode_config_path):
    original = {
        "timeout": {"execution": 1000},
        "servers": {
            "docs": {"type": "remote", "url": "https://example.test/mcp"},
            "malformed": "preserve this config value",
        },
    }
    opencode_config_path.write_text(json.dumps({"mcp": original}))
    connector_paths._set_opencode_mcp_server("added", {"command": "echo", "args": ["added"]})
    actual = json.loads(opencode_config_path.read_text())["mcp"]
    assert actual["servers"]["docs"] == original["servers"]["docs"]
    assert actual["servers"]["malformed"] == original["servers"]["malformed"]
    assert connector_paths._unset_opencode_mcp_server("added")
    assert json.loads(opencode_config_path.read_text())["mcp"] == original


@pytest.mark.parametrize(
    "directives", [["-acme.reviewer"], ["*", "-acme.*", "acme.reviewer"], ["opencode.provider.openai"]]
)
def test_plugin_controls_are_not_packages_and_activation_is_unverified(opencode_config_path, directives):
    from defenseclaw.commands.cmd_plugin import _plugin_list_json_items, _plugin_status_display

    opencode_config_path.write_text(json.dumps({"plugins": ["fixture-package", *directives]}))
    rows = _opencode_config_plugin_rows("")
    assert all(not row["id"].startswith(("-", "opencode.")) and row["id"] != "*" for row in rows)
    assert rows and all(row["status"] == "unverified" and not row["enabled"] for row in rows)
    assert all("unverified" in _plugin_status_display(row) for row in rows)
    payload = _plugin_list_json_items(rows, {}, {}, connector="opencode")
    assert all(row["status"] == "unverified" and row["activation_verified"] is False for row in payload)


@pytest.mark.parametrize("entry", ["local-helper", "cache", ".local-helper"])
def test_plugin_controls_also_mark_discovered_plugins_unverified(opencode_config_path, entry):
    from defenseclaw.inventory.claw_inventory import _enumerate_plugins_filesystem

    opencode_config_path.write_text(json.dumps({"plugins": ["-*"]}))
    plugin = opencode_config_path.parent / "plugins" / entry
    plugin.mkdir(parents=True)
    (plugin / "package.json").write_text(json.dumps({"name": "fixture-helper", "version": "0.0.0"}))
    (plugin / "index.js").write_text("export default { id: 'fixture.helper' }")
    rows = _enumerate_plugins_filesystem(default_config(), "opencode")
    assert len(rows) == 1 and rows[0]["path"] == str(plugin)
    assert rows[0]["status"] == "unverified" and rows[0]["enabled"] is False


def test_mcp_native_reserved_server_name_cannot_remove_the_container(opencode_config_path):
    original = {"timeout": {"execution": 1000}, "servers": {
        "docs": {"type": "remote", "url": "https://example.test/mcp"},
    }}
    opencode_config_path.write_text(json.dumps({"mcp": original}))
    connector_paths._set_opencode_mcp_server("servers", {"command": "echo"})
    assert connector_paths._unset_opencode_mcp_server("servers")
    assert json.loads(opencode_config_path.read_text())["mcp"] == original


def test_mcp_write_refuses_to_clobber_a_malformed_container(opencode_config_path):
    original = json.dumps({"mcp": {"servers": "unrelated malformed value", "timeout": {"execution": 1000}}})
    opencode_config_path.write_text(original)
    with pytest.raises(connector_paths.MCPWriteUnsupportedError, match="malformed OpenCode mcp.servers"):
        connector_paths._set_opencode_mcp_server("added", {"command": "echo"})
    assert opencode_config_path.read_text() == original
