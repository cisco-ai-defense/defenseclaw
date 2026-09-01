# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
from pathlib import Path

from defenseclaw import connector_paths, platform_support
from defenseclaw.inventory import agent_discovery
from defenseclaw.tui.services.cli_choices import CONNECTORS
from defenseclaw.tui.services.overview_state import (
    connector_source_label,
    friendly_connector_name,
)


def _write_mcp(path: Path, name: str, command: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"mcpServers": {name: {"command": command}}}),
        encoding="utf-8",
    )


def test_devin_is_the_only_public_cognition_connector() -> None:
    assert "devin" in connector_paths.KNOWN_CONNECTORS
    assert "devin" in connector_paths.HOOK_ONLY_CONNECTORS
    assert "devin" in CONNECTORS
    assert "devin" in agent_discovery.DISCOVERY_PRECEDENCE
    assert "windsurf" not in connector_paths.KNOWN_CONNECTORS
    assert "windsurf" not in CONNECTORS
    assert "windsurf" not in agent_discovery.DISCOVERY_PRECEDENCE
    assert friendly_connector_name("devin") == "Devin"


def test_devin_config_root_is_platform_exact() -> None:
    assert connector_paths._resolve_devin_config_home(
        platform_name="nt",
        user_home=r"C:\Users\alice",
        roaming_app_data=r"C:\Users\alice\AppData\Roaming",
    ) == r"C:\Users\alice\AppData\Roaming\devin"
    assert connector_paths._resolve_devin_config_home(
        platform_name="posix",
        user_home="/Users/alice",
        roaming_app_data="",
    ) == "/Users/alice/.config/devin"


def test_devin_local_catalog_paths_match_the_documented_contract(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    config_root = home / ".config" / "devin"
    workspace = tmp_path / "project"
    monkeypatch.setattr("defenseclaw.connector_paths.Path.home", lambda: home)
    monkeypatch.setattr(connector_paths, "devin_config_home", lambda: str(config_root))

    assert connector_paths.connector_home("devin") == str(config_root)
    assert connector_paths.devin_hook_config_path(str(workspace)) == str(
        workspace / ".devin" / "hooks.v1.json"
    )
    assert connector_paths.skill_dirs("devin", workspace_dir=str(workspace)) == [
        str(config_root / "skills"),
        str(home / ".agents" / "skills"),
        str(workspace / ".devin" / "skills"),
        str(workspace / ".agents" / "skills"),
    ]
    assert connector_paths.skill_write_dirs("devin", workspace_dir=str(workspace)) == [
        str(workspace / ".devin" / "skills")
    ]
    assert connector_paths.agent_dirs("devin", workspace_dir=str(workspace)) == [
        str(config_root / "agents"),
        str(workspace / ".devin" / "agents"),
        str(workspace / ".agents" / "agents"),
    ]
    assert connector_paths.plugin_dirs("devin", workspace_dir=str(workspace)) == []


def test_devin_mcp_precedence_and_writes_never_mutate_legacy_config(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_root = tmp_path / "user-config"
    workspace = tmp_path / "project"
    monkeypatch.setattr(connector_paths, "devin_config_home", lambda: str(config_root))

    user = config_root / "mcp_config.json"
    project = workspace / ".devin" / "mcp_config.json"
    local = workspace / ".devin" / "mcp_config.local.json"
    legacy = workspace / ".devin" / "config.compat.json"
    _write_mcp(user, "shared", "user")
    _write_mcp(project, "shared", "project")
    _write_mcp(local, "shared", "local")
    _write_mcp(legacy, "legacy", "legacy")

    servers = {
        entry.name: entry
        for entry in connector_paths.mcp_servers("devin", workspace_dir=str(workspace))
    }
    assert servers["shared"].command == "local"
    assert servers["legacy"].command == "legacy"

    before_local = local.read_bytes()
    before_legacy = legacy.read_bytes()
    connector_paths.set_mcp_server(
        "devin",
        "added",
        {"command": "project-added"},
        workspace_dir=str(workspace),
    )
    assert json.loads(project.read_text(encoding="utf-8"))["mcpServers"]["added"]["command"] == "project-added"
    assert local.read_bytes() == before_local
    assert legacy.read_bytes() == before_legacy


def test_devin_rule_discovery_is_bounded_to_documented_sources(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_root = tmp_path / "user-config"
    workspace = tmp_path / "project"
    monkeypatch.setattr(connector_paths, "devin_config_home", lambda: str(config_root))

    expected = [
        config_root / "AGENTS.md",
        config_root / "AGENT.md",
        workspace / "AGENTS.local.md",
        workspace / "nested" / "agent.md",
        workspace / ".devin" / "global_rules.md",
        workspace / ".devin" / "rules" / "policy.md",
    ]
    for path in expected:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("rule", encoding="utf-8")
    excluded = workspace / ".agents" / "rules" / "invented.md"
    excluded.parent.mkdir(parents=True, exist_ok=True)
    excluded.write_text("not a Devin rule source", encoding="utf-8")

    discovered = set(connector_paths.devin_rule_files(str(workspace)))
    assert discovered == {os.path.abspath(path) for path in expected}
    assert os.path.abspath(excluded) not in discovered


def test_devin_platform_and_tui_claims_are_bounded() -> None:
    for os_name in ("windows", "darwin", "linux"):
        assert platform_support.connector_supported_on_os("devin", os_name)
    windows_reason = platform_support.connector_support_reason("devin", "windows")
    assert "3000.4.25" in windows_reason
    assert "native OTLP" in windows_reason
    assert "closed beta" in connector_source_label("devin", "plugins")
    assert ".devin/hooks.v1.json" in connector_source_label("devin", "config")
