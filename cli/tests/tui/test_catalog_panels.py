# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Catalog panel parity tests for Skills, MCPs, Plugins, and Tools."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest
from defenseclaw.config import AssetPolicyRule
from defenseclaw.tui.panels.mcps import MCPsPanelModel, mcp_actions, mcp_unset_target_for_connector
from defenseclaw.tui.panels.plugins import PluginsPanelModel, plugin_actions
from defenseclaw.tui.panels.skills import SkillRow, SkillsPanelModel, registry_attribution_from_rules, skill_actions
from defenseclaw.tui.panels.tools import ToolRow, ToolsPanelModel, split_tool_target, tool_actions
from defenseclaw.tui.services.catalog_state import parse_mcp_list_json, parse_plugin_list_json, skill_list_to_row


def action_keys(actions: tuple[object, ...]) -> list[str]:
    return [getattr(action, "key") for action in actions]


def assert_no_duplicate_keys(actions: tuple[object, ...]) -> None:
    keys = action_keys(actions)
    assert len(keys) == len(set(keys))


def test_skill_list_to_row_status_precedence_matches_go_oracle() -> None:
    cases = [
        ({"name": "a", "disabled": True, "eligible": True, "scan": {"max_severity": "CRITICAL"}}, "disabled"),
        ({"name": "a", "eligible": True, "actions": {"file": "quarantine", "install": "block"}}, "quarantined"),
        ({"name": "a", "eligible": True, "actions": {"install": "block"}}, "blocked"),
        ({"name": "a", "eligible": True, "actions": {"runtime": "disable"}}, "disabled"),
        ({"name": "a", "eligible": True, "actions": {"install": "allow"}}, "allowed"),
        (
            {
                "name": "a",
                "eligible": True,
                "scan": {"clean": False, "max_severity": "HIGH", "total_findings": 3},
            },
            "rejected",
        ),
        (
            {
                "name": "a",
                "eligible": True,
                "scan": {"clean": False, "max_severity": "CRITICAL", "total_findings": 1},
            },
            "rejected",
        ),
        (
            {
                "name": "a",
                "eligible": True,
                "scan": {"clean": False, "max_severity": "MEDIUM", "total_findings": 1},
            },
            "warning",
        ),
        (
            {
                "name": "a",
                "eligible": True,
                "scan": {"clean": False, "max_severity": "LOW", "total_findings": 1},
            },
            "warning",
        ),
        ({"name": "a", "eligible": True, "scan": {"clean": True, "max_severity": "CLEAN"}}, "active"),
        (
            {
                "name": "a",
                "eligible": True,
                "scan": {"clean": True, "max_severity": "CRITICAL", "total_findings": 0},
            },
            "active",
        ),
        ({"name": "a", "eligible": True}, "active"),
        ({"name": "a", "source": "scan-history"}, "removed"),
        ({"name": "a", "source": "enforcement"}, "removed"),
        ({"name": "a"}, "inactive"),
        ({"name": "a", "status": "blocked"}, "blocked"),
    ]

    for raw, want in cases:
        assert skill_list_to_row(raw).status == want


def test_skill_actions_and_intents_match_go_branches() -> None:
    assert action_keys(skill_actions("blocked")) == ["s", "i", "u", "a"]
    assert action_keys(skill_actions("allowed")) == ["s", "i", "b", "d"]
    assert action_keys(skill_actions("quarantined")) == ["s", "i", "r"]
    assert action_keys(skill_actions("disabled")) == ["s", "i", "e", "b"]
    assert action_keys(skill_actions("clean")) == ["s", "i", "b", "a", "d", "q", "n"]
    for status in ("blocked", "allowed", "quarantined", "disabled", "clean", ""):
        assert_no_duplicate_keys(skill_actions(status))

    panel = SkillsPanelModel()
    panel.apply_loaded([SkillRow(name="tutor", status="active")])

    assert panel.handle_key("b").intent.args == ("skill", "block", "tutor")
    assert panel.handle_key("a").intent.args == ("skill", "allow", "tutor")
    assert panel.handle_key("s").intent.args == ("skill", "scan", "tutor")
    assert panel.action_intent("n").args == ("skill", "install", "tutor")


def test_skills_filter_cursor_registry_and_click_selection() -> None:
    panel = SkillsPanelModel(connector="codex")
    panel.apply_loaded(
        [
            SkillRow(name="alpha", status="active", description="math helper", source="local"),
            SkillRow(name="beta", status="blocked", description="database", source="remote"),
            SkillRow(name="gamma", status="allowed", description="files", source="local"),
        ]
    )
    panel.set_cursor(2)
    panel.set_filter("database")

    assert panel.filtered_count() == 1
    assert panel.cursor_at() == 0
    assert panel.selected().name == "beta"

    panel.set_registry_attribution({"beta": "corp-skills"})
    assert panel.selected().registry_badge == "registry:corp-skills"
    focus = panel.handle_key("R").registry_focus
    assert focus.entry_type == "skill"
    assert focus.name == "beta"
    assert focus.source_id == "corp-skills"

    panel.clear_filter()
    assert panel.select_row(2).name == "gamma"
    assert panel.action_intent("a").args == ("skill", "allow", "gamma")


def test_registry_attribution_from_asset_policy_rules() -> None:
    rules = [
        AssetPolicyRule(name="tutor", reason="registry:corp-skills"),
        AssetPolicyRule(name="manual", reason="operator allow"),
        AssetPolicyRule(name="", reason="registry:ignored"),
    ]

    assert registry_attribution_from_rules(rules) == {"tutor": "corp-skills"}


def test_catalog_load_errors_are_renderable_state() -> None:
    panel = SkillsPanelModel()
    panel.apply_loaded([], RuntimeError("boom"))

    assert panel.loaded is False
    assert panel.message == "Error loading skills: boom"

    with pytest.raises(ValueError, match="parse skill list"):
        panel.apply_json("{not-json")


def test_mcp_parse_filter_actions_and_registry_focus() -> None:
    rows = parse_mcp_list_json(
        json.dumps(
            [
                {
                    "name": "context7",
                    "transport": "stdio",
                    "command": "uvx",
                    "url": "https://example.invalid/mcp",
                    "severity": "HIGH",
                    "actions": {"install": "allow"},
                    "verdict": "allowed",
                },
                {"name": "filesystem", "command": "node server.js", "actions": {"install": "block"}},
            ]
        )
    )
    assert rows[0].status == "allowed"
    assert rows[0].url == "context7"
    assert rows[0].server_url == "https://example.invalid/mcp"
    assert rows[1].status == "blocked"

    panel = MCPsPanelModel(connector="zeptoclaw")
    panel.apply_loaded(rows)
    panel.set_filter("server.js")
    assert panel.filtered_count() == 1
    assert panel.selected().name == "filesystem"
    panel.set_registry_attribution({"filesystem": "smithery-public"})
    assert panel.selected().registry_badge == "registry:smithery-public"
    assert panel.handle_key("R").registry_focus.name == "filesystem"

    assert panel.action_intent("x").args == ("mcp", "unset", "filesystem")
    assert panel.action_intent("i").args == ("mcp", "list")
    assert panel.handle_key("n").open_mcp_set_form is True
    assert panel.handle_key("+").open_mcp_set_form is True


def test_mcp_actions_name_connector_specific_unset_targets() -> None:
    cases = {
        "openclaw": "OpenClaw config",
        "claudecode": "~/.claude/settings.json",
        "codex": "./.mcp.json",
        "zeptoclaw": "~/.zeptoclaw/config.json",
        "hermes": "~/.hermes/config.yaml",
        "cursor": "./.cursor/mcp.json",
        "windsurf": "~/.codeium/windsurf/mcp_config.json",
        "geminicli": "~/.gemini/settings.json",
        "copilot": "./.github/mcp.json",
    }
    for connector, want in cases.items():
        assert mcp_unset_target_for_connector(connector) == want
        unset = next(action for action in mcp_actions("blocked", connector) if action.key == "x")
        assert want in unset.description

    zepto_unset = next(action for action in mcp_actions("blocked", "zeptoclaw") if action.key == "x")
    assert "read-only" in zepto_unset.description.lower()
    assert action_keys(mcp_actions("blocked", "openclaw")) == ["s", "i", "u", "x"]
    assert action_keys(mcp_actions("allowed", "openclaw")) == ["s", "i", "b", "x"]
    assert action_keys(mcp_actions("active", "openclaw")) == ["s", "i", "b", "a"]


def test_plugin_parse_connector_gate_actions_and_intents() -> None:
    rows = parse_plugin_list_json(
        json.dumps(
            [
                {
                    "id": "plug_tutor",
                    "name": "tutor",
                    "description": "teaches",
                    "version": "1.2.3",
                    "origin": "local",
                    "status": "installed",
                    "enabled": True,
                    "verdict": "clean",
                    "scan": {"clean": False, "max_severity": "MEDIUM", "total_findings": 2},
                }
            ]
        )
    )
    assert rows[0].display_name == "tutor"
    assert rows[0].scan.max_severity == "MEDIUM"

    panel = PluginsPanelModel(connector="codex")
    panel.apply_loaded(rows)
    assert panel.is_visible_for_connector() is False
    assert "Codex" in panel.openclaw_only_notice()

    assert panel.handle_key("s").intent.args == ("plugin", "scan", "plug_tutor")
    assert panel.action_intent("s").args == ("plugin", "scan", "tutor")
    assert panel.action_intent("u").args == ("plugin", "allow", "tutor")


def test_plugin_actions_state_matrix_matches_go() -> None:
    blocked_disabled = action_keys(plugin_actions("blocked", "installed", False))
    assert blocked_disabled == ["s", "i", "u", "e", "q", "x"]

    allowed_enabled = action_keys(plugin_actions("allowed", "installed", True))
    assert allowed_enabled == ["s", "i", "b", "d", "q", "x"]

    clean_enabled = action_keys(plugin_actions("clean", "installed", True))
    assert clean_enabled == ["s", "i", "b", "a", "d", "q", "x"]

    quarantined = action_keys(plugin_actions("blocked", "quarantined", False))
    assert "r" in quarantined
    assert "q" not in quarantined
    assert quarantined[-1] == "x"

    for args in (
        ("blocked", "installed", False),
        ("allowed", "installed", True),
        ("clean", "quarantined", True),
        ("warning", "installed", True),
    ):
        assert_no_duplicate_keys(plugin_actions(*args))


@dataclass
class FakeActions:
    install: str = ""


@dataclass
class FakeActionEntry:
    target_name: str
    actions: FakeActions
    reason: str = ""
    updated_at: datetime | str | None = None


class FakeToolStore:
    def __init__(self, entries: list[FakeActionEntry]) -> None:
        self.entries = entries

    def list_actions_by_type(self, target_type: str) -> list[FakeActionEntry]:
        assert target_type == "tool"
        return self.entries


def test_tools_refresh_scoped_display_counts_and_intents() -> None:
    panel = ToolsPanelModel(
        FakeToolStore(
            [
                FakeActionEntry(
                    "write_file@filesystem",
                    FakeActions("block"),
                    "PII leak risk",
                    datetime(2026, 4, 17, 10, 0, tzinfo=timezone.utc),
                ),
                FakeActionEntry("read_file", FakeActions("allow"), "vetted", "2026-04-18T11:12:13"),
            ]
        )
    )
    panel.refresh()

    assert panel.count() == 2
    assert panel.blocked_count() == 1
    assert panel.allowed_count() == 1
    assert panel.selected() == ToolRow(
        name="write_file",
        scope="filesystem",
        status="blocked",
        reason="PII leak risk",
        time="2026-04-17 10:00",
        target_name="write_file@filesystem",
    )
    assert panel.selected().display_scope == "filesystem"
    assert panel.action_intent("b").args == ("tool", "block", "write_file@filesystem")
    assert panel.action_intent("u").args == ("tool", "unblock", "write_file@filesystem")

    panel.select_row(1)
    assert panel.selected().display_scope == "(global)"
    assert panel.action_intent("i").args == ("tool", "status", "read_file")


def test_tools_cursor_bounds_empty_and_action_menu_rules() -> None:
    panel = ToolsPanelModel()
    panel.apply_loaded([ToolRow(name="a"), ToolRow(name="b"), ToolRow(name="c")])

    panel.cursor_down()
    panel.cursor_down()
    panel.cursor_down()
    assert panel.cursor_at() == 2
    panel.cursor_up()
    panel.cursor_up()
    panel.cursor_up()
    assert panel.cursor_at() == 0
    assert panel.handle_key("o").open_action_menu is True

    assert action_keys(tool_actions("blocked")) == ["i", "u", "a"]
    assert action_keys(tool_actions("allowed")) == ["i", "u", "b"]
    assert action_keys(tool_actions("unknown")) == ["i", "b", "a"]
    forbidden = {"s", "d", "e", "q", "r", "x"}
    for status in ("blocked", "allowed", "unknown"):
        assert forbidden.isdisjoint(action_keys(tool_actions(status)))

    empty = ToolsPanelModel()
    assert "No tools" in empty.empty_state()
    assert empty.action_intent("b") is None


def test_tools_split_accepts_go_scope_and_python_cli_scope_edge_case() -> None:
    assert split_tool_target("write_file@filesystem") == ("write_file", "filesystem")
    assert split_tool_target("filesystem/write_file") == ("write_file", "filesystem")
    assert split_tool_target("delete_file") == ("delete_file", "")
