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
    # F-0521: action-menu intents must target the stable plugin id, not the
    # spoofable display name (which previously let actions hit the wrong row).
    assert panel.action_intent("s").args == ("plugin", "scan", "plug_tutor")
    assert panel.action_intent("u").args == ("plugin", "allow", "plug_tutor")


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


# ---------------------------------------------------------------------------
# Detail pane parity tests for Skills / MCP / Plugins / Tools.
#
# The detail pane is the primary surface operators use to understand
# "why is this row in this state and what can I do about it", so these
# tests lock in the structured sections (Status, Decisions, Scan,
# Source, Registry, Actions legend). Snapshot-style assertions on the
# specific labels protect against silent reflows that would force
# operators to relearn the layout.
# ---------------------------------------------------------------------------


def test_skill_list_to_row_preserves_scan_and_decision_details() -> None:
    """``skill list --json`` carries scan + action sub-objects that the
    detail pane needs. The row parser must denormalize them so the
    detail renderer doesn't have to re-parse the original JSON.
    """

    row = skill_list_to_row(
        {
            "name": "alpha",
            "description": "math helper",
            "source": "/skills/alpha",
            "eligible": True,
            "scan": {
                "clean": False,
                "max_severity": "HIGH",
                "total_findings": 3,
                "target": "/skills/alpha/SKILL.md",
            },
            "actions": {"install": "allow", "runtime": "disable"},
        }
    )

    assert row.total_findings == 3
    assert row.scan_clean is False
    assert row.scan_target == "/skills/alpha/SKILL.md"
    assert row.install_action == "allow"
    assert row.runtime_action == "disable"
    assert row.file_action == ""


def test_skill_detail_pane_renders_decisions_scan_and_action_legend() -> None:
    """Skills detail pane shows Status / Decisions / Scan / Source /
    Registry / a one-line action legend. The legend replaces the
    legacy ``press o for actions`` mystery with the actual keys.
    """

    from defenseclaw.tui.services.catalog_state import catalog_detail_text

    row = SkillRow(
        name="alpha",
        status="blocked",
        actions="blocked, quarantined",
        description="math helper",
        source="/skills/alpha",
        severity="HIGH",
        registry_source="corp-skills",
        total_findings=3,
        scan_clean=False,
        scan_target="/skills/alpha/SKILL.md",
        install_action="block",
        runtime_action="disable",
        file_action="quarantine",
    )
    out = catalog_detail_text(row)

    assert "[bold #22D3EE]Skill[/] alpha" in out
    assert "Status     [#F87171]blocked[/]" in out
    assert "install=block" in out and "runtime=disable" in out and "file=quarantine" in out
    assert "Scan       [#F87171]HIGH[/] · 3 findings · target=/skills/alpha/SKILL.md" in out
    assert "Source     /skills/alpha" in out
    assert "Registry   registry:corp-skills" in out
    # The legend should surface the actual shortcut keys, not a vague
    # "press o for menu" hint. Blocked status exposes Unblock so the
    # operator can recover without spelunking through the action menu.
    assert "[s] Scan" in out and "[i] Info" in out
    assert "[u] Unblock" in out


def test_skill_detail_pane_handles_clean_row_without_findings_bloat() -> None:
    """A clean row should NOT show ``0 findings`` (visually noisy).

    Operators reading the detail pane should see ``Scan  CLEAN`` and
    move on; the finding count only appears when something is wrong.
    """

    from defenseclaw.tui.services.catalog_state import catalog_detail_text

    row = SkillRow(name="alpha", status="active")
    out = catalog_detail_text(row)

    assert "Scan       [#34D399]CLEAN[/]" in out
    assert "findings" not in out


def test_mcp_detail_pane_renders_transport_url_and_command() -> None:
    from defenseclaw.tui.panels.mcps import MCPRow
    from defenseclaw.tui.services.catalog_state import catalog_detail_text

    row = MCPRow(
        name="context7",
        status="allowed",
        actions="allowed",
        transport="stdio",
        command="uvx mcp-server-context7",
        server_url="https://example.invalid/mcp",
        install_action="allow",
    )
    out = catalog_detail_text(row)

    assert "[bold #22D3EE]MCP[/] context7" in out
    assert "Status     [#34D399]allowed[/]" in out
    assert "Transport  stdio" in out
    assert "URL        https://example.invalid/mcp" in out
    assert "Command    uvx mcp-server-context7" in out
    # MCP legend should expose the unset-target hint via mcp_actions
    # under the action key list.
    assert "[s] Scan" in out and "[i] Info" in out


def test_plugin_detail_pane_renders_scan_summary_and_runtime_state() -> None:
    from defenseclaw.tui.services.catalog_state import (
        PluginRow,
        PluginScanSummary,
        catalog_detail_text,
    )

    row = PluginRow(
        id="hello-world",
        name="hello-world",
        description="example",
        version="1.2.0",
        origin="builtin",
        status="installed",
        enabled=True,
        scan=PluginScanSummary(clean=False, max_severity="MEDIUM", total_findings=2),
    )
    out = catalog_detail_text(row)

    assert "[bold #22D3EE]Plugin[/] hello-world" in out
    assert "Version    1.2.0" in out
    assert "Origin     builtin" in out
    assert "Scan       [#FBBF24]MEDIUM[/] · 2 findings" in out
    # Enabled plugin should expose the Disable action shortcut.
    assert "[d] Disable" in out


def test_catalog_summary_text_splits_navigation_and_action_keys() -> None:
    """The header now groups navigation and action keys on separate
    lines so operators see the action set (including the previously
    hidden ``o open menu``) without scanning a single dense line.
    """

    panel = SkillsPanelModel()
    panel.apply_loaded([SkillRow(name="alpha", status="active")])

    text = panel.summary_text("Skills")
    # Action set is on its own line so it can't be missed.
    assert "[dim]Actions:[/]" in text
    assert "o open menu" in text
    # Navigation primer is on the row above, not jammed in with actions.
    assert "[dim]Navigate:[/]" in text
    # Filter / detail metadata still on line 2.
    assert "1 of 1 rows" in text


# ---------------------------------------------------------------------------
# WU13: multi-connector focus — list command targets the focused connector
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "model_factory, base_args",
    [
        (lambda: SkillsPanelModel(connector="codex"), ("skill", "list", "--json")),
        (lambda: MCPsPanelModel(connector="codex"), ("mcp", "list", "--json")),
        (lambda: PluginsPanelModel(connector="codex"), ("plugin", "list", "--json")),
    ],
)
def test_catalog_load_intent_appends_connector_when_focus_enabled(model_factory, base_args) -> None:
    model = model_factory()

    # Default (single-connector / no focus): no --connector flag, so the
    # CLI lists the active connector exactly as before.
    assert model.load_intent().args == base_args

    # Multi-connector focus: the app sets connector_focus_enabled, so the
    # list command targets the focused connector explicitly.
    model.connector_focus_enabled = True
    assert model.load_intent().args == (*base_args, "--connector", "codex")


def test_catalog_focus_args_empty_without_connector() -> None:
    model = SkillsPanelModel(connector="")
    model.connector_focus_enabled = True
    # No connector name ⇒ no flag even when focus is enabled.
    assert model.load_intent().args == ("skill", "list", "--json")


def test_skill_mutation_intents_thread_focus_only_for_connector_aware_verbs() -> None:
    # E2: scan/info/install accept --connector; block/allow hit the global
    # enforcement store and must NOT carry --connector.
    model = SkillsPanelModel(connector="codex")
    model.apply_loaded([SkillRow(name="alpha", status="")])
    model.connector_focus_enabled = True

    assert model.action_intent("s").args == ("skill", "scan", "alpha", "--connector", "codex")
    assert model.action_intent("i").args == ("skill", "info", "alpha", "--connector", "codex")
    assert model.action_intent("n").args == ("skill", "install", "alpha", "--connector", "codex")
    # Enforcement verbs stay connector-agnostic.
    assert model.action_intent("b").args == ("skill", "block", "alpha")
    assert model.action_intent("a").args == ("skill", "allow", "alpha")


def test_mcp_and_plugin_mutation_intents_thread_focus() -> None:
    from defenseclaw.tui.panels.mcps import MCPRow
    from defenseclaw.tui.panels.plugins import PluginRow

    mcp = MCPsPanelModel(connector="codex")
    mcp.apply_loaded([MCPRow(name="srv", status="")])
    mcp.connector_focus_enabled = True
    assert mcp.action_intent("s").args == ("mcp", "scan", "srv", "--connector", "codex")
    assert mcp.action_intent("x").args == ("mcp", "unset", "srv", "--connector", "codex")
    assert mcp.action_intent("b").args == ("mcp", "block", "srv")

    plugin = PluginsPanelModel(connector="codex")
    plugin.apply_loaded([PluginRow(id="pg", name="pg")])
    plugin.connector_focus_enabled = True
    assert plugin.action_intent("s").args == ("plugin", "scan", "pg", "--connector", "codex")
    assert plugin.action_intent("i").args == ("plugin", "info", "pg", "--connector", "codex")
    assert plugin.action_intent("b").args == ("plugin", "block", "pg")
    # Direct-scan ('s' in handle_key) also follows focus.
    assert plugin.handle_key("s").intent.args == ("plugin", "scan", "pg", "--connector", "codex")


def test_catalog_apply_merged_tags_connector_and_adds_column() -> None:
    """8.13 pass 2: merging connectors tags each row with its origin and
    prepends a CONNECTOR column to the rendered table."""

    model = SkillsPanelModel(connector="codex")
    model.show_connector_column = True
    codex = json.dumps([{"name": "alpha", "status": "active"}])
    cursor = json.dumps([{"name": "beta", "status": "active"}])
    model.apply_merged([("codex", codex), ("cursor", cursor)])

    assert model.data_table_columns()[0] == "Connector"
    rows = model.data_table_rows()
    assert [row[0] for row in rows] == ["codex", "cursor"]
    assert [row[1] for row in rows] == ["alpha", "beta"]


def test_catalog_merged_connector_filter_narrows_rows_in_memory() -> None:
    model = MCPsPanelModel(connector="codex")
    model.show_connector_column = True
    codex = json.dumps([{"name": "srv-a"}])
    cursor = json.dumps([{"name": "srv-b"}])
    model.apply_merged([("codex", codex), ("cursor", cursor)])

    model.set_connector_filter("cursor")
    rows = model.data_table_rows()
    assert [row[0] for row in rows] == ["cursor"]
    assert [row[1] for row in rows] == ["srv-b"]

    # Clearing the filter restores the merged rows (no reload required).
    model.set_connector_filter("")
    assert [row[1] for row in model.data_table_rows()] == ["srv-a", "srv-b"]


def test_catalog_single_connector_keeps_original_columns() -> None:
    model = SkillsPanelModel(connector="codex")
    model.apply_json(json.dumps([{"name": "alpha", "status": "active"}]))
    assert "Connector" not in model.data_table_columns()
    assert model.data_table_columns() == ("Name", "Status", "Source", "Actions", "Details")


@pytest.mark.parametrize(
    "model_factory, base_args",
    [
        (lambda: SkillsPanelModel(connector="codex"), ("skill", "list", "--json")),
        (lambda: MCPsPanelModel(connector="codex"), ("mcp", "list", "--json")),
        (lambda: PluginsPanelModel(connector="codex"), ("plugin", "list", "--json")),
    ],
)
def test_catalog_load_intent_for_targets_connector_and_restores(model_factory, base_args) -> None:
    model = model_factory()
    intent = model.load_intent_for("cursor")
    assert intent.args == (*base_args, "--connector", "cursor")
    # Prior single-connector state is untouched.
    assert model.connector == "codex"
    assert model.connector_focus_enabled is False
