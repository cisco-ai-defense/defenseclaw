# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Inventory panel parity tests."""

from __future__ import annotations

import json

import pytest
from defenseclaw.tui.panels.inventory import (
    FAST_SCAN_CATEGORIES,
    INVENTORY_CATEGORIES,
    InventoryPanelModel,
    InventorySnapshot,
)


def _inventory_payload() -> dict[str, object]:
    return {
        "version": 1,
        "generated_at": "2026-05-20T12:00:00Z",
        "openclaw_config": "~/.openclaw/openclaw.json",
        "claw_home": "~/.openclaw",
        "claw_mode": "codex",
        "connector": "codex",
        "connector_home": "~/.codex",
        "connector_config_files": ["~/.codex/config.toml"],
        "skills": [
            {
                "id": "alpha",
                "source": "local",
                "eligible": True,
                "enabled": True,
                "description": "math helper",
                "policy_verdict": "allowed",
                "scan_findings": 0,
            },
            {
                "id": "beta",
                "source": "registry",
                "eligible": False,
                "enabled": False,
                "policy_verdict": "blocked",
                "policy_detail": "operator block",
                "scan_findings": 2,
                "scan_severity": "HIGH",
            },
            {
                "id": "gamma",
                "source": "local",
                "eligible": True,
                "policy_verdict": "warning",
                "scan_findings": 1,
                "scan_severity": "MEDIUM",
            },
        ],
        "plugins": [
            {
                "id": "plug_a",
                "name": "Tutor",
                "version": "1.0.0",
                "origin": "local",
                "enabled": True,
                "status": "loaded",
                "policy_verdict": "clean",
            },
            {
                "id": "plug_b",
                "name": "Risky",
                "origin": "remote",
                "enabled": False,
                "status": "disabled",
                "policy_verdict": "blocked",
            },
        ],
        "mcp": [{"id": "context7", "source": "codex", "transport": "stdio", "command": "uvx context7"}],
        "agents": [{"id": "default", "model": "gpt-5", "source": "codex", "is_default": True}],
        "model_providers": [{"id": "openai", "source": "config", "default_model": "gpt-5", "status": "ready"}],
        "memory": [
            {
                "id": "mem",
                "backend": "sqlite",
                "files": 2,
                "chunks": 9,
                "provider": "local",
                "sources": ["notes.md"],
                "workspace": "/tmp/ws",
                "fts_available": True,
                "vector_enabled": False,
            }
        ],
        "summary": {
            "total_items": 10,
            "skills": {"count": 3, "eligible": 2},
            "plugins": {"count": 2, "loaded": 1, "disabled": 1},
            "mcp": {"count": 1},
            "agents": {"count": 1},
            "model_providers": {"count": 1},
            "memory": {"count": 1},
            "policy_skills": {"blocked": 1, "allowed": 1, "warning": 1},
            "policy_plugins": {"blocked": 1, "clean": 1},
            "scan_skills": {"scanned": 2, "unscanned": 1, "total_findings": 3},
            "scan_plugins": {"scanned": 1, "unscanned": 1, "total_findings": 0},
        },
    }


def _inventory() -> InventorySnapshot:
    return InventorySnapshot.from_mapping(_inventory_payload())


def test_inventory_load_args_scope_and_only_flag_format() -> None:
    panel = InventoryPanelModel()
    assert panel.load_args() == ("aibom", "scan", "--json")

    panel.set_category_scope(["skills", "plugins"])
    assert panel.load_args() == ("aibom", "scan", "--json", "--only", "skills,plugins")
    assert " " not in panel.load_args()[-1]

    panel.set_category_scope(None)
    assert panel.load_args() == ("aibom", "scan", "--json")
    panel.set_category_scope([])
    assert panel.load_args() == ("aibom", "scan", "--json")


def test_inventory_load_args_follows_focused_connector() -> None:
    # E1: when a connector is focused (multi-connector), Inventory passes
    # --connector so it inventories that connector, not the primary.
    panel = InventoryPanelModel()
    panel.set_connector("codex")
    # Focus off ⇒ no --connector (single-connector behaviour unchanged).
    assert panel.load_args() == ("aibom", "scan", "--json")

    panel.connector_focus_enabled = True
    assert panel.load_args() == ("aibom", "scan", "--json", "--connector", "codex")


def test_inventory_category_scope_filters_unknown_and_toggles() -> None:
    panel = InventoryPanelModel()
    panel.set_category_scope(["skills", "bogus", "plugins"])
    assert panel.category_scope == ("skills", "plugins")

    panel.set_category_scope(["nothing", "real", "here"])
    assert panel.category_scope == ()

    panel.toggle_category("skills")
    panel.toggle_category("plugins")
    assert panel.category_scope == ("skills", "plugins")
    panel.toggle_category("skills")
    assert panel.category_scope == ("plugins",)
    panel.toggle_category("plugins")
    assert panel.category_scope == ()
    panel.toggle_category("bogus")
    assert panel.category_scope == ()


def test_inventory_fast_scan_preset_stability_and_order_independent_check() -> None:
    panel = InventoryPanelModel()
    panel.toggle_fast_scan()
    assert panel.category_scope == FAST_SCAN_CATEGORIES
    assert panel.is_fast_scan() is True

    panel.toggle_fast_scan()
    assert panel.category_scope == ()

    panel.set_category_scope(["agents", "models"])
    panel.toggle_fast_scan()
    assert panel.category_scope == FAST_SCAN_CATEGORIES

    panel.set_category_scope(["mcp", "skills", "plugins"])
    assert panel.is_fast_scan() is True
    assert INVENTORY_CATEGORIES == ("skills", "plugins", "mcp", "agents", "tools", "models", "memory")


def test_inventory_apply_json_summary_source_and_load_errors() -> None:
    panel = InventoryPanelModel(connector="openclaw")
    panel.apply_json(json.dumps(_inventory_payload()))
    assert panel.loaded is True
    summary = panel.summary_state()
    assert summary is not None
    assert summary.source_label == "Codex"
    assert summary.home_path == "~/.codex"
    assert summary.config_path == "~/.codex/config.toml"
    assert summary.counts["skills"] == "3"
    assert summary.policy_skill_verdicts["blocked"] == "1"
    assert summary.version == "1"
    assert summary.generated_at == "2026-05-20T12:00:00Z"
    assert summary.scan_skill_coverage["total_findings"] == "3"

    error_panel = InventoryPanelModel()
    error_panel.apply_loaded(None, RuntimeError("boom"))
    assert error_panel.loaded is False
    assert error_panel.message == "Error loading inventory: boom"

    with pytest.raises(ValueError, match="parse inventory json"):
        InventorySnapshot.from_json("{not-json")


def test_inventory_skill_and_plugin_filters_clamp_cursor_and_detail() -> None:
    panel = InventoryPanelModel()
    panel.apply_loaded(_inventory())

    panel.set_active_subtab("skills")
    panel.set_cursor(2)
    panel.set_filter("blocked")
    assert [skill.id for skill in panel.filtered_skills()] == ["beta"]
    assert panel.cursor_at() == 0
    detail = panel.detail_info()
    assert detail is not None
    assert detail.title == "SKILL: beta"
    assert ("Verdict", "blocked") in detail.fields
    assert ("Scan Severity", "HIGH") in detail.fields

    panel.set_active_subtab("plugins")
    panel.set_filter("loaded")
    assert [plugin.display_name for plugin in panel.filtered_plugins()] == ["Tutor"]
    panel.set_filter("loaded")
    assert panel.filter == ""
    panel.set_filter("blocked")
    assert [plugin.display_name for plugin in panel.filtered_plugins()] == ["Risky"]
    detail = panel.detail_info()
    assert detail is not None
    assert detail.title == "PLUGIN: Risky"
    assert ("Status", "disabled") in detail.fields


def test_inventory_detail_info_for_all_non_summary_tabs_and_command_intent() -> None:
    panel = InventoryPanelModel()
    panel.apply_loaded(_inventory())

    for tab, want_title in (
        ("mcp", "MCP: context7"),
        ("agents", "AGENT: default"),
        ("models", "MODEL: openai"),
        ("memory", "MEMORY: mem"),
    ):
        panel.set_active_subtab(tab)
        detail = panel.detail_info()
        assert detail is not None
        assert detail.title == want_title

    action = panel.handle_key("r")
    assert action.intent is not None
    assert action.intent.argv == ("defenseclaw", "aibom", "scan", "--json")

    panel.handle_key("o")
    assert panel.category_scope == FAST_SCAN_CATEGORIES


def test_inventory_subtab_scope_and_summary_metadata_match_go_labels() -> None:
    panel = InventoryPanelModel()
    panel.apply_loaded(_inventory())

    tabs = panel.subtab_info()
    assert [tab.display_label for tab in tabs] == [
        "Summary",
        "Skills (3)",
        "Plugins (2)",
        "MCPs (1)",
        "Agents (1)",
        "Models (1)",
        "Memory (1)",
    ]
    assert tabs[0].active is True

    assert panel.handle_key("l").handled is True
    assert panel.active_sub == "skills"
    assert panel.handle_key("right").handled is True
    assert panel.active_sub == "plugins"
    assert panel.handle_key("h").handled is True
    assert panel.active_sub == "skills"
    for _ in range(5):
        assert panel.handle_key("l").handled is True
    assert panel.active_sub == "memory"

    scope = panel.scope_state()
    assert scope.label == "Scope (all)"
    assert all(chip.active for chip in scope.chips)
    panel.toggle_fast_scan()
    scope = panel.scope_state()
    assert scope.label == "Scope (fast)"
    assert scope.only_arg == "skills,plugins,mcp"
    assert [chip.category for chip in scope.chips if chip.active] == ["skills", "plugins", "mcp"]
    panel.set_category_scope(["agents", "models"])
    scope = panel.scope_state()
    assert scope.label == "Scope"
    assert [chip.category for chip in scope.chips if chip.active] == ["agents", "models"]

    rows = dict(panel.summary_table_rows())
    assert rows["Skills"] == "3 (2 eligible)"
    assert rows["Plugins"] == "2 (1 loaded, 1 disabled)"
    assert rows["Skill policy verdicts"] == "1 blocked  1 allowed  1 warning"
    assert rows["Skill scan coverage"] == "2 scanned  1 unscanned  3 findings"


def test_inventory_merged_tags_connector_and_adds_column() -> None:
    """8.13 pass 2: merging multiple connectors tags every entity with its
    origin, prepends a CONNECTOR column, and concatenates the rows."""

    panel = InventoryPanelModel()
    panel.show_connector_column = True
    codex = json.dumps(
        {
            "connector": "codex",
            "skills": [{"id": "alpha", "enabled": True}],
            "mcp": [{"id": "context7", "transport": "stdio"}],
        }
    )
    cursor = json.dumps(
        {
            "connector": "cursor",
            "skills": [{"id": "beta"}],
            "agents": [{"id": "main", "model": "gpt"}],
        }
    )
    panel.apply_merged([("codex", codex), ("cursor", cursor)])
    assert panel.loaded is True

    panel.set_active_subtab("skills")
    assert panel.data_table_columns()[0] == "Connector"
    skill_rows = panel.data_table_rows()
    assert [row[0] for row in skill_rows] == ["codex", "cursor"]
    assert [row[1] for row in skill_rows] == ["alpha", "beta"]

    # Per-connector snapshots are retained for the Summary breakdown.
    assert [name for name, _snap in panel.connector_snapshots] == ["codex", "cursor"]


def test_inventory_merged_connector_filter_narrows_every_subtab() -> None:
    panel = InventoryPanelModel()
    panel.show_connector_column = True
    codex = json.dumps(
        {"connector": "codex", "skills": [{"id": "alpha"}], "mcp": [{"id": "ctx"}]}
    )
    cursor = json.dumps({"connector": "cursor", "skills": [{"id": "beta"}]})
    panel.apply_merged([("codex", codex), ("cursor", cursor)])

    panel.set_connector_filter("cursor")
    panel.set_active_subtab("skills")
    assert [row[1] for row in panel.data_table_rows()] == ["beta"]
    panel.set_active_subtab("mcp")
    # The only MCP belongs to codex, so the cursor filter hides it.
    assert panel.data_table_rows() == ()

    counts = {tab.subtab: tab.count for tab in panel.subtab_info()}
    assert counts["skills"] == 1
    assert counts["mcp"] == 0

    # Clearing the filter restores the merged view.
    panel.set_connector_filter("")
    panel.set_active_subtab("skills")
    assert [row[1] for row in panel.data_table_rows()] == ["alpha", "beta"]


def test_inventory_summary_follows_connector_filter() -> None:
    """The Summary sub-tab must switch with the shared connector chip.

    Before the fix it always rendered the merged snapshot (whose Source/Home
    come from the primary connector), so selecting another connector still
    showed the primary's summary."""

    panel = InventoryPanelModel()
    panel.show_connector_column = True
    antigravity = json.dumps(
        {
            "connector": "antigravity",
            "claw_mode": "antigravity",
            "connector_home": "/home/ag",
            "skills": [{"id": "a1"}, {"id": "a2"}],
            "summary": {"total_items": 2, "skills": {"count": "2"}},
        }
    )
    codex = json.dumps(
        {
            "connector": "codex",
            "claw_mode": "codex",
            "connector_home": "/home/cx",
            "skills": [{"id": "c1"}],
            "summary": {"total_items": 1, "skills": {"count": "1"}},
        }
    )
    panel.apply_merged([("antigravity", antigravity), ("codex", codex)])

    # "All" -> merged: primary attribution + combined totals.
    panel.set_connector_filter("")
    merged = panel.summary_state()
    assert merged is not None
    assert merged.home_path == "/home/ag"
    assert merged.counts["total_items"] == "3"

    # Narrow to codex -> codex's own snapshot, not the primary's.
    panel.set_connector_filter("codex")
    scoped = panel.summary_state()
    assert scoped is not None
    assert scoped.connector_name == "codex"
    assert scoped.home_path == "/home/cx"
    assert scoped.counts["total_items"] == "1"


def test_inventory_single_connector_has_no_connector_column() -> None:
    """Single-connector installs keep the original columns (no CONNECTOR)."""

    panel = InventoryPanelModel()
    panel.apply_loaded(_inventory())
    panel.set_active_subtab("skills")
    assert "Connector" not in panel.data_table_columns()
    assert panel.data_table_columns()[0] == "ID"


def test_inventory_load_intent_for_targets_connector_and_restores() -> None:
    panel = InventoryPanelModel(connector="codex")
    intent = panel.load_intent_for("cursor")
    assert intent.args == ("aibom", "scan", "--json", "--connector", "cursor")
    # Prior single-connector state is untouched.
    assert panel.connector == "codex"
    assert panel.connector_focus_enabled is False
