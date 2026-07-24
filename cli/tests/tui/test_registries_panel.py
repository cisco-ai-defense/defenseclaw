# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Registries panel parity tests for the Textual TUI migration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from defenseclaw.config import Config, RegistriesConfig, RegistrySource
from defenseclaw.tui.panels.registries import RegistriesPanelModel, RegistriesTab, registry_badge
from defenseclaw.tui.services.registry_cache import (
    UnsafeSourceIDError,
    load_registry_index,
    registry_index_path,
)


def write_index(data_dir: Path, source_id: str, index: dict[str, object]) -> None:
    source_dir = data_dir / "registries" / source_id
    source_dir.mkdir(mode=0o700, parents=True)
    (source_dir / "index.json").write_text(json.dumps(index), encoding="utf-8")


def new_panel(tmp_path: Path) -> RegistriesPanelModel:
    cfg = Config(
        data_dir=str(tmp_path),
        registries=RegistriesConfig(
            sources=[
                RegistrySource(
                    id="smithery-public",
                    kind="smithery",
                    content="mcp",
                    enabled=False,
                ),
                RegistrySource(
                    id="corp-skills",
                    kind="http_yaml",
                    url="https://catalog.example.com/skills.yaml",
                    content="skill",
                    enabled=True,
                ),
            ],
        ),
    )
    return RegistriesPanelModel(cfg)


def test_registry_index_path_rejects_unsafe_source_ids_before_read(tmp_path: Path) -> None:
    for source_id in ("../escape", "a/b", r"a\b", "x.y", "."):
        with pytest.raises(UnsafeSourceIDError):
            registry_index_path(tmp_path, source_id)


def test_registry_index_loader_reads_configurable_data_dir(tmp_path: Path) -> None:
    write_index(
        tmp_path,
        "corp-skills",
        {
            "source_id": "corp-skills",
            "fetched_at": "2026-05-20T12:00:00Z",
            "publisher": "security",
            "verdicts": [
                {"name": "demo-skill", "type": "skill", "status": "clean", "approved": True},
                {"name": "blocked-skill", "type": "skill", "status": "blocked", "severity": "HIGH"},
            ],
        },
    )

    index = load_registry_index(tmp_path, "corp-skills")

    assert index.source_id == "corp-skills"
    assert index.fetched_at == "2026-05-20T12:00:00Z"
    assert index.publisher == "security"
    assert index.entry_count == 2
    assert index.clean_count == 1
    assert index.blocked_count == 1
    assert index.verdicts[0].name == "demo-skill"


def test_registry_index_loader_missing_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_registry_index(tmp_path, "no-such")


def test_registries_panel_loads_sources_sorted_and_index_summaries(tmp_path: Path) -> None:
    write_index(
        tmp_path,
        "corp-skills",
        {"verdicts": [{"name": "demo-skill", "type": "skill", "status": "clean"}]},
    )

    panel = new_panel(tmp_path)

    assert panel.row_count() == 2
    assert [source.id for source in panel.sources] == ["corp-skills", "smithery-public"]
    assert panel.selected_source().id == "corp-skills"
    assert panel.sources[0].entry_count == 1
    assert panel.sources[0].clean_count == 1
    assert panel.sources[1].index_error == ""


def test_registries_panel_surfaces_unsafe_source_id_as_cache_error(tmp_path: Path) -> None:
    panel = RegistriesPanelModel(
        data_dir=tmp_path,
        sources=[RegistrySource(id="bad.id", kind="http_yaml", content="skill")],
    )

    assert panel.sources[0].index_error
    assert "unsafe registry source id" in panel.sources[0].status_label


def test_registries_panel_tab_switch_resets_cursor_and_filter(tmp_path: Path) -> None:
    panel = new_panel(tmp_path)
    panel.cursor_down()

    assert panel.cursor == 1

    panel.set_tab(RegistriesTab.ENTRIES)

    assert panel.cursor == 0
    assert panel.current_tab == RegistriesTab.ENTRIES


def test_registries_panel_entries_tab_reads_union_from_indexes(tmp_path: Path) -> None:
    write_index(
        tmp_path,
        "corp-skills",
        {
            "source_id": "corp-skills",
            "verdicts": [
                {
                    "name": "demo-skill",
                    "type": "skill",
                    "status": "clean",
                    "approved": False,
                    "url": "https://example.com/demo",
                    "command": "ignored",
                    "source_url": "ignored",
                },
                {
                    "name": "blocked-skill",
                    "type": "skill",
                    "status": "blocked",
                    "severity": "HIGH",
                    "command": "python server.py",
                    "source_url": "ignored",
                },
            ],
        },
    )
    write_index(
        tmp_path,
        "smithery-public",
        {
            "verdicts": [
                {
                    "name": "context7",
                    "type": "mcp",
                    "status": "warning",
                    "source_url": "https://registry.smithery.ai/context7",
                },
            ],
        },
    )
    panel = new_panel(tmp_path)
    panel.set_tab(RegistriesTab.ENTRIES)

    rows = panel.visible_entries()

    assert panel.row_count() == 3
    assert [row.source_id for row in rows] == ["corp-skills", "corp-skills", "smithery-public"]
    assert rows[0].location == "https://example.com/demo"
    assert rows[1].location == "python server.py"
    assert rows[2].location == "https://registry.smithery.ai/context7"


def test_registries_panel_approved_filter(tmp_path: Path) -> None:
    write_index(
        tmp_path,
        "corp-skills",
        {
            "verdicts": [
                {"name": "a", "type": "skill", "status": "clean", "approved": True},
                {"name": "b", "type": "skill", "status": "clean", "approved": False},
            ],
        },
    )
    panel = new_panel(tmp_path)

    panel.set_tab(RegistriesTab.APPROVED)

    assert panel.row_count() == 1
    assert panel.selected_entry().name == "a"


def test_registries_panel_focus_entry_filters_and_selects_match(tmp_path: Path) -> None:
    write_index(
        tmp_path,
        "corp-skills",
        {
            "verdicts": [
                {"name": "a", "type": "skill", "status": "clean"},
                {"name": "b", "type": "skill", "status": "clean"},
            ],
        },
    )
    panel = new_panel(tmp_path)

    assert panel.focus_entry("skill", "b") is True

    assert panel.current_tab == RegistriesTab.ENTRIES
    assert panel.row_count() == 1
    assert panel.selected_entry().name == "b"


def test_registries_panel_focus_entry_miss_shows_full_entries_table(tmp_path: Path) -> None:
    write_index(
        tmp_path,
        "corp-skills",
        {
            "verdicts": [
                {"name": "a", "type": "skill", "status": "clean"},
                {"name": "b", "type": "skill", "status": "clean"},
            ],
        },
    )
    panel = new_panel(tmp_path)

    assert panel.focus_entry("mcp", "missing") is False

    assert panel.current_tab == RegistriesTab.ENTRIES
    assert panel.row_count() == 2
    assert panel.selected_entry().name == "a"


def test_registries_panel_handle_key_tabs(tmp_path: Path) -> None:
    panel = new_panel(tmp_path)

    assert panel.handle_key("2").handled is True
    assert panel.current_tab == RegistriesTab.ENTRIES
    assert panel.handle_key("3").handled is True
    assert panel.current_tab == RegistriesTab.APPROVED


def test_registries_panel_sync_intents_are_data(tmp_path: Path) -> None:
    panel = new_panel(tmp_path)

    source_sync = panel.handle_key("s").intent
    sync_all = panel.handle_key("S").intent

    assert source_sync is not None
    assert source_sync.binary == "defenseclaw"
    assert source_sync.label == "registry sync corp-skills"
    assert source_sync.args == ("registry", "sync", "corp-skills", "--json")
    assert source_sync.argv == ("defenseclaw", "registry", "sync", "corp-skills", "--json")
    assert sync_all is not None
    assert sync_all.args == ("registry", "sync", "--all", "--json")


def test_registries_panel_entry_action_intents_are_data(tmp_path: Path) -> None:
    write_index(
        tmp_path,
        "corp-skills",
        {"verdicts": [{"name": "demo-skill", "type": "skill", "status": "clean"}]},
    )
    panel = new_panel(tmp_path)
    panel.set_tab(RegistriesTab.ENTRIES)

    approve = panel.handle_key("a").intent
    reject = panel.handle_key("x").intent

    assert approve is not None
    assert approve.label == "registry approve corp-skills demo-skill"
    assert approve.args == ("registry", "approve", "corp-skills", "demo-skill", "--type", "skill", "--json")
    assert reject is not None
    assert reject.label == "registry reject corp-skills demo-skill"
    assert reject.args == ("registry", "reject", "corp-skills", "demo-skill", "--type", "skill", "--json")


def test_registries_panel_remove_source_only_from_sources_tab(tmp_path: Path) -> None:
    panel = new_panel(tmp_path)

    remove = panel.handle_key("d")
    assert remove.handled is True
    assert remove.intent is not None
    assert remove.intent.args == ("registry", "remove", "corp-skills", "--non-interactive", "--json")

    panel.set_tab(RegistriesTab.ENTRIES)
    assert panel.handle_key("d").handled is False


def test_registries_panel_mixed_effective_state_toggles_broad_enforcement_on(tmp_path: Path) -> None:
    from defenseclaw.config import (
        GuardrailConfig,
        PerConnectorAssetPolicy,
        PerConnectorAssetTypePolicy,
        PerConnectorGuardrailConfig,
    )

    write_index(
        tmp_path,
        "corp-skills",
        {"verdicts": [{"name": "demo-skill", "type": "skill", "status": "clean"}]},
    )
    cfg = new_panel(tmp_path).config
    cfg.guardrail = GuardrailConfig(
        connectors={
            "codex": PerConnectorGuardrailConfig(),
            "claudecode": PerConnectorGuardrailConfig(),
        },
    )
    cfg.asset_policy.skill.registry_required = True
    cfg.asset_policy.connectors["codex"] = PerConnectorAssetPolicy(
        skill=PerConnectorAssetTypePolicy(registry_required=False),
    )
    panel = RegistriesPanelModel(cfg)
    panel.set_tab(RegistriesTab.ENTRIES)

    action = panel.handle_key("R")

    assert action.intent is not None
    assert action.intent.args == (
        "registry", "require", "--type", "skill", "--enabled", "--json",
    )


def test_registries_panel_approve_requires_selection(tmp_path: Path) -> None:
    panel = new_panel(tmp_path)
    panel.set_tab(RegistriesTab.ENTRIES)

    action = panel.handle_key("a")

    assert action.handled is True
    assert action.intent is None
    assert "no entry selected" in action.hint


def test_registries_panel_empty_states_and_textual_rows(tmp_path: Path) -> None:
    panel = RegistriesPanelModel(data_dir=tmp_path, sources=[])

    assert panel.empty_state() == (
        "No registry sources configured. Run `defenseclaw registry add` or use the Setup wizard."
    )
    assert panel.data_table_columns()[0] == "ID"

    panel.set_tab(RegistriesTab.ENTRIES)
    assert panel.empty_state() == "Sync a source to populate this view."
    assert panel.data_table_columns()[0] == "Source"

    panel.set_tab(RegistriesTab.APPROVED)
    assert panel.empty_state() == "No entries approved yet. Press 'a' on the Entries tab to approve one."


def test_registries_panel_source_detail_preserves_full_id_and_cache_safety(tmp_path: Path) -> None:
    long_id = "very-long-corporate-registry"
    panel = RegistriesPanelModel(
        data_dir=tmp_path,
        sources=[RegistrySource(id=long_id, kind="http_json", content="both", url="https://example.com/index.json")],
    )

    detail = panel.selected_detail_info()
    assert detail is not None
    fields = dict(detail.fields)
    assert detail.title == f"SOURCE: {long_id}"
    assert fields["Source ID"] == long_id
    assert fields["URL"] == "https://example.com/index.json"
    assert Path(fields["Cache Path"]).parts[-3:] == ("registries", long_id, "index.json")

    unsafe = RegistriesPanelModel(
        data_dir=tmp_path,
        sources=[RegistrySource(id="bad.id", kind="http_yaml", content="skill")],
    )
    detail = unsafe.selected_detail_info()
    assert detail is not None
    assert "unsafe registry source id" in dict(detail.fields)["Cache Safety"]


def test_registries_panel_entry_detail_exposes_full_registry_attribution(tmp_path: Path) -> None:
    write_index(
        tmp_path,
        "corp-skills",
        {
            "verdicts": [
                {
                    "name": "demo-skill",
                    "type": "skill",
                    "status": "warning",
                    "severity": "MEDIUM",
                    "findings": 2,
                    "approved": True,
                    "transport": "stdio",
                    "command": "python",
                    "args": ["server.py", "--stdio"],
                    "source_url": "https://catalog.example.com/demo",
                },
            ],
        },
    )
    panel = new_panel(tmp_path)
    panel.set_tab(RegistriesTab.ENTRIES)

    detail = panel.selected_detail_info()
    assert detail is not None
    fields = dict(detail.fields)
    assert detail.title == "SKILL: demo-skill"
    assert fields["Source ID"] == "corp-skills"
    assert fields["Findings"] == "2"
    assert fields["Approved"] == "yes"
    assert fields["Args"] == "server.py --stdio"
    assert fields["Location"] == "python"


def test_registry_badge_truncates_long_ids() -> None:
    assert registry_badge("") == ""
    assert registry_badge("corp-skills") == "registry:corp-skills"
    assert registry_badge("very-long-corporate-registry") == "registry:very-long-corpo..."
