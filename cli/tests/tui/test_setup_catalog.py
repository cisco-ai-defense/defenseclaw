# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Setup task groups, the group table row mapping and the config navigators."""

from __future__ import annotations

from collections import Counter

import pytest
from defenseclaw.tui.panels import setup_catalog
from defenseclaw.tui.panels.setup import WIZARD_DESCRIPTIONS, SetupPanelModel, SetupWizard
from defenseclaw.tui.screens.setup_picker import move_selection, visible_window
from defenseclaw.tui.services.setup_state import ConfigField, ConfigSection


def test_every_wizard_appears_exactly_once() -> None:
    shown = Counter(wizard for group in setup_catalog.GROUP_TITLES for wizard in setup_catalog.group_tasks(group))

    assert set(shown) == set(SetupWizard)
    assert all(count == 1 for count in shown.values())
    assert setup_catalog.display_order() == tuple(
        wizard for group in setup_catalog.GROUP_TITLES for wizard in setup_catalog.group_tasks(group)
    )


def test_enum_values_are_unchanged() -> None:
    # Saved state, intents and tests key off these ids; grouping must not move them.
    assert SetupWizard.CONNECTOR_SETUP == 0
    assert SetupWizard.SANDBOX == 13
    assert SetupWizard.ACP_GUARD == 21
    assert len(WIZARD_DESCRIPTIONS) == len(SetupWizard)


@pytest.mark.parametrize("wizard", list(SetupWizard))
def test_group_row_mapping_round_trips(wizard: SetupWizard) -> None:
    group = setup_catalog.wizard_group(wizard)

    assert setup_catalog.task_at(group, setup_catalog.task_row(wizard)) is wizard


def test_task_at_is_none_off_the_end_of_a_group() -> None:
    group = setup_catalog.GROUP_TITLES[0]

    assert setup_catalog.task_at(group, len(setup_catalog.group_tasks(group))) is None
    assert setup_catalog.task_at(group, -1) is None
    assert setup_catalog.task_at("No such group", 0) is None


def test_step_group_lands_on_the_first_task_and_wraps() -> None:
    first, second = setup_catalog.GROUP_TITLES[:2]
    last = setup_catalog.GROUP_TITLES[-1]
    somewhere = setup_catalog.group_tasks(first)[-1]

    assert setup_catalog.step_group(somewhere, 1) is setup_catalog.group_tasks(second)[0]
    assert setup_catalog.step_group(somewhere, -1) is setup_catalog.group_tasks(last)[0]


def test_step_wizard_crosses_groups_and_clamps_or_wraps() -> None:
    order = setup_catalog.display_order()

    assert setup_catalog.step_wizard(order[2], 1) is order[3]  # crosses a group boundary
    assert setup_catalog.step_wizard(order[0], -1) is order[0]
    assert setup_catalog.step_wizard(order[-1], 1) is order[-1]
    assert setup_catalog.step_wizard(order[-1], 1, wrap=True) is order[0]


def test_friendly_labels_cover_every_wizard() -> None:
    labels = [setup_catalog.wizard_label(wizard) for wizard in SetupWizard]

    assert all(labels)
    assert len(set(labels)) == len(labels)
    assert all(setup_catalog.wizard_group(wizard) for wizard in SetupWizard)


def _sections() -> tuple[ConfigSection, ...]:
    return (
        ConfigSection("Inspect LLM (legacy - read-only)", (ConfigField("Provider", kind="header", value="x"),), ""),
        ConfigSection(
            "Gateway",
            (
                ConfigField(".. Ports ..", kind="header"),
                ConfigField("Port", "gateway.port", "int", "18789", "18789"),
                ConfigField("API Port", "gateway.api_port", "int", "abc", "18970"),
            ),
            "",
        ),
        ConfigSection("Agent Hooks", (ConfigField("Mode", "agent_hooks.mode", "string", "a", "a"),), ""),
        ConfigSection("General", (ConfigField("Data Dir", "data_dir", "string", "/d", "/d"),), ""),
        ConfigSection("Brand New Section", (ConfigField("Thing", "brand.thing", "string"),), ""),
    )


def test_section_order_puts_legacy_last_and_groups_the_rest() -> None:
    sections = _sections()
    names = [sections[index].name for index in setup_catalog.section_order(sections)]

    assert names[-1] == "Inspect LLM (legacy - read-only)"
    assert names.index("General") < names.index("Gateway") < names.index("Agent Hooks")
    # Sections nobody grouped yet still show up (under Core).
    assert "Brand New Section" in names
    assert setup_catalog.section_group("Brand New Section") == "Core"


def test_step_section_walks_the_grouped_order_and_wraps() -> None:
    sections = _sections()
    order = setup_catalog.section_order(sections)

    assert setup_catalog.step_section(sections, order[0], 1) == order[1]
    assert setup_catalog.step_section(sections, order[-1], 1) == order[0]
    assert setup_catalog.step_section(sections, order[0], -1) == order[-1]
    assert setup_catalog.section_position(sections, order[-1]) == (len(order), len(order))


def test_section_picker_rows_have_group_headers_and_counts() -> None:
    sections = _sections()
    rows = setup_catalog.section_picker_rows(sections, active=1)
    headers = [row for row in rows if not row.selectable]
    gateway = next(row for row in rows if row.label == "Gateway")

    assert [row.label for row in headers] == ["Core", "Hooks (read-only)", "Legacy"]
    assert "1 changed" in gateway.detail and "1 to fix" in gateway.detail
    assert int(gateway.row_id) == 1


def test_field_finder_matches_key_or_label_and_skips_separators() -> None:
    sections = _sections()
    entries = setup_catalog.field_entries(sections)

    assert all(entry.label != ".. Ports .." for entry in entries)
    found = setup_catalog.filter_field_entries("port", entries)
    assert [entry.key for entry in found] == ["gateway.port", "gateway.api_port"]
    assert setup_catalog.filter_field_entries("gateway.api_port", entries)[0].key == "gateway.api_port"
    assert setup_catalog.filter_field_entries("data dir", entries)[0].key == "data_dir"
    assert setup_catalog.filter_field_entries("nothing-like-this", entries) == ()
    # Row ids point back at section/line so the finder can jump there.
    api = found[1]
    assert sections[api.section_index].fields[api.line].key == "gateway.api_port"


def test_picker_selection_skips_headers_and_windows_around_the_cursor() -> None:
    rows = setup_catalog.section_picker_rows(_sections())
    first = move_selection(rows, None, 1)

    assert rows[first].selectable
    assert all(rows[move_selection(rows, index, 1)].selectable for index in range(len(rows)))
    assert visible_window(100, 90, 10) == (85, 95)
    assert visible_window(5, 4, 10) == (0, 5)


def test_setup_detail_lists_attention_checks_first() -> None:
    model = SetupPanelModel(None)
    pairs = dict(setup_catalog.setup_detail_pairs(model))
    statuses = [
        value.split(" · ", 1)[0] for label, value in setup_catalog.setup_detail_pairs(model)[4:] if "·" in value
    ]

    assert pairs["Command"].startswith("defenseclaw ")
    assert statuses == sorted(statuses, key=lambda status: {"FAIL": 0, "WARN": 1}.get(status, 2))


def test_fail_mode_ignores_disabled_connector() -> None:
    from defenseclaw.config import PerConnectorGuardrailConfig, default_config

    cfg = default_config()
    cfg.guardrail.mode = "action"
    cfg.guardrail.hook_fail_mode = "closed"
    cfg.guardrail.connectors = {
        "claudecode": PerConnectorGuardrailConfig(mode="action", enabled=True),
        "codex": PerConnectorGuardrailConfig(mode="action", hook_fail_mode="open", enabled=False),
    }
    assert setup_catalog._fail_mode_text(cfg) == "fail closed"
