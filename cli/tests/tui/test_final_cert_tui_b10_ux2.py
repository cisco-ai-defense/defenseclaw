# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI UX batch 10 (ux2): GAP-2309, GAP-2314, GAP-2315."""

from __future__ import annotations

from defenseclaw.commands.cmd_plugin import _plugin_metadata_from_path
from defenseclaw.tui.command_line import ParsedCommand
from defenseclaw.tui.panels.registries import (
    RegistriesPanelModel,
    RegistrySourceRow,
    remove_source_intent,
    sync_source_intent,
)
from defenseclaw.tui.screens.command_preview import build_command_preview
from defenseclaw.tui.services.catalog_state import PluginRow, catalog_detail_text
from rich.text import Text


def _preview(intent):
    return build_command_preview(
        ParsedCommand(
            binary=intent.binary,
            args=intent.args,
            display_name=intent.label,
            category=intent.category,
            risk=intent.risk,
            needs_preview=True,
        )
    )


def test_registry_remove_confirm_is_destructive_and_focuses_cancel() -> None:
    removed = _preview(remove_source_intent("sf1-local"))
    assert removed.risk == "destructive" and removed.cancel_by_default
    assert removed.summary.startswith("Destructive command")
    synced = _preview(sync_source_intent("sf1-local"))
    assert synced.risk == "mutation" and not synced.cancel_by_default


def test_cut_plugin_description_points_to_info_and_info_reads_plugin_yaml(tmp_path) -> None:
    long = "Chronos - managed cron provider for hosted agents. " * 6
    text = Text.from_markup(catalog_detail_text(PluginRow(id="cron_providers/chronos", description=long))).plain
    assert "…" in text and "Full description: press o, then Info" in text
    short = Text.from_markup(catalog_detail_text(PluginRow(id="x", description="Short one."))).plain
    assert "Full description" not in short
    (tmp_path / "plugin.yaml").write_text(f"name: chronos\nversion: 1.2.0\ndescription: {long}\n", encoding="utf-8")
    info = _plugin_metadata_from_path("chronos", str(tmp_path))
    assert info["description"] == long.strip() and info["version"] == "1.2.0"


def test_sources_table_keeps_counts_before_a_short_sync_time(tmp_path) -> None:
    model = RegistriesPanelModel(data_dir=tmp_path)
    model.sources = [RegistrySourceRow(id="sf1-local", last_sync="2026-10-03T06:17:21Z", entry_count=1, clean_count=1)]
    columns = model.data_table_columns()
    assert columns.index("C/W/B/E") < columns.index("Last Sync") == len(columns) - 1
    row = dict(zip(columns, model.data_table_rows()[0], strict=True))
    assert row["C/W/B/E"] == "1/0/0/0" and row["Last Sync"] == "2026-10-03 06:17Z"
