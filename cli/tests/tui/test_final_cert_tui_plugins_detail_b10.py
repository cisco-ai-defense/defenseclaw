# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI Plugins detail and Info card (GAP-2369, GAP-2370)."""

from __future__ import annotations

from defenseclaw.tui.command_line import command_result_summary
from defenseclaw.tui.services.catalog_state import (
    PluginRow,
    PluginScanSummary,
    catalog_detail_text,
    catalog_row_cells,
)
from rich.text import Text


def test_blocked_plugin_detail_matches_the_table_row() -> None:
    row = PluginRow(
        id="image_gen/krea",
        name="krea",
        origin="bundled",
        status="blocked",
        enabled=True,
        verdict="blocked",
        scan=PluginScanSummary(clean=True),
    )
    assert catalog_row_cells(row)[1:4] == ("enabled", "bundled", "blocked")
    text = Text.from_markup(catalog_detail_text(row)).plain
    assert "Status     enabled" in text and "Enabled  yes" not in text
    assert "Verdict    blocked" in text


def test_plugin_info_card_summarises_the_result() -> None:
    lines = [
        "Plugin:      a2a",
        "Connector:   hermes",
        "Description: A2A protocol support. Verdict: none here.",
        "Installed:   yes",
        "Quarantined: no",
        "Last Scan:",
        "Verdict:  clean",
        "Findings: 0 findings",
        "Actions:     -",
    ]
    assert command_result_summary("info plugin a2a", lines) == "a2a: clean, 0 findings, not quarantined"
    blocked = [*lines[:-1], "Actions:     install-blocked (new installs are refused; the installed copy still loads)"]
    assert command_result_summary("plugin info krea", blocked).endswith("not quarantined, actions: install-blocked")
    long = PluginRow(id="x", description="Chronos managed cron provider. " * 8)
    assert "press o, then Info, then A" in Text.from_markup(catalog_detail_text(long)).plain
