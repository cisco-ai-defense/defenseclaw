# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tab strip at 200 columns, Cursor notice and skill-scanner row (final-cert fix batch 35)."""

from __future__ import annotations

import io

from defenseclaw.tui.app import PANELS, _hanging_text
from defenseclaw.tui.panels.setup import SetupWizard
from defenseclaw.tui.panels.setup_catalog import task_status
from defenseclaw.tui.services.overview_state import OverviewConfig, OverviewPanelModel
from defenseclaw.tui.widgets.tab_fit import fit_tab_labels
from rich.console import Console


def test_registries_tab_keeps_its_name_on_every_panel_at_200_columns() -> None:
    # GAP-2560: at 200 columns (186 strip cells) R read "R Registry" beside 11
    # free cells and "R Registries" only while it was open.
    unread = {"alerts": 181, "logs": 1500, "audit": 693, "activity": 2, "ai": 4}
    for active in ("overview", "mcps", "policies", "registries", "ai"):
        counts = {name: 0 if name == active and name != "alerts" else count for name, count in unread.items()}
        labels = fit_tab_labels(PANELS, active, counts, 186)
        assert labels["registries"] == "R Registries", active
    assert fit_tab_labels(PANELS, "ai", {**unread, "ai": 0}, 186)["ai"] == "V AI Discovery"


def test_cursor_notice_is_plain_words_with_a_hanging_indent() -> None:
    # GAP-2561: "Cursor (cursor): priority-conflict-detection=unavailable (none
    # inferred)" wrapped flush-left at 80 columns.
    notice = OverviewPanelModel(OverviewConfig(), version="test").connector_priority_conflict_notice("cursor")
    assert "=" not in notice and "Enterprise, Team or Project" in notice
    console = Console(file=io.StringIO(), width=60, record=True)
    console.print(_hanging_text("Cursor:", notice, ""))
    lines = console.export_text().splitlines()
    assert lines[0].startswith("Cursor: DefenseClaw") and len(lines) > 1
    assert all(line.startswith(" " * len("Cursor: ")) for line in lines[1:])


def test_skill_scanner_row_reads_none_for_an_empty_policy() -> None:
    # GAP-2562: "--policy none" saves policy '' and the row said "permissive".
    def row(scanner: dict) -> str:
        cfg = {"scanners": {"skill_scanner": {"binary": "skill-scanner", **scanner}}}
        return task_status(SetupWizard.SKILL_SCANNER, cfg).text

    assert row({"policy": ""}) == "none"
    assert row({}) == "permissive"
    assert row({"policy": "strict"}) == "strict"
