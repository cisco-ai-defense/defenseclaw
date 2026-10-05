# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fix-only batch 30: tab strip, Overview CONFIGURATION wrap and
Setup task Status width (GAP-2500, GAP-2501, GAP-2502)."""

from __future__ import annotations

from types import SimpleNamespace

from defenseclaw.tui import app as app_module
from defenseclaw.tui.app import PANELS, DefenseClawTUI
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.tab_fit import fit_tab_labels, strip_width


def test_windows_160_columns_names_plugins_and_audit(monkeypatch) -> None:
    # GAP-2500: at 160x45 on Windows "5" was bare and "9 Audit" read "9(12)"
    # beside 11 free cells, on Overview and on Setup.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", True)
    overview = fit_tab_labels(PANELS, "overview", {"alerts": 25, "audit": 12, "ai": 2}, 146)
    assert overview["plugins"] == "5 Plugin" and overview["audit"] == "9 Audit(12)", overview
    unread = {"alerts": 25, "audit": 12, "logs": 252, "activity": 6, "ai": 2}
    for active in ("overview", "setup", "alerts", "logs"):
        labels = fit_tab_labels(PANELS, active, {**unread, active: 0}, 146)
        assert strip_width(tuple(labels.values())) <= 146
        assert all(" " in label for label in labels.values()), (active, labels)


def test_overview_config_values_wrap_at_spaces() -> None:
    # GAP-2501: "block CRITICAL · al" / "ert MEDIUM+" and "per-connector m" /
    # "odes" were cut mid-word at 80 columns.
    wrap = app_module._wrap_at_separators
    posture = "default · block CRITICAL · alert MEDIUM+ · per-connector packs (see roster)"
    assert wrap(posture, 29).split("\n") == [
        "default · block CRITICAL ·",
        "alert MEDIUM+ · per-connector",
        "packs (see roster)",
    ]
    assert wrap("4 connectors (per-connector modes)", 29) == "4 connectors (per-connector\nmodes)"
    # A word longer than the line is still folded.
    assert wrap("x" * 31, 29) == "x" * 29 + "\nxx"


def test_setup_task_status_wraps_beside_nav_and_detail() -> None:
    # GAP-2502: at 160 columns "✓ on · action, 1 observe · ran ok" was cut
    # to "... · ran" at the table border, with no ellipsis.
    status = "✓ on · action, 1 observe · ran ok"
    rows = (("On/off, fail mode, approvals", "✓ fail open"), ("Guardrail", status))
    for width, nav in ((160, True), (140, True), (80, False), (220, True)):
        host = SimpleNamespace(_setup_width=lambda width=width: width, _setup_nav_shown=lambda nav=nav: nav)
        fitted = DefenseClawTUI._wrap_setup_task_status(host, rows)
        cell = fitted[1][1]
        assert cell.replace("\n", " ") == status, (width, cell)
        if width == 160:
            # 64-cell table: Task column 30 cells, so Status has 28.
            assert cell == "✓ on · action, 1 observe ·\nran ok"
        if width in (80, 220):
            assert cell == status
