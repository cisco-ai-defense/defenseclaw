# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fixes, batch 9: tab strip, Overview with the gateway down, uninstall chooser."""

from __future__ import annotations

import re

from defenseclaw.tui.app import PANELS
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.tab_fit import fit_tab_labels, strip_width

_COUNT = re.compile(r"(\([0-9+]+\)|[⁰¹²³⁴⁵⁶⁷⁸⁹⁺]+)$")


def test_badges_never_blank_or_rename_tabs_at_160_columns(monkeypatch) -> None:
    # GAP-2301: at 160 columns (a 146-cell strip) Logs/Activity badges left
    # "5" bare and turned "4 MCP" into "4 MCPs"; one Activity badge turned
    # "3 Skills" into "3 Skill".
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    names = {name: _COUNT.sub("", label) for name, label in fit_tab_labels(PANELS, "overview", {}, 146).items()}
    assert all(" " in label for label in names.values()), names
    for unread in ({"alerts": 22}, {"alerts": 22, "activity": 1}, {"alerts": 22, "logs": 37, "activity": 5, "ai": 1}):
        fits = {name: fit_tab_labels(PANELS, name, {**unread, name: 0}, 146) for name, _key, _title in PANELS}
        for active, labels in fits.items():
            assert strip_width(tuple(labels.values())) <= 146
            for name, label in labels.items():
                if name != active:
                    assert _COUNT.sub("", label) == names[name], (unread, active, label)
        assert fits["overview"]["alerts"] == "2 Alerts²²"
    assert fits["overview"]["logs"] == "8 Log³⁷"


def test_bare_alerts_key_reads_the_same_on_every_panel_at_80_columns(monkeypatch) -> None:
    # GAP-2301: at 80x24 Overview read "2(22)" but Setup "2²²".
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    for active, _key, _title in PANELS:
        if active != "alerts":
            labels = fit_tab_labels(PANELS, active, {"alerts": 22}, 66)
            assert strip_width(tuple(labels.values())) <= 66
            assert labels["alerts"].endswith("(22)"), (active, labels)

