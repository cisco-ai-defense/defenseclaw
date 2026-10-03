# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert stack batch 10 (tui tab bar): one fitting rule after the
queue/final-cert merge (GAP-2179, GAP-2180)."""

from __future__ import annotations

from defenseclaw.tui.app import PANELS
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.tab_fit import _fit_for_active, fit_tab_labels, strip_width


def _bare(labels: dict[str, str]) -> list[str]:
    return [name for name, label in labels.items() if " " not in label]


def test_windows_160_columns_names_tabs_and_keeps_counts(monkeypatch) -> None:
    # GAP-2180: on Windows (plain "(69)" badges) at 160x45 the strip left
    # 6, 9, A, N, R or A, V, N, R bare, some with free cells beside them.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", True)
    unread = {"alerts": 229, "logs": 69, "audit": 69}
    for active, _key, title in PANELS:
        counts = {**unread, active: 0}
        labels = fit_tab_labels(PANELS, active, counts, 146)
        assert strip_width(tuple(labels.values())) <= 146
        shown = labels[active].split(" ", 1)[1]
        assert shown.startswith(title) or (shown.endswith("…") and title.startswith(shown[:-1]))
        # Every tab keeps a name; a count that doesn't fit waits (GAP-2301).
        assert not _bare(labels), (active, labels)
        assert active == "alerts" or "(229)" in labels["alerts"]
        assert active == "logs" or "(69)" in labels["logs"], (active, labels)
        # A wider strip never names fewer tabs (GAP-2150).
        previous = len(PANELS)
        for width in range(tab_fit.NARROW_STRIP + 1, 200):
            bare = len(_bare(fit_tab_labels(PANELS, active, counts, width)))
            assert bare <= previous, (active, width)
            previous = bare


def test_stable_labels_name_as_many_tabs_as_the_per_panel_fit(monkeypatch) -> None:
    # GAP-2179: stable labels (GAP-2078) left one more bare key than the
    # per-panel fit from 76 to 136 cells. Now they keep every count and name
    # as many tabs as the per-panel fit, which drops the Logs/Audit counts.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    unread = {"alerts": 22, "audit": 13, "logs": 1000}
    for width in range(106, 137, 6):
        stable = [fit_tab_labels(PANELS, name, {**unread, name: 0}, width) for name, _k, _t in PANELS]
        per_panel = [_fit_for_active(PANELS, name, {**unread, name: 0}, width) for name, _k, _t in PANELS]
        assert max(map(len, map(_bare, stable))) <= max(map(len, map(_bare, per_panel))), width
        for (name, _k, _t), labels in zip(PANELS, stable, strict=True):
            assert name == "logs" or labels["logs"].endswith(("⁹⁹⁹⁺", "(999+)")), (width, name)
            assert name == "audit" or labels["audit"].endswith(("¹³", "(13)")), (width, name)
