# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tab strip names where the full names just fit (final-cert fix batch 30)."""

from __future__ import annotations

import re

import pytest
from defenseclaw.tui.app import PANELS
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.tab_fit import fit_tab_labels, strip_width


def _names(labels: dict[str, str]) -> dict[str, str]:
    return {name: re.sub(r" ?\(.*\)$|[⁰¹²³⁴⁵⁶⁷⁸⁹⁺]+$", "", text) for name, text in labels.items()}


@pytest.mark.parametrize("plain", [True, False])
def test_counts_never_rename_other_tabs_where_full_names_just_fit(monkeypatch, plain) -> None:
    # GAP-2601: at the width where the bare full names fit exactly, the first
    # Logs count renamed four tabs. GAP-2602: a few cells wider, Alerts going
    # from 5 to 34 renamed Registries. The names now come from the width alone.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", plain)
    bare = strip_width(tuple(fit_tab_labels(PANELS, "overview", {}, 400).values()))
    for width in range(bare - 1, bare + 8):
        base = _names(fit_tab_labels(PANELS, "overview", {}, width))
        for unread in ({"alerts": 5}, {"alerts": 34}, {"alerts": 1500}, {"logs": 5}, {"alerts": 34, "audit": 3}):
            labels = fit_tab_labels(PANELS, "overview", unread, width)
            assert _names(labels) == base, (width, unread, labels)
            assert strip_width(tuple(labels.values())) <= width
    # Every full name once it fits beside the longest Alerts count.
    room = 6 if plain else 4
    assert _names(fit_tab_labels(PANELS, "registries", {"alerts": 1500, "logs": 5}, bare + room)) == _names(
        fit_tab_labels(PANELS, "overview", {}, 400)
    )
    assert _names(fit_tab_labels(PANELS, "overview", {}, bare + room - 1))["registries"] != "R Registries"
