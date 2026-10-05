# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tab strip unread badges at 200 columns (final-cert fix batch 36)."""

from __future__ import annotations

from defenseclaw.tui.app import PANELS
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.tab_fit import fit_tab_labels, strip_width


def test_ai_badge_shows_beside_free_cells_at_200_columns(monkeypatch) -> None:
    # GAP-2582: at 200 columns (186 strip cells) "V AI⁴" lost its badge on
    # Overview, MCPs, Policies and Registries beside 12 free cells, because
    # the AI count kept room for the AI tab's own full name, and that tab's
    # count is 0 while it is open. The open tab still reads in full.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    unread = {"alerts": 181, "logs": 1500, "audit": 693, "activity": 2, "ai": 4}
    for active, _key, title in PANELS:
        counts = {name: 0 if name == active and name != "alerts" else count for name, count in unread.items()}
        labels = fit_tab_labels(PANELS, active, counts, 186)
        assert strip_width(tuple(labels.values())) <= 186, active
        assert labels["registries"] == "R Registries", active
        assert title in labels[active], active
        if active != "ai":
            assert labels["ai"] == "V AI Discovery⁴", active  # every full name fits (GAP-2599)
