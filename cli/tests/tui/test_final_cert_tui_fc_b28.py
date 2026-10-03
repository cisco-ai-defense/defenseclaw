# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tab strip with Windows' plain "(4)" badges at 200 columns (final-cert fix batch 28)."""

from __future__ import annotations

from defenseclaw.tui.app import PANELS
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.tab_fit import fit_tab_labels, strip_width


def test_windows_badges_keep_registries_named_at_200_columns(monkeypatch) -> None:
    # GAP-2588: with plain badges (os.name == "nt") Registries read
    # "R Registry" on every panel and a bare "R" beside the open
    # "V AI Discovery" with 4-6 cells free.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", True)
    unread = {"alerts": 181, "logs": 1500, "audit": 693, "activity": 2, "ai": 4}
    for active, _key, title in PANELS:
        counts = {name: 0 if name == active and name != "alerts" else count for name, count in unread.items()}
        labels = fit_tab_labels(PANELS, active, counts, 186)
        assert strip_width(tuple(labels.values())) <= 186, active
        assert title in labels[active], active
        assert labels["alerts"] == "2 Alerts(181)", active
        if active == "ai":
            assert labels["registries"] == "R Reg", active
        else:
            assert labels["registries"] == "R Registries", active
            assert labels["ai"] == "V AI(4)", active
