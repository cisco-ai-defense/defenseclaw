# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fixes, batch 20: minor tab counts at 80x24."""

from __future__ import annotations

from defenseclaw.tui.app import PANELS
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.tab_fit import fit_tab_labels, strip_width


def test_minor_counts_that_fit_show_on_every_panel_at_80_columns(monkeypatch) -> None:
    # GAP-2342: Overview read "8(48)" but Setup and Skills a bare "8" with
    # 7-8 strip cells free.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    for unread, name, badge in (
        ({"alerts": 22, "logs": 48}, "logs", "8(48)"),
        ({"alerts": 22, "activity": 1}, "activity", "A(1)"),
    ):
        for active in ("overview", "setup", "skills", "alerts"):
            labels = fit_tab_labels(PANELS, active, unread, 66)
            assert strip_width(tuple(labels.values())) <= 66
            assert labels[name] == badge, (active, labels)
            assert labels["alerts"].endswith("(22)"), (active, labels)
