# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tab strip names at 196-201 columns (final-cert fix batch 29)."""

from __future__ import annotations

import re

import pytest
from defenseclaw.tui.app import PANELS
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.tab_fit import fit_tab_labels, strip_width


def _names(labels: dict[str, str]) -> dict[str, str]:
    return {name: re.sub(r" ?\(.*\)$|[⁰¹²³⁴⁵⁶⁷⁸⁹⁺]+$", "", text) for name, text in labels.items()}


@pytest.mark.parametrize("plain", [True, False])
@pytest.mark.parametrize("width", range(182, 188))
def test_minor_badge_never_renames_other_tabs(monkeypatch, plain, width) -> None:
    # GAP-2599: at 196-201 columns a Logs, Audit or Activity count turned
    # "7 Sandboxes", "V AI Discovery" and "R Registries" into "7 Sandbox",
    # "V AI" and "R Registry" with 15 cells free; the count waits instead.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", plain)
    for alerts in (1, 34):
        base = _names(fit_tab_labels(PANELS, "overview", {"alerts": alerts}, width))
        for extra in ({"logs": 5}, {"activity": 2}, {"logs": 9, "audit": 3}, {"logs": 1500, "audit": 693}):
            labels = fit_tab_labels(PANELS, "overview", {"alerts": alerts, **extra}, width)
            assert _names(labels) == base, (width, extra, labels)
            assert strip_width(tuple(labels.values())) <= width
    labels = fit_tab_labels(PANELS, "overview", {"alerts": 34, "logs": 5}, 185)
    assert labels["logs"] == ("8 Logs(5)" if plain else "8 Logs⁵")
    assert labels["sandboxes"] == "7 Sandboxes" and labels["registries"] == "R Registries"
