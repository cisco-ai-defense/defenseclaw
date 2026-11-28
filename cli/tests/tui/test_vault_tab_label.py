# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The Vault tab reads "K Vault" in the tab strip, not a bare "K"."""

from __future__ import annotations

from defenseclaw.tui.app import ALL_PANELS
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.tab_fit import LABEL_PRIORITY, fit_tab_labels, strip_width

# Tabs shown where sandboxes run (Linux, macOS): Routing stays hidden unless
# routing is on.
VISIBLE = tuple(row for row in ALL_PANELS if row[0] != "routing")
# The counts the fake-data TUI shows (Alerts, Logs, Audit, Activity, AI).
UNREAD = {"alerts": 2, "logs": 2, "audit": 1, "activity": 1, "ai": 2}


def test_every_panel_has_a_label_priority() -> None:
    # An unranked tab tied for last and was the first left a bare key.
    assert {name for name, _key, _label in ALL_PANELS} <= set(LABEL_PRIORITY)


def test_vault_tab_is_named_on_a_160_column_screen(monkeypatch) -> None:
    # 160 columns leave a 146-cell strip: Vault read a bare "K" there while
    # the other tabs had names.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    for active in ("overview", "alerts", "setup", "ai", "vault"):
        labels = fit_tab_labels(VISIBLE, active, UNREAD, 146)
        assert strip_width(tuple(labels.values())) <= 146, (active, labels)
        assert labels["vault"] == "K Vault", (active, labels)
        assert labels["alerts"].startswith("2 Alerts"), (active, labels)


def test_open_vault_tab_is_named_at_80_columns(monkeypatch) -> None:
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    labels = fit_tab_labels(VISIBLE, "vault", UNREAD, 66)
    assert labels["vault"] == "K Vault", labels
    assert strip_width(tuple(labels.values())) <= 66, labels
