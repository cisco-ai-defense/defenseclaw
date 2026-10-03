# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fixes: tab strip counts and the Registries Sources table."""

from __future__ import annotations

from defenseclaw.tui.app import PANELS
from defenseclaw.tui.panels.registries import RegistriesPanelModel, RegistrySourceRow
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.tab_fit import fit_tab_labels, strip_width


def test_minor_count_takes_other_names_at_80_columns(monkeypatch) -> None:
    # GAP-2342: Skills read "1 Overview ... A" where "1 ... A(1)" fits.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    titles = {name: title for name, _key, title in PANELS}
    for unread, name, badge in (({"activity": 1}, "activity", "A(1)"), ({"logs": 48}, "logs", "8(48)")):
        for active in ("overview", "skills", "setup", "registries"):
            labels = fit_tab_labels(PANELS, active, unread, 66)
            assert strip_width(tuple(labels.values())) <= 66
            assert labels[name] == badge, (active, labels)
            assert labels[active].endswith(titles[active]), (active, labels)


def test_open_tab_keeps_its_full_name_when_another_tab_gets_a_count(monkeypatch) -> None:
    # GAP-2372: at 200 columns "R Registries" became "R Registri…" once
    # Activity got a count.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    base = {"alerts": 171, "logs": 1000, "audit": 579, "ai": 5}
    for width in (172, 174, 176):
        labels = fit_tab_labels(PANELS, "registries", {**base, "activity": 1}, width)
        assert labels["registries"] == "R Registries", (width, labels)
        assert labels["alerts"] == "2 Alerts¹⁷¹" and strip_width(tuple(labels.values())) <= width


def test_sources_table_fits_a_long_id_at_80_columns(tmp_path) -> None:
    # GAP-2365: an 11-character ID cut Last Sync to "2026-10-03 07:".
    model = RegistriesPanelModel(data_dir=tmp_path)
    model.sources = [
        RegistrySourceRow(id="rs3r8-local", kind="file", content="skill", last_sync="2026-10-03T07:45:10Z")
    ]
    columns = model.data_table_columns()
    assert model.data_table_rows()[0][-1] == "2026-10-03 07:45Z"
    assert model.data_table_rows(114)[0][-1] == "2026-10-03 07:45Z"

    def need(rows) -> int:
        return sum(max(map(len, column)) + 2 for column in zip(columns, *rows, strict=True)) - 1

    row = model.data_table_rows(74)[0]
    assert row[0] == "rs3r8-local" and row[-1] == "10-03 07:45Z" and need((row,)) <= 74
    model.sources = [
        RegistrySourceRow(
            id="a-much-longer-registry-id", kind="file", content="skill", last_sync="2026-10-03T07:45:10Z"
        )
    ]
    row = model.data_table_rows(74)[0]
    assert row[0].endswith("…") and row[-1] == "10-03 07:45Z" and need((row,)) <= 74
