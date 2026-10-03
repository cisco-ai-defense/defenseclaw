# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fix batch fcx-b6: tab bar, plugins detail, registries confirms."""

from __future__ import annotations

from types import SimpleNamespace

from defenseclaw.tui.app import PANELS
from defenseclaw.tui.panels.registries import (
    RegistriesPanelModel,
    approve_entry_intent,
    reject_entry_intent,
)
from defenseclaw.tui.services.catalog_state import PluginRow, PluginScanSummary, catalog_detail_text
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.tab_fit import fit_tab_labels, strip_width
from rich.text import Text


def test_wider_strip_never_shortens_the_active_tab_name(monkeypatch) -> None:
    # GAP-2020: 160 columns read "R Reg…" while 140 and 80 read "R Registries".
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    for name, key, title in PANELS:
        previous = 0
        for width in range(66, 190):
            labels = fit_tab_labels(PANELS, name, {"alerts": 9}, width)
            assert strip_width(tuple(labels.values())) <= width
            shown = len(labels[name].removeprefix(key).split(" (")[0].strip(" …⁰¹²³⁴⁵⁶⁷⁸⁹"))
            assert shown >= previous, (name, width, labels[name])
            previous = shown
    labels = fit_tab_labels(PANELS, "registries", {"alerts": 9}, 146)
    assert labels["registries"] == "R Registries"
    assert all(label != key for (name, key, _title), label in zip(PANELS, labels.values(), strict=True))


def test_rejected_plugin_detail_says_what_it_means_and_where_the_findings_are() -> None:
    # GAP-2048: no findings pointer, no next step, "Status enabled  Enabled
    # yes", and a description cut off mid-sentence.
    row = PluginRow(
        id="photon",
        name="photon-platform",
        description="word " * 80,
        version="0.3.0",
        origin="bundled",
        status="enabled",
        enabled=True,
        verdict="rejected",
        scan=PluginScanSummary(clean=False, max_severity="HIGH", total_findings=5),
        connector="hermes",
    )
    text = Text.from_markup(catalog_detail_text(row)).plain
    assert "Enabled  yes" not in text
    assert "still loads until you act (o, then Quarantine)" in text
    assert "(q " not in text  # GAP-2111: q is not a Plugins row key
    assert "defenseclaw plugin scan photon --connector hermes" in text
    description = [line for line in text.splitlines() if line.strip().startswith("word")][0]
    assert description.endswith("…") and len(description.strip()) <= 160


def test_registry_reject_approve_confirms_say_the_effect_and_e_works_on_sources(tmp_path) -> None:
    # GAP-2051: Reject/Approve confirms said only "can change DefenseClaw
    # state"; e on Sources answered "(no entry selected)".
    from defenseclaw.config import RegistrySource

    entry = SimpleNamespace(source_id="sf1-local", name="deepwiki", type="mcp")
    assert "never promoted" in reject_entry_intent(entry).consequence
    assert "promoted into policy now" in approve_entry_intent(entry).consequence
    model = RegistriesPanelModel(
        data_dir=tmp_path,
        sources=[RegistrySource(id="sf1-local", kind="file", content="mcp", enabled=True)],
    )
    action = model.handle_key("e")
    assert action.intent is not None, action.hint
    assert action.intent.args[:4] == ("registry", "require", "--type", "mcp")
