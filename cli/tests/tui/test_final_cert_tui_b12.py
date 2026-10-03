# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert UX batch 12 (tui): Alerts/Audit hints, Audit target search,
stable tab labels. The batch's Setup gaps (GAP-2058 to GAP-2061, GAP-2072)
were fixed on fix/final-cert-queue too; test_final_cert_tui_b13.py and
test_final_cert_tui_setup_b7.py cover that version."""

from __future__ import annotations

from defenseclaw.models import Event
from defenseclaw.tui.app import PANELS
from defenseclaw.tui.models import HintState
from defenseclaw.tui.panels.audit import AuditPanelModel, _event_field
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.hint_bar import HintEngine
from defenseclaw.tui.widgets.tab_fit import fit_tab_labels, strip_width


def test_tab_labels_stay_put_and_keep_unread_counts_on_wide_strips(monkeypatch) -> None:
    # GAP-2078: at 160 columns other tabs were relabelled on every panel
    # switch. GAP-2077: the Logs and Audit counts showed at 140, not at 160.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    unread = {"alerts": 7, "logs": 64, "audit": 10}
    for width in (86, 106, 126, 146, 160):
        fits = {name: fit_tab_labels(PANELS, name, unread, width) for name, _key, _label in PANELS}
        for active, labels in fits.items():
            assert strip_width(tuple(labels.values())) <= width
            # From 160 columns every tab keeps a name, so a long open name
            # can read "AI Discov…" beside the counts (GAP-2301).
            shown = labels[active].split(" ", 1)[-1]
            title = dict((n, t) for n, _k, t in PANELS)[active]
            assert shown.startswith(title) or (width >= 146 and title.startswith(shown.rstrip("…")))
            for other, other_labels in fits.items():
                for name, _key, _label in PANELS:
                    if name not in {active, other}:
                        assert labels[name] == other_labels[name], (width, active, other, name)
        # The Logs and Audit counts show at every width (GAP-2193: the queue
        # merge dropped them at 80-146 cells).
        assert fits["registries"]["logs"].endswith(("⁶⁴", "(64)")), width
        assert fits["registries"]["audit"].endswith(("¹⁰", "(10)")), width
    # At 160 columns every tab has a name as well.
    assert all(" " in label for label in fits["registries"].values())


def test_alerts_and_audit_hints_match_what_esc_does() -> None:
    # GAP-2074: All plus a search still said "Click All or press Esc to clear".
    engine = HintEngine()
    hint = engine.hint_for(
        HintState(active_panel="alerts", total_alerts=3, filter_active="All severities, search 'UserPromptSubmit'")
    )
    assert "Click All" not in hint and "Esc clears the search" in hint and "h goes back to Actionable" in hint
    hint = engine.hint_for(HintState(active_panel="alerts", total_alerts=3, filter_active="Critical"))
    assert "Esc goes back to Actionable" in hint
    hint = engine.hint_for(HintState(active_panel="audit", filter_active="search 'x'"))
    assert "Click All" not in hint and "Esc clears every filter" in hint


def test_audit_target_search_and_same_target_use_the_shown_target() -> None:
    # GAP-2076: hook_decision rows show "UserPromptSubmit" as TARGET from
    # structured data, but target: search and t ignored them.
    hook = Event(
        id="h", action="connector-hook", target="UserPromptSubmit", details="connector=claudecode action=block"
    )
    decision = Event(id="d", action="hook_decision", structured={"defenseclaw.hook.event": "UserPromptSubmit"})
    assert _event_field(decision, "target") == "userpromptsubmit"
    model = AuditPanelModel()
    model.show_all_events = True
    model.set_events([hook, decision, Event(id="o", action="scan", target="other")])
    model.set_filter("target:UserPromptSubmit")
    assert {event.id for event in model.filtered} == {"h", "d"}
    model.clear_filter()
    model.cursor = [event.id for event in model.filtered].index("d")
    assert model.filter_same_target()
    assert {event.id for event in model.filtered} == {"h", "d"}
