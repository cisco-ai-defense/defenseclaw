# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert UX batch 12 (tui): success card wording, Setup readiness and
form wording, Setup group nav, API keys hint and remove form, the Setup card
after help, Alerts/Audit hints, Audit target search, stable tab labels."""

from __future__ import annotations

import sys
from pathlib import Path

from defenseclaw.models import Event
from defenseclaw.tui.app import PANELS
from defenseclaw.tui.models import HintState
from defenseclaw.tui.panels import setup_keys
from defenseclaw.tui.panels.audit import AuditPanelModel, _event_field
from defenseclaw.tui.panels.setup import SetupPanelModel, SetupWizard, build_wizard_args, wizard_goals
from defenseclaw.tui.panels.setup_catalog import setup_detail_pairs
from defenseclaw.tui.services.setup_state import CredentialRow, CredentialSnapshot
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.hint_bar import HintEngine
from defenseclaw.tui.widgets.tab_fit import fit_tab_labels, strip_width

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixtures import snapshot_app  # noqa: E402


def test_tab_labels_stay_put_and_keep_unread_counts_on_wide_strips(monkeypatch) -> None:
    # GAP-2078: at 160 columns other tabs were relabelled on every panel
    # switch. GAP-2077: the Logs and Audit counts showed at 140, not at 160.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    unread = {"alerts": 7, "logs": 64, "audit": 10}
    for width in (86, 106, 126, 146, 160):
        fits = {name: fit_tab_labels(PANELS, name, unread, width) for name, _key, _label in PANELS}
        for active, labels in fits.items():
            assert strip_width(tuple(labels.values())) <= width
            assert labels[active].split(" ", 1)[-1].startswith(dict((n, t) for n, _k, t in PANELS)[active])
            for other, other_labels in fits.items():
                for name, _key, _label in PANELS:
                    if name not in {active, other}:
                        assert labels[name] == other_labels[name], (width, active, other, name)
        assert "⁶⁴" in fits["registries"]["logs"] and "¹⁰" in fits["registries"]["audit"], width


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


def test_setup_readiness_form_and_keys_wording() -> None:
    # GAP-2059: readiness rows split "Active Connector:" from the name; form
    # hints only repeated the field name; goal texts were jargon.
    model = SetupPanelModel({"config_version": 8, "guardrail": {"connectors": ["claudecode"]}})
    labels = [label for label, _value in setup_detail_pairs(model)]
    assert not any(label.startswith("Active Connector:") for label in labels)
    assert all(len(label) <= 22 for label in labels if label.startswith("Connector "))
    rerun = next(
        goal for goal in wizard_goals(SetupWizard.CONNECTOR_SETUP) if goal.fields[-1:] == ("Verify After Setup",)
    )
    model.open_wizard_form(SetupWizard.CONNECTOR_SETUP, goal=rerun)
    hints = {field.label: field.hint for field in model.form_fields}
    assert "observe" in hints["Guardrail Mode"] and "Proxy connectors only" in hints["Scanner Mode"]
    assert not any(hint.startswith(("Select ", "Toggle ")) for hint in hints.values())
    summaries = " ".join(goal.summary for goal in wizard_goals(SetupWizard.TOKEN_ROTATION))
    assert "distinct connector-scoped" not in summaries and "narrows" not in summaries

    # GAP-2061: "? all keys" read as "show every API key"; r was hidden; the
    # remove form previewed "keys remove '' --yes" and wanted a typed name.
    hint = setup_keys.keys_hint("wizards", {"credentials"})
    assert len(hint) <= setup_keys.HINT_WIDTH, hint
    assert "Enter open" in hint and "r reload" in hint and hint.endswith("? help")
    model.credential_snapshot = CredentialSnapshot(
        rows=(CredentialRow("OPENAI_API_KEY", source="dotenv", set=True), CredentialRow("SHELL_KEY", source="env"))
    )
    remove = next(goal for goal in wizard_goals(SetupWizard.CREDENTIALS) if goal.presets.get("@Action") == "remove")
    model.open_wizard_form(SetupWizard.CREDENTIALS, goal=remove)
    env = next(field for field in model.form_fields if field.label == "Env Name")
    assert env.kind == "choice" and env.options == ("OPENAI_API_KEY",)
    blank = [field.with_value("") if field.label == "Env Name" else field for field in model.form_fields]
    assert build_wizard_args(SetupWizard.CREDENTIALS, blank) == ("keys", "remove", "<ENV_NAME>", "--yes")


async def test_setup_80x24_nav_card_after_help_and_success_card(tmp_path) -> None:
    # GAP-2060: Right on the last group wrapped to the first instead of the
    # listed Config editor. GAP-2072: after ? / Esc the card lost its
    # "… i details" ending. GAP-2058: the success card said "q to clear"
    # but hid itself, taking its result with it.
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("0")
        await pilot.press("down", "up")
        await pilot.pause()
        before = str(app.query_one("#detail-panel-body").render())
        assert before.endswith("… i details")
        await pilot.press("question_mark")
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        await pilot.pause()
        assert str(app.query_one("#detail-panel-body").render()) == before

        for _ in range(6):
            if app.setup_model.mode == "config":
                break
            await pilot.press("right")
        assert app.setup_model.mode == "config"

        app._strip_running("keys list")  # noqa: SLF001
        app._strip_output("3 credentials, 1 required, all set")  # noqa: SLF001
        app._strip_finished(exit_code=0, duration=0.1)  # noqa: SLF001
        assert "hides in" in str(app.query_one("#command-progress-hint").render())
        app._auto_hide_success_strip(app._strip_auto_hide_token)  # noqa: SLF001
        assert app.query_one("#command-progress").has_class("hidden")
        assert app.status_text.startswith("keys list: ")
