# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert UX batch 11 (tui): skill unblock scope, stale status, drawer
result, add-connector mode, ``m`` with one connector, narrow tab bar."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from defenseclaw.commands.cmd_skill import _skill_global_decisions, _skill_list_json_items
from defenseclaw.models import ActionState
from defenseclaw.tui.app import PANELS
from defenseclaw.tui.command_line import command_result_summary, is_command_hint, suggested_next_action
from defenseclaw.tui.panels.setup import SetupPanelModel, SetupWizard, build_wizard_args, wizard_goals
from defenseclaw.tui.services.catalog_state import skill_action_intent, skill_list_to_row
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.tab_fit import fit_tab_labels, strip_width

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixtures import snapshot_app  # noqa: E402


def test_globally_blocked_skill_unblocks_for_every_connector() -> None:
    # GAP-1820: "skill unblock X --connector claudecode" only said the global
    # block stays, and the TUI reported "Done".
    entries = [
        SimpleNamespace(target_name="rev3", connector="", actions=ActionState(install="block", runtime="disable")),
        SimpleNamespace(target_name="peer", connector="codex", actions=ActionState(install="block")),
        SimpleNamespace(target_name="pinned", connector="", actions=ActionState(install="allow")),
    ]
    store = SimpleNamespace(list_actions_by_type=lambda _kind: entries)
    decisions = _skill_global_decisions(store)
    assert decisions == {"rev3"}
    items = _skill_list_json_items([{"name": "rev3"}, {"name": "peer"}], {}, {}, global_decisions=decisions)
    assert items[0]["global_decision"] is True and "global_decision" not in items[1]

    row = skill_list_to_row({"name": "rev3", "actions": {"install": "block", "file": "quarantine"}, "global_decision": True})
    intent = skill_action_intent("u", row, origin="key", connector="claudecode")
    assert intent is not None and intent.args == ("skill", "unblock", "rev3")
    assert intent.label == "unblock skill rev3 (every connector)"
    scoped = skill_list_to_row({"name": "peer", "actions": {"install": "block"}})
    intent = skill_action_intent("u", scoped, origin="key", connector="codex")
    assert intent is not None and intent.args[-2:] == ("--connector", "codex")


def test_setup_drawer_states_the_result_not_the_undo_command() -> None:
    # GAP-1910: the drawer read "defenseclaw guardrail disable --connector
    # claudecode · next: press 0 (Setup) ..." while on Setup.
    lines = [
        "  ✓ claudecode mode=action",
        "  ✓ Claude Code connector setup complete",
        "  Or keep it configured but stop enforcing it:",
        "    defenseclaw guardrail disable --connector claudecode",
    ]
    assert command_result_summary("setup claude-code", lines) == "Claude Code connector setup complete (mode action)"
    assert is_command_hint(lines[-1]) and not is_command_hint(lines[1])
    assert suggested_next_action("setup claude-code", 0, panel="setup") == "press i for readiness"
    assert "0 (Setup)" in suggested_next_action("setup claude-code", 0, panel="overview")


def test_add_connector_form_sets_the_guardrail_mode() -> None:
    # GAP-1957: the add form had no Guardrail Mode, so --mode was never passed.
    cfg = {"guardrail": {"connector": "codex", "connectors": {"codex": {}}}}
    goal = next(goal for goal in wizard_goals(SetupWizard.CONNECTOR_SETUP, cfg) if goal.id == "add")
    model = SetupPanelModel(cfg)
    model.open_wizard_form(SetupWizard.CONNECTOR_SETUP, goal=goal)
    fields = [
        replace(field, value="action") if field.label == "Guardrail Mode" else field for field in model.form_fields
    ]
    assert len(fields) > len([f for f in fields if f.label != "Guardrail Mode"])
    args = build_wizard_args(SetupWizard.CONNECTOR_SETUP, fields, cfg)
    assert args[args.index("--mode") + 1] == "action"


def test_tab_bar_below_80_columns_keeps_the_alerts_count(monkeypatch) -> None:
    # GAP-1998: at 66-75 columns the active tab read "R Reg…" beside a Logs
    # badge, or "R Reg" with the Alerts count dropped. Strip = columns - 14.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    unread = {"alerts": 7, "logs": 50, "audit": 27}
    for active, key in (("registries", "R"), ("sandboxes", "7"), ("overview", "1")):
        previous = 0
        for width in range(50, 66):
            labels = fit_tab_labels(PANELS, active, unread, width)
            assert strip_width(tuple(labels.values())) <= width
            assert labels["alerts"].endswith(("⁷", "(7)")), (active, width, labels["alerts"])
            name = labels[active].removeprefix(key).strip()
            assert len(name) >= previous, (active, width, labels[active])
            previous = len(name)
            if width >= 54:
                assert name, (active, width)
        assert fit_tab_labels(PANELS, active, unread, 60)[active].endswith(
            {"registries": "Registries", "sandboxes": "Sandboxes", "overview": "Overview"}[active]
        )


async def test_status_result_and_filter_prompt_do_not_stick(tmp_path) -> None:
    # GAP-1821: a resize re-stamped "Done: ..." so it followed you to every
    # panel; the filter prompt stayed after Enter left the box. GAP-1986: m on
    # Alerts did nothing with one connector.
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("plugins")
        app._set_status("Done: scan plugin photon.")  # noqa: SLF001
        app.action_switch_panel("runtime")
        assert app.status_text == "Done: scan plugin photon."
        app._status_set_at -= 60  # noqa: SLF001
        app._set_status(app.status_text)  # noqa: SLF001 - what a resize render does
        app.action_switch_panel("audit")
        assert app.status_text == "Ready."

        app.action_switch_panel("skills")
        await pilot.pause()
        assert app._focus_catalog_filter("skills")  # noqa: SLF001
        await pilot.press("enter")
        assert not app.status_text.startswith("Type to filter")

        app.action_switch_panel("alerts")
        await pilot.pause()
        await pilot.press("m")
        assert "nothing to filter by connector" in app.status_text
        sections = dict(app._help_sections())  # noqa: SLF001
        overview = [desc for key, desc in sum(sections.values(), []) if key == "m"]
        assert overview and not any("(Overview, Alerts, Audit, Logs)" in desc for desc in overview)


def test_tab_bar_names_tabs_before_minor_badges_and_brand(tmp_path, monkeypatch) -> None:
    # GAP-2150: at 124-136 strip cells five or six tabs were bare keys while
    # the Logs 999+ / Audit badges and the brand stayed, and a wider strip
    # named fewer tabs than a narrower one.
    from textual.geometry import Size

    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    unread = {"alerts": 22, "audit": 13, "logs": 1000}
    for active in ("registries", "setup", "overview"):
        previous = len(PANELS)
        # From 67 cells (wider than NARROW_STRIP) other tabs keep one label
        # whichever tab is open (GAP-2078); at that step one tab can give up
        # its name, so the check starts there.
        for width in range(tab_fit.NARROW_STRIP + 1, 180):
            labels = fit_tab_labels(PANELS, active, unread, width)
            assert strip_width(tuple(labels.values())) <= width
            bare = sum(" " not in label for label in labels.values())
            assert bare <= previous, (active, width, labels)
            previous = bare
    labels = fit_tab_labels(PANELS, "registries", unread, 136)
    # Other tabs keep one label whichever tab is open (GAP-2078), which
    # costs one name here: three bare keys, not five to seven.
    assert sum(" " not in label for label in labels.values()) <= 3
    assert labels["registries"] == "R Registries" and "²²" in labels["alerts"]

    app = snapshot_app(tmp_path)
    for width, brand in ((150, False), (157, False), (175, True)):
        monkeypatch.setattr(type(app), "size", property(lambda _self, width=width: Size(width, 45)))
        assert bool(app._header_title()) is brand, width  # noqa: SLF001 - brand rule under test.
