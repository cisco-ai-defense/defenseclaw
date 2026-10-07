# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tool-call block/alert levels in the protection center: rows, keys → intents,
pickers, weakening, and one ``b`` journey at 80x24.

The posture rows come from the real ``policy_catalog.scope_postures`` over a
real config, so the TUI is tested against what the catalog hands it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from defenseclaw import policy_catalog  # noqa: E402
from defenseclaw.config import PerConnectorGuardrailConfig, default_config  # noqa: E402
from defenseclaw.tui.policy_panel import level_change_modal, level_preview  # noqa: E402
from defenseclaw.tui.screens.posture_picker import tool_level_choices  # noqa: E402
from defenseclaw.tui.services.policy_state import (  # noqa: E402
    INHERIT,
    TOOL_BLOCK_LEVELS,
    PoliciesPanelModel,
    level_intent,
    level_origin,
    threshold_intent,
)
from test_policies_panel import policies_app, until  # noqa: E402
from test_policy_state import DEFAULT, PERMISSIVE, STRICT  # noqa: E402


def levels_model(*, multi: bool = True, global_block: str = "HIGH") -> PoliciesPanelModel:
    """global blocks HIGH; codex: strict pack, alerts LOW; claudecode: blocks MEDIUM."""
    cfg = default_config()
    cfg.data_dir = cfg.policy_dir = "/nonexistent/dc"
    cfg.guardrail.rule_pack = "default"
    cfg.guardrail.block_at = global_block
    if multi:
        cfg.guardrail.connectors = {
            "codex": PerConnectorGuardrailConfig(rule_pack="strict", alert_at="LOW"),
            "claudecode": PerConnectorGuardrailConfig(block_at="MEDIUM"),
        }
    else:
        cfg.claw.mode = cfg.guardrail.connector = "codex"
    model = PoliciesPanelModel()
    model.set_config(cfg)
    model.apply_policies([DEFAULT, PERMISSIVE, STRICT])
    model.apply_protection(policy_catalog.scope_postures(cfg))
    return model


def test_posture_rows_show_the_catalogs_levels() -> None:
    model = levels_model()
    rows = {row[0]: row for row in model.data_table_rows(80)}
    for posture in model.postures:
        assert rows[posture.scope][2:4] == (posture.block_at, posture.alert_at)
    assert rows["codex"][2:4] == ("HIGH+", "LOW+")  # the global HIGH beats the strict pack
    assert rows["claudecode"][2:4] == ("MEDIUM+", "MEDIUM+")


def test_b_and_a_pick_tool_call_levels_on_posture_and_policy_levels_on_policies() -> None:
    model = levels_model()
    model.handle_key("down")  # claudecode
    for key, kind in (("b", "pick_block"), ("a", "pick_alert")):
        action = model.handle_key(key)
        assert (action.kind, action.connector) == (kind, "claudecode")
    model.select_view("policies")
    model.handle_key("down")
    for key, kind in (("b", "pick_policy_block"), ("a", "pick_policy_alert")):
        action = model.handle_key(key)
        assert (action.kind, action.policy) == (kind, "permissive")
    empty = PoliciesPanelModel()
    empty.set_view("policies")
    assert empty.handle_key("b").kind == "hint"


def test_intents_build_the_exact_argv() -> None:
    assert level_intent("block", "HIGH+", "codex").argv == (
        "defenseclaw",
        "guardrail",
        "block-at",
        "HIGH",
        "--connector",
        "codex",
    )
    assert level_intent("alert", INHERIT).args == ("guardrail", "alert-at", "inherit")
    assert level_intent("alert", "LOW+").args == ("guardrail", "alert-at", "LOW")
    assert threshold_intent("block", "HIGH+", "strict").args == (
        "policy",
        "edit",
        "guardrail",
        "--block-threshold",
        "3",
        "-p",
        "strict",
    )
    with pytest.raises(ValueError):
        level_intent("block", "none")


def test_picker_marks_the_scopes_own_level_and_the_choices_that_loosen() -> None:
    model = levels_model()
    claude = model.scope_row("claudecode")
    current = model.level_current("block", claude)
    weaker = [v for v in (*TOOL_BLOCK_LEVELS, INHERIT) if model.level_change("block", claude, v).weakened()]
    choices = tool_level_choices("block", current, model.level_inherit_text("block", claude), weaker)
    assert [(c.value, c.current, c.weaker) for c in choices] == [
        ("CRITICAL", False, True),
        ("HIGH+", False, True),
        ("MEDIUM+", True, False),
        (INHERIT, False, True),  # back to the global HIGH+
    ]
    codex = model.scope_row("codex")
    assert model.level_current("block", codex) == INHERIT
    assert "HIGH+" in model.level_inherit_text("block", codex)  # it follows the global level
    assert "CRITICAL" in model.level_inherit_text("block", model.scope_row(""))  # the default pack's
    assert level_preview(model, "block", claude, "CRITICAL").startswith("At each severity: CRITICAL block")


def test_a_global_level_reaches_every_connector_without_its_own() -> None:
    model = levels_model()
    global_row = model.scope_row("")
    change = model.level_change("block", global_row, "CRITICAL")
    assert (change.connector, change.value, change.keep_own) == ("", "CRITICAL", ("claudecode",))
    assert [effect.scope for effect in change.weakened()] == ["global", "codex"]
    # Clearing the global value hands codex back to its strict pack: stricter there.
    cleared = model.level_change("block", global_row, INHERIT)
    assert {e.scope: e.after.block_at for e in cleared.effects} == {"global": "CRITICAL", "codex": "MEDIUM+"}
    assert [e.scope for e in cleared.weakened()] == ["global"]


def test_single_connector_install_changes_the_global_level() -> None:
    model = levels_model(multi=False, global_block="")
    codex = model.scope_row("codex")
    assert model.command_connector(codex) == ""
    change = model.level_change("block", codex, "HIGH+")
    assert change.connector == "" and change.effect_for("codex").after.block_at == "HIGH+"
    assert level_change_modal(model, codex, "block", "HIGH+").details[-1] == "Runs: defenseclaw guardrail block-at HIGH"


def test_level_modal_turns_red_only_when_a_scope_loosens() -> None:
    model = levels_model()
    claude, codex, global_row = model.scope_row("claudecode"), model.scope_row("codex"), model.scope_row("")

    def danger(row, kind, choice) -> bool:
        return level_change_modal(model, row, kind, choice).actions[0].danger

    assert danger(claude, "block", INHERIT) is True  # MEDIUM+ → the global HIGH+
    assert danger(codex, "block", "MEDIUM+") is False
    assert danger(global_row, "block", "CRITICAL") is True
    assert danger(global_row, "alert", "LOW+") is False
    # An alert level above the block level only loosens up to the block level.
    assert danger(codex, "alert", "CRITICAL") is True
    assert model.level_change("alert", codex, "CRITICAL").effect_for("codex").after.alert_at == "HIGH+"
    modal = level_change_modal(model, claude, "block", "HIGH+")
    assert modal.details[-1] == "Runs: defenseclaw guardrail block-at HIGH --connector claudecode"


def test_detail_says_where_the_levels_come_from() -> None:
    # The wording the product owner asked for.
    assert level_origin("override", "codex", "strict", "strict") == "set for codex"
    assert level_origin("global", "codex", "strict", "strict") == "set globally"
    assert level_origin("pack", "codex", "strict", "strict") == "from the strict pack"
    model = levels_model()
    codex = model.scope_row("codex")
    model.handle_key("down")
    model.handle_key("down")
    assert model.selected_scope() is codex
    assert model.levels_line(codex) in model.aside()[1]


@pytest.mark.asyncio
async def test_b_on_a_connector_sets_its_block_level(tmp_path, monkeypatch) -> None:
    app, _reads, _captured, runs = policies_app(tmp_path, monkeypatch, multi_connector=True)
    async with app.run_test(size=(80, 24)) as pilot:
        await until(pilot, lambda: app.policy_model.loaded)
        await pilot.press("P", "down", "b")  # codex → block-at picker
        await pilot.press("2", "enter")  # HIGH+: stricter than the pack's CRITICAL
        await pilot.press("enter")  # consequence: one press, nothing weakens
        await until(pilot, lambda: bool(runs))
    assert runs == [("defenseclaw", ("guardrail", "block-at", "HIGH", "--connector", "codex"))]


def test_a_pack_switch_says_when_set_levels_win_over_the_pack() -> None:
    from defenseclaw.tui.policy_panel import rule_pack_change_modal
    from defenseclaw.tui.screens.rule_pack_picker import RulePackChoice
    from defenseclaw.tui.services.policy_state import PackValidation

    valid = PackValidation("valid", rule_count=3, enabled_rule_count=3, rule_file_count=1)

    def held(connector: str, pack: str, **kwargs: object) -> list[str]:
        choice = RulePackChoice(connector, pack, pack, f"/p/guardrail/{pack}", True, valid)
        modal = rule_pack_change_modal(levels_model(**kwargs), choice)  # type: ignore[arg-type]
        return [line for line in modal.details if line.startswith("Tool calls still")]

    # claudecode blocks MEDIUM itself, so the default pack's CRITICAL doesn't apply.
    assert held("claudecode", "default") == [
        "Tool calls still block at MEDIUM+ (not the pack's CRITICAL), as set with block-at / alert-at."
    ]
    # Strict blocks MEDIUM+ anyway: nothing to say.
    assert held("claudecode", "strict") == []
    # Nothing set anywhere: the pack's levels apply.
    assert held("", "strict", multi=False, global_block="") == []
