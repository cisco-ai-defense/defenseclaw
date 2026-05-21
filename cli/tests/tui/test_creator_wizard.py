# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Phase 10: Quick Start wizard state-machine tests.

Tests the pure-Python wizard model so we get end-to-end coverage
of every keystroke without spinning up a Textual ``App``. The
matching ``ModalScreen`` in ``screens/quick_start.py`` is then a
trivial wrapper around this state machine.
"""

from __future__ import annotations

from defenseclaw.tui.creator.answers import (
    ALLOW_CARDS,
    BLOCK_CARDS,
    SINK_CARDS,
    SinkAnswer,
)
from defenseclaw.tui.creator.wizard import (
    WIZARD_STEPS,
    QuickStartWizardModel,
)


def test_initial_state_is_first_step_default_posture() -> None:
    model = QuickStartWizardModel()
    assert model.step.id == "posture"
    assert model.is_first
    assert not model.is_last
    assert model.answers.posture == "default"


def test_ctrl_right_advances_through_steps() -> None:
    model = QuickStartWizardModel()
    seen = [model.step.id]
    for _ in range(len(WIZARD_STEPS) - 1):
        model.handle_key("ctrl+right")
        seen.append(model.step.id)
    assert seen == [s.id for s in WIZARD_STEPS]
    assert model.is_last


def test_ctrl_left_walks_back_one_step() -> None:
    model = QuickStartWizardModel()
    model.handle_key("ctrl+right")
    assert model.step.id == "block"
    model.handle_key("ctrl+left")
    assert model.step.id == "posture"
    assert model.is_first


def test_ctrl_left_at_first_step_is_no_op() -> None:
    model = QuickStartWizardModel()
    action = model.handle_key("ctrl+left")
    assert action.outcome == "ignored"
    assert model.is_first


def test_ctrl_right_at_last_step_is_no_op() -> None:
    model = QuickStartWizardModel()
    model.goto(len(WIZARD_STEPS) - 1)
    assert model.is_last
    action = model.handle_key("ctrl+right")
    assert action.outcome == "ignored"


def test_escape_cancels_from_any_step() -> None:
    for step_idx in range(len(WIZARD_STEPS)):
        model = QuickStartWizardModel()
        model.goto(step_idx)
        action = model.handle_key("escape")
        assert action.outcome == "cancel"
        assert action.policy is None


def test_posture_step_arrow_keys_move_cursor() -> None:
    model = QuickStartWizardModel()
    assert model.selected_posture().id == "default"
    model.handle_key("up")
    assert model.selected_posture().id == "permissive"
    model.handle_key("down")
    model.handle_key("down")
    assert model.selected_posture().id == "strict"


def test_posture_enter_persists_selection_to_answers() -> None:
    model = QuickStartWizardModel()
    model.handle_key("up")
    model.handle_key("enter")
    assert model.answers.posture == "permissive"
    # Enter on a radio-style step also advances the wizard so the
    # operator gets a single linear keypath through the six steps.
    assert model.step.id == "block"


def test_posture_letter_shortcuts_pin_specific_choices() -> None:
    """``p``, ``d``, ``s`` jump straight to a specific posture and
    persist it without an extra Enter press."""
    model = QuickStartWizardModel()
    model.handle_key("s")
    assert model.answers.posture == "strict"
    model.handle_key("p")
    assert model.answers.posture == "permissive"
    model.handle_key("d")
    assert model.answers.posture == "default"
    # Letter shortcuts pick without advancing - they're meant for
    # quick re-runs / corrections, not the linear walkthrough path.
    assert model.step.id == "posture"


def test_posture_enter_returns_advance_outcome() -> None:
    """The screen layer keys off ``WizardOutcome.advance`` to refresh
    the body view when the wizard moves a step. Posture's Enter must
    return that outcome so the modal repaints, not just ``handled``.
    """

    from defenseclaw.tui.creator.wizard import QuickStartWizardModel

    model = QuickStartWizardModel()
    action = model.handle_key("enter")
    assert action.outcome == "advance"


def test_response_enter_returns_advance_outcome() -> None:
    from defenseclaw.tui.creator.wizard import QuickStartWizardModel

    model = QuickStartWizardModel()
    model.goto(3)
    action = model.handle_key("enter")
    assert action.outcome == "advance"


def test_block_step_toggles_card_id_into_answers() -> None:
    model = QuickStartWizardModel()
    model.goto(1)  # block
    model.handle_key(" ")
    first_card = BLOCK_CARDS[0].id
    assert first_card in model.answers.block
    model.handle_key("enter")
    assert first_card not in model.answers.block


def test_block_step_arrow_keys_clamp_to_bounds() -> None:
    model = QuickStartWizardModel()
    model.goto(1)
    for _ in range(50):
        model.handle_key("down")
    assert model.block_cursor() == len(BLOCK_CARDS) - 1
    for _ in range(50):
        model.handle_key("up")
    assert model.block_cursor() == 0


def test_block_step_down_walks_display_order_not_declaration_order() -> None:
    """The block cards live in declaration order in the tuple but
    render grouped by category. Up/Down must walk *display* order so
    the cursor doesn't visibly jump between categories.
    """

    from defenseclaw.tui.creator.answers import BLOCK_CARDS, BLOCK_DISPLAY_ORDER

    model = QuickStartWizardModel()
    model.goto(1)
    assert model.block_cursor() == BLOCK_DISPLAY_ORDER[0]
    model.handle_key("down")
    assert model.block_cursor() == BLOCK_DISPLAY_ORDER[1]
    # Walk a few more to ensure each step matches the next display-
    # order index and never re-introduces declaration-order jumps.
    for i in range(2, min(6, len(BLOCK_DISPLAY_ORDER))):
        model.handle_key("down")
        assert model.block_cursor() == BLOCK_DISPLAY_ORDER[i]
    # The cursor should never land on an index outside ``BLOCK_CARDS``.
    assert 0 <= model.block_cursor() < len(BLOCK_CARDS)


def test_click_posture_picks_and_advances() -> None:
    """Click handler for radio-style steps must mirror the keyboard
    Enter behaviour: pick + advance in one shot.
    """

    from defenseclaw.tui.creator.answers import POSTURES

    model = QuickStartWizardModel()
    action = model.click_posture(2)
    assert model.answers.posture == POSTURES[2].id
    assert action.outcome == "advance"
    assert model.step.id == "block"


def test_click_block_card_toggles_without_advancing() -> None:
    from defenseclaw.tui.creator.answers import BLOCK_CARDS

    model = QuickStartWizardModel()
    model.goto(1)
    target = 5  # arbitrary in-range index
    action = model.click_block_card(target)
    assert action.outcome == "handled"
    assert BLOCK_CARDS[target].id in model.answers.block
    assert model.step.id == "block"
    # Click again unselects.
    model.click_block_card(target)
    assert BLOCK_CARDS[target].id not in model.answers.block


def test_click_response_picks_and_advances() -> None:
    from defenseclaw.tui.creator.answers import RESPONSES

    model = QuickStartWizardModel()
    model.goto(3)
    action = model.click_response(0)
    assert model.answers.response == RESPONSES[0].id
    assert action.outcome == "advance"
    assert model.step.id == "sinks"


def test_click_allow_card_toggles_in_allow_region() -> None:
    from defenseclaw.tui.creator.answers import ALLOW_CARDS

    model = QuickStartWizardModel()
    model.goto(2)
    # Switch the cursor away from the toggle region; the click should
    # still set it back to ``allow`` mode and toggle.
    model.handle_key("tab")
    assert model.allow_cursor_state().mode == "domain"
    action = model.click_allow_card(0)
    assert action.outcome == "handled"
    assert ALLOW_CARDS[0].id in model.answers.allow
    assert model.allow_cursor_state().mode == "allow"


def test_click_sink_card_toggles_enabled_flag() -> None:
    """A click on a sink row flips its ``enabled`` state. Pick the
    second card (``langfuse``) so the test isn't sensitive to the
    default-on behaviour of ``local_file``.
    """

    from defenseclaw.tui.creator.answers import SINK_CARDS

    model = QuickStartWizardModel()
    model.goto(4)
    target = SINK_CARDS[1].id
    initial = model.answers.sinks[target].enabled
    model.click_sink_card(1)
    assert model.answers.sinks[target].enabled is not initial
    model.click_sink_card(1)
    assert model.answers.sinks[target].enabled is initial


def test_click_actions_ignore_out_of_range_indices() -> None:
    model = QuickStartWizardModel()
    assert model.click_posture(99).outcome == "ignored"
    assert model.click_block_card(-1).outcome == "ignored"
    assert model.click_response(99).outcome == "ignored"
    assert model.click_allow_card(99).outcome == "ignored"
    assert model.click_sink_card(99).outcome == "ignored"


def test_block_display_order_groups_by_category_in_render_order() -> None:
    """``BLOCK_DISPLAY_ORDER`` should walk every category in
    ``BLOCK_CATEGORIES`` order and emit each category's cards in
    declaration order. This is the contract that keeps render and
    navigation locked together.
    """

    from defenseclaw.tui.creator.answers import (
        BLOCK_CARDS,
        BLOCK_CATEGORIES,
        BLOCK_DISPLAY_ORDER,
    )

    seen_categories: list[str] = []
    last_cat = ""
    for idx in BLOCK_DISPLAY_ORDER:
        cat = BLOCK_CARDS[idx].category
        if cat != last_cat:
            seen_categories.append(cat)
            last_cat = cat
    expected = [cat.id for cat in BLOCK_CATEGORIES if any(
        c.category == cat.id for c in BLOCK_CARDS
    )]
    assert seen_categories == expected
    # Every card must appear exactly once.
    assert sorted(BLOCK_DISPLAY_ORDER) == list(range(len(BLOCK_CARDS)))


def test_allow_step_tab_cycles_through_modes() -> None:
    model = QuickStartWizardModel()
    model.goto(2)  # allow
    cur = model.allow_cursor_state()
    assert cur.mode == "allow"
    model.handle_key("tab")
    assert cur.mode == "domain"
    model.handle_key("tab")
    assert cur.mode == "first_party"
    model.handle_key("tab")
    assert cur.mode == "allow"


def test_allow_toggles_persist_card_ids() -> None:
    model = QuickStartWizardModel()
    model.goto(2)
    model.handle_key("enter")
    assert ALLOW_CARDS[0].id in model.answers.allow


def test_allow_freeform_input_collects_domain_after_enter() -> None:
    model = QuickStartWizardModel()
    model.goto(2)
    model.handle_key("tab")  # -> domain mode
    for ch in "*.corp.example":
        model.handle_key(ch)
    model.handle_key("enter")
    assert "*.corp.example" in model.answers.domains_extra
    # Pending input cleared after enter.
    assert model.allow_cursor_state().domain_input == ""


def test_allow_freeform_input_strips_blank_entries() -> None:
    """Trying to add a blank entry shouldn't pollute the list."""
    model = QuickStartWizardModel()
    model.goto(2)
    model.handle_key("tab")
    model.handle_key(" ")
    model.handle_key(" ")
    model.handle_key("enter")
    assert model.answers.domains_extra == []


def test_allow_freeform_backspace_removes_last_char() -> None:
    model = QuickStartWizardModel()
    model.goto(2)
    model.handle_key("tab")
    for ch in "abc":
        model.handle_key(ch)
    model.handle_key("backspace")
    assert model.allow_cursor_state().domain_input == "ab"


def test_allow_freeform_delete_pops_last_committed_item() -> None:
    """``delete`` removes the last committed entry, used as an
    "undo last add" affordance in the docs Creator."""
    model = QuickStartWizardModel()
    model.goto(2)
    model.handle_key("tab")
    for ch in "x.com":
        model.handle_key(ch)
    model.handle_key("enter")
    model.handle_key("delete")
    assert model.answers.domains_extra == []


def test_allow_freeform_dedupes_repeat_adds() -> None:
    model = QuickStartWizardModel()
    model.goto(2)
    model.handle_key("tab")
    for ch in "x.com":
        model.handle_key(ch)
    model.handle_key("enter")
    for ch in "x.com":
        model.handle_key(ch)
    model.handle_key("enter")
    assert model.answers.domains_extra == ["x.com"]


def test_response_step_persists_choice() -> None:
    model = QuickStartWizardModel()
    model.goto(3)
    model.handle_key("up")
    model.handle_key("enter")
    assert model.answers.response == "log_only"
    # Same advance-on-Enter contract as the posture step.
    assert model.step.id == "sinks"


def test_sinks_step_toggle_flips_enabled() -> None:
    model = QuickStartWizardModel()
    model.goto(4)
    # Row 0 = local_file, default-on. Pressing space toggles it off.
    model.handle_key(" ")
    assert model.answers.sinks[SINK_CARDS[0].id].enabled is False


def test_sinks_step_left_right_move_cursor_within_row() -> None:
    """The Slack row has 3 cells (toggle, URL, secret_env). Moving
    right walks through them and stops at the last cell."""
    model = QuickStartWizardModel()
    model.goto(4)
    # Step down to "slack" (id=3 in SINK_CARDS).
    slack_index = next(
        i for i, c in enumerate(SINK_CARDS) if c.id == "slack"
    )
    for _ in range(slack_index):
        model.handle_key("down")
    cur = model.sink_cursor_state()
    assert cur.row == slack_index
    assert cur.cell == 0
    model.handle_key("right")
    assert cur.cell == 1
    model.handle_key("right")
    assert cur.cell == 2
    model.handle_key("right")
    assert cur.cell == 2  # clamped


def test_sinks_step_typing_into_url_field_persists() -> None:
    model = QuickStartWizardModel()
    model.goto(4)
    slack_index = next(
        i for i, c in enumerate(SINK_CARDS) if c.id == "slack"
    )
    for _ in range(slack_index):
        model.handle_key("down")
    model.handle_key("right")  # cell 1 = URL field
    for ch in "https://example.com":
        model.handle_key(ch)
    assert model.answers.sinks["slack"].url == "https://example.com"


def test_review_step_save_returns_policy_when_savable() -> None:
    """Default answers produce a savable policy. The review step's
    Enter binding should return ``save`` with the derived policy."""
    model = QuickStartWizardModel()
    model.goto(len(WIZARD_STEPS) - 1)
    action = model.handle_key("enter")
    assert action.outcome == "save"
    assert action.policy is not None
    assert action.policy.name == "default"


def test_review_step_does_not_save_when_validators_disagree() -> None:
    """Inject a draft that we know fails validation (broken Cisco
    AID env-var name) and confirm the wizard refuses to save."""
    model = QuickStartWizardModel()
    model.goto(len(WIZARD_STEPS) - 1)
    # Force a validation error by writing a definitely-bad
    # secret_env value into a webhook the apply mapper will emit.
    model.answers.sinks["splunk"] = SinkAnswer(
        enabled=True,
        url="https://splunk.example.com:8088/services/collector/event",
        secret_env="ghp_" + "A" * 36,  # looks like a literal secret
    )
    assert not model.is_savable()
    action = model.handle_key("enter")
    assert action.outcome == "ignored"


def test_ctrl_s_saves_from_any_step_when_valid() -> None:
    """Power-user shortcut: ``ctrl+s`` short-circuits to save from
    any step in the wizard, not just Review."""
    model = QuickStartWizardModel()
    action = model.handle_key("ctrl+s")
    assert action.outcome == "save"
    assert action.policy is not None
