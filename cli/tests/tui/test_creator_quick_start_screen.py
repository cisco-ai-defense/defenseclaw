# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Phase 10: ``QuickStartScreen`` rendering smoke tests.

Each renderer is a pure function over ``QuickStartWizardModel`` so
we can pin the output without standing up a Textual ``App``. These
tests guard against:

* Rich markup parser crashes (every dynamic field must be escaped
  via ``rich_escape``).
* Cursor / step indicators lining up with the model.
* Validation banner rendering errors when the wizard is unsavable.
"""

from __future__ import annotations

from defenseclaw.tui.creator.answers import (
    SinkAnswer,
    default_answers,
)
from defenseclaw.tui.creator.wizard import (
    WIZARD_STEPS,
    QuickStartWizardModel,
)
from defenseclaw.tui.screens import quick_start
from defenseclaw.tui.screens.quick_start import (
    _render_allow,
    _render_block,
    _render_posture,
    _render_response,
    _render_review,
    _render_sinks,
)


def _plain(text: object) -> str:
    """Strip Rich style metadata so assertions inspect plain text."""
    return text.plain  # type: ignore[attr-defined]


def test_render_posture_marks_active_choice() -> None:
    model = QuickStartWizardModel()
    model.handle_key("s")  # pin "strict"
    body = _plain(_render_posture(model))
    assert "Strict" in body
    assert "(*) Strict" in body


def test_render_block_includes_category_headers_and_card_titles() -> None:
    body = _plain(_render_block(QuickStartWizardModel()))
    # Group headers from BLOCK_CATEGORIES.
    assert "Data leaks" in body
    assert "Multi-step attack patterns" in body
    # First card's title from BLOCK_CARDS.
    assert "Hardcoded secrets in prompts" in body


def test_render_block_marks_selected_card_with_checkbox() -> None:
    model = QuickStartWizardModel()
    model.goto(1)  # block step
    model.handle_key(" ")  # toggle the first card on
    body = _plain(_render_block(model))
    assert "(x)" in body


def test_render_block_contains_every_block_card_title() -> None:
    """Regression guard for the "we are not showing all rules" bug:
    the dialog used to clip the Multi-step category, leaving 3 cards
    invisible. The body renderer now emits every card; a
    ``VerticalScroll`` wrapper in the screen makes them reachable.
    """

    from defenseclaw.tui.creator.answers import BLOCK_CARDS

    body = _plain(_render_block(QuickStartWizardModel()))
    for card in BLOCK_CARDS:
        assert card.title in body, f"missing block card in render: {card.title}"


def test_block_cursor_line_advances_by_one_when_walking_in_category() -> None:
    """Two consecutive ``down`` presses inside the same category
    should bump the cursor line by exactly one row.
    """

    from defenseclaw.tui.screens.quick_start import _block_cursor_line

    model = QuickStartWizardModel()
    model.goto(1)
    first = _block_cursor_line(model)
    model.handle_key("down")
    second = _block_cursor_line(model)
    assert second - first == 1


def test_block_lines_to_card_idx_is_inverse_of_cursor_line() -> None:
    """For every card index, the inverse map must point back to it
    when keyed by the cursor line. This is the contract that lets a
    click on ``line L`` reliably toggle ``BLOCK_CARDS[mapping[L]]``.
    """

    from defenseclaw.tui.creator.answers import BLOCK_CARDS, BLOCK_DISPLAY_ORDER
    from defenseclaw.tui.screens.quick_start import (
        _block_cursor_line,
        _block_lines_to_card_idx,
    )

    model = QuickStartWizardModel()
    model.goto(1)
    mapping = _block_lines_to_card_idx(model)
    # All card indices must be reachable through the map.
    assert set(mapping.values()) == set(range(len(BLOCK_CARDS)))
    # And the round-trip must be exact for every display position.
    for display_pos in range(len(BLOCK_DISPLAY_ORDER)):
        for _ in range(display_pos):
            model.handle_key("down")
        line = _block_cursor_line(model)
        assert mapping[line] == model.block_cursor()
        model.goto(1)  # reset cursor back to the start


def test_posture_lines_to_idx_emits_one_entry_per_posture() -> None:
    from defenseclaw.tui.creator.answers import POSTURES
    from defenseclaw.tui.screens.quick_start import _posture_lines_to_idx

    mapping = _posture_lines_to_idx(QuickStartWizardModel())
    assert sorted(mapping.values()) == list(range(len(POSTURES)))


def test_response_lines_to_idx_emits_one_entry_per_response() -> None:
    from defenseclaw.tui.creator.answers import RESPONSES
    from defenseclaw.tui.screens.quick_start import _response_lines_to_idx

    mapping = _response_lines_to_idx(QuickStartWizardModel())
    assert sorted(mapping.values()) == list(range(len(RESPONSES)))


def test_allow_lines_to_idx_only_active_when_in_allow_mode() -> None:
    from defenseclaw.tui.creator.answers import ALLOW_CARDS
    from defenseclaw.tui.screens.quick_start import _allow_lines_to_idx

    model = QuickStartWizardModel()
    model.goto(2)
    assert sorted(_allow_lines_to_idx(model).values()) == list(range(len(ALLOW_CARDS)))
    model.handle_key("tab")  # -> domain
    assert _allow_lines_to_idx(model) == {}


def test_sinks_lines_to_idx_emits_one_entry_per_sink_row() -> None:
    from defenseclaw.tui.creator.answers import SINK_CARDS
    from defenseclaw.tui.screens.quick_start import _sinks_lines_to_idx

    mapping = _sinks_lines_to_idx(QuickStartWizardModel())
    assert sorted(mapping.values()) == list(range(len(SINK_CARDS)))


def test_block_cursor_line_jumps_when_crossing_category_boundary() -> None:
    """Crossing a category boundary should add three rows (the new
    category's title + blurb + blank) on top of the one-card step.
    """

    from defenseclaw.tui.screens.quick_start import _block_cursor_line
    from defenseclaw.tui.creator.answers import BLOCK_CARDS

    model = QuickStartWizardModel()
    model.goto(1)
    # Walk forward until the active card and the next card are in
    # different categories.
    for _ in range(len(BLOCK_CARDS)):
        cur_card = BLOCK_CARDS[model.block_cursor()]
        line_before = _block_cursor_line(model)
        model.handle_key("down")
        next_card = BLOCK_CARDS[model.block_cursor()]
        line_after = _block_cursor_line(model)
        if cur_card.category != next_card.category:
            assert line_after - line_before >= 4
            return
    raise AssertionError("never crossed a category boundary while walking")


def test_render_allow_shows_three_regions_and_pending_input() -> None:
    model = QuickStartWizardModel()
    model.goto(2)  # allow
    model.handle_key("tab")  # -> domain mode
    for ch in "*.corp.example":
        model.handle_key(ch)
    body = _plain(_render_allow(model))
    assert "Region: Allow domains" in body
    assert "*.corp.example" in body
    # Cursor caret rendered.
    assert ">> *.corp.example_" in body


def test_render_response_marks_active_choice() -> None:
    model = QuickStartWizardModel()
    model.goto(3)
    model.handle_key("up")
    model.handle_key("enter")
    body = _plain(_render_response(model))
    assert "(*) Log silently" in body


def test_render_sinks_shows_url_and_secret_fields_when_enabled() -> None:
    """Toggling Slack on must reveal the URL and secret_env cells."""
    model = QuickStartWizardModel()
    model.answers.sinks["slack"] = SinkAnswer(
        enabled=True,
        url="https://hooks.slack.com/services/T/B/X",
        secret_env="SLACK_WEBHOOK_SECRET",
    )
    body = _plain(_render_sinks(model))
    assert "https://hooks.slack.com/services/T/B/X" in body
    assert "SLACK_WEBHOOK_SECRET" in body


def test_render_review_lists_zero_findings_for_default_policy() -> None:
    body = _plain(_render_review(QuickStartWizardModel()))
    assert "name:" in body
    assert "basedOn:" in body
    assert "No validation findings" in body or "warning(s)" in body


def test_render_review_surfaces_validation_errors() -> None:
    """Inject a known-bad webhook to trigger
    ENV_NAME_LIKELY_SECRET, then confirm the review banner shows it.
    """
    model = QuickStartWizardModel()
    model.answers.sinks["splunk"] = SinkAnswer(
        enabled=True,
        url="https://splunk.example.com:8088/services/collector/event",
        secret_env="ghp_" + "A" * 36,
    )
    body = _plain(_render_review(model))
    assert "validation error" in body
    assert "ENV_NAME_LIKELY_SECRET" in body


def test_render_handlers_escape_user_supplied_strings() -> None:
    """Anything the operator can type into the wizard must reach
    Rich via ``rich_escape`` so brackets / markup don't trigger
    a ``MarkupError``."""
    model = QuickStartWizardModel()
    model.goto(2)
    model.handle_key("tab")  # domain mode
    for ch in "[evil]":  # bracketed input would crash Rich without escape
        model.handle_key(ch)
    model.handle_key("enter")
    body = _plain(_render_allow(model))
    assert "[evil]" in body  # rendered as literal text


def test_screen_class_can_be_instantiated_with_default_answers() -> None:
    """Smoke check: the ModalScreen subclass shouldn't raise during
    construction. We can't easily run the full render loop without
    a Textual App harness, but instantiation alone exercises the
    CSS string + binding declarations."""
    screen = quick_start.QuickStartScreen(default_answers())
    assert screen is not None
    # Internal model wired correctly.
    assert screen._model.step.id == "posture"


def test_wizard_step_count_matches_screen_module_constant() -> None:
    """Pin the contract: the screen and the model both reference the
    same WIZARD_STEPS source."""
    assert len(WIZARD_STEPS) == 6
    assert tuple(s.id for s in WIZARD_STEPS) == (
        "posture",
        "block",
        "allow",
        "response",
        "sinks",
        "review",
    )
