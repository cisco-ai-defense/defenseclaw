# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Quick Start wizard state machine.

The Textual ``ModalScreen`` in ``screens/quick_start.py`` is a thin
shell around this class. Putting the state machine here lets the
test suite pin every cursor-movement / toggle / back-next /
validation rule without spinning up a Textual ``App``.

Mirrors the six-step flow the docs Creator uses:

1. Posture (radio)
2. Block (multi-select grouped by category)
3. Allow (multi-select + free-form globs/domains)
4. Response (radio)
5. Sinks (toggle + URL/secret_env per row)
6. Review (summary, validator findings, save/cancel)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from defenseclaw.tui.creator.answers import (
    ALLOW_CARDS,
    BLOCK_CARDS,
    BLOCK_DISPLAY_ORDER,
    POSTURES,
    RESPONSES,
    SINK_CARDS,
    Answers,
    PostureCard,
    ResponseCard,
    SinkAnswer,
    SinkCard,
    default_answers,
)
from defenseclaw.tui.creator.apply import apply_answers
from defenseclaw.tui.creator.types import Policy, ValidationFinding
from defenseclaw.tui.creator.validators import summarize, validate_policy

StepId = Literal["posture", "block", "allow", "response", "sinks", "review"]
StepKind = Literal["question", "review"]
WizardOutcome = Literal["handled", "advance", "back", "save", "cancel", "ignored"]
SinkFieldKey = Literal["url", "secret_env"]
AllowMode = Literal["allow", "domain", "first_party"]


@dataclass(frozen=True)
class WizardStepDescriptor:
    id: StepId
    label: str
    kind: StepKind


WIZARD_STEPS: tuple[WizardStepDescriptor, ...] = (
    WizardStepDescriptor("posture", "Posture", "question"),
    WizardStepDescriptor("block", "Block", "question"),
    WizardStepDescriptor("allow", "Allow", "question"),
    WizardStepDescriptor("response", "Response", "question"),
    WizardStepDescriptor("sinks", "Sinks", "question"),
    WizardStepDescriptor("review", "Review", "review"),
)


@dataclass
class WizardAction:
    """Result of feeding a key into the wizard.

    ``outcome`` tells the screen layer what to do next; ``policy``
    is populated only on ``"save"`` so the caller can lift it into
    the surrounding Policy panel without re-running the apply mapper.
    """

    outcome: WizardOutcome
    policy: Policy | None = None


@dataclass
class _SinkCursor:
    """Cursor state inside the Sinks step.

    Each row has 1 (just the toggle) or 3 cells (toggle, URL,
    secret_env). ``cell`` is the column index; ``row`` is bounded
    by ``len(SINK_CARDS) - 1``.
    """

    row: int = 0
    cell: int = 0


@dataclass
class _AllowCursor:
    """Cursor state inside the Allow step.

    The Allow step has three logical regions: the toggle list, the
    domain free-form input, and the first-party glob input. ``mode``
    tells the screen which region is focused; ``index`` is the
    cursor position inside the toggle list.
    """

    mode: AllowMode = "allow"
    index: int = 0
    domain_input: str = ""
    first_party_input: str = ""


@dataclass
class _PostureSelection:
    index: int = 1  # default = "default"

    def move(self, delta: int) -> None:
        self.index = max(0, min(len(POSTURES) - 1, self.index + delta))

    def set(self, index: int) -> None:
        self.index = max(0, min(len(POSTURES) - 1, index))

    def value(self):
        return POSTURES[self.index].id


@dataclass
class _ResponseSelection:
    index: int = 1  # default = "alert"

    def move(self, delta: int) -> None:
        self.index = max(0, min(len(RESPONSES) - 1, self.index + delta))

    def set(self, index: int) -> None:
        self.index = max(0, min(len(RESPONSES) - 1, index))

    def value(self):
        return RESPONSES[self.index].id


def _next_allow_mode(current: AllowMode) -> AllowMode:
    if current == "allow":
        return "domain"
    if current == "domain":
        return "first_party"
    return "allow"


def _sink_cell_count(card: SinkCard) -> int:
    """Total focusable cells in a sink row.

    1 for the enable toggle + 1 per config field. Toggle and each
    field are independent horizontal stops so left/right/tab navigate
    predictably.
    """
    return 1 + len(card.config_fields)


class QuickStartWizardModel:
    """State machine for the Quick Start interview.

    Single source of truth for ``Answers``, current step index, and
    per-step cursors. The screen layer just calls
    ``model.handle_key(<key>)`` and renders ``model.view()``.
    """

    def __init__(self, answers: Answers | None = None) -> None:
        self._answers = answers if answers is not None else default_answers()
        self._step_idx = 0
        self._posture_cursor = _PostureSelection()
        self._block_cursor = 0
        self._allow_cursor = _AllowCursor()
        self._response_cursor = _ResponseSelection()
        self._sink_cursor = _SinkCursor()

    # --- public read-only accessors --------------------------------

    @property
    def answers(self) -> Answers:
        """Current ``Answers`` snapshot.

        Returned by reference: callers should treat it as read-only
        between key presses. The wizard mutates it in place.
        """
        return self._answers

    @property
    def step_idx(self) -> int:
        return self._step_idx

    @property
    def step(self) -> WizardStepDescriptor:
        return WIZARD_STEPS[self._step_idx]

    @property
    def is_first(self) -> bool:
        return self._step_idx == 0

    @property
    def is_last(self) -> bool:
        return self._step_idx == len(WIZARD_STEPS) - 1

    def derive_policy(self) -> Policy:
        """Re-run ``apply_answers`` against the current state.

        Pure - safe to call on every render. The screen uses this
        for the always-on preview pane.
        """
        return apply_answers(self._answers)

    def validate(self) -> tuple[ValidationFinding, ...]:
        """Run the full policy validator over the derived policy."""
        return validate_policy(self.derive_policy())

    def is_savable(self) -> bool:
        """True iff the derived policy has zero validator errors."""
        return summarize(self.validate()).errors == 0

    def block_cursor(self) -> int:
        return self._block_cursor

    def allow_cursor_state(self) -> _AllowCursor:
        return self._allow_cursor

    def sink_cursor_state(self) -> _SinkCursor:
        return self._sink_cursor

    def selected_posture(self) -> PostureCard:
        return POSTURES[self._posture_cursor.index]

    def selected_response(self) -> ResponseCard:
        return RESPONSES[self._response_cursor.index]

    # --- step navigation ------------------------------------------

    def goto(self, step_idx: int) -> None:
        """Jump to a specific step (saturated to valid range)."""
        self._step_idx = max(0, min(len(WIZARD_STEPS) - 1, step_idx))

    def next_step(self) -> WizardOutcome:
        if self.is_last:
            return "ignored"
        self._step_idx += 1
        return "advance"

    def prev_step(self) -> WizardOutcome:
        if self.is_first:
            return "ignored"
        self._step_idx -= 1
        return "back"

    # --- key dispatch ---------------------------------------------

    def handle_key(self, key: str) -> WizardAction:
        """Dispatch a key to the active step.

        Global keys (``ctrl+left``, ``ctrl+right``, ``ctrl+s``,
        ``escape``) are handled here so individual steps don't
        accidentally trap them.
        """
        if key == "ctrl+right":
            return WizardAction(self.next_step())
        if key == "ctrl+left":
            return WizardAction(self.prev_step())
        if key == "escape":
            return WizardAction("cancel")
        if key == "ctrl+s" and self.is_savable():
            return WizardAction("save", policy=self.derive_policy())

        step_id = self.step.id
        if step_id == "posture":
            return self._handle_posture_key(key)
        if step_id == "block":
            return self._handle_block_key(key)
        if step_id == "allow":
            return self._handle_allow_key(key)
        if step_id == "response":
            return self._handle_response_key(key)
        if step_id == "sinks":
            return self._handle_sinks_key(key)
        return self._handle_review_key(key)

    # --- step handlers --------------------------------------------

    def _handle_posture_key(self, key: str) -> WizardAction:
        if key in {"up", "k"}:
            self._posture_cursor.move(-1)
            return WizardAction("handled")
        if key in {"down", "j"}:
            self._posture_cursor.move(+1)
            return WizardAction("handled")
        if key in {"enter", " "}:
            # Posture is a radio-style choice: pick the highlighted
            # option AND advance. The web Creator behaves the same
            # way; making the operator press Ctrl+Right after Enter
            # was the most-reported usability papercut from the
            # first-iteration TUI Quick Start.
            self._answers.posture = self._posture_cursor.value()
            return WizardAction(self.next_step())
        # p / d / s pin a posture and activate it without moving the
        # cursor. Mirrors the ``[1] [2] [3]`` shortcuts in the docs
        # Creator's posture step.
        if key == "p":
            self._posture_cursor.set(0)
            self._answers.posture = "permissive"
            return WizardAction("handled")
        if key == "d":
            self._posture_cursor.set(1)
            self._answers.posture = "default"
            return WizardAction("handled")
        if key == "s":
            self._posture_cursor.set(2)
            self._answers.posture = "strict"
            return WizardAction("handled")
        return WizardAction("ignored")

    def _handle_block_key(self, key: str) -> WizardAction:
        # ``BLOCK_DISPLAY_ORDER`` maps "the i-th card the operator
        # sees on screen" -> "index into ``BLOCK_CARDS``". We track
        # the cursor in card-index space (so existing serialization
        # and tests stay stable) but step through display space so
        # up/down feels linear instead of jumping between groups.
        try:
            display_pos = BLOCK_DISPLAY_ORDER.index(self._block_cursor)
        except ValueError:
            display_pos = 0
        last_display = len(BLOCK_DISPLAY_ORDER) - 1
        if key in {"up", "k"}:
            display_pos = max(0, display_pos - 1)
            self._block_cursor = BLOCK_DISPLAY_ORDER[display_pos]
            return WizardAction("handled")
        if key in {"down", "j"}:
            display_pos = min(last_display, display_pos + 1)
            self._block_cursor = BLOCK_DISPLAY_ORDER[display_pos]
            return WizardAction("handled")
        if key in {"enter", " "}:
            card = BLOCK_CARDS[self._block_cursor]
            if card.id in self._answers.block:
                self._answers.block.remove(card.id)
            else:
                self._answers.block.add(card.id)
            return WizardAction("handled")
        return WizardAction("ignored")

    def _handle_allow_key(self, key: str) -> WizardAction:
        cur = self._allow_cursor
        if key == "tab":
            cur.mode = _next_allow_mode(cur.mode)
            cur.index = 0
            return WizardAction("handled")
        if cur.mode == "allow":
            return self._handle_allow_toggles(key)
        if cur.mode == "domain":
            return self._handle_freeform(
                key,
                pending_attr="domain_input",
                items=self._answers.domains_extra,
            )
        return self._handle_freeform(
            key,
            pending_attr="first_party_input",
            items=self._answers.first_party_extra,
        )

    def _handle_allow_toggles(self, key: str) -> WizardAction:
        cur = self._allow_cursor
        if key in {"up", "k"}:
            cur.index = max(0, cur.index - 1)
            return WizardAction("handled")
        if key in {"down", "j"}:
            cur.index = min(len(ALLOW_CARDS) - 1, cur.index + 1)
            return WizardAction("handled")
        if key in {"enter", " "}:
            card = ALLOW_CARDS[cur.index]
            if card.id in self._answers.allow:
                self._answers.allow.remove(card.id)
            else:
                self._answers.allow.add(card.id)
            return WizardAction("handled")
        return WizardAction("ignored")

    def _handle_freeform(
        self,
        key: str,
        *,
        pending_attr: str,
        items: list[str],
    ) -> WizardAction:
        cur = self._allow_cursor
        pending: str = getattr(cur, pending_attr)
        if key == "enter":
            value = pending.strip()
            if value and value not in items:
                items.append(value)
            setattr(cur, pending_attr, "")
            return WizardAction("handled")
        if key == "backspace":
            setattr(cur, pending_attr, pending[:-1])
            return WizardAction("handled")
        if key == "delete":
            if items:
                items.pop()
            return WizardAction("handled")
        if len(key) == 1 and key.isprintable():
            setattr(cur, pending_attr, pending + key)
            return WizardAction("handled")
        return WizardAction("ignored")

    def _handle_response_key(self, key: str) -> WizardAction:
        if key in {"up", "k"}:
            self._response_cursor.move(-1)
            return WizardAction("handled")
        if key in {"down", "j"}:
            self._response_cursor.move(+1)
            return WizardAction("handled")
        if key in {"enter", " "}:
            # Same UX as posture: response is radio-style, so Enter
            # picks the highlighted option and immediately advances
            # to the Sinks step.
            self._answers.response = self._response_cursor.value()
            return WizardAction(self.next_step())
        return WizardAction("ignored")

    def _handle_sinks_key(self, key: str) -> WizardAction:
        """Sinks step dispatch.

        Vim-style ``j``/``k``/``h``/``l`` only navigate when the
        cursor is on the toggle cell. As soon as the operator
        moves into a text input cell (URL or env-var) those keys
        become literal characters again so a URL like
        "https://example.com" types correctly. The arrow keys plus
        ``tab`` are reserved for navigation in either mode.
        """
        cur = self._sink_cursor
        in_text_cell = cur.cell > 0
        if key in {"up"} or (not in_text_cell and key == "k"):
            cur.row = max(0, cur.row - 1)
            cur.cell = 0
            return WizardAction("handled")
        if key in {"down"} or (not in_text_cell and key == "j"):
            cur.row = min(len(SINK_CARDS) - 1, cur.row + 1)
            cur.cell = 0
            return WizardAction("handled")
        card = SINK_CARDS[cur.row]
        cells = _sink_cell_count(card)
        if key == "left" or (not in_text_cell and key == "h"):
            cur.cell = max(0, cur.cell - 1)
            return WizardAction("handled")
        if key in {"right", "tab"} or (not in_text_cell and key == "l"):
            cur.cell = min(cells - 1, cur.cell + 1)
            return WizardAction("handled")
        if cur.cell == 0 and key in {"enter", " "}:
            sink = self._sink_for_card(card)
            sink.enabled = not sink.enabled
            return WizardAction("handled")
        if in_text_cell:
            field_key = card.config_fields[cur.cell - 1].key
            return self._handle_sink_text_input(card, field_key, key)
        return WizardAction("ignored")

    def _handle_sink_text_input(
        self, card: SinkCard, field_key: SinkFieldKey, key: str
    ) -> WizardAction:
        sink = self._sink_for_card(card)
        current = sink.url if field_key == "url" else sink.secret_env
        if key == "backspace":
            updated = current[:-1]
        elif key == "enter":
            return WizardAction("handled")
        elif len(key) == 1 and key.isprintable():
            updated = current + key
        else:
            return WizardAction("ignored")
        if field_key == "url":
            sink.url = updated
        else:
            sink.secret_env = updated
        return WizardAction("handled")

    def _handle_review_key(self, key: str) -> WizardAction:
        if key in {"enter", "y", "Y"} and self.is_savable():
            return WizardAction("save", policy=self.derive_policy())
        return WizardAction("ignored")

    def _sink_for_card(self, card: SinkCard) -> SinkAnswer:
        if card.id not in self._answers.sinks:
            self._answers.sinks[card.id] = SinkAnswer()
        return self._answers.sinks[card.id]

    # --- mouse-click entry points ----------------------------------
    #
    # The screen layer maps a click position back to a card index
    # and calls one of the helpers below. They mirror the keyboard
    # behaviour for the same step:
    #
    # * Radio-style steps (posture / response): pick + advance.
    # * Multi-toggle steps (block / allow / sinks): set cursor and
    #   flip the card's selection state without navigating.

    def click_posture(self, idx: int) -> WizardAction:
        if not (0 <= idx < len(POSTURES)):
            return WizardAction("ignored")
        self._posture_cursor.set(idx)
        self._answers.posture = self._posture_cursor.value()
        return WizardAction(self.next_step())

    def click_block_card(self, idx: int) -> WizardAction:
        if not (0 <= idx < len(BLOCK_CARDS)):
            return WizardAction("ignored")
        self._block_cursor = idx
        card = BLOCK_CARDS[idx]
        if card.id in self._answers.block:
            self._answers.block.remove(card.id)
        else:
            self._answers.block.add(card.id)
        return WizardAction("handled")

    def click_allow_card(self, idx: int) -> WizardAction:
        if not (0 <= idx < len(ALLOW_CARDS)):
            return WizardAction("ignored")
        self._allow_cursor.mode = "allow"
        self._allow_cursor.index = idx
        card = ALLOW_CARDS[idx]
        if card.id in self._answers.allow:
            self._answers.allow.remove(card.id)
        else:
            self._answers.allow.add(card.id)
        return WizardAction("handled")

    def click_response(self, idx: int) -> WizardAction:
        if not (0 <= idx < len(RESPONSES)):
            return WizardAction("ignored")
        self._response_cursor.set(idx)
        self._answers.response = self._response_cursor.value()
        return WizardAction(self.next_step())

    def click_sink_card(self, idx: int) -> WizardAction:
        if not (0 <= idx < len(SINK_CARDS)):
            return WizardAction("ignored")
        self._sink_cursor.row = idx
        self._sink_cursor.cell = 0
        card = SINK_CARDS[idx]
        sink = self._sink_for_card(card)
        sink.enabled = not sink.enabled
        return WizardAction("handled")


__all__ = [
    "QuickStartWizardModel",
    "WIZARD_STEPS",
    "WizardAction",
    "WizardOutcome",
    "WizardStepDescriptor",
    "_AllowCursor",
    "_SinkCursor",
]
