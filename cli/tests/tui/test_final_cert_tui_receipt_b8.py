# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert UX batch 8: the receipt keeps its next step at 80x24."""

from __future__ import annotations

from defenseclaw.tui.app import _fit_keeping_next_step, _truncate_for_strip

_RECEIPT = "Codex connector setup complete (mode observe) · next: press i for readiness"


def test_receipt_and_status_line_keep_the_next_step_at_80_columns() -> None:
    # GAP-2133: "· next: press i for rea..." on the card, "· next: pre…" on the status line.
    card = _truncate_for_strip(_RECEIPT, 74)
    assert card.endswith(" · next: press i for readiness")
    assert card.startswith("Codex connector setup")
    assert len(card) <= 72
    status = _fit_keeping_next_step(f"Done: setup codex · {_RECEIPT}", 78)
    assert status.startswith("Done: setup codex · Codex")
    assert status.endswith(" · next: press i for readiness")
    assert len(status) <= 78


def test_text_without_a_next_step_is_cut_as_before() -> None:
    assert _truncate_for_strip("x" * 100, 40) == "x" * 35 + "..."
    assert _fit_keeping_next_step(_RECEIPT, 200) == _RECEIPT
