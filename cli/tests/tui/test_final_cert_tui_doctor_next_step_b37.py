"""A clean doctor run gets no next step (GAP-2587)."""

from __future__ import annotations

from defenseclaw.tui.command_line import READINESS_HINT, suggested_next_action

CLEAN = ["[PASS] Gateway", "[PASS] Guardrail", "Health: 130 passed, 29 skipped"]


def test_clean_doctor_run_has_no_next_step() -> None:
    assert suggested_next_action("Doctor", 0, lines=CLEAN) == ""
    assert suggested_next_action("doctor", 0, panel="setup", lines=CLEAN) == ""


def test_failed_doctor_and_setup_keep_their_hints() -> None:
    assert suggested_next_action("Doctor", 1, lines=CLEAN) == f"{READINESS_HINT}, or rerun doctor"
    assert suggested_next_action("setup claude-code", 0) == READINESS_HINT
    assert suggested_next_action("keys list", 0) == READINESS_HINT
