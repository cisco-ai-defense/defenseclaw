# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Cause text names a folder exactly as it exists, runs of spaces included.

An account named with repeated spaces has a profile folder of the same name.
The gateway records the refusal with that folder unquoted, so doctor and the
setup readiness line must not fold the spaces: the folder shown in the cause
has to be the folder in the fix command next to it.
"""

from __future__ import annotations

import pytest
from defenseclaw import agent_selection
from defenseclaw.cause_text import single_line
from defenseclaw.commands import cmd_doctor, cmd_setup, cmd_status

FOLDER = "C:\\Users\\lane  x  yy zzzz\\.config\\opencode"
REASON = (
    "prepare opencode plugin destination: validate plugin directory custody: safefile: "
    f"private path DACL is unsafe to repair: {FOLDER}\\plugins "
    f"(HOST\\other has write access there, inherited from {FOLDER})"
)
FIX = f"icacls \"{FOLDER}\" /remove:g \"HOST\\other\""


def _health() -> dict:
    details = {
        "connectors_not_started": ["opencode"],
        "connectors_not_started_reasons": {"opencode": REASON},
        "connectors_not_started_repairs": {"opencode": {"fix": FIX}},
    }
    return {"guardrail": {"details": details}}


def test_the_doctor_cause_keeps_the_folder_name_byte_for_byte() -> None:
    text = cmd_doctor._bounded_recorded_reason(REASON)
    assert text == REASON
    assert f"{FOLDER}\\plugins" in text


def test_the_status_cause_and_its_fix_name_the_same_folder() -> None:
    detail = cmd_status._connector_recorded_cause(_health(), "opencode")
    assert FOLDER in detail.split("; fix: ")[0]
    assert detail.endswith(f"; fix: {FIX}")


def test_the_setup_readiness_cause_keeps_the_folder_name_byte_for_byte() -> None:
    detail = cmd_setup._connector_not_started_detail("opencode", REASON)
    assert detail.endswith(f"the gateway did not start it: {REASON}")
    assert cmd_setup._bounded_gateway_reason(REASON) == REASON


def test_a_probe_error_naming_a_folder_keeps_its_spaces() -> None:
    message = agent_selection.agent_did_not_run_message("OpenCode", f"version probe failed: {FOLDER}\\bin\\opencode")
    assert f"{FOLDER}\\bin\\opencode" in message


@pytest.mark.parametrize(
    ("text", "expected"),
    (
        ("one line", "one line"),
        ("a\nb", "a b"),
        ("a\r\n  b\t\tc\n\n", "a b  c"),
        ("  lead and trail  ", "lead and trail"),
        ("a\x0bb\x0cc\u2028d", "a b c d"),
        ("", ""),
    ),
)
def test_line_breaks_and_tabs_fold_to_one_line_and_spaces_are_kept(text: str, expected: str) -> None:
    assert single_line(text) == expected
    assert "\n" not in single_line(text)


def test_a_long_cause_stays_bounded_and_single_line() -> None:
    text = cmd_doctor._bounded_recorded_reason("line one\nline two " + "x" * 600)
    assert "\n" not in text
    assert len(text) <= cmd_doctor._RECORDED_REASON_CAUSE_LIMIT + 1 and text.endswith("…")
    setup_text = cmd_setup._bounded_gateway_reason("y\n" * 1000)
    assert "\n" not in setup_text and setup_text.endswith("(gateway.log has the rest)")
