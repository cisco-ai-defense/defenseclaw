# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""First-run Textual model parity tests."""

from __future__ import annotations

from defenseclaw.tui.panels.first_run import (
    CONNECTOR_CHOICES,
    FirstRunPanelModel,
    decide_first_run_prompt,
    first_run_prompt_text,
)


def test_first_run_defaults_match_go_panel_argv() -> None:
    panel = FirstRunPanelModel()

    assert CONNECTOR_CHOICES == (
        "codex",
        "claudecode",
        "zeptoclaw",
        "openclaw",
        "hermes",
        "cursor",
        "windsurf",
        "geminicli",
        "copilot",
    )
    assert panel.args() == (
        "init",
        "--non-interactive",
        "--yes",
        "--json-summary",
        "--connector",
        "codex",
        "--profile",
        "observe",
        "--scanner-mode",
        "local",
        "--no-judge",
        "--fail-mode",
        "open",
        "--no-start-gateway",
        "--verify",
    )


def test_first_run_cycles_choices_and_bools() -> None:
    panel = FirstRunPanelModel()

    # Flip connector to claudecode, judge on, start-gateway on,
    # verify off (the panel order is: Connector, Profile, Scanner,
    # LLM Judge, Hook Fail Mode, HITL, HITL Min Severity, Start, Verify).
    panel.cursor = 0
    panel.handle_key("right")
    panel.cursor = 3
    panel.handle_key("enter")
    panel.cursor = 7
    panel.handle_key(" ")
    panel.cursor = 8
    panel.handle_key(" ")

    assert panel.args() == (
        "init",
        "--non-interactive",
        "--yes",
        "--json-summary",
        "--connector",
        "claudecode",
        "--profile",
        "observe",
        "--scanner-mode",
        "local",
        "--with-judge",
        "--fail-mode",
        "open",
        "--start-gateway",
        "--no-verify",
    )


def test_first_run_passes_hitl_flags_only_in_action_profile() -> None:
    """HITL flags only flow through when profile=action.

    Mirrors CLI ``defenseclaw init`` semantics where ``--human-approval``
    is meaningful only in action mode; observe mode skips the flag so
    the existing setting is preserved.
    """

    panel = FirstRunPanelModel()
    panel.cursor = 1
    panel.handle_key("right")
    panel.cursor = 5
    panel.handle_key(" ")
    args = panel.args()

    assert "action" in args
    assert "--human-approval" in args
    assert "--hilt-min-severity" in args
    severity_index = args.index("--hilt-min-severity")
    assert args[severity_index + 1] == "HIGH"

    panel.cursor = 5
    panel.handle_key(" ")
    panel.cursor = 1
    panel.handle_key("left")
    args = panel.args()
    assert "observe" in args
    assert "--human-approval" not in args
    assert "--no-human-approval" not in args


def test_first_run_fail_mode_cycles_to_closed() -> None:
    panel = FirstRunPanelModel()
    panel.cursor = 4
    panel.handle_key("right")
    args = panel.args()

    fail_idx = args.index("--fail-mode")
    assert args[fail_idx + 1] == "closed"


def test_first_run_ctrl_r_returns_data_only_command_intent() -> None:
    action = FirstRunPanelModel().handle_key("ctrl+r")

    assert action.handled is True
    assert action.intent is not None
    assert action.intent.binary == "defenseclaw"
    assert action.intent.label == "init first-run"
    assert action.intent.origin == "first-run"
    assert action.intent.args[:4] == ("init", "--non-interactive", "--yes", "--json-summary")


def test_first_run_prompt_text_keeps_full_wizard_context() -> None:
    prompt = first_run_prompt_text("/tmp/config.yaml")

    assert "/tmp/config.yaml" in prompt
    assert "connector" in prompt
    assert "profile" in prompt
    assert "fail-mode" in prompt
    assert "Human-In-the-Loop" in prompt


def test_first_run_prompt_decisions_match_cli_bootstrap() -> None:
    assert decide_first_run_prompt("", skip=True).outcome == "unavailable"
    assert decide_first_run_prompt("", tty_ok=False).outcome == "unavailable"

    handed = decide_first_run_prompt("")
    assert handed.outcome == "handed"
    assert handed.should_spawn_init is True

    yes = decide_first_run_prompt("YES")
    assert yes.outcome == "handed"
    assert yes.should_spawn_init is True

    declined = decide_first_run_prompt("n")
    assert declined.outcome == "declined"
    assert declined.should_spawn_init is False
    assert "defenseclaw init" in declined.message

    invalid = decide_first_run_prompt("later")
    assert invalid.outcome == "unavailable"
    assert invalid.should_spawn_init is False
    assert '"later"' in invalid.message

    failed = decide_first_run_prompt("y", spawn_error=RuntimeError("boom"))
    assert failed.outcome == "unavailable"
    assert failed.should_spawn_init is True
    assert "defenseclaw init: boom" in failed.message
