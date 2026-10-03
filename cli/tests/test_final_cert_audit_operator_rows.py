# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert batch 10: operator Activity rows for setup llm / guardrail / redaction."""

from __future__ import annotations

from unittest.mock import MagicMock

from click.testing import CliRunner
from defenseclaw.commands import cmd_setup, cmd_setup_redaction
from defenseclaw.commands.cmd_setup import setup
from defenseclaw.logger import Logger


def _activity(operation: str, details: str) -> dict:
    fake = MagicMock()
    Logger.log_config_change(fake, operation, details)
    return fake.log_activity.call_args.kwargs


def test_setup_llm_judge_records_operator_activity_without_key_value() -> None:
    # GAP-2191: 'setup llm --role judge' left only the gateway's internal row.
    from tests.helpers import cleanup_app, make_app_context

    app, tmp_dir, db_path = make_app_context()
    try:
        app.logger = MagicMock()
        result = CliRunner().invoke(
            setup,
            [
                "llm",
                "--non-interactive",
                "--role",
                "judge",
                "--provider",
                "anthropic",
                "--model",
                "claude-sonnet-4-5",
                "--api-key",
                "sk-test-not-logged",
            ],
            obj=app,
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output
        operation, details = app.logger.log_config_change.call_args.args
        assert "sk-test-not-logged" not in details
        activity = _activity(operation, details)
        assert activity["actor"] == "cli:operator"
        assert activity["target_id"] == "llm:guardrail.judge"
        assert activity["diff"][0]["path"] == "model"
        assert activity["diff"][0]["after"] == "anthropic/claude-sonnet-4-5"
        assert activity["after"]["api_key_env"]
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_redaction_change_target_names_scope_and_profile() -> None:
    # GAP-2192: under strict only identifiers survive, so the target says what changed.
    app = MagicMock()
    cmd_setup_redaction._log_redaction_change(
        app, "apply scope=all-configurable profile=strict", "action=apply ...", 56, 0
    )

    app.logger.log_action.assert_called_once()
    activity = _activity(*app.logger.log_config_change.call_args.args)
    # The counts ride in the target too: strict keeps only "object_fields=3" of after.
    assert activity["target_id"] == "redaction-apply:all-configurable:strict:changed-legs-56:newly-unredacted-0"
    assert activity["after"] == {"profile": "strict", "changed_legs": "56", "newly_unredacted": "0"}


def test_setup_action_with_change_also_records_activity() -> None:
    app = MagicMock()
    cmd_setup._log_setup_action(
        app,
        "setup-guardrail",
        "mode=action",
        allow_offline=False,
        change=("guardrail-setup", "scope=claudecode:action mode=action scanner_mode=both"),
    )

    app.logger.log_action.assert_called_once_with("setup-guardrail", "config", "mode=action")
    activity = _activity(*app.logger.log_config_change.call_args.args)
    assert activity["target_id"] == "guardrail-setup:claudecode:action"
