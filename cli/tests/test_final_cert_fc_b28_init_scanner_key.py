# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""init: Cisco AI Defense key handling (final-cert batch 28)."""

from __future__ import annotations

import os
from unittest import mock

from click.testing import CliRunner

from tests.helpers import record_test_setup_agent_selections

_PASTED_KEY = "AIzaSyFakeB28InitKey0123456789abcdefg"


def test_init_refuses_a_pasted_key_in_cisco_api_key_env() -> None:
    # GAP-2589: init saved the pasted key as cisco_ai_defense.api_key_env.
    from defenseclaw.commands.cmd_init import init_cmd

    from tests.helpers import cleanup_app, make_app_context

    app, tmp_dir, db_path = make_app_context()
    try:
        argv = ["--non-interactive", "--connector", "claudecode", "--cisco-api-key-env", _PASTED_KEY]
        with mock.patch("defenseclaw.commands.cmd_init._run_first_run_cmd") as first_run:
            result = CliRunner().invoke(init_cmd, argv, obj=app)
        assert result.exit_code == 2, result.output
        assert "--cisco-api-key-env" in result.output and "keys set" in result.output
        assert _PASTED_KEY not in result.output
        first_run.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_missing_cisco_key_is_a_readiness_warning_not_a_rollback(tmp_path) -> None:
    # GAP-2590: a missing key failed readiness, so init rolled back config.yaml.
    from defenseclaw.bootstrap import FirstRunOptions, StepResult, targeted_readiness
    from defenseclaw.config import default_config

    with mock.patch.dict(os.environ, {"DEFENSECLAW_HOME": str(tmp_path)}):
        cfg = default_config()
    cfg.guardrail.enabled = True
    cfg.guardrail.scanner_mode = "remote"
    cfg.cisco_ai_defense.api_key_env = "MY_AID_KEY"
    failed = StepResult("Cisco AI Defense", "fail", "MY_AID_KEY not set", "defenseclaw doctor")
    with mock.patch("defenseclaw.bootstrap._doctor_check", return_value=failed):
        steps = targeted_readiness(cfg, FirstRunOptions(connector="claudecode", start_gateway=False))

    row = next(s for s in steps if s.name == "Cisco AI Defense")
    assert row.status == "warn"
    assert row.next_command == "defenseclaw keys set MY_AID_KEY"


def test_a_rolled_back_first_run_says_nothing_was_saved(tmp_path) -> None:
    # GAP-2590: after a rollback the report still read like a saved config.
    from defenseclaw.bootstrap import FirstRunOptions, StepResult, run_first_run

    with (
        mock.patch.dict(os.environ, {"DEFENSECLAW_HOME": str(tmp_path / "home")}),
        mock.patch(
            "defenseclaw.agent_selection.record_setup_agent_selections",
            side_effect=record_test_setup_agent_selections,
        ),
        mock.patch(
            "defenseclaw.bootstrap._quiet_guardrail_setup",
            return_value=StepResult("Guardrail", "fail", "test failure"),
        ),
    ):
        report = run_first_run(
            FirstRunOptions(connector="codex", skip_install=True, start_gateway=False, verify=False)
        )

    assert report.status == "needs_attention"
    row = report.setup[-1]
    assert row.name == "First-run rollback" and row.status == "fail"
    assert "nothing was saved" in row.detail
    assert not (tmp_path / "home" / "config.yaml").exists()
