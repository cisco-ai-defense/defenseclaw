# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""setup guardrail on a no-connector install does not enroll OpenClaw (GAP-2609)."""

from __future__ import annotations

from click.testing import CliRunner

from tests.helpers import cleanup_app, make_app_context


def test_non_interactive_guardrail_setup_refuses_without_a_connector() -> None:
    from defenseclaw.commands.cmd_setup import setup

    app, tmp_dir, db_path = make_app_context()
    try:
        # The markers init --connector none persists (GAP-1056).
        app.cfg.claw.mode = ""
        app.cfg.guardrail.connector = ""
        app.cfg.guardrail.connectors = {}
        argv = ["guardrail", "--non-interactive", "--no-restart", "--cisco-api-key-env", "ASIA_PACIFIC_KEY"]
        result = CliRunner().invoke(setup, argv, obj=app)
        assert result.exit_code == 1, result.output
        assert "no agent connector is configured" in result.output
        assert "--connector" in result.output
        assert app.cfg.claw.mode == ""
        assert app.cfg.guardrail.connector == ""
        assert app.cfg.cisco_ai_defense.api_key_env != "ASIA_PACIFIC_KEY"
    finally:
        cleanup_app(app, db_path, tmp_dir)
