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


def _guardrail_setup_with_picked_hint(installed: list[str]):
    import os
    from unittest.mock import patch

    from defenseclaw.commands import cmd_setup

    app, tmp_dir, db_path = make_app_context()
    app.cfg.claw.mode = ""
    app.cfg.guardrail.connector = ""
    app.cfg.guardrail.connectors = {}
    with open(os.path.join(app.cfg.data_dir, "picked_connector"), "w", encoding="utf-8") as fh:
        fh.write("codex\n")
    argv = ["guardrail", "--non-interactive", "--no-restart", "--cisco-api-key-env", "ASIA_PACIFIC_KEY"]
    with patch.object(cmd_setup, "_detect_installed_connectors", return_value=installed):
        result = CliRunner().invoke(cmd_setup.setup, argv, obj=app)
    return app, tmp_dir, db_path, result


def test_a_picked_hint_for_an_agent_that_is_not_installed_does_not_pass_the_gate() -> None:
    # GAP-0568: an older installer recorded codex when it had no terminal to
    # ask on; that hint must not enroll an agent the machine does not have.
    app, tmp_dir, db_path, result = _guardrail_setup_with_picked_hint([])
    try:
        assert result.exit_code == 1, result.output
        assert "no agent connector is configured" in result.output
        assert app.cfg.guardrail.connector == ""
        assert app.cfg.claw.mode == ""
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_a_picked_hint_for_an_installed_agent_still_passes_the_gate() -> None:
    app, tmp_dir, db_path, result = _guardrail_setup_with_picked_hint(["codex"])
    try:
        assert "no agent connector is configured" not in result.output
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_non_interactive_guardrail_uses_roster_when_claw_block_is_missing() -> None:
    from unittest.mock import patch

    from defenseclaw.commands import cmd_setup
    from defenseclaw.config import PerConnectorGuardrailConfig

    app, tmp_dir, db_path = make_app_context()
    try:
        # An upgraded config can have a configured roster but no claw block.
        # The loader supplies the old claw.mode default in this case.
        app.cfg.claw.mode = "openclaw"
        app.cfg.guardrail.connector = ""
        app.cfg.guardrail.connectors = {"codex": PerConnectorGuardrailConfig()}
        argv = ["guardrail", "--non-interactive", "--no-restart", "--cisco-api-key-env", "ASIA_PACIFIC_KEY"]
        with (
            patch.object(cmd_setup, "_installed_picked_connector", return_value=None),
            patch.object(cmd_setup, "_ensure_connector_available") as check,
        ):
            CliRunner().invoke(cmd_setup.setup, argv, obj=app)
        check.assert_any_call("codex")
        assert app.cfg.guardrail.connector != "openclaw"
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_non_interactive_guardrail_refuses_legacy_config_without_claw_or_agent() -> None:
    from pathlib import Path
    from unittest.mock import patch

    from defenseclaw import config as config_module
    from defenseclaw.commands import cmd_setup

    app, tmp_dir, db_path = make_app_context()
    try:
        Path(tmp_dir, "config.yaml").write_text("config_version: 9\n", encoding="utf-8")
        with patch.object(config_module, "openclaw_installed", return_value=False):
            app.cfg = config_module.load(data_dir=tmp_dir)
        argv = ["guardrail", "--non-interactive", "--no-restart", "--cisco-api-key-env", "ASIA_PACIFIC_KEY"]
        with patch.object(cmd_setup, "_detect_installed_connectors", return_value=[]):
            result = CliRunner().invoke(cmd_setup.setup, argv, obj=app)
        assert result.exit_code == 1, result.output
        assert "no agent connector is configured" in result.output
        assert app.cfg.guardrail.connector == ""
        assert app.cfg.cisco_ai_defense.api_key_env != "ASIA_PACIFIC_KEY"
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_non_interactive_guardrail_refuses_stale_openclaw_selection() -> None:
    from unittest.mock import patch

    from defenseclaw.commands import cmd_setup

    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.claw.mode = "openclaw"
        app.cfg.guardrail.connector = "openclaw"
        app.cfg.guardrail.connectors = {}
        argv = ["guardrail", "--non-interactive", "--no-restart", "--cisco-api-key-env", "ASIA_PACIFIC_KEY"]
        with (
            patch.object(cmd_setup, "_detect_installed_connectors", return_value=[]),
            patch.object(cmd_setup, "_installed_picked_connector", return_value=None),
            patch.object(cmd_setup, "_ensure_connector_available") as check,
        ):
            result = CliRunner().invoke(cmd_setup.setup, argv, obj=app)
        assert result.exit_code == 1, result.output
        assert "no agent connector is configured" in result.output
        check.assert_not_called()
        assert app.cfg.guardrail.connector == "openclaw"
        assert app.cfg.cisco_ai_defense.api_key_env != "ASIA_PACIFIC_KEY"
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_restart_without_a_connector_does_not_start_openclaw(tmp_path) -> None:
    from unittest.mock import patch

    from defenseclaw.commands import cmd_setup

    with (
        patch.object(cmd_setup, "_restart_defense_gateway", return_value=True),
        patch.object(cmd_setup, "_restart_openclaw_gateway") as restart_openclaw,
        patch.object(cmd_setup, "_check_openclaw_gateway") as check_openclaw,
    ):
        cmd_setup._restart_services(str(tmp_path))
    restart_openclaw.assert_not_called()
    check_openclaw.assert_not_called()


def test_disabling_guardrail_without_an_agent_does_not_restart_openclaw() -> None:
    from unittest.mock import patch

    from defenseclaw.commands import cmd_setup

    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.claw.mode = ""
        app.cfg.guardrail.connector = ""
        with (
            patch.object(app.cfg, "save"),
            patch.object(cmd_setup, "_restart_services") as restart,
        ):
            cmd_setup._disable_guardrail(app, app.cfg.guardrail)
        assert restart.call_args.kwargs["connector"] == ""
    finally:
        cleanup_app(app, db_path, tmp_dir)
