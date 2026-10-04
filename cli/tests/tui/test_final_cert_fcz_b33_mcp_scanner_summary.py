# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""setup mcp-scanner summary and env var names in the confirm dialog (final-cert batch 33)."""

from __future__ import annotations

from click.testing import CliRunner
from defenseclaw.tui.command_line import infer_command_risk
from defenseclaw.tui.screens.command_preview import mask_argv


def test_mcp_scanner_summary_lists_every_ai_defense_value_saved() -> None:
    # GAP-2539: api_key_env and timeout_ms were saved but never echoed.
    from defenseclaw.commands.cmd_setup import setup
    from tests.helpers import cleanup_app, make_app_context

    app, tmp_dir, db_path = make_app_context()
    try:
        argv = ["mcp-scanner", "--non-interactive", "--no-verify", "--api-endpoint", "https://aid.example"]
        argv += ["--api-key-env", "AID_KEY", "--api-timeout-ms", "7250"]
        result = CliRunner().invoke(setup, argv, obj=app, catch_exceptions=False)
        assert result.exit_code == 0, result.output
        assert "cisco_ai_defense.endpoint:" in result.output
        assert "cisco_ai_defense.api_key_env:" in result.output and "AID_KEY" in result.output
        assert "cisco_ai_defense.timeout_ms:" in result.output and "7250" in result.output
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_env_var_name_flags_are_shown_in_clear_and_not_secret() -> None:
    # GAP-2540: "--api-key-env NAME" read "Secret-bearing" with the name redacted.
    args = ("setup", "mcp-scanner", "--non-interactive", "--api-key-env", "DC_AID_KEY")
    assert mask_argv(("defenseclaw", *args)) == ("defenseclaw", *args)
    assert mask_argv(("defenseclaw", "setup", "x", "--api-key-env=DC_AID_KEY"))[-1] == "--api-key-env=DC_AID_KEY"
    assert infer_command_risk("setup", args) != "secret"
    # A real secret value, or a key pasted into the name field, stays hidden.
    assert mask_argv(("defenseclaw", "keys", "set", "K", "--value", "sk-1"))[-1] == "<redacted>"
    assert mask_argv(("defenseclaw", "setup", "x", "--api-key-env", "sk-live-1"))[-1] == "<redacted>"
    assert mask_argv(("defenseclaw", "setup", "x", "--api-key", "ABC"))[-1] == "<redacted>"
    assert infer_command_risk("setup", ("setup", "x", "--api-key-env", "sk-live-1")) == "secret"
