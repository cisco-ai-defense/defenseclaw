# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""setup guardrail: --cisco-api-key-env and its prompt take a variable name (final-cert batch 27)."""

from __future__ import annotations

from unittest import mock

import click
from click.testing import CliRunner

_PASTED_KEY = "AIzaSyFakeB27KeyValue0123456789abcdefg"


def _run(argv: list[str]):
    from defenseclaw.commands.cmd_setup import setup
    from tests.helpers import cleanup_app, make_app_context

    app, tmp_dir, db_path = make_app_context()
    try:
        result = CliRunner().invoke(
            setup, ["guardrail", "--non-interactive", "--no-restart", "--no-verify", *argv], obj=app
        )
        return result, app.cfg.cisco_ai_defense.api_key_env
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_cisco_api_key_env_refuses_a_pasted_key_and_saves_nothing() -> None:
    # GAP-2579: the flag saved the pasted key as cisco_ai_defense.api_key_env.
    for value in (_PASTED_KEY, "sk-fake-0123456789abcdef"):
        result, saved = _run(["--cisco-api-key-env", value])
        assert result.exit_code == 2, result.output
        assert "--cisco-api-key-env" in result.output
        assert "NAME of the variable" in result.output and "keys set" in result.output
        assert value not in result.output
        assert saved != value


def test_connector_alias_refuses_a_pasted_key_before_writing() -> None:
    from defenseclaw.commands.cmd_setup import setup
    from tests.helpers import cleanup_app, make_app_context

    app, tmp_dir, db_path = make_app_context()
    try:
        argv = ["openclaw", "--yes", "--no-restart", "--no-verify", "--cisco-api-key-env", _PASTED_KEY]
        with mock.patch("defenseclaw.commands.cmd_setup._setup_guardrail_connector_alias") as alias:
            result = CliRunner().invoke(setup, argv, obj=app)
        assert result.exit_code == 2, result.output
        assert "--cisco-api-key-env" in result.output and _PASTED_KEY not in result.output
        alias.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_cisco_api_key_env_prompt_re_asks_on_a_pasted_key() -> None:
    from defenseclaw.commands.cmd_setup import _prompt_cisco_api_key_env_name

    answers = iter([_PASTED_KEY, "AID_KEY"])
    with (
        mock.patch.object(click, "prompt", side_effect=lambda *a, **k: next(answers)),
        mock.patch.object(click, "echo") as echo,
    ):
        assert _prompt_cisco_api_key_env_name("CISCO_AI_DEFENSE_API_KEY") == "AID_KEY"
    printed = " ".join(str(call.args[0]) for call in echo.call_args_list if call.args)
    assert "NAME of the variable" in printed and _PASTED_KEY not in printed
