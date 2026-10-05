# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""setup/init api-key-env names and init --connector none flags (final-cert batch 38)."""

from __future__ import annotations

import os
from unittest import mock

import click
import pytest
from click.testing import CliRunner

from tests.helpers import cleanup_app, make_app_context, record_test_setup_agent_selections

_PASTED_KEY = "AIzaSyFakeB38KeyValue0123456789abcdefg"


def _setup(argv: list[str]):
    from defenseclaw.commands.cmd_setup import setup

    app, tmp_dir, db_path = make_app_context()
    try:
        result = CliRunner().invoke(setup, argv, obj=app)
        return result, app.cfg
    finally:
        cleanup_app(app, db_path, tmp_dir)


def _assert_refused(result, flag: str) -> None:
    assert result.exit_code == 2, result.output
    assert flag in result.output and "keys set DEFENSECLAW_LLM_KEY" in result.output
    assert _PASTED_KEY not in result.output


def test_setup_llm_refuses_a_pasted_key_in_api_key_env() -> None:
    # GAP-2593: the key was saved as llm.api_key_env.
    argv = ["llm", "--non-interactive", "--provider", "anthropic", "--model", "claude-haiku-4-5"]
    result, cfg = _setup([*argv, "--api-key-env", _PASTED_KEY])
    _assert_refused(result, "--api-key-env")
    assert cfg.llm.api_key_env != _PASTED_KEY


def test_setup_guardrail_refuses_a_pasted_key_in_judge_api_key_env() -> None:
    # GAP-2593: the key was saved as guardrail.judge.llm.api_key_env and llm.api_key_env.
    argv = ["guardrail", "--non-interactive", "--no-restart", "--no-verify", "--judge-api-key-env", _PASTED_KEY]
    result, cfg = _setup(argv)
    _assert_refused(result, "--judge-api-key-env")
    assert _PASTED_KEY not in (cfg.guardrail.judge.llm.api_key_env, cfg.llm.api_key_env)


def test_connector_alias_refuses_a_pasted_key_in_judge_api_key_env() -> None:
    argv = ["openclaw", "--yes", "--no-restart", "--no-verify", "--judge-api-key-env", _PASTED_KEY]
    with mock.patch("defenseclaw.commands.cmd_setup._setup_guardrail_connector_alias") as alias:
        result, _ = _setup(argv)
    _assert_refused(result, "--judge-api-key-env")
    alias.assert_not_called()


def test_init_refuses_a_pasted_key_in_llm_api_key_env() -> None:
    from defenseclaw.commands.cmd_init import init_cmd

    app, tmp_dir, db_path = make_app_context()
    try:
        argv = ["--non-interactive", "--connector", "none", "--llm-api-key-env", _PASTED_KEY]
        with mock.patch("defenseclaw.commands.cmd_init._run_first_run_cmd") as first_run:
            result = CliRunner().invoke(init_cmd, argv, obj=app)
        _assert_refused(result, "--llm-api-key-env")
        first_run.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_llm_key_env_prompt_re_asks_on_a_pasted_key() -> None:
    from defenseclaw.commands._llm_picker import pick_key_env

    answers = iter([_PASTED_KEY, "MY_LLM_KEY"])
    with (
        mock.patch.object(click, "prompt", side_effect=lambda *a, **k: next(answers)),
        mock.patch.object(click, "echo") as echo,
    ):
        assert pick_key_env(provider="anthropic", current="", flag_value=None, non_interactive=False) == "MY_LLM_KEY"
    printed = " ".join(str(call.args[0]) for call in echo.call_args_list if call.args)
    assert "NAME of the variable" in printed and _PASTED_KEY not in printed


@pytest.mark.parametrize("name", ["ASIA_PACIFIC_KEY", "AKIA_ROTATED_KEY", "AIZA_KEY", "EYJ_TOKEN_NAME", "AIza_NAME"])
def test_env_var_names_with_a_key_prefix_are_accepted(name: str) -> None:
    # GAP-2594: bare AKIA/ASIA/AIza/eyJ prefixes refused valid names.
    from defenseclaw.commands.cmd_setup import _looks_like_secret, _validated_api_key_env_name
    from defenseclaw.tui.services.setup_state import looks_like_secret_value

    assert not _looks_like_secret(name)
    assert not looks_like_secret_value(name)
    assert _validated_api_key_env_name(name, "'--cisco-api-key-env'") == name


@pytest.mark.parametrize(
    "value",
    ["AKIAFAKEB38EXAMPLE01", "ASIAFAKEB38EXAMPLE01", _PASTED_KEY, "eyJhbGciOiJIUzI1NiJ9.e30.c2ln"],
)
def test_key_shapes_are_still_refused(value: str) -> None:
    from defenseclaw.commands.cmd_setup import _looks_like_secret
    from defenseclaw.tui.services.setup_state import looks_like_secret_value

    assert _looks_like_secret(value)
    assert looks_like_secret_value(value)


def test_init_connector_none_saves_llm_cisco_and_scanner_mode_flags(tmp_path) -> None:
    # GAP-2592: --connector none dropped these flags with rc 0.
    from defenseclaw import config as cfg_mod
    from defenseclaw.bootstrap import FirstRunOptions, run_first_run

    with (
        mock.patch.dict(os.environ, {"DEFENSECLAW_HOME": str(tmp_path / "home")}),
        mock.patch(
            "defenseclaw.agent_selection.record_setup_agent_selections",
            side_effect=record_test_setup_agent_selections,
        ),
    ):
        run_first_run(
            FirstRunOptions(
                connector="none",
                scanner_mode="remote",
                skip_install=True,
                start_gateway=False,
                verify=False,
                llm_provider="openai",
                llm_model="gpt-4o-mini",
                llm_api_key_env="MY_LLM_KEY",
                cisco_api_key_env="MY_AID_KEY",
            )
        )
        cfg = cfg_mod.load()

    assert cfg.llm.provider == "openai"
    assert cfg.llm.model == "openai/gpt-4o-mini"
    assert cfg.llm.api_key_env == "MY_LLM_KEY"
    assert cfg.cisco_ai_defense.api_key_env == "MY_AID_KEY"
    assert cfg.guardrail.scanner_mode == "remote"
    assert cfg.guardrail.connector == ""
