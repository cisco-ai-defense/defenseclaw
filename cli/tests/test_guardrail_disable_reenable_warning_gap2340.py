# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-2340: ``guardrail disable`` says first when ``guardrail enable`` could not undo it."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_guardrail, cmd_setup
from defenseclaw.config import PerConnectorGuardrailConfig, default_config
from defenseclaw.context import AppContext

from tests.environment import isolated_home_env

_FLOOR = "kiro-cli 2.26.1 is below 2.27.1: before 2.27.1 a non-interactive kiro-cli --v3 run loads no hooks"


@pytest.fixture
def app(tmp_path, monkeypatch):
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    cfg = default_config()
    cfg.data_dir = str(tmp_path / "dc")
    cfg.policy_dir = str(tmp_path / "dc" / "policies")
    cfg.claw.mode = "codex"
    cfg.guardrail.connector = "codex"
    cfg.guardrail.enabled = True
    cfg.guardrail.mode = "action"
    cfg.guardrail.connectors = {
        "codex": PerConnectorGuardrailConfig(enabled=True),
        "kiro": PerConnectorGuardrailConfig(enabled=True),
    }
    cfg.save = MagicMock()
    ctx = AppContext()
    ctx.cfg = cfg
    ctx.logger = MagicMock()
    monkeypatch.setattr(cmd_guardrail, "_gateway_running", lambda _app: True)
    monkeypatch.setattr(cmd_guardrail, "_preflight_config_write", lambda _app: None)
    monkeypatch.setattr(cmd_guardrail, "_refuse_unverified_plugin_teardown", lambda _app, _names: None)
    monkeypatch.setattr(cmd_guardrail, "_note_running_agent_restart", lambda: None)
    monkeypatch.setattr(cmd_guardrail, "_log_guardrail_action", lambda *_a, **_k: None)
    monkeypatch.setattr(cmd_setup, "_restart_services", lambda *_a, **_k: None)
    return ctx


def _checks(monkeypatch, refused: dict[str, str]):
    calls: list[tuple[str, str]] = []

    def check(connector, *, mode, _refusal_scope=None, **_k):
        calls.append((connector, mode))
        if connector in refused:
            if _refusal_scope is not None:
                _refusal_scope["observe_admitted"] = False
                _refusal_scope["reason"] = refused[connector]
            return False
        return True

    monkeypatch.setattr(cmd_setup, "_check_connector_version_supported_for_setup", check)
    return calls


@pytest.mark.parametrize("args", [["disable", "--connector", "kiro"], ["disable"]])
def test_disable_warns_before_the_prompt_when_enable_would_be_refused(app, monkeypatch, args):
    calls = _checks(monkeypatch, {"kiro": _FLOOR})
    result = CliRunner().invoke(cmd_guardrail.guardrail, args, obj=app, input="n\n")
    assert result.exit_code == 1, result.output
    assert "Cancelled" in result.output
    out = " ".join(result.output.split())
    warning = out.index("defenseclaw guardrail enable --connector kiro")
    assert "kiro-cli 2.26.1 is below 2.27.1" in out
    assert "stays unprotected until you update it" in out
    assert "defenseclaw setup kiro" in out
    assert warning < out.index("Cancelled")
    assert ("kiro", "action") in calls
    app.cfg.save.assert_not_called()


def test_disable_still_runs_with_yes_after_the_warning(app, monkeypatch):
    _checks(monkeypatch, {"kiro": _FLOOR})
    result = CliRunner().invoke(cmd_guardrail.guardrail, ["disable", "--connector", "kiro", "--yes"], obj=app)
    assert result.exit_code == 0, result.output
    assert "stays unprotected until you update it" in " ".join(result.output.split())
    assert app.cfg.guardrail.connectors["kiro"].enabled is False


def test_disable_of_a_supported_agent_says_nothing_new(app, monkeypatch):
    calls = _checks(monkeypatch, {})
    result = CliRunner().invoke(cmd_guardrail.guardrail, ["disable", "--connector", "kiro", "--yes"], obj=app)
    assert result.exit_code == 0, result.output
    assert "stays unprotected" not in result.output
    assert calls == [("kiro", "action")]


def test_a_failed_version_probe_does_not_change_the_disable(app, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("probe failed")

    monkeypatch.setattr(cmd_setup, "_check_connector_version_supported_for_setup", boom)
    result = CliRunner().invoke(cmd_guardrail.guardrail, ["disable", "--connector", "kiro", "--yes"], obj=app)
    assert result.exit_code == 0, result.output
    assert app.cfg.guardrail.connectors["kiro"].enabled is False
