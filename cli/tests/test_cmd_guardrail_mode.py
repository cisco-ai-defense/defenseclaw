# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw guardrail mode observe|action``."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_guardrail, cmd_setup
from defenseclaw.config import PerConnectorGuardrailConfig, default_config
from defenseclaw.context import AppContext

from tests.environment import isolated_home_env


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
    cfg.guardrail.mode = "observe"
    cfg.guardrail.port = 4321
    cfg.guardrail.hook_fail_mode = "closed"
    cfg.guardrail.rule_pack_dir = "/packs/default"
    cfg.save = MagicMock()
    ctx = AppContext()
    ctx.cfg = cfg
    ctx.logger = MagicMock()
    return ctx


@pytest.fixture
def restarts(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(cmd_guardrail, "_gateway_running", lambda _app: True)
    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", lambda data_dir, **_k: calls.append(data_dir) or True)
    return calls


def _run(app, *args):
    result = CliRunner().invoke(cmd_guardrail.guardrail, ["mode", *args], obj=app, catch_exceptions=False)
    return result, (json.loads(result.stdout) if "--json" in args and result.stdout.strip() else None)


def _untouched(app) -> None:
    gc = app.cfg.guardrail
    assert (gc.enabled, gc.port, gc.rule_pack_dir) == (True, 4321, "/packs/default")


def test_global_switch_sets_only_guardrail_mode(app) -> None:
    result, payload = _run(app, "action", "--json")
    assert result.exit_code == 0, result.output
    assert payload == {
        "version": 1,
        "ok": True,
        "scope": "global",
        "mode": "action",
        "previous": "observe",
        "mode_source": "global",
        "changed": True,
        "not_covered": [],
        "gateway": "not_running",
        "message": payload["message"],
    }
    assert app.cfg.guardrail.mode == "action"
    assert app.cfg.guardrail.connectors == {}
    _untouched(app)
    app.cfg.save.assert_called_once()
    assert app.logger.log_action.call_args.args[0] == "guardrail-mode"


def test_global_switch_restarts_a_running_gateway(app, restarts) -> None:
    # codex inherits hook_fail_mode=closed, which only applies in action mode:
    # observe -> action flips its hooks from fail-open to fail-closed.
    result, payload = _run(app, "action", "--json")
    assert payload["gateway"] == "restarted" and restarts == [app.cfg.data_dir]
    text, _ = _run(app, "observe")
    assert "fail open" in text.output
    assert len(restarts) == 2

    # Even without a hook fail-mode flip: hook decisions only see the new
    # mode after a restart.
    app.cfg.guardrail.connectors = {"codex": PerConnectorGuardrailConfig(hook_fail_mode="closed")}
    _, payload = _run(app, "action", "--json")
    assert payload["gateway"] == "restarted" and len(restarts) == 3


def test_connector_override_created_on_a_single_install(app, restarts) -> None:
    result, payload = _run(app, "action", "--connector", "codex", "--json")
    assert result.exit_code == 0, result.output
    assert (payload["scope"], payload["mode"], payload["mode_source"], payload["gateway"]) == (
        "codex",
        "action",
        "override",
        "restarted",
    )
    gc = app.cfg.guardrail
    assert gc.mode == "observe" and gc.connectors["codex"].mode == "action"
    assert app.cfg.active_connectors() == ["codex"]
    _untouched(app)

    _, payload = _run(app, "action", "--connector", "codex", "--no-restart", "--json")
    assert payload["changed"] is False  # already there
    _, payload = _run(app, "--clear", "--connector", "codex", "--no-restart", "--json")
    assert (payload["mode"], payload["mode_source"], payload["gateway"]) == ("observe", "global", "restart_needed")
    assert gc.connectors["codex"].mode == ""


def test_connector_scope_leaves_peers_alone_and_global_names_overrides(app) -> None:
    app.cfg.guardrail.connectors = {
        "codex": PerConnectorGuardrailConfig(),
        "claudecode": PerConnectorGuardrailConfig(mode="observe"),
    }
    _, payload = _run(app, "action", "--connector", "codex", "--json")
    assert app.cfg.guardrail.connectors["claudecode"].mode == "observe"
    assert payload["not_covered"] == []

    _, payload = _run(app, "action", "--json")
    assert payload["not_covered"] == ["claudecode"]  # keeps its own observe override
    assert app.cfg.guardrail.connectors["claudecode"].mode == "observe"


def test_unknown_connector_and_noops_write_nothing(app) -> None:
    result, payload = _run(app, "action", "--connector", "claudecode", "--json")
    assert result.exit_code == 1 and payload["ok"] is False
    result, payload = _run(app, "observe", "--json")
    assert result.exit_code == 0 and payload["changed"] is False
    result, payload = _run(app, "--clear", "--connector", "codex", "--json")
    assert result.exit_code == 0 and payload["changed"] is False
    app.cfg.save.assert_not_called()


@pytest.mark.parametrize("args", [(), ("--clear",), ("action", "--clear", "--connector", "codex"), ("enforce",)])
def test_usage_errors(app, args) -> None:
    result = CliRunner().invoke(cmd_guardrail.guardrail, ["mode", *args], obj=app)
    assert result.exit_code == 2
    app.cfg.save.assert_not_called()
