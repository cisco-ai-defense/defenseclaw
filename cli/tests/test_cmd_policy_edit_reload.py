# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``policy edit … --reload/--no-reload`` reloads the gateway like ``activate``."""

from __future__ import annotations

import json
import os

import pytest
import requests
from click.testing import CliRunner
from defenseclaw import gateway
from defenseclaw.commands.cmd_policy import policy

from tests.environment import isolated_home_env
from tests.helpers import cleanup_app, make_app_context

EDITS = [
    ["edit", "guardrail", "--block-threshold", "3", "--alert-threshold", "1"],
    ["edit", "actions", "--severity", "medium", "--runtime", "disable"],
    ["edit", "scanner", "--type", "mcp", "--severity", "high", "--runtime", "disable"],
]


@pytest.fixture
def app(tmp_path, monkeypatch):
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    (tmp_path / "dc").mkdir()
    ctx, tmp_dir, db_path = make_app_context(str(tmp_path / "dc"))
    os.makedirs(ctx.cfg.policy_dir, exist_ok=True)
    ctx.cfg.save = lambda: None
    assert _invoke(ctx, ["activate", "default", "--no-reload"]).exit_code == 0
    yield ctx
    cleanup_app(ctx, db_path, tmp_dir)


@pytest.fixture
def reloads(monkeypatch):
    calls: list[str] = []

    def _ok(self):
        calls.append(self.base_url)
        return {"status": "reloaded", "policy_dir": "x"}

    monkeypatch.setattr(gateway.OrchestratorClient, "reload_policy", _ok)
    return calls


def _invoke(app, args):
    return CliRunner().invoke(policy, args, obj=app, catch_exceptions=False)


@pytest.mark.parametrize("args", EDITS, ids=lambda a: a[1])
def test_a_live_edit_reloads_the_gateway(app, reloads, args) -> None:
    result = _invoke(app, args)
    assert result.exit_code == 0, result.output
    assert len(reloads) == 1
    assert "Gateway reloaded the policy" in result.output


def test_a_live_edit_writes_config(app, reloads) -> None:
    assert _invoke(app, EDITS[0]).exit_code == 0
    assert (app.cfg.guardrail.block_at, app.cfg.guardrail.alert_at) == ("HIGH", "LOW")
    assert _invoke(app, EDITS[1]).exit_code == 0
    assert app.cfg.admission.defaults.actions["medium"]["runtime"] == "disable"


@pytest.mark.parametrize("args", EDITS, ids=lambda a: a[1])
def test_no_reload_and_drafts_leave_the_gateway_alone(app, monkeypatch, args) -> None:
    def _boom(self):
        raise AssertionError("must not contact the gateway")

    monkeypatch.setattr(gateway.OrchestratorClient, "reload_policy", _boom)
    assert _invoke(app, [*args, "--no-reload"]).exit_code == 0
    draft = _invoke(app, [*args, "--policy-name", "strict"])
    assert draft.exit_code == 0, draft.output
    assert "Apply it with" in draft.output


def test_stopped_gateway_is_fine(app) -> None:
    # The autouse conftest stub makes reload_policy raise ConnectionError.
    result = _invoke(app, EDITS[0])
    assert result.exit_code == 0, result.output
    assert "The gateway isn't running; it loads this policy when it starts" in result.output


def test_rejected_reload_exits_1(app, monkeypatch) -> None:
    def _reject(self):
        resp = requests.Response()
        resp.status_code = 400
        resp._content = b'{"error": "compilation failed: bad rego", "status": "failed"}'
        raise requests.HTTPError(response=resp)

    monkeypatch.setattr(gateway.OrchestratorClient, "reload_policy", _reject)
    result = _invoke(app, EDITS[0])
    assert result.exit_code == 1
    assert "defenseclaw policy validate" in result.output and "compilation failed" in result.output


def test_a_watch_change_restarts_only_a_secure_client_gateway(app, monkeypatch) -> None:
    # The gateway reloads watch hot (GAP-0056); a Secure Client gateway reads
    # it at start, so there activate keeps the restart of main (GAP-1236).
    from defenseclaw.commands import cmd_policy, cmd_setup

    restarts: list[str] = []
    monkeypatch.setattr(gateway.OrchestratorClient, "reload_policy", lambda self: {"status": "reloaded"})
    monkeypatch.setattr(cmd_policy, "_gateway_pid_alive", lambda _app: True)
    monkeypatch.setattr(
        cmd_setup, "_restart_defense_gateway", lambda data_dir, **_kw: restarts.append(data_dir) or True
    )
    app.cfg.watch.rescan_interval_min = 7
    result = _invoke(app, ["activate", "strict"])
    assert result.exit_code == 0, result.output
    assert restarts == [] and "Gateway reloaded the policy" in result.output

    rego_dir = os.path.join(app.cfg.policy_dir, "rego")
    os.makedirs(rego_dir, exist_ok=True)
    with open(os.path.join(rego_dir, "data.json"), "w") as f:
        json.dump({"config": {}, "actions": {}, "severity_ranking": {}}, f)
    monkeypatch.setattr(cmd_policy.asset_lists, "is_secure_client", lambda _cfg: True)
    app.cfg.watch.rescan_interval_min = 7
    result = _invoke(app, ["activate", "strict"])
    assert result.exit_code == 0, result.output
    assert restarts == [app.cfg.data_dir]
    assert "Restarted the gateway; it is enforcing the policy now." in result.output


def test_no_change_does_not_reload(app, monkeypatch) -> None:
    def _boom(self):
        raise AssertionError("must not contact the gateway")

    monkeypatch.setattr(gateway.OrchestratorClient, "reload_policy", _boom)
    result = _invoke(app, ["edit", "guardrail"])
    assert result.exit_code == 0 and "No changes specified" in result.output


def test_an_edit_names_what_it_changed(app, reloads) -> None:
    # GAP-1667: the result line said only 'Guardrail updated: block_threshold=3'.
    result = _invoke(app, EDITS[0])
    assert result.exit_code == 0, result.output
    assert "Guardrail updated: block_at=HIGH, alert_at=LOW" in result.output
    draft = _invoke(app, ["edit", "firewall", "--add-domain", "example.org", "-p", "strict"])
    assert "Firewall of policy 'strict' updated: +domain example.org" in draft.output
