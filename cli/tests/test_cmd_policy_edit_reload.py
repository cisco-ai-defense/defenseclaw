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
    ["edit", "firewall", "--add-domain", "example.com"],
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
def test_editing_the_active_policy_reloads_the_gateway(app, reloads, args) -> None:
    result = _invoke(app, args)
    assert result.exit_code == 0, result.output
    assert len(reloads) == 1
    assert "Gateway reloaded the policy" in result.output


def test_thresholds_reach_data_json_before_the_reload(app, reloads) -> None:
    assert _invoke(app, EDITS[0]).exit_code == 0
    with open(os.path.join(app.cfg.policy_dir, "rego", "data.json"), encoding="utf-8") as fh:
        guardrail = json.load(fh)["guardrail"]
    assert (guardrail["block_threshold"], guardrail["alert_threshold"]) == (3, 1)


def test_an_active_action_edit_also_updates_the_config_actions(app, reloads) -> None:
    # CLI skill-action paths fall back to config.yaml's skill_actions.
    assert _invoke(app, EDITS[1]).exit_code == 0
    assert app.cfg.skill_actions.medium.runtime == "disable"


@pytest.mark.parametrize("args", EDITS, ids=lambda a: a[1])
def test_no_reload_and_drafts_leave_the_gateway_alone(app, monkeypatch, args) -> None:
    def _boom(self):
        raise AssertionError("must not contact the gateway")

    monkeypatch.setattr(gateway.OrchestratorClient, "reload_policy", _boom)
    assert _invoke(app, [*args, "--no-reload"]).exit_code == 0
    draft = _invoke(app, [*args, "--policy-name", "strict"])
    assert draft.exit_code == 0, draft.output
    assert "Saved draft" in draft.output


def test_stopped_gateway_is_fine(app) -> None:
    # The autouse conftest stub makes reload_policy raise ConnectionError.
    result = _invoke(app, EDITS[0])
    assert result.exit_code == 0, result.output
    assert "saved; the gateway isn't running, it loads this policy when it starts" in result.output


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


def test_skill_action_change_restarts_a_running_gateway(app, monkeypatch) -> None:
    # GAP-1236: the gateway's config watcher refuses a skill_actions change
    # ("requires gateway restart"), so a hot policy reload alone would claim
    # an enforcement it does not have.
    from defenseclaw.commands import cmd_policy, cmd_setup

    restarts: list[str] = []

    def _no_reload(self):
        raise AssertionError("a restart replaces the hot reload")

    monkeypatch.setattr(gateway.OrchestratorClient, "reload_policy", _no_reload)
    monkeypatch.setattr(cmd_policy, "_gateway_pid_alive", lambda _app: True)
    monkeypatch.setattr(
        cmd_setup, "_restart_defense_gateway", lambda data_dir, **_kw: restarts.append(data_dir) or True
    )
    result = _invoke(app, ["activate", "strict"])
    assert result.exit_code == 0, result.output
    assert restarts == [app.cfg.data_dir]
    assert "Restarted the gateway; it is enforcing the policy now." in result.output
    assert "Gateway reloaded the policy" not in result.output


def test_no_change_does_not_reload(app, monkeypatch) -> None:
    def _boom(self):
        raise AssertionError("must not contact the gateway")

    monkeypatch.setattr(gateway.OrchestratorClient, "reload_policy", _boom)
    result = _invoke(app, ["edit", "guardrail"])
    assert result.exit_code == 0 and "No changes specified" in result.output


def test_threshold_edit_points_hook_tool_calls_at_block_at(app, reloads) -> None:
    result = _invoke(app, EDITS[0])
    assert result.exit_code == 0, result.output
    assert "guardrail proxy" in result.output
    assert "defenseclaw guardrail block-at" in result.output
    patterns = _invoke(app, ["edit", "guardrail", "--add-pattern", "injection", "dc-marker"])
    assert "guardrail block-at" not in patterns.output
