# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``policy list/show --json``, the firewall-template guard and activate --reload."""

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

# Captured at import, before the conftest isolation stub replaces it.
_REAL_RELOAD_POLICY = gateway.OrchestratorClient.reload_policy


@pytest.fixture
def app(tmp_path, monkeypatch):
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    (tmp_path / "dc").mkdir()
    ctx, tmp_dir, db_path = make_app_context(str(tmp_path / "dc"))
    os.makedirs(ctx.cfg.policy_dir, exist_ok=True)
    ctx.cfg.save = lambda: None
    yield ctx
    cleanup_app(ctx, db_path, tmp_dir)


def _invoke(app, args):
    return CliRunner().invoke(policy, args, obj=app, catch_exceptions=False)


def test_list_json_shape_and_firewall_template_excluded(app):
    result = _invoke(app, ["list", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["version"] == 1
    assert isinstance(payload["active"], str)
    names = {p["name"] for p in payload["policies"]}
    assert {"default", "strict", "permissive"} <= names
    assert "firewall-deny-default" not in names
    strict = next(p for p in payload["policies"] if p["name"] == "strict")
    assert strict["block_at"] == "MEDIUM+"
    assert strict["builtin"] is True


def test_list_text_omits_firewall_template(app):
    result = _invoke(app, ["list"])
    assert result.exit_code == 0, result.output
    assert "firewall-deny-default" not in result.output
    assert "strict" in result.output


def test_show_json_and_unknown(app):
    result = _invoke(app, ["show", "permissive", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["version"] == 1
    assert payload["policy"]["name"] == "permissive"
    assert payload["policy"]["firewall_default"] == "allow"

    missing = _invoke(app, ["show", "nope", "--json"])
    assert missing.exit_code == 1


@pytest.mark.parametrize("command", [["activate", "firewall-deny-default"], ["show", "firewall-deny-default"]])
def test_firewall_template_refused_with_explanation(app, command):
    result = _invoke(app, command)
    assert result.exit_code == 1
    assert "firewall" in result.output
    assert "defenseclaw policy list" in result.output


def test_activate_reloads_running_gateway(app, monkeypatch):
    calls = []

    def _ok(self):
        calls.append(self.base_url)
        return {"status": "reloaded", "policy_dir": "x"}

    monkeypatch.setattr(gateway.OrchestratorClient, "reload_policy", _ok)
    result = _invoke(app, ["activate", "strict"])
    assert result.exit_code == 0, result.output
    assert len(calls) == 1


def test_activate_no_reload_skips_gateway(app, monkeypatch):
    def _boom(self):
        raise AssertionError("must not contact the gateway")

    monkeypatch.setattr(gateway.OrchestratorClient, "reload_policy", _boom)
    result = _invoke(app, ["activate", "strict", "--no-reload"])
    assert result.exit_code == 0, result.output


def test_activate_gateway_not_running_still_succeeds(app):
    # The autouse conftest fixture makes reload_policy raise ConnectionError.
    result = _invoke(app, ["activate", "default"])
    assert result.exit_code == 0, result.output
    assert "saved; the gateway isn't running, it loads this policy when it starts" in result.output


def test_activate_gateway_rejects_exits_1(app, monkeypatch):
    def _reject(self):
        resp = requests.Response()
        resp.status_code = 400
        resp._content = b'{"error": "compilation failed: bad rego", "status": "failed"}'
        raise requests.HTTPError(response=resp)

    monkeypatch.setattr(gateway.OrchestratorClient, "reload_policy", _reject)
    result = _invoke(app, ["activate", "strict"])
    assert result.exit_code == 1
    assert "defenseclaw policy validate" in result.output
    assert "compilation failed" in result.output


def test_reload_policy_client_posts_policy_reload(monkeypatch):
    seen = {}

    class _Resp:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"status": "reloaded", "policy_dir": "/p"}

    monkeypatch.setattr(gateway.OrchestratorClient, "reload_policy", _REAL_RELOAD_POLICY)
    client = gateway.OrchestratorClient(host="127.0.0.1", port=1, token="t")

    def _post(url, **kwargs):
        seen["url"] = url
        seen["kwargs"] = kwargs
        return _Resp()

    monkeypatch.setattr(client._session, "post", _post)
    assert client.reload_policy()["status"] == "reloaded"
    assert seen["url"].endswith("/policy/reload")
    assert seen["kwargs"]["allow_redirects"] is False
