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
    ctx.cfg.save_verified = lambda verify: verify("")
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
    assert "The gateway isn't running; it loads this policy when it starts" in result.output


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


def test_activate_with_stopped_gateway_skips_audit_and_succeeds(app, monkeypatch):
    from defenseclaw.logger import CanonicalObservabilityUnavailableError

    def _down(*_args, **_kwargs):
        raise CanonicalObservabilityUnavailableError("no gateway")

    monkeypatch.setattr(app.logger, "log_action", _down)
    result = _invoke(app, ["activate", "permissive"])
    assert result.exit_code == 0, result.output
    # GAP-1718: one note after the success line, not two overlapping ones.
    out = result.output
    assert out.count("gateway isn't running") == 1, out
    assert out.index("Policy 'permissive' activated") < out.index("it loads this policy when it starts")
    assert "the audit event was not recorded." in out


def test_create_and_delete_with_stopped_gateway_warn_once_without_traceback(app, monkeypatch):
    # GAP-1651: the file is written; only the audit event is skipped.
    from defenseclaw.logger import CanonicalObservabilityUnavailableError

    def _down(*_args, **_kwargs):
        raise CanonicalObservabilityUnavailableError("no gateway")

    monkeypatch.setattr(app.logger, "log_action", _down)
    created = _invoke(app, ["create", "gap1651", "--from-preset", "strict"])
    assert created.exit_code == 0, created.output
    assert "Policy 'gap1651' created" in created.output
    assert "Policy created. The gateway isn't running, so the audit event was not recorded" in created.output
    assert "Traceback" not in created.output

    deleted = _invoke(app, ["delete", "gap1651"])
    assert deleted.exit_code == 0, deleted.output
    assert "Policy deleted. The gateway isn't running" in deleted.output


def _custom_policy(app, name, edit):
    import yaml

    created = _invoke(app, ["create", name, "--from-preset", "default"])
    assert created.exit_code == 0, created.output
    path = os.path.join(app.cfg.policy_dir, f"{name}.yaml")
    with open(path) as f:
        data = yaml.safe_load(f)
    edit(data)
    with open(path, "w") as f:
        yaml.safe_dump(data, f)


def test_activate_rejects_quoted_scan_bypass_boolean(app):
    _custom_policy(app, "quoted", lambda data: data["admission"].update(allow_list_bypass_scan="false"))
    result = _invoke(app, ["activate", "quoted", "--no-reload"])
    assert result.exit_code != 0
    assert "allow_list_bypass_scan must be a boolean" in result.output
    assert app.cfg.admission.defaults.allow_list_bypass_scan is None


def test_activate_rejects_unknown_runtime_action(app):
    _custom_policy(app, "misspelled", lambda data: data["skill_actions"]["high"].update(runtime="bloock"))
    result = _invoke(app, ["activate", "misspelled", "--no-reload"])
    assert result.exit_code != 0
    assert "invalid runtime action" in result.output


def test_list_skips_malformed_draft_when_matching_active_policy(app):
    app.cfg.guardrail.block_at = "LOW"
    _custom_policy(app, "broken", lambda data: data["guardrail"].update(block_threshold="banana"))
    result = _invoke(app, ["list", "--json"])
    assert result.exit_code == 0, result.output
    assert any(p["name"] == "broken" for p in json.loads(result.output)["policies"])


def test_secure_client_activation_and_live_edit_sync_legacy_data(app, monkeypatch):
    from defenseclaw.enforce import asset_lists

    monkeypatch.setattr(asset_lists, "is_secure_client", lambda _cfg: True)
    rego = os.path.join(app.cfg.policy_dir, "rego")
    os.makedirs(rego)
    path = os.path.join(rego, "data.json")
    with open(path, "w") as f:
        json.dump({"config": {}, "actions": {}, "severity_ranking": {}}, f)
    activated = _invoke(app, ["activate", "permissive", "--no-reload"])
    assert activated.exit_code == 0, activated.output
    with open(path) as f:
        data = json.load(f)
    assert data["config"]["policy_name"] == "permissive"
    assert data["guardrail"]["block_threshold"] == 4
    edited = _invoke(app, ["edit", "guardrail", "--block-threshold", "LOW", "--no-reload"])
    assert edited.exit_code == 0, edited.output
    with open(path) as f:
        data = json.load(f)
    assert data["guardrail"]["block_threshold"] == 1


def test_secure_client_activation_save_failure_keeps_opa_data(app, monkeypatch):
    from defenseclaw.enforce import asset_lists

    monkeypatch.setattr(asset_lists, "is_secure_client", lambda _cfg: True)
    rego = os.path.join(app.cfg.policy_dir, "rego")
    os.makedirs(rego)
    path = os.path.join(rego, "data.json")
    with open(path, "w") as f:
        json.dump({"config": {"policy_name": "default"}, "actions": {}}, f)
    before = open(path, "rb").read()

    def refused(_verify):
        raise OSError("config save refused")

    monkeypatch.setattr(app.cfg, "save_verified", refused)
    with pytest.raises(OSError, match="config save refused"):
        _invoke(app, ["activate", "strict", "--no-reload"])
    assert open(path, "rb").read() == before


def test_secure_client_activation_invalid_watch_keeps_opa_data(app, monkeypatch):
    from defenseclaw.enforce import asset_lists

    monkeypatch.setattr(asset_lists, "is_secure_client", lambda _cfg: True)
    rego = os.path.join(app.cfg.policy_dir, "rego")
    os.makedirs(rego)
    path = os.path.join(rego, "data.json")
    with open(path, "w") as f:
        json.dump({"config": {"policy_name": "default"}, "actions": {}}, f)
    before = open(path, "rb").read()
    _custom_policy(app, "invalid-watch", lambda data: data["watch"].update(rescan_interval_min="invalid"))
    with pytest.raises(ValueError):
        _invoke(app, ["activate", "invalid-watch", "--no-reload"])
    assert open(path, "rb").read() == before


@pytest.mark.parametrize("content", [None, "{"])
def test_secure_client_validate_requires_legacy_data_with_opa(app, monkeypatch, content):
    import subprocess

    from defenseclaw.enforce import asset_lists

    monkeypatch.setattr(asset_lists, "is_secure_client", lambda _cfg: True)
    if content is not None:
        rego = os.path.join(app.cfg.policy_dir, "rego")
        os.makedirs(rego, exist_ok=True)
        with open(os.path.join(rego, "data.json"), "w") as f:
            f.write(content)
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/opa")
    monkeypatch.setattr(
        "defenseclaw.commands.cmd_policy.subprocess.run",
        lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, stdout="", stderr=""),
    )
    result = _invoke(app, ["validate"])
    assert result.exit_code == 1
    assert "data.json" in result.output


def test_list_matches_watch_settings_of_activated_preset(app):
    _custom_policy(app, "mywatch", lambda data: data["watch"].update(rescan_interval_min=17))
    activated = _invoke(app, ["activate", "mywatch", "--no-reload"])
    assert activated.exit_code == 0, activated.output
    result = _invoke(app, ["list", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["active"] == "mywatch"
    assert next(p for p in payload["policies"] if p["name"] == "mywatch")["active"]
