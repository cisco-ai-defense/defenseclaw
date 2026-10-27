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
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_guardrail, cmd_setup
from defenseclaw.config import PerConnectorGuardrailConfig, default_config
from defenseclaw.connector_paths import connector_hook_config_paths, copilot_home
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
    cfg.guardrail.rule_pack = "default"
    cfg.save = MagicMock()
    ctx = AppContext()
    ctx.cfg = cfg
    ctx.logger = MagicMock()
    return ctx


@pytest.fixture(autouse=True)
def version_checks(monkeypatch):
    """Record action-mode version probes; every connector verifies by default."""
    calls: list[str] = []
    verdicts: dict[str, bool] = {}

    def check(connector, *, mode, **_k):
        assert mode == "action"
        calls.append(connector)
        return verdicts.get(connector, True)

    monkeypatch.setattr(cmd_setup, "_check_connector_version_supported_for_setup", check)
    return calls, verdicts


@pytest.fixture
def restarts(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(cmd_guardrail, "_gateway_running", lambda _app: True)
    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", lambda data_dir, **_k: calls.append(data_dir) or True)
    return calls


@pytest.fixture
def rerenders(monkeypatch):
    """Connectors whose hook scripts were re-rendered in place."""
    calls: list[str] = []
    monkeypatch.setattr(cmd_guardrail, "reconcile_connector_registration", lambda _cfg, name: calls.append(name))
    return calls


def _run(app, *args):
    result = CliRunner().invoke(cmd_guardrail.guardrail, ["mode", *args], obj=app, catch_exceptions=False)
    return result, (json.loads(result.stdout) if "--json" in args and result.stdout.strip() else None)


def _untouched(app) -> None:
    gc = app.cfg.guardrail
    assert (gc.enabled, gc.port, gc.rule_pack) == (True, 4321, "default")


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
    assert app.logger.log_config_change.call_args.args[0] == "guardrail-mode"  # a config-update mutation


def test_cursor_mode_switch_keeps_its_fail_mode(app, restarts, rerenders) -> None:
    # The guardrail mode no longer pins Cursor's fail mode: like every other
    # connector it keeps the explicitly saved mode, so
    # a mode switch re-renders no hook and restarts nothing.
    app.cfg.claw.mode = "cursor"
    app.cfg.guardrail.connector = "cursor"
    _, payload = _run(app, "action", "--json")
    assert payload["gateway"] == "live" and restarts == [] and rerenders == []
    _run(app, "observe")
    assert restarts == [] and rerenders == []
    assert app.cfg.guardrail.effective_hook_fail_mode("cursor") == "closed"


def test_mode_switch_outside_secure_client_keeps_the_hook_fail_mode(app, restarts, rerenders) -> None:
    # B-01 (owner rule): outside Secure Client observe and action mode fail
    # the same way, so a mode switch re-renders no hook and restarts nothing.
    _, payload = _run(app, "action", "--json")
    assert payload["gateway"] == "live" and rerenders == [] and restarts == []
    _, payload = _run(app, "observe", "--json")
    assert rerenders == [] and restarts == []
    # The fixture has an explicit saved closed choice.
    assert app.cfg.guardrail.effective_hook_fail_mode("codex") == "closed"


@pytest.mark.parametrize("scope", ["global", "connector", "clear"])
@pytest.mark.parametrize("fail_mode", ["closed", "open"])
def test_observe_message_scopes_policy_findings_and_closed_outages(app, monkeypatch, scope, fail_mode) -> None:
    gc = app.cfg.guardrail
    monkeypatch.setattr(type(gc), "effective_hook_fail_mode", lambda _self, _connector: fail_mode)
    if scope == "global":
        gc.mode = "action"
        args = ("observe", "--json")
    elif scope == "connector":
        gc.mode = "action"
        args = ("observe", "--connector", "codex", "--json")
    else:
        gc.connectors = {"codex": PerConnectorGuardrailConfig(mode="action")}
        args = ("--clear", "--connector", "codex", "--json")

    result, payload = _run(app, *args)
    assert result.exit_code == 0, result.output
    message = payload["message"]
    assert "policy findings" in message
    assert "blocks nothing" not in message
    if fail_mode == "closed":
        assert "gateway outage" in message and "deny" in message
    else:
        assert "gateway outage" not in message


def test_connector_override_created_on_a_single_install(app, restarts, rerenders) -> None:
    result, payload = _run(app, "action", "--connector", "codex", "--json")
    assert result.exit_code == 0, result.output
    assert (payload["scope"], payload["mode"], payload["mode_source"], payload["gateway"]) == (
        "codex",
        "action",
        "override",
        "live",
    )
    gc = app.cfg.guardrail
    assert gc.mode == "observe" and gc.connectors["codex"].mode == "action"
    assert app.cfg.active_connectors() == ["codex"]
    _untouched(app)

    _, payload = _run(app, "action", "--connector", "codex", "--no-restart", "--json")
    assert payload["changed"] is False  # already there
    _, payload = _run(app, "--clear", "--connector", "codex", "--no-restart", "--json")
    assert (payload["mode"], payload["mode_source"], payload["gateway"]) == ("observe", "global", "live")
    # guardrail.connector already lists codex, so its emptied entry goes (GAP-1954).
    assert "codex" not in gc.connectors
    assert app.cfg.active_connectors() == ["codex"]


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


def test_action_switch_probes_versions_and_refuses_an_unverified_connector(
    app, restarts, version_checks, rerenders
) -> None:
    # GAP-1340/GAP-1362: after an observe-mode quickstart no agent version is
    # on record, so the action-mode gateway refused to start. The switch now
    # probes first and changes nothing when a connector can't be verified.
    calls, verdicts = version_checks
    verdicts["codex"] = False
    result, payload = _run(app, "action", "--json")
    assert result.exit_code == 1 and payload["ok"] is False and payload["changed"] is False
    assert "Nothing was changed" in payload["message"] and "Codex" in payload["message"]
    assert calls == ["codex"] and restarts == []
    assert app.cfg.guardrail.mode == "observe"
    app.cfg.save.assert_not_called()

    verdicts["codex"] = True
    result, payload = _run(app, "action", "--json")
    assert result.exit_code == 0 and payload["gateway"] == "live"
    assert calls == ["codex", "codex"]
    # Switching back to observe needs no probe.
    _run(app, "observe", "--json")
    assert calls == ["codex", "codex"]


def test_copilot_mode_switch_keeps_its_fail_mode(app) -> None:
    # A mode switch changes no fail mode outside Cursor (owner rule), so it
    # names none.
    app.cfg.claw.mode = "copilot"
    app.cfg.guardrail.connector = "copilot"
    result, _ = _run(app, "action", "--connector", "copilot", "--no-restart")
    assert result.exit_code == 0, result.output
    assert "Hook failures for" not in result.output


@pytest.mark.parametrize("source", ["settings", "registration"])
def test_copilot_action_refuses_hooks_off_with_no_running_gateway(app, monkeypatch, tmp_path, source) -> None:
    # Use the native path resolver on each OS, including Windows. A stopped
    # gateway must not make an action-mode claim when Copilot runs no hooks.
    monkeypatch.setenv("COPILOT_HOME", str(tmp_path / "copilot"))
    monkeypatch.setattr(cmd_guardrail, "_gateway_running", lambda _app: False)
    app.cfg.claw.mode = "copilot"
    app.cfg.guardrail.connector = "copilot"
    path = (
        Path(copilot_home(), "settings.json")
        if source == "settings"
        else Path(connector_hook_config_paths("copilot")[0])
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"disableAllHooks": true}', encoding="utf-8")

    result, payload = _run(app, "action", "--connector", "copilot", "--json")

    assert result.exit_code == 1, result.output
    assert payload["ok"] is False and str(path) in payload["message"]
    assert "disableAllHooks" in payload["message"]
    assert app.cfg.guardrail.mode == "observe"
    app.cfg.save.assert_not_called()

    from defenseclaw import gateway

    monkeypatch.setattr(gateway, "current_user_guardrail_profile", lambda _cfg: {"error": "offline"})
    status = CliRunner().invoke(cmd_guardrail.guardrail, ["status", "--json"], obj=app, catch_exceptions=False)
    assert status.exit_code == 0, status.output
    posture = json.loads(status.stdout)
    assert any("disableAllHooks" in warning and str(path) in warning for warning in posture["warnings"])


@pytest.mark.parametrize("copilot_override", ["", "observe"], ids=["covered", "observe-only"])
def test_global_action_checks_only_the_copilot_scope(app, monkeypatch, tmp_path, copilot_override) -> None:
    monkeypatch.setenv("COPILOT_HOME", str(tmp_path / "copilot"))
    monkeypatch.setattr(cmd_guardrail, "_gateway_running", lambda _app: False)
    app.cfg.guardrail.connectors = {
        "codex": PerConnectorGuardrailConfig(),
        "copilot": PerConnectorGuardrailConfig(mode=copilot_override),
    }
    settings = Path(copilot_home(), "settings.json")
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text('{"disableAllHooks": true}', encoding="utf-8")

    result, payload = _run(app, "action", "--json")

    if copilot_override == "observe":
        assert result.exit_code == 0, result.output
        assert payload["not_covered"] == ["copilot"]
        assert app.cfg.guardrail.mode == "action"
    else:
        assert result.exit_code == 1, result.output
        assert payload["ok"] is False and str(settings) in payload["message"]
        assert app.cfg.guardrail.mode == "observe"
        app.cfg.save.assert_not_called()


def test_copilot_action_text_does_not_claim_enforcement_with_hooks_off(app, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("COPILOT_HOME", str(tmp_path / "copilot"))
    app.cfg.claw.mode = "copilot"
    app.cfg.guardrail.connector = "copilot"
    settings = Path(copilot_home(), "settings.json")
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text('{"disableAllHooks": true}', encoding="utf-8")

    result, _ = _run(app, "action")

    assert result.exit_code == 1, result.output
    assert "Nothing was changed" in result.output and "disableAllHooks" in result.output
    assert "now in action mode" not in result.output
    app.cfg.save.assert_not_called()


def test_action_mode_without_registered_hooks_is_not_reported_as_success(app, restarts, rerenders, tmp_path) -> None:
    # GAP-1035: after a Codex self-update config.toml had no DefenseClaw hooks,
    # yet the command said Codex was in action mode and exited 0.
    config = tmp_path / "codex-config.toml"
    config.write_text('model = "gpt"\n')
    data_dir = tmp_path / "dc"
    data_dir.mkdir(parents=True, exist_ok=True)
    lock = {"version": 2, "connectors": {"codex": {"locations": {"hook_config_paths": [str(config)]}}}}
    (data_dir / "hook_contract_lock.json").write_text(json.dumps(lock))

    result, payload = _run(app, "action", "--connector", "codex", "--json")
    assert result.exit_code == 1, result.output
    assert payload["ok"] is False and payload["mode"] == "action"
    assert "not guarded" in payload["message"] and str(config) in payload["message"]
