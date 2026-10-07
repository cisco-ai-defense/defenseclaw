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


def test_global_switch_rerenders_hooks_without_a_restart(app, restarts, rerenders, monkeypatch) -> None:
    # codex inherits hook_fail_mode=closed, which only applies in action mode:
    # observe -> action flips its hooks from fail-open to fail-closed. The
    # gateway reloads the mode hot and the script is re-rendered in place
    # (GAP-0002); no restart.
    result, payload = _run(app, "action", "--json")
    assert payload["gateway"] == "live" and rerenders == ["codex"] and restarts == []
    text, _ = _run(app, "observe")
    assert "fail open" in text.output
    assert rerenders == ["codex", "codex"] and restarts == []

    # Without a hook fail-mode flip nothing is re-rendered.
    app.cfg.guardrail.connectors = {"codex": PerConnectorGuardrailConfig(hook_fail_mode="closed")}
    _, payload = _run(app, "action", "--json")
    assert payload["gateway"] == "live" and len(rerenders) == 2

    # A failed re-render falls back to a restart, which re-bakes the script.
    app.cfg.guardrail.connectors = {}
    app.cfg.guardrail.mode = "observe"

    def broken(_cfg, _name):
        raise OSError("native defenseclaw-gateway executable not found")

    monkeypatch.setattr(cmd_guardrail, "reconcile_connector_registration", broken)
    _, payload = _run(app, "action", "--json")
    assert payload["gateway"] == "restarted" and restarts == [app.cfg.data_dir]


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
