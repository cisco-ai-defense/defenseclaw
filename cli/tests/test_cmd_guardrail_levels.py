# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw guardrail block-at|alert-at LEVEL [--connector C]``."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_guardrail, cmd_setup
from defenseclaw.config import PerConnectorGuardrailConfig, default_config
from defenseclaw.context import AppContext

from tests.environment import isolated_home_env

STRICT = "/packs/strict"


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
    cfg.guardrail.port = 4321
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


def _run(app, command, *args):
    result = CliRunner().invoke(cmd_guardrail.guardrail, [command, *args], obj=app, catch_exceptions=False)
    return result, (json.loads(result.stdout) if "--json" in args and result.stdout.strip() else None)


def _multi(app) -> None:
    app.cfg.guardrail.connectors = {
        "codex": PerConnectorGuardrailConfig(rule_pack_dir=STRICT),
        "claudecode": PerConnectorGuardrailConfig(),
    }


def test_global_block_at_sets_only_guardrail_block_at(app) -> None:
    result, payload = _run(app, "block-at", "high", "--json")
    assert result.exit_code == 0, result.output
    assert payload == {
        "version": 1,
        "ok": True,
        "scope": "global",
        "setting": "block_at",
        "level": "HIGH",
        "previous": "inherit",
        "source": "global",
        "effective_block_at": "HIGH+",
        "effective_alert_at": "MEDIUM+",
        "gateway": "not_running",
        "message": payload["message"],
    }
    gc = app.cfg.guardrail
    assert (gc.block_at, gc.alert_at, gc.connectors) == ("HIGH", "", {})
    assert (gc.enabled, gc.mode, gc.port, gc.rule_pack_dir) == (True, "action", 4321, "/packs/default")
    app.cfg.save.assert_called_once()
    assert app.logger.log_action.call_args.args[0] == "guardrail-block-at"


def test_global_and_connector_changes_restart_a_running_gateway(app, restarts) -> None:
    # Hook decisions read the config the gateway started with, so a global
    # level change needs a restart too.
    _multi(app)
    _, payload = _run(app, "alert-at", "LOW", "--json")
    assert (payload["gateway"], restarts) == ("restarted", [app.cfg.data_dir])

    _, payload = _run(app, "block-at", "CRITICAL", "--connector", "codex", "--json")
    assert (payload["scope"], payload["source"], payload["gateway"]) == ("codex", "override", "restarted")
    # Strict pack + codex's own CRITICAL: block 4, alert the global LOW.
    assert (payload["effective_block_at"], payload["effective_alert_at"]) == ("CRITICAL", "LOW+")
    assert app.cfg.guardrail.connectors["codex"].block_at == "CRITICAL"
    assert restarts == [app.cfg.data_dir] * 2

    _, payload = _run(app, "block-at", "inherit", "--connector", "codex", "--no-restart", "--json")
    assert (payload["level"], payload["previous"], payload["source"]) == ("inherit", "CRITICAL", "pack")
    assert (payload["effective_block_at"], payload["gateway"]) == ("MEDIUM+", "restart_needed")
    assert app.cfg.guardrail.connectors["codex"].block_at == ""
    assert len(restarts) == 2


def test_alert_above_the_block_level_is_clamped(app) -> None:
    _multi(app)
    result, payload = _run(app, "alert-at", "critical", "--connector", "codex", "--json")
    assert result.exit_code == 0, result.output
    assert (payload["level"], payload["effective_block_at"], payload["effective_alert_at"]) == (
        "CRITICAL",
        "MEDIUM+",
        "MEDIUM+",
    )


def test_a_global_level_names_the_connectors_it_loosens_and_those_it_skips(app) -> None:
    _multi(app)
    app.cfg.guardrail.connectors["claudecode"].block_at = "LOW"
    result, _ = _run(app, "block-at", "HIGH")
    assert result.exit_code == 0, result.output
    # codex's strict pack blocked MEDIUM+; claudecode keeps its own LOW.
    assert "block-at MEDIUM --connector codex" in result.output
    assert "block-at HIGH --connector claudecode" in result.output
    assert app.cfg.guardrail.connectors["claudecode"].block_at == "LOW"


def test_unknown_connector_and_noops_write_nothing(app) -> None:
    result, payload = _run(app, "block-at", "LOW", "--connector", "hermes", "--json")
    assert result.exit_code == 1 and payload["ok"] is False
    assert (payload["scope"], payload["level"], payload["previous"]) == ("hermes", "LOW", "inherit")
    result, payload = _run(app, "alert-at", "inherit", "--json")
    assert result.exit_code == 0 and payload["gateway"] is None
    app.cfg.guardrail.block_at = "HIGH"
    result, payload = _run(app, "block-at", "HIGH", "--json")
    assert (result.exit_code, payload["level"], payload["previous"]) == (0, "HIGH", "HIGH")
    app.cfg.save.assert_not_called()
    result, _ = _run(app, "block-at", "SEVERE")
    assert result.exit_code == 2


def test_single_connector_install_writes_its_override(app, restarts) -> None:
    _, payload = _run(app, "block-at", "MEDIUM", "--connector", "codex", "--json")
    assert (payload["scope"], payload["source"], payload["gateway"]) == ("codex", "override", "restarted")
    assert app.cfg.guardrail.connectors["codex"].block_at == "MEDIUM"
    assert app.cfg.active_connectors() == ["codex"]


def test_a_failed_save_reports_the_request_and_keeps_the_old_value(app) -> None:
    app.cfg.save.side_effect = OSError("read-only file system")
    result, payload = _run(app, "block-at", "LOW", "--json")
    assert result.exit_code == 1 and payload["ok"] is False
    assert (payload["level"], payload["previous"]) == ("LOW", "inherit")
    assert app.cfg.guardrail.block_at == ""
