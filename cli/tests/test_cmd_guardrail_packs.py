# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``guardrail list-packs --json`` and ``guardrail use-pack``."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from defenseclaw import rulepack_validation
from defenseclaw.commands import cmd_guardrail
from defenseclaw.config import PerConnectorGuardrailConfig, default_config
from defenseclaw.context import AppContext

from tests.environment import isolated_home_env


def _valid(path, **_kwargs):
    return rulepack_validation.RulePackValidationResult(
        wire_version=1, kind="validation_result", valid=True, summary={"rule_count": 1}
    )


def _invalid(path, **_kwargs):
    return rulepack_validation.RulePackValidationResult(
        wire_version=1,
        kind="validation_error",
        valid=False,
        error=rulepack_validation.RulePackValidationIssue(path="$.rules", code="bad_rule", reason="broken"),
    )


def _unavailable(path, **_kwargs):
    raise rulepack_validation.RulePackValidationBridgeError("no gateway binary", code="gateway_unavailable")


@pytest.fixture
def env(tmp_path, monkeypatch):
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(rulepack_validation, "validate_rule_pack", _valid)
    guardrail_root = tmp_path / "dc" / "policies" / "guardrail"
    for preset in ("default", "strict", "permissive"):
        (guardrail_root / preset / "rules").mkdir(parents=True)
    custom = tmp_path / "packs" / "team"
    (custom / "rules").mkdir(parents=True)

    cfg = default_config()
    cfg.data_dir = str(tmp_path / "dc")
    cfg.policy_dir = str(tmp_path / "dc" / "policies")
    cfg.claw.mode = "codex"
    cfg.guardrail.connector = "codex"
    cfg.guardrail.enabled = True
    cfg.guardrail.mode = "action"
    cfg.guardrail.port = 4321
    cfg.guardrail.rule_pack_dir = str(guardrail_root / "default")
    cfg.save = MagicMock()
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    return app, guardrail_root, custom


def _run(app, args):
    return CliRunner().invoke(cmd_guardrail.guardrail, args, obj=app, catch_exceptions=False)


def _multi(app, overrides: dict[str, str]):
    app.cfg.guardrail.connectors = {
        name: PerConnectorGuardrailConfig(rule_pack_dir=path) for name, path in overrides.items()
    }


def test_global_switch_clears_overrides_and_reports_them(env):
    app, root, custom = env
    _multi(app, {"codex": str(custom), "claudecode": ""})
    result = _run(app, ["use-pack", "strict", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["scope"] == "global"
    assert payload["connector"] is None
    assert payload["pack"] == "strict"
    assert payload["path"] == str(root / "strict")
    assert payload["cleared_overrides"] == ["codex"]
    assert payload["validation"]["valid"] is True
    gc = app.cfg.guardrail
    assert gc.rule_pack_dir == str(root / "strict")
    assert all(block.rule_pack_dir == "" for block in gc.connectors.values())
    assert (gc.enabled, gc.mode, gc.port) == (True, "action", 4321)
    app.cfg.save.assert_called_once()


def test_connector_scope_creates_only_that_block_on_single_install(env):
    app, root, custom = env
    result = _run(app, ["use-pack", str(custom), "--connector", "codex"])
    assert result.exit_code == 0, result.output
    gc = app.cfg.guardrail
    assert set(gc.connectors) == {"codex"}
    assert gc.connectors["codex"].rule_pack_dir == str(custom)
    assert gc.rule_pack_dir == str(root / "default")
    assert app.cfg.active_connectors() == ["codex"]


def test_connector_scope_leaves_peers_alone(env):
    app, root, custom = env
    _multi(app, {"codex": "", "claudecode": str(root / "permissive")})
    result = _run(app, ["use-pack", "team", "--connector", "codex", "--json"])
    # "team" isn't under <policy_dir>/guardrail, so it is not a known name.
    assert result.exit_code == 1
    assert json.loads(result.output)["ok"] is False
    app.cfg.save.assert_not_called()

    result = _run(app, ["use-pack", str(custom), "--connector", "codex", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert (payload["scope"], payload["connector"], payload["cleared_overrides"]) == ("connector", "codex", [])
    gc = app.cfg.guardrail
    assert gc.connectors["claudecode"].rule_pack_dir == str(root / "permissive")
    assert gc.rule_pack_dir == str(root / "default")


def test_unknown_connector_refused(env):
    app, _root, _custom = env
    result = _run(app, ["use-pack", "strict", "--connector", "claudecode"])
    assert result.exit_code == 1
    assert app.cfg.guardrail.connectors == {}
    app.cfg.save.assert_not_called()


def test_invalid_pack_writes_nothing(env, monkeypatch):
    app, root, _custom = env
    monkeypatch.setattr(rulepack_validation, "validate_rule_pack", _invalid)
    result = _run(app, ["use-pack", "strict", "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["ok"] is False
    assert payload["validation"]["error"]["code"] == "bad_rule"
    assert app.cfg.guardrail.rule_pack_dir == str(root / "default")
    app.cfg.save.assert_not_called()


def test_validator_unavailable_preset_proceeds_custom_refuses(env, monkeypatch):
    app, root, custom = env
    monkeypatch.setattr(rulepack_validation, "validate_rule_pack", _unavailable)

    preset = _run(app, ["use-pack", "permissive"])
    assert preset.exit_code == 0, preset.output
    assert app.cfg.guardrail.rule_pack_dir == str(root / "permissive")

    app.cfg.save.reset_mock()
    refused = _run(app, ["use-pack", str(custom), "--json"])
    assert refused.exit_code == 2
    assert json.loads(refused.output)["ok"] is False
    assert app.cfg.guardrail.rule_pack_dir == str(root / "permissive")
    app.cfg.save.assert_not_called()

    forced = _run(app, ["use-pack", str(custom), "--no-validate", "--json"])
    assert forced.exit_code == 0, forced.output
    payload = json.loads(forced.output)
    assert payload["validation"] is None
    assert payload["pack"] == "team"
    assert app.cfg.guardrail.rule_pack_dir == str(custom)


def test_clear_connector_override(env):
    app, root, custom = env
    _multi(app, {"codex": str(custom), "claudecode": ""})
    result = _run(app, ["use-pack", "--clear", "--connector", "codex", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["connector"] == "codex"
    assert payload["path"] == str(root / "default")
    gc = app.cfg.guardrail
    assert set(gc.connectors) == {"codex", "claudecode"}
    assert gc.connectors["codex"].rule_pack_dir == ""


def test_usage_errors(env):
    app, _root, _custom = env
    assert _run(app, ["use-pack"]).exit_code == 2
    assert _run(app, ["use-pack", "--clear"]).exit_code == 2
    assert _run(app, ["use-pack", "strict", "--clear", "--connector", "codex"]).exit_code == 2
    app.cfg.save.assert_not_called()


def test_list_packs_json(env):
    app, root, custom = env
    _multi(app, {"codex": str(custom), "claudecode": ""})
    (root / "team2" / "rules").mkdir(parents=True)
    result = _run(app, ["list-packs", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["version"] == 1
    assert payload["global"] == {
        "connector": "global",
        "pack": "default",
        "path": str(root / "default"),
        "source": "global",
    }
    rows = {row["connector"]: row for row in payload["connectors"]}
    assert rows["codex"]["source"] == "override"
    assert rows["claudecode"]["pack"] == "default"
    packs = {p["name"]: p for p in payload["packs"]}
    assert packs["team2"]["kind"] == "custom"
    assert packs["team"]["used_by"] == ["codex"]
    assert packs["default"]["used_by"] == ["global", "claudecode"]

    text = _run(app, ["list-packs"])
    assert text.exit_code == 0
    assert "team2" in text.output
