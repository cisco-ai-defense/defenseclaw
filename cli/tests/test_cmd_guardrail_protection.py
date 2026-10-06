# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``guardrail protection|rule|suppress|use-pack``: config.yaml keys through the writer.

The gateway composes rule packs in memory from ``guardrail.rules`` and
reloads hot, so these commands only write config (no rule files, no restart).
"""

from __future__ import annotations

import json
import shutil
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from defenseclaw import config_writer, rulepack_validation
from defenseclaw import policy_catalog as pc
from defenseclaw.commands import cmd_guardrail
from defenseclaw.config import GuardrailRulesConfig, PerConnectorGuardrailConfig, default_config
from defenseclaw.context import AppContext

from tests.environment import isolated_home_env

DB = "database-destruction-protection"
K8S = "kubernetes-production-protection"


@pytest.fixture
def env(tmp_path, monkeypatch):
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    root = tmp_path / "dc" / "policies" / "guardrail"
    for preset in pc.RULE_PACK_PRESETS:
        shutil.copytree(pc.preset_pack_dir(None, preset), root / preset)
    cfg = default_config()
    cfg.data_dir = str(tmp_path / "dc")
    cfg.policy_dir = str(tmp_path / "dc" / "policies")
    cfg.claw.mode = "codex"
    cfg.guardrail.connector = "codex"
    cfg.guardrail.enabled = True
    cfg.guardrail.rule_pack_dir = str(root / "default")
    cfg.save = MagicMock()
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    writes: list[tuple[list[config_writer.Change], str, str]] = []

    def _apply(changes, actor, reason, expect_sha256=None, **_kwargs):
        writes.append((list(changes), actor, reason))
        return config_writer.WriteResult(generation=7, sha256="0" * 64)

    monkeypatch.setattr(config_writer, "apply", _apply)
    monkeypatch.setattr(
        rulepack_validation,
        "validate_rule_pack",
        lambda _path, **_k: rulepack_validation.RulePackValidationResult(
            wire_version=1, kind="validation", valid=True, summary={"rule_count": 1, "digest": "a" * 64}
        ),
    )
    return app, root, writes


def _run(app, *args):
    return CliRunner().invoke(cmd_guardrail.guardrail, list(args), obj=app, catch_exceptions=False)


def test_protection_enable_and_disable_write_rules_keys(env) -> None:
    app, _root, writes = env
    result = _run(app, "protection", "enable", DB, "--json")
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["protection"] == [DB]
    (changes, actor, _reason) = writes[-1]
    assert changes == [config_writer.Change("guardrail.rules.protections", [DB])]
    assert actor.startswith(config_writer.ACTOR_PREFIX_CLI)
    app.cfg.save.assert_not_called()

    app.cfg.guardrail.connectors = {"codex": PerConnectorGuardrailConfig(rules=GuardrailRulesConfig(protections=[K8S]))}
    result = _run(app, "protection", "disable", K8S, "--connector", "codex")
    assert result.exit_code == 0, result.output
    assert writes[-1][0] == [config_writer.Change("guardrail.connectors.codex.rules.protections", unset=True)]
    assert "next reload" in result.output or "isn't running" in result.output


def test_protection_list_reads_config(env) -> None:
    app, _root, _writes = env
    app.cfg.guardrail.rules = GuardrailRulesConfig(protections=[DB])
    rows = pc.scope_postures(app.cfg)
    assert rows[0].scope == "global" and rows[0].protection == (DB,)


def test_rule_and_suppress_wrappers(env) -> None:
    app, _root, writes = env
    app.cfg.guardrail.rules = GuardrailRulesConfig(enable=["SEC-AWS-KEY"])
    assert _run(app, "rule", "disable", "sec-aws-key").exit_code == 0
    assert writes[-1][0] == [
        config_writer.Change("guardrail.rules.disable", ["SEC-AWS-KEY"]),
        config_writer.Change("guardrail.rules.enable", unset=True),
    ]
    result = _run(app, "suppress", "add", "SUPP-BUILD", "--finding", "JUDGE-PII-IP", "--reason", "build farm")
    assert result.exit_code == 0, result.output
    assert writes[-1][0] == [
        config_writer.Change(
            "guardrail.rules.suppressions",
            [{"id": "SUPP-BUILD", "finding_pattern": "JUDGE-PII-IP", "reason": "build farm"}],
        )
    ]


def test_use_pack_writes_rule_pack_and_pins_custom_digest(env, tmp_path) -> None:
    app, root, writes = env
    app.cfg.guardrail.connectors = {"codex": PerConnectorGuardrailConfig(rule_pack_dir=str(root / "strict"))}
    assert _run(app, "use-pack", "permissive").exit_code == 0
    assert writes[-1][0] == [
        config_writer.Change("guardrail.rule_pack", "permissive"),
        config_writer.Change("guardrail.rule_pack_dir", unset=True),
        config_writer.Change("guardrail.connectors.codex.rule_pack", unset=True),
        config_writer.Change("guardrail.connectors.codex.rule_pack_dir", unset=True),
    ]
    custom = tmp_path / "Acme Pack"
    shutil.copytree(root / "default", custom)
    assert _run(app, "use-pack", str(custom), "--connector", "codex").exit_code == 0
    assert writes[-1][0][:2] == [
        config_writer.Change("guardrail.custom_packs.acme-pack", {"path": str(custom), "digest": "sha256:" + "a" * 64}),
        config_writer.Change("guardrail.connectors.codex.rule_pack", "acme-pack"),
    ]


def test_managed_device_refuses_with_exit_3(env, monkeypatch) -> None:
    app, _root, _writes = env

    def _refuse(*_a, **_k):
        raise config_writer.ManagedConfigWriteError("managed")

    monkeypatch.setattr(config_writer, "apply", _refuse)
    result = CliRunner().invoke(cmd_guardrail.guardrail, ["protection", "enable", DB], obj=app)
    assert result.exit_code == 3
    assert "managed" in result.output
