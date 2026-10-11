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

import hashlib
import json
import shutil
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from defenseclaw import config_writer, rulepack_validation
from defenseclaw import policy_catalog as pc
from defenseclaw.commands import cmd_guardrail
from defenseclaw.config import (
    GuardrailProfile,
    GuardrailRulesConfig,
    PerConnectorGuardrailConfig,
    config_path_for_data_dir,
    default_config,
)
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
    cfg.guardrail.rule_pack = "default"
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
            wire_version=1, kind="validation", valid=True, summary={"rule_count": 1, "digest": "c" * 64, "files_digest": "a" * 64}
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


def test_scoped_disable_refuses_inherited_global_protection(env) -> None:
    app, _root, writes = env
    app.cfg.guardrail.rules = GuardrailRulesConfig(protections=[DB])
    result = _run(app, "protection", "disable", DB, "--connector", "codex", "--json")
    body = json.loads(result.stdout)
    assert result.exit_code == 1
    assert body["ok"] is False
    assert "global" in body["message"] and "still active" in body["message"]
    assert not writes


def test_protection_list_reads_config(env) -> None:
    app, _root, _writes = env
    app.cfg.guardrail.rules = GuardrailRulesConfig(protections=[DB])
    rows = pc.scope_postures(app.cfg)
    assert rows[0].scope == "global" and rows[0].protection == (DB,)


def test_protection_list_includes_profile_scopes(env) -> None:
    app, _root, _writes = env
    app.cfg.guardrail.profiles = {
        "contractors": GuardrailProfile(
            rules=GuardrailRulesConfig(protections=[DB]),
            connectors={"codex": PerConnectorGuardrailConfig(rules=GuardrailRulesConfig(protections=[K8S]))},
        )
    }
    result = _run(app, "protection", "list", "--json")
    assert result.exit_code == 0, result.output
    scopes = {row["scope"]: row["enabled"] for row in json.loads(result.output)["scopes"]}
    assert DB in scopes["profile:contractors"]
    assert set(scopes["profile:contractors/connector:codex"]) >= {DB, K8S}


def test_rule_and_suppress_wrappers(env) -> None:
    app, _root, writes = env
    app.cfg.guardrail.rules = GuardrailRulesConfig(enable=["SEC-AWS-KEY"])
    assert _run(app, "rule", "disable", "SEC-AWS-KEY").exit_code == 0
    assert writes[-1][0] == [
        config_writer.Change("guardrail.rules.disable", ["SEC-AWS-KEY"]),
        config_writer.Change("guardrail.rules.enable", unset=True),
    ]
    # The newer packs spell their IDs in lower case with dots: kept as typed, one key.
    assert _run(app, "rule", "severity", "impact.cloud_s3_data_delete", "HIGH").exit_code == 0
    assert writes[-1][0] == [
        config_writer.Change('guardrail.rules.severity_overrides["impact.cloud_s3_data_delete"]', "HIGH")
    ]
    assert _run(app, "rule", "disable", "exec.remote_ip_download_execute_same_artifact").exit_code == 0
    assert writes[-1][0] == [config_writer.Change("guardrail.rules.disable", ["exec.remote_ip_download_execute_same_artifact"])]
    result = _run(app, "suppress", "add", "SUPP-BUILD", "--finding", "JUDGE-PII-IP", "--reason", "build farm")
    assert result.exit_code == 0, result.output
    assert writes[-1][0] == [
        config_writer.Change(
            "guardrail.rules.suppressions",
            [{"id": "SUPP-BUILD", "finding_pattern": "JUDGE-PII-IP", "reason": "build farm"}],
        )
    ]
    # The list is read from config.yaml under the writer lock, so another writer's entry made
    # after this process loaded its config is kept, not overwritten (GAP-0304).
    config_path_for_data_dir(app.cfg.data_dir).write_text(
        "config_version: 9\nguardrail:\n  rules:\n    disable: [OTHER-RULE]\n", encoding="utf-8"
    )
    assert _run(app, "rule", "disable", "SEC-AWS-KEY").exit_code == 0
    assert writes[-1][0] == [config_writer.Change("guardrail.rules.disable", ["OTHER-RULE", "SEC-AWS-KEY"])]


def test_rule_severity_default_restores_profile_config_and_digest(env, monkeypatch) -> None:
    app, _root, _writes = env
    app.cfg.guardrail.profiles = {"everyone-default": GuardrailProfile()}
    path = config_path_for_data_dir(app.cfg.data_dir)
    original = (
        b"config_version: 9\nguardrail:\n  profiles:\n    everyone-default:\n"
        b"      mode: action\n      block_at: HIGH\n"
    )
    path.write_bytes(original)
    before_digest = hashlib.sha256(original).hexdigest()

    def apply(changes, _actor, _reason, **_kwargs):
        candidate, changed = config_writer._patch(path.read_bytes(), changes, str(path))
        path.write_bytes(candidate)
        return config_writer.WriteResult(generation=1, sha256=hashlib.sha256(candidate).hexdigest(), changed=changed)

    monkeypatch.setattr(config_writer, "apply", apply)
    for scope in ((), ("--connector", "codex")):
        assert _run(app, "rule", "severity", "MARKER-RULE", "LOW", "--profile", "everyone-default", *scope).exit_code == 0
        assert path.read_bytes() != original
        result = _run(app, "rule", "severity", "MARKER-RULE", "default", "--profile", "everyone-default", *scope)
        assert result.exit_code == 0, result.output
        assert path.read_bytes() == original
        assert hashlib.sha256(path.read_bytes()).hexdigest() == before_digest


def test_rule_severity_default_keeps_empty_assigned_profile(env, monkeypatch) -> None:
    app, _root, _writes = env
    app.cfg.guardrail.profiles = {"everyone-default": GuardrailProfile()}
    path = config_path_for_data_dir(app.cfg.data_dir)
    original = (
        b"config_version: 9\nguardrail:\n  profiles:\n    everyone-default: {}\n"
        b"  profile_assignments:\n    - profile: everyone-default\n      match:\n        users: [test-user]\n"
    )

    def apply(changes, actor, reason, **_kwargs):
        return config_writer.write_with(
            lambda current, source: config_writer._patch(current, changes, source),
            actor,
            reason,
            path=path,
        )

    monkeypatch.setattr(config_writer, "apply", apply)
    for scope in ((), ("--connector", "codex")):
        path.write_bytes(original)
        set_result = _run(app, "rule", "severity", "CMD-PIPE-CURL", "critical", "--profile", "everyone-default", *scope)
        assert set_result.exit_code == 0, set_result.output
        reset_result = _run(app, "rule", "severity", "CMD-PIPE-CURL", "default", "--profile", "everyone-default", *scope)
        assert reset_result.exit_code == 0, reset_result.output
        document = config_writer._parse_config_document(path.read_bytes())
        assert document["guardrail"]["profiles"]["everyone-default"] == {}
        assert document["guardrail"]["profile_assignments"][0]["profile"] == "everyone-default"


def test_rule_enable_of_a_rule_the_pack_ships_on_only_drops_its_disable_entry(env) -> None:
    # GAP-0258: rules.enable is for off-by-default rules; a leftover entry breaks a later pack switch.
    app, _root, writes = env
    app.cfg.guardrail.rules = GuardrailRulesConfig(disable=["SEC-AWS-KEY"])
    assert _run(app, "rule", "enable", "SEC-AWS-KEY").exit_code == 0
    assert writes[-1][0] == [config_writer.Change("guardrail.rules.disable", unset=True)]
    # A connector re-enabling a rule the global scope disabled still needs its own entry.
    app.cfg.guardrail.connectors = {"codex": PerConnectorGuardrailConfig()}
    app.cfg.guardrail.rules = GuardrailRulesConfig(disable=["SEC-AWS-KEY"])
    assert _run(app, "rule", "enable", "SEC-AWS-KEY", "--connector", "codex").exit_code == 0
    assert writes[-1][0] == [config_writer.Change("guardrail.connectors.codex.rules.enable", ["SEC-AWS-KEY"])]


def test_use_pack_drops_rule_references_the_new_pack_does_not_have(env) -> None:
    # GAP-0258/0261: a reference to a rule of the old pack must not block the switch away from it.
    app, _root, writes = env
    app.cfg.guardrail.rules = GuardrailRulesConfig(
        enable=["P0-GONE"], disable=["SEC-AWS-KEY", "P0-GONE"], severity_overrides={"P0-GONE": "LOW"}
    )
    result = _run(app, "use-pack", "permissive")
    assert result.exit_code == 0, result.output
    assert writes[-1][0] == [
        config_writer.Change("guardrail.rule_pack", "permissive"),
        config_writer.Change("guardrail.rules.enable", unset=True),
        config_writer.Change("guardrail.rules.disable", ["SEC-AWS-KEY"]),
        config_writer.Change("guardrail.rules.severity_overrides", unset=True),
    ]
    assert "Dropped rule references" in result.output and "guardrail.rules.enable: P0-GONE" in result.output


def test_use_pack_writes_rule_pack_and_pins_custom_digest(env, tmp_path) -> None:
    app, root, writes = env
    app.cfg.guardrail.connectors = {"codex": PerConnectorGuardrailConfig(rule_pack="strict")}
    assert _run(app, "use-pack", "permissive").exit_code == 0
    assert writes[-1][0] == [
        config_writer.Change("guardrail.rule_pack", "permissive"),
        config_writer.Change("guardrail.connectors.codex.rule_pack", unset=True),
    ]
    custom = tmp_path / "Acme Pack"
    shutil.copytree(root / "default", custom)
    assert _run(app, "use-pack", str(custom), "--connector", "codex").exit_code == 0
    assert writes[-1][0][:2] == [
        config_writer.Change("guardrail.custom_packs.acme-pack", {"path": str(custom), "digest": "sha256:" + "a" * 64}),
        config_writer.Change("guardrail.connectors.codex.rule_pack", "acme-pack"),
    ]


def test_managed_device_refuses_before_the_scope_is_checked(env, monkeypatch) -> None:
    # GAP-0168: a scope problem or "already on" must not be the answer.
    from defenseclaw.enforce import asset_lists

    app, _root, writes = env
    monkeypatch.setattr(asset_lists, "is_managed_standalone", lambda _cfg: True)
    result = _run(app, "protection", "enable", DB, "--connector", "nosuch")
    assert result.exit_code == 3
    assert "This device is managed" in result.output
    assert not writes


def test_managed_device_refuses_with_exit_3(env, monkeypatch) -> None:
    app, _root, _writes = env

    def _refuse(*_a, **_k):
        raise config_writer.ManagedConfigWriteError("managed")

    monkeypatch.setattr(config_writer, "apply", _refuse)
    result = CliRunner().invoke(cmd_guardrail.guardrail, ["protection", "enable", DB], obj=app)
    assert result.exit_code == 3
    assert "managed" in result.output
    app.logger.log_action.assert_called_once_with(
        "action",
        "guardrail.rules.protections",
        f"outcome=refused reason=managed_device command=guardrail protection enable {DB}",
    )


def test_preflight_names_the_managed_refusal_not_admin_elevation(env, monkeypatch, capsys) -> None:
    app, _root, _writes = env
    monkeypatch.setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "standalone")
    data_dir = Path(app.cfg.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "config.yaml").write_text("config_version: 9\ndeployment_mode: managed_enterprise\n")
    with pytest.raises(SystemExit) as exited:
        cmd_guardrail._preflight_config_write(app)
    assert exited.value.code == 3
    captured = capsys.readouterr()
    shown = " ".join((captured.out + captured.err).split())
    assert config_writer.MANAGED_REFUSAL in shown and "elevation" not in shown
