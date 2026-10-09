# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``guardrail list-packs --json`` and ``guardrail use-pack``.

use-pack writes ``guardrail[.connectors.C].rule_pack`` through the config
writer; the writer is recorded here, not run.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from defenseclaw import config_writer, policy_catalog, rulepack_validation
from defenseclaw.commands import cmd_guardrail
from defenseclaw.config import (
    CustomRulePack,
    GuardrailProfile,
    GuardrailRulesConfig,
    PerConnectorGuardrailConfig,
    default_config,
)
from defenseclaw.context import AppContext

from tests.environment import isolated_home_env
from tests.helpers import select_pack


def _valid(path, **_kwargs):
    return rulepack_validation.RulePackValidationResult(
        wire_version=1, kind="validation_result", valid=True, summary={"rule_count": 1, "digest": "c" * 64, "files_digest": "a" * 64}
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
    cfg.guardrail.rule_pack = "default"
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    writes: list[list[config_writer.Change]] = []

    def _apply(changes, actor, reason, expect_sha256=None, **_kwargs):
        writes.append(list(changes))
        return config_writer.WriteResult(generation=7, sha256="0" * 64)

    monkeypatch.setattr(config_writer, "apply", _apply)
    return app, guardrail_root, custom, writes


def _run(app, args):
    return CliRunner().invoke(cmd_guardrail.guardrail, args, obj=app, catch_exceptions=False)


def _multi(app, overrides: dict[str, str]):
    app.cfg.guardrail.connectors = {name: PerConnectorGuardrailConfig() for name in overrides}
    for name, path in overrides.items():
        select_pack(app.cfg, app.cfg.guardrail.connectors[name], path)


def test_global_switch_clears_overrides_and_reports_them(env):
    app, root, custom, writes = env
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
    assert len(writes) == 1
    assert not any(c.path.startswith("guardrail.connectors.claudecode") for c in writes[0])


def test_connector_scope_leaves_peers_alone(env):
    app, root, custom, writes = env
    _multi(app, {"codex": "", "claudecode": str(root / "permissive")})
    result = _run(app, ["use-pack", "team", "--connector", "codex", "--json"])
    # "team" isn't under <policy_dir>/guardrail, so it is not a known name.
    assert result.exit_code == 1
    assert json.loads(result.output)["ok"] is False
    assert writes == []

    result = _run(app, ["use-pack", str(custom), "--connector", "codex", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert (payload["scope"], payload["connector"], payload["cleared_overrides"]) == ("connector", "codex", [])
    paths = [c.path for c in writes[-1]]
    assert paths == [
        "guardrail.custom_packs.team",
        "guardrail.connectors.codex.rule_pack",
    ]


def test_connector_custom_path_cannot_replace_global_pack(env, tmp_path):
    app, _root, custom, writes = env
    app.cfg.guardrail.rule_pack = "team"
    app.cfg.guardrail.custom_packs = {
        "team": CustomRulePack(path=str(custom), digest="sha256:" + "a" * 64)
    }
    other = tmp_path / "another" / "team"
    (other / "rules").mkdir(parents=True)

    result = _run(app, ["use-pack", str(other), "--connector", "codex", "--json"])

    assert result.exit_code == 1
    assert json.loads(result.output)["ok"] is False
    assert app.cfg.guardrail.custom_packs["team"].path == str(custom)
    assert writes == []


def test_registered_custom_pack_key_is_selected_by_name(env):
    """GAP-0049: a guardrail.custom_packs key selects like config set guardrail.rule_pack does,
    keeping its pinned digest; a pack edited since it was pinned is refused."""
    app, _root, custom, writes = env
    app.cfg.guardrail.custom_packs = {"team": CustomRulePack(path=str(custom), digest="sha256:" + "a" * 64)}
    result = _run(app, ["use-pack", "team", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["pack"] == "team"
    assert writes[-1] == [config_writer.Change("guardrail.rule_pack", "team")]

    app.cfg.guardrail.custom_packs = {"team": CustomRulePack(path=str(custom), digest="sha256:" + "b" * 64)}
    refused = _run(app, ["use-pack", "team"])
    assert refused.exit_code == 1
    assert "config set guardrail.custom_packs.team.digest sha256:" + "a" * 64 in refused.output
    assert len(writes) == 1

    # GAP-0159: an unknown name lists the registered custom_packs names it could have been.
    unknown = _run(app, ["use-pack", "nosuch"])
    assert unknown.exit_code == 1 and "guardrail.custom_packs name (team)" in unknown.output


def test_bare_name_selects_installed_pack_over_cwd_folder(env, tmp_path, monkeypatch):
    """GAP-1576: an unrelated ./vsg2 folder does not shadow the installed vsg2 pack."""
    app, root, _custom, writes = env
    (root / "vsg2" / "rules").mkdir(parents=True)
    workdir = tmp_path / "work"
    (workdir / "vsg2").mkdir(parents=True)
    monkeypatch.chdir(workdir)
    result = _run(app, ["use-pack", "vsg2", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["path"] == str(root / "vsg2")
    assert writes[-1][0].value["path"] == str(root / "vsg2")
    assert config_writer.Change("guardrail.rule_pack", "vsg2") in writes[-1]


def test_unknown_connector_refused(env):
    app, _root, _custom, writes = env
    result = _run(app, ["use-pack", "strict", "--connector", "claudecode"])
    assert result.exit_code == 1
    assert writes == []


def test_invalid_pack_writes_nothing(env, monkeypatch):
    app, _root, _custom, writes = env
    monkeypatch.setattr(rulepack_validation, "validate_rule_pack", _invalid)
    result = _run(app, ["use-pack", "strict", "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["ok"] is False
    assert payload["validation"]["error"]["code"] == "bad_rule"
    assert writes == []


def test_validator_unavailable_preset_proceeds_custom_refuses(env, monkeypatch):
    """A custom pack is pinned by its validated digest, so without the
    validator it is refused even with --no-validate."""
    app, _root, custom, writes = env
    monkeypatch.setattr(rulepack_validation, "validate_rule_pack", _unavailable)

    preset = _run(app, ["use-pack", "permissive"])
    assert preset.exit_code == 0, preset.output
    assert writes[-1][0] == config_writer.Change("guardrail.rule_pack", "permissive")

    for extra in ([], ["--no-validate"]):
        refused = _run(app, ["use-pack", str(custom), *extra, "--json"])
        assert refused.exit_code == 2
        assert json.loads(refused.output)["ok"] is False
    assert len(writes) == 1


def test_clear_connector_override(env):
    app, root, custom, writes = env
    _multi(app, {"codex": str(custom), "claudecode": ""})
    result = _run(app, ["use-pack", "--clear", "--connector", "codex", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["connector"] == "codex"
    assert payload["path"] == str(root / "default")
    assert writes == [[config_writer.Change("guardrail.connectors.codex.rule_pack", unset=True)]]


def test_clear_connector_pack_drops_stale_rule_overrides(env, monkeypatch):
    app, _root, _custom, writes = env
    monkeypatch.setattr(policy_catalog, "pack_rule_defaults", lambda _path: {"SEC-AWS-KEY": True})
    monkeypatch.setattr(policy_catalog, "rule_defaults_with_protections", lambda _path, _packs: {"SEC-AWS-KEY": True})
    app.cfg.guardrail.connectors = {
        "codex": PerConnectorGuardrailConfig(
            rule_pack="strict", rules=GuardrailRulesConfig(disable=["SEC-ENV-DUMP-REQUEST"])
        )
    }
    result = _run(app, ["use-pack", "--clear", "--connector", "codex", "--json"])
    assert result.exit_code == 0, result.output
    assert writes[-1] == [
        config_writer.Change("guardrail.connectors.codex.rule_pack", unset=True),
        config_writer.Change("guardrail.connectors.codex.rules.disable", unset=True),
    ]
    assert json.loads(result.output)["dropped_rule_references"] == [
        "guardrail.connectors.codex.rules.disable: SEC-ENV-DUMP-REQUEST"
    ]


def test_global_pack_switch_keeps_profile_connector_rule_from_profile_protection(env, monkeypatch):
    app, _root, _custom, writes = env
    rule_id = "impact.sql_schema_destroy"
    protection = "database-destruction-protection"
    monkeypatch.setattr(policy_catalog, "pack_rule_defaults", lambda _path: {"other.rule": True})
    monkeypatch.setattr(
        policy_catalog,
        "rule_defaults_with_protections",
        lambda _path, packs: {"other.rule": True, **({rule_id: True} if protection in packs else {})},
    )
    app.cfg.guardrail.profiles = {
        "engineering": GuardrailProfile(
            rules=GuardrailRulesConfig(protections=[protection]),
            connectors={
                "codex": PerConnectorGuardrailConfig(
                    rules=GuardrailRulesConfig(severity_overrides={rule_id: "LOW"})
                )
            },
        )
    }
    result = _run(app, ["use-pack", "permissive", "--json"])
    assert result.exit_code == 0, result.output
    assert not any(c.path.endswith("severity_overrides") for c in writes[-1])
    assert json.loads(result.output)["dropped_rule_references"] == []


def test_usage_errors(env):
    app, _root, _custom, writes = env
    assert _run(app, ["use-pack"]).exit_code == 2
    assert _run(app, ["use-pack", "--clear"]).exit_code == 2
    assert _run(app, ["use-pack", "strict", "--clear", "--connector", "codex"]).exit_code == 2
    assert writes == []


def test_list_packs_json(env):
    app, root, custom, _writes = env
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


def test_validate_pack_unknown_bare_name_lists_available_packs(env, monkeypatch):
    app, root, _custom, _writes = env
    monkeypatch.setattr("defenseclaw.config.load", lambda: app.cfg)
    (root / "team2" / "rules").mkdir(parents=True)
    result = _run(app, ["validate-pack", "nosuchpack"])
    assert result.exit_code != 0
    assert "no pack with the name 'nosuchpack' was found" in result.output
    assert "default" in result.output and "team2" in result.output
