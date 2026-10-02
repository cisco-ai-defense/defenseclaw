# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``guardrail protection list|enable|disable`` and the shared restart step."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml
from click.testing import CliRunner
from defenseclaw import policy_catalog as pc
from defenseclaw import rulepack_validation
from defenseclaw.commands import cmd_guardrail, cmd_setup
from defenseclaw.config import PerConnectorGuardrailConfig, default_config
from defenseclaw.context import AppContext

from tests.environment import isolated_home_env

DB = "database-destruction-protection"
PRIVACY = "privacy-high-assurance"
CLOUD = "cloud-production-protection"
K8S = "kubernetes-production-protection"


class _Validator:
    """Records the directories validated; answers valid unless told otherwise."""

    def __init__(self) -> None:
        self.paths: list[str] = []
        self.answer = "valid"

    def __call__(self, path, **_kwargs):
        self.paths.append(path)
        if self.answer == "unavailable":
            raise rulepack_validation.RulePackValidationBridgeError("no gateway binary", code="gateway_unavailable")
        if self.answer == "invalid":
            return rulepack_validation.RulePackValidationResult(
                wire_version=1,
                kind="validation_error",
                valid=False,
                error=rulepack_validation.RulePackValidationIssue(
                    path="rules/x.yaml", code="semantic_catalog_cost_limit", reason="too costly"
                ),
            )
        return rulepack_validation.RulePackValidationResult(
            wire_version=1, kind="validation", valid=True, summary={"rule_count": 1}
        )


@pytest.fixture
def env(tmp_path, monkeypatch):
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    validator = _Validator()
    monkeypatch.setattr(rulepack_validation, "validate_rule_pack", validator)
    root = tmp_path / "dc" / "policies" / "guardrail"
    for preset in pc.RULE_PACK_PRESETS:
        shutil.copytree(pc.preset_pack_dir(None, preset), root / preset)

    cfg = default_config()
    cfg.data_dir = str(tmp_path / "dc")
    cfg.policy_dir = str(tmp_path / "dc" / "policies")
    cfg.claw.mode = "codex"
    cfg.guardrail.connector = "codex"
    cfg.guardrail.enabled = True
    cfg.guardrail.mode = "action"
    cfg.guardrail.port = 4321
    cfg.guardrail.rule_pack_dir = str(root / "default")
    cfg.save = MagicMock()
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    return app, root, validator


def _run(app, *args):
    return CliRunner().invoke(cmd_guardrail.guardrail, ["protection", *args], obj=app, catch_exceptions=False)


def _json(result):
    # stdout only: restart progress and audit warnings go to stderr.
    assert result.stdout.strip(), result.output
    return json.loads(result.stdout)


def _multi(app, **overrides: str) -> None:
    app.cfg.guardrail.connectors = {
        name: PerConnectorGuardrailConfig(rule_pack_dir=path) for name, path in overrides.items()
    }


def _rule_ids(path: Path) -> list[str]:
    return [rule["id"] for rule in yaml.safe_load(path.read_text())["rules"]]


def test_enable_globally_composes_validates_then_switches(env) -> None:
    app, root, validator = env
    result = _run(app, "enable", DB, "--json")
    assert result.exit_code == 0, result.output
    payload = _json(result)
    final = root / "protected-global" / "default"
    assert payload == {
        "version": 1,
        "ok": True,
        "scope": "global",
        "pack_path": str(final),
        "protection": [DB],
        "validation": {"wire_version": 1, "kind": "validation", "valid": True, "summary": {"rule_count": 1}},
        "not_covered": [],
        "gateway": "not_running",
        "message": payload["message"],
    }
    # Validated the staging copy before anything pointed at it.
    assert len(validator.paths) == 1 and validator.paths[0] != str(final)
    assert not os.path.exists(validator.paths[0])
    manifest = json.loads((final / pc.PROTECTION_MANIFEST).read_text())
    assert manifest == {
        "version": 1,
        "base": os.path.realpath(root / "default"),
        "base_name": "default",
        "protection": [DB],
    }
    assert (final / "rules" / "commands.yaml").read_bytes() == (
        root / "default" / "rules" / "commands.yaml"
    ).read_bytes()
    assert _rule_ids(final / "rules" / "database-destruction.yaml")[0] == "impact.sql_unbounded_delete"
    gc = app.cfg.guardrail
    assert gc.rule_pack_dir == str(final)
    assert (gc.enabled, gc.mode, gc.port, gc.connectors) == (True, "action", 4321, {})
    app.cfg.save.assert_called_once()
    assert app.logger.log_config_change.call_args.args[0] == "guardrail-protection"  # a config-update mutation


def test_second_pack_recomposes_from_the_recorded_base(env) -> None:
    app, root, _validator = env
    assert _run(app, "enable", CLOUD).exit_code == 0
    payload = _json(_run(app, "enable", PRIVACY, "--json"))
    final = root / "protected-global" / "default"
    assert payload["protection"] == [PRIVACY, CLOUD]  # catalog order
    manifest = json.loads((final / pc.PROTECTION_MANIFEST).read_text())
    assert manifest["base"] == os.path.realpath(root / "default")
    assert pc.enabled_protection(str(final)) == (PRIVACY, CLOUD)
    # Policy Creator semantics: a pack's ids leave every base file.
    assert "tamper.cloud_audit_control_destruction" not in _rule_ids(final / "rules" / "commands.yaml")
    assert "tamper.cloud_audit_control_destruction" in _rule_ids(final / "rules" / "cloud-production.yaml")
    assert "PII-CARD-LABELED" in _rule_ids(final / "rules" / "enterprise-data.yaml")
    assert [p.name for p in final.parent.iterdir() if p.name.startswith(".")] == []  # no staging leftovers


def test_a_failed_save_puts_the_previous_composed_pack_back(env) -> None:
    app, root, _validator = env
    assert _run(app, "enable", CLOUD).exit_code == 0
    final = root / "protected-global" / "default"
    before = {path.relative_to(final): path.read_bytes() for path in final.rglob("*") if path.is_file()}
    # The saved config already points at `final`: a failed save must not
    # leave the recomposed pack there for the next gateway start.
    app.cfg.save.side_effect = OSError("disk full")
    result = _run(app, "enable", PRIVACY)
    assert result.exit_code == 1 and "disk full" in result.output
    after = {path.relative_to(final): path.read_bytes() for path in final.rglob("*") if path.is_file()}
    assert after == before
    assert pc.enabled_protection(str(final)) == (CLOUD,)
    assert [p.name for p in final.parent.iterdir() if p.name.startswith(".")] == []


def test_disable_keeps_the_rest_then_returns_to_the_base(env) -> None:
    app, root, _validator = env
    _run(app, "enable", DB)
    _run(app, "enable", K8S)
    final = root / "protected-global" / "default"

    payload = _json(_run(app, "disable", DB, "--json"))
    assert (payload["ok"], payload["protection"], payload["pack_path"]) == (True, [K8S], str(final))
    assert pc.enabled_protection(str(final)) == (K8S,)

    payload = _json(_run(app, "disable", K8S, "--json"))
    assert (payload["protection"], payload["pack_path"], payload["validation"]) == ([], str(root / "default"), None)
    assert app.cfg.guardrail.rule_pack_dir == str(root / "default")
    assert not final.exists() and not final.parent.exists()  # nothing uses the composed pack any more


def test_connector_scope_writes_only_that_override(env) -> None:
    app, root, _validator = env
    _multi(app, codex="", claudecode=str(root / "permissive"))
    payload = _json(_run(app, "enable", K8S, "--connector", "codex", "--json"))
    assert payload["ok"] is True and payload["scope"] == "codex"
    gc = app.cfg.guardrail
    assert gc.connectors["codex"].rule_pack_dir == str(root / "protected-codex" / "default")
    assert gc.connectors["claudecode"].rule_pack_dir == str(root / "permissive")
    assert gc.rule_pack_dir == str(root / "default")
    manifest = json.loads((root / "protected-codex" / "default" / pc.PROTECTION_MANIFEST).read_text())
    assert manifest["base_name"] == "default"  # it inherited the global pack


def test_single_connector_install_gets_an_override_block(env) -> None:
    app, root, _validator = env
    assert _run(app, "enable", DB, "--connector", "codex").exit_code == 0
    assert set(app.cfg.guardrail.connectors) == {"codex"}
    assert app.cfg.active_connectors() == ["codex"]
    assert _run(app, "enable", DB, "--connector", "claudecode").exit_code == 1


def test_global_scope_leaves_connector_packs_and_names_them(env) -> None:
    app, root, _validator = env
    _multi(app, codex=str(root / "strict"), claudecode="")
    payload = _json(_run(app, "enable", DB, "--json"))
    assert payload["not_covered"] == ["codex"]
    assert app.cfg.guardrail.connectors["codex"].rule_pack_dir == str(root / "strict")  # never cleared
    text = _run(app, "enable", DB)  # already on: still names the gap
    assert text.exit_code == 0 and "--connector codex" in text.output


def test_inherited_composed_pack_is_recomposed_for_the_connector(env) -> None:
    app, root, _validator = env
    _multi(app, codex="", claudecode="")
    _run(app, "enable", PRIVACY)
    payload = _json(_run(app, "enable", DB, "--connector", "codex", "--json"))
    assert payload["protection"] == [PRIVACY, DB]  # keeps what it inherited
    manifest = json.loads((root / "protected-codex" / "default" / pc.PROTECTION_MANIFEST).read_text())
    assert manifest["base"] == os.path.realpath(root / "default")


def test_invalid_composition_switches_nothing(env) -> None:
    app, root, validator = env
    validator.answer = "invalid"
    result = _run(app, "enable", DB, "--json")
    assert result.exit_code == 1
    payload = _json(result)
    assert payload["ok"] is False and payload["validation"]["error"]["code"] == "semantic_catalog_cost_limit"
    assert payload["pack_path"] == str(root / "default") and payload["protection"] == []
    assert sorted(p.name for p in root.iterdir()) == ["default", "permissive", "strict"]
    assert app.cfg.guardrail.rule_pack_dir == str(root / "default")
    app.cfg.save.assert_not_called()


def test_unavailable_validator_refuses_unless_no_validate(env) -> None:
    app, root, validator = env
    validator.answer = "unavailable"
    refused = _run(app, "enable", DB, "--json")
    assert refused.exit_code == 2 and _json(refused)["validation"]["error"]["code"] == "gateway_unavailable"
    app.cfg.save.assert_not_called()

    forced = _json(_run(app, "enable", DB, "--no-validate", "--json"))
    assert forced["ok"] is True and forced["validation"] is None
    _run(app, "enable", K8S, "--no-validate")
    # Disabling only removes rules: a missing validator warns and goes ahead.
    payload = _json(_run(app, "disable", DB, "--json"))
    assert payload["ok"] is True and payload["protection"] == [K8S]


@pytest.mark.parametrize(("name", "needle"), [("ssh-authorized-keys-protection", "staged"), ("nope", "no opt-in")])
def test_staged_and_unknown_packs_are_refused(env, name: str, needle: str) -> None:
    app, _root, _validator = env
    for verb in ("enable", "disable"):
        result = _run(app, verb, name, "--json")
        assert result.exit_code == 1
        payload = _json(result)
        assert payload["ok"] is False and needle in payload["message"].lower()
    app.cfg.save.assert_not_called()


def test_noops_and_a_foreign_directory(env) -> None:
    app, root, _validator = env
    off = _json(_run(app, "disable", DB, "--json"))
    assert off["ok"] is True and off["protection"] == []
    (root / "protected-global" / "default" / "rules").mkdir(parents=True)
    result = _run(app, "enable", DB, "--json")
    assert result.exit_code == 1 and "wasn't composed" in _json(result)["message"]
    assert not (root / "protected-global" / "default" / pc.PROTECTION_MANIFEST).exists()
    app.cfg.save.assert_not_called()


def test_list_json(env) -> None:
    app, root, _validator = env
    _multi(app, codex="", claudecode="")
    _run(app, "enable", DB, "--connector", "codex")
    payload = _json(_run(app, "list", "--json"))
    assert payload["version"] == 1
    assert [p["name"] for p in payload["packs"]][-1] == "ssh-authorized-keys-protection"
    assert {p["status"] for p in payload["packs"]} == {"selectable", "staged"}
    assert payload["scopes"] == [
        {"scope": "global", "pack": "default", "path": str(root / "default"), "enabled": []},
        {"scope": "claudecode", "pack": "default", "path": str(root / "default"), "enabled": []},
        {"scope": "codex", "pack": "protected-codex", "path": str(root / "protected-codex" / "default"), "enabled": [DB]},
    ]
    text = _run(app, "list")
    assert text.exit_code == 0 and DB in text.output


def test_running_gateway_is_restarted(env, monkeypatch) -> None:
    app, _root, _validator = env
    restarts: list[dict] = []

    def _restart(data_dir, **kwargs):
        restarts.append({"data_dir": data_dir, **kwargs})
        print("  defenseclaw-gateway: restarting... ✓")  # must not reach --json stdout
        return True

    monkeypatch.setattr(cmd_guardrail, "_gateway_running", lambda _app: True)
    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", _restart)
    payload = _json(_run(app, "enable", DB, "--json"))
    assert payload["gateway"] == "restarted"
    assert restarts == [{"data_dir": app.cfg.data_dir, "start_if_stopped": False}]

    assert _json(_run(app, "enable", K8S, "--no-restart", "--json"))["gateway"] == "restart_needed"
    assert len(restarts) == 1

    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", lambda *_a, **_k: False)
    failed = _run(app, "disable", K8S, "--json")
    assert failed.exit_code == 1
    assert _json(failed)["gateway"] == "restart_failed"

    app.cfg.guardrail.enabled = False
    assert _json(_run(app, "disable", DB, "--json"))["gateway"] == "guardrail_off"


def test_use_pack_restarts_a_running_gateway_too(env, monkeypatch) -> None:
    app, root, _validator = env
    calls: list[str] = []
    monkeypatch.setattr(cmd_guardrail, "_gateway_running", lambda _app: True)
    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", lambda data_dir, **_k: calls.append(data_dir) or True)
    result = CliRunner().invoke(cmd_guardrail.guardrail, ["use-pack", "strict", "--json"], obj=app)
    assert result.exit_code == 0, result.output
    assert _json(result)["gateway"] == "restarted" and calls == [app.cfg.data_dir]


def test_audit_rejection_after_save_is_a_warning(env) -> None:
    from defenseclaw.logger import CanonicalObservabilityError

    app, _root, _validator = env
    app.logger.log_config_change.side_effect = CanonicalObservabilityError("admission was not confirmed")
    result = _run(app, "enable", DB)
    assert result.exit_code == 0, result.output
    app.cfg.save.assert_called_once()


def test_a_strict_base_stays_strict_after_layering(env) -> None:
    # The gateway reads tool-call block/alert levels from the pack folder name
    # (guardrailProfileForDir), so the composed folder must end in "strict".
    app, root, _validator = env
    _multi(app, codex=str(root / "strict"), claudecode="")
    payload = _json(_run(app, "enable", K8S, "--connector", "codex", "--json"))
    assert payload["ok"] is True
    composed = root / "protected-codex" / "strict"
    assert payload["pack_path"] == str(composed)
    assert pc.pack_profile(payload["pack_path"]) == "strict"
    assert app.cfg.guardrail.connectors["codex"].rule_pack_dir == str(composed)
    assert pc.pack_name_for_path(app.cfg, str(composed)) == ("protected-codex", "custom")
