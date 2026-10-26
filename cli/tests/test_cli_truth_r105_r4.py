# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""The CLI says the truth plainly (r105 cli-tui-obs round 4)."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from click.testing import CliRunner
from defenseclaw import config_writer, rulepack_validation
from defenseclaw import policy_catalog as pc
from defenseclaw.commands import cmd_config, cmd_guardrail
from defenseclaw.config import PerConnectorGuardrailConfig, config_path_for_data_dir, default_config
from defenseclaw.config_inspect import ConfigV8WireResult
from defenseclaw.context import AppContext

from tests.environment import isolated_home_env


@pytest.fixture
def guardrail_app(tmp_path, monkeypatch):
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
    path = config_path_for_data_dir(cfg.data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)

    def apply(changes, _actor, _reason, **_kwargs):
        candidate, changed = config_writer._patch(path.read_bytes(), changes, str(path))
        path.write_bytes(candidate)
        return config_writer.WriteResult(generation=1, sha256=hashlib.sha256(candidate).hexdigest(), changed=changed)

    monkeypatch.setattr(config_writer, "apply", apply)
    monkeypatch.setattr(
        rulepack_validation,
        "validate_rule_pack",
        lambda _path, **_k: rulepack_validation.RulePackValidationResult(
            wire_version=1,
            kind="validation",
            valid=True,
            summary={"rule_count": 1, "digest": "c" * 64, "files_digest": "a" * 64},
        ),
    )
    return app, path


def _guardrail(app, *args):
    return CliRunner().invoke(cmd_guardrail.guardrail, list(args), obj=app, catch_exceptions=False)


def _reload_connectors(app, path: Path) -> None:
    # The next command reads the config as the last one left it.
    listed = (yaml.safe_load(path.read_text()).get("guardrail") or {}).get("connectors") or {}
    app.cfg.guardrail.connectors = {name: PerConnectorGuardrailConfig() for name in listed}


def test_batch_set_then_unset_of_its_only_sibling_keeps_the_set() -> None:
    # GAP-1893: the unset's prune saw the document before the set, so it
    # removed the parent with the new key in it.
    current = b"config_version: 9\nguardrail:\n  connectors:\n    codex:\n      rules:\n        disable: [R]\n"
    candidate, _ = config_writer._patch(
        current,
        [
            config_writer.Change("guardrail.connectors.codex.rules.enable", ["R"]),
            config_writer.Change(
                "guardrail.connectors.codex.rules.disable", unset=True, prune_empty_to="guardrail.connectors.codex"
            ),
        ],
        "config.yaml",
    )
    assert yaml.safe_load(candidate)["guardrail"]["connectors"]["codex"] == {"rules": {"enable": ["R"]}}


def test_rule_enable_for_a_connector_writes_the_enable(guardrail_app) -> None:
    # GAP-1893 repro: R off globally and for codex; enable for codex must turn it on.
    app, path = guardrail_app
    from defenseclaw.config import GuardrailRulesConfig

    rule = "TRUST-IGNORE-PREVIOUS"
    path.write_bytes(
        b"config_version: 9\nguardrail:\n  connector: codex\n  rules:\n    disable: [" + rule.encode() + b"]\n"
        b"  connectors:\n    codex:\n      rules:\n        disable: [" + rule.encode() + b"]\n"
    )
    app.cfg.guardrail.rules = GuardrailRulesConfig(disable=[rule])
    app.cfg.guardrail.connectors = {"codex": PerConnectorGuardrailConfig(rules=GuardrailRulesConfig(disable=[rule]))}
    result = _guardrail(app, "rule", "enable", rule, "--connector", "codex")
    assert result.exit_code == 0, result.output
    codex = yaml.safe_load(path.read_text())["guardrail"]["connectors"]["codex"]
    assert codex == {"rules": {"enable": [rule]}}, codex
