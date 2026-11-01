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


@pytest.mark.parametrize(
    ("add", "remove"),
    [
        (("rule", "severity", "SOME-RULE", "HIGH", "--connector", "codex"),
         ("rule", "severity", "SOME-RULE", "default", "--connector", "codex")),
        (("rule", "disable", "SEC-AWS-KEY", "--connector", "codex"),
         ("rule", "enable", "SEC-AWS-KEY", "--connector", "codex")),
        (("suppress", "add", "SUPP-BUILD", "--finding", "JUDGE-PII-IP", "--reason", "test", "--connector", "codex"),
         ("suppress", "remove", "SUPP-BUILD", "--connector", "codex")),
        (("protection", "enable", "database-destruction-protection", "--connector", "codex"),
         ("protection", "disable", "database-destruction-protection", "--connector", "codex")),
    ],
)
def test_guardrail_undo_on_a_single_connector_config_restores_the_exact_bytes(guardrail_app, add, remove) -> None:
    # GAP-0967 / GAP-1894: no 'connectors: codex: {}' after the undo when
    # guardrail.connector already names codex and there is no connectors map.
    app, path = guardrail_app
    original = b"config_version: 9\nguardrail:\n  enabled: true\n  connector: codex\n"
    path.write_bytes(original)
    app.cfg.guardrail.connectors = {}
    result = _guardrail(app, *add)
    assert result.exit_code == 0, result.output
    assert path.read_bytes() != original
    _reload_connectors(app, path)
    result = _guardrail(app, *remove)
    assert result.exit_code == 0, result.output
    assert path.read_bytes() == original, path.read_text()


def test_use_pack_clear_on_a_single_connector_config_restores_the_exact_bytes(guardrail_app) -> None:
    # GAP-1954: use-pack --clear left 'connectors: codex: {}' (the GAP-1894 class).
    app, path = guardrail_app
    original = b"config_version: 9\nguardrail:\n  enabled: true\n  connector: codex\n"
    path.write_bytes(original)
    app.cfg.guardrail.connectors = {}
    result = _guardrail(app, "use-pack", "strict", "--connector", "codex")
    assert result.exit_code == 0, result.output
    assert yaml.safe_load(path.read_text())["guardrail"]["connectors"] == {"codex": {"rule_pack": "strict"}}
    app.cfg.guardrail.connectors = {"codex": PerConnectorGuardrailConfig(rule_pack="strict")}
    result = _guardrail(app, "use-pack", "--clear", "--connector", "codex")
    assert result.exit_code == 0, result.output
    assert path.read_bytes() == original, path.read_text()


def test_use_pack_clear_keeps_an_entry_that_puts_the_connector_on_the_roster(guardrail_app) -> None:
    app, path = guardrail_app
    path.write_bytes(
        b"config_version: 9\nguardrail:\n  enabled: true\n  connector: codex\n"
        b"  connectors:\n    codex:\n      rule_pack: strict\n    claudecode: {}\n"
    )
    app.cfg.guardrail.connectors = {
        "codex": PerConnectorGuardrailConfig(rule_pack="strict"), "claudecode": PerConnectorGuardrailConfig()
    }
    result = _guardrail(app, "use-pack", "--clear", "--connector", "codex")
    assert result.exit_code == 0, result.output
    assert yaml.safe_load(path.read_text())["guardrail"]["connectors"] == {"codex": {}, "claudecode": {}}


def test_mode_clear_drops_only_a_redundant_entry(guardrail_app) -> None:
    # GAP-1954: mode --clear left 'connectors: codex: {mode: ""}' on a single-connector config.
    app, _path = guardrail_app
    app.cfg.guardrail.connectors = {}
    result = _guardrail(app, "mode", "observe", "--connector", "codex")
    assert result.exit_code == 0, result.output
    assert app.cfg.guardrail.connectors["codex"].mode == "observe"
    result = _guardrail(app, "mode", "--clear", "--connector", "codex")
    assert result.exit_code == 0, result.output
    assert app.cfg.guardrail.connectors == {}

    # With another entry on the roster the codex entry is what lists codex: it stays.
    app.cfg.guardrail.connectors = {
        "codex": PerConnectorGuardrailConfig(mode="observe"), "claudecode": PerConnectorGuardrailConfig()
    }
    result = _guardrail(app, "mode", "--clear", "--connector", "codex")
    assert result.exit_code == 0, result.output
    assert app.cfg.guardrail.connectors["codex"] == PerConnectorGuardrailConfig()


def test_guardrail_undo_on_a_claw_mode_only_config_keeps_the_codex_entry(guardrail_app) -> None:
    # GAP-1953: claw.mode codex, no guardrail.connector, connectors {codex: {}}.
    # Go hook enablement reads only guardrail.connector and the connectors map,
    # so pruning the entry would let Codex hook calls through unscanned.
    app, path = guardrail_app
    original = b"config_version: 9\nclaw:\n  mode: codex\nguardrail:\n  enabled: true\n  mode: action\n  connectors:\n    codex: {}\n"
    path.write_bytes(original)
    app.cfg.guardrail.connector = ""
    app.cfg.guardrail.connectors = {"codex": PerConnectorGuardrailConfig()}
    for level in ("HIGH", "default"):
        result = _guardrail(app, "rule", "severity", "SOME-RULE", level, "--connector", "codex")
        assert result.exit_code == 0, result.output
        _reload_connectors(app, path)
    assert yaml.safe_load(path.read_text())["guardrail"]["connectors"] == {"codex": {}}, path.read_text()
    assert cmd_guardrail.roster_entry_is_redundant(app.cfg, "codex", ["codex"]) is False


def test_guardrail_undo_keeps_an_entry_that_puts_the_connector_on_the_roster() -> None:
    # The entry stays when it is what puts the connector on the roster.
    cfg = default_config()
    cfg.claw.mode = "claudecode"
    cfg.guardrail.connector = "claudecode"
    assert cmd_guardrail._rule_prune_scope("codex", None, cfg) == "guardrail.connectors.codex"
    cfg.guardrail.connector = "codex"
    cfg.guardrail.connectors = {"codex": PerConnectorGuardrailConfig(), "claudecode": PerConnectorGuardrailConfig()}
    assert cmd_guardrail._rule_prune_scope("codex", None, cfg) == "guardrail.connectors.codex"
    cfg.guardrail.connectors = {"codex": PerConnectorGuardrailConfig()}
    assert cmd_guardrail._rule_prune_scope("codex", None, cfg) == "guardrail"
    assert cmd_guardrail._rule_prune_scope("codex", "pa", cfg) == "guardrail.profiles.pa"


def _wire() -> ConfigV8WireResult:
    return ConfigV8WireResult(
        wire_version=1,
        kind="effective",
        config_version=9,
        source="/tmp/config.yaml",
        data_dir="/tmp/dc",
        plan_digest="digest",
        network_validation="offline_syntax_and_literal_policy_only",
        valid=None,
        effective={},
    )


def _config(tmp_path: Path, monkeypatch, body: str) -> Path:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    path = tmp_path / "config.yaml"
    path.write_text("config_version: 9\n" + body)
    return path


def _config_cmd(*args: str):
    with (
        patch("defenseclaw.gateway.local_policy_digest", return_value=None),
        patch.object(cmd_config, "inspect_v8_config", return_value=_wire()),
    ):
        return CliRunner().invoke(cmd_config.config_cmd, list(args))


def test_profile_connector_leaf_unset_restores_the_exact_bytes(tmp_path: Path, monkeypatch) -> None:
    # GAP-1894: 'config unset' of a profile's connector override left
    # 'p.connectors.codex: {}'; the profile itself stays.
    path = _config(tmp_path, monkeypatch, "guardrail:\n  enabled: true\n  profiles:\n    pa:\n      description: a\n")
    before = path.read_bytes()
    key = "guardrail.profiles.pa.connectors.codex.rules.enable"
    added = _config_cmd("set", "--json", key, '["TRUST-IGNORE-PREVIOUS"]')
    assert added.exit_code == 0, added.output
    removed = _config_cmd("unset", key)
    assert removed.exit_code == 0, removed.output
    assert path.read_bytes() == before, path.read_text()


def test_get_reads_an_observability_default_config_set_wrote(tmp_path: Path, monkeypatch) -> None:
    # GAP-1901: config get said "not set and has no default" right after
    # config set wrote observability.defaults.redaction_profile.
    _config(tmp_path, monkeypatch, "observability:\n  defaults:\n    redaction_profile: content\n")
    with patch.object(cmd_config, "_key_view", return_value={"observability": {"destinations": []}}):
        result = CliRunner().invoke(
            cmd_config.config_cmd, ["get", "observability.defaults.redaction_profile"], catch_exceptions=False
        )
    assert result.exit_code == 0, result.output
    assert result.output.strip().splitlines()[-1] == "content", result.output
