"""Config writes with a custom data_dir go to the account config (rel-1-0-6 GAP-0232).

``defenseclaw config set data_dir ~/dcdata`` leaves config.yaml in the install
home. Every CLI write joined config.yaml to the data folder instead, so
``guardrail use-pack strict`` created a second config.yaml in ~/dcdata without
the account ports, and the hooks then read it and failed closed on the default
port. The CLI now resolves the account config with one shared helper.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml
from click.testing import CliRunner
from defenseclaw import config as config_module
from defenseclaw import config_writer, rulepack_validation
from defenseclaw import policy_catalog as pc
from defenseclaw.commands import cmd_guardrail
from defenseclaw.config import default_config
from defenseclaw.context import AppContext

from tests.environment import isolated_home_env

API_PORT = 19911


def _account(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    user = tmp_path / "home"
    for key, value in isolated_home_env(user).items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    home = user / ".defenseclaw"
    home.mkdir(parents=True)
    data = tmp_path / "dcdata"
    data.mkdir()
    (home / "config.yaml").write_text(
        f"config_version: 9\ndata_dir: {data}\ngateway:\n  api_port: {API_PORT}\n"
        "guardrail:\n  enabled: true\n  connector: codex\n  rule_pack: default\n"
    )
    return home, data


def test_a_custom_data_dir_reads_and_writes_the_account_config(tmp_path, monkeypatch) -> None:
    home, data = _account(tmp_path, monkeypatch)

    assert config_module.config_path_for_data_dir(str(data)) == home / "config.yaml"
    assert config_module.gateway_home_for_data_dir(str(data)) == str(home)
    assert config_module.load(data_dir=str(data)).gateway.api_port == API_PORT


def test_leftover_store_config_does_not_replace_active_home_config(tmp_path, monkeypatch) -> None:
    home, data = _account(tmp_path, monkeypatch)
    (data / "config.yaml").write_text("config_version: 9\ndata_dir: /unrelated/store\n")

    assert config_module.load().gateway.api_port == API_PORT
    assert config_module.config_path_for_data_dir(data) == home / "config.yaml"
    assert config_module.gateway_pid_path(data) == str(home / "gateway.pid")
    assert config_module.load(data_dir=data).gateway.api_port == API_PORT


def test_default_and_unrelated_data_dirs_keep_their_own_config(tmp_path, monkeypatch) -> None:
    home, _ = _account(tmp_path, monkeypatch)
    other = tmp_path / "other"
    other.mkdir()

    assert config_module.config_path_for_data_dir(str(home)) == home / "config.yaml"
    assert config_module.config_path_for_data_dir(str(other)) == other / "config.yaml"
    (other / "config.yaml").write_text("config_version: 9\n")
    assert config_module.config_path_for_data_dir(str(other)) == other / "config.yaml"


@pytest.mark.parametrize("mode_source", ["config", "service_pin"])
def test_explicit_managed_config_keeps_its_runtime_pid_home(tmp_path, monkeypatch, mode_source) -> None:
    runtime = tmp_path / "managed runtime"
    runtime.mkdir()
    active_config = tmp_path / "managed config.yaml"
    managed_line = "deployment_mode: managed_enterprise\n" if mode_source == "config" else ""
    active_config.write_text(
        f"config_version: 8\n{managed_line}data_dir: {runtime}\n"
    )
    monkeypatch.delenv("DEFENSECLAW_HOME", raising=False)
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    if mode_source == "service_pin":
        monkeypatch.setenv("DEFENSECLAW_DEPLOYMENT_MODE", "managed_enterprise")
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(active_config))

    assert config_module.gateway_pid_path(runtime) == str(runtime / "gateway.pid")


def test_use_pack_with_a_custom_data_dir_updates_the_account_config(tmp_path, monkeypatch) -> None:
    home, data = _account(tmp_path, monkeypatch)
    root = data / "policies" / "guardrail"
    for preset in pc.RULE_PACK_PRESETS:
        shutil.copytree(pc.preset_pack_dir(None, preset), root / preset)
    cfg = default_config()
    cfg.data_dir = str(data)
    cfg.policy_dir = str(data / "policies")
    cfg.claw.mode = "codex"
    cfg.guardrail.connector = "codex"
    cfg.guardrail.enabled = True
    cfg.guardrail.rule_pack = "default"
    cfg.save = MagicMock()
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    targets: list[str] = []

    def apply(changes, _actor, _reason, *, path=None, **_kwargs):
        targets.append(str(path))
        target = Path(path)
        current = target.read_bytes() if target.exists() else b""
        candidate, changed = config_writer._patch(current, changes, str(target))
        target.write_bytes(candidate)
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

    result = CliRunner().invoke(cmd_guardrail.guardrail, ["use-pack", "strict"], obj=app, catch_exceptions=False)

    assert result.exit_code == 0, result.output
    assert targets and set(targets) == {str(home / "config.yaml")}
    assert not (data / "config.yaml").exists(), "use-pack created a second config.yaml in the data dir"
    saved = yaml.safe_load((home / "config.yaml").read_text())
    assert saved["guardrail"]["rule_pack"] == "strict"
    assert saved["gateway"]["api_port"] == API_PORT
