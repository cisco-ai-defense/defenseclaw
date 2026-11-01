# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""config set data_dir moves the folders the gateway reads (GAP-2126)."""

import os

from click.testing import CliRunner
from defenseclaw import config as config_module
from defenseclaw.commands import cmd_config
from defenseclaw.context import AppContext

from tests.environment import isolated_home_env


def _install_home(tmp_path, monkeypatch):
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    home = tmp_path / "inst-home"
    home.mkdir()
    path = home / "config.yaml"
    path.write_text(
        f"config_version: 9\ndata_dir: {home.as_posix()}\nobservability: {{}}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(path))
    monkeypatch.setattr(cmd_config.config_module, "config_path", lambda: path)
    monkeypatch.setattr("defenseclaw.gateway.local_policy_digest", lambda *a, **kw: None)
    monkeypatch.setattr(cmd_config, "_refresh_stopped_gateway_hooks", lambda *a: [])
    return home, path


def test_omitted_paths_are_under_the_data_dir_config_yaml_names(tmp_path, monkeypatch):
    home, path = _install_home(tmp_path, monkeypatch)
    moved = tmp_path / "dcdata"
    path.write_text(
        f"config_version: 9\ndata_dir: {moved.as_posix()}\nobservability: {{}}\n",
        encoding="utf-8",
    )

    cfg = config_module.load()

    assert cfg.data_dir == moved.as_posix()
    assert cfg.policy_dir == os.path.join(str(moved), "policies")
    assert cfg.quarantine_dir == os.path.join(str(moved), "quarantine")
    assert cfg.plugin_dir == os.path.join(str(moved), "plugins")
    assert os.path.dirname(cfg.audit_db) == str(moved)


def test_config_set_data_dir_seeds_the_rule_packs_the_gateway_loads(tmp_path, monkeypatch):
    home, path = _install_home(tmp_path, monkeypatch)
    moved = tmp_path / "dcdata"

    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())

    assert result.exit_code == 0, result.output
    assert os.path.isdir(moved / "policies" / "guardrail" / "default"), result.output
    assert f"Seeded the rule packs and Rego policies in {moved / 'policies'}" in result.output
    get = CliRunner().invoke(cmd_config.config_cmd, ["get", "policy_dir"], obj=AppContext())
    assert get.exit_code == 0, get.output
    assert str(moved / "policies") in get.output
    # Moving back seeds the folder it moves to as well.
    again = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(home)], obj=AppContext())
    assert again.exit_code == 0, again.output
    assert os.path.isdir(home / "policies" / "guardrail" / "default"), again.output
