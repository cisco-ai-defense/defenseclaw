# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Every reader agrees on the hook fail mode a config.yaml that leaves it out runs (GAP-0719).

The model fills an unset ``guardrail.hook_fail_mode`` with a closed
placeholder. ``config get`` and the status JSON printed that placeholder as
the default while init, doctor and the rendered hooks said open (the per-user
default and permissive tiers keep a gateway outage fail-open; strict and a
managed standalone profile close it).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw import fail_mode
from defenseclaw.commands import cmd_config
from defenseclaw.config import default_config

from tests.environment import isolated_home_env


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    return tmp_path


def _config_get(home: Path, yaml_text: str, *args: str):
    config_path = home / "config.yaml"
    config_path.write_text("config_version: 9\ngateway: {}\nobservability: {}\n" + yaml_text, encoding="utf-8")
    with patch.object(cmd_config.config_module, "config_path", return_value=config_path):
        return CliRunner().invoke(cmd_config.config_cmd, ["get", *args])


@pytest.mark.parametrize(
    ("pack", "mode"),
    [("default", "open"), ("permissive", "open"), ("strict", "closed")],
)
def test_config_get_of_an_unset_key_prints_the_mode_the_tier_runs(home: Path, pack: str, mode: str) -> None:
    result = _config_get(home, f"guardrail: {{rule_pack: {pack}}}\n", "guardrail.hook_fail_mode")
    assert result.exit_code == 0, result.output
    assert result.stdout == f"{mode}\n"
    assert f"pack-default:{pack}" in result.stderr
    assert "closed" not in result.stderr or mode == "closed"


def test_config_get_of_an_unset_connector_key_prints_the_mode_the_tier_runs(home: Path) -> None:
    result = _config_get(
        home,
        "guardrail: {connector: codex, connectors: {codex: {mode: observe}}}\n",
        "guardrail.connectors.codex.hook_fail_mode",
    )
    assert result.exit_code == 0, result.output
    assert result.stdout == "open\n"
    assert "pack-default:default" in result.stderr


@pytest.mark.parametrize("saved", ["open", "closed"])
def test_config_get_of_a_saved_key_prints_the_saved_value(home: Path, saved: str) -> None:
    plain = _config_get(home, f"guardrail: {{hook_fail_mode: {saved}}}\n", "guardrail.hook_fail_mode")
    effective = _config_get(
        home, f"guardrail: {{hook_fail_mode: {saved}}}\n", "guardrail.hook_fail_mode", "--effective"
    )
    assert plain.exit_code == 0 and plain.stdout == f"{saved}\n"
    assert effective.exit_code == 0 and effective.stdout == f"{saved}\n"
    assert "config:guardrail.hook_fail_mode" in effective.stderr


def test_report_of_an_unset_mode_names_no_configured_value() -> None:
    cfg = default_config()
    cfg.guardrail.connector = "codex"
    cfg.guardrail.rule_pack = "default"
    report = fail_mode.connector_fail_mode_report(cfg, "codex", inspect_effective_policy=False)
    assert report["desired"] == "open"
    assert report["configured"] is None
    assert {item["name"]: item["mode"] for item in report["sources"]}["config"] is None


def test_report_of_a_saved_mode_keeps_the_configured_value() -> None:
    cfg = default_config()
    cfg.guardrail.connector = "codex"
    cfg.guardrail.rule_pack = "default"
    cfg.guardrail.hook_fail_mode = "closed"
    report = fail_mode.connector_fail_mode_report(cfg, "codex", inspect_effective_policy=False)
    assert report["configured"] == "closed"
    assert report["desired"] == "closed"


def test_every_reader_takes_the_default_from_one_resolver() -> None:
    cfg = default_config()
    cfg.guardrail.connector = "codex"
    for pack, mode in (("default", "open"), ("permissive", "open"), ("strict", "closed")):
        cfg.guardrail.rule_pack = pack
        assert cfg.guardrail.hook_fail_mode_resolution("codex") == (mode, f"pack-default:{pack}")
        assert cfg.guardrail.effective_hook_fail_mode("codex") == mode
