# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-0632: a broken ``guardrail.custom_packs`` entry is one config error.

Mirrors Go ``Config.CustomRulePackError``: the selection loads its built-in
fallback pack, the hook's outage mode follows the strict tier (closed), and
``doctor`` names the entry's error; a usable entry keeps its own folder.
"""

from __future__ import annotations

import os

import pytest
from defenseclaw import config as dcconfig
from defenseclaw import policy_catalog
from defenseclaw.commands.cmd_doctor import _DoctorResult, _emit_custom_pack_config_error
from defenseclaw.config import Config, CustomRulePack

PIN = "sha256:" + "a" * 64


def _cfg(tmp_path, name: str, entry: CustomRulePack) -> Config:
    cfg = Config()
    cfg.data_dir = str(tmp_path / "data")
    cfg.guardrail.rule_pack = name
    cfg.guardrail.custom_packs = {name: entry}
    return cfg


def _pack(tmp_path, name: str = "pack") -> str:
    path = tmp_path / name
    path.mkdir(exist_ok=True)
    (path / "suppressions.yaml").write_text("version: 1\n", encoding="utf-8")
    return str(path)


@pytest.mark.parametrize("name", ["strict", "default", "operator"])
@pytest.mark.parametrize("variant", ["blank path", "empty file set", "missing folder"])
def test_broken_entry_is_a_config_error_with_builtin_fallback(tmp_path, name, variant):
    entry = {
        "blank path": CustomRulePack(path="  ", digest=PIN),
        "empty file set": CustomRulePack(path=_pack(tmp_path), digest=policy_catalog.EMPTY_RULE_PACK_FILES_DIGEST.upper()),
        "missing folder": CustomRulePack(path=str(tmp_path / "missing"), digest=PIN),
    }[variant]
    cfg = _cfg(tmp_path, name, entry)
    problem = policy_catalog.custom_pack_problem(cfg, name)
    assert f"guardrail.custom_packs.{name}" in problem
    fallback = name if name in policy_catalog.RULE_PACK_PRESETS else "default"
    assert policy_catalog.builtin_rule_pack_fallback(name) == fallback
    assert os.path.basename(cfg.guardrail.effective_rule_pack_dir("codex")) == fallback
    assert cfg.guardrail.hook_policy_tier("codex") == "strict"
    assert cfg.guardrail.effective_hook_outage_fail_mode("codex") == "closed"

    result = _DoctorResult()
    _emit_custom_pack_config_error(cfg.guardrail, cfg, "codex", result)
    (row,) = result.checks
    assert row["status"] == "fail"
    assert f"guardrail.custom_packs.{name}" in row["detail"]
    assert f"built-in {fallback} pack" in row["detail"]
    assert "fail closed" in row["detail"]


def test_usable_entry_keeps_its_folder_and_posture(tmp_path):
    path = _pack(tmp_path)
    cfg = _cfg(tmp_path, "operator", CustomRulePack(path=path, digest=PIN))
    assert policy_catalog.custom_pack_problem(cfg, "operator") == ""
    assert cfg.guardrail.effective_rule_pack_dir("codex") == path
    assert cfg.guardrail.hook_policy_tier("codex") == "default"
    assert cfg.guardrail.effective_hook_outage_fail_mode("codex") == "open"
    result = _DoctorResult()
    _emit_custom_pack_config_error(cfg.guardrail, cfg, "codex", result)
    assert result.checks == []


def test_relative_path_is_relative_to_the_config_directory(tmp_path, monkeypatch):
    config_dir = tmp_path / "home"
    config_dir.mkdir()
    pack = _pack(config_dir)
    monkeypatch.setattr(dcconfig, "config_path_for_data_dir", lambda _data_dir=None: config_dir / "config.yaml")
    monkeypatch.chdir(tmp_path)
    cfg = _cfg(tmp_path, "operator", CustomRulePack(path="pack", digest=PIN))
    assert policy_catalog.custom_pack_problem(cfg, "operator") == ""
    assert cfg.guardrail.effective_rule_pack_dir("codex") == pack
    # "~" is not expanded: the gateway reads it as a relative path.
    tilde = _cfg(tmp_path, "operator", CustomRulePack(path="~/pack", digest=PIN))
    assert policy_catalog.custom_pack_problem(tilde, "operator")
