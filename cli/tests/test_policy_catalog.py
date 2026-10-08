# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for :mod:`defenseclaw.policy_catalog`."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from defenseclaw import policy_catalog as pc
from defenseclaw.config import PerConnectorGuardrailConfig, default_config

from tests.helpers import select_pack


@pytest.fixture
def policy_dir(tmp_path: Path) -> Path:
    d = tmp_path / "policies"
    d.mkdir()
    return d


def _by_name(items):
    return {item.name: item for item in items}


def test_builtin_summaries_match_yaml(policy_dir: Path) -> None:
    policies = _by_name(pc.list_named_policies(policy_dir))
    assert {"default", "strict", "permissive"} <= set(policies)

    default = policies["default"]
    assert (default.block_at, default.alert_at, default.install_block_at) == ("CRITICAL", "MEDIUM+", "HIGH+")
    assert default.firewall_default == "deny"
    assert default.hilt is False
    assert default.scanner_overrides == 4
    assert default.adds_webhooks is False  # webhooks: [] adds nothing (GAP-1273)
    assert default.edited is False
    assert default.sets_cisco is False
    assert default.builtin is True

    strict = policies["strict"]
    assert (strict.block_at, strict.alert_at, strict.install_block_at) == ("MEDIUM+", "LOW+", "MEDIUM+")
    assert strict.firewall_default == "deny"

    permissive = policies["permissive"]
    assert (permissive.block_at, permissive.alert_at, permissive.install_block_at) == ("CRITICAL", "HIGH+", "CRITICAL")
    assert permissive.firewall_default == "allow"
    assert permissive.scanner_overrides == 0


def test_firewall_template_is_not_a_named_policy(policy_dir: Path) -> None:
    names = {p.name for p in pc.list_named_policies(policy_dir)}
    assert "firewall-deny-default" not in names
    assert pc.get_policy("firewall-deny-default", policy_dir) is None
    assert pc.policy_file("firewall-deny-default", policy_dir) is not None
    assert not pc.is_named_policy({"version": "1.0", "default_action": "deny", "rules": []})
    assert pc.is_named_policy({"name": "x", "skill_actions": {}})
    assert pc.is_named_policy({"name": "bare"})
    assert not pc.is_named_policy(["not", "a", "mapping"])  # type: ignore[arg-type]


def test_active_policy_is_the_preset_the_config_holds(policy_dir: Path) -> None:
    # config_version 9 records no active policy: it is the preset whose
    # keys the config holds (no keys set is the shipped default).
    from defenseclaw.commands.cmd_policy import _admission_from_policy, _apply_policy_guardrail

    cfg = default_config()
    cfg.policy_dir = str(policy_dir)
    assert pc.active_policy_name(policy_dir, cfg) == "default"
    strict = pc.load_policy_yaml(pc.policy_file("strict", policy_dir))
    cfg.admission = _admission_from_policy(strict)
    _apply_policy_guardrail(cfg, strict)
    # `policy activate` also writes the preset watch settings.
    cfg.watch.rescan_enabled = strict["watch"]["rescan_enabled"]
    cfg.watch.rescan_interval_min = strict["watch"]["rescan_interval_min"]
    assert [p.name for p in pc.list_named_policies(policy_dir, cfg) if p.active] == ["strict"]
    cfg.guardrail.block_at = "LOW"
    assert pc.active_policy_name(policy_dir, cfg) == ""


def test_user_policy_shadows_builtin_and_bad_yaml_skipped(policy_dir: Path) -> None:
    (policy_dir / "default.yaml").write_text("name: default\ndescription: mine\nguardrail:\n  block_threshold: 3\n")
    (policy_dir / "broken.yaml").write_text("name: [unterminated\n")
    (policy_dir / "list.yaml").write_text("- a\n- b\n")
    (policy_dir / "custom.yaml").write_text(
        "name: custom\nskill_actions:\n  low:\n    install: block\n"
        "guardrail:\n  hilt:\n    enabled: true\ncisco_ai_defense:\n  endpoint: x\n"
    )
    policies = _by_name(pc.list_named_policies(policy_dir))
    assert "broken" not in policies and "list" not in policies
    mine = policies["default"]
    assert mine.description == "mine"
    assert mine.builtin is True
    assert mine.edited is True  # GAP-1458: an edited built-in stays a built-in
    assert mine.path == str(policy_dir / "default.yaml")
    assert mine.block_at == "HIGH+"
    assert mine.alert_at == "none"
    custom = policies["custom"]
    assert custom.install_block_at == "LOW+"
    assert custom.hilt is True
    assert custom.sets_cisco is True
    assert custom.adds_webhooks is False
    assert set(custom.to_json()) == {
        "name",
        "description",
        "builtin",
        "active",
        "path",
        "block_at",
        "alert_at",
        "install_block_at",
        "firewall_default",
        "hilt",
        "scanner_overrides",
        "adds_webhooks",
        "sets_cisco",
        "edited",
    }


def test_get_policy_rejects_traversal(policy_dir: Path) -> None:
    assert pc.get_policy("../default", policy_dir) is None
    assert pc.get_policy("", policy_dir) is None
    assert pc.get_policy("nope", policy_dir) is None
    assert pc.get_policy("default", policy_dir) is not None


# ---------------------------------------------------------------------------
# Rule packs
# ---------------------------------------------------------------------------


def _cfg(tmp_path: Path, *, connectors: dict[str, str] | None = None, global_dir: str = ""):
    cfg = default_config()
    cfg.data_dir = str(tmp_path)
    cfg.policy_dir = str(tmp_path / "policies")
    select_pack(cfg, cfg.guardrail, global_dir)
    cfg.guardrail.connectors = {name: PerConnectorGuardrailConfig() for name in (connectors or {})}
    for name, path in (connectors or {}).items():
        select_pack(cfg, cfg.guardrail.connectors[name], path)
    return cfg


def _make_pack(root: Path) -> Path:
    (root / "rules").mkdir(parents=True)
    return root


def test_presets_fall_back_to_bundled_when_not_seeded(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, connectors={"codex": ""})
    packs = _by_name(pc.discover_rule_packs(cfg))
    for preset in ("default", "strict", "permissive"):
        assert packs[preset].kind == "preset"
        assert os.path.isdir(packs[preset].path)
    g = pc.global_pack(cfg)
    assert (g.connector, g.pack, g.source) == ("global", "default", "default")
    assert packs["default"].used_by == ("global", "codex")


def test_discovery_and_effective_sources(tmp_path: Path) -> None:
    guardrail_root = tmp_path / "policies" / "guardrail"
    for preset in ("default", "strict", "permissive"):
        _make_pack(guardrail_root / preset)
    _make_pack(guardrail_root / "team")
    (guardrail_root / "empty").mkdir()
    external = _make_pack(tmp_path / "elsewhere" / "ext")

    cfg = _cfg(
        tmp_path,
        global_dir=str(guardrail_root / "strict"),
        connectors={"codex": str(external), "claudecode": ""},
    )
    packs = _by_name(pc.discover_rule_packs(cfg))
    assert packs["strict"].path == str(guardrail_root / "strict")
    assert packs["team"].kind == "custom"
    assert "empty" not in packs
    assert packs["ext"].path == str(external)
    assert packs["ext"].used_by == ("codex",)
    assert packs["strict"].used_by == ("global", "claudecode")
    assert packs["team"].used_by == ()

    g = pc.global_pack(cfg)
    assert (g.pack, g.source) == ("strict", "global")
    rows = {row.connector: row for row in pc.effective_packs(cfg)}
    assert (rows["codex"].pack, rows["codex"].source) == ("ext", "override")
    assert (rows["claudecode"].pack, rows["claudecode"].source) == ("strict", "global")
    assert rows["codex"].to_json() == {
        "connector": "codex",
        "pack": "ext",
        "path": str(external),
        "source": "override",
    }
    assert packs["ext"].to_json()["used_by"] == ["codex"]


def test_effective_packs_empty_without_connectors(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    cfg.claw.mode = ""
    cfg.guardrail.connector = ""
    assert pc.effective_packs(cfg) == []
