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
    assert default.scanner_overrides == 5
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


def test_active_policy_is_the_activated_one_of_two_equal_presets(policy_dir: Path, tmp_path: Path) -> None:
    # GAP-1022: a policy created from strict holds strict's values; the one
    # `policy activate` named is the active one, until the config changes.
    from defenseclaw.commands.cmd_policy import _admission_from_policy, _apply_policy_guardrail

    # UTF-8 both ways: strict.yaml has non-ASCII comments, and the Windows
    # locale default (cp1252) would make the copy unreadable to the loader.
    (policy_dir / "w5-team.yaml").write_text(
        Path(pc.policy_file("strict", policy_dir)).read_text(encoding="utf-8").replace("name: strict", "name: w5-team"),
        encoding="utf-8",
    )
    cfg = default_config()
    cfg.policy_dir = str(policy_dir)
    cfg.data_dir = str(tmp_path)
    strict = pc.load_policy_yaml(pc.policy_file("strict", policy_dir))
    cfg.admission = _admission_from_policy(strict)
    _apply_policy_guardrail(cfg, strict)
    cfg.watch.rescan_enabled = strict["watch"]["rescan_enabled"]
    cfg.watch.rescan_interval_min = strict["watch"]["rescan_interval_min"]
    assert pc.active_policy_name(policy_dir, cfg) == "strict"  # nothing activated: first match
    pc.record_activated_policy(cfg, "w5-team")
    assert [p.name for p in pc.list_named_policies(policy_dir, cfg) if p.active] == ["w5-team"]
    pc.record_activated_policy(cfg, "strict")
    assert pc.active_policy_name(policy_dir, cfg) == "strict"
    pc.record_activated_policy(cfg, "w5-team")
    cfg.guardrail.block_at = "LOW"  # no longer the preset's values
    assert pc.active_policy_name(policy_dir, cfg) == ""


def test_active_policy_after_upgrade_from_a_release_that_kept_no_record(policy_dir: Path, tmp_path: Path) -> None:
    # GAP-1341: 1.0.5 wrote no policy_activated.json, only a policy-activate
    # audit event. A policy created from strict whose name sorts after
    # "strict" must stay the active one after the upgrade.
    from defenseclaw.commands.cmd_policy import _admission_from_policy, _apply_policy_guardrail
    from defenseclaw.db import Store
    from defenseclaw.models import Event

    (policy_dir / "u33a-pol.yaml").write_text(
        open(pc.policy_file("strict", policy_dir), encoding="utf-8").read().replace("name: strict", "name: u33a-pol")
    )
    cfg = default_config()
    cfg.policy_dir = str(policy_dir)
    cfg.data_dir = str(tmp_path)
    cfg.audit_db = str(tmp_path / "audit.db")
    strict = pc.load_policy_yaml(pc.policy_file("strict", policy_dir))
    cfg.admission = _admission_from_policy(strict)
    _apply_policy_guardrail(cfg, strict)
    cfg.watch.rescan_enabled = strict["watch"]["rescan_enabled"]
    cfg.watch.rescan_interval_min = strict["watch"]["rescan_interval_min"]
    assert pc.active_policy_name(policy_dir, cfg) == "strict"  # no audit database: first match
    store = Store(cfg.audit_db)
    store.init()
    store.log_event(Event(action="policy-activate", target="u33a-pol"))
    store.close()
    assert not os.path.exists(tmp_path / "policy_activated.json")
    assert [p.name for p in pc.list_named_policies(policy_dir, cfg) if p.active] == ["u33a-pol"]
    cfg.guardrail.block_at = "LOW"  # the config no longer holds the preset
    assert pc.active_policy_name(policy_dir, cfg) == ""


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
    # GAP-0903: the v8 -> v9 migration spells the same preset as per-type
    # shorthand and leaves built-in-equal values unset; it is still strict.
    from defenseclaw.config import AdmissionConfig

    migrated = AdmissionConfig()
    migrated.defaults.allow_list_bypass_scan = False
    migrated.skill.actions = {"critical": "quarantine", "high": "quarantine", "medium": "quarantine",
                              "low": "warn", "info": "warn"}
    cfg.admission = migrated
    from defenseclaw.enforce.admission import compile_admission

    mcp = compile_admission(cfg, "mcp")
    assert mcp.actions["HIGH"][0].install == "block"
    assert mcp.actions["MEDIUM"][0].install == "block"
    assert mcp.actions["LOW"][0].runtime == "disable"
    assert pc.active_policy_name(policy_dir, cfg) == "strict"
    migrated.mcp.actions["high"] = "warn"
    assert compile_admission(cfg, "mcp").actions["HIGH"][0].install == "none"
    migrated.mcp.actions.clear()
    cfg.guardrail.block_at = "LOW"
    assert pc.active_policy_name(policy_dir, cfg) == ""

    balanced_no_bypass = default_config()
    balanced_no_bypass.admission.defaults.allow_list_bypass_scan = False
    assert compile_admission(balanced_no_bypass, "mcp").actions["HIGH"][0].install == "none"


def test_activated_pre104_default_keeps_balanced_mcp_and_name(policy_dir: Path) -> None:
    from defenseclaw.commands.cmd_policy import _admission_from_policy, _apply_policy_guardrail
    from defenseclaw.enforce.admission import compile_admission

    old_default = pc.load_policy_yaml(Path(__file__).resolve().parents[2] / "testdata/legacy_default_1_0_3.yaml")
    assert old_default is not None
    cfg = default_config()
    cfg.policy_dir = str(policy_dir)
    cfg.admission = _admission_from_policy(old_default)
    # A 1.0.4 activation writes the HIGH that MCP inherits under MCP too
    # (GAP-1488); 1.0.0-1.0.3 wrote the block without it.
    assert cfg.admission.mcp.actions.pop("high") == cfg.admission.defaults.actions["high"]
    _apply_policy_guardrail(cfg, old_default)
    cfg.watch.rescan_enabled = old_default["watch"]["rescan_enabled"]
    cfg.watch.rescan_interval_min = old_default["watch"]["rescan_interval_min"]

    actions = compile_admission(cfg, "mcp").actions
    for severity in ("HIGH", "MEDIUM", "LOW"):
        assert (actions[severity][0].install, actions[severity][0].runtime) == ("none", "enable")
    assert actions["CRITICAL"][0].install == "block"
    assert pc.active_policy_name(policy_dir, cfg) == "default"

    cfg.admission.mcp.actions["high"] = "quarantine"
    assert compile_admission(cfg, "mcp").actions["HIGH"][0].install == "block"
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
