# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Protection packs, rule families, tool chains and scope posture in
:mod:`defenseclaw.policy_catalog`."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml
from defenseclaw import policy_catalog as pc
from defenseclaw.config import CustomRulePack, HILTConfig, PerConnectorGuardrailConfig, default_config

SELECTABLE = (
    "privacy-high-assurance",
    "cloud-production-protection",
    "database-destruction-protection",
    "infrastructure-destruction-protection",
    "kubernetes-production-protection",
)
STAGED = "ssh-authorized-keys-protection"


def _write_rules(path: Path, category: str, rules: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({"version": 1, "category": category, "rules": rules}, sort_keys=False))


def _rule(rule_id: str, **extra) -> dict:
    return {"id": rule_id, "pattern": "a^", "title": f"title {rule_id}", "severity": "HIGH", **extra}


def _default_copy(tmp_path: Path, name: str = "copy") -> Path:
    dest = tmp_path / name
    shutil.copytree(pc.preset_pack_dir(None, "default"), dest)
    return dest


def _cfg(tmp_path: Path):
    cfg = default_config()
    cfg.data_dir = str(tmp_path / "dc")
    cfg.policy_dir = str(tmp_path / "dc" / "policies")
    cfg.claw.mode = "codex"
    cfg.guardrail.connector = "codex"
    return cfg


# --- protection packs -----------------------------------------------------


def test_bundled_packs_are_the_use_case_tree() -> None:
    packs = pc.protection_packs()
    assert [p.name for p in packs] == [*SELECTABLE, STAGED]
    by_name = {p.name: p for p in packs}
    assert [by_name[n].rule_count for n in SELECTABLE] == [13, 4, 3, 5, 3]
    assert by_name[STAGED].status == "staged"
    assert by_name[STAGED].rule_ids == ()
    for pack in packs:
        # Every shipped pack has a hand-kept "covers" phrase that fits a cell.
        assert pack.covers == pc._PROTECTION_COVERS[pack.name]
        assert 0 < len(pack.covers) <= pc.COVERS_MAX_CHARS
        assert pack.title and "\n" not in pack.summary and pack.summary
        assert pack.rule_ids == tuple(rule.id for rule in pack.rules)
        assert pack.status == ("selectable" if pack.name in SELECTABLE else "staged")
    assert all(rule.severity and rule.title for rule in by_name["privacy-high-assurance"].rules)
    payload = by_name["database-destruction-protection"].to_json()
    assert payload["rule_ids"] == list(by_name["database-destruction-protection"].rule_ids)
    assert payload["rules"][0] == {
        "id": "impact.sql_unbounded_delete",
        "severity": "CRITICAL",
        "title": "SQL DELETE without a WHERE clause",
    }
    assert json.loads(json.dumps(payload)) == payload


def test_pack_readme_and_status_parsing(tmp_path: Path) -> None:
    root = tmp_path / "use-cases"
    alpha = root / "alpha"
    alpha.mkdir(parents=True)
    (alpha / "README.md").write_text(
        "# Alpha guard\n\nFirst paragraph\nwraps   here.\n\nSecond paragraph.\n", encoding="utf-8"
    )
    _write_rules(alpha / "rules" / "alpha.yaml", "alpha", [_rule("A-1"), _rule("A-2", severity="critical")])
    (alpha / "rules" / "notes.txt").write_text("ignored")
    staged = root / "zeta"
    staged.mkdir()
    (staged / "README.md").write_text("no heading here\n")
    (root / ".hidden").mkdir()
    (root / "stray.md").write_text("not a pack")

    packs = pc.protection_packs(root)
    assert [p.name for p in packs] == ["alpha", "zeta"]
    alpha_pack, zeta_pack = packs
    assert (alpha_pack.title, alpha_pack.summary) == ("Alpha guard", "First paragraph wraps here.")
    assert alpha_pack.status == "selectable" and alpha_pack.rule_ids == ("A-1", "A-2")
    assert alpha_pack.rules[1].severity == "CRITICAL"
    assert alpha_pack.covers == "Alpha guard"  # no hand-kept phrase: the title
    assert (zeta_pack.title, zeta_pack.status, zeta_pack.rule_count) == ("zeta", "staged", 0)
    assert pc.protection_packs(tmp_path / "missing") == []
    assert pc.protection_pack_dir("alpha", root) == str(alpha)
    assert pc.protection_pack_dir("../alpha", root) == ""


# --- enabled protection -----------------------------------------------------


def test_manifest_wins_in_catalog_order(tmp_path: Path) -> None:
    pack_dir = tmp_path / "protected-global"
    (pack_dir / "rules").mkdir(parents=True)
    (pack_dir / pc.PROTECTION_MANIFEST).write_text(
        json.dumps(
            {
                "version": 1,
                "base": "/somewhere/default",
                "base_name": "default",
                "protection": ["database-destruction-protection", "unknown-pack", STAGED, "privacy-high-assurance"],
            }
        )
    )
    manifest = pc.read_protection_manifest(str(pack_dir))
    assert manifest is not None and manifest.base_name == "default"
    assert pc.enabled_protection(str(pack_dir)) == ("privacy-high-assurance", "database-destruction-protection")

    (pack_dir / pc.PROTECTION_MANIFEST).write_text(json.dumps({"version": 2, "base": "x", "protection": []}))
    assert pc.read_protection_manifest(str(pack_dir)) is None
    (pack_dir / pc.PROTECTION_MANIFEST).write_text("{not json")
    assert pc.read_protection_manifest(str(pack_dir)) is None


def test_rule_match_needs_every_rule_present_and_unchanged(tmp_path: Path) -> None:
    for preset in pc.RULE_PACK_PRESETS:
        assert pc.enabled_protection(pc.preset_pack_dir(None, preset)) == ()
    assert pc.enabled_protection("") == ()

    pack_dir = _default_copy(tmp_path)
    source = Path(pc.protection_pack_dir("database-destruction-protection"))
    shutil.copy(source / "rules" / "database-destruction.yaml", pack_dir / "rules" / "database-destruction.yaml")
    assert pc.enabled_protection(str(pack_dir)) == ("database-destruction-protection",)

    path = pack_dir / "rules" / "database-destruction.yaml"
    data = yaml.safe_load(path.read_text())
    data["rules"][0]["severity"] = "HIGH"
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    assert pc.enabled_protection(str(pack_dir)) == ()

    data["rules"][0]["severity"] = "CRITICAL"
    data["rules"][1]["enabled"] = False
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    assert pc.enabled_protection(str(pack_dir)) == ()


# --- rule families ------------------------------------------------------------


def test_default_families_follow_the_reference_table() -> None:
    families = pc.rule_families("")
    assert [f.name for f in families] == [
        "command",
        "sensitive-path",
        "secret",
        "trust-exploit",
        "c2",
        "enterprise-data",
        "cognitive-file",
    ]
    assert all(f.description and 0 < f.enabled <= f.rules for f in families)
    by_name = {f.name: f for f in families}
    assert by_name["enterprise-data"].enabled < by_name["enterprise-data"].rules  # disabled lexical variants
    assert pc.rule_families(pc.preset_pack_dir(None, "default")) == families
    assert json.loads(json.dumps(families[0].to_json()))["name"] == "command"


def test_families_overlay_replaces_adds_and_keeps_all_disabled_defaults(tmp_path: Path) -> None:
    defaults = {f.name: f for f in pc.rule_families("")}
    pack_dir = tmp_path / "overlay"
    _write_rules(pack_dir / "rules" / "a.yaml", "command", [_rule("X-1"), _rule("X-2", enabled=False)])
    _write_rules(pack_dir / "rules" / "b.yaml", "cloud-production-protection", [_rule(f"C-{i}") for i in range(4)])
    _write_rules(pack_dir / "rules" / "c.yaml", "secret", [_rule("S-1", enabled=False)])
    (pack_dir / "rules" / "local-patterns.yaml").write_text("version: 1\n")

    families = pc.rule_families(str(pack_dir))
    by_name = {f.name: f for f in families}
    assert (by_name["command"].rules, by_name["command"].enabled) == (2, 1)
    # A file whose rules are all disabled leaves the built-in family in place.
    assert by_name["secret"] == defaults["secret"]
    added = families[-1]
    assert (added.name, added.rules, added.enabled) == ("cloud-production-protection", 4, 4)
    assert added.description == "Opt-in: " + pc._PROTECTION_COVERS["cloud-production-protection"]


# --- tool chains ----------------------------------------------------------------


def test_tool_chains_read_the_contract_shape(tmp_path: Path) -> None:
    path = tmp_path / "tool-chains.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "chains": [
                    {
                        "id": "chain.sql_read_then_delete",
                        "title": "Sensitive SQLite read → unbounded delete",
                        "severity": "HIGH",
                        "domain": "sql",
                        "can_block": True,
                        "event_window": 8,
                        "time_window_seconds": 1800,
                        "requires": ["same session", "exact identity join", ""],
                        "note": "Can block when the profile maps its severity to block",
                    },
                    {"title": "no id"},
                    "not a mapping",
                    {"id": "chain.minimal", "can_block": "yes", "event_window": True, "requires": "nope"},
                ],
            }
        )
    )
    chains = pc.tool_chains(path)
    assert [c.id for c in chains] == ["chain.sql_read_then_delete", "chain.minimal"]
    first, minimal = chains
    assert (first.domain, first.can_block, first.event_window, first.time_window_seconds) == ("sql", True, 8, 1800)
    assert first.requires == ("same session", "exact identity join")
    assert first.to_json()["requires"] == ["same session", "exact identity join"]
    assert (minimal.title, minimal.can_block, minimal.event_window, minimal.requires) == (
        "chain.minimal",
        False,
        0,
        (),
    )


@pytest.mark.parametrize("body", ["", "{", json.dumps({"version": 2, "chains": []}), json.dumps({"version": 1})])
def test_tool_chains_are_empty_when_missing_or_unknown(tmp_path: Path, body: str) -> None:
    path = tmp_path / "tool-chains.json"
    path.write_text(body)
    assert pc.tool_chains(path) == []
    assert pc.tool_chains(tmp_path / "absent.json") == []


# --- scope posture ----------------------------------------------------------------


def test_scope_postures_global_first_then_active_connectors(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    composed = tmp_path / "dc" / "policies" / "guardrail" / "protected-codex"
    (composed / "rules").mkdir(parents=True)
    (composed / pc.PROTECTION_MANIFEST).write_text(
        json.dumps(
            {
                "version": 1,
                "base": "/x/default",
                "base_name": "default",
                "protection": ["kubernetes-production-protection"],
            }
        )
    )
    cfg.guardrail.mode = "observe"
    cfg.guardrail.hilt = HILTConfig(enabled=True, min_severity="HIGH")
    cfg.guardrail.custom_packs["protected-codex"] = CustomRulePack(path=str(composed))
    cfg.guardrail.connectors = {
        "codex": PerConnectorGuardrailConfig(
            mode="action", hilt=HILTConfig(enabled=True, min_severity="CRITICAL"), rule_pack="protected-codex"
        ),
        "claudecode": PerConnectorGuardrailConfig(),
    }

    rows = pc.scope_postures(cfg)
    assert [r.scope for r in rows] == ["global", "claudecode", "codex"]
    glob, claude, codex = rows
    assert (glob.mode, glob.mode_source, glob.hilt, glob.pack, glob.pack_source, glob.protection) == (
        "observe",
        "global",
        "HIGH+",
        "default",
        "default",
        (),
    )
    assert (claude.mode, claude.mode_source, claude.hilt, claude.pack_path) == (
        "observe",
        "global",
        "HIGH+",
        glob.pack_path,
    )
    assert (codex.mode, codex.mode_source, codex.hilt, codex.pack, codex.pack_source) == (
        "action",
        "override",
        "CRITICAL",
        "protected-codex",
        "override",
    )
    assert codex.protection == ("kubernetes-production-protection",)
    assert codex.to_json()["protection"] == ["kubernetes-production-protection"]


def test_scope_postures_without_connectors_is_just_global(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    cfg.claw.mode = ""
    cfg.guardrail.connector = ""
    assert [r.scope for r in pc.scope_postures(cfg)] == ["global"]


@pytest.mark.parametrize(
    ("hilt", "label"),
    [
        (None, "off"),
        (HILTConfig(enabled=False, min_severity="LOW"), "off"),
        (HILTConfig(enabled=True, min_severity="critical"), "CRITICAL"),
        (HILTConfig(enabled=True, min_severity="HIGH"), "HIGH+"),
        (HILTConfig(enabled=True, min_severity="MEDIUM"), "MEDIUM+"),
        (HILTConfig(enabled=True, min_severity="LOW"), "LOW+"),
        (HILTConfig(enabled=True, min_severity=""), "HIGH+"),
    ],
)
def test_hilt_label(hilt, label: str) -> None:
    assert pc.hilt_label(hilt) == label


def test_mode_label() -> None:
    assert [pc.mode_label(v) for v in ("action", " ACTION ", "observe", "", None, "enforce")] == [
        "action",
        "action",
        "observe",
        "observe",
        "observe",
        "observe",
    ]
