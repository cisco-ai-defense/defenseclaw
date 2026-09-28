# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Pure tests for :mod:`defenseclaw.rulepack_compose` (Policy Creator layering)."""

from __future__ import annotations

import copy
import json
import os
import shutil
from pathlib import Path

import pytest
import yaml
from defenseclaw import policy_catalog as pc
from defenseclaw import rulepack_compose as rc

from tests.environment import requires_symlink_privilege


def _file(category: str, *ids: str, **extra) -> dict:
    return {"version": 1, "category": category, "rules": [{"id": i, "title": i, **extra} for i in ids]}


def test_merge_drops_matching_ids_everywhere_then_appends_to_the_same_file() -> None:
    base = {
        "commands.yaml": _file("command", "CMD-1", "SHARED-1"),
        "enterprise-data.yaml": _file("enterprise-data", "ENT-1", "ENT-2"),
    }
    pristine = copy.deepcopy(base)
    privacy = [("enterprise-data.yaml", _file("enterprise-data-hi", "ENT-2", "ENT-NEW", severity="CRITICAL"))]
    cloud = [("cloud.yaml", _file("cloud-production-protection", "SHARED-1", "CLOUD-1"))]

    merged, changed = rc.merge_rule_files(base, [privacy, cloud])

    assert base == pristine  # inputs untouched
    assert changed == {"commands.yaml", "enterprise-data.yaml", "cloud.yaml"}
    assert [r["id"] for r in merged["commands.yaml"]["rules"]] == ["CMD-1"]
    ent = merged["enterprise-data.yaml"]
    assert ent["category"] == "enterprise-data-hi"  # the pack's category wins
    assert [r["id"] for r in ent["rules"]] == ["ENT-1", "ENT-2", "ENT-NEW"]
    assert ent["rules"][1]["severity"] == "CRITICAL"
    assert [r["id"] for r in merged["cloud.yaml"]["rules"]] == ["SHARED-1", "CLOUD-1"]


def test_merge_is_idempotent_for_a_pack_already_layered() -> None:
    base = {"a.yaml": _file("a", "A-1")}
    pack = [("p.yaml", _file("p", "P-1"))]
    once, _ = rc.merge_rule_files(base, [pack])
    twice, _ = rc.merge_rule_files(once, [pack])
    assert twice == once


def test_dumped_rule_files_round_trip_exactly() -> None:
    # The largest real rule file: regexes with quotes, backslashes, unicode.
    default = Path(pc.preset_pack_dir(None, "default"))
    for name in ("commands.yaml", "trust-exploit.yaml", "sensitive-paths.yaml"):
        data = yaml.safe_load((default / "rules" / name).read_text(encoding="utf-8"))
        assert yaml.safe_load(rc._dump_rule_file(data)) == data


def _pack_dir(root: Path, name: str) -> Path:
    path = root / name
    (path / "rules").mkdir(parents=True)
    (path / "rules" / "r.yaml").write_text(yaml.safe_dump(_file("r", "R-1")))
    return path


def test_resolve_base_follows_manifests(tmp_path: Path) -> None:
    base = _pack_dir(tmp_path, "team")
    composed = _pack_dir(tmp_path, "protected-global")
    (composed / pc.PROTECTION_MANIFEST).write_text(
        json.dumps({"version": 1, "base": str(base), "base_name": "team", "protection": []})
    )
    assert rc.resolve_base(None, str(composed)) == (str(base), "team")
    assert rc.resolve_base(None, str(base)) == (str(base), "team")

    shutil.rmtree(base)
    with pytest.raises(rc.ComposeError, match="no longer exists"):
        rc.resolve_base(None, str(composed))
    (composed / pc.PROTECTION_MANIFEST).write_text(
        json.dumps({"version": 1, "base": str(composed), "base_name": "x", "protection": []})
    )
    with pytest.raises(rc.ComposeError, match="points back"):
        rc.resolve_base(None, str(composed))
    with pytest.raises(rc.ComposeError, match="doesn't exist"):
        rc.resolve_base(None, str(tmp_path / "missing"))


def test_stage_copies_only_pack_components_and_writes_the_manifest(tmp_path: Path) -> None:
    base = tmp_path / "base"
    shutil.copytree(pc.preset_pack_dir(None, "default"), base)
    (base / "README.md").write_text("not a component")
    (base / ".git").mkdir()
    (base / ".git" / "config").write_text("[core]")
    final = tmp_path / "guardrail" / "protected-global"

    staged = Path(
        rc.stage_pack(
            base_dir=str(base),
            base_name="default",
            protection=["database-destruction-protection"],
            layer=["database-destruction-protection"],
            final=str(final),
        )
    )
    assert staged.parent == final.parent and staged.name.startswith(".protected-global.")
    assert not (staged / "README.md").exists() and not (staged / ".git").exists()
    for rel in ("suppressions.yaml", "sensitive-tools.yaml", "judge/pii.yaml", "rules/local-patterns.yaml"):
        assert (staged / rel).read_bytes() == (base / rel).read_bytes()
    assert (staged / "rules" / "commands.yaml").read_bytes() == (base / "rules" / "commands.yaml").read_bytes()
    added = yaml.safe_load((staged / "rules" / "database-destruction.yaml").read_text())
    assert [r["id"] for r in added["rules"]][0] == "impact.sql_unbounded_delete"
    manifest = json.loads((staged / pc.PROTECTION_MANIFEST).read_text())
    assert manifest == {
        "version": 1,
        "base": os.path.realpath(base),
        "base_name": "default",
        "protection": ["database-destruction-protection"],
    }

    rc.install_pack(str(staged), str(final))
    assert not staged.exists() and pc.enabled_protection(str(final)) == ("database-destruction-protection",)
    # Replacing an earlier composition goes through the same swap.
    again = rc.stage_pack(base_dir=str(base), base_name="default", protection=[], layer=[], final=str(final))
    rc.install_pack(again, str(final))
    assert pc.enabled_protection(str(final)) == ()
    assert [p.name for p in final.parent.iterdir()] == ["protected-global"]  # no backups left behind


def test_install_refuses_a_directory_it_did_not_compose(tmp_path: Path) -> None:
    final = _pack_dir(tmp_path, "protected-global")
    with pytest.raises(rc.ComposeError, match="wasn't composed"):
        rc.check_target(str(final))
    assert not rc.remove_pack(str(final))
    assert final.exists()


@requires_symlink_privilege
def test_stage_refuses_symlinked_components(tmp_path: Path) -> None:
    base = _pack_dir(tmp_path, "base")
    outside = tmp_path / "outside.yaml"
    outside.write_text(yaml.safe_dump(_file("x", "X-1")))
    (base / "rules" / "linked.yaml").symlink_to(outside)
    with pytest.raises(rc.ComposeError, match="symbolic link"):
        rc.stage_pack(base_dir=str(base), base_name="base", protection=[], layer=[], final=str(tmp_path / "p" / "x"))
    assert not (tmp_path / "p").exists() or not any((tmp_path / "p").iterdir())


def test_scope_names_are_directory_safe() -> None:
    assert rc.protected_scope_name("Codex") == "codex"
    for bad in ("", "../x", "a/b", "x" * 80):
        with pytest.raises(rc.ComposeError):
            rc.protected_scope_name(bad)
