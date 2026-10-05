# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The opt-in protection packs ship in the wheel and resolve without a checkout."""

from __future__ import annotations

import re
import sys
from fnmatch import fnmatchcase
from pathlib import Path

import pytest
from defenseclaw import paths
from defenseclaw import policy_catalog as pc

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
USE_CASES = ROOT / "policies" / "guardrail-use-cases"


def _package_data() -> list[str]:
    with open(ROOT / "pyproject.toml", "rb") as fh:
        return tomllib.load(fh)["tool"]["setuptools"]["package-data"]["defenseclaw"]


def _glob_match(pattern: str, rel: str) -> bool:
    # setuptools package-data globs never let "*" cross a "/".
    parts, names = pattern.split("/"), rel.split("/")
    return len(parts) == len(names) and all(fnmatchcase(n, p) for p, n in zip(parts, names))


def test_every_use_case_file_is_package_data() -> None:
    patterns = _package_data()
    files = sorted(p.relative_to(USE_CASES).as_posix() for p in USE_CASES.rglob("*") if p.is_file())
    assert files, "policies/guardrail-use-cases is empty"
    missing = [
        rel
        for rel in files
        if not any(_glob_match(pat, f"_data/policies/guardrail-use-cases/{rel}") for pat in patterns)
    ]
    assert missing == []


def test_bundle_steps_copy_the_use_case_packs() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    recipe = re.search(r"(?ms)^_bundle-data:.*?(?=^\S)", makefile)
    assert recipe
    assert "rm -rf cli/defenseclaw/_data/policies/guardrail-use-cases" in recipe.group(0)
    assert "cp -r policies/guardrail-use-cases cli/defenseclaw/_data/policies/" in recipe.group(0)

    harness = (ROOT / "scripts" / "windows-native-ci.ps1").read_text(encoding="utf-8")
    stage = re.search(r"(?ms)^function Stage-PackageData\b.*?(?=^function |\Z)", harness)
    assert stage and "policies\\guardrail-use-cases" in stage.group(0)


@pytest.mark.parametrize("wheel_first", [True, False])
def test_packaged_copy_wins_and_the_checkout_is_the_fallback(tmp_path, monkeypatch, wheel_first: bool) -> None:
    data, repo = tmp_path / "pkg" / "_data", tmp_path / "repo"
    for base in (data, repo) if wheel_first else (repo,):
        pack = base / "policies" / "guardrail-use-cases" / f"{base.name}-pack"
        (pack / "rules").mkdir(parents=True)
        (pack / "README.md").write_text(f"# {base.name}\n\nSummary.\n")
        (pack / "rules" / "r.yaml").write_text("version: 1\ncategory: r\nrules:\n  - id: R-1\n    pattern: 'a^'\n")
        (base / "policies" / "guardrail").mkdir(parents=True)
        (base / "policies" / "guardrail" / "tool-chains.json").write_text('{"version": 1, "chains": []}')
    monkeypatch.setattr(paths, "_DATA_DIR", data)
    monkeypatch.setattr(paths, "_REPO_ROOT", repo)

    winner = data if wheel_first else repo
    assert paths.bundled_guardrail_use_cases_dir() == winner / "policies" / "guardrail-use-cases"
    assert paths.bundled_tool_chains_file() == winner / "policies" / "guardrail" / "tool-chains.json"
    assert [p.name for p in pc.protection_packs()] == [f"{winner.name}-pack"]


def test_nothing_bundled_means_no_packs(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(paths, "_DATA_DIR", tmp_path / "none-a")
    monkeypatch.setattr(paths, "_REPO_ROOT", tmp_path / "none-b")
    assert paths.bundled_guardrail_use_cases_dir() is None
    assert paths.bundled_tool_chains_file() is None
    assert pc.protection_packs() == [] and pc.tool_chains() == [] and pc.enabled_protection("") == ()


def test_bundled_mcp_yara_pack_is_package_data_and_staged() -> None:
    """GAP-1084: the wheel shipped without policies/yara/mcp-tools."""
    patterns = _package_data()
    rules = sorted((ROOT / "policies" / "yara" / "mcp-tools").glob("*.yara"))
    assert rules
    missing = [
        rule.name
        for rule in rules
        if not any(_glob_match(pat, f"_data/policies/yara/mcp-tools/{rule.name}") for pat in patterns)
    ]
    assert missing == []

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    recipe = re.search(r"(?ms)^_bundle-data:.*?(?=^\S)", makefile)
    assert recipe
    assert "cp -r policies/yara/mcp-tools cli/defenseclaw/_data/policies/yara/" in recipe.group(0)

    harness = (ROOT / "scripts" / "windows-native-ci.ps1").read_text(encoding="utf-8")
    stage = re.search(r"(?ms)^function Stage-PackageData\b.*?(?=^function |\Z)", harness)
    assert stage and "policies\\yara\\mcp-tools" in stage.group(0)
