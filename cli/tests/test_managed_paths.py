# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Contract for the managed path manifest (.github/managed-paths.txt)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / ".github" / "managed-paths.txt"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check_managed_paths = _load("check_managed_paths")
ci_changes = _load("ci_changes")


def _sections() -> dict[str, tuple[str, ...]]:
    return ci_changes.parse_managed_manifest(MANIFEST.read_text(encoding="utf-8"))


def test_the_classifier_reads_this_manifest() -> None:
    assert ROOT / ci_changes.MANAGED_MANIFEST == MANIFEST


def test_the_repository_manifest_is_current() -> None:
    files = check_managed_paths.tracked_files()
    assert check_managed_paths.problems(_sections(), files, ci_changes._matches) == []


def test_every_managed_path_runs_the_managed_lanes() -> None:
    sections = _sections()
    included = sections["managed"] + sections["managed_impacting"]
    files = check_managed_paths.tracked_files()
    managed = [path for path in files if ci_changes.is_managed(path, included)]
    assert managed
    assert set(ci_changes.managed_patterns()) == set(included)
    outputs = ci_changes._outputs({"managed"}, [], [], "test")
    for lane in ("managed", "enterprise", "windows_go", "windows_python", "pwsh"):
        assert outputs[lane], lane


def test_a_stale_entry_is_reported() -> None:
    sections = {"managed": ("internal/gone/",), "managed_impacting": (), "excluded": ()}
    found = check_managed_paths.problems(sections, ["internal/managed/a.go"], ci_changes._matches)
    assert "[managed] internal/gone/: matches no tracked file" in found


def test_a_new_managed_looking_file_must_be_listed() -> None:
    sections = {"managed": ("internal/managed/",), "managed_impacting": (), "excluded": ()}
    files = ["internal/managed/a.go", "cli/defenseclaw/enterprise_mode.py", "internal/gateway/router.go"]
    found = check_managed_paths.problems(sections, files, ci_changes._matches)
    assert len(found) == 1
    assert found[0].startswith("cli/defenseclaw/enterprise_mode.py: looks managed")


def test_a_path_cannot_be_managed_and_excluded() -> None:
    sections = {"managed": ("docs/",), "managed_impacting": (), "excluded": ("docs/*.md",)}
    found = check_managed_paths.problems(sections, ["docs/a.md"], ci_changes._matches)
    assert found == ["docs/a.md: in [excluded] and in a managed section"]
