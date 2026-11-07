# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Test filenames name behavior rather than an internal release round."""

import os
import re
import subprocess
from pathlib import Path

ROUND_TAG = re.compile(r"(?:^|_)(?:r|g)\d{3}[a-z0-9]*(?:_|\.)")

# Used only when root is not a git checkout; git-tracked paths need no exclusion.
NON_REPO_SKIP_DIRS = {".git", "node_modules", ".venv", "venv"}


def go_test_paths(root: Path) -> list[str]:
    """Go test files that belong to the repository: tracked, or new and not ignored.

    Tracked files count even under directories named build/ or dist/ (ignored for
    generated output), so a source package cannot hide a tagged test there.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            check=True,
            capture_output=True,
        ).stdout.decode()
    except (OSError, subprocess.CalledProcessError):
        paths = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in NON_REPO_SKIP_DIRS]
            paths += [str((Path(dirpath) / n).relative_to(root)) for n in filenames]
        return [p for p in paths if p.endswith("_test.go")]
    return [p for p in out.split(chr(0)) if p.endswith("_test.go")]


def tagged_go_tests(root: Path) -> list[str]:
    """Round-tagged *_test.go files anywhere in the repository."""
    return sorted(p for p in go_test_paths(root) if ROUND_TAG.search(Path(p).name))


def test_go_test_filename_hygiene_recognizes_release_identifiers():
    assert ROUND_TAG.search("inventory_identity_r109_g619_linux_test.go") is not None
    assert ROUND_TAG.search("openshell_floor_g608_test.go") is not None
    assert ROUND_TAG.search("inventory_identity_r1090_g0619b_linux_test.go") is not None
    assert ROUND_TAG.search("openshell_floor_g608b_test.go") is not None


def test_go_test_filename_hygiene_accepts_behavior_names():
    assert ROUND_TAG.search("inventory_identity_verified_lifecycle_linux_test.go") is None
    assert ROUND_TAG.search("ai_discovery_owner_identity_test.go") is None
    assert ROUND_TAG.search("openshell_prerequisite_floor_test.go") is None
    assert ROUND_TAG.search("generation_123_test.go") is None


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def test_go_test_filename_hygiene_scans_the_whole_repository(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("build/\ndist/\nvendor/\n")
    for rel in (
        "cmd/tool/identity_g732_test.go",
        "test/e2e/flow_r109_test.go",
        "internal/pkg/sub/floor_g608b_test.go",
        "internal/gateway/build/identity_g732_test.go",
        "internal/gateway/dist/identity_g732_test.go",
        "cmd/tool/identity_verified_test.go",
        "vendor/dep/x_g732_test.go",
        "build/out/x_g732_test.go",
    ):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("package x\n")
    # Tracked despite the ignore rule: a source package named build/ or dist/ is still checked.
    _git(tmp_path, "add", "-f", "internal/gateway/build", "internal/gateway/dist")
    assert tagged_go_tests(tmp_path) == [
        "cmd/tool/identity_g732_test.go",
        "internal/gateway/build/identity_g732_test.go",
        "internal/gateway/dist/identity_g732_test.go",
        "internal/pkg/sub/floor_g608b_test.go",
        "test/e2e/flow_r109_test.go",
    ]


def test_go_test_filename_hygiene_outside_git_checks_every_directory(tmp_path, monkeypatch):
    for rel in ("internal/gateway/build/identity_g732_test.go", "node_modules/dep/x_g732_test.go"):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("package x\n")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    assert tagged_go_tests(tmp_path) == ["internal/gateway/build/identity_g732_test.go"]


def test_go_test_filenames_do_not_carry_round_tags():
    assert tagged_go_tests(Path(__file__).resolve().parents[2]) == []
