# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Test filenames name behavior rather than an internal release round."""

import os
import re
from pathlib import Path

ROUND_TAG = re.compile(r"(?:^|_)(?:r|g)\d{3}[a-z0-9]*(?:_|\.)")

# Directories that never hold repository-owned Go tests.
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "build", "dist"}


def tagged_go_tests(root: Path) -> list[str]:
    """Round-tagged *_test.go files anywhere under root (cmd/, internal/, test/ ...)."""
    tagged = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith("_test.go") and ROUND_TAG.search(name):
                tagged.append(str((Path(dirpath) / name).relative_to(root)))
    return sorted(tagged)


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


def test_go_test_filename_hygiene_scans_outside_internal(tmp_path):
    for rel in (
        "cmd/tool/identity_g732_test.go",
        "test/e2e/flow_r109_test.go",
        "internal/pkg/sub/floor_g608b_test.go",
    ):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("package x\n")
    for rel in (
        "cmd/tool/identity_verified_test.go",
        "vendor/dep/x_g732_test.go",
        "node_modules/dep/x_g732_test.go",
    ):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("package x\n")
    assert tagged_go_tests(tmp_path) == [
        "cmd/tool/identity_g732_test.go",
        "internal/pkg/sub/floor_g608b_test.go",
        "test/e2e/flow_r109_test.go",
    ]


def test_go_test_filenames_do_not_carry_round_tags():
    assert tagged_go_tests(Path(__file__).resolve().parents[2]) == []
