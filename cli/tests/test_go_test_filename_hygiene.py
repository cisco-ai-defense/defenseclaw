# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Test filenames name behavior rather than an internal release round."""

import re
from pathlib import Path

ROUND_TAG = re.compile(r"(?:^|_)(?:r|g)\d{3}[a-z0-9]*(?:_|\.)")


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


def test_go_test_filenames_do_not_carry_round_tags():
    root = Path(__file__).resolve().parents[2] / "internal"
    tagged = [
        str(path.relative_to(root))
        for path in root.rglob("*_test.go")
        if ROUND_TAG.search(path.name)
    ]
    assert tagged == []
