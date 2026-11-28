# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""The repository tests score against a small test split, never the frozen gate split (not in the repository)."""

import os

os.environ.setdefault(
    "S7_HOLDOUT_SPLIT", os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata", "holdout-split-test.json")
)

# Fixture trees (make_fixture, gc_fixtures) go to a scratch dir, never the box's real ~/s7c/fx.
_FX = os.path.join(__import__("tempfile").mkdtemp(prefix="s7gate-fx-"), "fx")
os.environ.setdefault("S7_FX_BASE", _FX)
os.environ.setdefault("S7_FIXTURE_ROOT", _FX)
