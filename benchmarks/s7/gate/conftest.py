# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""The repository tests score against a small test split, never the frozen gate split (not in the repository)."""

import os

os.environ.setdefault(
    "S7_HOLDOUT_SPLIT", os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata", "holdout-split-test.json")
)
