# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Test filenames name behavior rather than an internal release round."""

import re
from pathlib import Path


def test_go_test_filenames_do_not_carry_round_tags():
    root = Path(__file__).resolve().parents[2] / "internal"
    tagged = [
        str(path.relative_to(root))
        for path in root.rglob("*_test.go")
        if re.search(r"(?:^|_)r\d{3}(?:_|\.)", path.name)
    ]
    assert tagged == []
