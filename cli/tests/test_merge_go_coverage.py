# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import pytest

from scripts.merge_go_coverage import merge_profiles, write_profile


def test_merge_go_coverage_sums_duplicate_blocks(tmp_path: Path) -> None:
    first = tmp_path / "first.out"
    second = tmp_path / "second.out"
    output = tmp_path / "coverage.out"
    first.write_text("mode: atomic\na.go:1.1,2.2 1 3\n", encoding="utf-8")
    second.write_text(
        "mode: atomic\na.go:1.1,2.2 1 4\nb.go:3.1,4.2 2 1\n",
        encoding="utf-8",
    )

    mode, blocks = merge_profiles([first, second])
    write_profile(output, mode, blocks)

    assert output.read_text(encoding="utf-8") == (
        "mode: atomic\na.go:1.1,2.2 1 7\nb.go:3.1,4.2 2 1\n"
    )


def test_merge_go_coverage_rejects_mixed_modes(tmp_path: Path) -> None:
    first = tmp_path / "first.out"
    second = tmp_path / "second.out"
    first.write_text("mode: atomic\na.go:1.1,2.2 1 1\n", encoding="utf-8")
    second.write_text("mode: set\na.go:1.1,2.2 1 1\n", encoding="utf-8")

    with pytest.raises(ValueError, match="mode mismatch"):
        merge_profiles([first, second])


def test_merge_go_coverage_uses_union_for_set_mode(tmp_path: Path) -> None:
    first = tmp_path / "first.out"
    second = tmp_path / "second.out"
    first.write_text("mode: set\na.go:1.1,2.2 1 1\n", encoding="utf-8")
    second.write_text("mode: set\na.go:1.1,2.2 1 1\n", encoding="utf-8")

    mode, blocks = merge_profiles([first, second])

    assert mode == "set"
    assert blocks == {"a.go:1.1,2.2 1": 1}
