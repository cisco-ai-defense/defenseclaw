# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import pytest

from scripts.go_test_shards import discover_test_files, partition_test_files


def test_go_test_file_shards_are_deterministic_and_exhaustive(tmp_path: Path) -> None:
    (tmp_path / "small_test.go").write_text(
        "package sample\n"
        "func TestSmall(t *testing.T) {}\n"
        "func FuzzInput(f *testing.F) {}\n"
        "func ExampleSmall() {}\n",
        encoding="utf-8",
    )
    (tmp_path / "large_test.go").write_text(
        "package sample\n"
        "func TestLargeA(t *testing.T) {}\n"
        "func TestLargeB(t *testing.T) {}\n"
        + ("// weight\n" * 50),
        encoding="utf-8",
    )

    files = discover_test_files(tmp_path)
    first = partition_test_files(files, 2)
    second = partition_test_files(files, 2)

    assert first == second
    assert sorted(name for shard in first for name in shard) == [
        "ExampleSmall",
        "FuzzInput",
        "TestLargeA",
        "TestLargeB",
        "TestSmall",
    ]
    assert set(first[0]).isdisjoint(first[1])
    assert {"TestLargeA", "TestLargeB"} in (set(first[0]), set(first[1]))


def test_go_test_shards_reject_invalid_count() -> None:
    with pytest.raises(ValueError, match="positive"):
        partition_test_files([], 0)
    with pytest.raises(ValueError, match="cannot exceed"):
        partition_test_files([], 1)
