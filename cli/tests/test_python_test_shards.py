# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.python_test_shards import discover_test_files, partition_test_files


def _write(path: Path, size: int) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x" * size, encoding="utf-8")
    return path.resolve()


def test_discovers_pytest_modules_once(tmp_path: Path) -> None:
    expected = {
        _write(tmp_path / "test_alpha.py", 10),
        _write(tmp_path / "nested" / "beta_test.py", 20),
    }
    _write(tmp_path / "helpers.py", 100)
    _write(tmp_path / "nested" / "conftest.py", 100)

    assert set(discover_test_files(tmp_path)) == expected


def test_partition_is_deterministic_exhaustive_and_balanced(tmp_path: Path) -> None:
    files = [_write(tmp_path / f"test_{index}.py", size) for index, size in enumerate((100, 80, 60, 40, 20, 10))]

    first = partition_test_files(files, 3)
    second = partition_test_files(list(reversed(files)), 3)

    assert first == second
    flattened = [path for shard in first for path in shard.files]
    assert sorted(flattened) == sorted(files)
    assert len(flattened) == len(set(flattened))
    assert max(shard.weight for shard in first) - min(shard.weight for shard in first) <= 10


@pytest.mark.parametrize("count", (0, -1, 7))
def test_partition_rejects_invalid_shard_counts(tmp_path: Path, count: int) -> None:
    files = [_write(tmp_path / f"test_{index}.py", 1) for index in range(6)]

    with pytest.raises(ValueError):
        partition_test_files(files, count)
