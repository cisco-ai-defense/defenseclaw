#!/usr/bin/env python3
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

"""Partition Python test files into deterministic, isolated CI shards."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TEST_ROOT = ROOT / "cli" / "tests"


@dataclass(frozen=True)
class Shard:
    files: tuple[Path, ...]
    weight: int


def discover_test_files(test_root: Path) -> list[Path]:
    """Return every pytest test module below *test_root* exactly once."""

    test_root = test_root.resolve()
    files = {
        path.resolve()
        for pattern in ("test_*.py", "*_test.py")
        for path in test_root.rglob(pattern)
        if path.is_file()
    }
    return sorted(files, key=lambda path: path.relative_to(test_root).as_posix())


def exclude_test_files(files: list[Path], excluded: list[Path]) -> list[Path]:
    """Remove explicitly isolated modules without allowing silent omissions."""

    resolved_files = [path.resolve() for path in files]
    resolved_excluded = [path.resolve() for path in excluded]
    if len(resolved_excluded) != len(set(resolved_excluded)):
        raise ValueError("excluded test files must be unique")
    missing = sorted(set(resolved_excluded) - set(resolved_files), key=Path.as_posix)
    if missing:
        rendered = ", ".join(path.as_posix() for path in missing)
        raise ValueError(f"excluded test files were not discovered: {rendered}")
    excluded_set = set(resolved_excluded)
    return [path for path in resolved_files if path not in excluded_set]


def partition_test_files(files: list[Path], shard_count: int) -> list[Shard]:
    """Greedily balance files by source size without splitting a module."""

    if shard_count < 1:
        raise ValueError("shard_count must be positive")
    if len(files) < shard_count:
        raise ValueError("shard_count cannot exceed the number of test files")

    buckets: list[list[Path]] = [[] for _ in range(shard_count)]
    weights = [0] * shard_count
    weighted_files = sorted(files, key=lambda path: (-path.stat().st_size, path.as_posix()))
    for path in weighted_files:
        shard_index = min(range(shard_count), key=lambda index: (weights[index], index))
        buckets[shard_index].append(path)
        weights[shard_index] += path.stat().st_size

    return [
        Shard(files=tuple(sorted(bucket, key=Path.as_posix)), weight=weights[index])
        for index, bucket in enumerate(buckets)
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shard-count", required=True, type=int)
    parser.add_argument("--shard-index", required=True, type=int)
    parser.add_argument("--test-root", type=Path, default=DEFAULT_TEST_ROOT)
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        type=Path,
        help="test module to omit from regular shards, relative to the repository root",
    )
    args = parser.parse_args()

    if args.shard_index < 0 or args.shard_index >= args.shard_count:
        parser.error("--shard-index must be within [0, --shard-count)")
    test_root = args.test_root.resolve()
    try:
        excluded = [(path if path.is_absolute() else ROOT / path).resolve() for path in args.exclude]
        files = exclude_test_files(discover_test_files(test_root), excluded)
        shards = partition_test_files(files, args.shard_count)
    except ValueError as exc:
        parser.error(str(exc))

    for path in shards[args.shard_index].files:
        try:
            print(path.relative_to(ROOT).as_posix())
        except ValueError:
            print(path.as_posix())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
