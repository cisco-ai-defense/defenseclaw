#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Partition one Go package's top-level tests into deterministic file shards."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

TEST_FUNCTION_RE = re.compile(
    r"^func\s+((?:Test|Fuzz|Example)[A-Za-z0-9_]*)\s*\(", re.MULTILINE
)


def discover_test_files(package_dir: Path) -> list[tuple[Path, tuple[str, ...]]]:
    discovered: list[tuple[Path, tuple[str, ...]]] = []
    for path in sorted(package_dir.glob("*_test.go")):
        names = tuple(sorted(set(TEST_FUNCTION_RE.findall(path.read_text(encoding="utf-8")))))
        if names:
            discovered.append((path, names))
    return discovered


def partition_test_files(
    files: list[tuple[Path, tuple[str, ...]]], shard_count: int
) -> list[list[str]]:
    if shard_count <= 0:
        raise ValueError("shard_count must be positive")
    if len(files) < shard_count:
        raise ValueError("shard_count cannot exceed discovered test files")
    shards: list[list[str]] = [[] for _ in range(shard_count)]
    weights = [0] * shard_count
    weighted_files = sorted(
        files,
        key=lambda item: (-item[0].stat().st_size, item[0].as_posix()),
    )
    for path, names in weighted_files:
        shard = min(range(shard_count), key=lambda index: (weights[index], index))
        shards[shard].extend(names)
        weights[shard] += path.stat().st_size
    for shard in shards:
        shard.sort()
    return shards


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-dir", type=Path, required=True)
    parser.add_argument("--shard-count", type=int, required=True)
    parser.add_argument("--shard-index", type=int, required=True)
    args = parser.parse_args()

    if not 0 <= args.shard_index < args.shard_count:
        parser.error("shard-index must be within shard-count")
    shards = partition_test_files(discover_test_files(args.package_dir), args.shard_count)
    names = shards[args.shard_index]
    if not names:
        parser.error("selected shard contains no tests")
    print("^(?:" + "|".join(re.escape(name) for name in names) + ")$")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
