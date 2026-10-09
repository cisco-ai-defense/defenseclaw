#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Partition one Go package top-level tests into deterministic file shards.

With --shard-index, print the -run regex of that shard (CI runs one shard per
job). With a command after "--", run the command once per shard, all shards in
parallel, each with its own -run regex appended; "{shard}" in an argument
becomes the shard index (for example -coverprofile=cover-{shard}.out). The
gateway package takes well over an hour as one race-enabled test binary, so
local targets use this form instead of one process.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
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


def shard_regex(names: list[str]) -> str:
    return "^(?:" + "|".join(re.escape(name) for name in names) + ")$"


def run_shards(shards: list[list[str]], command: list[str]) -> int:
    """Run command for every shard in parallel; print the output of each shard in shard order."""
    running: list[tuple[int, subprocess.Popen, object]] = []
    print(f"running {len(shards)} shards in parallel; output follows as each shard ends", flush=True)
    try:
        for index, names in enumerate(shards):
            argv = [arg.replace("{shard}", str(index)) for arg in command]
            log = tempfile.TemporaryFile()
            proc = subprocess.Popen(argv + ["-run", shard_regex(names)], stdout=log, stderr=subprocess.STDOUT)
            running.append((index, proc, log))
        failed: list[int] = []
        for index, proc, log in running:
            code = proc.wait()
            log.seek(0)
            sys.stdout.flush()
            sys.stdout.buffer.write(log.read())
            print(f"--- shard {index + 1}/{len(shards)} exit {code}", flush=True)
            if code != 0:
                failed.append(index + 1)
        if failed:
            print(f"FAIL: shards {failed} of {len(shards)}", file=sys.stderr)
            return 1
        return 0
    finally:
        for _, proc, log in running:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            log.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-dir", type=Path, required=True)
    parser.add_argument("--shard-count", type=int, required=True)
    parser.add_argument("--shard-index", type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command

    if (args.shard_index is None) == (not command):
        parser.error("pass either --shard-index or a command after --")
    shards = partition_test_files(discover_test_files(args.package_dir), args.shard_count)
    if command:
        return run_shards(shards, command)
    if not 0 <= args.shard_index < args.shard_count:
        parser.error("shard-index must be within shard-count")
    names = shards[args.shard_index]
    if not names:
        parser.error("selected shard contains no tests")
    print(shard_regex(names))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
