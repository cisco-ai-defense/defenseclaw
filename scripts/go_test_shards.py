#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Partition Go tests into deterministic, time-balanced CI shards.

Test mode (--package-dir): partition one package's top-level tests. With
--shard-index, print the -run regex of that shard (CI runs one shard per
job). With a command after "--", run the command once per shard, all shards
in parallel, each with its own -run regex appended; "{shard}" in an argument
becomes the shard index (for example -coverprofile=cover-{shard}.out). The
gateway package takes well over an hour as one race-enabled test binary, so
local targets use this form instead of one process.

Package mode (--packages-file): partition a `go list` package list (minus
--exclude) and print one shard, a line per item: a package to test whole,
or "<package><TAB><-run regex>" for a part of a package too slow for one
shard.

--timings names a JSON file of recorded seconds (scripts/test-timings/,
refreshed by scripts/update_test_timings.py). Tests stay together by file
unless a file alone weighs more than half a shard; a test or package with no
recorded time still runs and weighs the recorded mean of the package's
tests under two seconds ("*"), or the median recorded time. Without
timings a file weighs its source size. --check prints the shard weights and
fails unless every discovered test (test mode) or package (package mode) is
in exactly one shard. --match (test mode) keeps only the tests whose name a
`go test -run` pattern without "/" selects (an unanchored search), so a job
can shard a package's filtered subset.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST_FUNCTION_RE = re.compile(r"^func\s+((?:Test|Fuzz|Example)[A-Za-z0-9_]*)\s*\(", re.MULTILINE)


def discover_test_files(package_dir: Path) -> list[tuple[Path, tuple[str, ...]]]:
    discovered: list[tuple[Path, tuple[str, ...]]] = []
    for path in sorted(package_dir.glob("*_test.go")):
        names = tuple(sorted(set(TEST_FUNCTION_RE.findall(path.read_text(encoding="utf-8")))))
        if names:
            discovered.append((path, names))
    return discovered


def match_test_files(files: list[tuple[Path, tuple[str, ...]]], pattern: str) -> list[tuple[Path, tuple[str, ...]]]:
    """Keep the tests `go test -run pattern` runs (a pattern without "/"
    selects top-level names by unanchored search); drop files left empty."""
    if "/" in pattern:
        raise ValueError("--match takes a top-level -run pattern (no '/')")
    selector = re.compile(pattern)
    kept = [(path, tuple(name for name in names if selector.search(name))) for path, names in files]
    return [(path, names) for path, names in kept if names]


def load_timings(path: Path | None) -> dict:
    if path is None:
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: timings must be a JSON object")
    return data


def _median(values) -> float:
    recorded = [float(value) for value in values if float(value) > 0]
    return statistics.median(recorded) if recorded else 1.0


def balance(items: list[tuple[str, float]], shard_count: int) -> list[list[str]]:
    """Longest-processing-time greedy split: heaviest item first, each into
    the lightest shard (lowest index on ties). Deterministic for one input."""
    if shard_count <= 0:
        raise ValueError("shard_count must be positive")
    if len(items) < shard_count:
        raise ValueError("shard_count cannot exceed the number of items to shard")
    shards: list[list[str]] = [[] for _ in range(shard_count)]
    weights = [0.0] * shard_count
    for key, weight in sorted(items, key=lambda item: (-item[1], item[0])):
        shard = min(range(shard_count), key=lambda index: (weights[index], index))
        shards[shard].append(key)
        weights[shard] += weight
    return shards


def weighted_test_groups(
    files: list[tuple[Path, tuple[str, ...]]],
    shard_count: int,
    test_seconds: dict[str, float] | None,
) -> list[tuple[tuple[str, ...], float]]:
    """Units to balance: one per file, except that a file heavier than half
    a shard is split into one unit per test."""
    if test_seconds:
        default = float(test_seconds.get("*", _median(v for k, v in test_seconds.items() if k != "*")))
        weigh = lambda name: float(test_seconds.get(name, default))  # noqa: E731
        file_weights = [(path, names, sum(weigh(name) for name in names)) for path, names in files]
        limit = sum(weight for _, _, weight in file_weights) / shard_count / 2
        groups: list[tuple[tuple[str, ...], float]] = []
        for _, names, weight in file_weights:
            if weight > limit and len(names) > 1:
                groups.extend(((name,), weigh(name)) for name in names)
            else:
                groups.append((names, weight))
        return groups
    return [(names, float(path.stat().st_size)) for path, names in files]


def partition_test_files(
    files: list[tuple[Path, tuple[str, ...]]],
    shard_count: int,
    test_seconds: dict[str, float] | None = None,
) -> list[list[str]]:
    """Return each shard's sorted test names; every test lands in exactly one."""
    if shard_count <= 0:
        raise ValueError("shard_count must be positive")
    if len(files) < shard_count:
        raise ValueError("shard_count cannot exceed discovered test files")
    groups = weighted_test_groups(files, shard_count, test_seconds)
    keyed = {f"{index:06d}": names for index, (names, _) in enumerate(groups)}
    items = [(f"{index:06d}", weight) for index, (_, weight) in enumerate(groups)]
    return [sorted(name for key in shard for name in keyed[key]) for shard in balance(items, shard_count)]


def module_path(root: Path = ROOT) -> str:
    match = re.search(r"^module\s+(\S+)", (root / "go.mod").read_text(encoding="utf-8"), re.MULTILINE)
    if not match:
        raise ValueError("go.mod declares no module path")
    return match.group(1)


def partition_packages(
    packages: list[str],
    shard_count: int,
    timings: dict | None = None,
    root: Path = ROOT,
) -> list[list[tuple[str, str]]]:
    """Return each shard's (package, -run regex) items; an empty regex tests
    the whole package. A package heavier than 60% of a shard whose tests have
    recorded times is split into parts of at most half a shard."""
    timings = timings or {}
    package_seconds = timings.get("packages", {})
    test_seconds = timings.get("tests", {})
    default = _median(package_seconds.values())
    unique = sorted(set(packages))
    weights = {package: float(package_seconds.get(package, default)) for package in unique}
    target = sum(weights.values()) / shard_count if shard_count > 0 else 0
    prefix = module_path(root) + "/"
    items: dict[str, tuple[str, str, float]] = {}
    for package in unique:
        rel = package[len(prefix) :] if package.startswith(prefix) else ""
        recorded = test_seconds.get(rel)
        if recorded and weights[package] > 0.6 * target:
            files = discover_test_files(root / rel)
            parts = min(len(files), max(2, math.ceil(weights[package] / (0.5 * target))))
            if parts >= 2:
                for index, names in enumerate(partition_test_files(files, parts, recorded)):
                    fallback = float(recorded.get("*", _median(v for k, v in recorded.items() if k != "*")))
                    piece = sum(float(recorded.get(name, fallback)) for name in names)
                    items[f"{package}#{index:03d}"] = (package, shard_regex(names), piece)
                continue
        items[package] = (package, "", weights[package])
    shards = balance([(key, weight) for key, (_, _, weight) in items.items()], shard_count)
    return [sorted(items[key][:2] for key in shard) for shard in shards]


def check_exact_cover(shards: list[list[str]], expected: list[str]) -> list[str]:
    """Return problems unless every expected item is in exactly one shard."""
    seen: dict[str, int] = {}
    for shard in shards:
        for item in shard:
            seen[item] = seen.get(item, 0) + 1
    problems = [f"{item} is in {count} shards" for item, count in sorted(seen.items()) if count != 1]
    problems += [f"{item} is in no shard" for item in sorted(set(expected) - set(seen))]
    problems += [f"{item} was not discovered" for item in sorted(set(seen) - set(expected))]
    return problems


def regex_names(regex: str) -> list[str]:
    body = regex.removeprefix("^(?:").removesuffix(")$")
    return [re.sub(r"\\(.)", r"\1", name) for name in body.split("|")] if body else []


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


def _package_mode(args: argparse.Namespace, timings: dict) -> tuple[list[list[str]], list[str], list[str]]:
    listed = [line.strip() for line in args.packages_file.read_text(encoding="utf-8").splitlines()]
    listed = [package for package in listed if package]
    missing = sorted(set(args.exclude) - set(listed))
    if missing:
        raise ValueError(f"excluded packages were not listed: {', '.join(missing)}")
    expected = sorted(set(listed) - set(args.exclude))
    shards = partition_packages(expected, args.shard_count, timings)
    lines = [[f"{package}\t{regex}" if regex else package for package, regex in shard] for shard in shards]
    # Exact cover over packages, and over the tests of every split package.
    covered: list[list[str]] = []
    split: dict[str, list[list[str]]] = {}
    for shard in shards:
        covered.append([package for package, regex in shard if not regex])
        for package, regex in shard:
            if regex:
                split.setdefault(package, []).append(regex_names(regex))
    problems = check_exact_cover(covered + [[package] for package in split], expected)
    prefix = module_path() + "/"
    for package, parts in split.items():
        tests = sorted({name for _, names in discover_test_files(ROOT / package[len(prefix) :]) for name in names})
        problems += [f"{package}: {problem}" for problem in check_exact_cover(parts, tests)]
    return lines, expected, problems


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--package-dir", type=Path, help="test mode: the package directory")
    mode.add_argument("--packages-file", type=Path, help="package mode: `go list` output, one package per line")
    parser.add_argument("--exclude", action="append", default=[], help="package mode: a listed package to leave out")
    parser.add_argument("--shard-count", type=int, required=True)
    parser.add_argument("--shard-index", type=int)
    parser.add_argument("--timings", type=Path, help="recorded seconds (scripts/test-timings/*.json)")
    parser.add_argument("--check", action="store_true", help="print every shard and verify the exact cover")
    parser.add_argument("--match", help="test mode: keep only the tests this go test -run pattern selects")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command

    try:
        timings = load_timings(args.timings)
        if args.packages_file is not None:
            if command:
                parser.error("package mode does not run a command")
            if args.match is not None:
                parser.error("--match is for test mode")
            shards, expected, problems = _package_mode(args, timings)
        else:
            files = discover_test_files(args.package_dir)
            if args.match is not None:
                files = match_test_files(files, args.match)
            package_dir = args.package_dir.resolve()
            key = package_dir.relative_to(ROOT).as_posix() if package_dir.is_relative_to(ROOT) else ""
            shards = partition_test_files(files, args.shard_count, timings.get("tests", {}).get(key))
            expected = sorted({name for _, names in files for name in names})
            problems = check_exact_cover(shards, expected)
    except ValueError as exc:
        parser.error(str(exc))

    if args.check:
        for index, shard in enumerate(shards):
            print(f"shard {index}: {len(shard)} items")
        print(f"{len(expected)} {'packages' if args.packages_file is not None else 'tests'} discovered")
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1 if problems else 0
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    if (args.shard_index is None) == (not command):
        parser.error("pass either --shard-index, --check, or a command after --")
    if command:
        return run_shards(shards, command)
    if not 0 <= args.shard_index < args.shard_count:
        parser.error("shard-index must be within shard-count")
    selected = shards[args.shard_index]
    if not selected:
        parser.error("selected shard contains no tests")
    print("\n".join(selected) if args.packages_file is not None else shard_regex(selected))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
