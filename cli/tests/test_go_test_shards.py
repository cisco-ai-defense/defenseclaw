# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import sys
from pathlib import Path

import pytest

from scripts.go_test_shards import (
    check_exact_cover,
    discover_test_files,
    partition_packages,
    partition_test_files,
    regex_names,
    run_shards,
)


def test_go_test_file_shards_are_deterministic_and_exhaustive(tmp_path: Path) -> None:
    (tmp_path / "small_test.go").write_text(
        "package sample\nfunc TestSmall(t *testing.T) {}\nfunc FuzzInput(f *testing.F) {}\nfunc ExampleSmall() {}\n",
        encoding="utf-8",
    )
    (tmp_path / "large_test.go").write_text(
        "package sample\nfunc TestLargeA(t *testing.T) {}\nfunc TestLargeB(t *testing.T) {}\n" + ("// weight\n" * 50),
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


def test_run_shards_runs_every_shard_with_its_regex_and_fails_on_any(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Local race targets run the gateway package as parallel shards because one
    # race-enabled binary outlives the 60m timeout; every shard must run with
    # its own -run regex, and one failing shard must fail the target.
    probe = (
        'import sys; args = sys.argv[1:]; print("shard", args[0], args[args.index("-run") + 1]);'
        ' sys.exit(3 if args[0] == "1" else 0)'
    )
    command = [sys.executable, "-c", probe, "{shard}"]

    assert run_shards([["TestA"], ["TestB", "TestC"]], command) == 1
    out = capsys.readouterr().out
    assert "shard 0 ^(?:TestA)$" in out
    assert "shard 1 ^(?:TestB|TestC)$" in out
    assert "--- shard 2/2 exit 3" in out
    assert run_shards([["TestA"]], command) == 0


def _write_package(root: Path) -> Path:
    package = root / "pkg"
    package.mkdir()
    (package / "heavy_test.go").write_text(
        "package pkg\nfunc TestHeavyA(t *testing.T) {}\nfunc TestHeavyB(t *testing.T) {}\n", encoding="utf-8"
    )
    (package / "light_test.go").write_text(
        "package pkg\nfunc TestLightA(t *testing.T) {}\nfunc TestLightB(t *testing.T) {}\n", encoding="utf-8"
    )
    (package / "new_test.go").write_text("package pkg\nfunc TestUnrecorded(t *testing.T) {}\n", encoding="utf-8")
    return package


def test_timed_shards_split_a_heavy_file_and_still_run_unrecorded_tests(tmp_path: Path) -> None:
    files = discover_test_files(_write_package(tmp_path))
    seconds = {"TestHeavyA": 100.0, "TestHeavyB": 100.0, "TestLightA": 1.0, "TestLightB": 1.0, "*": 0.5}

    shards = partition_test_files(files, 2, seconds)

    assert partition_test_files(files, 2, seconds) == shards
    names = [name for shard in shards for name in shard]
    assert sorted(names) == ["TestHeavyA", "TestHeavyB", "TestLightA", "TestLightB", "TestUnrecorded"]
    # The heavy file outweighs half a shard, so its two tests land apart.
    assert {"TestHeavyA", "TestHeavyB"} not in (set(shards[0]), set(shards[1]))
    assert check_exact_cover(shards, sorted(names)) == []


def test_exact_cover_reports_missing_duplicate_and_unknown_items() -> None:
    problems = check_exact_cover([["A", "B"], ["B", "X"]], ["A", "B", "C"])

    assert "B is in 2 shards" in problems
    assert "C is in no shard" in problems
    assert "X was not discovered" in problems


def test_package_mode_splits_a_slow_package_and_covers_every_package_once(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.com/m\n", encoding="utf-8")
    _write_package(tmp_path)
    packages = ["example.com/m/pkg"] + [f"example.com/m/p{index}" for index in range(5)]
    timings = {
        "packages": {"example.com/m/pkg": 200.0, **{f"example.com/m/p{index}": 10.0 for index in range(4)}},
        "tests": {"pkg": {"TestHeavyA": 100.0, "TestHeavyB": 100.0, "*": 0.5}},
    }

    shards = partition_packages(packages, 3, timings, root=tmp_path)

    whole = sorted(package for shard in shards for package, regex in shard if not regex)
    parts = [regex_names(regex) for shard in shards for package, regex in shard if regex]
    # p4 has no recorded time and still runs.
    assert whole == [f"example.com/m/p{index}" for index in range(5)]
    assert len(parts) >= 2
    assert sorted(name for part in parts for name in part) == [
        "TestHeavyA",
        "TestHeavyB",
        "TestLightA",
        "TestLightB",
        "TestUnrecorded",
    ]


def test_windows_connector_shards_count_the_operator_collector_matrix() -> None:
    # GAP-2199: TestClaudeMarkedOperatorCollectorKeepsBytes runs 126 full
    # Claude Setup/Teardown subtests (231 s on a native Windows preflight
    # host). Unrecorded, it weighed the 0.18 s "*" default, so the balancer
    # put it beside a full 288 s shard and the connector package hit its
    # 660 s Go timeout on the hosted runner (a slow run, not a blocked write).
    import json
    import statistics

    root = Path(__file__).resolve().parents[2]
    timings = json.loads((root / "scripts/test-timings/go-windows.json").read_text(encoding="utf-8"))
    tests = timings["tests"]["internal/gateway/connector"]
    files = discover_test_files(root / "internal/gateway/connector")
    shards = partition_test_files(files, 16, tests)
    measured = dict(tests, TestClaudeMarkedOperatorCollectorKeepsBytes=231.3)
    default = tests["*"]
    weights = [sum(float(measured.get(name, default)) for name in shard) for shard in shards]
    holder = next(i for i, shard in enumerate(shards) if "TestClaudeMarkedOperatorCollectorKeepsBytes" in shard)
    assert weights[holder] <= 1.25 * statistics.median(weights), (holder, weights)
