# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

from scripts.go_test_shards import partition_packages
from scripts.update_test_timings import (
    go_timings,
    keep_unreached_go_tests,
    keep_unreached_windows_packages,
    merge_go_timings,
    prune_retired,
    python_timings,
    runs_of,
    windows_go_timings,
)

STAMP = "2026-10-19T12:00:00.1234567Z"
MODULE = "github.com/example"


def _event(action: str, package: str, elapsed: float, test: str | None = None) -> str:
    event = {"Action": action, "Package": f"{MODULE}/{package}", "Elapsed": elapsed}
    if test is not None:
        event["Test"] = test
    return json.dumps(event)


def test_go_timings_sums_shards_and_keeps_slow_top_level_tests(tmp_path: Path) -> None:
    # Two CI shards of one package (go_test_report.py --timings files).
    (tmp_path / "a.json").write_text(
        "\n".join(
            [
                _event("pass", "pkg/a", 30.0, "TestSlow"),
                _event("pass", "pkg/a", 0.5, "TestFast"),
                _event("pass", "pkg/a", 0.1, "TestSlow/sub"),
                _event("pass", "pkg/a", 40.0),
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "b.json").write_text(
        "\n".join([_event("fail", "pkg/a", 25.0, "TestOther"), _event("fail", "pkg/a", 30.0), "not json"]),
        encoding="utf-8",
    )

    data = go_timings([tmp_path / "a.json", tmp_path / "b.json"], MODULE)

    assert data["packages"] == {f"{MODULE}/pkg/a": 70.0}
    assert data["tests"] == {"pkg/a": {"TestOther": 25.0, "TestSlow": 30.0, "*": 0.5}}


def test_go_timings_reads_events_after_a_log_prefix(tmp_path: Path) -> None:
    # A Windows job log (gh run view --log) puts the job and step names and a
    # timestamp before every event the go test -json run printed.
    prefix = f"Windows x64 Go suite / shard gw3\tFull native Windows Go test\t{STAMP} "
    log = tmp_path / "win.log"
    log.write_text(
        "\n".join(
            [
                prefix + _event("pass", "internal/gateway", 61.0, "TestSlow"),
                prefix + _event("pass", "internal/gateway", 62.0),
                prefix + _event("pass", "internal/gateway/connector/hookexec", 119.0, "TestHook"),
                prefix + _event("pass", "internal/gateway/connector/hookexec", 120.0),
                f"{prefix}[go-package-time] {MODULE}/internal/cli pass 40.5",
                prefix + "=== RUN   TestSlow",
            ]
        ),
        encoding="utf-8",
    )

    assert go_timings([log], MODULE)["tests"] == {
        "internal/gateway": {"TestSlow": 61.0, "*": 0.1},
        "internal/gateway/connector/hookexec": {"TestHook": 119.0, "*": 0.1},
    }
    windows = windows_go_timings([log], MODULE)
    assert windows["packages"] == {f"{MODULE}/internal/cli": 46.5}
    assert windows["tests"] == {
        "internal/gateway": {"TestSlow": 61.0, "*": 0.1},
        "internal/gateway/connector/hookexec": {"TestHook": 119.0, "*": 0.1},
    }


def test_go_timings_time_a_test_from_its_run_to_its_end(tmp_path: Path) -> None:
    # Windows Native CI dispatch 43024510603: the internal/hookpaths archive
    # table parts, whose subtests call t.Parallel, report an Elapsed of 0.01 s
    # but run 33 to 41 s each. Weighed as fast tests, all sixteen landed in one
    # part, which took 571 s. A test now weighs the time from its run event to
    # its end; a test whose Elapsed covers its run (the benign twin) keeps it.
    def at(seconds: float, action: str, test: str, elapsed: float = 0.0) -> str:
        event = json.loads(_event(action, "pkg/a", elapsed, test))
        event["Time"] = f"2026-11-11T13:05:{seconds:09.6f}1-05:00"
        return json.dumps(event)

    log = tmp_path / "pk6.log"
    log.write_text(
        "\n".join(
            [
                at(0.0, "run", "TestTable"),
                at(0.2, "run", "TestTable/ditto"),
                at(34.2, "pass", "TestTable/ditto", 34.0),
                at(35.0, "pass", "TestTable", 0.01),
                at(36.0, "run", "TestSerial"),
                at(46.0, "pass", "TestSerial", 10.0),
                _event("pass", "pkg/a", 70.0),
            ]
        ),
        encoding="utf-8",
    )

    assert go_timings([log], MODULE)["tests"] == {"pkg/a": {"TestSerial": 10.0, "TestTable": 35.0, "*": 0.1}}


def test_merge_go_timings_replaces_only_the_measured_packages() -> None:
    # go-darwin.json: the darwin connector parts refresh the connector
    # package; the enterpriseunix times recorded earlier stay.
    old = {
        "packages": {f"{MODULE}/pkg/a": 100.0, f"{MODULE}/pkg/b": 50.0},
        "tests": {"pkg/a": {"TestGone": 9.0, "*": 0.2}, "pkg/b": {"TestKept": 7.0, "*": 0.3}},
    }
    new = {"packages": {f"{MODULE}/pkg/a": 120.0}, "tests": {"pkg/a": {"TestNew": 30.0, "*": 0.4}}}

    data = merge_go_timings(old, new, MODULE)

    assert data["packages"] == {f"{MODULE}/pkg/a": 120.0, f"{MODULE}/pkg/b": 50.0}
    assert data["tests"] == {"pkg/a": {"TestNew": 30.0, "*": 0.4}, "pkg/b": {"TestKept": 7.0, "*": 0.3}}


def test_a_refresh_keeps_the_time_of_a_test_a_timed_out_shard_never_reached(tmp_path: Path) -> None:
    # The shard ended at its -timeout before TestUnreached ran: it keeps its
    # recorded time instead of weighing as an unlisted test. A test that ran
    # takes its new time, and a test the package no longer defines is dropped.
    package = tmp_path / "pkg" / "a"
    package.mkdir(parents=True)
    (package / "a_test.go").write_text(
        "package a\n\nfunc TestRan(t *testing.T) {}\n\nfunc TestUnreached(t *testing.T) {}\n\nfunc TestFast(t *testing.T) {}\n",
        encoding="utf-8",
    )
    log = tmp_path / "shard.json"
    log.write_text(
        "\n".join(
            [
                _event("pass", "pkg/a", 30.0, "TestRan"),
                _event("pass", "pkg/a", 0.5, "TestFast"),
                _event("fail", "pkg/a", 660.0),
            ]
        ),
        encoding="utf-8",
    )
    old = {"tests": {"pkg/a": {"TestRan": 10.0, "TestUnreached": 90.0, "TestFast": 40.0, "TestGone": 50.0, "*": 0.2}}}

    data = keep_unreached_go_tests(old, go_timings([log], MODULE), [log], MODULE, root=tmp_path)

    assert data["tests"]["pkg/a"] == {"*": 0.5, "TestRan": 30.0, "TestUnreached": 90.0}


HEAVY_PART_SECONDS = (180.492, 164.289, 244.576)


def _heavy_package_log(tmp_path: Path) -> Path:
    # One Windows run: the heavy package runs in three parts (one
    # [go-package-time] line each) and a few fifty small packages run whole.
    prefix = f"Windows x64 Go suite / shard pk4\tFull native Windows Go test\t{STAMP} "
    lines = []
    for seconds in HEAVY_PART_SECONDS:
        lines.append(f"{prefix}[go-package-time] {MODULE}/pkg/heavy pass {seconds}")
    for index in range(50):
        lines.append(f"{prefix}[go-package-time] {MODULE}/pkg/small{index} pass 20.0")
    log = tmp_path / "win.log"
    log.write_text("\n".join(lines), encoding="utf-8")
    return log


def test_windows_go_timings_sum_the_parts_of_a_split_package(tmp_path: Path) -> None:
    # A package run in parts prints one time per part; the record is the whole
    # package, every part and every link, not the last part.
    data = windows_go_timings([_heavy_package_log(tmp_path)], MODULE)

    assert data["packages"][f"{MODULE}/pkg/heavy"] == round(sum(HEAVY_PART_SECONDS) + 3 * 6.0, 1)
    assert data["packages"][f"{MODULE}/pkg/small0"] == 26.0


def test_a_timing_refresh_keeps_a_split_package_split(tmp_path: Path) -> None:
    # Refresh the record from a run that already split the package, then plan
    # the next run: the package is still placed in parts, not whole in one
    # shard (the whole package ran past the Windows step timeout).
    (tmp_path / "go.mod").write_text(f"module {MODULE}\n", encoding="utf-8")
    heavy = tmp_path / "pkg" / "heavy"
    heavy.mkdir(parents=True)
    for index in range(3):
        (heavy / f"part{index}_test.go").write_text(
            f"package heavy\nfunc TestPart{index}(t *testing.T) {{}}\n", encoding="utf-8"
        )
    refreshed = windows_go_timings([_heavy_package_log(tmp_path)], MODULE)
    refreshed["tests"] = {"pkg/heavy": {f"TestPart{i}": s for i, s in enumerate(HEAVY_PART_SECONDS)} | {"*": 0.1}}
    packages = [f"{MODULE}/pkg/heavy"] + [f"{MODULE}/pkg/small{index}" for index in range(50)]

    shards = partition_packages(packages, 3, refreshed, root=tmp_path)

    heavy_items = [(package, regex) for shard in shards for package, regex in shard if package.endswith("/heavy")]
    assert len(heavy_items) >= 2
    assert all(regex for _, regex in heavy_items)


def test_a_windows_refresh_keeps_the_time_of_a_package_its_timed_out_part_never_reached(tmp_path: Path) -> None:
    for rel in ("internal/reached", "internal/unreached"):
        (tmp_path / rel).mkdir(parents=True)
        (tmp_path / rel / "code.go").write_text("package p\n", encoding="utf-8")
    old = {
        "packages": {
            f"{MODULE}/internal/reached": 10.0,
            f"{MODULE}/internal/unreached": 300.0,
            f"{MODULE}/internal/removed": 5.0,
        },
        "tests": {},
    }
    log = tmp_path / "pk0.log"
    log.write_text(f"{STAMP} [go-package-time] {MODULE}/internal/reached pass 12.0\n", encoding="utf-8")

    data = keep_unreached_windows_packages(old, windows_go_timings([log], MODULE), MODULE, root=tmp_path)

    # The measured package takes its new time (with the link), the package
    # the step timeout never reached keeps its old one, and a package that
    # no longer exists is dropped.
    assert data["packages"] == {f"{MODULE}/internal/reached": 18.0, f"{MODULE}/internal/unreached": 300.0}


def _timed(seconds: float, action: str, package: str, test: str | None = None, elapsed: float = 0.0) -> str:
    event = json.loads(_event(action, package, elapsed, test))
    event["Time"] = f"2026-11-12T14:{int(seconds // 60):02d}:{seconds % 60:09.6f}1Z"
    return "2026-11-12T14:00:00.0000000Z " + json.dumps(event)


def test_a_windows_log_leaves_the_t_parallel_wait_out_of_a_test(tmp_path: Path) -> None:
    # A Windows part log has the go test -json events with their Time. A
    # t.Parallel test pauses until the serial tests of its package are done;
    # the refresh timed it from its run event and so weighed that wait too
    # (TestLater 60 s here, of which it ran 5). Its time is its share of the
    # package run after its cont event.
    log = tmp_path / "pk0.log"
    log.write_text(
        "\n".join(
            [
                _timed(0, "run", "internal/gateway", "TestLater"),
                _timed(0, "pause", "internal/gateway", "TestLater"),
                _timed(0, "run", "internal/gateway", "TestSerial"),
                _timed(55, "pass", "internal/gateway", "TestSerial", 55.0),
                _timed(55, "cont", "internal/gateway", "TestLater"),
                _timed(60, "pass", "internal/gateway", "TestLater", 5.0),
                _timed(60, "pass", "internal/gateway", None, 60.0),
                "[go-package-time] github.com/example/internal/gateway pass 60.0",
            ]
        ),
        encoding="utf-8",
    )

    tests = windows_go_timings([log], MODULE)["tests"]["internal/gateway"]
    assert tests["TestSerial"] == 55.0 and tests["TestLater"] == 5.0


def test_a_refresh_from_several_runs_weighs_the_slowest_run(tmp_path: Path) -> None:
    # A plan from fast runners must fit a slow one: each run directory is one
    # run, and a package or test weighs the slowest run that timed it. The
    # shards of one run still add up (pkg/a ran in two shards).
    seconds = {"r1": (30.0, 70.0), "r2": (90.0, 130.0), "r3": (40.0, 80.0)}
    for run, (slow, package) in seconds.items():
        (tmp_path / run).mkdir()
        (tmp_path / run / "shard-0.json").write_text(
            _event("pass", "pkg/a", slow, "TestSlow") + "\n" + _event("pass", "pkg/a", package / 2) + "\n",
            encoding="utf-8",
        )
        (tmp_path / run / "shard-1.json").write_text(_event("pass", "pkg/a", package / 2) + "\n", encoding="utf-8")
    (tmp_path / "r2" / "extra.json").write_text(_event("pass", "pkg/b", 5.0) + "\n", encoding="utf-8")

    runs = runs_of([tmp_path / "r1", tmp_path / "r2", tmp_path / "r3"])
    data = go_timings([file for run in runs for file in run], MODULE, runs)

    assert [len(run) for run in runs] == [2, 3, 2]
    median = go_timings([file for run in runs for file in run], MODULE, runs, "median")
    assert median["packages"] == {f"{MODULE}/pkg/a": 80.0, f"{MODULE}/pkg/b": 5.0}
    assert median["tests"] == {"pkg/a": {"TestSlow": 40.0, "*": 0.1}}
    assert data["packages"] == {f"{MODULE}/pkg/a": 130.0, f"{MODULE}/pkg/b": 5.0}
    assert data["tests"] == {"pkg/a": {"TestSlow": 90.0, "*": 0.1}}


def test_files_named_directly_are_one_run(tmp_path: Path) -> None:
    # The documented single-run form (t/*/*.json) keeps summing the shards.
    files = []
    for shard in range(3):
        path = tmp_path / f"s{shard}.json"
        path.write_text(_event("pass", "pkg/a", 30.0) + "\n", encoding="utf-8")
        files.append(path)

    runs = runs_of(files)
    assert runs == [files]
    assert go_timings(files, MODULE, runs)["packages"] == {f"{MODULE}/pkg/a": 90.0}


def test_python_timings_weigh_the_slowest_run(tmp_path: Path) -> None:
    runs = []
    for run, seconds in (("r1", 1.0), ("r2", 9.0), ("r3", 2.0)):
        (tmp_path / run).mkdir()
        (tmp_path / run / "py.xml").write_text(
            f'<testsuite><testcase classname="cli.tests.test_go_test_report" name="t" time="{seconds}"/></testsuite>',
            encoding="utf-8",
        )
        runs.append([tmp_path / run / "py.xml"])

    assert python_timings([], runs) == {"files": {"cli/tests/test_go_test_report.py": 9.0}}


def test_a_refresh_drops_packages_and_tests_this_tree_does_not_have(tmp_path: Path) -> None:
    # Runs of another branch (feat/endpoint-health-report) put
    # internal/diagnostics and a gateway test that rel/1.0.10 lacks in the
    # timing files.
    (tmp_path / "pkg" / "a").mkdir(parents=True)
    (tmp_path / "pkg" / "a" / "a_test.go").write_text("package a\n\nfunc TestKept(t *testing.T) {}\n", encoding="utf-8")
    data = {
        "packages": {f"{MODULE}/pkg/a": 70.0, f"{MODULE}/pkg/gone": 30.0},
        "tests": {"pkg/a": {"TestKept": 9.0, "TestOtherBranch": 8.0, "*": 0.1}, "pkg/gone": {"TestX": 5.0, "*": 0.1}},
    }

    assert prune_retired(data, MODULE, tmp_path) == {
        "packages": {f"{MODULE}/pkg/a": 70.0},
        "tests": {"pkg/a": {"TestKept": 9.0, "*": 0.1}},
    }
