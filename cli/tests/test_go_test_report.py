# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "go_test_report.py"


def _run(events: list[dict], tmp_path: Path, *extra: str) -> tuple[str, list[dict]]:
    stream = "# github.com/example/pkg [build output]\n" + "".join(json.dumps(e) + "\n" for e in events)
    timings = tmp_path / "timings.json"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--timings", str(timings), *extra],
        input=stream,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout, [json.loads(line) for line in timings.read_text(encoding="utf-8").splitlines()]


def _out(test: str | None, text: str) -> dict:
    event = {"Action": "output", "Package": "p", "Output": text}
    if test:
        event["Test"] = test
    return event


def test_quiet_log_keeps_failures_and_times(tmp_path: Path) -> None:
    out, timings = _run(
        [
            _out("TestOk", "=== RUN   TestOk\n"),
            _out("TestOk", "    ok_test.go:1: noise\n"),
            {"Action": "pass", "Package": "p", "Test": "TestOk", "Elapsed": 3.5},
            _out("TestBad", "    bad_test.go:2: boom\n"),
            _out("TestBad/sub", "    bad_test.go:3: sub boom\n"),
            {"Action": "fail", "Package": "p", "Test": "TestBad/sub", "Elapsed": 0.1},
            {"Action": "fail", "Package": "p", "Test": "TestBad", "Elapsed": 1.0},
            _out(None, "FAIL\tp\t5.0s\n"),
            {"Action": "fail", "Package": "p", "Elapsed": 5.0},
        ],
        tmp_path,
        "--annotate",
        "shard 3 failed",
    )

    assert "noise" not in out and "=== RUN" not in out
    assert "build output" in out and "boom" in out and "sub boom" in out and "FAIL\tp\t5.0s" in out
    assert out.count("::error title=shard 3 failed::") == 1 and "::TestBad\n" in out
    assert timings == [
        {"Action": "pass", "Package": "p", "Test": "TestOk", "Elapsed": 3.5},
        {"Action": "fail", "Package": "p", "Test": "TestBad", "Elapsed": 1.0},
        {"Action": "fail", "Package": "p", "Elapsed": 5.0},
    ]


def test_a_test_still_running_at_the_end_is_named(tmp_path: Path) -> None:
    # go test -timeout kills a hung test binary: its last test never ends.
    out, _ = _run(
        [
            _out("TestHangs", "    hang_test.go:9: waiting for the daemon\n"),
            _out(None, "panic: test timed out after 11m0s\n"),
            _out(None, "\trunning tests:\n\t\tTestHangs (10m59s)\n"),
            {"Action": "fail", "Package": "p", "Elapsed": 660.0},
        ],
        tmp_path,
        "--annotate",
        "shard 1 failed",
    )

    assert "panic: test timed out" in out
    assert "=== still running when go test ended: TestHangs (p)" in out
    assert "waiting for the daemon" in out
    assert "::error title=shard 1 failed::TestHangs was still running" in out


def test_a_test_the_timeout_killed_keeps_the_time_it_ran(tmp_path: Path) -> None:
    # The timed-out test never ends, so it has no pass or fail event: it is
    # written with the wall time up to the last event, so a timing refresh
    # does not weigh it as an unlisted test. A parallel test still waiting
    # for its turn and a skipped test have no time to record.
    def at(seconds: int) -> str:
        return f"2026-11-10T20:{seconds // 60:02d}:{seconds % 60:02d}.000000000Z"

    _, timings = _run(
        [
            {"Action": "run", "Package": "p", "Test": "TestSkipped", "Time": at(0)},
            {"Action": "skip", "Package": "p", "Test": "TestSkipped", "Time": at(0), "Elapsed": 0},
            {"Action": "run", "Package": "p", "Test": "TestWaits", "Time": at(1)},
            {"Action": "pause", "Package": "p", "Test": "TestWaits", "Time": at(1)},
            {"Action": "run", "Package": "p", "Test": "TestSlow", "Time": at(2)},
            {"Action": "run", "Package": "p", "Test": "TestSlow/case", "Time": at(3)},
            _out(None, "panic: test timed out after 11m0s\n"),
            {"Action": "fail", "Package": "p", "Time": at(662), "Elapsed": 662.0},
        ],
        tmp_path,
    )

    assert timings == [
        {"Action": "fail", "Package": "p", "Elapsed": 662.0},
        {"Action": "fail", "Package": "p", "Test": "TestSlow", "Elapsed": 660.0, "CutOff": True},
    ]


def test_a_test_running_when_the_job_died_is_marked_cut_off(tmp_path: Path) -> None:
    # A job killed before go test's own -timeout leaves no package end
    # event: the test still running is written with the time it had run and
    # the CutOff mark, so a refresh does not take that lower bound as its
    # time (GAP-1033).
    def at(seconds: int) -> str:
        return f"2026-11-10T20:{seconds // 60:02d}:{seconds % 60:02d}.000000000Z"

    _, timings = _run(
        [
            {"Action": "run", "Package": "p", "Test": "TestEnded", "Time": at(0)},
            {"Action": "pass", "Package": "p", "Test": "TestEnded", "Time": at(4), "Elapsed": 4.0},
            {"Action": "run", "Package": "p", "Test": "TestSlow", "Time": at(4)},
            _out("TestSlow", "still working\n"),
            {"Action": "output", "Package": "p", "Test": "TestSlow", "Time": at(25), "Output": "x\n"},
        ],
        tmp_path,
    )

    assert timings == [
        {"Action": "pass", "Package": "p", "Test": "TestEnded", "Elapsed": 4.0},
        {"Action": "fail", "Package": "p", "Test": "TestSlow", "Elapsed": 21.0, "CutOff": True},
    ]


def test_build_errors_in_json_are_printed(tmp_path: Path) -> None:
    # Go 1.24+ reports compiler output as build-output events with an
    # ImportPath and no Package; a shard that does not compile must show why.
    importpath = "github.com/example/pkg [github.com/example/pkg.test]"
    out, timings = _run(
        [
            {"ImportPath": importpath, "Action": "build-output", "Output": "# github.com/example/pkg\n"},
            {
                "ImportPath": importpath,
                "Action": "build-output",
                "Output": "./x_test.go:7:2: undefined: missingHelper\n",
            },
            {"ImportPath": importpath, "Action": "build-fail"},
            _out(None, "FAIL\tp [build failed]\n"),
            {"Action": "fail", "Package": "p", "Elapsed": 0, "FailedBuild": importpath},
        ],
        tmp_path,
        "--annotate",
        "shard 1 failed",
    )

    assert "./x_test.go:7:2: undefined: missingHelper" in out
    assert "FAIL\tp [build failed]" in out
    assert "::error title=shard 1 failed::No named failing test was reported" in out
    assert timings == [{"Action": "fail", "Package": "p", "Elapsed": 0}]


def test_a_test_of_parallel_subtests_weighs_its_wall_time(tmp_path: Path) -> None:
    # go test reports a parent without its parallel subtests (1.0 s here),
    # and a parallel top-level test without its wait for t.Parallel.
    def at(seconds: float) -> str:
        return f"2026-10-31T05:00:{seconds:09.6f}123Z"

    _, timings = _run(
        [
            {"Action": "run", "Package": "p", "Test": "TestParent", "Time": at(0)},
            {"Action": "run", "Package": "p", "Test": "TestParent/a", "Time": at(1)},
            {"Action": "pass", "Package": "p", "Test": "TestParent/a", "Elapsed": 20.0, "Time": at(21)},
            {"Action": "pass", "Package": "p", "Test": "TestParent", "Elapsed": 1.0, "Time": at(21.5)},
            {"Action": "run", "Package": "p", "Test": "TestParallel", "Time": at(22)},
            {"Action": "pause", "Package": "p", "Test": "TestParallel", "Time": at(22)},
            {"Action": "cont", "Package": "p", "Test": "TestParallel", "Time": at(50)},
            {"Action": "pass", "Package": "p", "Test": "TestParallel", "Elapsed": 2.0, "Time": at(52)},
            {"Action": "pass", "Package": "p", "Test": "TestNoTime", "Elapsed": 3.0},
        ],
        tmp_path,
    )

    assert timings == [
        {"Action": "pass", "Package": "p", "Test": "TestParent", "Elapsed": 21.5},
        {"Action": "pass", "Package": "p", "Test": "TestParallel", "Elapsed": 2.0},
        {"Action": "pass", "Package": "p", "Test": "TestNoTime", "Elapsed": 3.0},
    ]


def test_parallel_tests_that_run_side_by_side_split_the_time_they_share(tmp_path: Path) -> None:
    # Run 43229287498: the t.Parallel tests of internal/actionfacts summed
    # 653 s of wall spans in a package run of 165 s, so a split of such a
    # package would have weighed it four times over. Two tests that run
    # together split the seconds they share; the shares of the package add
    # up to the time its tests ran (a serial test 10 s, then two parallel
    # tests side by side for 20 s, one of them 10 s longer alone).
    def at(seconds: float) -> str:
        return f"2026-11-12T13:00:{seconds:09.6f}000Z"

    _, timings = _run(
        [
            {"Action": "run", "Package": "p", "Test": "TestA", "Time": at(0)},
            {"Action": "pause", "Package": "p", "Test": "TestA", "Time": at(0)},
            {"Action": "run", "Package": "p", "Test": "TestB", "Time": at(0)},
            {"Action": "pause", "Package": "p", "Test": "TestB", "Time": at(0)},
            {"Action": "run", "Package": "p", "Test": "TestSerial", "Time": at(0)},
            {"Action": "pass", "Package": "p", "Test": "TestSerial", "Elapsed": 10.0, "Time": at(10)},
            {"Action": "cont", "Package": "p", "Test": "TestA", "Time": at(10)},
            {"Action": "cont", "Package": "p", "Test": "TestB", "Time": at(10)},
            {"Action": "run", "Package": "p", "Test": "TestA/case", "Time": at(11)},
            {"Action": "pass", "Package": "p", "Test": "TestA/case", "Elapsed": 18.0, "Time": at(29)},
            {"Action": "pass", "Package": "p", "Test": "TestA", "Elapsed": 20.0, "Time": at(30)},
            {"Action": "pass", "Package": "p", "Test": "TestB", "Elapsed": 30.0, "Time": at(40)},
            {"Action": "pass", "Package": "p", "Elapsed": 40.1, "Time": at(40.1)},
        ],
        tmp_path,
    )

    assert timings == [
        {"Action": "pass", "Package": "p", "Test": "TestSerial", "Elapsed": 10.0},
        {"Action": "pass", "Package": "p", "Test": "TestA", "Elapsed": 10.0},
        {"Action": "pass", "Package": "p", "Test": "TestB", "Elapsed": 20.0},
        {"Action": "pass", "Package": "p", "Elapsed": 40.1},
    ]


def test_a_rerun_or_a_restarted_package_starts_its_shares_again(tmp_path: Path) -> None:
    # A test run again weighs its last run (5 s, not 15), and a package that
    # starts again in the same log (a job killed mid-package, then rerun)
    # does not charge the gap to the test the first job left running.
    def at(seconds: float) -> str:
        return f"2026-11-12T13:{int(seconds // 60):02d}:{seconds % 60:09.6f}000Z"

    _, timings = _run(
        [
            {"Action": "start", "Package": "p", "Time": at(0)},
            {"Action": "run", "Package": "p", "Test": "TestTwice", "Time": at(0)},
            {"Action": "pass", "Package": "p", "Test": "TestTwice", "Elapsed": 10.0, "Time": at(10)},
            {"Action": "run", "Package": "p", "Test": "TestTwice", "Time": at(10)},
            {"Action": "pass", "Package": "p", "Test": "TestTwice", "Elapsed": 5.0, "Time": at(15)},
            {"Action": "run", "Package": "p", "Test": "TestKilled", "Time": at(15)},
            {"Action": "start", "Package": "p", "Time": at(120)},
            {"Action": "run", "Package": "p", "Test": "TestKilled", "Time": at(120)},
            {"Action": "pass", "Package": "p", "Test": "TestKilled", "Elapsed": 3.0, "Time": at(123)},
            {"Action": "pass", "Package": "p", "Elapsed": 3.1, "Time": at(123.1)},
        ],
        tmp_path,
    )

    tests = {t["Test"]: t["Elapsed"] for t in timings if "Test" in t}
    assert tests == {"TestTwice": 5.0, "TestKilled": 3.0}


def _report(events: list[dict], *extra: str) -> subprocess.CompletedProcess[str]:
    stream = "".join(json.dumps(e) + "\n" for e in events)
    return subprocess.run([sys.executable, str(SCRIPT), *extra], input=stream, capture_output=True, text=True)


def _result(test: str, action: str) -> dict:
    return {"Action": action, "Package": "p", "Test": test, "Elapsed": 0.1}


def test_expect_run_passes_when_every_selected_test_reported_a_result() -> None:
    events = [_result("TestA", "pass"), _result("TestB/sub", "pass"), _result("TestB", "fail"), _result("TestC", "skip")]
    result = _report(events, "--expect-run", "^(TestA|TestB|TestC)$")
    assert result.returncode == 0
    assert "3 of 3 selected tests reported a result" in result.stdout


def test_expect_run_fails_when_a_selected_test_reported_nothing() -> None:
    # go_test_shards.py prints ^(?:...)$ with re.escape; a subtest is no result.
    events = [_result("TestA", "pass"), _result("TestB/sub", "pass")]
    result = _report(events, "--annotate", "part 2 failed", "--expect-run", "^(?:TestA|TestB)$")
    assert result.returncode == 1
    assert "1 of 2 selected tests reported a result" in result.stdout
    assert "::error title=part 2 failed::TestB reported no result" in result.stdout


def test_expect_run_fails_when_no_test_ran() -> None:
    events = [{"Action": "output", "Package": "p", "Output": "testing: warning: no tests to run\n"}]
    events.append({"Action": "pass", "Package": "p", "Elapsed": 0})
    result = _report(events, "--expect-run", "^(TestA|TestB)$")
    assert result.returncode == 1
    assert "0 of 2 selected tests reported a result" in result.stdout


def test_expect_run_refuses_a_pattern_that_is_not_a_name_list() -> None:
    for pattern in ("TestA", "^(TestA|Test.*)$", "^()$"):
        assert _report([], "--expect-run", pattern).returncode == 2


def test_without_expect_run_the_exit_status_stays_zero() -> None:
    assert _report([_result("TestA", "fail")]).returncode == 0


def test_untimed_against_names_the_slow_tests_the_timings_do_not_time(tmp_path: Path) -> None:
    # The shard planner weighs a test the timings do not name as a fast one
    # (about 0.25 s): TestGAP0980Round2ReviewRows took 391 s under -race and
    # overfilled its shard. The run names such tests; a fast test, a timed
    # test and a test of a package not timed by test are not named (GAP-1053).
    known = tmp_path / "go-linux.json"
    known.write_text(json.dumps({"tests": {"internal/gateway": {"TestTimed": 50.0, "*": 0.25}}}), encoding="utf-8")
    gateway = "github.com/example/internal/gateway"
    events = [
        {"Action": "pass", "Package": gateway, "Test": "TestTimed", "Elapsed": 40.0},
        {"Action": "pass", "Package": gateway, "Test": "TestFast", "Elapsed": 1.5},
        {"Action": "pass", "Package": gateway, "Test": "TestNewSlow", "Elapsed": 391.0},
        {"Action": "fail", "Package": gateway, "Test": "TestNewFailing", "Elapsed": 3.0},
        {"Action": "pass", "Package": "github.com/example/internal/other", "Test": "TestElsewhere", "Elapsed": 90.0},
    ]
    result = _report(events, "--untimed-against", str(known))
    assert result.returncode == 0
    assert f"2 tests of 2 s or more have no time in {known}" in result.stdout
    warnings = [line for line in result.stdout.splitlines() if line.startswith("::warning")]
    assert warnings == [
        f"::warning title=untimed test::TestNewSlow ({gateway}) ran 391.0 s with no time in {known}",
        f"::warning title=untimed test::TestNewFailing ({gateway}) ran 3.0 s with no time in {known}",
    ]


def test_every_linux_gateway_race_shard_names_its_untimed_tests() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    step = workflow.split("name: Run gateway race/coverage shard", 1)[1].split("- uses:", 1)[0]
    assert "--untimed-against scripts/test-timings/go-linux.json" in step
