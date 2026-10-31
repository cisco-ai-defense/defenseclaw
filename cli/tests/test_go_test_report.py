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


def test_build_errors_in_json_are_printed(tmp_path: Path) -> None:
    # Go 1.24+ reports compiler output as build-output events with an
    # ImportPath and no Package; a shard that does not compile must show why.
    importpath = "github.com/example/pkg [github.com/example/pkg.test]"
    out, timings = _run(
        [
            {"ImportPath": importpath, "Action": "build-output", "Output": "# github.com/example/pkg\n"},
            {"ImportPath": importpath, "Action": "build-output", "Output": "./x_test.go:7:2: undefined: missingHelper\n"},
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
