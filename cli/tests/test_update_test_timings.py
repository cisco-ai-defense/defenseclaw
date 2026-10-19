# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

from scripts.update_test_timings import go_ci_log_results, go_ci_log_timings

STAMP = "2026-10-19T12:00:00.1234567Z"


def test_go_ci_log_reads_raw_job_logs() -> None:
    text = "\n".join(
        [
            f"{STAMP} ok  \tgithub.com/example/pkg/a\t12.5s\tcoverage: 80.0% of statements",
            f"{STAMP} FAIL\tgithub.com/example/pkg/b\t3.25s",
            f"{STAMP} FAIL",
            f"{STAMP} ok  \tgithub.com/example/pkg/c\t(cached)",
            "ok  \tgithub.com/example/pkg/d\t1.0s",
        ]
    )

    assert go_ci_log_results(text) == [
        ("github.com/example/pkg/a", "12.5"),
        ("github.com/example/pkg/b", "3.25"),
        ("github.com/example/pkg/d", "1.0"),
    ]


def test_go_ci_log_strips_gh_run_view_job_and_step_columns() -> None:
    # gh run view --log writes "<job name>\t<step name>\t<timestamp> <line>",
    # and this repository's job and step names contain spaces.
    prefix = "Go Test (gateway race 1/3)\tRun the gateway race shard\t"
    text = "\n".join(
        [
            f"{prefix}{STAMP} ok  \tgithub.com/example/pkg/a\t12.5s",
            f"{prefix}{STAMP} FAIL\tgithub.com/example/pkg/b\t3.25s",
            f"{prefix}{STAMP} === RUN   TestOk",
            f"{prefix}{STAMP} --- PASS: TestOk (0.00s)",
        ]
    )

    assert go_ci_log_results(text) == [
        ("github.com/example/pkg/a", "12.5"),
        ("github.com/example/pkg/b", "3.25"),
    ]


def test_go_ci_log_timings_sums_split_parts_and_keeps_test_times(tmp_path: Path) -> None:
    current = tmp_path / "go-linux.json"
    current.write_text(
        json.dumps(
            {
                "packages": {"github.com/example/pkg/a": 99.0, "github.com/example/pkg/z": 4.0},
                "tests": {"pkg/a": {"*": 0.1}},
            }
        ),
        encoding="utf-8",
    )
    log = tmp_path / "ci.log"
    log.write_text(
        "\n".join(
            [
                f"Go Test (part 1)\tRun tests\t{STAMP} ok  \tgithub.com/example/pkg/a\t10.0s",
                f"Go Test (part 2)\tRun tests\t{STAMP} ok  \tgithub.com/example/pkg/a\t5.0s",
                # The same result line twice in one log counts once.
                f"Go Test (part 2)\tRun tests\t{STAMP} ok  \tgithub.com/example/pkg/a\t5.0s",
            ]
        ),
        encoding="utf-8",
    )

    data = go_ci_log_timings([log], current)

    assert data["packages"] == {"github.com/example/pkg/a": 15.0, "github.com/example/pkg/z": 4.0}
    assert data["tests"] == {"pkg/a": {"*": 0.1}}
