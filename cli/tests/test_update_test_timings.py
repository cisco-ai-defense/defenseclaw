# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

from scripts.update_test_timings import go_timings, windows_go_timings

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
                f"{prefix}[go-package-time] {MODULE}/internal/cli pass 40.5",
                prefix + "=== RUN   TestSlow",
            ]
        ),
        encoding="utf-8",
    )

    assert go_timings([log], MODULE)["tests"] == {"internal/gateway": {"TestSlow": 61.0, "*": 0.1}}
    windows = windows_go_timings([log], MODULE)
    assert windows["packages"] == {f"{MODULE}/internal/cli": 46.5}
    assert windows["tests"] == {"internal/gateway": {"TestSlow": 61.0, "*": 0.1}}
