#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Show `go test -json` as the quiet `go test` log and keep the test times.

CI pipes `go test -json` through this script:

  go test -json ... ./pkg | python3 scripts/go_test_report.py --timings t.json

The log looks like a `go test` run without -v: package lines ("ok", "FAIL",
coverage, a timeout panic and its goroutine dump) and compiler errors (the
build-output events) as they arrive, and the
output of a test only when it fails. A test still running when the stream
ends (a hang the package -timeout killed) has its output printed too, under
a "still running" line, so a hung shard names its test.

--timings writes the pass and fail events of every package and top-level
test, without output, in `go test -json` form: scripts/update_test_timings.py
go reads these files to refresh scripts/test-timings/go-linux.json. A
top-level test's Elapsed there is its share of its package's wall time
(TopLevelShares): every second of the run is split evenly between the
top-level tests running in it, from a run or cont event to the next pause,
pass, fail or skip. A test of parallel subtests therefore weighs the wall
time its subtests hold (go test leaves them out of their parent's Elapsed,
so such a test weighed almost nothing to the shard planner while it held
its shard for minutes), and t.Parallel top-level tests that run side by
side weigh their part of that time, not each the whole of it (their wall
spans overlap: internal/actionfacts summed 653 s of test time in a package
run of 165 s, run 43229287498). The shares of a package add up to the time
its tests ran, which is what a shard of them takes. A top-level test still
running when the stream ends (the package -timeout killed it) is written as
a fail with the share it had until the last event: a refresh then weighs
the slowest test of a timed-out shard by at least that time, not as an
unlisted test. An event without a Time keeps go test's Elapsed.

--annotate TITLE prints a GitHub error annotation per failed top-level test
(at most 20). The exit status is always 0; the caller keeps go test's.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime

_FRACTION = re.compile(r"(\.\d{6})\d+")


def _time(event: dict) -> datetime | None:
    """The event's Time (RFC 3339, nanoseconds), or None."""
    value = event.get("Time")
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(_FRACTION.sub(r"\1", value).replace("Z", "+00:00"))
    except ValueError:
        return None


class TopLevelShares:
    """Each top-level test's share of its package's wall time.

    Feed every event in stream order (event()); seconds() is the share of a
    test that ran with timed events, or None. Between two events of a
    package, the time is split evenly between its top-level tests that are
    running (a run or cont event, not yet followed by a pause, pass, fail
    or skip); subtest events only move the clock. A package's end (its own
    pass or fail) clears its clock, so the next shard or part of the same
    package in one log starts afresh.
    """

    def __init__(self) -> None:
        self._running: dict[str, set[str]] = {}
        self._clock: dict[str, datetime] = {}
        self._share: dict[tuple[str, str], float] = {}

    def _advance(self, package: str, at: datetime) -> None:
        clock = self._clock.get(package)
        running = self._running.get(package)
        if clock is not None and running and at > clock:
            part = (at - clock).total_seconds() / len(running)
            for test in running:
                self._share[(package, test)] += part
        if clock is None or at > clock or not running:
            self._clock[package] = at

    def event(self, package: str, test: str | None, action: str | None, at: datetime | None) -> None:
        if at is None:
            return
        self._advance(package, at)
        if test is None:
            if action in ("pass", "fail"):
                self._clock.pop(package, None)
                self._running.pop(package, None)
            return
        if "/" in test:
            return
        if action in ("run", "cont"):
            self._running.setdefault(package, set()).add(test)
            self._share.setdefault((package, test), 0.0)
        elif action in ("pause", "pass", "fail", "skip"):
            self._running.get(package, set()).discard(test)

    def finish(self, at: datetime) -> None:
        """Charge the tests still running up to at (the last event)."""
        for package in list(self._running):
            self._advance(package, at)

    def seconds(self, package: str, test: str) -> float | None:
        share = self._share.get((package, test))
        return None if share is None else round(share, 3)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timings", help="write the pass/fail events (no output) to this file")
    parser.add_argument("--annotate", metavar="TITLE", help="GitHub ::error title for failed tests")
    args = parser.parse_args()

    out = sys.stdout
    timings = open(args.timings, "w", encoding="utf-8") if args.timings else None
    buffered: dict[tuple[str, str], list[str]] = {}
    started: set[tuple[str, str]] = set()
    shares = TopLevelShares()
    last: datetime | None = None
    failed: list[str] = []
    package_failed = False
    try:
        for line in sys.stdin:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                # Build errors and anything else go test prints as plain text.
                out.write(line)
                out.flush()
                continue
            if not isinstance(event, dict):
                out.write(line)
                continue
            action = event.get("Action")
            if action == "build-output":
                # Go 1.24 and later report a package's compiler output as
                # JSON (ImportPath, no Package): print it, or a shard that
                # does not compile fails without its error.
                out.write(event.get("Output", ""))
                out.flush()
                continue
            if action == "build-fail":
                package_failed = True
                continue
            package = event.get("Package", "")
            test = event.get("Test")
            at = _time(event)
            if at is not None:
                last = at
            shares.event(package, test, action, at)
            if test is None:
                if action == "output":
                    out.write(event.get("Output", ""))
                    out.flush()
                elif action in ("pass", "fail"):
                    package_failed = package_failed or action == "fail"
                    if timings is None:
                        continue
                    timings.write(
                        json.dumps({"Action": action, "Package": package, "Elapsed": event.get("Elapsed", 0)}) + "\n"
                    )
                continue
            key = (package, test)
            if action in ("run", "cont") and "/" not in test and at is not None:
                started.add(key)
            elif action in ("pause", "skip"):
                # A parallel test waits for its turn: that wait is not its time.
                started.discard(key)
            if action == "output":
                buffered.setdefault(key, []).append(event.get("Output", ""))
            elif action in ("pass", "skip"):
                buffered.pop(key, None)
            elif action == "fail":
                out.write("".join(buffered.pop(key, [])))
                out.flush()
                if "/" not in test:
                    failed.append(test)
            if action in ("pass", "fail") and "/" not in test and timings is not None:
                elapsed = event.get("Elapsed", 0)
                share = shares.seconds(package, test)
                if key in started and at is not None and share is not None:
                    elapsed = share
                started.discard(key)
                record = {"Action": action, "Package": package, "Test": test, "Elapsed": elapsed}
                timings.write(json.dumps(record) + "\n")
        if timings is not None and last is not None:
            shares.finish(last)
            for package, test in sorted(started):
                elapsed = shares.seconds(package, test) or 0.0
                record = {"Action": "fail", "Package": package, "Test": test, "Elapsed": elapsed}
                timings.write(json.dumps(record) + "\n")
    finally:
        if timings is not None:
            timings.close()
    for (package, test), lines in buffered.items():
        out.write(f"=== still running when go test ended: {test} ({package})\n")
        out.write("".join(lines))
    if args.annotate:
        names = sorted({name for name in failed if name.replace("_", "").isalnum()})
        for name in names[:20]:
            out.write(f"::error title={args.annotate}::{name}\n")
        if not names and buffered:
            for _, test in list(buffered)[:20]:
                out.write(f"::error title={args.annotate}::{test} was still running\n")
        elif not names and package_failed:
            out.write(f"::error title={args.annotate}::No named failing test was reported\n")
    out.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
