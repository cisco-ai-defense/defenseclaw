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
top-level test's Elapsed there is its wall time (from its run event, or its
cont event once t.Parallel resumed it, to its pass or fail event) when that
is longer: go test leaves the parallel subtests out of their parent's
Elapsed, so a test of parallel subtests weighed almost nothing to the shard
planner while it held its shard for minutes.

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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timings", help="write the pass/fail events (no output) to this file")
    parser.add_argument("--annotate", metavar="TITLE", help="GitHub ::error title for failed tests")
    args = parser.parse_args()

    out = sys.stdout
    timings = open(args.timings, "w", encoding="utf-8") if args.timings else None
    buffered: dict[tuple[str, str], list[str]] = {}
    started: dict[tuple[str, str], datetime] = {}
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
            if test is None:
                if action == "output":
                    out.write(event.get("Output", ""))
                    out.flush()
                elif action in ("pass", "fail"):
                    package_failed = package_failed or action == "fail"
                    if timings is None:
                        continue
                    timings.write(json.dumps({"Action": action, "Package": package, "Elapsed": event.get("Elapsed", 0)}) + "\n")
                continue
            key = (package, test)
            if action in ("run", "cont") and "/" not in test:
                at = _time(event)
                if at is not None:
                    started[key] = at
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
                start, end = started.pop(key, None), _time(event)
                if start is not None and end is not None:
                    elapsed = max(elapsed, round((end - start).total_seconds(), 3))
                record = {"Action": action, "Package": package, "Test": test, "Elapsed": elapsed}
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
