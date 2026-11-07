#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Run the private D1 replay until its verdict file is complete.

An evaluator that never returns (rel-1-0-6 GAP-0700) cannot be stopped inside
a Go test binary, so the replay records the row as timeout, writes a stall
marker next to the verdict file and exits cleanly. This driver starts the
next run, which resumes after that row, until a run finishes without a
marker. The comparison (scripts/d1diff.py) then decides on the complete file.
It prints counts only, never row identities.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

MAX_RUNS = 8


def drive(
    command: Sequence[str],
    output: Path,
    max_runs: int = MAX_RUNS,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    env: dict[str, str] | None = None,
) -> int:
    environment = dict(os.environ if env is None else env)
    environment["DC_D1_OUTPUT"] = str(output)
    marker = Path(str(output) + ".stalled")
    for attempt in range(max_runs):
        environment["DC_D1_RESUME"] = "1" if attempt else "0"
        code = runner(list(command), env=environment).returncode
        if code != 0:
            return code
        if not marker.exists():
            return 0
        print(f"D1 replay: run {attempt + 1} stopped at a timed-out row; resuming", file=sys.stderr)
    print(f"D1 replay: still stopping at timed-out rows after {max_runs} runs", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=os.environ.get("DC_D1_OUTPUT"))
    parser.add_argument("--max-runs", type=int, default=MAX_RUNS)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not args.output or not command or args.max_runs < 1:
        parser.error("need --output (or DC_D1_OUTPUT), --max-runs >= 1 and a command after --")
    return drive(command, Path(args.output), args.max_runs)


if __name__ == "__main__":
    raise SystemExit(main())
